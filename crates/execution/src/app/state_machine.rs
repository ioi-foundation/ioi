// Path: crates/execution/src/app/state_machine.rs

use super::{end_block, ExecutionMachine};
use crate::app::parallel_state::ParallelStateAccess;
use crate::mv_memory::MVMemory;
use crate::scheduler::{Scheduler, Task};
use async_trait::async_trait;
use dashmap::DashMap;
// REMOVED: use ibc_primitives::Timestamp;
use ioi_api::app::{Block, BlockHeader, ChainStatus, ChainTransaction};
use ioi_api::chain::{AnchoredStateView, ChainStateMachine, ChainView, PreparedBlock, StateRef};
use ioi_api::commitment::CommitmentScheme;
use ioi_api::consensus::PenaltyMechanism;
use ioi_api::services::access::ServiceDirectory;
use ioi_api::state::namespaced::NamespacedStateAccess;
use ioi_api::state::namespaced::ReadOnlyNamespacedStateAccess;
use ioi_api::state::{
    service_namespace_prefix, PinGuard, ProofProvider, StateAccess, StateManager, StateOverlay,
};
use ioi_api::transaction::context::TxContext;
use ioi_api::transaction::TransactionModel;
use ioi_api::validator::WorkloadContainer;
use ioi_consensus::Consensus;
use ioi_tx::system::{nonce, validation};
use ioi_tx::unified::UnifiedProof;
use ioi_tx::unified::UnifiedTransactionModel;
use ioi_types::app::{
    account_id_from_key_material,
    aft_bulletin_commitment_key,
    aft_canonical_collapse_object_key,
    build_reference_bulletin_commitment,
    canonical_transactions_root,
    compute_next_timestamp_ms,
    derive_canonical_collapse_object_with_previous,
    read_validator_sets,
    timestamp_millis_to_legacy_seconds,
    to_root_hash,
    AccountId,
    BlockTimingParams,
    BlockTimingRuntime,
    Membership,
    QuorumCertificate, // [FIX] Import QuorumCertificate
    SignatureSuite,
    StateRoot,
};
use ioi_types::codec;
use ioi_types::config::ConsensusType;
use ioi_types::error::{BlockError, ChainError, StateError};
use ioi_types::keys::{
    BLOCK_TIMING_PARAMS_KEY, BLOCK_TIMING_RUNTIME_KEY, STATUS_KEY, UPGRADE_ACTIVE_SERVICE_PREFIX,
    VALIDATOR_SET_KEY,
};
use ioi_types::service_configs::ActiveServiceMeta;
use libp2p::identity::Keypair;
use parity_scale_codec::Decode;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::sync::Arc;
use std::time::{Duration, Instant};

// --- Parallel Executor Context ---

fn benchmark_trace_enabled() -> bool {
    std::env::var_os("IOI_AFT_BENCH_TRACE").is_some()
}

/// A lightweight, thread-safe context for executing transactions in parallel.
/// Implements `ChainView` to satisfy TransactionModel requirements.
#[derive(Clone, Debug)]
struct ParallelExecutor<CS, ST>
where
    CS: CommitmentScheme + Clone, // Added Clone bound here
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>,
{
    chain_id: ioi_types::app::ChainId,
    services: ServiceDirectory,
    service_meta_cache: Arc<HashMap<String, Arc<ActiveServiceMeta>>>,
    transaction_model: UnifiedTransactionModel<CS>,
    workload_container: Arc<WorkloadContainer<ST>>,
    recent_blocks: Arc<Vec<Block<ChainTransaction>>>,
    last_state_root: Vec<u8>,
    consensus_engine: Consensus<ChainTransaction>,
}

#[async_trait]
impl<CS, ST> ChainView<CS, ST> for ParallelExecutor<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static, // Added Clone bound here
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
{
    async fn view_at(
        &self,
        state_ref: &StateRef,
    ) -> Result<Arc<dyn AnchoredStateView>, ChainError> {
        // Re-implement view resolution logic using captured state
        let (resolved_root_bytes, gas_used) = if state_ref.state_root.is_empty() {
            return Err(ChainError::UnknownStateAnchor(
                "Cannot create view for empty state root".to_string(),
            ));
        } else if self.last_state_root == state_ref.state_root {
            let gas = self
                .recent_blocks
                .last()
                .map(|b| b.header.gas_used)
                .unwrap_or(0);
            (Some(self.last_state_root.clone()), gas)
        } else {
            let found = self.recent_blocks.iter().rev().find_map(|b| {
                if b.header.state_root.as_ref() == state_ref.state_root {
                    Some((b.header.state_root.0.clone(), b.header.gas_used))
                } else {
                    None
                }
            });
            match found {
                Some((root, gas)) => (Some(root), gas),
                None => (None, 0),
            }
        };

        let root = resolved_root_bytes
            .ok_or_else(|| ChainError::UnknownStateAnchor(hex::encode(&state_ref.state_root)))?;

        // Construct view manually since we can't use `ExecutionMachine` methods directly
        // We reuse the view type from `app/view.rs` which is generic.
        // For simplicity in this parallel context, we assume `ChainStateView` from `super::view` is usable.
        let view = super::view::ChainStateView {
            state_tree: self.workload_container.state_tree(),
            height: state_ref.height,
            root,
            gas_used,
        };
        Ok(Arc::new(view))
    }

    fn get_penalty_mechanism(&self) -> Box<dyn PenaltyMechanism + Send + Sync + '_> {
        Box::new(self.consensus_engine.clone())
    }

    fn consensus_type(&self) -> ConsensusType {
        self.consensus_engine.consensus_type()
    }

    fn workload_container(&self) -> &WorkloadContainer<ST> {
        &self.workload_container
    }
}

impl<CS, ST> ParallelExecutor<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static, // Added Clone bound here
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + ProofProvider
        + Send
        + Sync
        + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
{
    /// Process a single transaction in a parallel worker context.
    /// This logic mirrors `ExecutionMachine::process_transaction` but is adapted for thread safety.
    async fn process_transaction_parallel(
        &self,
        tx: &ChainTransaction,
        state: &mut dyn StateAccess, // ParallelStateAccess
        block_height: u64,
        block_timestamp: u64,
        skip_stateless_signature: bool,
    ) -> Result<(Vec<u8>, u64), ChainError> {
        // [FIX] Removed wildcard match that caused unreachable pattern warnings
        let signer_account_id = match tx {
            ChainTransaction::System(s) => s.header.account_id,
            ChainTransaction::Settlement(s) => s.header.account_id,
            ChainTransaction::Application(a) => match a {
                ioi_types::app::ApplicationTransaction::DeployContract { header, .. }
                | ioi_types::app::ApplicationTransaction::CallContract { header, .. } => {
                    header.account_id
                }
            },
            ChainTransaction::Semantic { header, .. } => header.account_id,
        };

        // [FIX] Update timestamp handling
        let block_timestamp_ns = (block_timestamp as u128)
            .saturating_mul(1_000_000_000)
            .try_into()
            .map_err(|_| ChainError::Transaction("Timestamp overflow".to_string()))?;

        let mut tx_ctx = TxContext {
            block_height,
            block_timestamp: block_timestamp_ns,
            chain_id: self.chain_id,
            signer_account_id,
            services: &self.services,
            simulation: false,
            is_internal: false,
        };

        // --- PHASE 1: READ-ONLY VALIDATION ---

        // [MIGRATION] Split validation
        // 1a. Stateless: Verify Signatures
        if !skip_stateless_signature {
            validation::verify_stateless_signature(tx)?;
        }

        // 1b. Stateful: Verify Authorization (Reads from MVMemory)
        validation::verify_stateful_authorization(state, &self.services, tx, &tx_ctx)?;

        nonce::assert_next_nonce(state, tx)?;

        let decorators: Vec<(&str, &dyn ioi_api::transaction::decorator::TxDecorator)> = self
            .services
            .services_in_deterministic_order()
            .filter_map(|s| s.as_tx_decorator().map(|d| (s.id(), d)))
            .collect();

        for (id, decorator) in &decorators {
            let meta = self.service_meta_cache.get(*id).ok_or_else(|| {
                ChainError::Transaction(format!("Metadata missing for service '{}'", id))
            })?;
            let prefix = service_namespace_prefix(id);
            // ReadOnly wrapper ensures no writes occur during validation
            let namespaced_view = ReadOnlyNamespacedStateAccess::new(state, prefix, meta);
            decorator
                .validate_ante(&namespaced_view, tx, &tx_ctx)
                .await?;
        }

        // --- PHASE 2: STATE MUTATION ---
        for (id, decorator) in decorators {
            let meta = self.service_meta_cache.get(id).unwrap();
            let prefix = service_namespace_prefix(id);
            let mut namespaced_write = NamespacedStateAccess::new(state, prefix, meta);
            decorator
                .write_ante(&mut namespaced_write, tx, &tx_ctx)
                .await?;
        }

        nonce::bump_nonce(state, tx)?;

        // --- PHASE 3: PAYLOAD EXECUTION ---
        let (proof, gas_used) = self
            .transaction_model
            .apply_payload(self, state, tx, &mut tx_ctx)
            .await?;

        let proof_bytes =
            ioi_types::codec::to_bytes_canonical(&proof).map_err(ChainError::Transaction)?;

        Ok((proof_bytes, gas_used))
    }
}

// --- ChainStateMachine Implementation ---

#[async_trait]
impl<CS, ST> ChainStateMachine<CS, UnifiedTransactionModel<CS>, ST> for ExecutionMachine<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + ProofProvider
        + Send
        + Sync
        + 'static
        + Clone,
    <CS as CommitmentScheme>::Value: From<Vec<u8>> + AsRef<[u8]> + Send + Sync + std::fmt::Debug,
    <CS as CommitmentScheme>::Proof: AsRef<[u8]>
        + Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Decode
        + Debug,
    <CS as CommitmentScheme>::Commitment: From<Vec<u8>> + Debug + Send + Sync,
{
    fn status(&self) -> &ChainStatus {
        &self.state.status
    }

    fn status_mut(&mut self) -> &mut ChainStatus {
        &mut self.state.status
    }

    fn transaction_model(&self) -> &UnifiedTransactionModel<CS> {
        &self.state.transaction_model
    }

    async fn prepare_block(
        &self,
        block: Block<ChainTransaction>,
    ) -> Result<PreparedBlock, ChainError> {
        let prepare_started = Instant::now();
        let benchmark_trace = benchmark_trace_enabled();
        let skip_stateless_signature = block.header.signature.is_empty();
        let workload = &self.workload_container;
        let expected_height = self.state.status.height + 1;
        if block.header.height != expected_height {
            return Err(ChainError::Block(BlockError::InvalidHeight {
                expected: expected_height,
                got: block.header.height,
            }));
        }

        let num_txs = block.transactions.len();

        // 1. Initialize State Snapshot & Pinning
        // We hold the pin guard for the duration of execution to prevent GC of the base state.
        let _pin_guard = PinGuard::new(workload.pins().clone(), self.state.status.height);
        let snapshot_started = Instant::now();

        // Acquire a consistent view of the state (Base View for MVMemory).
        // `read()` gives us a `RwLockReadGuard<ST>`. We clone ST to get an owned snapshot
        // (assuming ST is cheap to clone/Arc-like or persistent structure handle).
        let snapshot_state: ST = {
            let state_tree_arc = workload.state_tree();
            let backend_guard = state_tree_arc.read().await;
            backend_guard.clone()
        };
        let snapshot_elapsed = snapshot_started.elapsed();

        // Wrap as Arc<dyn StateAccess> for MVMemory
        let snapshot_arc: Arc<dyn StateAccess> = Arc::new(snapshot_state);
        let mv_memory = Arc::new(MVMemory::new(snapshot_arc.clone()));

        // 2. Initialize Scheduler and Result Storage
        let scheduler = Arc::new(Scheduler::new(num_txs));
        let read_sets = Arc::new(DashMap::new());
        let results = Arc::new(DashMap::new());

        let transactions = block.transactions.clone();
        let block_header_height = block.header.height;
        let block_timestamp_ms = if block.header.timestamp_ms > 0 {
            block.header.timestamp_ms
        } else if !block.header.state_root.0.is_empty() || !block.header.transactions_root.is_empty()
        {
            block.header.timestamp_ms_or_legacy()
        } else {
            self.resolve_next_block_timestamp_ms(&*snapshot_arc, block.header.height)?
        };
        let block_header_timestamp = block_timestamp_ms / 1_000;

        let externally_committed =
            !block.header.state_root.0.is_empty() || !block.header.transactions_root.is_empty();
        let force_sequential_replay = std::env::var("IOI_EXEC_FORCE_SEQUENTIAL_REPLAY")
            .ok()
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let replay_sequentially = num_txs <= 1 || externally_committed || force_sequential_replay;

        let (
            state_changes,
            proofs_out,
            block_gas_used,
            parallel_exec_elapsed,
            overlay_elapsed,
            collect_results_elapsed,
        ) = if replay_sequentially {
            let sequential_exec_started = Instant::now();
            let mut final_overlay = StateOverlay::new(&*snapshot_arc);
            let mut proofs_out = Vec::with_capacity(num_txs);
            let mut block_gas_used = 0;

            for tx in &block.transactions {
                block_gas_used += self
                    .process_transaction(
                        tx,
                        &mut final_overlay,
                        block_header_height,
                        block_header_timestamp,
                        &mut proofs_out,
                    )
                    .await?;
            }

            let state_changes = final_overlay.into_ordered_batch();
            let sequential_exec_elapsed = sequential_exec_started.elapsed();

            tracing::debug!(
                target: "execution",
                height = block.header.height,
                tx_count = num_txs,
                externally_committed,
                force_sequential_replay,
                "Prepared block via sequential replay"
            );

            (
                state_changes,
                proofs_out,
                block_gas_used,
                sequential_exec_elapsed,
                Duration::ZERO,
                Duration::ZERO,
            )
        } else {
            // 3. Prepare Parallel Executor Context
            let executor = Arc::new(ParallelExecutor {
                chain_id: self.state.chain_id,
                services: self.services.clone(),
                // Ensure service_meta_cache is accessible (cloning the HashMap into an Arc)
                service_meta_cache: Arc::new(self.service_meta_cache.clone()),
                transaction_model: self.state.transaction_model.clone(),
                workload_container: self.workload_container.clone(),
                recent_blocks: Arc::new(self.state.recent_blocks.clone()),
                last_state_root: self.state.last_state_root.clone(),
                consensus_engine: self.consensus_engine.clone(),
            });

            // 4. Thread Pool Execution
            let num_threads = std::cmp::min(
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(1),
                num_txs,
            )
            .max(1);

            tracing::debug!(
                target: "execution",
                "Starting parallel execution with {} threads for {} txs",
                num_threads,
                num_txs
            );

            let scheduler_clone = scheduler.clone();
            let mv_memory_clone = mv_memory.clone();
            let read_sets_clone = read_sets.clone();
            let results_clone = results.clone();

            let parallel_exec_started = Instant::now();
            tokio::task::spawn_blocking(move || {
                crossbeam_utils::thread::scope(|s| {
                    for _ in 0..num_threads {
                        let scheduler = scheduler_clone.clone();
                        let mv_memory = mv_memory_clone.clone();
                        let read_sets = read_sets_clone.clone();
                        let results = results_clone.clone();
                        let txs = &transactions;
                        let executor = executor.clone();

                        s.spawn(move |_| {
                            let rt = tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()
                                .expect("Failed to build Tokio runtime for execution worker");
                            loop {
                                match scheduler.next_task() {
                                    Task::Execute(idx) => {
                                        let tx = &txs[idx];
                                        let mut state_proxy =
                                            ParallelStateAccess::new(&mv_memory, idx);
                                        let result =
                                            rt.block_on(executor.process_transaction_parallel(
                                                tx,
                                                &mut state_proxy,
                                                block_header_height,
                                                block_header_timestamp,
                                                skip_stateless_signature,
                                            ));

                                        let rs = state_proxy.read_set.lock().unwrap().clone();
                                        read_sets.insert(idx, rs);

                                        match result {
                                            Ok((proof, gas)) => {
                                                results.insert(idx, (proof, gas));
                                                scheduler.finish_execution(idx);
                                            }
                                            Err(e) => {
                                                tracing::error!(
                                                    target: "execution",
                                                    tx_index = idx,
                                                    error = %e,
                                                    "Transaction failed in parallel execution"
                                                );
                                                results.insert(idx, (vec![], 0));
                                                scheduler.finish_execution(idx);
                                            }
                                        }
                                    }
                                    Task::Validate(idx) => {
                                        if let Some(rs) = read_sets.get(&idx) {
                                            match mv_memory.validate_read_set(&rs, idx) {
                                                Ok(valid) => {
                                                    if !valid {
                                                        scheduler.abort_tx(idx);
                                                    } else {
                                                        scheduler.finish_validation(idx);
                                                    }
                                                }
                                                Err(_) => {
                                                    scheduler.abort_tx(idx);
                                                }
                                            }
                                        } else {
                                            tracing::warn!(
                                                target: "execution",
                                                tx_index = idx,
                                                "Validation ran before a read set was recorded; rewinding transaction"
                                            );
                                            scheduler.abort_tx(idx);
                                        }
                                    }
                                    Task::Done => break,
                                    Task::RetryLater => std::thread::yield_now(),
                                }
                            }
                        });
                    }
                })
                .unwrap();
            })
            .await
            .map_err(|e| ChainError::Transaction(format!("Parallel execution panicked: {}", e)))?;
            let parallel_exec_elapsed = parallel_exec_started.elapsed();

            let overlay_started = Instant::now();
            let mut final_overlay = StateOverlay::new(&*snapshot_arc);
            mv_memory
                .apply_to_overlay(&mut final_overlay)
                .map_err(ChainError::State)?;
            let state_changes = final_overlay.into_ordered_batch();
            let overlay_elapsed = overlay_started.elapsed();

            let collect_results_started = Instant::now();
            let mut proofs_out = Vec::with_capacity(num_txs);
            let mut block_gas_used = 0;

            for i in 0..num_txs {
                if let Some((_, (p, gas))) = results.remove(&i) {
                    proofs_out.push(p);
                    block_gas_used += gas;
                } else {
                    tracing::warn!(
                        target: "execution",
                        tx_index = i,
                        "Missing execution result, using empty."
                    );
                    proofs_out.push(vec![]);
                }
            }
            let collect_results_elapsed = collect_results_started.elapsed();

            (
                state_changes,
                proofs_out,
                block_gas_used,
                parallel_exec_elapsed,
                overlay_elapsed,
                collect_results_elapsed,
            )
        };

        // 7. Compute Roots
        let roots_started = Instant::now();
        let transactions_root =
            canonical_transactions_root(&block.transactions).map_err(ChainError::Transaction)?;
        let vs_bytes = self.get_validator_set_for(block.header.height).await?;
        let validator_set_hash = ioi_crypto::algorithms::hash::sha256(vs_bytes.concat())
            .map_err(|e| ChainError::Transaction(e.to_string()))?;
        let roots_elapsed = roots_started.elapsed();

        if benchmark_trace {
            eprintln!(
                "[BENCH-EXEC] prepare_block height={} tx_count={} snapshot_ms={} parallel_exec_ms={} overlay_ms={} collect_results_ms={} roots_ms={} total_ms={}",
                block.header.height,
                num_txs,
                snapshot_elapsed.as_millis(),
                parallel_exec_elapsed.as_millis(),
                overlay_elapsed.as_millis(),
                collect_results_elapsed.as_millis(),
                roots_elapsed.as_millis(),
                prepare_started.elapsed().as_millis(),
            );
            tracing::info!(
                target: "execution_bench",
                height = block.header.height,
                tx_count = num_txs,
                snapshot_ms = snapshot_elapsed.as_millis(),
                parallel_exec_ms = parallel_exec_elapsed.as_millis(),
                overlay_ms = overlay_elapsed.as_millis(),
                collect_results_ms = collect_results_elapsed.as_millis(),
                roots_ms = roots_elapsed.as_millis(),
                total_ms = prepare_started.elapsed().as_millis(),
                "prepare_block timing"
            );
        }

        Ok(PreparedBlock {
            block,
            block_timestamp_ms,
            state_changes: Arc::new(state_changes),
            parent_state_root: self.state.last_state_root.clone(),
            transactions_root,
            validator_set_hash,
            tx_proofs: proofs_out,
            gas_used: block_gas_used,
        })
    }

    async fn commit_block(
        &mut self,
        prepared: PreparedBlock,
    ) -> Result<(Block<ChainTransaction>, Vec<Vec<u8>>), ChainError> {
        let commit_started = Instant::now();
        let benchmark_trace = benchmark_trace_enabled();
        let workload = &self.workload_container;
        let mut block = prepared.block;
        let block_timestamp_ms = prepared.block_timestamp_ms;
        let state_changes = prepared.state_changes;
        let (inserts, deletes) = state_changes.as_ref();
        let mut proof_verify_elapsed = Duration::ZERO;
        let mut apply_elapsed = Duration::ZERO;
        let mut end_block_elapsed = Duration::ZERO;
        let mut persist_elapsed = Duration::ZERO;

        if block.header.height != self.state.status.height + 1 {
            return Err(ChainError::Transaction(
                "Stale preparation: Chain height advanced since block was prepared".into(),
            ));
        }
        if prepared.parent_state_root != self.state.last_state_root {
            return Err(ChainError::Transaction(
                "Stale preparation: Parent state root has changed since block was prepared".into(),
            ));
        }

        // --- VERIFY PROOFS ---
        let backend = {
            let tree_arc = workload.state_tree();
            let guard = tree_arc.read().await;
            guard.clone()
        };
        // Unused verify commit
        let _commit = backend
            .commitment_from_bytes(&prepared.parent_state_root)
            .map_err(ChainError::State)?;

        let proof_verify_started = Instant::now();
        for (i, _tx) in block.transactions.iter().enumerate() {
            let proof_bytes = prepared.tx_proofs.get(i).ok_or_else(|| {
                ChainError::Transaction("Missing proof for transaction".to_string())
            })?;

            if proof_bytes.is_empty() {
                // Transaction failed or produced no proof, skip verification
                continue;
            }

            // [FIX] Remove generic argument from UnifiedProof
            let proof: UnifiedProof =
                codec::from_bytes_canonical(proof_bytes).map_err(ChainError::Transaction)?;

            match proof {
                // [FIX] UTXO Removed. Settlement currently has empty proof, so nothing to verify against backend yet.
                // In future, if Settlement returns Merkle proofs for balances, verify them here.
                UnifiedProof::Settlement => {
                    // No-op for now
                }
                _ => { /* Verification for other proof types would go here */ }
            }
        }
        proof_verify_elapsed = proof_verify_started.elapsed();

        drop(backend); // Release read lock before acquiring write lock

        let publish_aft_ordering = self.consensus_engine.consensus_type() == ConsensusType::Aft;
        let current_bulletin = if publish_aft_ordering {
            Some(
                build_reference_bulletin_commitment(
                    block.header.height,
                    block_timestamp_ms,
                    &block.transactions,
                )
                .map_err(ChainError::Transaction)?,
            )
        } else {
            None
        };
        let mut next_status = self.state.status.clone();
        let mut committed_block_bytes: Option<Vec<u8>> = None;
        let supplied_timestamp_ms = block.header.timestamp_ms;
        let supplied_legacy_timestamp = block.header.timestamp;
        let supplied_state_root = block.header.state_root.clone();
        let supplied_transactions_root = block.header.transactions_root.clone();
        let supplied_gas_used = block.header.gas_used;
        let header_carries_external_finality = !block.header.signature.is_empty()
            || block.header.guardian_certificate.is_some()
            || block.header.sealed_finality_proof.is_some()
            || block.header.canonical_order_certificate.is_some()
            || block.header.oracle_counter != 0
            || block.header.oracle_trace_hash != [0u8; 32];
        let header_carries_materialized_execution = supplied_timestamp_ms > 0
            || !supplied_state_root.0.is_empty()
            || !supplied_transactions_root.is_empty()
            || supplied_gas_used > 0;
        let externally_finalized_header =
            header_carries_external_finality && header_carries_materialized_execution;

        let authoritative_gas_used = if externally_finalized_header && supplied_gas_used > 0 {
            supplied_gas_used
        } else {
            prepared.gas_used
        };

        let final_state_root_bytes = {
            let state_tree_arc = workload.state_tree();
            let mut state = state_tree_arc.write().await;

            let apply_started = Instant::now();
            state.begin_block_writes(block.header.height);
            state.batch_apply(inserts, deletes)?;
            apply_elapsed = apply_started.elapsed();
            if apply_elapsed.as_millis() >= 250 {
                tracing::warn!(
                    target: "execution",
                    height = block.header.height,
                    tx_count = block.transactions.len(),
                    elapsed_ms = apply_elapsed.as_millis(),
                    "state.batch_apply() is slow"
                );
            }

            let end_block_started = Instant::now();
            let upgrade_count = end_block::handle_service_upgrades(
                &mut self.service_manager,
                block.header.height,
                &mut *state,
            )
            .await?;

            if upgrade_count > 0 {
                self.services =
                    ServiceDirectory::new(self.service_manager.all_services_as_trait_objects());
                // MODIFIED: Refresh the metadata cache after upgrades.
                self.service_meta_cache.clear();
                let service_iter = state.prefix_scan(UPGRADE_ACTIVE_SERVICE_PREFIX)?;
                for item in service_iter {
                    let (_key, meta_bytes) = item?;
                    if let Ok(meta) = codec::from_bytes_canonical::<ActiveServiceMeta>(&meta_bytes)
                    {
                        self.service_meta_cache
                            .insert(meta.id.clone(), Arc::new(meta));
                    }
                }
            }

            // [FIX] Update timestamp handling
            let ts_ns: u64 = (block_timestamp_ms as u128)
                .saturating_mul(1_000_000)
                .try_into()
                .map_err(|_| ChainError::Transaction("Timestamp overflow".to_string()))?;

            let end_block_ctx = TxContext {
                block_height: block.header.height,
                block_timestamp: ts_ns,
                chain_id: self.state.chain_id,
                signer_account_id: AccountId::default(),
                services: &self.services,
                simulation: false,
                is_internal: true,
            };

            end_block::run_on_end_block_hooks(
                &self.services,
                &mut *state,
                &end_block_ctx,
                &self.service_meta_cache,
            )
            .await?;
            end_block::handle_validator_set_promotion(&mut *state, block.header.height)?;
            end_block::handle_timing_update(
                &mut *state,
                block.header.height,
                authoritative_gas_used,
            )?;
            end_block_elapsed = end_block_started.elapsed();
            if end_block_elapsed.as_millis() >= 250 {
                tracing::warn!(
                    target: "execution",
                    height = block.header.height,
                    tx_count = block.transactions.len(),
                    elapsed_ms = end_block_elapsed.as_millis(),
                    "end-block hooks or timing update are slow"
                );
            }

            if let Some(bulletin) = current_bulletin.as_ref() {
                state.insert(
                    &aft_bulletin_commitment_key(bulletin.height),
                    &codec::to_bytes_canonical(bulletin).map_err(ChainError::Transaction)?,
                )?;
            }

            next_status.height = block.header.height;
            next_status.set_latest_timestamp_ms(block_timestamp_ms);
            next_status.total_transactions = next_status
                .total_transactions
                .saturating_add(block.transactions.len() as u64);

            let status_bytes =
                codec::to_bytes_canonical(&next_status).map_err(ChainError::Transaction)?;
            state.insert(STATUS_KEY, &status_bytes)?;

            let final_root_bytes = state.root_commitment().as_ref().to_vec();
            if externally_finalized_header {
                if supplied_timestamp_ms > 0 && supplied_timestamp_ms != block_timestamp_ms {
                    return Err(ChainError::Transaction(format!(
                        "Committed block timestamp_ms mismatch: header={}, computed={}",
                        supplied_timestamp_ms, block_timestamp_ms
                    )));
                }
                if supplied_legacy_timestamp != 0
                    && supplied_legacy_timestamp
                        != timestamp_millis_to_legacy_seconds(block_timestamp_ms)
                {
                    return Err(ChainError::Transaction(format!(
                        "Committed block timestamp mismatch: header={}, computed={}",
                        supplied_legacy_timestamp,
                        timestamp_millis_to_legacy_seconds(block_timestamp_ms)
                    )));
                }
                if !supplied_state_root.0.is_empty() && supplied_state_root.0 != final_root_bytes {
                    return Err(ChainError::Transaction(
                        "Committed block state_root mismatch".to_string(),
                    ));
                }
                if !supplied_transactions_root.is_empty()
                    && supplied_transactions_root != prepared.transactions_root
                {
                    return Err(ChainError::Transaction(
                        "Committed block transactions_root mismatch".to_string(),
                    ));
                }
                if supplied_gas_used > 0 && supplied_gas_used != prepared.gas_used {
                    tracing::warn!(
                        target: "execution",
                        height = block.header.height,
                        tx_count = block.transactions.len(),
                        header_gas_used = supplied_gas_used,
                        computed_gas_used = prepared.gas_used,
                        "Committed block gas_used diverged from local replay; using authoritative header gas_used"
                    );
                }
            }

            let canonical_collapse_object = if self.consensus_engine.consensus_type()
                == ConsensusType::Aft
                && externally_finalized_header
            {
                    let previous_canonical_collapse = if block.header.height <= 1 {
                        None
                    } else {
                        let key = aft_canonical_collapse_object_key(block.header.height - 1);
                        let Some(raw) = state.get(&key)? else {
                            return Err(ChainError::Transaction(format!(
                                "Externally finalized AFT block at height {} is missing the previous canonical collapse object at height {}",
                                block.header.height,
                                block.header.height - 1
                            )));
                        };
                        Some(
                            codec::from_bytes_canonical(&raw).map_err(ChainError::Transaction)?,
                        )
                    };
                    let mut collapse_header = block.header.clone();
                    collapse_header.timestamp =
                        timestamp_millis_to_legacy_seconds(block_timestamp_ms);
                    collapse_header.timestamp_ms = block_timestamp_ms;
                    collapse_header.state_root = StateRoot(final_root_bytes.clone());
                    collapse_header.transactions_root = prepared.transactions_root.clone();
                    collapse_header.gas_used = authoritative_gas_used;
                    Some(
                        derive_canonical_collapse_object_with_previous(
                            &collapse_header,
                            &block.transactions,
                            previous_canonical_collapse.as_ref(),
                        )
                        .map_err(|error| {
                            ChainError::Transaction(format!(
                                "Externally finalized AFT block is missing a decisive canonical collapse object: {error}"
                            ))
                        })?,
                    )
                } else {
                    None
                };

            if let Some(canonical_collapse_object) = canonical_collapse_object.as_ref() {
                state.insert(
                    &aft_canonical_collapse_object_key(canonical_collapse_object.height),
                    &codec::to_bytes_canonical(canonical_collapse_object)
                        .map_err(ChainError::Transaction)?,
                )?;
            }

            block.header.timestamp = timestamp_millis_to_legacy_seconds(block_timestamp_ms);
            block.header.timestamp_ms = block_timestamp_ms;
            block.header.state_root = StateRoot(final_root_bytes.clone());
            block.header.transactions_root = prepared.transactions_root;
            block.header.gas_used = authoritative_gas_used;
            let block_bytes = codec::to_bytes_canonical(&block).map_err(ChainError::Transaction)?;

            let persist_started = Instant::now();
            state
                .commit_version_persist_with_block(
                    block.header.height,
                    &*workload.store,
                    &block_bytes,
                )
                .await?;
            persist_elapsed = persist_started.elapsed();
            if persist_elapsed.as_millis() >= 250 {
                tracing::warn!(
                    target: "execution",
                    height = block.header.height,
                    tx_count = block.transactions.len(),
                    elapsed_ms = persist_elapsed.as_millis(),
                    "commit_version_persist() is slow"
                );
            }
            committed_block_bytes = Some(block_bytes);

            {
                let final_commitment = state.commitment_from_bytes(&final_root_bytes)?;
                if cfg!(debug_assertions) && !state.version_exists_for_root(&final_commitment) {
                    return Err(ChainError::State(StateError::Validation(format!("FATAL INVARIANT VIOLATION: The committed root for height {} is not mapped to a queryable version!", block.header.height))));
                }
                if self.consensus_engine.consensus_type() == ConsensusType::ProofOfStake {
                    match state.get_with_proof_at(&final_commitment, VALIDATOR_SET_KEY) {
                        Ok((Membership::Present(_), _)) => {
                            tracing::info!(target: "pos_finality_check", event = "validator_set_provable", height = block.header.height, root = hex::encode(&final_root_bytes), "OK");
                        }
                        Ok((other, _)) => {
                            return Err(ChainError::State(StateError::Validation(format!("INVARIANT: Validator set missing at end of block {} (membership={:?}, root={})", block.header.height, other, hex::encode(&final_root_bytes)))));
                        }
                        Err(e) => {
                            return Err(ChainError::State(StateError::Validation(format!("INVARIANT: get_with_proof_at failed for validator set at end of block {}: {}", block.header.height, e))));
                        }
                    }
                }
            }
            final_root_bytes
        };
        self.state.last_state_root = final_state_root_bytes;

        let anchor = StateRoot(block.header.state_root.0.clone())
            .to_anchor()
            .map_err(|e| ChainError::Transaction(e.to_string()))?;
        tracing::info!(target: "execution", event = "commit", height = block.header.height, state_root = hex::encode(&block.header.state_root.0), anchor = hex::encode(anchor.as_ref()));

        let _block_bytes = committed_block_bytes
            .take()
            .ok_or_else(|| ChainError::Transaction("Committed block bytes missing".to_string()))?;
        let store_elapsed = Duration::ZERO;

        // Expose the new tip only after the committed block is queryable from storage.
        self.state.status = next_status;

        if benchmark_trace {
            eprintln!(
                "[BENCH-EXEC] commit_block height={} tx_count={} proof_verify_ms={} apply_ms={} end_block_ms={} persist_ms={} put_block_ms={} total_ms={}",
                block.header.height,
                block.transactions.len(),
                proof_verify_elapsed.as_millis(),
                apply_elapsed.as_millis(),
                end_block_elapsed.as_millis(),
                persist_elapsed.as_millis(),
                store_elapsed.as_millis(),
                commit_started.elapsed().as_millis(),
            );
            tracing::info!(
                target: "execution_bench",
                height = block.header.height,
                tx_count = block.transactions.len(),
                proof_verify_ms = proof_verify_elapsed.as_millis(),
                apply_ms = apply_elapsed.as_millis(),
                end_block_ms = end_block_elapsed.as_millis(),
                persist_ms = persist_elapsed.as_millis(),
                put_block_ms = store_elapsed.as_millis(),
                total_ms = commit_started.elapsed().as_millis(),
                "commit_block timing"
            );
        }

        if self.state.recent_blocks.len() >= self.state.max_recent_blocks {
            self.state.recent_blocks.remove(0);
        }
        self.state.recent_blocks.push(block.clone());

        let events = vec![];
        Ok((block, events))
    }

    fn create_block(
        &self,
        transactions: Vec<ChainTransaction>,
        current_validator_set: &[Vec<u8>],
        _known_peers_bytes: &[Vec<u8>],
        producer_keypair: &Keypair,
        expected_timestamp: u64,
        view: u64, // <--- NEW parameter
    ) -> Result<Block<ChainTransaction>, ChainError> {
        let height = self.state.status.height + 1;
        let (parent_hash_vec, parent_state_root) = self.state.recent_blocks.last().map_or_else(
            || {
                let parent_hash =
                    to_root_hash(&self.state.last_state_root).map_err(ChainError::State)?;
                Ok((
                    parent_hash.to_vec(),
                    StateRoot(self.state.last_state_root.clone()),
                ))
            },
            |b| -> Result<_, ChainError> {
                Ok((
                    b.header.hash().unwrap_or(vec![0; 32]),
                    b.header.state_root.clone(),
                ))
            },
        )?;

        let parent_hash: [u8; 32] = parent_hash_vec.try_into().map_err(|_| {
            ChainError::Block(BlockError::Hash("Parent hash was not 32 bytes".into()))
        })?;

        let producer_pubkey = producer_keypair.public().encode_protobuf();
        // [FIX] Use CONSTANT instead of ENUM VARIANT for the new SignatureSuite struct
        let suite = SignatureSuite::ED25519;
        let producer_pubkey_hash = account_id_from_key_material(suite, &producer_pubkey)?;
        let producer_account_id = AccountId(producer_pubkey_hash);

        let timestamp = expected_timestamp;

        let mut header = BlockHeader {
            height,
            view, // <--- Set view
            parent_hash,
            parent_state_root,
            state_root: StateRoot(vec![]),
            transactions_root: vec![],
            timestamp,
            timestamp_ms: timestamp.saturating_mul(1000),
            gas_used: 0,
            validator_set: current_validator_set.to_vec(),
            producer_account_id,
            producer_key_suite: suite,
            producer_pubkey_hash,
            producer_pubkey: producer_pubkey.to_vec(),
            signature: vec![],
            // [FIXED] Initialize new fields with default values.
            // The Oracle will overwrite these during the signing process.
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            parent_qc: QuorumCertificate::default(), // [FIX] Added field
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        };

        let preimage = header
            .to_preimage_for_signing()
            .map_err(|e| ChainError::Transaction(e.to_string()))?;
        let signature = producer_keypair
            .sign(&preimage)
            .map_err(|e| ChainError::Transaction(e.to_string()))?;
        header.signature = signature;

        Ok(Block {
            header,
            transactions,
        })
    }

    fn get_block(&self, height: u64) -> Option<&Block<ChainTransaction>> {
        self.state
            .recent_blocks
            .iter()
            .find(|b| b.header.height == height)
    }

    fn get_blocks_since(&self, height: u64) -> Vec<Block<ChainTransaction>> {
        self.state
            .recent_blocks
            .iter()
            .filter(|b| b.header.height > height)
            .cloned()
            .collect()
    }

    async fn get_validator_set_for(&self, height: u64) -> Result<Vec<Vec<u8>>, ChainError> {
        let workload = &self.workload_container;
        let state = workload.state_tree();
        let state_guard = state.read().await;
        let bytes = state_guard
            .get(VALIDATOR_SET_KEY)?
            .ok_or(ChainError::from(StateError::KeyNotFound))?;
        let sets = read_validator_sets(&bytes)?;
        let effective_set = ioi_types::app::effective_set_for_height(&sets, height);
        Ok(effective_set
            .validators
            .iter()
            .map(|v| v.account_id.0.to_vec())
            .collect())
    }

    async fn get_staked_validators(&self) -> Result<BTreeMap<AccountId, u64>, ChainError> {
        let state = self.workload_container.state_tree();
        let guard = state.read().await;
        let bytes = guard
            .get(VALIDATOR_SET_KEY)?
            .ok_or_else(|| ChainError::from(StateError::KeyNotFound))?;
        let sets = read_validator_sets(&bytes)?;
        Ok(sets
            .current
            .validators
            .into_iter()
            .map(|v| (v.account_id, v.weight as u64))
            .collect())
    }

    async fn get_next_staked_validators(&self) -> Result<BTreeMap<AccountId, u64>, ChainError> {
        let state = self.workload_container.state_tree();
        let guard = state.read().await;
        let bytes = guard
            .get(VALIDATOR_SET_KEY)?
            .ok_or_else(|| ChainError::from(StateError::KeyNotFound))?;
        let sets = read_validator_sets(&bytes)?;
        let effective_set = sets.next.as_ref().unwrap_or(&sets.current);
        Ok(effective_set
            .validators
            .iter()
            .map(|v| (v.account_id, v.weight as u64))
            .collect())
    }
}

impl<CS, ST> ExecutionMachine<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + ProofProvider
        + Send
        + Sync
        + 'static
        + Clone,
    <CS as CommitmentScheme>::Value: From<Vec<u8>> + AsRef<[u8]> + Send + Sync + std::fmt::Debug,
    <CS as CommitmentScheme>::Proof: AsRef<[u8]>
        + Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Commitment: std::fmt::Debug + Send + Sync,
{
    fn resolve_next_block_timestamp_ms(
        &self,
        state: &dyn StateAccess,
        block_height: u64,
    ) -> Result<u64, ChainError> {
        let params_bytes = state
            .get(BLOCK_TIMING_PARAMS_KEY)?
            .ok_or_else(|| ChainError::Transaction("Missing BlockTimingParams".into()))?;
        let runtime_bytes = state
            .get(BLOCK_TIMING_RUNTIME_KEY)?
            .ok_or_else(|| ChainError::Transaction("Missing BlockTimingRuntime".into()))?;
        let params: BlockTimingParams =
            codec::from_bytes_canonical(&params_bytes).map_err(ChainError::Transaction)?;
        let runtime: BlockTimingRuntime =
            codec::from_bytes_canonical(&runtime_bytes).map_err(ChainError::Transaction)?;
        let parent_gas_used = self
            .state
            .recent_blocks
            .last()
            .map(|block| block.header.gas_used)
            .unwrap_or(0);

        compute_next_timestamp_ms(
            &params,
            &runtime,
            block_height.saturating_sub(1),
            self.state.status.latest_timestamp_ms_or_legacy(),
            parent_gas_used,
        )
        .ok_or_else(|| ChainError::Transaction("Timestamp overflow".into()))
    }
}
