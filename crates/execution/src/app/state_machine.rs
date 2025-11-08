// Path: crates/execution/src/app/state_machine.rs

use super::Chain;
use async_trait::async_trait;
use ioi_api::app::{Block, BlockHeader, ChainStatus, ChainTransaction};
use ioi_api::chain::{ChainStateMachine, PreparedBlock, ChainView};
use ioi_api::commitment::CommitmentScheme;
use ioi_api::state::{PinGuard, StateManager, StateOverlay};
use ioi_api::transaction::context::TxContext;
use ioi_api::validator::WorkloadContainer;
use ioi_tx::unified::UnifiedTransactionModel;
// FIX: Add missing imports for functions and types used in this module.
use ioi_types::app::{
    account_id_from_key_material, compute_interval_from_parent_state, read_validator_sets,
    to_root_hash, write_validator_sets, AccountId, BlockTimingParams, BlockTimingRuntime,
    SignatureSuite, StateRoot,
};
use ioi_types::codec;
// FIX: Add missing import for the ConsensusType enum.
use ioi_types::config::ConsensusType;
use ioi_types::error::{BlockError, ChainError, StateError};
use ioi_types::keys::{STATUS_KEY, VALIDATOR_SET_KEY};
use ioi_types::service_configs::Capabilities;
use ibc_primitives::Timestamp;
use libp2p::identity::Keypair;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;

#[async_trait]
impl<CS, ST> ChainStateMachine<CS, UnifiedTransactionModel<CS>, ST> for Chain<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Clone,
    <CS as CommitmentScheme>::Value: From<Vec<u8>> + AsRef<[u8]> + Send + Sync + std::fmt::Debug,
    <CS as CommitmentScheme>::Proof:
        AsRef<[u8]> + Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Commitment: From<Vec<u8>>,
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
        workload: &WorkloadContainer<ST>,
    ) -> Result<PreparedBlock, ChainError> {
        let expected_height = self.state.status.height + 1;
        if block.header.height != expected_height {
            return Err(ChainError::Block(BlockError::InvalidHeight {
                expected: expected_height,
                got: block.header.height,
            }));
        }

        let state_changes = {
            let _pin_guard = PinGuard::new(workload.pins.clone(), self.state.status.height).await;
            let snapshot_state = {
                let state_tree_arc = workload.state_tree();
                let base_state = state_tree_arc.read().await;
                base_state.clone()
            };
            let mut overlay = StateOverlay::new(&snapshot_state);

            for tx in &block.transactions {
                if let Err(e) = self
                    .process_transaction(
                        tx,
                        &mut overlay,
                        block.header.height,
                        block.header.timestamp,
                    )
                    .await
                {
                    tracing::error!(target: "block", height = block.header.height, error = %e, "process_transaction failed; rejecting block proposal");
                    return Err(e);
                }
            }

            overlay.into_ordered_batch()
        };

        let transactions_root = ioi_types::codec::to_bytes_canonical(&block.transactions)
            .map_err(ChainError::Transaction)?;
        let vs_bytes = self
            .get_validator_set_for(workload, block.header.height)
            .await?;
        let validator_set_hash = ioi_crypto::algorithms::hash::sha256(vs_bytes.concat())
            .map_err(|e| ChainError::Transaction(e.to_string()))?;

        Ok(PreparedBlock {
            block,
            state_changes: Arc::new(state_changes),
            parent_state_root: self.state.last_state_root.clone(),
            transactions_root,
            validator_set_hash,
        })
    }

    async fn commit_block(
        &mut self,
        prepared: PreparedBlock,
        workload: &WorkloadContainer<ST>,
    ) -> Result<(Block<ChainTransaction>, Vec<Vec<u8>>), ChainError> {
        let mut block = prepared.block;
        let state_changes = prepared.state_changes;
        let (inserts, deletes) = state_changes.as_ref();

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

        let final_state_root_bytes = {
            let state_tree_arc = workload.state_tree();
            let mut state = state_tree_arc.write().await;

            state.begin_block_writes(block.header.height);
            state.batch_apply(inserts, deletes)?;

            let upgrade_count = self
                .service_manager
                .apply_upgrades_at_height(block.header.height, &mut *state)
                .await
                .map_err(|e| ChainError::State(StateError::Apply(e.to_string())))?;
            if upgrade_count > 0 {
                tracing::info!(target: "chain", event = "module_upgrade", height = block.header.height, num_applied = upgrade_count, "Successfully applied on-chain service upgrades.");
                let all_services = self.service_manager.all_services();
                let services_for_dir: Vec<Arc<dyn ioi_api::services::BlockchainService>> = all_services
                    .iter()
                    .map(|s| s.clone() as Arc<dyn ioi_api::services::BlockchainService>)
                    .collect();
                self.services = ioi_api::services::access::ServiceDirectory::new(services_for_dir);
            }

            let end_block_ctx = TxContext {
                block_height: block.header.height,
                block_timestamp: Timestamp::from_nanoseconds(
                    block.header.timestamp * 1_000_000_000,
                )
                .map_err(|e| ChainError::Transaction(format!("Invalid timestamp: {}", e)))?,
                chain_id: self.state.chain_id,
                signer_account_id: AccountId::default(),
                services: &self.services,
                simulation: false,
                is_internal: true,
            };
            for service in self.services.services_in_deterministic_order() {
                if service.capabilities().contains(Capabilities::ON_END_BLOCK) {
                    if let Some(hook) = service.as_on_end_block() {
                        hook.on_end_block(&mut *state, &end_block_ctx)
                            .await
                            .map_err(ChainError::State)?;
                    }
                }
            }

            match state.get(VALIDATOR_SET_KEY)? {
                Some(ref bytes) => {
                    let mut sets = read_validator_sets(bytes)?;
                    let mut modified = false;
                    if let Some(next_vs) = &sets.next {
                        if block.header.height >= next_vs.effective_from_height {
                            tracing::info!(target: "chain", event = "validator_set_promotion", height = block.header.height, "Promoting validator set");
                            let promoted_from_height = next_vs.effective_from_height;
                            sets.current = next_vs.clone();
                            if sets
                                .next
                                .as_ref()
                                .is_some_and(|n| n.effective_from_height == promoted_from_height)
                            {
                                sets.next = None;
                            }
                            modified = true;
                        }
                    };
                    let out = write_validator_sets(&sets)?;
                    state.insert(VALIDATOR_SET_KEY, &out)?;
                    if modified {
                        tracing::info!(target: "chain", event = "validator_set_promotion", "Validator set updated and carried forward.");
                    } else {
                        tracing::debug!(target: "chain", event = "validator_set_promotion", "Validator set carried forward unchanged.");
                    }
                }
                None => {
                    tracing::error!(target: "chain", event = "end_block", height = block.header.height, "MISSING VALIDATOR_SET_KEY before commit.");
                }
            }

            let timing_params_bytes = state.get(super::BLOCK_TIMING_PARAMS_KEY)?;
            let timing_runtime_bytes = state.get(super::BLOCK_TIMING_RUNTIME_KEY)?;
            if let (Some(params_bytes), Some(runtime_bytes)) =
                (timing_params_bytes, timing_runtime_bytes)
            {
                let params: BlockTimingParams =
                    codec::from_bytes_canonical(&params_bytes).map_err(ChainError::Transaction)?;
                let old_runtime: BlockTimingRuntime =
                    codec::from_bytes_canonical(&runtime_bytes).map_err(ChainError::Transaction)?;
                let mut new_runtime = old_runtime.clone();

                if params.retarget_every_blocks > 0
                    && block.header.height % params.retarget_every_blocks as u64 == 0
                {
                    let gas_used_this_block = 0;
                    // FIX: Call the newly imported function directly.
                    let next_interval = compute_interval_from_parent_state(
                        &params,
                        &old_runtime,
                        block.header.height,
                        gas_used_this_block,
                    );
                    let alpha = params.ema_alpha_milli as u128;
                    new_runtime.ema_gas_used = (alpha * gas_used_this_block as u128
                        + (1000 - alpha) * old_runtime.ema_gas_used)
                        / 1000;
                    new_runtime.effective_interval_secs = next_interval;

                    if new_runtime.ema_gas_used != old_runtime.ema_gas_used
                        || new_runtime.effective_interval_secs
                            != old_runtime.effective_interval_secs
                    {
                        state
                            .insert(
                                super::BLOCK_TIMING_RUNTIME_KEY,
                                &codec::to_bytes_canonical(&new_runtime)
                                    .map_err(ChainError::Transaction)?,
                            )?;
                    }
                }
            }

            self.state.status.height = block.header.height;
            self.state.status.latest_timestamp = block.header.timestamp;
            self.state.status.total_transactions += block.transactions.len() as u64;

            let status_bytes = codec::to_bytes_canonical(&self.state.status)
                .map_err(|e| ChainError::Transaction(e.to_string()))?;
            state.insert(STATUS_KEY, &status_bytes)?;

            state.commit_version_persist(block.header.height, &*workload.store)?;
            let final_root_bytes = state.root_commitment().as_ref().to_vec();

            {
                use ioi_types::app::Membership;
                let final_commitment = state.commitment_from_bytes(&final_root_bytes)?;
                if cfg!(debug_assertions) && !state.version_exists_for_root(&final_commitment) {
                    return Err(ChainError::State(StateError::Validation(format!("FATAL INVARIANT VIOLATION: The committed root for height {} is not mapped to a queryable version!", block.header.height))));
                }
                // FIX: Use the newly imported enum directly.
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

        block.header.state_root = StateRoot(final_state_root_bytes.clone());
        self.state.last_state_root = final_state_root_bytes;

        let anchor = StateRoot(block.header.state_root.0.clone())
            .to_anchor()
            .map_err(|e| ChainError::Transaction(e.to_string()))?;
        tracing::info!(target: "chain", event = "commit", height = block.header.height, state_root = hex::encode(&block.header.state_root.0), anchor = hex::encode(anchor.as_ref()));

        let block_bytes = codec::to_bytes_canonical(&block)
            .map_err(|e| ChainError::Transaction(e.to_string()))?;
        workload
            .store
            .put_block(block.header.height, &block_bytes)
            .map_err(|e| ChainError::State(StateError::Backend(e.to_string())))?;

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
        let suite = SignatureSuite::Ed25519;
        let producer_pubkey_hash = account_id_from_key_material(suite, &producer_pubkey)?;
        let producer_account_id = AccountId(producer_pubkey_hash);

        let timestamp = expected_timestamp;

        let mut header = BlockHeader {
            height,
            parent_hash,
            parent_state_root,
            state_root: StateRoot(vec![]),
            transactions_root: vec![],
            timestamp,
            validator_set: current_validator_set.to_vec(),
            producer_account_id,
            producer_key_suite: suite,
            producer_pubkey_hash,
            producer_pubkey,
            signature: vec![],
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

    async fn get_validator_set_for(
        &self,
        workload: &WorkloadContainer<ST>,
        height: u64,
    ) -> Result<Vec<Vec<u8>>, ChainError> {
        let state = workload.state_tree();
        let state_guard = state.read().await;
        let bytes = state_guard
            .get(VALIDATOR_SET_KEY)?
            .ok_or(ChainError::from(StateError::KeyNotFound))?;
        let sets = read_validator_sets(&bytes)?;
        let effective_set = Self::select_set_for_height(&sets, height);
        Ok(effective_set
            .validators
            .iter()
            .map(|v| v.account_id.0.to_vec())
            .collect())
    }

    async fn get_staked_validators(
        &self,
        _workload: &WorkloadContainer<ST>,
    ) -> Result<BTreeMap<AccountId, u64>, ChainError> {
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

    async fn get_next_staked_validators(
        &self,
        _workload: &WorkloadContainer<ST>,
    ) -> Result<BTreeMap<AccountId, u64>, ChainError> {
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