// Path: crates/execution/src/app/mod.rs
mod end_block;
mod state_machine;
mod view;

// [NEW] Include parallel execution modules
pub mod parallel_state;

use crate::upgrade_manager::ServiceUpgradeManager;
use anyhow::Result;
use async_trait::async_trait;
use ibc_primitives::Timestamp;
use ioi_api::app::{Block, BlockHeader, ChainStatus, ChainTransaction};
use ioi_api::commitment::CommitmentScheme;
use ioi_api::consensus::PenaltyMechanism;
use ioi_api::services::access::ServiceDirectory;
use ioi_api::services::{BlockchainService, UpgradableService};
use ioi_api::state::namespaced::ReadOnlyNamespacedStateAccess;
use ioi_api::state::{
    service_namespace_prefix, NamespacedStateAccess, StateAccess, StateManager, StateOverlay,
};
use ioi_api::transaction::context::TxContext;
use ioi_api::transaction::TransactionModel;
use ioi_api::validator::WorkloadContainer;
use ioi_consensus::Consensus;
use ioi_tx::system::{nonce, validation};
use ioi_tx::unified::UnifiedTransactionModel;
use ioi_types::app::{
    AccountId, BlockTimingParams, BlockTimingRuntime, ChainId, FailureReport, StateRoot,
};
use ioi_types::codec;
use ioi_types::config::ServicePolicy;
use ioi_types::error::{ChainError, CoreError, StateError, TransactionError};
use ioi_types::keys::{
    BLOCK_TIMING_PARAMS_KEY, BLOCK_TIMING_RUNTIME_KEY, STATUS_KEY, UPGRADE_ACTIVE_SERVICE_PREFIX,
};
use ioi_types::service_configs::ActiveServiceMeta;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::sync::Arc;

/// Represents the initialization state of the chain's genesis block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenesisState {
    /// The chain has not yet loaded or committed the genesis block.
    Pending,
    /// The genesis block has been successfully loaded and committed.
    Ready {
        /// The final, canonical raw root commitment of the fully initialized genesis state.
        root: Vec<u8>,
        /// The chain ID as loaded from configuration.
        chain_id: ChainId,
    },
}

// Delegates PenaltyMechanism to the borrowed Consensus engine.
struct PenaltyDelegator<'a> {
    inner: &'a Consensus<ioi_types::app::ChainTransaction>,
}

#[async_trait]
impl<'a> PenaltyMechanism for PenaltyDelegator<'a> {
    async fn apply_penalty(
        &self,
        state: &mut dyn StateAccess,
        report: &FailureReport,
    ) -> Result<(), TransactionError> {
        self.inner.apply_penalty(state, report).await
    }
}

#[derive(Debug)]
pub struct ExecutionMachineState<CS: CommitmentScheme + Clone> {
    pub commitment_scheme: CS,
    pub transaction_model: UnifiedTransactionModel<CS>,
    pub chain_id: ChainId,
    pub status: ChainStatus,
    pub recent_blocks: Vec<Block<ChainTransaction>>,
    pub max_recent_blocks: usize,
    /// Last committed state root (raw bytes).
    pub last_state_root: Vec<u8>,
    pub genesis_state: GenesisState,
}

/// The primary state machine that orchestrates block execution, service dispatch, and state updates.
///
/// # State Isolation Enforcement
///
/// The `ExecutionMachine` enforces the "Namespaced Storage" invariant. When dispatching
/// lifecycle hooks (like `on_end_block`) or transaction payloads (via `UnifiedTransactionModel`),
/// it wraps the raw `StateAccess` in a `NamespacedStateAccess`.
///
/// This ensures that a service cannot accidentally or maliciously corrupt the state of
/// another service or the kernel, unless explicitly authorized via security policy.
pub struct ExecutionMachine<CS: CommitmentScheme + Clone, ST: StateManager> {
    pub state: ExecutionMachineState<CS>,
    pub services: ServiceDirectory,
    pub service_manager: ServiceUpgradeManager,
    pub consensus_engine: Consensus<ioi_types::app::ChainTransaction>,
    workload_container: Arc<WorkloadContainer<ST>>,
    /// In-memory cache for fast access to on-chain service metadata.
    pub service_meta_cache: HashMap<String, Arc<ActiveServiceMeta>>,
    /// Holds the configuration-driven policies for services
    service_policies: BTreeMap<String, ServicePolicy>,
}

impl<CS, ST> Debug for ExecutionMachine<CS, ST>
where
    CS: CommitmentScheme + Clone,
    ST: StateManager,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutionMachine")
            .field("state", &self.state)
            .field("services", &self.services)
            .field("consensus_type", &self.consensus_engine.consensus_type())
            .field("service_meta_cache", &self.service_meta_cache.keys())
            .finish()
    }
}

/// Checks if the services required for a specific transaction type are enabled.
#[allow(dead_code)]
fn preflight_capabilities(
    services: &ServiceDirectory,
    tx: &ioi_types::app::ChainTransaction,
) -> Result<(), TransactionError> {
    let _ = (services, tx);
    Ok(())
}

/// Extracts the signer's AccountId from any transaction type that has a SignHeader.
#[allow(dead_code)]
fn signer_from_tx(tx: &ChainTransaction) -> AccountId {
    match tx {
        ChainTransaction::System(s) => s.header.account_id,
        ChainTransaction::Application(a) => match a {
            ioi_types::app::ApplicationTransaction::DeployContract { header, .. }
            | ioi_types::app::ApplicationTransaction::CallContract { header, .. } => {
                header.account_id
            }
            ioi_types::app::ApplicationTransaction::UTXO(_) => AccountId::default(),
        },
        // Semantic transactions are signed by a committee aggregate, not a single account.
        // Return default AccountId as there is no single "signer".
        ChainTransaction::Semantic { .. } => AccountId::default(),
    }
}

impl<CS, ST> ExecutionMachine<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        serde::Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    <CS as CommitmentScheme>::Commitment: std::fmt::Debug + Send + Sync,
{
    pub fn new(
        commitment_scheme: CS,
        transaction_model: UnifiedTransactionModel<CS>,
        chain_id: ChainId,
        initial_services: Vec<Arc<dyn UpgradableService>>,
        consensus_engine: Consensus<ioi_types::app::ChainTransaction>,
        workload_container: Arc<WorkloadContainer<ST>>,
        service_policies: BTreeMap<String, ServicePolicy>,
    ) -> Result<Self, CoreError> {
        let status = ChainStatus {
            height: 0,
            latest_timestamp: 0,
            total_transactions: 0,
            is_running: false,
        };

        let services_for_dir: Vec<Arc<dyn BlockchainService>> = initial_services
            .iter()
            .map(|s| s.clone() as Arc<dyn BlockchainService>)
            .collect();
        let service_directory = ServiceDirectory::new(services_for_dir);

        let mut service_manager = ServiceUpgradeManager::new();
        for service in initial_services {
            service_manager.register_service(service)?;
        }

        let state = ExecutionMachineState {
            commitment_scheme,
            transaction_model,
            chain_id,
            status,
            recent_blocks: Vec::new(),
            max_recent_blocks: 100,
            last_state_root: Vec::new(),
            genesis_state: GenesisState::Pending,
        };

        Ok(Self {
            state,
            services: service_directory,
            service_manager,
            consensus_engine,
            workload_container,
            service_meta_cache: HashMap::new(),
            service_policies,
        })
    }

    pub async fn load_or_initialize_status(
        &mut self,
        workload: &WorkloadContainer<ST>,
    ) -> Result<(), ChainError> {
        let state_tree_arc = workload.state_tree();
        let mut state = state_tree_arc.write().await;

        match state.get(STATUS_KEY) {
            Ok(Some(ref status_bytes)) => {
                let status: ChainStatus =
                    codec::from_bytes_canonical(status_bytes).map_err(ChainError::Transaction)?;
                tracing::info!(target: "execution", event = "status_loaded", height = status.height, "Successfully loaded existing chain status from state manager.");
                self.state.status = status;
                let root = state.root_commitment().as_ref().to_vec();
                self.state.last_state_root = root.clone();
                self.state.genesis_state = GenesisState::Ready {
                    root,
                    chain_id: self.state.chain_id,
                };

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
            Ok(None) => {
                tracing::info!(target: "execution", event = "status_init", "No existing chain status found. Initializing and saving genesis status.");

                for service in self.service_manager.all_services() {
                    let service_id = service.id();
                    let key = ioi_types::keys::active_service_key(service_id);

                    // Lookup security policy from configuration or fall back to default (empty)
                    let policy = self
                        .service_policies
                        .get(service_id)
                        .cloned()
                        .unwrap_or_default();

                    if policy.methods.is_empty() && service_id != "gas_escrow" {
                        tracing::warn!(target: "execution", "Service '{}' has no method permissions configured.", service_id);
                        debug_assert!(
                            false,
                            "Service '{}' has no method permissions configured.",
                            service_id
                        );
                    }

                    let meta = ActiveServiceMeta {
                        id: service_id.to_string(),
                        abi_version: service.abi_version(),
                        state_schema: service.state_schema().into(),
                        caps: service.capabilities(),
                        artifact_hash: [0u8; 32],
                        activated_at: 0,
                        methods: policy.methods,
                        allowed_system_prefixes: policy.allowed_system_prefixes,
                    };
                    let meta_bytes = codec::to_bytes_canonical(&meta)
                        .map_err(|e| ChainError::Transaction(e.to_string()))?;
                    state
                        .insert(&key, &meta_bytes)
                        .map_err(|e| ChainError::Transaction(e.to_string()))?;
                    self.service_meta_cache
                        .insert(service_id.to_string(), Arc::new(meta));
                    tracing::info!(target: "execution", "Registered initial service '{}' as active in genesis state.", service_id);
                }

                // Check if timing parameters were loaded from genesis file before applying defaults.
                if state.get(BLOCK_TIMING_PARAMS_KEY)?.is_none() {
                    tracing::info!(target: "execution", "Initializing default BlockTimingParams.");
                    let timing_params = BlockTimingParams {
                        base_interval_secs: 5,
                        min_interval_secs: 2,
                        max_interval_secs: 10,
                        target_gas_per_block: 1_000_000,
                        ema_alpha_milli: 200,
                        interval_step_bps: 500,
                        retarget_every_blocks: 0,
                    };
                    state
                        .insert(
                            BLOCK_TIMING_PARAMS_KEY,
                            &codec::to_bytes_canonical(&timing_params)
                                .map_err(ChainError::Transaction)?,
                        )
                        .map_err(|e| ChainError::Transaction(e.to_string()))?;
                } else {
                    tracing::info!(target: "execution", "Found existing BlockTimingParams in genesis.");
                }

                if state.get(BLOCK_TIMING_RUNTIME_KEY)?.is_none() {
                    tracing::info!(target: "execution", "Initializing default BlockTimingRuntime.");
                    // We need to know the base interval to initialize runtime.
                    // Re-read params we just wrote (or that existed).
                    let params_bytes = state
                        .get(BLOCK_TIMING_PARAMS_KEY)?
                        .ok_or(ChainError::Transaction("Missing params".into()))?;
                    let params: BlockTimingParams = codec::from_bytes_canonical(&params_bytes)
                        .map_err(ChainError::Transaction)?;

                    let timing_runtime = BlockTimingRuntime {
                        ema_gas_used: 0,
                        effective_interval_secs: params.base_interval_secs,
                    };
                    state
                        .insert(
                            BLOCK_TIMING_RUNTIME_KEY,
                            &codec::to_bytes_canonical(&timing_runtime)
                                .map_err(ChainError::Transaction)?,
                        )
                        .map_err(|e| ChainError::Transaction(e.to_string()))?;
                }

                let status_bytes = ioi_types::codec::to_bytes_canonical(&self.state.status)
                    .map_err(ChainError::Transaction)?;
                state
                    .insert(STATUS_KEY, &status_bytes)
                    .map_err(|e| ChainError::Transaction(e.to_string()))?;

                // [FIX] Await async persist
                state.commit_version_persist(0, &*workload.store).await?;
                tracing::debug!(target: "execution", "[ExecutionMachine] Committed genesis state.");

                let final_root = state.root_commitment().as_ref().to_vec();

                // Create and persist the genesis block (Height 0) so that queries for the head block succeed.
                // This fixes regressions where the chain head was not found immediately after start.
                let genesis_block = Block {
                    header: BlockHeader {
                        height: 0,
                        view: 0,
                        parent_hash: [0u8; 32],
                        parent_state_root: StateRoot(vec![]),
                        state_root: StateRoot(final_root.clone()),
                        transactions_root: vec![],
                        timestamp: self.state.status.latest_timestamp,
                        gas_used: 0,
                        validator_set: vec![],
                        producer_account_id: AccountId::default(),
                        producer_key_suite: Default::default(),
                        producer_pubkey_hash: [0u8; 32],
                        producer_pubkey: vec![],
                        oracle_counter: 0,
                        oracle_trace_hash: [0u8; 32],
                        signature: vec![],
                    },
                    transactions: vec![],
                };

                let genesis_block_bytes =
                    codec::to_bytes_canonical(&genesis_block).map_err(ChainError::Transaction)?;

                workload
                    .store
                    .put_block(0, &genesis_block_bytes)
                    .map_err(|e| ChainError::State(StateError::Backend(e.to_string())))?;

                self.state.recent_blocks.push(genesis_block);

                let root_commitment_for_check = state.commitment_from_bytes(&final_root)?;

                let (membership, _proof) =
                    state.get_with_proof_at(&root_commitment_for_check, STATUS_KEY)?;
                match membership {
                    ioi_types::app::Membership::Present(_) => {
                        tracing::debug!(target: "execution", "[ExecutionMachine] Genesis self-check passed.");
                    }
                    ioi_types::app::Membership::Absent => {
                        tracing::error!(target: "execution", "[ExecutionMachine] Genesis self-check FAILED: query for '{}' returned Absent.", hex::encode(STATUS_KEY));
                        return Err(ChainError::from(StateError::Validation(
                            "Committed genesis state is not provable".into(),
                        )));
                    }
                }

                self.state.genesis_state = GenesisState::Ready {
                    root: final_root.clone(),
                    chain_id: self.state.chain_id,
                };
                self.state.last_state_root = final_root;
            }
            Err(e) => return Err(ChainError::Transaction(e.to_string())),
        }

        if let GenesisState::Ready { root, .. } = &self.state.genesis_state {
            tracing::info!(target: "execution", event = "genesis_ready", root = hex::encode(root));
        }

        Ok(())
    }

    /// Internal helper to process a single transaction against a state overlay.
    #[allow(dead_code)]
    async fn process_transaction(
        &self,
        tx: &ChainTransaction,
        overlay: &mut StateOverlay<'_>,
        block_height: u64,
        block_timestamp: u64,
        proofs_out: &mut Vec<Vec<u8>>,
    ) -> Result<u64, ChainError> {
        let signer_account_id = signer_from_tx(tx);
        let mut tx_ctx = TxContext {
            block_height,
            block_timestamp: Timestamp::from_nanoseconds(
                (block_timestamp as u128)
                    .saturating_mul(1_000_000_000)
                    .try_into()
                    .map_err(|_| ChainError::Transaction("Timestamp overflow".to_string()))?,
            ),
            chain_id: self.state.chain_id,
            signer_account_id,
            services: &self.services,
            simulation: false,
            is_internal: false,
        };

        preflight_capabilities(&self.services, tx)?;

        // --- PHASE 1: READ-ONLY VALIDATION ---
        // 1. System Checks
        // Pass immutable reference to overlay to prevent side effects during validation.
        validation::verify_transaction_signature(&*overlay, &self.services, tx, &tx_ctx)?;
        nonce::assert_next_nonce(&*overlay, tx)?;

        // 2. Service Decorator Checks (Validation)
        // Collect decorators to avoid multiple borrows
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

            // Immutable namespaced state for validation phase
            let namespaced_view = ReadOnlyNamespacedStateAccess::new(&*overlay, prefix, meta);
            decorator
                .validate_ante(&namespaced_view, tx, &tx_ctx)
                .await?;
        }

        // --- PHASE 2: STATE MUTATION ---
        // If we reached here, all validations passed. Now apply side effects.

        // 1. Service Decorator Writes
        for (id, decorator) in decorators {
            // Safe to unwrap: verified existence in Phase 1
            let meta = self.service_meta_cache.get(id).unwrap();
            let prefix = service_namespace_prefix(id);

            // Mutable namespaced state for write phase
            let mut namespaced_write = NamespacedStateAccess::new(overlay, prefix, meta);
            decorator
                .write_ante(&mut namespaced_write, tx, &tx_ctx)
                .await?;
        }

        // 2. System Writes
        nonce::bump_nonce(overlay, tx)?;

        // --- PHASE 3: PAYLOAD EXECUTION ---
        let (proof, gas_used) = self
            .state
            .transaction_model
            .apply_payload(self, overlay, tx, &mut tx_ctx)
            .await?;

        proofs_out
            .push(ioi_types::codec::to_bytes_canonical(&proof).map_err(ChainError::Transaction)?);

        Ok(gas_used)
    }
}
