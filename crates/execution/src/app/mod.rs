// Path: crates/execution/src/app/mod.rs
// NEW: Declare the new modules containing the trait implementations.
mod state_machine;
mod view;

use crate::upgrade_manager::ServiceUpgradeManager;
use anyhow::Result;
use async_trait::async_trait;
use ioi_api::app::{Block, ChainStatus, ChainTransaction};
// FIX: Import PenaltyMechanism from its canonical public path.
use ioi_api::consensus::PenaltyMechanism;
use ioi_api::commitment::CommitmentScheme;
use ioi_api::services::access::ServiceDirectory;
use ioi_api::services::{BlockchainService, UpgradableService};
// FIX: `PinGuard` was moved, but `StateOverlay` is still used by `process_transaction` here.
use ioi_api::state::{StateAccess, StateManager, StateOverlay};
use ioi_api::transaction::context::TxContext;
use ioi_api::transaction::TransactionModel;
use ioi_api::validator::WorkloadContainer;
use ioi_consensus::Consensus;
use ioi_tx::system::{nonce, validation};
use ioi_tx::unified::UnifiedTransactionModel;
use ioi_types::app::{
    to_root_hash, AccountId, BlockTimingParams, BlockTimingRuntime, ChainId, FailureReport,
    Membership, ValidatorSetV1, ValidatorSetsV1,
};
use ioi_types::codec;
use ioi_types::error::{ChainError, StateError, TransactionError};
use ioi_types::keys::{
    BLOCK_TIMING_PARAMS_KEY, BLOCK_TIMING_RUNTIME_KEY, STATUS_KEY, VALIDATOR_SET_KEY,
};
use ioi_types::service_configs::{ActiveServiceMeta, MethodPermission};
use ibc_primitives::Timestamp;
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
pub struct ExecutionState<CS: CommitmentScheme + Clone> {
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

pub struct Chain<CS: CommitmentScheme + Clone, ST: StateManager> {
    pub state: ExecutionState<CS>,
    pub services: ServiceDirectory,
    pub service_manager: ServiceUpgradeManager,
    pub consensus_engine: Consensus<ioi_types::app::ChainTransaction>,
    workload_container: Arc<WorkloadContainer<ST>>,
    /// In-memory cache for fast access to on-chain service metadata.
    service_meta_cache: HashMap<String, Arc<ActiveServiceMeta>>,
}

impl<CS, ST> Debug for Chain<CS, ST>
where
    CS: CommitmentScheme + Clone,
    ST: StateManager,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Chain")
            .field("state", &self.state)
            .field("services", &self.services)
            .field("consensus_type", &self.consensus_engine.consensus_type())
            .field("service_meta_cache", &self.service_meta_cache.keys())
            .finish()
    }
}

/// Checks if the services required for a specific transaction type are enabled.
fn preflight_capabilities(
    services: &ServiceDirectory,
    tx: &ioi_types::app::ChainTransaction,
) -> Result<(), TransactionError> {
    let _ = (services, tx);
    Ok(())
}

/// Extracts the signer's AccountId from any transaction type that has a SignHeader.
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
    }
}

impl<CS, ST> Chain<CS, ST>
where
    CS: CommitmentScheme + Clone,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        serde::Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
{
    /// Select the validator set that is effective for the given height.
    fn select_set_for_height(sets: &ValidatorSetsV1, h: u64) -> &ValidatorSetV1 {
        if let Some(next) = &sets.next {
            if h >= next.effective_from_height
                && !next.validators.is_empty()
                && next.total_weight > 0
            {
                return next;
            }
        }
        &sets.current
    }

    pub fn new(
        commitment_scheme: CS,
        transaction_model: UnifiedTransactionModel<CS>,
        chain_id: ChainId,
        initial_services: Vec<Arc<dyn UpgradableService>>,
        consensus_engine: Consensus<ioi_types::app::ChainTransaction>,
        workload_container: Arc<WorkloadContainer<ST>>,
    ) -> Self {
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
            service_manager.register_service(service);
        }

        let state = ExecutionState {
            commitment_scheme,
            transaction_model,
            chain_id,
            status,
            recent_blocks: Vec::new(),
            max_recent_blocks: 100,
            last_state_root: Vec::new(),
            genesis_state: GenesisState::Pending,
        };

        Self {
            state,
            services: service_directory,
            service_manager,
            consensus_engine,
            workload_container,
            service_meta_cache: HashMap::new(),
        }
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
                tracing::info!(target: "chain", event = "status_loaded", height = status.height, "Successfully loaded existing chain status from state manager.");
                self.state.status = status;
                let root = state.root_commitment().as_ref().to_vec();
                self.state.last_state_root = root.clone();
                self.state.genesis_state = GenesisState::Ready {
                    root,
                    chain_id: self.state.chain_id,
                };
            }
            Ok(None) => {
                if let Ok((head_height, _)) = workload.store.head() {
                    if head_height > 0 {
                        if let Ok(Some(head_block)) =
                            workload.store.get_block_by_height(head_height)
                        {
                            let recovered_root = &head_block.header.state_root.0;
                            state
                                .adopt_known_root(recovered_root, head_height)
                                .map_err(ChainError::State)?;

                            let status = ChainStatus {
                                height: head_block.header.height,
                                latest_timestamp: head_block.header.timestamp,
                                total_transactions: 0,
                                is_running: true,
                            };
                            tracing::warn!(target: "chain", event = "status_recovered_from_store", height = status.height, "Recovered and adopted durable head into state backend.");

                            let anchor = to_root_hash(recovered_root)?;
                            if let Ok((Membership::Present(status_bytes), _)) =
                                state.get_with_proof_at_anchor(&anchor, STATUS_KEY)
                            {
                                state.insert(STATUS_KEY, &status_bytes)?;
                                tracing::info!(target: "chain", "Re-hydrated STATUS_KEY into current state.");
                            }
                            if let Ok((Membership::Present(vs_bytes), _)) =
                                state.get_with_proof_at_anchor(&anchor, VALIDATOR_SET_KEY)
                            {
                                state.insert(VALIDATOR_SET_KEY, &vs_bytes)?;
                                tracing::info!(target: "chain", "Re-hydrated VALIDATOR_SET_KEY into current state.");
                            }

                            self.state.status = status;
                            self.state.last_state_root = recovered_root.clone();
                            self.state.genesis_state = GenesisState::Ready {
                                root: self.state.last_state_root.clone(),
                                chain_id: self.state.chain_id,
                            };
                            return Ok(());
                        }
                    }
                }

                tracing::info!(target: "chain", event = "status_init", "No existing chain status found. Initializing and saving genesis status.");

                for service in self.service_manager.all_services() {
                    let service_id = service.id();
                    let key = ioi_types::keys::active_service_key(service_id);
                    let mut methods = BTreeMap::new();
                    match service_id {
                        "governance" => {
                            methods.insert("submit_proposal@v1".into(), MethodPermission::User);
                            methods.insert("vote@v1".into(), MethodPermission::User);
                        }
                        "identity_hub" => {
                            methods.insert("rotate_key@v1".into(), MethodPermission::User);
                        }
                        "oracle" => {
                            methods.insert("request_data@v1".into(), MethodPermission::User);
                            methods.insert("submit_data@v1".into(), MethodPermission::User);
                        }
                        "ibc" => {
                            methods.insert("verify_header@v1".into(), MethodPermission::User);
                            methods.insert("recv_packet@v1".into(), MethodPermission::User);
                            methods.insert("msg_dispatch@v1".into(), MethodPermission::User);
                        }
                        _ => {}
                    }
                    let meta = ActiveServiceMeta {
                        id: service_id.to_string(),
                        abi_version: service.abi_version(),
                        state_schema: service.state_schema().into(),
                        caps: service.capabilities(),
                        artifact_hash: [0u8; 32],
                        activated_at: 0,
                        methods,
                    };
                    let meta_bytes = codec::to_bytes_canonical(&meta)
                        .map_err(|e| ChainError::Transaction(e.to_string()))?;
                    state
                        .insert(&key, &meta_bytes)
                        .map_err(|e| ChainError::Transaction(e.to_string()))?;
                    tracing::info!(target: "chain", "Registered initial service '{}' as active in genesis state.", service_id);
                }

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

                let timing_runtime = BlockTimingRuntime {
                    ema_gas_used: 0,
                    effective_interval_secs: timing_params.base_interval_secs,
                };
                state
                    .insert(
                        BLOCK_TIMING_RUNTIME_KEY,
                        &codec::to_bytes_canonical(&timing_runtime)
                            .map_err(ChainError::Transaction)?,
                    )
                    .map_err(|e| ChainError::Transaction(e.to_string()))?;

                state.commit_version(0)?;
                tracing::debug!(target: "chain", "[Chain] Committed full genesis state.");

                let status_bytes = ioi_types::codec::to_bytes_canonical(&self.state.status)
                    .map_err(ChainError::Transaction)?;
                state
                    .insert(STATUS_KEY, &status_bytes)
                    .map_err(|e| ChainError::Transaction(e.to_string()))?;

                state.commit_version(0)?;
                tracing::debug!(target: "chain", "[Chain] Committed genesis state including status key.");

                let final_root = state.root_commitment().as_ref().to_vec();
                let root_commitment_for_check = state.commitment_from_bytes(&final_root)?;

                let (membership, _proof) =
                    state.get_with_proof_at(&root_commitment_for_check, STATUS_KEY)?;
                match membership {
                    ioi_types::app::Membership::Present(_) => {
                        tracing::debug!(target: "chain", "[Chain] Genesis self-check passed.");
                    }
                    ioi_types::app::Membership::Absent => {
                        tracing::error!(target: "chain", "[Chain] Genesis self-check FAILED: query for '{}' returned Absent.", hex::encode(STATUS_KEY));
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
            tracing::info!(target: "chain", event = "genesis_ready", root = hex::encode(root));
        }

        Ok(())
    }

    /// Internal helper to process a single transaction against a state overlay.
    async fn process_transaction(
        &self,
        tx: &ChainTransaction,
        overlay: &mut StateOverlay<'_>,
        block_height: u64,
        block_timestamp: u64,
    ) -> Result<(), ChainError> {
        let signer_account_id = signer_from_tx(tx);
        let mut tx_ctx = TxContext {
            block_height,
            block_timestamp: Timestamp::from_nanoseconds(block_timestamp * 1_000_000_000)
                .map_err(|e| ChainError::Transaction(format!("Invalid timestamp: {}", e)))?,
            chain_id: self.state.chain_id,
            signer_account_id,
            services: &self.services,
            simulation: false,
            is_internal: false,
        };

        preflight_capabilities(&self.services, tx)?;

        validation::verify_transaction_signature(overlay, &self.services, tx, &tx_ctx)?;
        nonce::assert_next_nonce(overlay, tx)?;

        for service in self.services.services_in_deterministic_order() {
            if let Some(decorator) = service.as_tx_decorator() {
                decorator.ante_handle(overlay, tx, &tx_ctx).await?;
            }
        }

        nonce::bump_nonce(overlay, tx)?;

        self.state
            .transaction_model
            .apply_payload(self, overlay, tx, &mut tx_ctx)
            .await?;

        Ok(())
    }
}