// Path: crates/execution/src/app/mod.rs
mod end_block;
mod state_machine;
mod view;

// [NEW] Include parallel execution modules
pub mod parallel_state;

use crate::upgrade_manager::ServiceUpgradeManager;
use anyhow::Result;
use async_trait::async_trait;
// REMOVED: use ibc_primitives::Timestamp;
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
use ioi_services::guardian_registry::GuardianRegistry;
use ioi_tx::system::{nonce, validation};
use ioi_tx::unified::UnifiedTransactionModel;
use ioi_types::app::{
    seconds_to_millis, to_root_hash, AccountId, AftRecoveredConsensusHeaderEntry,
    AftRecoveredReplayEntry, AftRecoveredStateSurface, BlockTimingParams, BlockTimingRuntime,
    ChainId, FailureReport, QuorumCertificate, StateRoot,
};
use ioi_types::codec;
use ioi_types::config::{ConsensusType, ServicePolicy};
use ioi_types::error::{ChainError, CoreError, StateError, TransactionError};
use ioi_types::keys::{
    BLOCK_TIMING_PARAMS_KEY, BLOCK_TIMING_RUNTIME_KEY, STATUS_KEY, UPGRADE_ACTIVE_SERVICE_PREFIX,
};
use ioi_types::service_configs::ActiveServiceMeta;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

// [FIX] Import OsDriver trait
use ioi_api::vm::drivers::os::OsDriver;

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
    /// Bounded AFT recovered-state surface retained across restarts for read-side and
    /// parent-continuity lookup.
    pub recent_aft_recovered_state: AftRecoveredStateSurface,
    pub max_recent_blocks: usize,
    /// Last committed state root (raw bytes).
    pub last_state_root: Vec<u8>,
    pub genesis_state: GenesisState,
}

pub struct ExecutionMachine<CS: CommitmentScheme + Clone, ST: StateManager> {
    pub state: ExecutionMachineState<CS>,
    pub services: ServiceDirectory,
    pub service_manager: ServiceUpgradeManager,
    pub consensus_engine: Consensus<ioi_types::app::ChainTransaction>,
    workload_container: Arc<WorkloadContainer<ST>>,
    /// In-memory cache for fast access to on-chain service metadata.
    pub service_meta_cache: HashMap<String, Arc<ActiveServiceMeta>>,
    /// Holds the configuration-driven policies for services
    pub service_policies: BTreeMap<String, ServicePolicy>,
    // [FIX] Added os_driver field for policy enforcement context
    pub os_driver: Arc<dyn OsDriver>,
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
            .field("os_driver", &"Arc<dyn OsDriver>")
            .finish()
    }
}

// [FIX] Allow dead code for legacy function
#[allow(dead_code)]
fn signer_from_tx(tx: &ChainTransaction) -> AccountId {
    match tx {
        ChainTransaction::System(s) => s.header.account_id,
        ChainTransaction::Settlement(s) => s.header.account_id,
        ChainTransaction::Application(a) => match a {
            ioi_types::app::ApplicationTransaction::DeployContract { header, .. }
            | ioi_types::app::ApplicationTransaction::CallContract { header, .. } => {
                header.account_id
            }
        },
        ChainTransaction::Semantic { .. } => AccountId::default(),
    }
}

const AFT_RESTART_REPLAY_PREFIX_WINDOW: u64 = 4;

/// Returns the latest durable replay-prefix anchor that execution can trust on restart.
pub fn recover_execution_restart_anchor_from_replay_prefix(
    replay_prefix: &[AftRecoveredReplayEntry],
) -> Result<AftRecoveredReplayEntry, ChainError> {
    replay_prefix.last().cloned().ok_or_else(|| {
        ChainError::Transaction(
            "AFT execution restart requires a non-empty canonical replay prefix".into(),
        )
    })
}

pub(crate) fn resolve_replay_prefix_entry(
    replay_prefix: &[AftRecoveredReplayEntry],
    expected_height: u64,
    expected_state_root: &[u8],
) -> Option<AftRecoveredReplayEntry> {
    replay_prefix
        .iter()
        .rev()
        .find(|entry| {
            entry.height == expected_height
                && entry.resulting_state_root_hash.as_slice() == expected_state_root
        })
        .cloned()
}

pub(crate) fn resolve_recovered_header_entry(
    recovered_headers: &[AftRecoveredConsensusHeaderEntry],
    expected_height: u64,
) -> Option<AftRecoveredConsensusHeaderEntry> {
    recovered_headers
        .iter()
        .rev()
        .find(|entry| entry.height == expected_height)
        .cloned()
}

pub(crate) fn resolve_execution_anchor_from_recent_blocks_or_replay_prefix(
    recent_blocks: &[Block<ChainTransaction>],
    last_state_root: &[u8],
    recent_aft_recovered_state: &AftRecoveredStateSurface,
    expected_height: u64,
    expected_state_root: &[u8],
) -> Option<(Vec<u8>, u64)> {
    if expected_state_root.is_empty() {
        return None;
    }

    if last_state_root == expected_state_root {
        let gas = recent_blocks
            .last()
            .map(|block| block.header.gas_used)
            .unwrap_or(0);
        return Some((last_state_root.to_vec(), gas));
    }

    if let Some((root, gas)) = recent_blocks.iter().rev().find_map(|block| {
        if block.header.height == expected_height
            && block.header.state_root.as_ref() == expected_state_root
        {
            Some((block.header.state_root.0.clone(), block.header.gas_used))
        } else {
            None
        }
    }) {
        return Some((root, gas));
    }

    resolve_replay_prefix_entry(
        &recent_aft_recovered_state.replay_prefix,
        expected_height,
        expected_state_root,
    )
    .map(|entry| (entry.resulting_state_root_hash.to_vec(), 0))
}

pub(crate) fn resolve_execution_parent_anchor(
    current_height: u64,
    recent_blocks: &[Block<ChainTransaction>],
    last_state_root: &[u8],
    recent_aft_recovered_state: &AftRecoveredStateSurface,
) -> Result<(Vec<u8>, StateRoot), ChainError> {
    if let Some(block) = recent_blocks.last() {
        return Ok((
            block.header.hash().unwrap_or(vec![0; 32]),
            block.header.state_root.clone(),
        ));
    }

    let recovered_header = resolve_recovered_header_entry(
        &recent_aft_recovered_state.consensus_headers,
        current_height,
    );
    if let Some(replay_tip) = recent_aft_recovered_state.replay_prefix.last() {
        if replay_tip.height != current_height {
            return Err(ChainError::Transaction(format!(
                "AFT execution replay-prefix parent height mismatch: expected {}, got {}",
                current_height, replay_tip.height
            )));
        }
        if !last_state_root.is_empty()
            && replay_tip.resulting_state_root_hash.as_slice() != last_state_root
        {
            return Err(ChainError::Transaction(format!(
                "AFT execution replay-prefix parent state-root mismatch at height {}",
                current_height
            )));
        }
        if let Some(recovered_header) = recovered_header.as_ref() {
            if let Some(replay_block_hash) = replay_tip.canonical_block_commitment_hash {
                if recovered_header.canonical_block_commitment_hash != replay_block_hash {
                    return Err(ChainError::Transaction(format!(
                        "AFT execution recovered header block-hash mismatch at height {}",
                        current_height
                    )));
                }
            }
            if let Some(replay_parent_hash) = replay_tip.parent_block_commitment_hash {
                if recovered_header.parent_block_commitment_hash != replay_parent_hash {
                    return Err(ChainError::Transaction(format!(
                        "AFT execution recovered header parent-hash mismatch at height {}",
                        current_height
                    )));
                }
            }
        }
        let parent_state_root = replay_tip.resulting_state_root_hash.to_vec();
        let parent_hash = match recovered_header {
            Some(header) => header.canonical_block_commitment_hash.to_vec(),
            None => match replay_tip.canonical_block_commitment_hash {
                Some(hash) => hash.to_vec(),
                None => to_root_hash(&parent_state_root)
                    .map_err(ChainError::State)?
                    .to_vec(),
            },
        };
        return Ok((parent_hash, StateRoot(parent_state_root)));
    }

    if last_state_root.is_empty() {
        return Err(ChainError::UnknownStateAnchor(
            "Cannot derive execution parent anchor without a recent block, replay prefix, or last state root"
                .to_string(),
        ));
    }

    let parent_hash = to_root_hash(last_state_root)
        .map_err(ChainError::State)?
        .to_vec();
    Ok((parent_hash, StateRoot(last_state_root.to_vec())))
}

fn validate_execution_restart_handoff_from_replay_prefix(
    replay_prefix: &[AftRecoveredReplayEntry],
    expected_height: u64,
    expected_state_root: &[u8],
) -> Result<AftRecoveredReplayEntry, ChainError> {
    let restart_anchor = recover_execution_restart_anchor_from_replay_prefix(replay_prefix)?;
    if restart_anchor.height != expected_height {
        return Err(ChainError::Transaction(format!(
            "AFT execution restart replay-prefix tip height mismatch: expected {}, got {}",
            expected_height, restart_anchor.height
        )));
    }

    let expected_state_root_hash: [u8; 32] = expected_state_root.try_into().map_err(|_| {
        ChainError::Transaction(format!(
            "AFT execution restart expected a 32-byte state root, got {} bytes",
            expected_state_root.len()
        ))
    })?;
    if restart_anchor.resulting_state_root_hash != expected_state_root_hash {
        return Err(ChainError::Transaction(format!(
            "AFT execution restart replay-prefix tip state-root mismatch at height {}",
            expected_height
        )));
    }

    Ok(restart_anchor)
}

#[cfg(test)]
fn validate_aft_restart_replay_prefix_with_extractor<F>(
    state: &dyn StateAccess,
    expected_height: u64,
    expected_state_root: &[u8],
    extractor: F,
) -> Result<AftRecoveredReplayEntry, ChainError>
where
    F: FnOnce(&dyn StateAccess, u64, u64) -> Result<Vec<AftRecoveredReplayEntry>, StateError>,
{
    let start_height = expected_height
        .saturating_sub(AFT_RESTART_REPLAY_PREFIX_WINDOW.saturating_sub(1))
        .max(1);
    let replay_prefix = extractor(state, start_height, expected_height)?;
    validate_execution_restart_handoff_from_replay_prefix(
        &replay_prefix,
        expected_height,
        expected_state_root,
    )
}

impl<CS, ST> ExecutionMachine<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        serde::Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    <CS as CommitmentScheme>::Commitment: std::fmt::Debug + Send + Sync,
{
    fn configured_genesis_timestamp_secs() -> u64 {
        std::env::var("IOI_GENESIS_TIMESTAMP_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0)
    }

    fn configured_genesis_timestamp_ms() -> u64 {
        std::env::var("IOI_GENESIS_TIMESTAMP_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or_else(|| seconds_to_millis(Self::configured_genesis_timestamp_secs()))
    }

    pub fn new(
        commitment_scheme: CS,
        transaction_model: UnifiedTransactionModel<CS>,
        chain_id: ChainId,
        initial_services: Vec<Arc<dyn UpgradableService>>,
        consensus_engine: Consensus<ioi_types::app::ChainTransaction>,
        workload_container: Arc<WorkloadContainer<ST>>,
        service_policies: BTreeMap<String, ServicePolicy>,
        os_driver: Arc<dyn OsDriver>,
    ) -> Result<Self, CoreError> {
        // [FIX] Initialize as running=true so the API reports correct status immediately
        let genesis_timestamp_ms = Self::configured_genesis_timestamp_ms();
        let status = ChainStatus {
            height: 0,
            latest_timestamp: genesis_timestamp_ms / 1000,
            total_transactions: 0,
            is_running: true,
            latest_timestamp_ms: genesis_timestamp_ms,
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
            recent_aft_recovered_state: AftRecoveredStateSurface::default(),
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
            os_driver,
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
                let mut status: ChainStatus =
                    codec::from_bytes_canonical(status_bytes).map_err(ChainError::Transaction)?;

                // [FIX] Ensure we report running after a restart/recovery
                status.is_running = true;
                if status.latest_timestamp_ms == 0 {
                    status.latest_timestamp_ms = seconds_to_millis(status.latest_timestamp);
                }

                tracing::info!(target: "execution", event = "status_loaded", height = status.height, "Successfully loaded existing chain status from state manager.");
                self.state.status = status;
                let root = state.root_commitment().as_ref().to_vec();
                self.state.last_state_root = root.clone();
                self.state.genesis_state = GenesisState::Ready {
                    root,
                    chain_id: self.state.chain_id,
                };
                self.state.recent_aft_recovered_state = AftRecoveredStateSurface::default();
                if self.consensus_engine.consensus_type() == ConsensusType::Aft
                    && self.state.status.height > 0
                {
                    let start_height = self
                        .state
                        .status
                        .height
                        .saturating_sub(AFT_RESTART_REPLAY_PREFIX_WINDOW.saturating_sub(1))
                        .max(1);
                    let recovered_state = GuardianRegistry::extract_aft_recovered_state_surface(
                        &*state,
                        start_height,
                        self.state.status.height,
                    )?;
                    let restart_anchor = validate_execution_restart_handoff_from_replay_prefix(
                        &recovered_state.replay_prefix,
                        self.state.status.height,
                        &self.state.last_state_root,
                    )?;
                    self.state.recent_aft_recovered_state = recovered_state;
                    tracing::info!(
                        target: "execution",
                        recovered_prefix_len = self.state.recent_aft_recovered_state.replay_prefix.len(),
                        recovered_header_len = self.state.recent_aft_recovered_state.consensus_headers.len(),
                        "Loaded bounded AFT recovered-state surface for restart continuity"
                    );
                    tracing::info!(
                        target: "execution",
                        height = restart_anchor.height,
                        collapse = hex::encode(restart_anchor.canonical_collapse_commitment_hash),
                        "Verified bounded AFT replay-prefix restart anchor"
                    );
                } else {
                    self.state.recent_aft_recovered_state = AftRecoveredStateSurface::default();
                }

                let service_iter = state.prefix_scan(UPGRADE_ACTIVE_SERVICE_PREFIX)?;
                for item in service_iter {
                    let (_key, meta_bytes) = item?;
                    if let Ok(meta) = codec::from_bytes_canonical::<ActiveServiceMeta>(&meta_bytes)
                    {
                        self.service_meta_cache
                            .insert(meta.id.clone(), Arc::new(meta));
                    }
                }

                // Backfill newly introduced ABI methods/prefixes for active services
                // when loading an existing state snapshot.
                for service in self.service_manager.all_services() {
                    let service_id = service.id();
                    let Some(policy) = self.service_policies.get(service_id) else {
                        continue;
                    };
                    let Some(existing_meta) = self.service_meta_cache.get(service_id) else {
                        continue;
                    };

                    let mut patched_meta = (**existing_meta).clone();
                    let mut changed = false;

                    for (method, permission) in &policy.methods {
                        if !patched_meta.methods.contains_key(method) {
                            patched_meta
                                .methods
                                .insert(method.clone(), permission.clone());
                            changed = true;
                        }
                    }

                    for prefix in &policy.allowed_system_prefixes {
                        if !patched_meta.allowed_system_prefixes.contains(prefix) {
                            patched_meta.allowed_system_prefixes.push(prefix.clone());
                            changed = true;
                        }
                    }

                    if changed {
                        let key = ioi_types::keys::active_service_key(service_id);
                        let meta_bytes = codec::to_bytes_canonical(&patched_meta)
                            .map_err(ChainError::Transaction)?;
                        state
                            .insert(&key, &meta_bytes)
                            .map_err(|e| ChainError::Transaction(e.to_string()))?;
                        self.service_meta_cache
                            .insert(service_id.to_string(), Arc::new(patched_meta));
                        tracing::warn!(
                            target: "execution",
                            service_id = service_id,
                            "Backfilled active service ABI metadata from configured policy"
                        );
                    }
                }
            }
            Ok(None) => {
                tracing::info!(target: "execution", event = "status_init", "No existing chain status found. Initializing and saving genesis status.");

                if self.state.status.latest_timestamp_ms_or_legacy() == 0 {
                    tracing::warn!(
                        target: "execution",
                        "Genesis timestamp defaulted to zero; set IOI_GENESIS_TIMESTAMP_MS or IOI_GENESIS_TIMESTAMP_SECS for deterministic block-timing tests"
                    );
                } else {
                    let now_secs = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|duration| duration.as_secs())
                        .unwrap_or_default();
                    tracing::info!(
                        target: "execution",
                        genesis_timestamp = self.state.status.latest_timestamp,
                        genesis_timestamp_ms = self.state.status.latest_timestamp_ms_or_legacy(),
                        wall_clock = now_secs,
                        "Initializing genesis status with configured timestamp"
                    );
                }

                for service in self.service_manager.all_services() {
                    let service_id = service.id();
                    let key = ioi_types::keys::active_service_key(service_id);

                    // Lookup security policy from configuration or fall back to default (empty)
                    let policy = self
                        .service_policies
                        .get(service_id)
                        .cloned()
                        .unwrap_or_default();

                    let meta = ActiveServiceMeta {
                        id: service_id.to_string(),
                        abi_version: service.abi_version(),
                        state_schema: service.state_schema().into(),
                        caps: service.capabilities(),
                        artifact_hash: [0u8; 32],
                        activated_at: 0,
                        methods: policy.methods,
                        allowed_system_prefixes: policy.allowed_system_prefixes,
                        generation_id: 0,
                        parent_hash: None,
                        author: None, // [FIX] Initial system services have no specific author
                        context_filter: None, // [FIX] Initial system services have no context filter
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
                        base_interval_ms: 5_000,
                        min_interval_ms: 2_000,
                        max_interval_ms: 10_000,
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
                    let params_bytes = state
                        .get(BLOCK_TIMING_PARAMS_KEY)?
                        .ok_or(ChainError::Transaction("Missing params".into()))?;
                    let params: BlockTimingParams = codec::from_bytes_canonical(&params_bytes)
                        .map_err(ChainError::Transaction)?;

                    let timing_runtime = BlockTimingRuntime {
                        ema_gas_used: 0,
                        effective_interval_secs: params.base_interval_secs,
                        effective_interval_ms: params.base_interval_ms_or_legacy(),
                    };
                    state
                        .insert(
                            BLOCK_TIMING_RUNTIME_KEY,
                            &codec::to_bytes_canonical(&timing_runtime)
                                .map_err(ChainError::Transaction)?,
                        )
                        .map_err(|e| ChainError::Transaction(e.to_string()))?;
                }

                // [FIX] Explicitly set running before saving genesis status
                self.state.status.is_running = true;

                let status_bytes = ioi_types::codec::to_bytes_canonical(&self.state.status)
                    .map_err(ChainError::Transaction)?;
                state
                    .insert(STATUS_KEY, &status_bytes)
                    .map_err(|e| ChainError::Transaction(e.to_string()))?;

                state.commit_version_persist(0, &*workload.store).await?;
                tracing::debug!(target: "execution", "[ExecutionMachine] Committed genesis state.");

                let final_root = state.root_commitment().as_ref().to_vec();

                let genesis_block = Block {
                    header: BlockHeader {
                        height: 0,
                        view: 0,
                        parent_hash: [0u8; 32],
                        parent_state_root: StateRoot(vec![]),
                        state_root: StateRoot(final_root.clone()),
                        transactions_root: vec![],
                        timestamp: self.state.status.latest_timestamp,
                        timestamp_ms: self.state.status.latest_timestamp_ms_or_legacy(),
                        gas_used: 0,
                        validator_set: vec![],
                        producer_account_id: AccountId::default(),
                        producer_key_suite: Default::default(),
                        producer_pubkey_hash: [0u8; 32],
                        producer_pubkey: vec![],
                        signature: vec![],
                        oracle_counter: 0,
                        oracle_trace_hash: [0u8; 32],
                        parent_qc: QuorumCertificate::default(),
                        previous_canonical_collapse_commitment_hash: [0u8; 32],
                        canonical_collapse_extension_certificate: None,
                        publication_frontier: None,
                        guardian_certificate: None,
                        sealed_finality_proof: None,
                        canonical_order_certificate: None,
                        timeout_certificate: None,
                    },
                    transactions: vec![],
                };

                let genesis_block_bytes =
                    codec::to_bytes_canonical(&genesis_block).map_err(ChainError::Transaction)?;

                workload
                    .store
                    .put_block(0, &genesis_block_bytes)
                    .await
                    .map_err(|e| ChainError::State(StateError::Backend(e.to_string())))?;

                self.state.recent_blocks.push(genesis_block);

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

    // [FIX] Allow dead code for sequential processor (replaced by parallel version in state_machine.rs)
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
        let block_timestamp_ns = (block_timestamp as u128)
            .saturating_mul(1_000_000_000)
            .try_into()
            .map_err(|_| ChainError::Transaction("Timestamp overflow".to_string()))?;

        let mut tx_ctx = TxContext {
            block_height,
            block_timestamp: block_timestamp_ns,
            chain_id: self.state.chain_id,
            signer_account_id,
            services: &self.services,
            simulation: false,
            is_internal: false,
        };

        validation::verify_stateless_signature(tx)?;
        validation::verify_stateful_authorization(&*overlay, &self.services, tx, &tx_ctx)?;
        nonce::assert_next_nonce(&*overlay, tx)?;

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
            let namespaced_view = ReadOnlyNamespacedStateAccess::new(&*overlay, prefix, meta);
            decorator
                .validate_ante(&namespaced_view, tx, &tx_ctx)
                .await?;
        }

        for (id, decorator) in decorators {
            let meta = self.service_meta_cache.get(id).unwrap();
            let prefix = service_namespace_prefix(id);
            let mut namespaced_write = NamespacedStateAccess::new(overlay, prefix, meta);
            decorator
                .write_ante(&mut namespaced_write, tx, &tx_ctx)
                .await?;
        }

        nonce::bump_nonce(overlay, tx)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::{CanonicalCollapseKind, SignatureSuite};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    #[derive(Default)]
    struct MockState {
        data: BTreeMap<Vec<u8>, Vec<u8>>,
    }

    impl StateAccess for MockState {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
            Ok(self.data.get(key).cloned())
        }

        fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
            self.data.insert(key.to_vec(), value.to_vec());
            Ok(())
        }

        fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
            self.data.remove(key);
            Ok(())
        }

        fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
            for (key, value) in updates {
                self.data.insert(key.clone(), value.clone());
            }
            Ok(())
        }

        fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
            Ok(keys.iter().map(|key| self.data.get(key).cloned()).collect())
        }

        fn batch_apply(
            &mut self,
            inserts: &[(Vec<u8>, Vec<u8>)],
            deletes: &[Vec<u8>],
        ) -> Result<(), StateError> {
            self.batch_set(inserts)?;
            for key in deletes {
                self.data.remove(key);
            }
            Ok(())
        }

        fn prefix_scan(
            &self,
            prefix: &[u8],
        ) -> Result<ioi_api::state::StateScanIter<'_>, StateError> {
            let items = self
                .data
                .iter()
                .filter(|(key, _)| key.starts_with(prefix))
                .map(|(key, value)| {
                    Ok((
                        Arc::<[u8]>::from(key.clone()),
                        Arc::<[u8]>::from(value.clone()),
                    ))
                })
                .collect::<Vec<_>>();
            Ok(Box::new(items.into_iter()))
        }
    }

    fn sample_replay_prefix_entry(
        height: u64,
        resulting_state_root_hash: [u8; 32],
        ordering_kind: CanonicalCollapseKind,
    ) -> AftRecoveredReplayEntry {
        AftRecoveredReplayEntry {
            height,
            resulting_state_root_hash,
            canonical_block_commitment_hash: Some([height.wrapping_add(100) as u8; 32]),
            parent_block_commitment_hash: Some(if height <= 1 {
                [0u8; 32]
            } else {
                [height.wrapping_add(99) as u8; 32]
            }),
            canonical_collapse_commitment_hash: [height as u8; 32],
            previous_canonical_collapse_commitment_hash: [height.saturating_sub(1) as u8; 32],
            ordering_kind,
            ordering_resolution_hash: [height.wrapping_add(40) as u8; 32],
            publication_frontier_hash: if ordering_kind == CanonicalCollapseKind::Close {
                Some([height.wrapping_add(80) as u8; 32])
            } else {
                None
            },
            extracted_bulletin_surface_present: ordering_kind == CanonicalCollapseKind::Close,
            archived_recovered_history_checkpoint_hash: None,
            archived_recovered_history_profile_activation_hash: None,
            archived_recovered_history_retention_receipt_hash: None,
        }
    }

    fn sample_recovered_header_entry(
        height: u64,
        canonical_block_commitment_hash: [u8; 32],
        parent_block_commitment_hash: [u8; 32],
    ) -> AftRecoveredConsensusHeaderEntry {
        AftRecoveredConsensusHeaderEntry {
            height,
            view: height,
            canonical_block_commitment_hash,
            parent_block_commitment_hash,
            transactions_root_hash: [height.wrapping_add(70) as u8; 32],
            resulting_state_root_hash: [height.wrapping_add(71) as u8; 32],
            previous_canonical_collapse_commitment_hash: [height.saturating_sub(1) as u8; 32],
        }
    }

    #[test]
    fn recover_execution_restart_anchor_returns_prefix_tip() {
        let replay_prefix = vec![
            sample_replay_prefix_entry(2, [0x22; 32], CanonicalCollapseKind::Close),
            sample_replay_prefix_entry(3, [0x33; 32], CanonicalCollapseKind::Abort),
            sample_replay_prefix_entry(4, [0x44; 32], CanonicalCollapseKind::Close),
        ];

        let anchor = recover_execution_restart_anchor_from_replay_prefix(&replay_prefix)
            .expect("recover restart anchor");

        assert_eq!(anchor.height, 4);
        assert_eq!(anchor.resulting_state_root_hash, [0x44; 32]);
    }

    #[test]
    fn validate_execution_restart_handoff_rejects_tip_state_root_mismatch() {
        let replay_prefix = vec![
            sample_replay_prefix_entry(3, [0x33; 32], CanonicalCollapseKind::Abort),
            sample_replay_prefix_entry(4, [0x44; 32], CanonicalCollapseKind::Close),
        ];

        let error =
            validate_execution_restart_handoff_from_replay_prefix(&replay_prefix, 4, &[0x99; 32])
                .expect_err("mismatched root should fail");

        assert!(error
            .to_string()
            .contains("replay-prefix tip state-root mismatch"));
    }

    #[test]
    fn validate_aft_restart_replay_prefix_uses_bounded_recent_window() {
        let state = MockState::default();
        let mut observed_window = None;

        let anchor = validate_aft_restart_replay_prefix_with_extractor(
            &state,
            10,
            &[0xaa; 32],
            |_, start_height, end_height| {
                observed_window = Some((start_height, end_height));
                Ok(vec![
                    sample_replay_prefix_entry(7, [0x77; 32], CanonicalCollapseKind::Close),
                    sample_replay_prefix_entry(8, [0x88; 32], CanonicalCollapseKind::Abort),
                    sample_replay_prefix_entry(9, [0x99; 32], CanonicalCollapseKind::Close),
                    sample_replay_prefix_entry(10, [0xaa; 32], CanonicalCollapseKind::Close),
                ])
            },
        )
        .expect("bounded replay-prefix restart validation");

        assert_eq!(observed_window, Some((7, 10)));
        assert_eq!(anchor.height, 10);
        assert_eq!(anchor.resulting_state_root_hash, [0xaa; 32]);
    }

    #[test]
    fn resolve_execution_anchor_uses_recovered_prefix_when_recent_blocks_absent() {
        let replay_prefix = vec![
            sample_replay_prefix_entry(7, [0x77; 32], CanonicalCollapseKind::Close),
            sample_replay_prefix_entry(8, [0x88; 32], CanonicalCollapseKind::Abort),
            sample_replay_prefix_entry(9, [0x99; 32], CanonicalCollapseKind::Close),
            sample_replay_prefix_entry(10, [0xaa; 32], CanonicalCollapseKind::Close),
        ];
        let recovered_state = AftRecoveredStateSurface {
            replay_prefix,
            ..AftRecoveredStateSurface::default()
        };

        let resolved = resolve_execution_anchor_from_recent_blocks_or_replay_prefix(
            &[],
            &[0xaa; 32],
            &recovered_state,
            8,
            &[0x88; 32],
        )
        .expect("resolve recovered prefix anchor");

        assert_eq!(resolved.0, vec![0x88; 32]);
        assert_eq!(resolved.1, 0);
    }

    #[test]
    fn resolve_execution_parent_anchor_uses_recovered_prefix_tip() {
        let replay_prefix = vec![
            sample_replay_prefix_entry(9, [0x99; 32], CanonicalCollapseKind::Close),
            sample_replay_prefix_entry(10, [0xaa; 32], CanonicalCollapseKind::Close),
        ];
        let recovered_state = AftRecoveredStateSurface {
            replay_prefix,
            ..AftRecoveredStateSurface::default()
        };

        let (parent_hash, parent_state_root) =
            resolve_execution_parent_anchor(10, &[], &[0xaa; 32], &recovered_state)
                .expect("resolve recovered parent anchor");

        assert_eq!(parent_state_root.0, vec![0xaa; 32]);
        assert_eq!(parent_hash, vec![110u8; 32]);
    }

    #[test]
    fn resolve_execution_parent_anchor_matches_ordinary_lane_when_recovered_header_cache_carries_block_hash(
    ) {
        let mut header = BlockHeader {
            height: 10,
            view: 4,
            parent_hash: [0x91; 32],
            parent_state_root: StateRoot(vec![0x92; 32]),
            state_root: StateRoot(vec![0xaa; 32]),
            transactions_root: vec![0x93; 32],
            timestamp: 1_750_100_000,
            timestamp_ms: 1_750_100_000_000,
            gas_used: 7,
            validator_set: Vec::new(),
            producer_account_id: AccountId([0x94; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [0x95; 32],
            producer_pubkey: Vec::new(),
            signature: Vec::new(),
            oracle_counter: 0,
            oracle_trace_hash: [0u8; 32],
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
        };
        header.signature = vec![1, 2, 3];
        let block = Block {
            header: header.clone(),
            transactions: Vec::new(),
        };
        let block_hash = header.hash().expect("block hash");

        let ordinary = resolve_execution_parent_anchor(
            10,
            &[block],
            &[0xaa; 32],
            &AftRecoveredStateSurface::default(),
        )
        .expect("ordinary parent anchor");
        let replay_prefix = vec![AftRecoveredReplayEntry {
            height: 10,
            resulting_state_root_hash: [0xaa; 32],
            canonical_block_commitment_hash: None,
            parent_block_commitment_hash: Some(header.parent_hash),
            canonical_collapse_commitment_hash: [10u8; 32],
            previous_canonical_collapse_commitment_hash: [9u8; 32],
            ordering_kind: CanonicalCollapseKind::Close,
            ordering_resolution_hash: [50u8; 32],
            publication_frontier_hash: Some([60u8; 32]),
            extracted_bulletin_surface_present: true,
            archived_recovered_history_checkpoint_hash: None,
            archived_recovered_history_profile_activation_hash: None,
            archived_recovered_history_retention_receipt_hash: None,
        }];
        let recovered_headers = vec![sample_recovered_header_entry(
            10,
            block_hash.as_slice().try_into().unwrap(),
            header.parent_hash,
        )];
        let recovered_state = AftRecoveredStateSurface {
            replay_prefix,
            consensus_headers: recovered_headers,
            ..AftRecoveredStateSurface::default()
        };
        let recovered = resolve_execution_parent_anchor(10, &[], &[0xaa; 32], &recovered_state)
            .expect("recovered parent anchor");

        assert_eq!(recovered, ordinary);
    }

    #[test]
    fn resolve_execution_parent_anchor_rejects_recovered_header_block_hash_mismatch() {
        let replay_prefix = vec![sample_replay_prefix_entry(
            10,
            [0xaa; 32],
            CanonicalCollapseKind::Close,
        )];
        let recovered_state = AftRecoveredStateSurface {
            replay_prefix,
            consensus_headers: vec![sample_recovered_header_entry(10, [0xbb; 32], [109u8; 32])],
            ..AftRecoveredStateSurface::default()
        };

        let error = resolve_execution_parent_anchor(10, &[], &[0xaa; 32], &recovered_state)
            .expect_err("mismatched recovered header block hash should fail");

        assert!(error
            .to_string()
            .contains("recovered header block-hash mismatch"));
    }

    #[test]
    fn resolve_execution_parent_anchor_rejects_recovered_tip_root_mismatch() {
        let replay_prefix = vec![sample_replay_prefix_entry(
            10,
            [0xaa; 32],
            CanonicalCollapseKind::Close,
        )];
        let recovered_state = AftRecoveredStateSurface {
            replay_prefix,
            ..AftRecoveredStateSurface::default()
        };

        let error = resolve_execution_parent_anchor(10, &[], &[0xbb; 32], &recovered_state)
            .expect_err("mismatched recovered parent anchor should fail");

        assert!(error
            .to_string()
            .contains("replay-prefix parent state-root mismatch"));
    }
}
