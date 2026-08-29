// Path: crates/execution/src/app/mod.rs
mod aft_aux;
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

pub use aft_aux::{
    derive_canonical_collapse_for_block, derive_canonical_collapse_for_height,
    load_aft_auxiliary_raw_state_value,
};

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

/// One-height rollback material for the bounded AFT workload projection suffix.
///
/// AFT executes a proposal before its descendant certificate makes the
/// proposal an Agentgres-recognized effect.  A higher-view proposal at the
/// same height may therefore legitimately replace the local projection.  The
/// snapshot is deliberately in-memory and grants no authority. The
/// machine retains only the two projections required by the AFT two-chain
/// pipeline, and callers must separately bind the Agentgres admission floor.
pub(crate) struct AftTipRollbackSnapshot<ST: StateManager> {
    pub projected_height: u64,
    pub projected_parent_state_root: Vec<u8>,
    pub projected_state_root: Vec<u8>,
    pub projected_transactions_root: Vec<u8>,
    pub state_tree: ST,
    pub status: ChainStatus,
    pub recent_blocks: Vec<Block<ChainTransaction>>,
    pub recent_aft_recovered_state: AftRecoveredStateSurface,
    pub last_state_root: Vec<u8>,
    pub genesis_state: GenesisState,
    pub services: ServiceDirectory,
    pub service_manager: ServiceUpgradeManager,
    pub service_meta_cache: HashMap<String, Arc<ActiveServiceMeta>>,
}

/// Exact live projection retained only while one AFT replacement is in flight.
///
/// Unlike `AftTipRollbackSnapshot`, this value is not a pre-projection stack
/// entry and deliberately carries no projected-height metadata. Keeping the
/// types distinct prevents the live state from ever being mistaken for a
/// rollback entry whose `status.height + 1 == projected_height` invariant is
/// load-bearing at admission.
struct AftLiveProjectionSnapshot<ST: StateManager> {
    state_tree: ST,
    status: ChainStatus,
    recent_blocks: Vec<Block<ChainTransaction>>,
    recent_aft_recovered_state: AftRecoveredStateSurface,
    last_state_root: Vec<u8>,
    genesis_state: GenesisState,
    services: ServiceDirectory,
    service_manager: ServiceUpgradeManager,
    service_meta_cache: HashMap<String, Arc<ActiveServiceMeta>>,
}

/// Opaque rollback material held across one speculative AFT replacement.
///
/// The token grants no ordering authority. It exists only so a replacement
/// rejected before changing the durable target block or state root can restore the exact live
/// projection and its bounded rollback suffix instead of freezing an honest
/// node on peer-controlled invalid content.
pub struct AftBranchRollbackTransaction<ST: StateManager> {
    live_snapshot: AftLiveProjectionSnapshot<ST>,
    retired_snapshots: Vec<AftTipRollbackSnapshot<ST>>,
}

const MAX_AFT_SPECULATIVE_PROJECTIONS: u64 = 2;

fn aft_branch_rollback_count(
    live_height: u64,
    expected_live_height: u64,
    target_height: u64,
    recognized_height: u64,
    available_snapshots: usize,
) -> Result<usize, ChainError> {
    if live_height != expected_live_height {
        return Err(ChainError::Transaction(format!(
            "stale AFT live-tip fence: expected {}, live {}",
            expected_live_height, live_height
        )));
    }
    if target_height <= recognized_height {
        return Err(ChainError::Transaction(format!(
            "AFT branch replacement target {} is at or below Agentgres-recognized height {}",
            target_height, recognized_height
        )));
    }
    if live_height < target_height {
        return Err(ChainError::Transaction(format!(
            "stale AFT branch replacement height: target {}, live {}",
            target_height, live_height
        )));
    }
    let count = live_height
        .checked_sub(target_height)
        .and_then(|distance| distance.checked_add(1))
        .ok_or_else(|| ChainError::Transaction("AFT rollback depth overflow".into()))?;
    if count > MAX_AFT_SPECULATIVE_PROJECTIONS {
        return Err(ChainError::Transaction(format!(
            "AFT branch replacement depth {} exceeds the two-chain projection bound",
            count
        )));
    }
    let count = usize::try_from(count)
        .map_err(|_| ChainError::Transaction("AFT rollback depth is not representable".into()))?;
    if available_snapshots < count {
        return Err(ChainError::Transaction(
            "AFT branch replacement snapshots are unavailable; freeze/restart recovery required"
                .into(),
        ));
    }
    Ok(count)
}

pub struct ExecutionMachine<CS: CommitmentScheme + Clone, ST: StateManager> {
    pub state: ExecutionMachineState<CS>,
    pub services: ServiceDirectory,
    pub service_manager: ServiceUpgradeManager,
    pub consensus_engine: Consensus<ioi_types::app::ChainTransaction>,
    workload_container: Arc<WorkloadContainer<ST>>,
    /// In-memory cache for fast access to on-chain service metadata.
    pub service_meta_cache: HashMap<String, Arc<ActiveServiceMeta>>,
    /// Reversible, non-authoritative AFT projections for the bounded two-chain
    /// pipeline. Entries are ordered from oldest to newest and never authorize
    /// a rollback at or below the Agentgres-recognized height.
    pub(crate) aft_tip_rollbacks: Vec<AftTipRollbackSnapshot<ST>>,
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
/// Testing-harness escape hatch mirroring the stable-state-dir resume lane
/// in crates/validator/src/standard/workload/setup.rs: GuardianMajority
/// harness chains publish no canonical collapse objects (that publication
/// lane is Asymptote-only), so the bounded AFT restart surface can never be
/// extracted for them. With the env set (only by the testing harness in
/// crates/cli/src/testing) the restart proceeds with the same empty
/// recovered surface every non-AFT chain uses. Never set in production;
/// without it the behavior is byte-identical.
fn testing_trivial_aft_restart_anchor_enabled() -> bool {
    std::env::var("IOI_TESTING_AFT_TRIVIAL_RESTART_ANCHOR")
        .map(|value| value == "1")
        .unwrap_or(false)
}

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
            aft_tip_rollbacks: Vec::new(),
            service_policies,
            os_driver,
        })
    }

    /// Restores the exact parent snapshot of a bounded AFT workload branch.
    ///
    /// This method is intentionally narrower than a general chain reorg. It
    /// can retire at most the two in-memory projections permitted by the AFT
    /// two-chain pipeline, every retired projection is changed-byte fenced,
    /// and the target must remain strictly above the Agentgres-recognized
    /// height supplied by the runtime. The snapshots are never themselves
    /// evidence of finality or authority.
    pub async fn rollback_aft_branch_projection(
        &mut self,
        expected_target: &Block<ChainTransaction>,
        expected_live_tip: &Block<ChainTransaction>,
        recognized_height: u64,
    ) -> Result<AftBranchRollbackTransaction<ST>, ChainError>
    where
        ST: Clone,
    {
        if self.consensus_engine.consensus_type() != ConsensusType::Aft {
            return Err(ChainError::Transaction(
                "tip replacement is available only to the canonical AFT profile".into(),
            ));
        }
        let expected_height = expected_target.header.height;
        let live_height = self.state.status.height;
        let rollback_count = aft_branch_rollback_count(
            live_height,
            expected_live_tip.header.height,
            expected_height,
            recognized_height,
            self.aft_tip_rollbacks.len(),
        )?;

        let target_tip = self
            .state
            .recent_blocks
            .iter()
            .rev()
            .find(|block| block.header.height == expected_height)
            .ok_or_else(|| {
                ChainError::Transaction(format!(
                    "AFT branch replacement target {} is unavailable",
                    expected_height
                ))
            })?;
        if codec::to_bytes_canonical(target_tip).map_err(ChainError::Transaction)?
            != codec::to_bytes_canonical(expected_target).map_err(ChainError::Transaction)?
        {
            return Err(ChainError::Transaction(
                "changed-byte or stale AFT branch replacement target fence".into(),
            ));
        }

        let live_tip = self.state.recent_blocks.last().ok_or_else(|| {
            ChainError::Transaction("AFT branch replacement has no live tip block".into())
        })?;
        if codec::to_bytes_canonical(live_tip).map_err(ChainError::Transaction)?
            != codec::to_bytes_canonical(expected_live_tip).map_err(ChainError::Transaction)?
        {
            return Err(ChainError::Transaction(
                "changed-byte or stale AFT branch replacement live-tip fence".into(),
            ));
        }

        let snapshot_start = self.aft_tip_rollbacks.len() - rollback_count;
        for (offset, snapshot) in self.aft_tip_rollbacks[snapshot_start..].iter().enumerate() {
            let projected_height = expected_height + offset as u64;
            let projected = self
                .state
                .recent_blocks
                .iter()
                .rev()
                .find(|block| block.header.height == projected_height)
                .ok_or_else(|| {
                    ChainError::Transaction(format!(
                        "AFT projected block {} is unavailable for branch fencing",
                        projected_height
                    ))
                })?;
            let projected_parent = self
                .state
                .recent_blocks
                .iter()
                .rev()
                .find(|block| block.header.height.saturating_add(1) == projected_height)
                .ok_or_else(|| {
                    ChainError::Transaction(format!(
                        "AFT projected parent of height {} is unavailable for branch fencing",
                        projected_height
                    ))
                })?;
            let snapshot_parent = snapshot.recent_blocks.last().ok_or_else(|| {
                ChainError::Transaction(format!(
                    "AFT rollback snapshot for height {} has no parent block",
                    projected_height
                ))
            })?;
            let projected_parent_hash = projected_parent
                .header
                .hash()
                .map_err(|error| ChainError::Transaction(error.to_string()))?;
            if snapshot.projected_height != projected_height
                || snapshot.projected_parent_state_root != projected.header.parent_state_root.0
                || snapshot.projected_state_root != projected.header.state_root.0
                || snapshot.projected_transactions_root != projected.header.transactions_root
                || snapshot.status.height.saturating_add(1) != projected_height
                || codec::to_bytes_canonical(snapshot_parent).map_err(ChainError::Transaction)?
                    != codec::to_bytes_canonical(projected_parent)
                        .map_err(ChainError::Transaction)?
                || projected.header.parent_hash.as_slice() != projected_parent_hash.as_slice()
                || projected.header.parent_state_root != projected_parent.header.state_root
            {
                return Err(ChainError::Transaction(format!(
                    "AFT rollback snapshot does not bind projected height {}",
                    projected_height
                )));
            }
            let snapshot_root = snapshot.state_tree.root_commitment().as_ref().to_vec();
            if snapshot_root != snapshot.last_state_root {
                return Err(ChainError::Transaction(format!(
                    "AFT rollback snapshot for height {} restores root {} instead of {}",
                    projected_height,
                    hex::encode(snapshot_root),
                    hex::encode(&snapshot.last_state_root)
                )));
            }
        }
        let restored_parent = &self.aft_tip_rollbacks[snapshot_start];
        if restored_parent.status.height.saturating_add(1) != expected_height
            || restored_parent.last_state_root != expected_target.header.parent_state_root.0
        {
            return Err(ChainError::Transaction(format!(
                "AFT rollback snapshot suffix does not restore the fenced parent of height {}",
                expected_height
            )));
        }
        let live_root = {
            let state = self.workload_container.state_tree().read_owned().await;
            state.root_commitment().as_ref().to_vec()
        };
        if live_tip.header.height != live_height || live_root != live_tip.header.state_root.0 {
            return Err(ChainError::Transaction(format!(
                "AFT branch replacement live-tip fence mismatch at height {}: block {}, live {}",
                live_height,
                hex::encode(&live_tip.header.state_root.0),
                hex::encode(live_root)
            )));
        }

        // Every fallible fence is complete before split_off mutates the
        // snapshot stack. A crash before the later durable replacement commit
        // leaves the pre-call durable projection in place. A completed commit
        // publishes replacement bytes at the target height; any retired higher
        // projection remains physically present but is hidden by the canonical
        // committed-height read boundary.
        let live_snapshot = AftLiveProjectionSnapshot {
            state_tree: {
                let state = self.workload_container.state_tree().read_owned().await;
                state.clone()
            },
            status: self.state.status.clone(),
            recent_blocks: self.state.recent_blocks.clone(),
            recent_aft_recovered_state: self.state.recent_aft_recovered_state.clone(),
            last_state_root: self.state.last_state_root.clone(),
            genesis_state: self.state.genesis_state.clone(),
            services: self.services.clone(),
            service_manager: self.service_manager.clone(),
            service_meta_cache: self.service_meta_cache.clone(),
        };
        let retired_snapshots = self.aft_tip_rollbacks.split_off(snapshot_start);
        for snapshot in retired_snapshots.iter().rev() {
            self.apply_aft_projection_snapshot(snapshot).await;
        }

        tracing::warn!(
            target: "execution",
            replacement_target_height = expected_height,
            retired_live_height = live_height,
            restored_height = self.state.status.height,
            restored_root = %hex::encode(&self.state.last_state_root),
            "Rolled back a bounded unrecognized AFT workload branch under exact projection fences"
        );
        Ok(AftBranchRollbackTransaction {
            live_snapshot,
            retired_snapshots,
        })
    }

    async fn apply_aft_projection_snapshot(&mut self, snapshot: &AftTipRollbackSnapshot<ST>)
    where
        ST: Clone,
    {
        {
            let state_tree = self.workload_container.state_tree();
            let mut state = state_tree.write().await;
            *state = snapshot.state_tree.clone();
        }
        self.state.status = snapshot.status.clone();
        self.state.recent_blocks = snapshot.recent_blocks.clone();
        self.state.recent_aft_recovered_state = snapshot.recent_aft_recovered_state.clone();
        self.state.last_state_root = snapshot.last_state_root.clone();
        self.state.genesis_state = snapshot.genesis_state.clone();
        self.services = snapshot.services.clone();
        self.service_manager = snapshot.service_manager.clone();
        self.service_meta_cache = snapshot.service_meta_cache.clone();
    }

    async fn restore_aft_live_projection(&mut self, snapshot: AftLiveProjectionSnapshot<ST>) {
        {
            let state_tree = self.workload_container.state_tree();
            let mut state = state_tree.write().await;
            *state = snapshot.state_tree;
        }
        self.state.status = snapshot.status;
        self.state.recent_blocks = snapshot.recent_blocks;
        self.state.recent_aft_recovered_state = snapshot.recent_aft_recovered_state;
        self.state.last_state_root = snapshot.last_state_root;
        self.state.genesis_state = snapshot.genesis_state;
        self.services = snapshot.services;
        self.service_manager = snapshot.service_manager;
        self.service_meta_cache = snapshot.service_meta_cache;
    }

    /// Restore the exact pre-replacement live projection after a rejection
    /// proven to have left the durable target block and state root unchanged.
    pub async fn restore_aft_branch_projection(
        &mut self,
        transaction: AftBranchRollbackTransaction<ST>,
    ) where
        ST: Clone,
    {
        self.restore_aft_live_projection(transaction.live_snapshot)
            .await;
        self.aft_tip_rollbacks.extend(transaction.retired_snapshots);
        debug_assert!(
            self.aft_tip_rollbacks.len() <= MAX_AFT_SPECULATIVE_PROJECTIONS as usize,
            "restored AFT rollback suffix exceeded its protocol bound"
        );
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
                self.state.recent_aft_recovered_state = AftRecoveredStateSurface::default();
                if self.consensus_engine.consensus_type() == ConsensusType::Aft
                    && self.state.status.height > 0
                    && !testing_trivial_aft_restart_anchor_enabled()
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

                let root = state.root_commitment().as_ref().to_vec();
                self.state.last_state_root = root.clone();
                self.state.genesis_state = GenesisState::Ready {
                    root,
                    chain_id: self.state.chain_id,
                };
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
#[path = "tests.rs"]
mod tests;
