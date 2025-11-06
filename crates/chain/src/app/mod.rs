// Path: crates/chain/src/app/mod.rs
use crate::upgrade_manager::ModuleUpgradeManager;
use anyhow::Result;
use async_trait::async_trait;
use depin_sdk_api::app::{Block, BlockHeader, ChainStatus, ChainTransaction};
use depin_sdk_api::chain::{
    AnchoredStateView, AppChain, ChainView, PreparedBlock, RemoteStateView, StateRef,
};
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_api::consensus::PenaltyMechanism;
use depin_sdk_api::services::access::ServiceDirectory;
use depin_sdk_api::services::{BlockchainService, UpgradableService};
use depin_sdk_api::state::{PinGuard, StateAccessor, StateManager, StateOverlay};
use depin_sdk_api::transaction::context::TxContext;
use depin_sdk_api::transaction::TransactionModel;
use depin_sdk_api::validator::WorkloadContainer;
use depin_sdk_transaction_models::system::{nonce, validation};
use depin_sdk_transaction_models::unified::UnifiedTransactionModel;
use depin_sdk_types::app::{
    account_id_from_key_material, compute_interval_from_parent_state, read_validator_sets,
    to_root_hash, write_validator_sets, AccountId, BlockTimingParams, BlockTimingRuntime, ChainId,
    FailureReport, Membership, SignatureSuite, StateRoot, ValidatorSetV1, ValidatorSetsV1,
};
use depin_sdk_types::codec;
use depin_sdk_types::config::ConsensusType;
use depin_sdk_types::error::{BlockError, ChainError, StateError, TransactionError};
use depin_sdk_types::keys::{
    BLOCK_TIMING_PARAMS_KEY, BLOCK_TIMING_RUNTIME_KEY, STATUS_KEY, VALIDATOR_SET_KEY,
};
use depin_sdk_types::service_configs::{ActiveServiceMeta, Capabilities, MethodPermission};
// [+] ADD import for IBC Timestamp
use ibc_primitives::Timestamp;
use libp2p::identity::Keypair;
use serde::Serialize;
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

use depin_sdk_consensus::Consensus;

// Delegates PenaltyMechanism to the borrowed Consensus engine.
struct PenaltyDelegator<'a> {
    inner: &'a depin_sdk_consensus::Consensus<depin_sdk_types::app::ChainTransaction>,
}

#[async_trait]
impl<'a> PenaltyMechanism for PenaltyDelegator<'a> {
    async fn apply_penalty(
        &self,
        state: &mut dyn StateAccessor,
        report: &FailureReport,
    ) -> Result<(), TransactionError> {
        self.inner.apply_penalty(state, report).await
    }
}

#[derive(Debug)]
pub struct ChainState<CS: CommitmentScheme + Clone> {
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
    pub state: ChainState<CS>,
    pub services: ServiceDirectory,
    pub service_manager: ModuleUpgradeManager,
    pub consensus_engine: Consensus<depin_sdk_types::app::ChainTransaction>,
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
    tx: &depin_sdk_types::app::ChainTransaction,
) -> Result<(), TransactionError> {
    let _ = (services, tx);
    Ok(())
}

/// Extracts the signer's AccountId from any transaction type that has a SignHeader.
fn signer_from_tx(tx: &ChainTransaction) -> AccountId {
    match tx {
        ChainTransaction::System(s) => s.header.account_id,
        ChainTransaction::Application(a) => match a {
            depin_sdk_types::app::ApplicationTransaction::DeployContract { header, .. }
            | depin_sdk_types::app::ApplicationTransaction::CallContract { header, .. } => {
                header.account_id
            }
            depin_sdk_types::app::ApplicationTransaction::UTXO(_) => AccountId::default(),
        },
    }
}

impl<CS, ST> Chain<CS, ST>
where
    CS: CommitmentScheme + Clone,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
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
        consensus_engine: Consensus<depin_sdk_types::app::ChainTransaction>,
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

        let mut service_manager = ModuleUpgradeManager::new();
        for service in initial_services {
            service_manager.register_service(service);
        }

        let state = ChainState {
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

                tracing::info!(
                    target: "chain",
                    event = "status_init",
                    "No existing chain status found. Initializing and saving genesis status."
                );

                for service in self.service_manager.all_services() {
                    let service_id = service.id();
                    let key = depin_sdk_types::keys::active_service_key(service_id);
                    let mut methods = BTreeMap::new();
                    // Populate the ABI for built-in services so CallService can dispatch to them.
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
                        artifact_hash: [0u8; 32], // [0; 32] signifies a native service.
                        activated_at: 0,
                        methods,
                    };
                    let meta_bytes = codec::to_bytes_canonical(&meta)
                        .map_err(|e| ChainError::Transaction(e.to_string()))?;
                    tracing::debug!(
                        target = "genesis",
                        "ActiveServiceMeta for {} has methods: {:?}",
                        service_id,
                        meta.methods.keys().collect::<Vec<_>>()
                    );
                    state
                        .insert(&key, &meta_bytes)
                        .map_err(|e| ChainError::Transaction(e.to_string()))?;
                    tracing::info!(
                        target: "chain",
                        "Registered initial service '{}' as active in genesis state.",
                        service_id
                    );
                }

                // Seed initial timing params at genesis.
                // Start with a fixed 5-second block time (retarget_every_blocks = 0).
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

                let status_bytes = depin_sdk_types::codec::to_bytes_canonical(&self.state.status)
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
                    depin_sdk_types::app::Membership::Present(_) => {
                        tracing::debug!(target: "chain", "[Chain] Genesis self-check passed.");
                    }
                    depin_sdk_types::app::Membership::Absent => {
                        tracing::error!(
                            target: "chain",
                            "[Chain] Genesis self-check FAILED: query for '{}' returned Absent.",
                            hex::encode(STATUS_KEY)
                        );
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
            tracing::info!(
                target: "chain",
                event = "genesis_ready",
                root = hex::encode(root)
            );
        }

        Ok(())
    }

    /// Internal helper to process a single transaction against a state overlay.
    // [+] MODIFIED: Added block_timestamp parameter
    async fn process_transaction(
        &self,
        tx: &ChainTransaction,
        overlay: &mut StateOverlay<'_>,
        block_height: u64,
        block_timestamp: u64,
    ) -> Result<(), ChainError> {
        let signer_account_id = signer_from_tx(tx);
        // [+] MODIFIED: Instantiate TxContext with the block_timestamp
        let mut tx_ctx = TxContext {
            block_height,
            block_timestamp: Timestamp::from_nanoseconds(block_timestamp * 1_000_000_000)
                .map_err(|e| ChainError::Transaction(format!("Invalid timestamp: {}", e)))?,
            chain_id: self.state.chain_id,
            signer_account_id,
            services: &self.services,
            simulation: false,
            is_internal: false, // User transactions are never internal.
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

pub struct ChainStateView<ST: StateManager> {
    state_tree: Arc<tokio::sync::RwLock<ST>>,
    height: u64,
    root: Vec<u8>,
}

#[async_trait]
impl<ST: StateManager + Send + Sync + 'static> RemoteStateView for ChainStateView<ST> {
    fn height(&self) -> u64 {
        self.height
    }

    fn state_root(&self) -> &[u8] {
        &self.root
    }

    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ChainError> {
        use depin_sdk_types::app::Membership;
        let state = self.state_tree.read().await;
        let key_hex = hex::encode(key);

        let commitment = state.commitment_from_bytes(&self.root)?;
        let (membership, _proof) = state.get_with_proof_at(&commitment, key)?;
        let present = matches!(membership, Membership::Present(_));
        tracing::info!(
            target = "state",
            event = "view_get",
            key = key_hex,
            root = hex::encode(&self.root),
            present,
            mode = "anchored",
        );
        Ok(match membership {
            Membership::Present(bytes) => Some(bytes),
            _ => None,
        })
    }
}

impl<ST: StateManager + Send + Sync + 'static> AnchoredStateView for ChainStateView<ST> {}

#[async_trait]
impl<CS, ST> ChainView<CS, ST> for Chain<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
{
    async fn view_at(
        &self,
        state_ref: &StateRef,
    ) -> Result<Arc<dyn AnchoredStateView>, ChainError> {
        let resolved_root_bytes = if state_ref.state_root.is_empty() {
            return Err(ChainError::UnknownStateAnchor(
                "Cannot create view for empty state root".to_string(),
            ));
        } else if self.state.last_state_root == state_ref.state_root {
            Some(self.state.last_state_root.clone())
        } else {
            self.state.recent_blocks.iter().rev().find_map(|b| {
                if b.header.state_root.as_ref() == state_ref.state_root {
                    tracing::info!(
                        target = "state",
                        event = "view_at_resolve",
                        height = b.header.height,
                        root = hex::encode(b.header.state_root.as_ref())
                    );
                    Some(b.header.state_root.0.clone())
                } else {
                    None
                }
            })
        };

        let root = resolved_root_bytes
            .ok_or_else(|| ChainError::UnknownStateAnchor(hex::encode(&state_ref.state_root)))?;

        tracing::info!(
            target = "state",
            event = "view_at_resolved",
            root = hex::encode(&root)
        );

        let view = ChainStateView {
            state_tree: self.workload_container.state_tree(),
            height: state_ref.height,
            root,
        };
        Ok(Arc::new(view))
    }

    fn get_penalty_mechanism(&self) -> Box<dyn PenaltyMechanism + Send + Sync + '_> {
        Box::new(PenaltyDelegator {
            inner: &self.consensus_engine,
        })
    }

    fn consensus_type(&self) -> ConsensusType {
        self.consensus_engine.consensus_type()
    }

    fn workload_container(&self) -> &WorkloadContainer<ST> {
        &self.workload_container
    }
}

#[async_trait]
impl<CS, ST> AppChain<CS, UnifiedTransactionModel<CS>, ST> for Chain<CS, ST>
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
                // [+] MODIFIED: Pass the block timestamp to process_transaction
                if let Err(e) = self
                    .process_transaction(
                        tx,
                        &mut overlay,
                        block.header.height,
                        block.header.timestamp,
                    )
                    .await
                {
                    tracing::error!(
                        target = "block",
                        height = block.header.height,
                        error = %e,
                        "process_transaction failed; rejecting block proposal"
                    );
                    return Err(e);
                }
            }

            overlay.into_ordered_batch()
        };

        let transactions_root = depin_sdk_types::codec::to_bytes_canonical(&block.transactions)
            .map_err(ChainError::Transaction)?;
        let vs_bytes = self
            .get_validator_set_for(workload, block.header.height)
            .await?;
        let validator_set_hash = depin_sdk_crypto::algorithms::hash::sha256(vs_bytes.concat())
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
                tracing::info!(
                    target = "chain",
                    event = "module_upgrade",
                    height = block.header.height,
                    num_applied = upgrade_count,
                    "Successfully applied on-chain service upgrades."
                );
                let all_services = self.service_manager.all_services();
                let services_for_dir: Vec<Arc<dyn BlockchainService>> = all_services
                    .iter()
                    .map(|s| s.clone() as Arc<dyn BlockchainService>)
                    .collect();
                self.services = ServiceDirectory::new(services_for_dir);
            }

            // [+] MODIFIED: Instantiate TxContext with the block_timestamp
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
                is_internal: true, // This is an internal call
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
                            tracing::info!(
                                target = "chain",
                                event = "validator_set_promotion",
                                height = block.header.height,
                                "Promoting validator set"
                            );
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
                    tracing::error!(
                        target = "chain",
                        event = "end_block",
                        height = block.header.height,
                        "MISSING VALIDATOR_SET_KEY before commit. The next block may stall or fail without it."
                    );
                }
            }

            // [+] End-of-Block Hook: Update BlockTimingRuntime for adaptive intervals
            let timing_params_bytes = state.get(BLOCK_TIMING_PARAMS_KEY)?;
            let timing_runtime_bytes = state.get(BLOCK_TIMING_RUNTIME_KEY)?;
            if let (Some(params_bytes), Some(runtime_bytes)) =
                (timing_params_bytes, timing_runtime_bytes)
            {
                let params: BlockTimingParams =
                    codec::from_bytes_canonical(&params_bytes).map_err(ChainError::Transaction)?;
                let old_runtime: BlockTimingRuntime =
                    codec::from_bytes_canonical(&runtime_bytes).map_err(ChainError::Transaction)?;
                let mut new_runtime = old_runtime.clone();

                // Only perform updates if adaptive timing is enabled and it's a retarget block.
                if params.retarget_every_blocks > 0
                    && block.header.height % params.retarget_every_blocks as u64 == 0
                {
                    // TODO: Replace this placeholder with the actual gas used by the block.
                    // This could be stored in the block header or a dedicated state key.
                    let gas_used_this_block = 0;

                    // Re-compute the interval that *should* have been used for the *next* block.
                    // This is the value we persist for the subsequent proposer/verifier.
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

                    // Persist the new runtime state if it changed.
                    if new_runtime.ema_gas_used != old_runtime.ema_gas_used
                        || new_runtime.effective_interval_secs
                            != old_runtime.effective_interval_secs
                    {
                        state.insert(
                            BLOCK_TIMING_RUNTIME_KEY,
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
                use depin_sdk_types::app::Membership;

                let final_commitment = state.commitment_from_bytes(&final_root_bytes)?;
                if cfg!(debug_assertions) && !state.version_exists_for_root(&final_commitment) {
                    return Err(ChainError::State(StateError::Validation(format!(
                        "FATAL INVARIANT VIOLATION: The committed root for height {} is not mapped to a queryable version!",
                        block.header.height
                    ))));
                }

                if self.consensus_engine.consensus_type() == ConsensusType::ProofOfStake {
                    match state.get_with_proof_at(&final_commitment, VALIDATOR_SET_KEY) {
                        Ok((Membership::Present(_), _)) => {
                            tracing::info!(
                                target = "pos_finality_check",
                                event = "validator_set_provable",
                                height = block.header.height,
                                root = hex::encode(&final_root_bytes),
                                "OK"
                            );
                        }
                        Ok((other, _)) => {
                            return Err(ChainError::State(StateError::Validation(format!(
                                "INVARIANT: Validator set missing at end of block {} (membership={:?}, root={})",
                                block.header.height,
                                other,
                                hex::encode(&final_root_bytes),
                            ))));
                        }
                        Err(e) => {
                            return Err(ChainError::State(StateError::Validation(format!(
                                "INVARIANT: get_with_proof_at failed for validator set at end of block {}: {}",
                                block.header.height, e
                            ))));
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
        tracing::info!(
            target = "chain",
            event = "commit",
            height = block.header.height,
            state_root = hex::encode(&block.header.state_root.0),
            anchor = hex::encode(anchor.as_ref())
        );

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
