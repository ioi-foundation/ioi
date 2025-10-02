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
use depin_sdk_api::services::access::{Service, ServiceDirectory};
use depin_sdk_api::services::{ServiceType, UpgradableService};
use depin_sdk_api::state::{PinGuard, StateAccessor, StateManager, StateOverlay};
use depin_sdk_api::transaction::context::TxContext;
use depin_sdk_api::transaction::TransactionModel;
use depin_sdk_api::validator::WorkloadContainer;
use depin_sdk_transaction_models::system::{nonce, validation};
use depin_sdk_transaction_models::unified::UnifiedTransactionModel;
use depin_sdk_types::app::{
    account_id_from_key_material, read_validator_sets, to_root_hash, write_validator_sets,
    AccountId, ChainId, FailureReport, SignatureSuite, StateRoot, ValidatorSetV1, ValidatorSetsV1,
};
use depin_sdk_types::codec;
use depin_sdk_types::config::ConsensusType;
use depin_sdk_types::error::{BlockError, ChainError, StateError, TransactionError};
use depin_sdk_types::keys::{STATUS_KEY, VALIDATOR_SET_KEY};
use libp2p::identity::Keypair;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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

type ServiceFactory = Box<
    dyn Fn(&[u8]) -> Result<Arc<dyn UpgradableService>, depin_sdk_types::error::CoreError>
        + Send
        + Sync,
>;

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
            .finish()
    }
}

/// Checks if the services required for a specific transaction type are enabled.
fn preflight_capabilities(
    services: &ServiceDirectory,
    tx: &depin_sdk_types::app::ChainTransaction,
) -> Result<(), TransactionError> {
    if let depin_sdk_types::app::ChainTransaction::System(sys_tx) = tx {
        if let depin_sdk_types::app::SystemPayload::RotateKey(_) = sys_tx.payload {
            if services
                .services()
                .find_map(|s| s.as_credentials_view())
                .is_none()
            {
                return Err(TransactionError::Unsupported(
                    "RotateKey requires the IdentityHub service".into(),
                ));
            }
        }
    }
    Ok(())
}

impl<CS, ST> Chain<CS, ST>
where
    CS: CommitmentScheme + Clone,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
{
    /// Select the validator set that is effective for the given height.
    /// Mirrors the logic used by the PoS engine.
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
        service_factory: ServiceFactory,
        consensus_engine: Consensus<depin_sdk_types::app::ChainTransaction>,
        workload_container: Arc<WorkloadContainer<ST>>,
    ) -> Self {
        let status = ChainStatus {
            height: 0,
            latest_timestamp: 0,
            total_transactions: 0,
            is_running: false,
        };

        let services_for_dir: Vec<Arc<dyn Service>> = initial_services
            .iter()
            .map(|s| s.clone() as Arc<dyn Service>)
            .collect();
        let service_directory = ServiceDirectory::new(services_for_dir);

        let mut service_manager = ModuleUpgradeManager::new(service_factory);
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
        }
    }

    pub async fn load_or_initialize_status(
        &mut self,
        workload: &WorkloadContainer<ST>,
    ) -> Result<(), ChainError> {
        let state_tree_arc = workload.state_tree();
        let mut state = state_tree_arc.write().await;
        match state.get(STATUS_KEY) {
            Ok(Some(status_bytes)) => {
                let status: ChainStatus =
                    codec::from_bytes_canonical(&status_bytes).map_err(ChainError::Transaction)?;
                tracing::info!(target: "chain", event = "status_loaded", height = status.height);
                self.state.status = status;
                let root = state.root_commitment().as_ref().to_vec();
                self.state.genesis_state = GenesisState::Ready {
                    root: root.clone(),
                    chain_id: self.state.chain_id,
                };
                self.state.last_state_root = root;
            }
            Ok(None) => {
                tracing::info!(
                    target: "chain",
                    event = "status_init",
                    "No existing chain status found. Initializing and saving genesis status."
                );

                // Persist initial services in the canonical, queryable state.
                for service in self.service_manager.all_services() {
                    let type_str = match service.service_type() {
                        ServiceType::Custom(s) => s.clone(),
                        st => format!("{st:?}"),
                    };
                    // Write the canonical "active" key into the main state tree.
                    let key = depin_sdk_types::keys::active_service_key(&type_str);
                    state.insert(&key, &[])?; // Value can be empty; existence is enough.
                    tracing::info!(target: "chain", "Registered initial service {:?} as active in genesis state.", service.service_type());
                }

                // The first commit is for height 0 (genesis).
                state.commit_version(0)?;
                tracing::debug!(target: "chain", "[Chain] Committed full genesis state.");

                let status_bytes = depin_sdk_types::codec::to_bytes_canonical(&self.state.status)
                    .map_err(ChainError::Transaction)?;
                state
                    .insert(STATUS_KEY, &status_bytes)
                    .map_err(|e| ChainError::Transaction(e.to_string()))?;

                // The second commit finalizes the state including the status key.
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
        };
        Ok(())
    }

    /// Internal helper to process a single transaction against a state overlay.
    async fn process_transaction(
        &self,
        tx: &ChainTransaction,
        overlay: &mut StateOverlay<'_>,
        block_height: u64,
    ) -> Result<(), ChainError> {
        let tx_ctx = TxContext {
            block_height,
            chain_id: self.state.chain_id,
            services: &self.services,
            simulation: false,
        };

        preflight_capabilities(&self.services, tx)?;
        validation::verify_transaction_signature(overlay, &self.services, tx, &tx_ctx)?;
        nonce::assert_next_nonce(overlay, tx)?;

        for service in self.services.services_in_deterministic_order() {
            if let Some(decorator) = service.as_tx_decorator() {
                decorator.ante_handle(overlay, tx, &tx_ctx)?;
            }
        }

        nonce::bump_nonce(overlay, tx)?;
        self.state
            .transaction_model
            .apply_payload(self, overlay, tx, tx_ctx)
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

        // This view is always anchored, so we use the proof-based path.
        let commitment = state.commitment_from_bytes(&self.root)?;
        let (membership, _proof) = state.get_with_proof_at(&commitment, key)?;
        let present = matches!(membership, Membership::Present(_));
        tracing::info!(
            target: "state",
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
                        target: "state",
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
            target: "state",
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
                self.process_transaction(tx, &mut overlay, block.header.height)
                    .await?;
            }

            let end_block_ctx = TxContext {
                block_height: block.header.height,
                chain_id: self.state.chain_id,
                services: &self.services,
                simulation: true,
            };
            for service in self.services.services_in_deterministic_order() {
                if let Some(hook) = service.as_on_end_block() {
                    hook.on_end_block(&mut overlay, &end_block_ctx)?;
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
            state.batch_apply(inserts, deletes)?;

            match state.get(VALIDATOR_SET_KEY)? {
                Some(bytes) => {
                    let mut sets = read_validator_sets(&bytes)?;
                    let mut modified = false;
                    if let Some(next_vs) = &sets.next {
                        if block.header.height >= next_vs.effective_from_height {
                            tracing::info!(
                                target: "chain",
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
                        target: "chain",
                        event = "end_block",
                        height = block.header.height,
                        "MISSING VALIDATOR_SET_KEY before commit. The next block may stall or fail without it."
                    );
                }
            }

            let upgrade_key = [
                depin_sdk_types::keys::UPGRADE_PENDING_PREFIX,
                &block.header.height.to_le_bytes(),
            ]
            .concat();

            if let Some(upgrade_bytes) = state.get(&upgrade_key)? {
                let upgrades: Vec<(String, Vec<u8>)> =
                    depin_sdk_types::codec::from_bytes_canonical(&upgrade_bytes)
                        .unwrap_or_else(|_| Default::default());
                let mut applied_count = 0;
                for (service_type_str, wasm) in upgrades {
                    let service_type =
                        depin_sdk_api::services::ServiceType::Custom(service_type_str);

                    match self
                        .service_manager
                        .execute_upgrade(&service_type, &wasm, &mut *state)
                    {
                        Ok(_) => applied_count += 1,
                        Err(e) => {
                            tracing::error!(
                                target: "chain",
                                event = "upgrade_fail",
                                ?service_type,
                                height = block.header.height,
                                error = %e,
                            );
                        }
                    }
                }
                if applied_count > 0 {
                    let all_active_services = self.service_manager.all_services();
                    let services_for_dir: Vec<Arc<dyn Service>> = all_active_services
                        .into_iter()
                        .map(|s| s as Arc<dyn Service>)
                        .collect();
                    self.services = ServiceDirectory::new(services_for_dir);
                    tracing::info!(
                        target: "chain",
                        event = "upgrades_applied",
                        count = applied_count,
                        height = block.header.height,
                    );
                }
                state.delete(&upgrade_key)?;
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
                                target: "pos_finality_check",
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
            target: "chain",
            event = "commit",
            height = block.header.height,
            state_root = hex::encode(&block.header.state_root.0),
            anchor = hex::encode(anchor.as_ref())
        );

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

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| ChainError::Time(e.to_string()))?
            .as_secs();

        let mut header = BlockHeader {
            height,
            parent_hash,
            parent_state_root,
            state_root: StateRoot(vec![]), // Placeholder, filled in by commit_block
            transactions_root: vec![],     // Placeholder, filled in by prepare_block
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
