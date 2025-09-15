// Path: crates/chain/src/app/mod.rs
use crate::upgrade_manager::ModuleUpgradeManager;
use async_trait::async_trait;
use depin_sdk_api::chain::{AppChain, ChainView, StakeAmount, StateView};
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_api::consensus::PenaltyMechanism;
use depin_sdk_api::services::access::{Service, ServiceDirectory};
use depin_sdk_api::services::UpgradableService;
use depin_sdk_api::state::{StateAccessor, StateManager, StateOverlay};
use depin_sdk_api::transaction::context::TxContext;
use depin_sdk_api::transaction::TransactionModel;
use depin_sdk_api::validator::WorkloadContainer;
use depin_sdk_transaction_models::system::{nonce, validation};
use depin_sdk_transaction_models::unified::UnifiedTransactionModel;
use depin_sdk_types::app::{
    account_id_from_key_material, read_validator_sets, write_validator_sets, AccountId,
    ActiveKeyRecord, Block, BlockHeader, ChainStatus, ChainTransaction, FailureReport,
    SignatureSuite, StateAnchor, StateRoot, SystemPayload, ValidatorSetV1, ValidatorSetsV1,
};
use depin_sdk_types::codec;
use depin_sdk_types::config::ConsensusType;
use depin_sdk_types::error::{BlockError, ChainError, CoreError, StateError, TransactionError};
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
        /// The final, canonical state root of the fully initialized genesis state.
        root: StateRoot,
        /// The chain ID as loaded from configuration.
        chain_id: String,
    },
}

use depin_sdk_consensus::Consensus;

type ServiceFactory =
    Box<dyn Fn(&[u8]) -> Result<Arc<dyn UpgradableService>, CoreError> + Send + Sync>;

// Delegates PenaltyMechanism to the borrowed Consensus engine.
struct PenaltyDelegator<'a> {
    inner: &'a depin_sdk_consensus::Consensus<ChainTransaction>,
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
    pub chain_id: String,
    pub status: ChainStatus,
    pub recent_blocks: Vec<Block<ChainTransaction>>,
    pub max_recent_blocks: usize,
    /// Last committed state root. Initialized to the genesis root in `load_or_initialize_status`,
    /// then updated after every successful block commit.
    pub last_state_root: StateRoot,
    pub genesis_state: GenesisState,
}

pub struct Chain<CS: CommitmentScheme + Clone, ST: StateManager> {
    pub state: ChainState<CS>,
    pub services: ServiceDirectory,
    pub _service_manager: ModuleUpgradeManager,
    pub consensus_engine: Consensus<ChainTransaction>,
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
    tx: &ChainTransaction,
) -> Result<(), TransactionError> {
    if let ChainTransaction::System(sys_tx) = tx {
        if matches!(sys_tx.payload, SystemPayload::RotateKey(_))
            && services
                .services()
                .find_map(|s| s.as_credentials_view())
                .is_none()
        {
            return Err(TransactionError::Unsupported(
                "RotateKey requires the IdentityHub service".into(),
            ));
        }
    }
    Ok(())
}

impl<CS, ST> Chain<CS, ST>
where
    CS: CommitmentScheme + Clone,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
    // --- FIX START: Add the missing trait bounds here ---
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
    // --- FIX END ---
{
    /// Select the validator set that is effective for the given height.
    /// Mirrors the logic used by the PoS engine.
    fn select_set_for_height<'a>(sets: &'a ValidatorSetsV1, h: u64) -> &'a ValidatorSetV1 {
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
        chain_id: &str,
        initial_services: Vec<Arc<dyn UpgradableService>>,
        service_factory: ServiceFactory,
        consensus_engine: Consensus<ChainTransaction>,
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
            chain_id: chain_id.to_string(),
            status,
            recent_blocks: Vec::new(),
            max_recent_blocks: 100,
            last_state_root: StateRoot(vec![]),
            genesis_state: GenesisState::Pending,
        };

        Self {
            state,
            services: service_directory,
            _service_manager: service_manager,
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
                let status: ChainStatus = serde_json::from_slice(&status_bytes).map_err(|e| {
                    ChainError::Transaction(format!("Failed to deserialize status: {e}"))
                })?;
                log::info!("Loaded chain status: height {}", status.height);
                self.state.status = status;
                // If we loaded state, the last committed root is the current root.
                let root = StateRoot(state.root_commitment().as_ref().to_vec());
                self.state.genesis_state = GenesisState::Ready {
                    root: root.clone(),
                    chain_id: self.state.chain_id.clone(),
                };
                self.state.last_state_root = root;
            }
            Ok(None) => {
                log::info!(
                    "No existing chain status found. Initializing and saving genesis status."
                );
                // The genesis file has already been loaded at this point.
                // 1. Commit the fully-loaded genesis state to create version 0.
                state.commit_version();
                log::debug!("[Chain] Committed full genesis state.");

                // 2. Now write the initial status key.
                let status_bytes = serde_json::to_vec(&self.state.status).unwrap();
                state
                    .insert(STATUS_KEY, &status_bytes)
                    .map_err(|e| ChainError::Transaction(e.to_string()))?;

                // 3. Commit AGAIN to include the status key. This is the new canonical root for H=0.
                state.commit_version();
                log::debug!("[Chain] Committed genesis state including status key.");

                // 4. Set the final genesis state.
                let final_root = StateRoot(state.root_commitment().as_ref().to_vec());

                // ---- NEW: Perform self-check for proofability ----
                let root_commitment_for_check = state
                    .commitment_from_bytes(final_root.as_ref())
                    .expect("Failed to create commitment for self-check");
                let (membership, _proof) = state
                    .get_with_proof_at(&root_commitment_for_check, STATUS_KEY)
                    .expect("Failed to generate proof for self-check");
                match membership {
                    depin_sdk_types::app::Membership::Present(_) => {
                        log::debug!("[Chain] Genesis state self-check passed.");
                    }
                    _ => panic!("CRITICAL: Committed genesis state is not provable. Halting."),
                }
                // ---- END: Self-check ----

                self.state.genesis_state = GenesisState::Ready {
                    root: final_root.clone(),
                    chain_id: self.state.chain_id.clone(),
                };
                self.state.last_state_root = final_root;
            }
            Err(e) => return Err(ChainError::Transaction(e.to_string())),
        }

        if let GenesisState::Ready { root, .. } = &self.state.genesis_state {
            log::info!(
                "[Chain] Genesis ready with root {}",
                hex::encode(root.as_ref())
            );
        }
        Ok(())
    }

    /// Internal helper to process a single transaction against a state overlay.
    async fn process_transaction(
        &mut self,
        tx: &ChainTransaction,
        overlay: &mut StateOverlay<'_>,
        block_height: u64,
    ) -> Result<(), ChainError> {
        let tx_ctx = TxContext {
            block_height,
            chain_id: self.state.chain_id.parse().unwrap_or(1),
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

// A concrete implementation of StateView for the Chain.
pub struct ChainStateView<ST: StateManager> {
    state_tree: Arc<tokio::sync::RwLock<ST>>,
    anchor: StateAnchor,
    // Non-zero anchors are resolved to the full commitment bytes (StateRoot bytes).
    // None => latest state (fast path).
    resolved_root_bytes: Option<Vec<u8>>,
}

#[async_trait]
impl<ST: StateManager + Send + Sync + 'static> StateView for ChainStateView<ST> {
    fn state_anchor(&self) -> &StateAnchor {
        &self.anchor
    }

    async fn validator_set_legacy(&self) -> Result<Vec<AccountId>, ChainError> {
        let bytes = self
            .get(depin_sdk_types::keys::VALIDATOR_SET_KEY)
            .await?
            .ok_or_else(|| {
                ChainError::State(StateError::KeyNotFound(
                    "ValidatorSetBlob not found".to_string(),
                ))
            })?;

        let sets = depin_sdk_types::app::read_validator_sets(&bytes).map_err(ChainError::State)?;
        Ok(sets
            .current
            .validators
            .into_iter()
            .map(|v| v.account_id)
            .collect())
    }

    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ChainError> {
        use depin_sdk_types::app::Membership;
        let state = self.state_tree.read().await;
        let key_hex = hex::encode(key);

        if self.resolved_root_bytes.is_none() {
            // FAST PATH (latest snapshot)
            let out = state.get(key).map_err(ChainError::State)?;
            log::info!(
                "[StateView::get][fast] key={} -> present={}",
                key_hex,
                out.is_some()
            );
            return Ok(out);
        }

        // HISTORICAL PATH (anchored)
        let root_bytes = self.resolved_root_bytes.as_ref().unwrap();
        let commitment = state
            .commitment_from_bytes(root_bytes)
            .map_err(|e| ChainError::State(StateError::InvalidValue(e.to_string())))?;

        let (membership, _proof) = state
            .get_with_proof_at(&commitment, key)
            .map_err(ChainError::State)?;

        let present = matches!(membership, Membership::Present(_));
        log::info!(
            "[StateView::get][anchored] key={} root={} -> present={}",
            key_hex,
            hex::encode(root_bytes),
            present
        );

        Ok(match membership {
            Membership::Present(bytes) => Some(bytes),
            _ => None,
        })
    }

    async fn active_consensus_key(&self, acct: &AccountId) -> Option<ActiveKeyRecord> {
        const KEY_PREFIX: &[u8] = b"identity::key_record::";
        let key = [KEY_PREFIX, acct.as_ref()].concat();
        let bytes = self.get(&key).await.ok()??;
        codec::from_bytes_canonical(&bytes).ok()
    }
}

#[async_trait]
impl<CS, ST> ChainView<CS, ST> for Chain<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
{
    async fn view_at(&self, anchor: &StateAnchor) -> Result<Box<dyn StateView>, ChainError> {
        // Resolve the anchor (if non-zero) to the full StateRoot bytes.
        let resolved_root_bytes = if anchor.0 == [0u8; 32] {
            None
        } else if self.state.last_state_root.to_anchor() == *anchor {
            Some(self.state.last_state_root.as_ref().to_vec())
        } else {
            // Search recent blocks for a matching anchor.
            let bytes = self.state.recent_blocks.iter().rev().find_map(|b| {
                if b.header.state_root.to_anchor() == *anchor {
                    log::info!(
                        "[StateView::view_at] anchor={} matched H={} root={}",
                        hex::encode(anchor.as_ref()),
                        b.header.height,
                        hex::encode(b.header.state_root.as_ref())
                    );
                    Some(b.header.state_root.as_ref().to_vec())
                } else {
                    None
                }
            });
            if bytes.is_none() {
                return Err(ChainError::State(StateError::InvalidValue(format!(
                    "Could not resolve unknown state anchor: {}",
                    hex::encode(anchor.as_ref())
                ))));
            }
            bytes
        };

        if let Some(bytes) = &resolved_root_bytes {
            log::info!(
                "[StateView::view_at] anchor={} -> resolved_root={}",
                hex::encode(anchor.as_ref()),
                hex::encode(bytes)
            );
        } else {
            log::info!(
                "[StateView::view_at] anchor={} -> resolved_root=<LATEST>",
                hex::encode(anchor.as_ref())
            );
        }

        let view = ChainStateView {
            state_tree: self.workload_container.state_tree(),
            anchor: *anchor,
            resolved_root_bytes,
        };
        Ok(Box::new(view))
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
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
{
    fn status(&self) -> &ChainStatus {
        &self.state.status
    }

    fn transaction_model(&self) -> &UnifiedTransactionModel<CS> {
        &self.state.transaction_model
    }

    async fn process_block(
        &mut self,
        mut block: Block<ChainTransaction>,
        workload: &WorkloadContainer<ST>,
    ) -> Result<(Block<ChainTransaction>, Vec<Vec<u8>>), ChainError> {
        let expected_height = self.state.status.height + 1;
        if block.header.height != expected_height {
            return Err(ChainError::Block(BlockError::InvalidHeight {
                expected: expected_height,
                got: block.header.height,
            }));
        }

        // --- PHASE 1: Execution (No Write Lock) ---
        let (inserts, deletes) = {
            let state_tree_arc = workload.state_tree();
            let base_state = state_tree_arc.read().await;
            let mut overlay = StateOverlay::new(&*base_state);

            for tx in &block.transactions {
                self.process_transaction(tx, &mut overlay, block.header.height)
                    .await?;
            }

            overlay.into_ordered_batch()
        }; // Read lock on state_tree is released here.

        // --- PHASE 2: Commit (Short Write Lock) ---
        {
            let state_tree_arc = workload.state_tree();
            let mut state = state_tree_arc.write().await;

            // Apply the collected state changes.
            state.batch_apply(&inserts, &deletes)?;

            let end_block_ctx = TxContext {
                block_height: block.header.height,
                chain_id: self.state.chain_id.parse().unwrap_or(1),
                services: &self.services,
                simulation: false,
            };
            for service in self.services.services_in_deterministic_order() {
                if let Some(hook) = service.as_on_end_block() {
                    hook.on_end_block(&mut *state, &end_block_ctx)?;
                }
            }

            // --- FIX START: Strengthen Validator Set Promotion and Carry-Forward Logic ---
            if self.consensus_engine.consensus_type() == ConsensusType::ProofOfStake {
                match state.get(VALIDATOR_SET_KEY)? {
                    Some(bytes) => {
                        let mut sets = read_validator_sets(&bytes)?;
                        let mut modified = false;
                        if let Some(next_vs) = &sets.next {
                            if block.header.height >= next_vs.effective_from_height {
                                log::info!(
                                    "[PoS EndBlock] Promoting validator set @H={}",
                                    block.header.height
                                );
                                sets.current = next_vs.clone();
                                sets.next = None;
                                modified = true;
                            }
                        }
                        let out = write_validator_sets(&sets);
                        state.insert(VALIDATOR_SET_KEY, &out)?;
                        if modified {
                            log::info!("[PoS EndBlock] Validator set updated and carried forward.");
                        } else {
                            log::debug!("[PoS EndBlock] Validator set carried forward unchanged.");
                        }
                    }
                    None => {
                        log::error!(
                            "[PoS EndBlock] MISSING VALIDATOR_SET_KEY before commit at H={}. \
                         The next block will stall without it.",
                            block.header.height
                        );
                    }
                }
            }
            // --- FIX END ---

            // The status height is updated to the current block's height *before* commit,
            // as the commit operation finalizes the state FOR this height.
            self.state.status.height = block.header.height;
            self.state.status.latest_timestamp = block.header.timestamp;
            self.state.status.total_transactions += block.transactions.len() as u64;
            let status_bytes = serde_json::to_vec(&self.state.status).unwrap();
            state.insert(STATUS_KEY, &status_bytes)?;

            // --- FIX START: Correctly sequence state root calculation and version commit ---
            // 1. Commit all state changes for this block, including the status update.
            // For versioned trees like IAVL, this creates a queryable snapshot.
            state.commit_version();

            // 2. Get the final, committed root hash *after* the version has been saved.
            let final_state_root_bytes = state.root_commitment().as_ref().to_vec();

            // 3. (Debug Only) Sanity check: ensure the committed root is actually queryable.
            // This is the actionable guard that turns a silent stall into an explicit panic.
            {
                use depin_sdk_types::app::Membership;

                let final_commitment = state
                    .commitment_from_bytes(&final_state_root_bytes)
                    .unwrap();
                debug_assert!(
                    state.version_exists_for_root(&final_commitment),
                    "FATAL INVARIANT VIOLATION: The committed root for height {} is not mapped to a queryable version!",
                    block.header.height
                );

                // --- NEW: Add invariant check for validator set presence ---
                if self.consensus_engine.consensus_type() == ConsensusType::ProofOfStake {
                    match state.get_with_proof_at(&final_commitment, VALIDATOR_SET_KEY) {
                        Ok((Membership::Present(_), _)) => {
                            log::info!(
                                "[EndBlock@{}] Validator set present and provable at new root {}",
                                block.header.height,
                                hex::encode(&final_state_root_bytes)
                            );
                        }
                        Ok((other, _)) => {
                            panic!(
                                "INVARIANT: Validator set missing at end of block {} (membership={:?}, root={})",
                                block.header.height,
                                other,
                                hex::encode(&final_state_root_bytes),
                            );
                        }
                        Err(e) => {
                            panic!(
                                "INVARIANT: get_with_proof_at failed for validator set at end of block {}: {}",
                                block.header.height, e
                            );
                        }
                    }
                }
            }

            // 4. Set the block header's state_root to this final, verifiable hash.
            block.header.state_root = StateRoot(final_state_root_bytes.clone());

            // 5. Update the chain's internal tracker for the last committed state root.
            self.state.last_state_root = StateRoot(final_state_root_bytes);
            // --- FIX END ---
        } // Write lock is released here

        log::info!(
            "[Chain Commit] H={} state_root={} anchor={}",
            block.header.height,
            hex::encode(block.header.state_root.as_ref()),
            hex::encode(block.header.state_root.to_anchor().as_ref())
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
    ) -> Block<ChainTransaction> {
        let height = self.state.status.height + 1;
        let parent_hash_bytes = self
            .state
            .recent_blocks
            .last()
            .map(|b| b.header.hash())
            .unwrap_or_else(|| vec![0; 32]);
        let parent_hash = parent_hash_bytes.try_into().unwrap();

        let producer_pubkey = producer_keypair.public().encode_protobuf();
        let suite = SignatureSuite::Ed25519;
        let producer_pubkey_hash = account_id_from_key_material(suite, &producer_pubkey).unwrap();
        let producer_account_id = AccountId(producer_pubkey_hash);

        let header = BlockHeader {
            height,
            parent_hash,
            parent_state_root: self.state.last_state_root.clone(),
            state_root: StateRoot(vec![]),
            transactions_root: vec![],
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            validator_set: current_validator_set.to_vec(),
            producer_account_id,
            producer_key_suite: suite,
            producer_pubkey_hash,
            producer_pubkey,
            signature: vec![],
        };

        Block {
            header,
            transactions,
        }
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
            .ok_or(ChainError::State(StateError::KeyNotFound(
                "ValidatorSet".to_string(),
            )))?;
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
    ) -> Result<BTreeMap<AccountId, StakeAmount>, ChainError> {
        let state = self.workload_container.state_tree();
        let guard = state.read().await;
        let bytes = guard
            .get(VALIDATOR_SET_KEY)?
            .ok_or_else(|| ChainError::State(StateError::KeyNotFound("ValidatorSet".into())))?;
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
    ) -> Result<BTreeMap<AccountId, StakeAmount>, ChainError> {
        let state = self.workload_container.state_tree();
        let guard = state.read().await;
        let bytes = guard
            .get(VALIDATOR_SET_KEY)?
            .ok_or_else(|| ChainError::State(StateError::KeyNotFound("ValidatorSet".into())))?;
        let sets = read_validator_sets(&bytes)?;
        let effective_set = sets.next.as_ref().unwrap_or(&sets.current);
        Ok(effective_set
            .validators
            .iter()
            .map(|v| (v.account_id, v.weight as u64))
            .collect())
    }
}
