// Path: crates/chain/src/app/mod.rs

use crate::upgrade_manager::ModuleUpgradeManager;
use async_trait::async_trait;
use depin_sdk_api::chain::{AppChain, ChainView, PublicKey, StakeAmount, StateView};
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_api::consensus::PenaltyMechanism;
use depin_sdk_api::services::access::{Service, ServiceDirectory};
use depin_sdk_api::services::{ServiceType, UpgradableService};
use depin_sdk_api::state::{StateAccessor, StateManager};
use depin_sdk_api::transaction::context::TxContext;
use depin_sdk_api::transaction::TransactionModel;
use depin_sdk_api::validator::WorkloadContainer;
use depin_sdk_consensus::Consensus;
use depin_sdk_transaction_models::system::{nonce, validation};
use depin_sdk_transaction_models::unified::UnifiedTransactionModel;
use depin_sdk_types::app::{
    account_id_from_key_material, AccountId, ActiveKeyRecord, Block, BlockHeader, ChainStatus,
    ChainTransaction, FailureReport, SignatureSuite, SystemPayload,
};
use depin_sdk_types::codec;
use depin_sdk_types::config::ConsensusType;
use depin_sdk_types::error::{BlockError, ChainError, CoreError, StateError, TransactionError};
use depin_sdk_types::keys::{
    ACCOUNT_ID_TO_PUBKEY_PREFIX, AUTHORITY_SET_KEY, GOVERNANCE_KEY, STAKES_KEY_CURRENT,
    STAKES_KEY_NEXT, STATUS_KEY,
};
use libp2p::identity::{Keypair, PublicKey as Libp2pPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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
    pub last_state_root: [u8; 32],
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
{
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
            last_state_root: [0; 32],
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
        let state_tree = workload.state_tree();
        let mut state = state_tree.lock().await;
        match state.get(STATUS_KEY) {
            Ok(Some(status_bytes)) => {
                let status: ChainStatus = serde_json::from_slice(&status_bytes).map_err(|e| {
                    ChainError::Transaction(format!("Failed to deserialize status: {e}"))
                })?;
                log::info!("Loaded chain status: height {}", status.height);
                self.state.status = status;
            }
            Ok(None) => {
                log::info!(
                    "No existing chain status found. Initializing and saving genesis status."
                );
                let status_bytes = serde_json::to_vec(&self.state.status).unwrap();
                state
                    .insert(STATUS_KEY, &status_bytes)
                    .map_err(|e| ChainError::Transaction(e.to_string()))?;
            }
            Err(e) => return Err(ChainError::Transaction(e.to_string())),
        }
        // compute current root and publish anchor for genesis state
        let root_vec = state.root_commitment().as_ref().to_vec();
        drop(state);
        let root: [u8; 32] = root_vec.try_into().unwrap_or([0u8; 32]);
        self.workload_container
            .publish_anchor_snapshot::<CS>(root)
            .await;
        // remember the genesis state root so H=1 can reference the correct parent
        self.state.last_state_root = root;
        Ok(())
    }

    // This function is now async to correctly lock the mutex.
    async fn get_validator_set_from_key(
        &self,
        workload: &WorkloadContainer<ST>,
        key: &[u8],
    ) -> Result<Vec<Vec<u8>>, ChainError> {
        let state_tree_arc = workload.state_tree();
        let state = state_tree_arc.lock().await;
        match state.get(key)? {
            Some(bytes) => {
                let stakers: BTreeMap<AccountId, u64> = codec::from_bytes_canonical(&bytes)
                    .map_err(|e| ChainError::State(StateError::InvalidValue(e)))?;

                let mut validator_pubkeys = Vec::new();
                for (account_id, stake) in stakers {
                    if stake > 0 {
                        let pubkey_map_key =
                            [ACCOUNT_ID_TO_PUBKEY_PREFIX, account_id.as_ref()].concat();
                        if let Some(pubkey_bytes) = state.get(&pubkey_map_key)? {
                            validator_pubkeys.push(pubkey_bytes);
                        } else {
                            log::warn!(
                                "Validator with AccountId {} has stake but no public key in lookup map.",
                                hex::encode(account_id)
                            );
                        }
                    }
                }
                Ok(validator_pubkeys)
            }
            None => Ok(Vec::new()),
        }
    }
}

// A concrete implementation of StateView for the Chain.
pub struct StateViewImpl<ST: StateManager> {
    state_root: [u8; 32],
    workload: Arc<WorkloadContainer<ST>>,
    consensus_type: ConsensusType,
}

#[async_trait]
impl<ST: StateManager + Send + Sync + 'static> StateView for StateViewImpl<ST> {
    fn state_root(&self) -> &[u8] {
        &self.state_root
    }

    async fn validator_set(&self) -> Result<Vec<AccountId>, ChainError> {
        match self.consensus_type {
            ConsensusType::ProofOfAuthority => {
                let bytes = self
                    .workload
                    .get_at(self.state_root, AUTHORITY_SET_KEY)
                    .await
                    .ok_or_else(|| {
                        ChainError::State(StateError::KeyNotFound(
                            "Authority set not found".to_string(),
                        ))
                    })?;
                codec::from_bytes_canonical(&bytes)
                    .map_err(|e| ChainError::State(StateError::InvalidValue(e)))
            }
            ConsensusType::ProofOfStake => {
                let bytes = self
                    .workload
                    .get_at(self.state_root, STAKES_KEY_CURRENT)
                    .await
                    .ok_or_else(|| {
                        ChainError::State(StateError::KeyNotFound(
                            "Current stakes not found".to_string(),
                        ))
                    })?;
                let stakes: BTreeMap<AccountId, u64> = codec::from_bytes_canonical(&bytes)
                    .map_err(|e| ChainError::State(StateError::InvalidValue(e)))?;

                let mut validators: Vec<AccountId> = stakes
                    .into_iter()
                    .filter(|(_, s)| *s > 0)
                    .map(|(a, _)| a)
                    .collect();
                validators.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
                Ok(validators)
            }
        }
    }

    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ChainError> {
        Ok(self.workload.get_at(self.state_root, key).await)
    }

    async fn active_consensus_key(&self, acct: &AccountId) -> Option<ActiveKeyRecord> {
        const KEY_PREFIX: &[u8] = b"identity::key_record::";
        let key = [KEY_PREFIX, acct.as_ref()].concat();
        let bytes = self.workload.get_at(self.state_root, &key).await?;
        codec::from_bytes_canonical(&bytes).ok()
    }
}

#[async_trait]
impl<CS, ST> ChainView<CS, ST> for Chain<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
{
    fn view_at(&self, state_root: &[u8; 32]) -> Result<Box<dyn StateView>, ChainError> {
        let view = StateViewImpl {
            state_root: *state_root,
            workload: self.workload_container.clone(),
            consensus_type: self.consensus_engine.consensus_type(),
        };
        Ok(Box::new(view))
    }

    fn get_penalty_mechanism(&self) -> Box<dyn PenaltyMechanism + Send + Sync + '_> {
        // Return a delegator that borrows the engine and forwards apply_penalty.
        Box::new(PenaltyDelegator {
            inner: &self.consensus_engine,
        })
    }

    fn consensus_type(&self) -> ConsensusType {
        self.consensus_engine.consensus_type()
    }
}

#[async_trait]
impl<CS, ST> AppChain<CS, UnifiedTransactionModel<CS>, ST> for Chain<CS, ST>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug,
    CS::Commitment: Send + Sync + Debug,
{
    fn status(&self) -> &ChainStatus {
        &self.state.status
    }

    fn transaction_model(&self) -> &UnifiedTransactionModel<CS> {
        &self.state.transaction_model
    }

    async fn process_transaction(
        &mut self,
        tx: &ChainTransaction,
        workload: &WorkloadContainer<ST>,
        block_height: u64,
    ) -> Result<(), ChainError> {
        let chain_id = self.state.chain_id.parse().unwrap_or(1);
        let ctx = TxContext {
            block_height,
            chain_id,
            services: &self.services,
        };

        if let ChainTransaction::System(sys_tx) = tx {
            if let SystemPayload::SwapModule {
                service_type,
                module_wasm,
                activation_height,
            } = &sys_tx.payload
            {
                let state_tree_arc = workload.state_tree();
                let state = state_tree_arc.lock().await;
                let gov_pk_bs58_val = state
                    .get(GOVERNANCE_KEY)?
                    .ok_or_else(|| ChainError::Transaction("Governance key not set".into()))?;
                let gov_pk_bs58: String = serde_json::from_slice(&gov_pk_bs58_val).unwrap();
                let gov_pk_bytes = bs58::decode(gov_pk_bs58).into_vec().unwrap();

                let signer_pk =
                    Libp2pPublicKey::try_decode_protobuf(&sys_tx.signature_proof.public_key)
                        .map_err(|_| {
                            ChainError::Transaction("Invalid public key in signature proof".into())
                        })?;
                let signer_ed_pk = signer_pk.clone().try_into_ed25519().unwrap();

                if gov_pk_bytes != signer_ed_pk.to_bytes() {
                    return Err(ChainError::Transaction(
                        "Transaction not signed by governance key".into(),
                    ));
                }

                let sign_bytes = sys_tx.to_sign_bytes().unwrap();
                if !signer_pk.verify(&sign_bytes, &sys_tx.signature_proof.signature) {
                    return Err(ChainError::Transaction(
                        "Invalid governance signature for SwapModule".into(),
                    ));
                }
                drop(state);

                log::info!(
                    "[Chain] Scheduling module upgrade for service '{}' at height {}",
                    service_type,
                    activation_height
                );
                self._service_manager
                    .schedule_upgrade(
                        ServiceType::Custom(service_type.clone()),
                        module_wasm.clone(),
                        *activation_height,
                    )
                    .map_err(|e| ChainError::Transaction(e.to_string()))?;
                self.state.status.total_transactions += 1;
                return Ok(());
            }
        }

        let state_tree_arc = workload.state_tree();

        // === READ-ONLY VALIDATION PHASE ===
        let state = state_tree_arc.lock().await;
        nonce::assert_next_nonce(&*state, tx)?;
        validation::verify_transaction_signature(&*state, &self.services, tx, &ctx)?;
        drop(state);

        // === READ-WRITE VALIDATION & EXECUTION PHASE ===
        let mut state = state_tree_arc.lock().await;

        // Re-assert Nonce under write lock to prevent TOCTOU races.
        nonce::assert_next_nonce(&*state, tx)?;

        // Capability Pre-check (BEFORE ante handlers to fail fast).
        preflight_capabilities(&self.services, tx)?;

        // Optional Service Ante Handlers (in a stable, deterministic order).
        for service in self.services.services_in_deterministic_order() {
            if let Some(decorator) = service.as_tx_decorator() {
                decorator.ante_handle(&mut *state, tx, &ctx)?;
            }
        }

        // Core Nonce Bump (Write) - The point of no return.
        nonce::bump_nonce(&mut *state, tx)?;

        drop(state);

        // PAYLOAD APPLICATION PHASE
        self.state
            .transaction_model
            .apply_payload(self, tx, workload, ctx)
            .await?;

        self.state.status.total_transactions += 1;
        Ok(())
    }

    async fn process_block(
        &mut self,
        mut block: Block<ChainTransaction>,
        workload: &WorkloadContainer<ST>,
    ) -> Result<(Block<ChainTransaction>, Vec<Vec<u8>>), ChainError> {
        let is_producing = block.header.signature.is_empty();
        let height = block.header.height;

        if height != self.state.status.height + 1 {
            return Err(BlockError::InvalidHeight {
                expected: self.state.status.height + 1,
                got: height,
            }
            .into());
        }

        let (expected_prev_hash_array, parent_state_root) =
            if let Some(b) = self.state.recent_blocks.last() {
                (b.header.hash().try_into().unwrap(), b.header.state_root)
            } else {
                // H=1: no previous block. Parent hash is zero; parent *state root* must be the actual genesis root.
                ([0; 32], self.state.last_state_root)
            };

        if is_producing {
            block.header.parent_state_root = parent_state_root;
        }

        if block.header.parent_hash != expected_prev_hash_array {
            return Err(BlockError::MismatchedPrevHash {
                expected: hex::encode(expected_prev_hash_array),
                got: hex::encode(block.header.parent_hash),
            }
            .into());
        }

        if height > 0 {
            let applied_count = self
                ._service_manager
                .apply_upgrades_at_height(height)
                .map_err(|e| ChainError::Transaction(e.to_string()))?;
            if applied_count > 0 {
                log::info!(
                    "[Workload] Applied {} module upgrade(s) at height {}",
                    applied_count,
                    height
                );
            }
        }

        if height > 0 {
            let state_tree_arc = workload.state_tree();
            let mut state = state_tree_arc.lock().await;

            // Epoch transition: The stakes for this block are whatever was decided in the last block.
            let stakes_for_current_block = match state.get(STAKES_KEY_NEXT)? {
                Some(next_bytes) => {
                    state.insert(STAKES_KEY_CURRENT, &next_bytes)?;
                    next_bytes
                }
                None => {
                    // Fallback for the first few blocks if NEXT isn't set yet.
                    // If CURRENT doesn't exist either, it's an empty vec, which is fine.
                    state.get(STAKES_KEY_CURRENT)?.unwrap_or_default()
                }
            };
            // The starting point for the *next* block's stakes is the current one.
            // Any staking txs in this block will modify this copy in STAKES_KEY_NEXT.
            state.insert(STAKES_KEY_NEXT, &stakes_for_current_block)?;
        }

        let current_validator_set = self.get_next_validator_set(workload).await?;
        let mut sorted_current_set = current_validator_set;
        sorted_current_set.sort();
        let mut header_set = block.header.validator_set.clone();
        header_set.sort();
        if header_set != sorted_current_set {
            log::warn!("Block header validator set does not match expected H+1 set.");
        }

        for tx in &block.transactions {
            self.process_transaction(tx, workload, height).await?;
        }

        if height > 0 {
            let state_tree_arc = workload.state_tree();
            let ctx = TxContext {
                block_height: height,
                chain_id: self.state.chain_id.parse().unwrap_or(1),
                services: &self.services,
            };
            for service in self.services.services() {
                if let Some(hook) = service.as_on_end_block() {
                    let mut state = state_tree_arc.lock().await;
                    if let Err(e) = hook.on_end_block(&mut *state, &ctx) {
                        log::error!("End-of-block hook for a service failed: {}", e);
                    }
                }
            }
        }

        let state_tree_arc = workload.state_tree();
        let mut state = state_tree_arc.lock().await;
        let new_state_root_vec = state.root_commitment().as_ref().to_vec();
        let new_state_root: [u8; 32] = new_state_root_vec.try_into().map_err(|_| {
            ChainError::State(StateError::Validation(
                "State root is not 32 bytes".to_string(),
            ))
        })?;

        if is_producing {
            block.header.state_root = new_state_root;
        } else if block.header.state_root != new_state_root {
            return Err(BlockError::MismatchedStateRoot {
                expected: hex::encode(new_state_root),
                got: hex::encode(block.header.state_root),
            }
            .into());
        }

        self.state.status.height = height;
        self.state.status.latest_timestamp = block.header.timestamp;
        let status_bytes = serde_json::to_vec(&self.state.status)
            .map_err(|e| ChainError::Transaction(format!("Failed to serialize status: {e}")))?;
        state.insert(STATUS_KEY, &status_bytes)?;
        let root_to_publish = new_state_root;

        // --- FIX START: Release the state lock before publishing the snapshot ---
        // IMPORTANT: release the state lock before taking it again inside publish_anchor_snapshot
        drop(state);

        // Publish anchored snapshot for this root (so H+1 decisions can read at H)
        self.workload_container
            .publish_anchor_snapshot::<CS>(root_to_publish)
            .await;
        // --- FIX END ---

        // Remember the new committed root for subsequent block building.
        self.state.last_state_root = root_to_publish;

        let validator_set_for_h_plus_1 = self.get_next_validator_set(workload).await?;

        self.state.recent_blocks.push(block.clone());
        if self.state.recent_blocks.len() > self.state.max_recent_blocks {
            self.state.recent_blocks.remove(0);
        }

        Ok((block, validator_set_for_h_plus_1))
    }

    fn create_block(
        &self,
        transactions: Vec<ChainTransaction>,
        current_validator_set: &[Vec<u8>],
        _known_peers_bytes: &[Vec<u8>],
        producer_keypair: &Keypair,
    ) -> Block<ChainTransaction> {
        let (parent_hash, parent_state_root) = if let Some(b) = self.state.recent_blocks.last() {
            (b.header.hash().try_into().unwrap(), b.header.state_root)
        } else {
            // At H=1 there is no prior block; parent hash stays zero,
            // but the parent *state root* must be the actual genesis root.
            ([0; 32], self.state.last_state_root)
        };

        let mut validator_set_bytes = current_validator_set.to_vec();
        validator_set_bytes.sort();

        let producer_pubkey = producer_keypair.public().encode_protobuf();
        let producer_key_suite = SignatureSuite::Ed25519;
        let producer_pubkey_hash =
            account_id_from_key_material(producer_key_suite, &producer_pubkey).unwrap();
        let producer_account_id = AccountId(producer_pubkey_hash);

        let header = BlockHeader {
            height: self.state.status.height + 1,
            parent_hash,
            parent_state_root,
            state_root: [0; 32], // Filled in by `process_block`
            transactions_root: vec![0; 32],
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            validator_set: validator_set_bytes,
            producer_account_id,
            producer_key_suite,
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

    async fn get_next_validator_set(
        &self,
        workload: &WorkloadContainer<ST>,
    ) -> Result<Vec<Vec<u8>>, ChainError> {
        match self.consensus_engine.consensus_type() {
            ConsensusType::ProofOfStake => {
                self.get_validator_set_from_key(workload, STAKES_KEY_NEXT)
                    .await
            }
            ConsensusType::ProofOfAuthority => {
                let state_tree_arc = workload.state_tree();
                let state = state_tree_arc.lock().await;
                match state.get(AUTHORITY_SET_KEY)? {
                    Some(bytes) => {
                        let account_ids: Vec<AccountId> = codec::from_bytes_canonical(&bytes)
                            .map_err(|e| ChainError::State(StateError::InvalidValue(e)))?;
                        // This method is now informational, so we convert back to the old format.
                        // A better refactor would remove this method entirely.
                        let mut peer_id_bytes = Vec::new();
                        for id in account_ids {
                            let key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, id.as_ref()].concat();
                            if let Some(pk_bytes) = state.get(&key)? {
                                let pk = Libp2pPublicKey::try_decode_protobuf(&pk_bytes).unwrap();
                                peer_id_bytes.push(pk.to_peer_id().to_bytes());
                            }
                        }
                        Ok(peer_id_bytes)
                    }
                    None => Ok(Vec::new()),
                }
            }
        }
    }

    async fn get_staked_validators(
        &self,
        workload: &WorkloadContainer<ST>,
    ) -> Result<BTreeMap<PublicKey, StakeAmount>, ChainError> {
        let state_tree_arc = workload.state_tree();
        let state = state_tree_arc.lock().await;
        match state.get(STAKES_KEY_CURRENT)? {
            Some(ref bytes) => {
                let raw_map: BTreeMap<AccountId, u64> = codec::from_bytes_canonical(bytes)
                    .map_err(|e| ChainError::State(StateError::InvalidValue(e)))?;
                let stakes_map: BTreeMap<PublicKey, StakeAmount> = raw_map
                    .into_iter()
                    .filter(|(_, stake)| *stake > 0)
                    .map(|(account_id, stake)| (hex::encode(account_id.0), stake))
                    .collect();
                Ok(stakes_map)
            }
            None => Ok(BTreeMap::new()),
        }
    }

    async fn get_next_staked_validators(
        &self,
        workload: &WorkloadContainer<ST>,
    ) -> Result<BTreeMap<PublicKey, StakeAmount>, ChainError> {
        let state_tree_arc = workload.state_tree();
        let state = state_tree_arc.lock().await;
        match state.get(STAKES_KEY_NEXT)? {
            Some(ref bytes) => {
                let raw_map: BTreeMap<AccountId, u64> = codec::from_bytes_canonical(bytes)
                    .map_err(|e| ChainError::State(StateError::InvalidValue(e)))?;
                let stakes_map: BTreeMap<PublicKey, StakeAmount> = raw_map
                    .into_iter()
                    .filter(|(_, stake)| *stake > 0)
                    .map(|(account_id, stake)| (hex::encode(account_id.0), stake))
                    .collect();
                Ok(stakes_map)
            }
            None => Ok(BTreeMap::new()),
        }
    }
}
