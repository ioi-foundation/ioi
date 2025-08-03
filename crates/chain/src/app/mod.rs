// Path: crates/chain/src/app/mod.rs
/// The private implementation for the `AppChain` trait.
use crate::upgrade_manager::ModuleUpgradeManager;
use async_trait::async_trait;
use depin_sdk_api::chain::{AppChain, PublicKey, StakeAmount};
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_api::services::UpgradableService;
use depin_sdk_api::state::StateManager;
use depin_sdk_api::transaction::TransactionModel;
use depin_sdk_api::validator::{TransactionExecutor, WorkloadContainer};
use depin_sdk_api::vm::ExecutionContext;
use depin_sdk_types::app::{
    ApplicationTransaction, Block, BlockHeader, ChainStatus, ProtocolTransaction, SystemPayload,
    SystemTransaction, UTXOTransaction,
};
use depin_sdk_types::error::{ChainError, StateError};
use libp2p::identity::ed25519::PublicKey as Ed25519PublicKey;
use libp2p::identity::PublicKey as Libp2pPublicKey;
use libp2p::PeerId;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const STAKES_KEY: &[u8] = b"system::stakes";
pub(crate) const STATUS_KEY: &[u8] = b"chain::status";
pub(crate) const VALIDATOR_SET_KEY: &[u8] = b"system::validators";
pub(crate) const AUTHORITY_SET_KEY: &[u8] = b"system::authorities";
pub(crate) const GOVERNANCE_KEY: &[u8] = b"system::governance_key";

/// A struct that holds the core, serializable state of a blockchain.
#[derive(Debug)]
#[allow(dead_code)] // FIX: Allow dead code for fields kept for future use.
pub struct ChainState<CS, TM: TransactionModel> {
    /// The commitment scheme in use.
    pub commitment_scheme: CS,
    /// The transaction model in use.
    pub transaction_model: TM,
    /// The unique identifier for the chain.
    pub chain_id: String,
    /// The current status of the chain.
    pub status: ChainStatus,
    /// A list of recent blocks.
    pub recent_blocks: Vec<Block<ProtocolTransaction>>,
    /// The maximum number of recent blocks to keep.
    pub max_recent_blocks: usize,
}

#[derive(Debug)]
pub struct Chain<CS, TM: TransactionModel> {
    state: ChainState<CS, TM>,
    #[allow(dead_code)]
    service_manager: ModuleUpgradeManager,
}

impl<CS, TM> Chain<CS, TM>
where
    CS: CommitmentScheme,
    TM: TransactionModel<CommitmentScheme = CS>,
{
    pub fn new(
        commitment_scheme: CS,
        transaction_model: TM,
        chain_id: &str,
        initial_services: Vec<Arc<dyn UpgradableService>>,
    ) -> Self {
        let status = ChainStatus {
            height: 0,
            latest_timestamp: 0,
            total_transactions: 0,
            is_running: false,
        };
        let mut service_manager = ModuleUpgradeManager::new();
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
        };
        Self {
            state,
            service_manager,
        }
    }

    pub async fn load_or_initialize_status<ST>(
        &mut self,
        workload: &WorkloadContainer<ST>,
    ) -> Result<(), ChainError>
    where
        ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
    {
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
        Ok(())
    }

    async fn process_system_transaction<ST>(
        &mut self,
        tx: &SystemTransaction,
        workload: &WorkloadContainer<ST>,
    ) -> Result<(), ChainError>
    where
        ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
    {
        let state_tree_arc = workload.state_tree();
        let mut state = state_tree_arc.lock().await;
        let payload_bytes = serde_json::to_vec(&tx.payload)
            .map_err(|e| ChainError::Transaction(format!("Failed to serialize payload: {e}")))?;

        match &tx.payload {
            SystemPayload::UpdateAuthorities { new_authorities } => {
                let governance_pk_str_bytes = state.get(GOVERNANCE_KEY)?.ok_or_else(|| {
                    ChainError::Transaction("Governance key not found in state".to_string())
                })?;
                let governance_pk_str: String = serde_json::from_slice(&governance_pk_str_bytes)
                    .map_err(|e| {
                        ChainError::Transaction(format!(
                            "Failed to parse governance key string: {e}"
                        ))
                    })?;
                let governance_pk_bytes =
                    bs58::decode(governance_pk_str).into_vec().map_err(|e| {
                        ChainError::Transaction(format!("Failed to decode governance key: {e}"))
                    })?;
                let ed25519_pk =
                    libp2p::identity::ed25519::PublicKey::try_from_bytes(&governance_pk_bytes)
                        .map_err(|e| {
                            ChainError::Transaction(format!("Invalid governance key: {e}"))
                        })?;
                let libp2p_pk = Libp2pPublicKey::from(ed25519_pk);

                if !libp2p_pk.verify(&payload_bytes, &tx.signature) {
                    return Err(ChainError::Transaction(
                        "Invalid governance signature for UpdateAuthorities".to_string(),
                    ));
                }
                if new_authorities.is_empty() {
                    return Err(ChainError::Transaction(
                        "Authority set cannot be empty".to_string(),
                    ));
                }
                for peer_id_bytes in new_authorities {
                    if PeerId::from_bytes(peer_id_bytes).is_err() {
                        return Err(ChainError::Transaction(
                            "Invalid PeerId in new authority set".to_string(),
                        ));
                    }
                }
                let serialized_authorities = serde_json::to_vec(new_authorities).unwrap();
                state.insert(AUTHORITY_SET_KEY, &serialized_authorities)?;
                state.insert(VALIDATOR_SET_KEY, &serialized_authorities)?;
                log::info!("Successfully updated authority set via governance.");
            }
            SystemPayload::Stake { amount } => {
                if tx.signature.len() < 96 {
                    return Err(ChainError::Transaction(
                        "Invalid signature length for stake".to_string(),
                    ));
                }
                let (signer_pk_bytes, signature_bytes) = tx.signature.split_at(32);

                let ed25519_pk = Ed25519PublicKey::try_from_bytes(signer_pk_bytes)
                    .map_err(|e| ChainError::Transaction(format!("Invalid public key: {e}")))?;
                let libp2p_pk = Libp2pPublicKey::from(ed25519_pk.clone());

                if !libp2p_pk.verify(&payload_bytes, signature_bytes) {
                    return Err(ChainError::Transaction(
                        "Invalid signature for Stake transaction".to_string(),
                    ));
                }

                let peer_id = PeerId::from_public_key(&libp2p_pk);
                let signer_pk_b58 = peer_id.to_base58();

                let mut stakes: BTreeMap<PublicKey, StakeAmount> = match state.get(STAKES_KEY)? {
                    Some(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
                    None => BTreeMap::new(),
                };

                let current_stake = stakes.entry(signer_pk_b58).or_insert(0);
                *current_stake += amount;

                log::info!("Processed stake of {amount} for validator.");

                let stakes_bytes = serde_json::to_vec(&stakes).unwrap();
                state.insert(STAKES_KEY, &stakes_bytes)?;
            }
            SystemPayload::Unstake { amount } => {
                if tx.signature.len() < 96 {
                    return Err(ChainError::Transaction(
                        "Invalid signature length for unstake".to_string(),
                    ));
                }
                let (signer_pk_bytes, signature_bytes) = tx.signature.split_at(32);

                let ed25519_pk = Ed25519PublicKey::try_from_bytes(signer_pk_bytes)
                    .map_err(|e| ChainError::Transaction(format!("Invalid public key: {e}")))?;
                let libp2p_pk = Libp2pPublicKey::from(ed25519_pk.clone());

                if !libp2p_pk.verify(&payload_bytes, signature_bytes) {
                    return Err(ChainError::Transaction(
                        "Invalid signature for Unstake transaction".to_string(),
                    ));
                }

                let peer_id = PeerId::from_public_key(&libp2p_pk);
                let signer_pk_b58 = peer_id.to_base58();

                let mut stakes: BTreeMap<PublicKey, StakeAmount> = match state.get(STAKES_KEY)? {
                    Some(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
                    None => BTreeMap::new(),
                };

                if let Some(current_stake) = stakes.get_mut(&signer_pk_b58) {
                    *current_stake = current_stake.saturating_sub(*amount);
                    if *current_stake == 0 {
                        stakes.remove(&signer_pk_b58);
                    }
                    log::info!("Processed unstake of {amount} for validator.");
                }

                let stakes_bytes = serde_json::to_vec(&stakes).unwrap();
                state.insert(STAKES_KEY, &stakes_bytes)?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl<CS, TM, ST> AppChain<CS, TM, ST> for Chain<CS, TM>
where
    CS: CommitmentScheme + Send + Sync + 'static,
    TM: TransactionModel<CommitmentScheme = CS, Transaction = UTXOTransaction>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    CS::Commitment: Send + Sync + Debug,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug,
    WorkloadContainer<ST>: TransactionExecutor<ST>,
{
    fn status(&self) -> &ChainStatus {
        &self.state.status
    }

    fn transaction_model(&self) -> &TM {
        &self.state.transaction_model
    }

    async fn process_transaction(
        &mut self,
        tx: &ProtocolTransaction,
        workload: &WorkloadContainer<ST>,
    ) -> Result<(), ChainError> {
        match tx {
            ProtocolTransaction::Application(app_tx) => {
                // --- VERIFY SIGNATURE for contract transactions ---
                let signer_pubkey_bytes = match app_tx {
                    ApplicationTransaction::DeployContract { signer_pubkey, .. } => signer_pubkey,
                    ApplicationTransaction::CallContract { signer_pubkey, .. } => signer_pubkey,
                    _ => &vec![], // UTXO handled by workload
                };

                if !signer_pubkey_bytes.is_empty() {
                    let signature = match app_tx {
                        ApplicationTransaction::DeployContract { signature, .. } => signature,
                        ApplicationTransaction::CallContract { signature, .. } => signature,
                        _ => &vec![],
                    };
                    let payload = app_tx.to_signature_payload();
                    // FIX: Use try_decode_protobuf instead of try_from_protobuf_encoding
                    let pubkey = Libp2pPublicKey::try_decode_protobuf(signer_pubkey_bytes)
                        .map_err(|_| {
                            ChainError::Transaction("Invalid public key format".to_string())
                        })?;

                    if !pubkey.verify(&payload, signature) {
                        return Err(ChainError::Transaction(
                            "Invalid transaction signature".to_string(),
                        ));
                    }
                }
                // --- END VERIFICATION ---

                match app_tx {
                    ApplicationTransaction::UTXO(utxo_tx) => {
                        workload
                            .execute_transaction(utxo_tx, &self.state.transaction_model)
                            .await
                            .map_err(|e| ChainError::Transaction(e.to_string()))?;
                    }
                    ApplicationTransaction::DeployContract {
                        code,
                        signer_pubkey,
                        ..
                    } => {
                        // Use the verified signer's public key as the sender context
                        workload
                            .deploy_contract(code.clone(), signer_pubkey.clone())
                            .await
                            .map_err(|e| ChainError::Transaction(e.to_string()))?;
                    }
                    ApplicationTransaction::CallContract {
                        address,
                        input_data,
                        gas_limit,
                        signer_pubkey,
                        ..
                    } => {
                        // Populate context with the verified caller and dynamic gas limit
                        let context = ExecutionContext {
                            caller: signer_pubkey.clone(),
                            block_height: self.status().height,
                            gas_limit: *gas_limit,
                            contract_address: vec![], // Will be populated by workload
                        };
                        workload
                            .call_contract(address.clone(), input_data.clone(), context)
                            .await
                            .map_err(|e| ChainError::Transaction(e.to_string()))?;
                    }
                }
            }
            ProtocolTransaction::System(sys_tx) => {
                self.process_system_transaction(sys_tx, workload).await?;
            }
        }
        self.state.status.total_transactions += 1;
        Ok(())
    }

    async fn process_block(
        &mut self,
        mut block: Block<ProtocolTransaction>,
        workload: &WorkloadContainer<ST>,
    ) -> Result<Block<ProtocolTransaction>, ChainError> {
        if block.header.height != self.state.status.height + 1 {
            return Err(ChainError::Block(format!(
                "Invalid block height. Expected {}, got {}",
                self.state.status.height + 1,
                block.header.height
            )));
        }
        let expected_prev_hash = self
            .state
            .recent_blocks
            .last()
            .map_or(vec![0; 32], |b| b.header.state_root.clone());
        if block.header.prev_hash != expected_prev_hash {
            return Err(ChainError::Block(format!(
                "Invalid prev_hash for block {}. Expected {}, got {}",
                block.header.height,
                hex::encode(&expected_prev_hash),
                hex::encode(&block.header.prev_hash)
            )));
        }
        for tx in &block.transactions {
            self.process_transaction(tx, workload).await?;
        }
        self.state.status.height = block.header.height;
        self.state.status.latest_timestamp = block.header.timestamp;

        let status_bytes = serde_json::to_vec(&self.state.status)
            .map_err(|e| ChainError::Transaction(format!("Failed to serialize status: {e}")))?;
        let validator_set_bytes = serde_json::to_vec(&block.header.validator_set).map_err(|e| {
            ChainError::Transaction(format!("Failed to serialize validator set: {e}"))
        })?;

        let state_tree_arc = workload.state_tree();
        let mut state = state_tree_arc.lock().await;
        state.insert(STATUS_KEY, &status_bytes)?;
        state.insert(VALIDATOR_SET_KEY, &validator_set_bytes)?;

        let state_root = state.root_commitment();
        drop(state);

        block.header.state_root = state_root.as_ref().to_vec();
        self.state.recent_blocks.push(block.clone());
        if self.state.recent_blocks.len() > self.state.max_recent_blocks {
            self.state.recent_blocks.remove(0);
        }
        Ok(block)
    }

    fn create_block(
        &self,
        transactions: Vec<ProtocolTransaction>,
        _workload: &WorkloadContainer<ST>,
        current_validator_set: &[Vec<u8>],
        _known_peers_bytes: &[Vec<u8>],
    ) -> Block<ProtocolTransaction> {
        let prev_hash = self
            .state
            .recent_blocks
            .last()
            .map_or(vec![0; 32], |b| b.header.state_root.clone());

        let mut peers: Vec<PeerId> = current_validator_set
            .iter()
            .filter_map(|bytes| PeerId::from_bytes(bytes).ok())
            .collect();
        peers.sort();
        let validator_set: Vec<Vec<u8>> = peers.iter().map(|p| p.to_bytes()).collect();

        let next_height = self.state.status.height + 1;
        let header = BlockHeader {
            height: next_height,
            prev_hash: prev_hash.clone(),
            state_root: prev_hash,
            transactions_root: vec![0; 32],
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            validator_set,
        };
        Block {
            header,
            transactions,
        }
    }

    fn get_block(&self, height: u64) -> Option<&Block<ProtocolTransaction>> {
        self.state
            .recent_blocks
            .iter()
            .find(|b| b.header.height == height)
    }

    fn get_blocks_since(&self, height: u64) -> Vec<Block<ProtocolTransaction>> {
        self.state
            .recent_blocks
            .iter()
            .filter(|b| b.header.height > height)
            .cloned()
            .collect()
    }

    async fn get_validator_set(
        &self,
        workload: &WorkloadContainer<ST>,
    ) -> Result<Vec<Vec<u8>>, ChainError> {
        let state_tree_arc = workload.state_tree();
        let state = state_tree_arc.lock().await;
        match state.get(VALIDATOR_SET_KEY) {
            Ok(Some(bytes)) => serde_json::from_slice(&bytes).map_err(|e| {
                ChainError::Transaction(format!("Failed to deserialize validator set: {e}"))
            }),
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }

    async fn get_authority_set(
        &self,
        workload: &WorkloadContainer<ST>,
    ) -> Result<Vec<Vec<u8>>, ChainError> {
        let state_tree_arc = workload.state_tree();
        let state = state_tree_arc.lock().await;
        match state.get(AUTHORITY_SET_KEY) {
            Ok(Some(bytes)) => serde_json::from_slice(&bytes).map_err(|e| {
                ChainError::Transaction(format!("Failed to deserialize authority set: {e}"))
            }),
            Ok(None) => Err(ChainError::State(StateError::KeyNotFound(
                "system::authorities not found in state. Check genesis file.".to_string(),
            ))),
            Err(e) => Err(e.into()),
        }
    }

    async fn get_staked_validators(
        &self,
        workload: &WorkloadContainer<ST>,
    ) -> Result<BTreeMap<PublicKey, StakeAmount>, ChainError> {
        let state_tree_arc = workload.state_tree();
        let state = state_tree_arc.lock().await;
        match state.get(STAKES_KEY) {
            Ok(Some(bytes)) => serde_json::from_slice(&bytes).map_err(|e| {
                ChainError::Transaction(format!("Failed to deserialize stakes map: {e}"))
            }),
            Ok(None) => Ok(BTreeMap::new()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use depin_sdk_api::state::StateTree;
    use depin_sdk_commitment::hash::HashCommitmentScheme;
    use depin_sdk_state_tree::hashmap::HashMapStateTree;
    use depin_sdk_transaction_models::utxo::UTXOModel;
    use depin_sdk_types::config::WorkloadConfig;
    use depin_sdk_vm_wasm::WasmVm;
    use libp2p::identity;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_process_system_transaction_update_authorities() {
        // Setup
        let scheme = HashCommitmentScheme::new();
        let state_tree = HashMapStateTree::new(scheme.clone());
        let wasm_vm = Box::new(WasmVm::new());
        let workload = Arc::new(WorkloadContainer::new(
            WorkloadConfig {
                enabled_vms: vec![],
            },
            state_tree,
            wasm_vm,
        ));
        let mut chain = Chain::new(scheme.clone(), UTXOModel::new(scheme), "test-chain", vec![]);

        let gov_keypair = identity::Keypair::generate_ed25519();
        let gov_pk_bs58 =
            bs58::encode(gov_keypair.public().try_into_ed25519().unwrap().to_bytes()).into_string();

        workload
            .state_tree()
            .lock()
            .await
            .insert(GOVERNANCE_KEY, &serde_json::to_vec(&gov_pk_bs58).unwrap())
            .unwrap();

        // Create transaction
        let new_authorities = vec![PeerId::random().to_bytes()];
        let payload = SystemPayload::UpdateAuthorities {
            new_authorities: new_authorities.clone(),
        };
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let signature = gov_keypair.sign(&payload_bytes).unwrap();
        let sys_tx = SystemTransaction { payload, signature };
        let protocol_tx = ProtocolTransaction::System(sys_tx);

        // Test
        let result = chain.process_transaction(&protocol_tx, &workload).await;
        assert!(result.is_ok());

        // Verify
        let stored_bytes = workload
            .state_tree()
            .lock()
            .await
            .get(AUTHORITY_SET_KEY)
            .unwrap()
            .unwrap();
        let stored_authorities: Vec<Vec<u8>> = serde_json::from_slice(&stored_bytes).unwrap();
        assert_eq!(stored_authorities, new_authorities);
    }

    #[tokio::test]
    async fn test_process_system_tx_invalid_signature() {
        // Setup
        let scheme = HashCommitmentScheme::new();
        let state_tree = HashMapStateTree::new(scheme.clone());
        let wasm_vm = Box::new(WasmVm::new());
        let workload = Arc::new(WorkloadContainer::new(
            WorkloadConfig {
                enabled_vms: vec![],
            },
            state_tree,
            wasm_vm,
        ));
        let mut chain = Chain::new(scheme.clone(), UTXOModel::new(scheme), "test-chain", vec![]);
        let gov_keypair = identity::Keypair::generate_ed25519();
        let gov_pk_bs58 =
            bs58::encode(gov_keypair.public().try_into_ed25519().unwrap().to_bytes()).into_string();

        workload
            .state_tree()
            .lock()
            .await
            .insert(GOVERNANCE_KEY, &serde_json::to_vec(&gov_pk_bs58).unwrap())
            .unwrap();

        // Create transaction with invalid signature
        let new_authorities = vec![PeerId::random().to_bytes()];
        let payload = SystemPayload::UpdateAuthorities { new_authorities };
        let sys_tx = SystemTransaction {
            payload,
            signature: b"invalid-signature".to_vec(),
        };
        let protocol_tx = ProtocolTransaction::System(sys_tx);

        let result = chain.process_transaction(&protocol_tx, &workload).await;
        assert!(result.is_err());
        assert!(
            matches!(result, Err(ChainError::Transaction(msg)) if msg.contains("Invalid governance signature"))
        );
    }
}
