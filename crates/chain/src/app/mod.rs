// Path: crates/chain/src/app/mod.rs

use crate::upgrade_manager::ModuleUpgradeManager;
use async_trait::async_trait;
use depin_sdk_api::chain::{AppChain, PublicKey, StakeAmount};
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_api::services::{ServiceType, UpgradableService};
use depin_sdk_api::state::StateManager;
use depin_sdk_api::transaction::TransactionModel;
use depin_sdk_api::validator::WorkloadContainer;
use depin_sdk_transaction_models::unified::UnifiedTransactionModel;
use depin_sdk_types::app::{Block, BlockHeader, ChainStatus, ChainTransaction, SystemPayload};
use depin_sdk_types::error::{ChainError, CoreError, StateError};
use depin_sdk_types::keys::*;
use libp2p::identity::Keypair;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

type ServiceFactory =
    Box<dyn Fn(&[u8]) -> Result<Arc<dyn UpgradableService>, CoreError> + Send + Sync>;

#[derive(Debug)]
pub struct ChainState<CS: CommitmentScheme + Clone> {
    pub commitment_scheme: CS,
    pub transaction_model: UnifiedTransactionModel<CS>,
    pub chain_id: String,
    pub status: ChainStatus,
    pub recent_blocks: Vec<Block<ChainTransaction>>,
    pub max_recent_blocks: usize,
}

#[derive(Debug)]
pub struct Chain<CS: CommitmentScheme + Clone> {
    pub state: ChainState<CS>,
    pub service_manager: ModuleUpgradeManager,
}

impl<CS> Chain<CS>
where
    CS: CommitmentScheme + Clone,
{
    pub fn new(
        commitment_scheme: CS,
        transaction_model: UnifiedTransactionModel<CS>,
        chain_id: &str,
        initial_services: Vec<Arc<dyn UpgradableService>>,
        service_factory: ServiceFactory,
    ) -> Self {
        let status = ChainStatus {
            height: 0,
            latest_timestamp: 0,
            total_transactions: 0,
            is_running: false,
        };
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

    async fn get_validator_set_from_key<ST>(
        &self,
        workload: &WorkloadContainer<ST>,
        key: &[u8],
    ) -> Result<Vec<Vec<u8>>, ChainError>
    where
        ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
    {
        let state_tree_arc = workload.state_tree();
        let state = state_tree_arc.lock().await;
        match state.get(key) {
            Ok(Some(bytes)) => {
                let stakers: BTreeMap<String, u64> = serde_json::from_slice(&bytes)
                    .map_err(|e| ChainError::State(StateError::InvalidValue(e.to_string())))?;
                let mut active_stakers: Vec<Vec<u8>> = stakers
                    .into_iter()
                    .filter(|(_, stake)| *stake > 0)
                    .filter_map(|(key, _)| bs58::decode(key).into_vec().ok())
                    .collect();
                // --- FIX: Sort the set for canonical representation ---
                active_stakers.sort();
                Ok(active_stakers)
            }
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }
}

#[async_trait]
impl<CS, ST> AppChain<CS, UnifiedTransactionModel<CS>, ST> for Chain<CS>
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
    ) -> Result<(), ChainError> {
        self.state
            .transaction_model
            .apply(tx, workload, self.state.status.height)
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
            return Err(ChainError::Block(format!(
                "Invalid block height. Expected {}, got {}",
                self.state.status.height + 1,
                height
            )));
        }

        // --- FIX START: Simplify state promotion at the start of block processing ---
        if height > 0 {
            let state_tree_arc = workload.state_tree();
            let mut state = state_tree_arc.lock().await;
            // Promote NEXT from the previous block to become CURRENT for this block.
            let next_stakes_bytes = state
                .get(STAKES_KEY_NEXT)?
                .unwrap_or_else(|| b"{}".to_vec());
            state.insert(STAKES_KEY_CURRENT, &next_stakes_bytes)?;
        }
        // --- FIX END ---

        let expected_prev_hash = self
            .state
            .recent_blocks
            .last()
            .map_or(vec![0; 32], |b| b.header.hash());
        if block.header.prev_hash != expected_prev_hash {
            return Err(ChainError::Block(format!(
                "Invalid prev_hash for block {}. Expected {}, got {}",
                height,
                hex::encode(&expected_prev_hash),
                hex::encode(&block.header.prev_hash)
            )));
        }

        for tx in &block.transactions {
            if let ChainTransaction::System(sys_tx) = tx {
                if let SystemPayload::SwapModule {
                    service_type,
                    module_wasm,
                    activation_height,
                } = &sys_tx.payload
                {
                    let service_type_enum = ServiceType::Custom(service_type.clone());
                    self.service_manager
                        .schedule_upgrade(
                            service_type_enum,
                            module_wasm.clone(),
                            *activation_height,
                        )
                        .map_err(|e| {
                            ChainError::Block(format!("Failed to schedule upgrade: {}", e))
                        })?;
                }
            }
        }

        for tx in &block.transactions {
            self.process_transaction(tx, workload).await?;
        }

        if let Ok(count) = self.service_manager.apply_upgrades_at_height(height) {
            if count > 0 {
                log::info!("Applied {} module upgrade(s) at height {}", count, height);
            }
        }

        self.state.status.height = height;
        self.state.status.latest_timestamp = block.header.timestamp;

        let validator_set_for_h_plus_1 = self
            .get_validator_set_from_key(workload, STAKES_KEY_NEXT)
            .await?;

        let status_bytes = serde_json::to_vec(&self.state.status)
            .map_err(|e| ChainError::Transaction(format!("Failed to serialize status: {e}")))?;
        let state_tree_arc = workload.state_tree();
        let mut state = state_tree_arc.lock().await;
        state.insert(STATUS_KEY, &status_bytes)?;
        let new_state_root = state.root_commitment().as_ref().to_vec();
        drop(state);

        if is_producing {
            block.header.state_root = new_state_root;
            // --- FIX START: Sort the validator set before putting it in the header ---
            let mut set = self
                .get_validator_set_from_key(workload, STAKES_KEY_CURRENT)
                .await?;
            set.sort();
            block.header.validator_set = set;
            // --- FIX END ---
        } else {
            if block.header.state_root != new_state_root {
                return Err(ChainError::Block(format!(
                    "State root mismatch. Expected {}, got {}",
                    hex::encode(&block.header.state_root),
                    hex::encode(&new_state_root)
                )));
            }
            // --- FIX START: Sort both sets before comparing ---
            let mut current_validator_set = self
                .get_validator_set_from_key(workload, STAKES_KEY_CURRENT)
                .await?;
            current_validator_set.sort();
            let mut header_set = block.header.validator_set.clone();
            header_set.sort();

            if header_set != current_validator_set {
                return Err(ChainError::Block(
                    "Validator set mismatch in received block".to_string(),
                ));
            }
            // --- FIX END ---
        }

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
        let prev_hash = self
            .state
            .recent_blocks
            .last()
            .map_or(vec![0; 32], |b| b.header.hash());

        let mut validator_set_bytes = current_validator_set.to_vec();
        validator_set_bytes.sort();

        let header = BlockHeader {
            height: self.state.status.height + 1,
            prev_hash,
            state_root: vec![],
            transactions_root: vec![0; 32],
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            validator_set: validator_set_bytes,
            producer: producer_keypair.public().encode_protobuf(),
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

    async fn get_validator_set(
        &self,
        workload: &WorkloadContainer<ST>,
    ) -> Result<Vec<Vec<u8>>, ChainError> {
        let state_tree_arc = workload.state_tree();
        let state = state_tree_arc.lock().await;

        if state.get(STAKES_KEY_CURRENT)?.is_some() || state.get(STAKES_KEY_NEXT)?.is_some() {
            drop(state);
            self.get_validator_set_from_key(workload, STAKES_KEY_CURRENT)
                .await
        } else {
            match state.get(AUTHORITY_SET_KEY) {
                Ok(Some(bytes)) => serde_json::from_slice(&bytes).map_err(|e| {
                    ChainError::Transaction(format!("Failed to deserialize authority set: {e}"))
                }),
                Ok(None) => Ok(Vec::new()),
                Err(e) => Err(e.into()),
            }
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
        match state.get(STAKES_KEY_CURRENT) {
            Ok(Some(bytes)) => {
                let raw_map: BTreeMap<String, u64> =
                    serde_json::from_slice(&bytes).map_err(|e| {
                        ChainError::Transaction(format!("Failed to deserialize stakes map: {e}"))
                    })?;

                let stakes_map: BTreeMap<PublicKey, StakeAmount> = raw_map
                    .into_iter()
                    .filter(|(_, stake)| *stake > 0)
                    .collect();
                Ok(stakes_map)
            }
            Ok(None) => Ok(BTreeMap::new()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use depin_sdk_api::state::StateCommitment;
    use depin_sdk_commitment::primitives::hash::HashCommitmentScheme;
    use depin_sdk_commitment::tree::hashmap::HashMapStateTree;
    use depin_sdk_transaction_models::unified::UnifiedTransactionModel;
    use depin_sdk_types::app::{SystemPayload, SystemTransaction};
    use depin_sdk_types::config::WorkloadConfig;
    use depin_sdk_vm_wasm::WasmVm;
    use libp2p::identity::Keypair;
    use libp2p::PeerId;
    use std::sync::Arc;

    fn placeholder_factory(_: &[u8]) -> Result<Arc<dyn UpgradableService>, CoreError> {
        unimplemented!("WASM loading not needed for this test")
    }

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
        let mut chain = Chain::new(
            scheme.clone(),
            UnifiedTransactionModel::new(scheme),
            "test-chain",
            vec![],
            Box::new(placeholder_factory),
        );

        let gov_keypair = Keypair::generate_ed25519();
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
        let protocol_tx = ChainTransaction::System(sys_tx);

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
        let mut chain = Chain::new(
            scheme.clone(),
            UnifiedTransactionModel::new(scheme),
            "test-chain",
            vec![],
            Box::new(placeholder_factory),
        );
        let gov_keypair = Keypair::generate_ed25519();
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
        let protocol_tx = ChainTransaction::System(sys_tx);

        let result = chain.process_transaction(&protocol_tx, &workload).await;
        assert!(result.is_err());
        assert!(
            matches!(result, Err(ChainError::Transaction(msg)) if msg.contains("Invalid governance signature"))
        );
    }
}
