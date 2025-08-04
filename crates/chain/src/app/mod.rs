// Path: crates/chain/src/app/mod.rs
// Final Version: This file includes the critical fix for scheduling module upgrades
// and resolves all associated clippy warnings.

/// The private implementation for the `AppChain` trait.
use crate::upgrade_manager::ModuleUpgradeManager;
use async_trait::async_trait;
use depin_sdk_api::chain::{AppChain, PublicKey, StakeAmount};
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_api::services::{ServiceType, UpgradableService};
use depin_sdk_api::state::StateManager;
use depin_sdk_api::transaction::TransactionModel;
use depin_sdk_api::validator::{TransactionExecutor, WorkloadContainer};
use depin_sdk_transaction_models::protocol::ProtocolModel;
use depin_sdk_types::app::{Block, BlockHeader, ChainStatus, ProtocolTransaction, SystemPayload};
use depin_sdk_types::error::{ChainError, CoreError, StateError};
use depin_sdk_types::keys::*;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// A type alias for the factory function that instantiates services from WASM blobs.
type ServiceFactory =
    Box<dyn Fn(&[u8]) -> Result<Arc<dyn UpgradableService>, CoreError> + Send + Sync>;

/// A struct that holds the core, serializable state of a blockchain.
#[derive(Debug)]
#[allow(dead_code)]
pub struct ChainState<CS: CommitmentScheme + Clone> {
    pub commitment_scheme: CS,
    pub transaction_model: ProtocolModel<CS>,
    pub chain_id: String,
    pub status: ChainStatus,
    pub recent_blocks: Vec<Block<ProtocolTransaction>>,
    pub max_recent_blocks: usize,
}

#[derive(Debug)]
pub struct Chain<CS: CommitmentScheme + Clone> {
    state: ChainState<CS>,
    pub service_manager: ModuleUpgradeManager,
}

impl<CS> Chain<CS>
where
    CS: CommitmentScheme + Clone,
{
    pub fn new(
        commitment_scheme: CS,
        transaction_model: ProtocolModel<CS>,
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
}

#[async_trait]
impl<CS, ST> AppChain<CS, ProtocolModel<CS>, ST> for Chain<CS>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug,
    WorkloadContainer<ST>: TransactionExecutor<ST>,
    CS::Commitment: Send + Sync + Debug,
{
    fn status(&self) -> &ChainStatus {
        &self.state.status
    }

    fn transaction_model(&self) -> &ProtocolModel<CS> {
        &self.state.transaction_model
    }

    async fn process_transaction(
        &mut self,
        tx: &ProtocolTransaction,
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

        // **FIX**: Explicitly handle scheduling of module swaps before general processing.
        for tx in &block.transactions {
            if let ProtocolTransaction::System(sys_tx) = tx {
                if let SystemPayload::SwapModule {
                    service_type,
                    module_wasm,
                    activation_height,
                } = &sys_tx.payload
                {
                    let service_type_enum = ServiceType::Custom(service_type.clone());
                    log::info!(
                        "Scheduling module upgrade for {:?} at height {}",
                        service_type_enum,
                        activation_height
                    );
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

        // ** WIRING FOR FORKLESS UPGRADES **
        // Apply any scheduled upgrades at the end of block processing.
        match self
            .service_manager
            .apply_upgrades_at_height(block.header.height)
        {
            Ok(count) if count > 0 => {
                log::info!(
                    "Successfully applied {} module upgrade(s) at height {}",
                    count,
                    block.header.height
                );
            }
            Ok(_) => (), // No upgrades, do nothing.
            Err(e) => {
                log::error!(
                    "CRITICAL: Failed to apply scheduled module upgrade at height {}: {:?}",
                    block.header.height,
                    e
                );
                return Err(ChainError::Block(format!("Module upgrade failed: {}", e)));
            }
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

        let mut validator_set_bytes = current_validator_set.to_vec();
        validator_set_bytes.sort();

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
            validator_set: validator_set_bytes,
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
    use depin_sdk_transaction_models::protocol::ProtocolModel;
    use depin_sdk_types::app::{SystemPayload, SystemTransaction};
    use depin_sdk_types::config::WorkloadConfig;
    use depin_sdk_vm_wasm::WasmVm;
    use libp2p::identity::{self, Keypair};
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
            ProtocolModel::new(scheme),
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
        let mut chain = Chain::new(
            scheme.clone(),
            ProtocolModel::new(scheme),
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
        let protocol_tx = ProtocolTransaction::System(sys_tx);

        let result = chain.process_transaction(&protocol_tx, &workload).await;
        assert!(result.is_err());
        assert!(
            matches!(result, Err(ChainError::Transaction(msg)) if msg.contains("Invalid governance signature"))
        );
    }
}
