// Path: crates/chain/src/app/mod.rs

//! The private implementation for the `SovereignChain` trait.

use crate::upgrade_manager::ModuleUpgradeManager;
use async_trait::async_trait;
use depin_sdk_core::app::{Block, BlockHeader, ChainError, ChainStatus, SovereignAppChain};
use depin_sdk_core::chain::SovereignChain;
use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_core::services::UpgradableService;
use depin_sdk_core::state::StateManager;
use depin_sdk_core::transaction::TransactionModel;
use depin_sdk_core::validator::{WorkloadContainer, WorkloadLogic};
use libp2p::PeerId;
use std::collections::HashSet;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const STATUS_KEY: &[u8] = b"chain::status";
const VALIDATOR_SET_KEY: &[u8] = b"system::validators";
const AUTHORITY_SET_KEY: &[u8] = b"system::authorities";

#[derive(Debug)]
pub struct ChainLogic<CS, TM: TransactionModel> {
    app_chain: SovereignAppChain<CS, TM>,
    #[allow(dead_code)]
    service_manager: ModuleUpgradeManager,
}

impl<CS, TM> ChainLogic<CS, TM>
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
        let app_chain = SovereignAppChain {
            commitment_scheme,
            transaction_model,
            chain_id: chain_id.to_string(),
            status,
            recent_blocks: Vec::new(),
            max_recent_blocks: 100,
        };
        Self {
            app_chain,
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
                let status: ChainStatus = serde_json::from_slice(&status_bytes)
                    .map_err(|e| ChainError::Transaction(format!("Failed to deserialize status: {}", e)))?;
                log::info!("Loaded chain status: height {}", status.height);
                self.app_chain.status = status;
            }
            Ok(None) => {
                log::info!("No existing chain status found. Initializing and saving genesis status.");
                let status_bytes = serde_json::to_vec(&self.app_chain.status).unwrap();
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
impl<CS, TM, ST> SovereignChain<CS, TM, ST> for ChainLogic<CS, TM>
where
    CS: CommitmentScheme + Send + Sync + 'static,
    TM: TransactionModel<CommitmentScheme = CS> + Clone + Send + Sync + 'static + Debug,
    TM::Transaction: Clone + Send + Sync + Debug,
    CS::Commitment: Send + Sync + Debug,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static + Debug,
{
    fn status(&self) -> &ChainStatus {
        &self.app_chain.status
    }

    fn transaction_model(&self) -> &TM {
        &self.app_chain.transaction_model
    }

    async fn process_transaction(
        &mut self,
        tx: &TM::Transaction,
        workload: &WorkloadContainer<ST>,
    ) -> Result<(), ChainError> {
        workload
            .execute_transaction(tx, &self.app_chain.transaction_model)
            .await
            .map_err(|e| ChainError::Transaction(e.to_string()))?;
        self.app_chain.status.total_transactions += 1;
        Ok(())
    }

    async fn process_block(
        &mut self,
        mut block: Block<TM::Transaction>,
        workload: &WorkloadContainer<ST>,
    ) -> Result<Block<TM::Transaction>, ChainError> {
        if block.header.height != self.app_chain.status.height + 1 {
            return Err(ChainError::Block(format!(
                "Invalid block height. Expected {}, got {}",
                self.app_chain.status.height + 1,
                block.header.height
            )));
        }
        let expected_prev_hash = self
            .app_chain
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
        self.app_chain.status.height = block.header.height;
        self.app_chain.status.latest_timestamp = block.header.timestamp;
        
        let status_bytes = serde_json::to_vec(&self.app_chain.status)
            .map_err(|e| ChainError::Transaction(format!("Failed to serialize status: {}", e)))?;
        let validator_set_bytes = serde_json::to_vec(&block.header.validator_set)
            .map_err(|e| ChainError::Transaction(format!("Failed to serialize validator set: {}", e)))?;
        
        // FIX: Bind the Arc to a variable to extend its lifetime.
        let state_tree_arc = workload.state_tree();
        let mut state = state_tree_arc.lock().await;
        state.insert(STATUS_KEY, &status_bytes)
             .map_err(|e| ChainError::Transaction(e.to_string()))?;
        // Commit the validator set from the block header to the state tree.
        state.insert(VALIDATOR_SET_KEY, &validator_set_bytes)
             .map_err(|e| ChainError::Transaction(e.to_string()))?;
        
        let state_root = state.root_commitment();
        drop(state); // release lock

        block.header.state_root = state_root.as_ref().to_vec();
        // Push a clone because we are returning the original block
        self.app_chain.recent_blocks.push(block.clone());
        if self.app_chain.recent_blocks.len() > self.app_chain.max_recent_blocks {
            self.app_chain.recent_blocks.remove(0);
        }
        Ok(block)
    }

    fn create_block(
        &self,
        transactions: Vec<TM::Transaction>,
        _workload: &WorkloadContainer<ST>,
        current_validator_set: &Vec<Vec<u8>>,
        known_peers_bytes: &Vec<Vec<u8>>,
    ) -> Block<TM::Transaction> {
        let prev_hash = self
            .app_chain
            .recent_blocks
            .last()
            .map_or(vec![0; 32], |b| b.header.state_root.clone());

        // Propose a new validator set by taking the union of the last committed set
        // and the current set of known network peers. This allows new nodes to be added.
        let base_validators: HashSet<PeerId> = current_validator_set.iter()
            .filter_map(|bytes| PeerId::from_bytes(bytes).ok())
            .collect();

        let known_peers: HashSet<PeerId> = known_peers_bytes.iter()
            .filter_map(|bytes| PeerId::from_bytes(bytes).ok())
            .collect();
        
        let mut new_validator_set_peers: Vec<PeerId> = base_validators.union(&known_peers).cloned().collect();
        new_validator_set_peers.sort();
        
        let validator_set: Vec<Vec<u8>> = new_validator_set_peers.iter().map(|p| p.to_bytes()).collect();

        let next_height = self.app_chain.status.height + 1;
        let state_root = prev_hash.clone();
        let header = BlockHeader {
            height: next_height,
            prev_hash,
            state_root,
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

    fn get_block(&self, height: u64) -> Option<&Block<TM::Transaction>> {
        self.app_chain
            .recent_blocks
            .iter()
            .find(|b| b.header.height == height)
    }

    fn get_blocks_since(&self, height: u64) -> Vec<Block<TM::Transaction>> {
        self.app_chain
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
        // FIX: Bind the Arc to a variable to extend its lifetime.
        let state_tree_arc = workload.state_tree();
        let state = state_tree_arc.lock().await;
        match state.get(VALIDATOR_SET_KEY) {
            Ok(Some(bytes)) => serde_json::from_slice(&bytes)
                .map_err(|e| ChainError::Transaction(format!("Failed to deserialize validator set: {}", e))),
            Ok(None) => Ok(Vec::new()), // Not found, return empty set
            Err(e) => Err(ChainError::Transaction(e.to_string())),
        }
    }

    async fn get_authority_set(
        &self,
        workload: &WorkloadContainer<ST>,
    ) -> Result<Vec<Vec<u8>>, ChainError> {
        let state_tree_arc = workload.state_tree();
        let state = state_tree_arc.lock().await;
        match state.get(AUTHORITY_SET_KEY) {
            Ok(Some(bytes)) => serde_json::from_slice(&bytes)
                .map_err(|e| ChainError::Transaction(format!("Failed to deserialize authority set: {}", e))),
            Ok(None) => Ok(Vec::new()), // Return an empty set if not found.
            Err(e) => Err(ChainError::Transaction(e.to_string())),
        }
    }
}