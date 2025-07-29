// Path: crates/chain/src/app/mod.rs

//! The private implementation for the `SovereignChain` trait.

use crate::upgrade_manager::ModuleUpgradeManager;
use async_trait::async_trait;
use depin_sdk_core::app::{Block, BlockHeader, ChainError, ChainStatus, SovereignAppChain};
use depin_sdk_core::chain::SovereignChain;
use depin_sdk_core::commitment::CommitmentScheme;
// REMOVED: Unused import `StateError`
use depin_sdk_core::services::UpgradableService;
// REMOVED: Unused import `StateTree`
use depin_sdk_core::state::StateManager;
use depin_sdk_core::transaction::TransactionModel;
use depin_sdk_core::validator::WorkloadContainer;
use depin_sdk_validator::traits::WorkloadLogic;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

// Define a well-known key for storing the chain status in the state tree.
const STATUS_KEY: &[u8] = b"chain::status";

/// A container struct that holds the chain's data (`SovereignAppChain`) and its
/// associated logic managers (`ModuleUpgradeManager`).
/// This struct implements the `SovereignChain` trait.
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
    /// The `new` constructor is an inherent method on the logic struct,
    /// which allows the `SovereignChain` trait to be object-safe.
    pub fn new(
        commitment_scheme: CS,
        transaction_model: TM,
        chain_id: &str,
        initial_services: Vec<Arc<dyn UpgradableService>>,
    ) -> Self {
        // This now creates a default/genesis status, which will be overwritten
        // by load_or_initialize_status if state exists.
        let status = ChainStatus {
            height: 0,
            latest_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
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

    /// [NEW METHOD] Loads chain status from the state manager, or initializes it if not found.
    pub async fn load_or_initialize_status<ST>(
        &mut self,
        workload: &WorkloadContainer<ST>,
    ) -> Result<(), ChainError>
    where
        ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
    {
        // FIX: Create a longer-lived binding for the Arc<Mutex> to solve the lifetime error.
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

/// Implements the `dyn`-safe `SovereignChain` trait for the `ChainLogic` struct.
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

    /// Processes a transaction by delegating execution to the WorkloadContainer.
    async fn process_transaction(
        &mut self,
        tx: &TM::Transaction,
        workload: &WorkloadContainer<ST>,
    ) -> Result<(), ChainError> {
        workload
            .execute_transaction(
                tx,
                <Self as SovereignChain<CS, TM, ST>>::transaction_model(self),
            )
            .await
            .map_err(|e| ChainError::Transaction(e.to_string()))?;

        self.app_chain.status.total_transactions += 1;
        Ok(())
    }

    /// Processes a full block by iterating through its transactions and delegating
    /// each one to the WorkloadContainer for execution.
    async fn process_block(
        &mut self,
        mut block: Block<TM::Transaction>,
        workload: &WorkloadContainer<ST>,
    ) -> Result<(), ChainError> {
        if block.header.height != self.app_chain.status.height + 1 {
            return Err(ChainError::Block("Invalid block height".to_string()));
        }

        for tx in &block.transactions {
            self.process_transaction(tx, workload).await?;
        }

        // After all transactions are processed, get the final state root from the workload container.
        let state_root =
            workload.state_tree().lock().await.root_commitment();
        block.header.state_root = state_root.as_ref().to_vec();

        self.app_chain.status.height = block.header.height;
        self.app_chain.status.latest_timestamp = block.header.timestamp;
        self.app_chain.recent_blocks.push(block);
        if self.app_chain.recent_blocks.len() > self.app_chain.max_recent_blocks {
            self.app_chain.recent_blocks.remove(0);
        }

        // [MODIFIED] Persist the updated status to the state tree.
        let status_bytes = serde_json::to_vec(&self.app_chain.status)
            .map_err(|e| ChainError::Transaction(format!("Failed to serialize status: {}", e)))?;
        workload
            .state_tree()
            .lock()
            .await
            .insert(STATUS_KEY, &status_bytes)
            .map_err(|e| ChainError::Transaction(e.to_string()))?;

        Ok(())
    }

    /// Creates a new block template to be filled by a block producer.
    fn create_block(
        &self,
        transactions: Vec<TM::Transaction>,
        _workload: &WorkloadContainer<ST>,
    ) -> Block<TM::Transaction> {
        let prev_hash = self
            .app_chain
            .recent_blocks
            .last()
            .map_or(vec![0; 32], |b| b.header.state_root.clone());

        // FIX: The state_root here is just a placeholder. The real root is calculated
        // and overwritten in `process_block` after all transactions are executed.
        // We remove the illegal `block_on` call and just use the previous hash as the initial value.
        let state_root = prev_hash.clone();

        let header = BlockHeader {
            height: self.app_chain.status.height + 1,
            prev_hash,
            state_root,
            transactions_root: vec![0; 32],
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
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
}