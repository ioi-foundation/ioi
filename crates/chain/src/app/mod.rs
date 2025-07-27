use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_core::error::CoreError;
use depin_sdk_core::services::{ServiceType, UpgradableService};
use depin_sdk_core::state::{StateManager, StateTree};
use depin_sdk_core::transaction::TransactionModel;
use depin_sdk_core::validator::ValidatorModel;
use crate::upgrade_manager::ModuleUpgradeManager;
use depin_sdk_state_trees::file::FileStateTree;
use depin_sdk_commitment_schemes::hash::HashCommitmentScheme;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Block header containing metadata
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlockHeader {
    /// Block height
    pub height: u64,
    /// Previous block hash
    pub prev_hash: Vec<u8>,
    /// State root commitment
    pub state_root: Vec<u8>,
    /// Transactions root (e.g., Merkle root of transactions)
    pub transactions_root: Vec<u8>,
    /// Block timestamp (Unix timestamp in seconds)
    pub timestamp: u64,
}

/// Block structure containing transactions
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Block<T> {
    /// Block header
    pub header: BlockHeader,
    /// Transactions included in this block
    pub transactions: Vec<T>,
}

/// Chain status information
#[derive(Debug, Clone)]
pub struct ChainStatus {
    /// Current block height
    pub height: u64,
    /// Latest block timestamp
    pub latest_timestamp: u64,
    /// Number of transactions processed
    pub total_transactions: u64,
    /// Chain running status
    pub is_running: bool,
}

/// Implementation of sovereign app chain with runtime-swappable modules
pub struct SovereignAppChain<CS, ST, TM, VM>
where
    CS: CommitmentScheme,
    // Specify that ST implements both StateTree and StateManager with the specific commitment types
    ST: StateTree<Commitment = CS::Commitment, Proof = CS::Proof>
        + StateManager<Commitment = CS::Commitment, Proof = CS::Proof>,
    TM: TransactionModel,
    VM: ValidatorModel,
    // Ensure the transaction model's commitment scheme uses the same types
    TM::CommitmentScheme: CommitmentScheme<Commitment = CS::Commitment, Proof = CS::Proof>,
{
    /// Commitment scheme
    commitment_scheme: CS,
    /// State tree
    state_tree: ST,
    /// Transaction model
    transaction_model: TM,
    /// Validator model
    validator_model: VM,
    /// Module upgrade manager for runtime-swappable services
    service_manager: ModuleUpgradeManager,
    /// Chain ID
    chain_id: String,
    /// Current status
    status: ChainStatus,
    /// Latest blocks (limited cache)
    recent_blocks: Vec<Block<TM::Transaction>>,
    /// Maximum blocks to keep in memory
    max_recent_blocks: usize,
}

impl<CS, ST, TM, VM> SovereignAppChain<CS, ST, TM, VM>
where
    CS: CommitmentScheme,
    ST: StateTree<Commitment = CS::Commitment, Proof = CS::Proof>
        + StateManager<Commitment = CS::Commitment, Proof = CS::Proof>,
    TM: TransactionModel,
    VM: ValidatorModel,
    TM::CommitmentScheme: CommitmentScheme<Commitment = CS::Commitment, Proof = CS::Proof>,
{
    /// Create a new sovereign app chain with runtime-swappable services
    pub fn new(
        commitment_scheme: CS,
        state_tree: ST,
        transaction_model: TM,
        validator_model: VM,
        chain_id: &str,
        initial_services: Vec<Arc<dyn UpgradableService>>,
    ) -> Self {
        let status = ChainStatus {
            height: 0,
            latest_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_secs(),
            total_transactions: 0,
            is_running: false,
        };

        // Initialize the module upgrade manager with initial services
        let mut service_manager = ModuleUpgradeManager::new();
        for service in initial_services {
            service_manager.register_service(service);
        }

        Self {
            commitment_scheme,
            state_tree,
            transaction_model,
            validator_model,
            service_manager,
            chain_id: chain_id.to_string(),
            status,
            recent_blocks: Vec::new(),
            max_recent_blocks: 100, // Default to storing last 100 blocks
        }
    }

    /// Get the chain ID
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    /// Get the current chain status
    pub fn status(&self) -> &ChainStatus {
        &self.status
    }

    /// Get a reference to the service manager
    pub fn service_manager(&self) -> &ModuleUpgradeManager {
        &self.service_manager
    }

    /// Get a mutable reference to the service manager
    pub fn service_manager_mut(&mut self) -> &mut ModuleUpgradeManager {
        &mut self.service_manager
    }

    //
    // Service Interaction Methods
    //

    /// Get a service by type
    pub fn get_service(&self, service_type: &ServiceType) -> Option<Arc<dyn UpgradableService>> {
        self.service_manager.get_service(service_type)
    }

    /// Submit a governance proposal (if governance service is available)
    pub fn submit_governance_proposal(&self, proposal_data: &[u8]) -> Result<(), CoreError> {
        let governance = self
            .service_manager
            .get_service(&ServiceType::Governance)
            .ok_or(CoreError::ServiceNotFound("Governance".to_string()))?;

        // Call the governance service's proposal submission method
        // Note: This assumes a GovernanceService trait with submit_proposal method
        // governance.submit_proposal(proposal_data)

        // For now, return Ok as we don't have the actual trait definition
        Ok(())
    }

    /// Query external data (if external data service is available)
    pub fn query_external_data(&self, query: &str) -> Result<Vec<u8>, CoreError> {
        let external_data = self
            .service_manager
            .get_service(&ServiceType::ExternalData)
            .ok_or(CoreError::ServiceNotFound("ExternalData".to_string()))?;

        // Call the external data service's query method
        // external_data.fetch_data(query)

        // For now, return placeholder
        Ok(vec![])
    }

    /// Execute semantic interpretation (if semantic service is available)
    pub fn interpret_semantic(&self, input: &str) -> Result<String, CoreError> {
        let semantic = self
            .service_manager
            .get_service(&ServiceType::Semantic)
            .ok_or(CoreError::ServiceNotFound("Semantic".to_string()))?;

        // Call the semantic service's interpretation method
        // semantic.interpret(input)

        // For now, return placeholder
        Ok("Interpretation not implemented".to_string())
    }

    //
    // 1. State Management Methods
    //

    /// Query a value from the state tree
    pub fn query_state(&self, key: &[u8]) -> Option<Vec<u8>> {
        // Use expect to handle the Result and extract the Option
        <ST as StateTree>::get(&self.state_tree, key).expect("State access error")
    }

    /// Get the current state root commitment
    pub fn get_state_commitment(&self) -> CS::Commitment {
        <ST as StateTree>::root_commitment(&self.state_tree)
    }

    /// Create a proof for a key
    pub fn create_state_proof(&self, key: &[u8]) -> Option<CS::Proof> {
        <ST as StateTree>::create_proof(&self.state_tree, key)
    }

    /// Verify a state proof
    pub fn verify_state_proof(
        &self,
        commitment: &CS::Commitment,
        proof: &CS::Proof,
        key: &[u8],
        value: &[u8],
    ) -> bool {
        <ST as StateTree>::verify_proof(&self.state_tree, commitment, proof, key, value)
    }

    /// Update state directly (administrative function)
    pub fn update_state(&mut self, key: &[u8], value: &[u8]) -> Result<(), String> {
        <ST as StateTree>::insert(&mut self.state_tree, key, value)
            .map_err(|e| format!("State error: {}", e))
    }

    /// Delete a key from state (administrative function)
    pub fn delete_state(&mut self, key: &[u8]) -> Result<(), String> {
        <ST as StateTree>::delete(&mut self.state_tree, key)
            .map_err(|e| format!("State error: {}", e))
    }

    //
    // 2. Transaction Processing Methods
    //

    /// Process a transaction
    pub fn process_transaction(&mut self, tx: &TM::Transaction) -> Result<(), String> {
        // Validate the transaction against current state
        // Pass the state_tree itself, not just the commitment
        match self.transaction_model.validate(tx, &self.state_tree) {
            Ok(valid) => {
                if !valid {
                    return Err("Transaction validation failed".to_string());
                }
            }
            Err(e) => return Err(format!("Validation error: {}", e)),
        }

        // Apply the transaction to state - map error to String
        match self.transaction_model.apply(tx, &mut self.state_tree) {
            Ok(_) => {
                // Update statistics on success
                self.status.total_transactions += 1;
                Ok(())
            }
            Err(e) => Err(format!("Transaction application failed: {}", e)),
        }
    }

    /// Process a batch of transactions
    pub fn process_transactions(&mut self, txs: &[TM::Transaction]) -> Result<Vec<String>, String> {
        let mut results = Vec::with_capacity(txs.len());

        for tx in txs {
            match self.process_transaction(tx) {
                Ok(()) => results.push("Success".to_string()),
                Err(e) => results.push(e),
            }
        }

        Ok(results)
    }

    //
    // 3. Block Processing Methods
    //

    /// Process a block
    pub fn process_block(&mut self, mut block: Block<TM::Transaction>) -> Result<(), String>
    where
        CS: Clone,
        CS::Value: From<Vec<u8>> + AsRef<[u8]> + Clone,
    {
        // Ensure block is built on current chain state
        if block.header.height != self.status.height + 1 {
            return Err(format!(
                "Invalid block height: expected {}, got {}",
                self.status.height + 1,
                block.header.height
            ));
        }

        // Verify block timestamp is reasonable
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();

        if block.header.timestamp > now + 60 {
            // Allow 1 minute clock drift
            return Err("Block timestamp is in the future".to_string());
        }

        // Validate block using validator_model
        if !self.validator_model.is_running() {
            self.validator_model
                .start()
                .map_err(|e| format!("Failed to start validator: {}", e))?;
        }

        // Process all transactions
        let mut tx_results = Vec::new();
        for tx in &block.transactions {
            match self.process_transaction(tx) {
                Ok(()) => tx_results.push(true),
                Err(e) => {
                    tx_results.push(false);
                    return Err(format!("Transaction processing failed: {}", e));
                }
            }
        }

        // Update state root in block header to match current state
        let current_state_root = <ST as StateTree>::root_commitment(&self.state_tree);
        block.header.state_root = current_state_root.as_ref().to_vec();

        // Check for and apply any module upgrades scheduled for this block height
        // This happens after transaction processing but before finalizing the block
        match self
            .service_manager
            .apply_upgrades_at_height(block.header.height)
        {
            Ok(upgrades_applied) => {
                if upgrades_applied > 0 {
                    println!(
                        "Applied {} module upgrades at height {}",
                        upgrades_applied, block.header.height
                    );
                }
            }
            Err(e) => {
                return Err(format!("Failed to apply module upgrades: {}", e));
            }
        }

        // Update chain status
        self.status.height = block.header.height;
        self.status.latest_timestamp = block.header.timestamp;

        // Add block to recent blocks cache
        self.recent_blocks.push(block);
        if self.recent_blocks.len() > self.max_recent_blocks {
            self.recent_blocks.remove(0); // Remove oldest block
        }

        // Periodically save state if the state tree supports it (e.g., FileStateTree)
        if self.status.height % 10 == 0 {
            // This uses `as_any()` and `downcast_ref` to check if the state tree is a `FileStateTree`
            // without breaking the generic `ST` constraint. This is a common pattern for
            // accessing concrete type features from generic code.
            if let Some(persistable_tree) = self.state_tree.as_any().downcast_ref::<FileStateTree<CS>>() {
                // Now valid because of the `where` clause on this method
                if let Err(e) = persistable_tree.save() {
                    eprintln!("[Warning] Periodic state save failed at height {}: {}", self.status.height, e);
                } else {
                    println!("State periodically saved at height {}", self.status.height);
                }
            }
        }


        Ok(())
    }

    /// Create a new block (for validators/block producers)
    pub fn create_block(&self, transactions: Vec<TM::Transaction>) -> Block<TM::Transaction> {
        let prev_hash = if self.recent_blocks.is_empty() {
            vec![0; 32] // Genesis block
        } else {
            // In a real implementation, this would be the hash of the latest block
            // For simplicity, we'll use the serialized state root as the prev hash
            <ST as StateTree>::root_commitment(&self.state_tree)
                .as_ref()
                .to_vec()
        };

        let header = BlockHeader {
            height: self.status.height + 1,
            prev_hash,
            state_root: <ST as StateTree>::root_commitment(&self.state_tree)
                .as_ref()
                .to_vec(),
            transactions_root: vec![0; 32], // Simplified - would compute actual Merkle root
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_secs(),
        };

        Block {
            header,
            transactions,
        }
    }

    /// Get a recent block by height
    pub fn get_block(&self, height: u64) -> Option<&Block<TM::Transaction>> {
        self.recent_blocks
            .iter()
            .find(|block| block.header.height == height)
    }

    /// Get the latest block
    pub fn get_latest_block(&self) -> Option<&Block<TM::Transaction>> {
        self.recent_blocks.last()
    }

    //
    // 4. Enhanced Start/Stop Methods
    //

    /// Start the chain with proper initialization
    pub fn start(&mut self) -> Result<(), String> {
        println!("Starting sovereign app chain: {}", self.chain_id);

        // Initialize validator
        self.validator_model
            .start()
            .map_err(|e| format!("Failed to start validator: {}", e))?;

        // Start all registered services
        self.service_manager
            .start_all_services()
            .map_err(|e| format!("Failed to start services: {}", e))?;

        // Initialize state (in a real implementation, would load from persistent storage)
        // For now, we'll just use the existing state

        // Update status
        self.status.is_running = true;
        self.status.latest_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();

        println!(
            "Sovereign app chain started successfully: {}",
            self.chain_id
        );

        Ok(())
    }

    /// Stop the chain
    pub fn stop(&mut self) -> Result<(), String> {
        println!("Stopping sovereign app chain: {}", self.chain_id);

        // Stop all services
        self.service_manager
            .stop_all_services()
            .map_err(|e| format!("Failed to stop services: {}", e))?;

        // Stop the validator
        self.validator_model
            .stop()
            .map_err(|e| format!("Failed to stop validator: {}", e))?;

        // In a real implementation, we would:
        // 1. Persist state to storage
        // 2. Close connections
        // 3. Shutdown properly

        // Update status
        self.status.is_running = false;

        println!(
            "Sovereign app chain stopped successfully: {}",
            self.chain_id
        );

        Ok(())
    }

    /// Reset the chain (for testing purposes)
    pub fn reset(&mut self) -> Result<(), String> {
        // Stop the chain if running
        if self.status.is_running {
            self.stop()?;
        }

        // Reset service manager
        self.service_manager.reset()
            .map_err(|e| format!("Failed to reset service manager: {}", e))?;

        // Reset state (implementation would depend on how ST can be reset)
        // For demonstration purposes, assuming ST has no reset method

        // Reset chain status
        self.status = ChainStatus {
            height: 0,
            latest_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_secs(),
            total_transactions: 0,
            is_running: false,
        };

        // Clear recent blocks
        self.recent_blocks.clear();

        Ok(())
    }

    /// Configure the maximum number of recent blocks to keep in memory
    pub fn set_max_recent_blocks(&mut self, count: usize) {
        self.max_recent_blocks = count;

        // Trim if needed
        while self.recent_blocks.len() > self.max_recent_blocks {
            self.recent_blocks.remove(0);
        }
    }

    /// Get the commitment scheme
    pub fn commitment_scheme(&self) -> &CS {
        &self.commitment_scheme
    }

    /// Get the state tree
    pub fn state_tree(&self) -> &ST {
        &self.state_tree
    }

    /// Get the transaction model
    pub fn transaction_model(&self) -> &TM {
        &self.transaction_model
    }

    /// Get the validator model
    pub fn validator_model(&self) -> &VM {
        &self.validator_model
    }

    /// Check service health
    pub fn check_service_health(&self) -> Vec<(ServiceType, bool)> {
        self.service_manager.check_all_health()
    }

    /// Get upgrade history for a service
    pub fn get_service_history(&self, service_type: &ServiceType) -> Vec<u64> {
        self.service_manager.get_upgrade_history(service_type)
    }
}

#[cfg(test)]
mod tests;