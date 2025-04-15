#!/bin/bash

# additional-setup.sh - Sets up transaction models and validator components for DePIN SDK
set -e  # Exit on error

echo "Setting up transaction models and validator components..."

# Transaction Models Implementation
cat > crates/transaction_models/Cargo.toml << 'EOF'
[package]
name = "depin-sdk-transaction-models"
version = "0.1.0"
edition = "2021"
description = "Transaction model implementations for the DePIN SDK"
license = "MIT OR Apache-2.0"

[dependencies]
depin-sdk-core = { path = "../core" }
depin-sdk-commitment-schemes = { path = "../commitment_schemes" }
depin-sdk-state-trees = { path = "../state_trees" }
log = { workspace = true }
serde = { workspace = true }
thiserror = { workspace = true }
bytes = { workspace = true }
anyhow = { workspace = true }

[features]
default = []
utxo = []
account = []
hybrid = ["utxo", "account"]
EOF

mkdir -p crates/transaction_models/src/{utxo,account,hybrid}
cat > crates/transaction_models/src/lib.rs << 'EOF'
//! # DePIN SDK Transaction Models
//!
//! Implementations of various transaction models for the DePIN SDK.

pub mod utxo;
pub mod account;
pub mod hybrid;

use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_core::transaction::TransactionModel;
EOF

# UTXO Transaction Model
cat > crates/transaction_models/src/utxo/mod.rs << 'EOF'
//! UTXO transaction model implementation

use std::fmt::Debug;
use std::collections::HashMap;
use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_core::transaction::TransactionModel;
use depin_sdk_core::state::StateManager;

/// UTXO transaction
#[derive(Debug, Clone)]
pub struct UTXOTransaction {
    /// Transaction ID
    pub txid: Vec<u8>,
    /// Inputs (references to previous transaction outputs)
    pub inputs: Vec<UTXOInput>,
    /// Outputs (new unspent transaction outputs)
    pub outputs: Vec<UTXOOutput>,
}

/// UTXO input
#[derive(Debug, Clone)]
pub struct UTXOInput {
    /// Previous transaction ID
    pub prev_txid: Vec<u8>,
    /// Output index in the previous transaction
    pub prev_index: u32,
    /// Signature unlocking the UTXO
    pub signature: Vec<u8>,
}

/// UTXO output
#[derive(Debug, Clone)]
pub struct UTXOOutput {
    /// Value of the output
    pub value: u64,
    /// Locking script or public key hash
    pub lock_script: Vec<u8>,
}

/// UTXO proof
#[derive(Debug, Clone)]
pub struct UTXOProof<P> {
    /// Proof that inputs exist and are unspent
    pub input_proofs: Vec<P>,
}

/// UTXO model with any commitment scheme
pub struct UTXOModel<CS: CommitmentScheme> {
    /// Commitment scheme
    commitment_scheme: CS,
    /// UTXO set
    utxo_set: HashMap<Vec<u8>, UTXOOutput>,
}

impl<CS: CommitmentScheme> UTXOModel<CS> {
    /// Create a new UTXO model
    pub fn new(commitment_scheme: CS) -> Self {
        Self {
            commitment_scheme,
            utxo_set: HashMap::new(),
        }
    }
}

impl<CS: CommitmentScheme> TransactionModel<CS> for UTXOModel<CS> {
    type Transaction = UTXOTransaction;
    type Proof = UTXOProof<CS::Proof>;
    
    fn validate(&self, tx: &Self::Transaction, commitment: &CS::Commitment) -> bool {
        // Simplified validation for initial setup
        // In a real implementation, we would verify:
        // 1. All inputs reference valid UTXOs
        // 2. Input signatures are valid
        // 3. Sum of inputs >= sum of outputs
        true
    }
    
    fn apply(&self, tx: &Self::Transaction, state: &mut dyn StateManager<CS>) -> Result<(), String> {
        // Simplified implementation for initial setup
        // In a real implementation, we would:
        // 1. Mark inputs as spent
        // 2. Add outputs to the UTXO set
        Ok(())
    }
}
EOF

# Account Transaction Model
cat > crates/transaction_models/src/account/mod.rs << 'EOF'
//! Account-based transaction model implementation

use std::fmt::Debug;
use std::collections::HashMap;
use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_core::transaction::TransactionModel;
use depin_sdk_core::state::StateManager;

/// Account transaction
#[derive(Debug, Clone)]
pub struct AccountTransaction {
    /// Transaction ID
    pub txid: Vec<u8>,
    /// Sender account
    pub from: Vec<u8>,
    /// Receiver account
    pub to: Vec<u8>,
    /// Value to transfer
    pub value: u64,
    /// Nonce to prevent replay
    pub nonce: u64,
    /// Signature from sender
    pub signature: Vec<u8>,
}

/// Account proof
#[derive(Debug, Clone)]
pub struct AccountProof<P> {
    /// Proof that the sender account exists and has sufficient balance
    pub sender_proof: P,
    /// Proof that the sender's nonce is correct
    pub nonce_proof: P,
}

/// Account state
#[derive(Debug, Clone)]
pub struct AccountState {
    /// Account balance
    pub balance: u64,
    /// Account nonce
    pub nonce: u64,
}

/// Account model with any commitment scheme
pub struct AccountModel<CS: CommitmentScheme> {
    /// Commitment scheme
    commitment_scheme: CS,
    /// Account states
    accounts: HashMap<Vec<u8>, AccountState>,
}

impl<CS: CommitmentScheme> AccountModel<CS> {
    /// Create a new account model
    pub fn new(commitment_scheme: CS) -> Self {
        Self {
            commitment_scheme,
            accounts: HashMap::new(),
        }
    }
}

impl<CS: CommitmentScheme> TransactionModel<CS> for AccountModel<CS> {
    type Transaction = AccountTransaction;
    type Proof = AccountProof<CS::Proof>;
    
    fn validate(&self, tx: &Self::Transaction, commitment: &CS::Commitment) -> bool {
        // Simplified validation for initial setup
        // In a real implementation, we would verify:
        // 1. Sender account exists and has sufficient balance
        // 2. Nonce is correct to prevent replay
        // 3. Signature is valid
        true
    }
    
    fn apply(&self, tx: &Self::Transaction, state: &mut dyn StateManager<CS>) -> Result<(), String> {
        // Simplified implementation for initial setup
        // In a real implementation, we would:
        // 1. Reduce sender balance
        // 2. Increase receiver balance
        // 3. Increment sender nonce
        Ok(())
    }
}
EOF

# Hybrid Transaction Model
cat > crates/transaction_models/src/hybrid/mod.rs << 'EOF'
//! Hybrid transaction model implementation

use std::fmt::Debug;
use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_core::transaction::TransactionModel;
use depin_sdk_core::state::StateManager;
use crate::utxo::{UTXOModel, UTXOTransaction, UTXOProof};
use crate::account::{AccountModel, AccountTransaction, AccountProof};

/// Hybrid transaction enum
#[derive(Debug, Clone)]
pub enum HybridTransaction<CS: CommitmentScheme> {
    /// UTXO-based transaction
    UTXO(UTXOTransaction),
    /// Account-based transaction
    Account(AccountTransaction),
}

/// Hybrid proof enum
#[derive(Debug, Clone)]
pub enum HybridProof<CS: CommitmentScheme> {
    /// UTXO-based proof
    UTXO(UTXOProof<CS::Proof>),
    /// Account-based proof
    Account(AccountProof<CS::Proof>),
}

/// Hybrid transaction model with any commitment scheme
pub struct HybridModel<CS: CommitmentScheme> {
    /// UTXO model
    utxo_model: UTXOModel<CS>,
    /// Account model
    account_model: AccountModel<CS>,
}

impl<CS: CommitmentScheme> HybridModel<CS> {
    /// Create a new hybrid model
    pub fn new(commitment_scheme: CS) -> Self {
        Self {
            utxo_model: UTXOModel::new(commitment_scheme.clone()),
            account_model: AccountModel::new(commitment_scheme),
        }
    }
}

impl<CS: CommitmentScheme> TransactionModel<CS> for HybridModel<CS> {
    type Transaction = HybridTransaction<CS>;
    type Proof = HybridProof<CS>;
    
    fn validate(&self, tx: &Self::Transaction, commitment: &CS::Commitment) -> bool {
        // Delegate to the appropriate model based on transaction type
        match tx {
            HybridTransaction::UTXO(utxo_tx) => self.utxo_model.validate(utxo_tx, commitment),
            HybridTransaction::Account(account_tx) => self.account_model.validate(account_tx, commitment),
        }
    }
    
    fn apply(&self, tx: &Self::Transaction, state: &mut dyn StateManager<CS>) -> Result<(), String> {
        // Delegate to the appropriate model based on transaction type
        match tx {
            HybridTransaction::UTXO(utxo_tx) => self.utxo_model.apply(utxo_tx, state),
            HybridTransaction::Account(account_tx) => self.account_model.apply(account_tx, state),
        }
    }
}
EOF

# Validator Implementation
cat > crates/validator/Cargo.toml << 'EOF'
[package]
name = "depin-sdk-validator"
version = "0.1.0"
edition = "2021"
description = "Validator implementation with container architecture for the DePIN SDK"
license = "MIT OR Apache-2.0"

[dependencies]
depin-sdk-core = { path = "../core" }
log = { workspace = true }
serde = { workspace = true }
thiserror = { workspace = true }
bytes = { workspace = true }
anyhow = { workspace = true }
tokio = { version = "1.28", features = ["full"] }
toml = "0.7"

[[bin]]
name = "depin-sdk-validator"
path = "src/bin/validator.rs"

[[bin]]
name = "depin-sdk-validator-hybrid"
path = "src/bin/validator_hybrid.rs"
EOF

mkdir -p crates/validator/src/{common,standard,hybrid}/tests
mkdir -p crates/validator/src/bin

cat > crates/validator/src/lib.rs << 'EOF'
//! # DePIN SDK Validator
//!
//! Validator implementation with container architecture for the DePIN SDK.

pub mod common;
pub mod standard;
pub mod hybrid;

use std::error::Error;
use depin_sdk_core::validator::ValidatorModel;
EOF

# Common Validator Components
cat > crates/validator/src/common/mod.rs << 'EOF'
//! Common validator components shared by all types

mod guardian;
mod security;

#[cfg(test)]
mod tests;

pub use guardian::*;
pub use security::*;
EOF

cat > crates/validator/src/common/guardian.rs << 'EOF'
//! Implementation of the guardian container

use std::path::Path;
use std::error::Error;
use std::sync::{Arc, Mutex};

/// Guardian container for security, boot process, and attestation
pub struct GuardianContainer {
    /// Configuration path
    config_path: String,
    /// Boot status
    boot_status: Arc<Mutex<BootStatus>>,
}

/// Boot status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootStatus {
    /// Not started
    NotStarted,
    /// In progress
    InProgress,
    /// Completed successfully
    Completed,
    /// Failed
    Failed,
}

impl GuardianContainer {
    /// Create a new guardian container
    pub fn new<P: AsRef<Path>>(config_path: P) -> Self {
        Self {
            config_path: config_path.as_ref().to_string_lossy().to_string(),
            boot_status: Arc::new(Mutex::new(BootStatus::NotStarted)),
        }
    }
    
    /// Start the boot process
    pub fn start_boot(&self) -> Result<(), Box<dyn Error>> {
        let mut status = self.boot_status.lock().unwrap();
        *status = BootStatus::InProgress;
        
        // Perform boot process (simplified for initial setup)
        println!("Guardian container starting boot process...");
        
        // In a real implementation, we would:
        // 1. Verify hardware attestation
        // 2. Check secure boot status
        // 3. Initialize security boundaries
        
        *status = BootStatus::Completed;
        println!("Guardian container boot process completed.");
        
        Ok(())
    }
    
    /// Get the current boot status
    pub fn boot_status(&self) -> BootStatus {
        *self.boot_status.lock().unwrap()
    }
    
    /// Verify attestation
    pub fn verify_attestation(&self) -> Result<bool, Box<dyn Error>> {
        // Simplified attestation verification for initial setup
        // In a real implementation, we would verify hardware attestation
        Ok(true)
    }
}
EOF

cat > crates/validator/src/common/security.rs << 'EOF'
//! Implementation of security boundaries between containers

use std::error::Error;

/// Security channel for communication between containers
pub struct SecurityChannel {
    /// Source container ID
    pub source: String,
    /// Destination container ID
    pub destination: String,
    /// Channel ID
    pub channel_id: String,
}

impl SecurityChannel {
    /// Create a new security channel
    pub fn new(source: &str, destination: &str) -> Self {
        let channel_id = format!("{}:{}", source, destination);
        
        Self {
            source: source.to_string(),
            destination: destination.to_string(),
            channel_id,
        }
    }
    
    /// Establish the security channel
    pub fn establish(&self) -> Result<(), Box<dyn Error>> {
        // Simplified channel establishment for initial setup
        // In a real implementation, we would:
        // 1. Perform mutual authentication
        // 2. Establish encrypted channel
        // 3. Set up access controls
        
        println!("Establishing security channel: {}", self.channel_id);
        
        Ok(())
    }
    
    /// Send data through the security channel
    pub fn send(&self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        // Simplified sending for initial setup
        println!("Sending {} bytes through channel {}", data.len(), self.channel_id);
        
        Ok(())
    }
    
    /// Receive data from the security channel
    pub fn receive(&self, max_size: usize) -> Result<Vec<u8>, Box<dyn Error>> {
        // Simplified receiving for initial setup
        println!("Receiving up to {} bytes from channel {}", max_size, self.channel_id);
        
        // Return empty data for now
        Ok(Vec::new())
    }
}
EOF

# Standard Validator
cat > crates/validator/src/standard/mod.rs << 'EOF'
//! Standard validator implementation (3 containers)

mod orchestration;
mod workload;

#[cfg(test)]
mod tests;

pub use orchestration::*;
pub use workload::*;

use std::error::Error;
use std::path::Path;
use crate::common::{GuardianContainer, SecurityChannel};

/// Standard validator with 3 containers
pub struct StandardValidator {
    /// Guardian container
    pub guardian: GuardianContainer,
    /// Orchestration container
    pub orchestration: OrchestrationContainer,
    /// Workload container
    pub workload: WorkloadContainer,
    /// Security channels between containers
    security_channels: Vec<SecurityChannel>,
}

impl StandardValidator {
    /// Create a new standard validator
    pub fn new<P: AsRef<Path>>(config_dir: P) -> Result<Self, Box<dyn Error>> {
        let config_dir = config_dir.as_ref();
        
        // Create containers
        let guardian = GuardianContainer::new(config_dir.join("guardian.toml"));
        let orchestration = OrchestrationContainer::new(config_dir.join("orchestration.toml"));
        let workload = WorkloadContainer::new(config_dir.join("workload.toml"));
        
        // Create security channels
        let mut security_channels = Vec::new();
        
        // Guardian to Orchestration
        let channel_g_o = SecurityChannel::new("guardian", "orchestration");
        channel_g_o.establish()?;
        security_channels.push(channel_g_o);
        
        // Orchestration to Workload
        let channel_o_w = SecurityChannel::new("orchestration", "workload");
        channel_o_w.establish()?;
        security_channels.push(channel_o_w);
        
        Ok(Self {
            guardian,
            orchestration,
            workload,
            security_channels,
        })
    }
    
    /// Start the validator
    pub fn start(&self) -> Result<(), Box<dyn Error>> {
        // Start Guardian first
        self.guardian.start_boot()?;
        
        // Start Orchestration
        self.orchestration.start()?;
        
        // Start Workload
        self.workload.start()?;
        
        println!("Standard validator started successfully");
        
        Ok(())
    }
    
    /// Stop the validator
    pub fn stop(&self) -> Result<(), Box<dyn Error>> {
        // Stop in reverse order
        self.workload.stop()?;
        self.orchestration.stop()?;
        
        println!("Standard validator stopped successfully");
        
        Ok(())
    }
}
EOF

cat > crates/validator/src/standard/orchestration.rs << 'EOF'
//! Implementation of orchestration container

use std::path::Path;
use std::error::Error;
use std::sync::{Arc, Mutex};

/// Orchestration container for node functions and consensus
pub struct OrchestrationContainer {
    /// Configuration path
    config_path: String,
    /// Running status
    running: Arc<Mutex<bool>>,
}

impl OrchestrationContainer {
    /// Create a new orchestration container
    pub fn new<P: AsRef<Path>>(config_path: P) -> Self {
        Self {
            config_path: config_path.as_ref().to_string_lossy().to_string(),
            running: Arc::new(Mutex::new(false)),
        }
    }
    
    /// Start the orchestration container
    pub fn start(&self) -> Result<(), Box<dyn Error>> {
        let mut running = self.running.lock().unwrap();
        *running = true;
        
        println!("Orchestration container starting...");
        
        // In a real implementation, we would:
        // 1. Initialize consensus mechanism
        // 2. Connect to peer network
        // 3. Start block processing
        
        println!("Orchestration container started successfully");
        
        Ok(())
    }
    
    /// Stop the orchestration container
    pub fn stop(&self) -> Result<(), Box<dyn Error>> {
        let mut running = self.running.lock().unwrap();
        *running = false;
        
        println!("Orchestration container stopping...");
        
        // In a real implementation, we would:
        // 1. Gracefully disconnect from network
        // 2. Stop consensus mechanism
        // 3. Save state
        
        println!("Orchestration container stopped successfully");
        
        Ok(())
    }
    
    /// Check if the container is running
    pub fn is_running(&self) -> bool {
        *self.running.lock().unwrap()
    }
}
EOF

cat > crates/validator/src/standard/workload.rs << 'EOF'
//! Implementation of workload container

use std::path::Path;
use std::error::Error;
use std::sync::{Arc, Mutex};

/// Workload container for resource provisioning and execution
pub struct WorkloadContainer {
    /// Configuration path
    config_path: String,
    /// Running status
    running: Arc<Mutex<bool>>,
}

impl WorkloadContainer {
    /// Create a new workload container
    pub fn new<P: AsRef<Path>>(config_path: P) -> Self {
        Self {
            config_path: config_path.as_ref().to_string_lossy().to_string(),
            running: Arc::new(Mutex::new(false)),
        }
    }
    
    /// Start the workload container
    pub fn start(&self) -> Result<(), Box<dyn Error>> {
        let mut running = self.running.lock().unwrap();
        *running = true;
        
        println!("Workload container starting...");
        
        // In a real implementation, we would:
        // 1. Initialize execution environment
        // 2. Allocate resources
        // 3. Start transaction processing
        
        println!("Workload container started successfully");
        
        Ok(())
    }
    
    /// Stop the workload container
    pub fn stop(&self) -> Result<(), Box<dyn Error>> {
        let mut running = self.running.lock().unwrap();
        *running = false;
        
        println!("Workload container stopping...");
        
        // In a real implementation, we would:
        // 1. Gracefully stop transaction processing
        // 2. Release resources
        // 3. Save state
        
        println!("Workload container stopped successfully");
        
        Ok(())
    }
    
    /// Execute a transaction
    pub fn execute_transaction(&self, tx_data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        if !self.is_running() {
            return Err("Workload container is not running".into());
        }
        
        // Simplified transaction execution for initial setup
        println!("Executing transaction of {} bytes", tx_data.len());
        
        // In a real implementation, we would:
        // 1. Parse the transaction
        // 2. Verify it against the state
        // 3. Apply it to the state
        // 4. Return the result
        
        // Return a dummy result for now
        Ok(vec![1, 2, 3, 4])
    }
    
    /// Check if the container is running
    pub fn is_running(&self) -> bool {
        *self.running.lock().unwrap()
    }
}
EOF

# Hybrid Validator (Additional Containers)
cat > crates/validator/src/hybrid/mod.rs << 'EOF'
//! Hybrid validator implementation (5 containers)

mod interface;
mod api;

#[cfg(test)]
mod tests;

pub use interface::*;
pub use api::*;

use std::error::Error;
use std::path::Path;
use crate::common::{GuardianContainer, SecurityChannel};
use crate::standard::{OrchestrationContainer, WorkloadContainer};

/// Hybrid validator with 5 containers
pub struct HybridValidator {
    /// Guardian container
    pub guardian: GuardianContainer,
    /// Orchestration container
    pub orchestration: OrchestrationContainer,
    /// Workload container
    pub workload: WorkloadContainer,
    /// Interface container
    pub interface: InterfaceContainer,
    /// API container
    pub api: ApiContainer,
    /// Security channels between containers
    security_channels: Vec<SecurityChannel>,
}

impl HybridValidator {
    /// Create a new hybrid validator
    pub fn new<P: AsRef<Path>>(config_dir: P) -> Result<Self, Box<dyn Error>> {
        let config_dir = config_dir.as_ref();
        
        // Create containers
        let guardian = GuardianContainer::new(config_dir.join("guardian.toml"));
        let orchestration = OrchestrationContainer::new(config_dir.join("orchestration.toml"));
        let workload = WorkloadContainer::new(config_dir.join("workload.toml"));
        let interface = InterfaceContainer::new(config_dir.join("interface.toml"));
        let api = ApiContainer::new(config_dir.join("api.toml"));
        
        // Create security channels
        let mut security_channels = Vec::new();
        
        // Guardian to Orchestration
        let channel_g_o = SecurityChannel::new("guardian", "orchestration");
        channel_g_o.establish()?;
        security_channels.push(channel_g_o);
        
        // Orchestration to Workload
        let channel_o_w = SecurityChannel::new("orchestration", "workload");
        channel_o_w.establish()?;
        security_channels.push(channel_o_w);
        
        // Orchestration to Interface
        let channel_o_i = SecurityChannel::new("orchestration", "interface");
        channel_o_i.establish()?;
        security_channels.push(channel_o_i);
        
        // Interface to API
        let channel_i_a = SecurityChannel::new("interface", "api");
        channel_i_a.establish()?;
        security_channels.push(channel_i_a);
        
        Ok(Self {
            guardian,
            orchestration,
            workload,
            interface,
            api,
            security_channels,
        })
    }
    
    /// Start the validator
    pub fn start(&self) -> Result<(), Box<dyn Error>> {
        // Start Guardian first
        self.guardian.start_boot()?;
        
        // Start Orchestration
        self.orchestration.start()?;
        
        // Start Workload
        self.workload.start()?;
        
        // Start Interface
        self.interface.start()?;
        
        // Start API
        self.api.start()?;
        
        println!("Hybrid validator started successfully");
        
        Ok(())
    }
    
    /// Stop the validator
    pub fn stop(&self) -> Result<(), Box<dyn Error>> {
        // Stop in reverse order
        self.api.stop()?;
        self.interface.stop()?;
        self.workload.stop()?;
        self.orchestration.stop()?;
        
        println!("Hybrid validator stopped successfully");
        
        Ok(())
    }
}
EOF

cat > crates/validator/src/hybrid/interface.rs << 'EOF'
//! Implementation of interface container

use std::path::Path;
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::net::SocketAddr;

/// Interface container for connection handling and protocol routing
pub struct InterfaceContainer {
    /// Configuration path
    config_path: String,
    /// Running status
    running: Arc<Mutex<bool>>,
}

impl InterfaceContainer {
    /// Create a new interface container
    pub fn new<P: AsRef<Path>>(config_path: P) -> Self {
        Self {
            config_path: config_path.as_ref().to_string_lossy().to_string(),
            running: Arc::new(Mutex::new(false)),
        }
    }
    
    /// Start the interface container
    pub fn start(&self) -> Result<(), Box<dyn Error>> {
        let mut running = self.running.lock().unwrap();
        *running = true;
        
        println!("Interface container starting...");
        
        // In a real implementation, we would:
        // 1. Start listening for connections
        // 2. Initialize protocol handlers
        // 3. Set up routing logic
        
        println!("Interface container started successfully");
        
        Ok(())
    }
    
    /// Stop the interface container
    pub fn stop(&self) -> Result<(), Box<dyn Error>> {
        let mut running = self.running.lock().unwrap();
        *running = false;
        
        println!("Interface container stopping...");
        
        // In a real implementation, we would:
        // 1. Close all connections
        // 2. Stop listeners
        // 3. Clean up resources
        
        println!("Interface container stopped successfully");
        
        Ok(())
    }
    
    /// Handle a client connection
    pub fn handle_connection(&self, addr: SocketAddr, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        if !self.is_running() {
            return Err("Interface container is not running".into());
        }
        
        // Simplified connection handling for initial setup
        println!("Handling connection from {}, {} bytes", addr, data.len());
        
        // In a real implementation, we would:
        // 1. Identify the protocol
        // 2. Route to the appropriate handler
        // 3. Process the request
        // 4. Return the response
        
        // Return a dummy response for now
        Ok(vec![5, 6, 7, 8])
    }
    
    /// Check if the container is running
    pub fn is_running(&self) -> bool {
        *self.running.lock().unwrap()
    }
}
EOF

cat > crates/validator/src/hybrid/api.rs << 'EOF'
//! Implementation of API container

use std::path::Path;
use std::error::Error;
use std::sync::{Arc, Mutex};

/// API container for API implementation and state queries
pub struct ApiContainer {
    /// Configuration path
    config_path: String,
    /// Running status
    running: Arc<Mutex<bool>>,
}

impl ApiContainer {
    /// Create a new API container
    pub fn new<P: AsRef<Path>>(config_path: P) -> Self {
        Self {
            config_path: config_path.as_ref().to_string_lossy().to_string(),
            running: Arc::new(Mutex::new(false)),
        }
    }
    
    /// Start the API container
    pub fn start(&self) -> Result<(), Box<dyn Error>> {
        let mut running = self.running.lock().unwrap();
        *running = true;
        
        println!("API container starting...");
        
        // In a real implementation, we would:
        // 1. Initialize API endpoints
        // 2. Connect to state storage
        // 3. Start serving requests
        
        println!("API container started successfully");
        
        Ok(())
    }
    
    /// Stop the API container
    pub fn stop(&self) -> Result<(), Box<dyn Error>> {
        let mut running = self.running.lock().unwrap();
        *running = false;
        
        println!("API container stopping...");
        
        // In a real implementation, we would:
        // 1. Gracefully shutdown API server
        // 2. Close state connections
        // 3. Clean up resources
        
        println!("API container stopped successfully");
        
        Ok(())
    }
    
    /// Handle an API request
    pub fn handle_request(&self, endpoint: &str, params: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        if !self.is_running() {
            return Err("API container is not running".into());
        }
        
        // Simplified API handling for initial setup
        println!("Handling API request to endpoint {}, {} bytes", endpoint, params.len());
        
        // In a real implementation, we would:
        // 1. Parse the request parameters
        // 2. Execute the appropriate API function
        // 3. Format and return the response
        
        // Return a dummy response for now
        Ok(vec![9, 10, 11, 12])
    }
    
    /// Check if the container is running
    pub fn is_running(&self) -> bool {
        *self.running.lock().unwrap()
    }
}
EOF

# Create validator binaries
cat > crates/validator/src/bin/validator.rs << 'EOF'
//! Standard validator binary

use std::env;
use std::path::Path;
use depin_sdk_validator::standard::StandardValidator;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    let container_type = if args.len() > 1 { &args[1] } else { "all" };
    
    // Default config directory is ./config
    let config_dir = env::var("CONFIG_DIR").unwrap_or_else(|_| "./config".to_string());
    
    println!("Starting DePIN SDK Standard Validator");
    println!("Container type: {}", container_type);
    println!("Config directory: {}", config_dir);
    
    match container_type {
        "guardian" => {
            // Start only the guardian container
            let path = Path::new(&config_dir);
            let guardian = depin_sdk_validator::common::GuardianContainer::new(path.join("guardian.toml"));
            guardian.start_boot()?;
            
            // Keep the process running
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        },
        "orchestration" => {
            // Start only the orchestration container
            let path = Path::new(&config_dir);
            let orchestration = depin_sdk_validator::standard::OrchestrationContainer::new(path.join("orchestration.toml"));
            orchestration.start()?;
            
            // Keep the process running
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        },
        "workload" => {
            // Start only the workload container
            let path = Path::new(&config_dir);
            let workload = depin_sdk_validator::standard::WorkloadContainer::new(path.join("workload.toml"));
            workload.start()?;
            
            // Keep the process running
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        },
        "all" | _ => {
            // Start the full validator
            let path = Path::new(&config_dir);
            let validator = StandardValidator::new(path)?;
            validator.start()?;
            
            // Keep the process running
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        },
    }
}
EOF

cat > crates/validator/src/bin/validator_hybrid.rs << 'EOF'
//! Hybrid validator binary

use std::env;
use std::path::Path;
use depin_sdk_validator::hybrid::HybridValidator;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    let container_type = if args.len() > 1 { &args[1] } else { "all" };
    
    // Default config directory is ./config
    let config_dir = env::var("CONFIG_DIR").unwrap_or_else(|_| "./config".to_string());
    
    println!("Starting DePIN SDK Hybrid Validator");
    println!("Container type: {}", container_type);
    println!("Config directory: {}", config_dir);
    
    match container_type {
        "guardian" => {
            // Start only the guardian container
            let path = Path::new(&config_dir);
            let guardian = depin_sdk_validator::common::GuardianContainer::new(path.join("guardian.toml"));
            guardian.start_boot()?;
            
            // Keep the process running
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        },
        "orchestration" => {
            // Start only the orchestration container
            let path = Path::new(&config_dir);
            let orchestration = depin_sdk_validator::standard::OrchestrationContainer::new(path.join("orchestration.toml"));
            orchestration.start()?;
            
            // Keep the process running
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        },
        "workload" => {
            // Start only the workload container
            let path = Path::new(&config_dir);
            let workload = depin_sdk_validator::standard::WorkloadContainer::new(path.join("workload.toml"));
            workload.start()?;
            
            // Keep the process running
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        },
        "interface" => {
            // Start only the interface container
            let path = Path::new(&config_dir);
            let interface = depin_sdk_validator::hybrid::InterfaceContainer::new(path.join("interface.toml"));
            interface.start()?;
            
            // Keep the process running
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        },
        "api" => {
            // Start only the API container
            let path = Path::new(&config_dir);
            let api = depin_sdk_validator::hybrid::ApiContainer::new(path.join("api.toml"));
            api.start()?;
            
            // Keep the process running
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        },
        "all" | _ => {
            // Start the full validator
            let path = Path::new(&config_dir);
            let validator = HybridValidator::new(path)?;
            validator.start()?;
            
            // Keep the process running
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        },
    }
}
EOF

# Add transaction model implementation to core crate
cat > crates/core/src/transaction/mod.rs << 'EOF'
//! Transaction model trait definitions

mod model;
mod utxo;
mod account;

#[cfg(test)]
mod tests;

pub use model::*;
pub use utxo::*;
pub use account::*;
EOF

cat > crates/core/src/transaction/model.rs << 'EOF'
//! Definition of the TransactionModel trait

use crate::commitment::CommitmentScheme;
use crate::state::StateManager;

/// Error type for transaction operations
#[derive(Debug)]
pub enum Error {
    /// Invalid transaction
    Invalid(String),
    /// Insufficient funds
    InsufficientFunds,
    /// Nonce mismatch
    NonceMismatch,
    /// Invalid signature
    InvalidSignature,
    /// Other error
    Other(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Invalid(msg) => write!(f, "Invalid transaction: {}", msg),
            Error::InsufficientFunds => write!(f, "Insufficient funds"),
            Error::NonceMismatch => write!(f, "Nonce mismatch"),
            Error::InvalidSignature => write!(f, "Invalid signature"),
            Error::Other(msg) => write!(f, "Other error: {}", msg),
        }
    }
}

impl std::error::Error for Error {}

/// Transaction model trait
pub trait TransactionModel<CS: CommitmentScheme> {
    /// Transaction type
    type Transaction;
    
    /// Proof type
    type Proof;
    
    /// Validate a transaction against a state commitment
    fn validate(&self, tx: &Self::Transaction, commitment: &CS::Commitment) -> bool;
    
    /// Apply a transaction to the state
    fn apply(&self, tx: &Self::Transaction, state: &mut dyn StateManager<CS>) -> Result<(), String>;
}
EOF

cat > crates/core/src/transaction/utxo.rs << 'EOF'
//! UTXO-specific trait definitions

/// UTXO transaction traits
pub trait UTXOTransaction {
    /// Get transaction ID
    fn txid(&self) -> &[u8];
    
    /// Get inputs
    fn inputs(&self) -> &[Self::Input];
    
    /// Get outputs
    fn outputs(&self) -> &[Self::Output];
    
    /// Input type
    type Input;
    
    /// Output type
    type Output;
}
EOF

cat > crates/core/src/transaction/account.rs << 'EOF'
//! Account-specific trait definitions

/// Account transaction traits
pub trait AccountTransaction {
    /// Get transaction ID
    fn txid(&self) -> &[u8];
    
    /// Get sender
    fn sender(&self) -> &[u8];
    
    /// Get receiver
    fn receiver(&self) -> &[u8];
    
    /// Get value
    fn value(&self) -> u64;
    
    /// Get nonce
    fn nonce(&self) -> u64;
    
    /// Get signature
    fn signature(&self) -> &[u8];
}
EOF

# Core validator traits
cat > crates/core/src/validator/mod.rs << 'EOF'
//! Validator architecture trait definitions

mod container;
mod types;

#[cfg(test)]
mod tests;

pub use container::*;
pub use types::*;
EOF

cat > crates/core/src/validator/container.rs << 'EOF'
//! Container interface definitions

/// Container interface
pub trait Container {
    /// Start the container
    fn start(&self) -> Result<(), String>;
    
    /// Stop the container
    fn stop(&self) -> Result<(), String>;
    
    /// Check if the container is running
    fn is_running(&self) -> bool;
    
    /// Get the container ID
    fn id(&self) -> &str;
}

/// Guardian container interface
pub trait GuardianContainer: Container {
    /// Start the boot process
    fn start_boot(&self) -> Result<(), String>;
    
    /// Verify attestation
    fn verify_attestation(&self) -> Result<bool, String>;
}
EOF

cat > crates/core/src/validator/types.rs << 'EOF'
//! Validator type definitions

/// Validator model trait
pub trait ValidatorModel {
    /// Start the validator
    fn start(&self) -> Result<(), String>;
    
    /// Stop the validator
    fn stop(&self) -> Result<(), String>;
    
    /// Check if the validator is running
    fn is_running(&self) -> bool;
    
    /// Get the validator type
    fn validator_type(&self) -> ValidatorType;
}

/// Validator types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorType {
    /// Standard validator (3 containers)
    Standard,
    /// Hybrid validator (5 containers)
    Hybrid,
}
EOF

echo "Transaction models and validator components setup completed!"