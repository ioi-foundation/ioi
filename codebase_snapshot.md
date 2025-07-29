# Codebase Snapshot: crates
Created: Tue Jul 29 02:25:53 AM UTC 2025
Target: /workspaces/depin-sdk/crates
Line threshold for included files: 1500

## Summary Statistics

* Total files: 152
* Total directories: 117

### Directory: /workspaces/depin-sdk/crates

#### Directory: chain

##### Directory: chain/src

###### Directory: chain/src/app

####### File: chain/src/app/mod.rs
####*Size: 12K, Lines: 225, Type: ASCII text*

```rust
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
}```

###### Directory: chain/src/bin

####### File: chain/src/bin/mvsc.rs
####*Size: 8.0K, Lines: 104, Type: C source, ASCII text*

```rust
// Path: crates/chain/src/bin/mvsc.rs

//! # Minimum Viable Single-Node Chain (MVSC)
//!
//! This binary acts as the composition root for the validator node. It initializes
//! all core components (chain logic, state, containers) and wires them together.

use anyhow::anyhow;
use clap::Parser;
use depin_sdk_chain::ChainLogic;
use depin_sdk_commitment_schemes::hash::HashCommitmentScheme;
// FIX: Import the Container trait to bring start() and stop() methods into scope.
use depin_sdk_core::app::ChainError;
use depin_sdk_core::Container;
use depin_sdk_core::config::WorkloadConfig;
use depin_sdk_core::validator::WorkloadContainer;
use depin_sdk_state_trees::file::FileStateTree;
use depin_sdk_transaction_models::utxo::UTXOModel;
// FIXME: The following components must be made public in the `depin-sdk-validator` crate
// for this binary to compile. This requires editing `crates/validator/src/common/mod.rs`
// and `crates/validator/src/standard/mod.rs`.
use depin_sdk_validator::common::GuardianContainer;
use depin_sdk_validator::standard::OrchestrationContainer;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Parser, Debug)]
#[clap(name = "mvsc", about = "A minimum viable sovereign chain node.")]
struct Opts {
    #[clap(long, default_value = "state.json")]
    state_file: String,
    #[clap(long, default_value = "./config")]
    config_dir: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::builder().filter_level(log::LevelFilter::Info).init();
    let opts = Opts::parse();
    log::info!("Initializing DePIN SDK Node...");

    // --- 1. Initialize Independent Components ---
    let commitment_scheme = HashCommitmentScheme::new();
    let transaction_model = UTXOModel::new(commitment_scheme.clone());
    let state_tree = FileStateTree::new(&opts.state_file, commitment_scheme.clone());
    let workload_config = WorkloadConfig { enabled_vms: vec!["WASM".to_string()] };

    // --- 2. Build the Validator Containers ---
    let workload_container = Arc::new(WorkloadContainer::new(workload_config, state_tree));

    // FIX: Correctly construct PathBuf from String and borrow it.
    let config_path = PathBuf::from(&opts.config_dir);
    let orchestration_container = Arc::new(
        OrchestrationContainer::<
            HashCommitmentScheme,
            UTXOModel<HashCommitmentScheme>,
            FileStateTree<HashCommitmentScheme>,
        >::new(&config_path.join("orchestration.toml"))
        .await?,
    );
    let guardian_container = GuardianContainer::new(
        &config_path.join("guardian.toml"),
    )?;

    // --- 3. Create and Initialize the SovereignChain Logic ---
    // FIX: Move `transaction_model` instead of cloning it, as it's no longer needed here.
    let mut chain_logic = ChainLogic::new(
        commitment_scheme.clone(),
        transaction_model,
        "mvsc-chain-1",
        vec![],
    );
    // [MODIFIED] Load status from state or initialize it.
    chain_logic
        .load_or_initialize_status(&workload_container)
        .await
        .map_err(|e| anyhow!("Failed to load or initialize chain status: {:?}", e))?;
    let chain_ref: Arc<Mutex<ChainLogic<HashCommitmentScheme, UTXOModel<HashCommitmentScheme>>>> = Arc::new(Mutex::new(chain_logic));

    // --- 4. Wire Up the Components (Inversion of Control) ---
    orchestration_container.set_chain_and_workload_ref(
        chain_ref.clone(),
        workload_container.clone(),
    );

    // --- 5. Start the Validator Services ---
    // FIX: Add .await to all async start/stop calls.
    guardian_container.start().await.map_err(|e| anyhow!(e))?;
    orchestration_container.start().await.map_err(|e| anyhow!(e))?;
    workload_container.start().await.map_err(|e| anyhow!(e))?;

    log::info!("Node successfully started. Running indefinitely...");

    // 6. Keep the main thread alive.
    tokio::signal::ctrl_c().await?;

    log::info!("Shutdown signal received. Stopping node...");
    orchestration_container.stop().await.map_err(|e| anyhow!(e))?;
    workload_container.stop().await.map_err(|e| anyhow!(e))?;
    guardian_container.stop().await.map_err(|e| anyhow!(e))?;
    log::info!("Node stopped gracefully.");

    Ok(())
}```

###### Directory: chain/src/traits

####### File: chain/src/traits/mod.rs
####*Size: 4.0K, Lines: 56, Type: ASCII text*

```rust
// Path: crates/chain/src/traits.rs

//! This module defines the public traits that describe the core logic of a sovereign chain.

use depin_sdk_core::app::{Block, ChainError, ChainStatus};
use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_core::state::{StateManager, StateTree};
use depin_sdk_core::transaction::TransactionModel;
use depin_sdk_core::validator::WorkloadContainer;

/// A trait that defines the logic and capabilities of a sovereign chain state machine.
// FIX: The `Sized` bound is removed, making this trait object-safe (`dyn`).
pub trait SovereignChain<CS, TM>
where
    CS: CommitmentScheme,
    TM: TransactionModel<CommitmentScheme = CS>,
{
    // FIX: `new` is removed from the trait. Construction is now an inherent method on the impl struct.

    // Accessor methods remain.
    fn status(&self) -> &ChainStatus;
    fn transaction_model(&self) -> &TM;

    fn process_transaction<ST>(
        &mut self,
        tx: &TM::Transaction,
        workload: &WorkloadContainer<ST>,
    ) -> Result<(), ChainError>
    where
        ST: StateTree<Commitment = CS::Commitment, Proof = CS::Proof>
            + StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
            + Send + Sync + 'static;

    fn process_block<ST>(
        &mut self,
        block: Block<TM::Transaction>,
        workload: &WorkloadContainer<ST>,
    ) -> Result<(), ChainError>
    where
        ST: StateTree<Commitment = CS::Commitment, Proof = CS::Proof>
            + StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
            + Send + Sync + 'static,
        CS::Commitment: Send + Sync;

    fn create_block<ST>(
        &self,
        transactions: Vec<TM::Transaction>,
        workload: &WorkloadContainer<ST>,
    ) -> Block<TM::Transaction>
    where
        ST: StateTree<Commitment = CS::Commitment, Proof = CS::Proof>
            + StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
            + Send + Sync + 'static,
        CS::Commitment: Send + Sync;
    
    fn get_block(&self, height: u64) -> Option<&Block<TM::Transaction>>;
}```

###### Directory: chain/src/upgrade_manager

####### File: chain/src/upgrade_manager/mod.rs
####*Size: 8.0K, Lines: 193, Type: ASCII text*

```rust
use depin_sdk_core::error::CoreError;
use depin_sdk_core::services::{ServiceType, UpgradableService};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

/// Manages runtime upgrades of blockchain services
pub struct ModuleUpgradeManager {
    /// Holds the currently active, concrete service implementations
    active_services: HashMap<ServiceType, Arc<dyn UpgradableService>>,
    /// Tracks upgrade history for each service type
    upgrade_history: HashMap<ServiceType, Vec<u64>>,
    /// Scheduled upgrades by block height
    scheduled_upgrades: HashMap<u64, Vec<(ServiceType, Vec<u8>)>>,
}

// FIX: Manually implement Debug because Arc<dyn UpgradableService> does not implement Debug.
// This implementation prints the service types instead of the service objects themselves.
impl fmt::Debug for ModuleUpgradeManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ModuleUpgradeManager")
            .field("active_services", &self.active_services.keys())
            .field("upgrade_history", &self.upgrade_history)
            .field("scheduled_upgrades", &self.scheduled_upgrades)
            .finish()
    }
}

impl ModuleUpgradeManager {
    /// Create a new module upgrade manager
    pub fn new() -> Self {
        Self {
            active_services: HashMap::new(),
            upgrade_history: HashMap::new(),
            scheduled_upgrades: HashMap::new(),
        }
    }

    /// Register a service with the manager
    pub fn register_service(&mut self, service: Arc<dyn UpgradableService>) {
        let service_type = service.service_type();
        self.active_services.insert(service_type.clone(), service);

        // Initialize upgrade history if not present
        self.upgrade_history
            .entry(service_type)
            .or_insert_with(Vec::new);
    }

    /// Get a service by type
    pub fn get_service(&self, service_type: &ServiceType) -> Option<Arc<dyn UpgradableService>> {
        self.active_services.get(service_type).cloned()
    }

    /// Schedule an upgrade for a specific block height
    pub fn schedule_upgrade(
        &mut self,
        service_type: ServiceType,
        upgrade_data: Vec<u8>,
        activation_height: u64,
    ) -> Result<(), CoreError> {
        self.scheduled_upgrades
            .entry(activation_height)
            .or_insert_with(Vec::new)
            .push((service_type, upgrade_data));

        Ok(())
    }

    /// Apply any upgrades scheduled for the given block height
    pub fn apply_upgrades_at_height(&mut self, height: u64) -> Result<usize, CoreError> {
        let upgrades = match self.scheduled_upgrades.remove(&height) {
            Some(upgrades) => upgrades,
            None => return Ok(0),
        };

        let mut applied_count = 0;

        for (service_type, upgrade_data) in upgrades {
            match self.execute_upgrade(&service_type, &upgrade_data) {
                Ok(()) => {
                    applied_count += 1;
                    // Record the upgrade in history
                    if let Some(history) = self.upgrade_history.get_mut(&service_type) {
                        history.push(height);
                    }
                }
                Err(e) => {
                    // Log error but continue with other upgrades
                    eprintln!("Failed to upgrade service {:?}: {}", service_type, e);
                }
            }
        }

        Ok(applied_count)
    }

    /// Execute an upgrade for a specific service
    pub fn execute_upgrade(
        &mut self,
        service_type: &ServiceType,
        new_module_wasm: &[u8],
    ) -> Result<(), CoreError> {
        let active_service = self
            .active_services
            .get_mut(service_type)
            .ok_or_else(|| CoreError::ServiceNotFound(format!("{:?}", service_type)))?;

        // 1. Prepare: Get the state snapshot from the current service
        let _snapshot = active_service
            .prepare_upgrade(new_module_wasm)
            .map_err(|e| CoreError::UpgradeError(e.to_string()))?;

        // 2. TODO: Instantiate new service from WASM (or other format)
        // This would require a proper WASM loading mechanism
        // For now, we'll create a placeholder

        // 3. TODO: Complete the upgrade by migrating state to new service
        // new_service.complete_upgrade(&snapshot)?;

        // 4. TODO: Atomically swap the implementation
        // self.active_services.insert(service_type.clone(), Arc::new(new_service));

        // For now, just return success as this is a stub implementation
        Ok(())
    }

    /// Get upgrade history for a service
    pub fn get_upgrade_history(&self, service_type: &ServiceType) -> Vec<u64> {
        self.upgrade_history
            .get(service_type)
            .cloned()
            .unwrap_or_default()
    }

    /// Check health status of all services
    pub fn check_all_health(&self) -> Vec<(ServiceType, bool)> {
        self.active_services
            .iter()
            .map(|(service_type, service)| {
                let is_healthy = match service.health_check() {
                    Ok(_) => true,
                    Err(_) => false,
                };
                (service_type.clone(), is_healthy)
            })
            .collect()
    }

    /// Start all registered services
    pub fn start_all_services(&mut self) -> Result<(), CoreError> {
        for (service_type, service) in &self.active_services {
            service.start().map_err(|e| {
                CoreError::Custom(format!(
                    "Failed to start service {:?}: {}",
                    service_type, e
                ))
            })?;
        }
        Ok(())
    }

    /// Stop all registered services
    pub fn stop_all_services(&mut self) -> Result<(), CoreError> {
        for (service_type, service) in &self.active_services {
            service.stop().map_err(|e| {
                CoreError::Custom(format!("Failed to stop service {:?}: {}", service_type, e))
            })?;
        }
        Ok(())
    }

    /// Reset the manager to initial state
    pub fn reset(&mut self) -> Result<(), CoreError> {
        // Stop all services first
        self.stop_all_services()?;

        // Clear all state
        self.active_services.clear();
        self.upgrade_history.clear();
        self.scheduled_upgrades.clear();

        Ok(())
    }
}

/// Helper function to load a service from WASM bytes
/// TODO: Implement actual WASM loading logic
#[allow(dead_code)]
fn load_service_from_wasm(_wasm_bytes: &[u8]) -> Result<Box<dyn UpgradableService>, CoreError> {
    Err(CoreError::Custom(
        "WASM loading not implemented yet".to_string(),
    ))
}```

###### File: chain/src/lib.rs
###*Size: 4.0K, Lines: 10, Type: ASCII text*

```rust
//! # DePIN SDK Chain
//!
//! This crate provides the implementation logic for the `SovereignAppChain` state machine.

mod app;
pub mod upgrade_manager;
pub mod traits;

// FIX: Corrected the path to ChainLogic, removing the non-existent 'logic' module.
pub use app::ChainLogic;
pub use upgrade_manager::ModuleUpgradeManager;```

##### File: chain/Cargo.toml
##*Size: 4.0K, Lines: 45, Type: ASCII text*

```toml
[package]
name = "depin-sdk-chain"
version = "0.1.0"
edition = "2021"
description = "Chain implementation components for the DePIN SDK"
license = "MIT OR Apache-2.0"

[dependencies]
depin-sdk-consensus = { path = "../consensus" }
depin-sdk-core = { path = "../core" }
depin-sdk-commitment-schemes = { path = "../commitment_schemes" }
depin-sdk-state-trees = { path = "../state_trees" }
depin-sdk-transaction-models = { path = "../transaction_models" }
depin-sdk-validator = { path = "../validator" }
log = { workspace = true }
serde = { workspace = true, features = ["derive"] }
serde_json = { workspace = true }
thiserror = { workspace = true }
anyhow = { workspace = true }
tokio = { workspace = true, features = ["full"], optional = true }
futures = { workspace = true, optional = true }
hex = { workspace = true, optional = true }
clap = { workspace = true, features = ["derive"], optional = true }
env_logger = { workspace = true, optional = true }
libp2p = { workspace = true, optional = true }
# FIX: Add the missing async-trait dependency.
async-trait = { workspace = true }

[features]
default = []
tendermint = []
custom-consensus = []
mvsc-bin = [
    "dep:tokio",
    "dep:futures",
    "dep:hex",
    "dep:clap",
    "dep:env_logger",
    "dep:libp2p",
]

[[bin]]
name = "mvsc"
path = "src/bin/mvsc.rs"
required-features = ["mvsc-bin"]
```

#### Directory: commitment_schemes

##### Directory: commitment_schemes/src

###### Directory: commitment_schemes/src/elliptical_curve

####### File: commitment_schemes/src/elliptical_curve/mod.rs
####*Size: 16K, Lines: 381, Type: ASCII text*

```rust
//! Elliptical curve commitment implementation
// File: crates/commitment_schemes/src/elliptical_curve/mod.rs
//! Elliptical curve commitment implementation

use depin_sdk_crypto::algorithms::hash;
use dcrypt::algorithms::ec::k256::{self as k256, Point, Scalar};
use rand::{rngs::OsRng, RngCore};

use depin_sdk_core::commitment::{
    CommitmentScheme, HomomorphicCommitmentScheme, HomomorphicOperation, ProofContext,
    SchemeIdentifier, Selector,
};

/// Elliptical curve commitment scheme
#[derive(Debug, Clone)]
pub struct EllipticalCurveCommitmentScheme {
    /// Generator points
    generators: Vec<Point>,
}

/// Elliptical curve commitment
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EllipticalCurveCommitment([u8; k256::K256_POINT_COMPRESSED_SIZE]);

impl AsRef<[u8]> for EllipticalCurveCommitment {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Elliptical curve proof
#[derive(Debug, Clone)]
pub struct EllipticalCurveProof {
    /// Blinding factor
    blinding: Scalar,
    /// Position in the commitment
    position: usize,
    /// Value
    value: Vec<u8>,
}

impl EllipticalCurveCommitmentScheme {
    /// Create a new elliptical curve commitment scheme with the specified number of generators
    pub fn new(num_generators: usize) -> Self {
        // Generate deterministic generators for reproducible tests
        let mut generators = Vec::with_capacity(num_generators);
        let g = k256::base_point_g();
        for i in 0..num_generators {
            // Use a SHA-256 hash to derive a scalar for each generator point
            let scalar = Self::hash_to_scalar(format!("generator-{}", i).as_bytes());
            generators.push(g.mul(&scalar).expect("Failed to create generator"));
        }

        Self { generators }
    }

    /// Generate a random blinding factor
    fn random_blinding() -> k256::Scalar {
        let mut rng = OsRng;
        loop {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            if let Ok(scalar) = Scalar::new(bytes) {
                return scalar;
            }
        }
    }

    /// Convert value to scalar
    fn value_to_scalar(value: &impl AsRef<[u8]>) -> k256::Scalar {
        Self::hash_to_scalar(value.as_ref())
    }

    /// Helper to convert a hash to a valid scalar, retrying if needed.
    fn hash_to_scalar(data: &[u8]) -> k256::Scalar {
        let mut hash_bytes = hash::sha256(data);
        loop {
            // Create a fixed-size array from the vector's slice to avoid moving hash_bytes.
            let mut array = [0u8; 32];
            array.copy_from_slice(&hash_bytes);
            if let Ok(scalar) = Scalar::new(array) {
                return scalar;
            }
            // Re-hash if the hash corresponds to an invalid scalar (e.g., zero)
            hash_bytes = hash::sha256(&hash_bytes);
        }
    }
}

impl CommitmentScheme for EllipticalCurveCommitmentScheme {
    type Commitment = EllipticalCurveCommitment;
    type Proof = EllipticalCurveProof;
    type Value = Vec<u8>;

    fn commit(&self, values: &[Option<Self::Value>]) -> Self::Commitment {
        // Start with identity point
        let mut commitment_point = Point::identity();

        // Use generators for each value
        for (i, value_opt) in values.iter().enumerate() {
            if i >= self.generators.len() {
                break; // Don't exceed available generators
            }

            if let Some(value) = value_opt {
                // Convert value to scalar
                let scalar = Self::value_to_scalar(value);

                // Add generator_i * value_scalar to the commitment point
                let term = self.generators[i].mul(&scalar).expect("Scalar mul failed");
                commitment_point = commitment_point.add(&term);
            }
        }

        // Add a random blinding factor with the last generator if we have one
        if !self.generators.is_empty() {
            let blinding = Self::random_blinding();
            let blinding_term = self.generators[self.generators.len() - 1].mul(&blinding).expect("Blinding failed");
            commitment_point = commitment_point.add(&blinding_term);
        }

        // Return the compressed point representation
        EllipticalCurveCommitment(commitment_point.serialize_compressed())
    }

    fn create_proof(
        &self,
        selector: &Selector,
        value: &Self::Value,
    ) -> Result<Self::Proof, String> {
        // Extract position from selector
        let position = match selector {
            Selector::Position(pos) => *pos,
            // For now, we only support position-based selectors
            _ => return Err("Only position-based selectors are supported".to_string()),
        };

        if position >= self.generators.len() {
            return Err(format!("Position {} out of bounds", position));
        }

        // Create a random blinding factor
        let blinding = Self::random_blinding();

        // Return a proof with position, value, and blinding
        Ok(EllipticalCurveProof {
            blinding,
            position,
            value: value.clone(),
        })
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        selector: &Selector,
        value: &Self::Value,
        context: &ProofContext,
    ) -> bool {
        // Extract position from selector
        let position = match selector {
            Selector::Position(pos) => *pos,
            // For now, we only support position-based selectors
            _ => return false,
        };

        // Check position matches
        if position != proof.position || position >= self.generators.len() {
            return false;
        }

        // Check value matches
        if proof.value != *value {
            return false;
        }

        // Use context to check for verification flags or parameters
        // This is a placeholder implementation to demonstrate context usage

        /* The context parameter in a real-world scenario might include:
         * 1. Cryptographic domain separation parameters to prevent cross-protocol attacks
         * 2. Chain-specific verification rules (e.g., specific validation rules per blockchain)
         * 3. Security level parameters (e.g., required bit security level)
         * 4. Curve-specific parameters or optimizations
         * 5. Batch verification settings to optimize multiple proof verifications
         * 6. Time bounds for time-sensitive commitments
         * 7. Circuit-specific parameters for zero-knowledge proofs
         * 8. Public parameters needed for verification
         * 9. Reusable values to prevent recomputation across multiple verifications
         * 10. Context-specific verification flags like the one demonstrated below
         */

        let strict_verification = context
            .get_data("strict_verification")
            .map(|v| !v.is_empty() && v[0] == 1)
            .unwrap_or(false);

        // Apply additional verification logic based on context
        if strict_verification {
            // In strict mode, we might perform additional checks
            // For example, ensure the commitment is not identity
            if commitment.as_ref() == [0u8; 32] {
                return false;
            }
        }

        // In a real implementation, we'd need to properly verify the commitment
        // with the blinding factor. This is a simplified implementation.

        // Convert value to scalar
        let value_scalar = Self::value_to_scalar(value);

        // Recreate the point for the value and blinding factor
        let blinding_generator = &self.generators[self.generators.len() - 1];
        let value_term = self.generators[position].mul(&value_scalar).expect("Scalar mul failed");
        let blinding_term = blinding_generator.mul(&proof.blinding).expect("Blinding failed");
        let computed_point = value_term.add(&blinding_term);

        // Check if the computed commitment matches the provided one
        let computed_commitment = EllipticalCurveCommitment(computed_point.serialize_compressed());

        // This is a simplified check - a real implementation would be more complex
        // for multiple values
        commitment.as_ref() == computed_commitment.as_ref()
    }

    fn scheme_id() -> SchemeIdentifier {
        SchemeIdentifier::new("elliptical_curve")
    }
}

impl HomomorphicCommitmentScheme for EllipticalCurveCommitmentScheme {
    fn add(&self, a: &Self::Commitment, b: &Self::Commitment) -> Result<Self::Commitment, String> {
        // Decompress points
        let point_a = Point::deserialize_compressed(a.as_ref()).map_err(|e| e.to_string())?;
        let point_b = Point::deserialize_compressed(b.as_ref()).map_err(|e| e.to_string())?;

        // Homomorphic addition is point addition
        let result_point = point_a.add(&point_b);

        Ok(EllipticalCurveCommitment(result_point.serialize_compressed()))
    }

    fn scalar_multiply(
        &self,
        a: &Self::Commitment,
        scalar: i32,
    ) -> Result<Self::Commitment, String> {
        if scalar <= 0 {
            return Err("Scalar must be positive".to_string());
        }

        // Decompress point
        let point = Point::deserialize_compressed(a.as_ref()).map_err(|e| e.to_string())?;

        // Convert i32 to Scalar. This is a simplified conversion for small, positive integers.
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes[..8].copy_from_slice(&(scalar as u64).to_le_bytes());
        let s = Scalar::new(scalar_bytes).map_err(|e| e.to_string())?;

        // Scalar multiplication
        let result_point = point.mul(&s).map_err(|e| e.to_string())?;

        Ok(EllipticalCurveCommitment(result_point.serialize_compressed()))
    }

    fn supports_operation(&self, operation: HomomorphicOperation) -> bool {
        matches!(
            operation,
            HomomorphicOperation::Addition | HomomorphicOperation::ScalarMultiplication
        )
    }
}

// Add utility methods for EllipticalCurveCommitment
impl EllipticalCurveCommitment {
    /// Create a new EllipticalCurveCommitment from a compressed point
    pub fn new(point: [u8; k256::K256_POINT_COMPRESSED_SIZE]) -> Self {
        Self(point)
    }

    /// Get the compressed point
    pub fn point(&self) -> &[u8; k256::K256_POINT_COMPRESSED_SIZE] {
        &self.0
    }

    /// Convert to a byte representation
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let array: [u8; k256::K256_POINT_COMPRESSED_SIZE] = bytes.try_into().map_err(|_| "Invalid point length".to_string())?;
        Ok(Self(array))
    }
}

// Utility methods for EllipticalCurveProof
impl EllipticalCurveProof {
    /// Create a new proof
    pub fn new(blinding: Scalar, position: usize, value: Vec<u8>) -> Self {
        Self {
            blinding,
            position,
            value,
        }
    }

    /// Get the blinding factor
    pub fn blinding(&self) -> &Scalar {
        &self.blinding
    }

    /// Get the position
    pub fn position(&self) -> usize {
        self.position
    }

    /// Get the value
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Serialize the proof
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(32 + 8 + self.value.len() + 4);

        // Serialize blinding factor (32 bytes)
        result.extend_from_slice(self.blinding.serialize().as_ref());

        // Serialize position (8 bytes)
        result.extend_from_slice(&self.position.to_le_bytes());

        // Serialize value length and value
        result.extend_from_slice(&(self.value.len() as u32).to_le_bytes());
        result.extend_from_slice(&self.value);

        result
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 44 {
            // 32 + 8 + 4 (minimum for blinding, position, and value length)
            return Err("Invalid proof length".to_string());
        }

        let mut pos = 0;

        // Read blinding
        let mut blinding_bytes = [0u8; 32];
        blinding_bytes.copy_from_slice(&bytes[pos..pos + 32]);
        let blinding = Scalar::new(blinding_bytes).map_err(|e| e.to_string())?;
        pos += 32;

        // Read position
        let mut position_bytes = [0u8; 8];
        position_bytes.copy_from_slice(&bytes[pos..pos + 8]);
        let position = usize::from_le_bytes(position_bytes);
        pos += 8;

        // Read value length
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&bytes[pos..pos + 4]);
        let value_len = u32::from_le_bytes(len_bytes) as usize;
        pos += 4;

        // Read value
        if pos + value_len > bytes.len() {
            return Err("Invalid value length".to_string());
        }
        let value = bytes[pos..pos + value_len].to_vec();

        Ok(Self {
            blinding,
            position,
            value,
        })
    }
}```

###### Directory: commitment_schemes/src/hash

####### File: commitment_schemes/src/hash/mod.rs
####*Size: 12K, Lines: 375, Type: ASCII text*

```rust
//! Hash-based commitment scheme implementations

use depin_sdk_core::commitment::{CommitmentScheme, ProofContext, SchemeIdentifier, Selector};
use depin_sdk_crypto::algorithms::hash;
use std::fmt::Debug;

/// Hash-based commitment scheme
#[derive(Debug, Clone)]
pub struct HashCommitmentScheme {
    /// Hash function to use (defaults to SHA-256)
    hash_function: HashFunction,
}

/// Available hash functions
#[derive(Debug, Clone, Copy)]
pub enum HashFunction {
    /// SHA-256
    Sha256,
    /// SHA-512
    Sha512,
}

/// Hash-based commitment
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashCommitment(Vec<u8>);

impl AsRef<[u8]> for HashCommitment {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Hash-based proof
#[derive(Debug, Clone)]
pub struct HashProof {
    /// Value hash
    pub value_hash: Vec<u8>,
    /// Selector used for this proof
    pub selector: Selector,
    /// Additional proof data
    pub additional_data: Vec<u8>,
}

impl HashCommitmentScheme {
    /// Create a new hash commitment scheme with the default hash function (SHA-256)
    pub fn new() -> Self {
        Self {
            hash_function: HashFunction::Sha256,
        }
    }

    /// Create a new hash commitment scheme with a specific hash function
    pub fn with_hash_function(hash_function: HashFunction) -> Self {
        Self { hash_function }
    }

    /// Helper function to hash data using the selected hash function
    pub fn hash_data(&self, data: &[u8]) -> Vec<u8> {
        match self.hash_function {
            HashFunction::Sha256 => hash::sha256(data),
            HashFunction::Sha512 => hash::sha512(data),
        }
    }

    /// Get the current hash function
    pub fn hash_function(&self) -> HashFunction {
        self.hash_function
    }

    /// Get the digest size in bytes
    pub fn digest_size(&self) -> usize {
        match self.hash_function {
            HashFunction::Sha256 => 32,
            HashFunction::Sha512 => 64,
        }
    }
}

impl CommitmentScheme for HashCommitmentScheme {
    type Commitment = HashCommitment;
    type Proof = HashProof;
    type Value = Vec<u8>;

    fn commit(&self, values: &[Option<Self::Value>]) -> Self::Commitment {
        // Simple commitment: hash the concatenation of all values
        let mut combined = Vec::new();

        for value in values {
            if let Some(v) = value {
                // Add length prefix to prevent collision attacks
                combined.extend_from_slice(&(v.len() as u32).to_le_bytes());
                combined.extend_from_slice(v);
            } else {
                // Mark None values with a zero length
                combined.extend_from_slice(&0u32.to_le_bytes());
            }
        }

        // If there are no values, hash an empty array
        if combined.is_empty() {
            return HashCommitment(self.hash_data(&[]));
        }

        // Return the hash of the combined data
        HashCommitment(self.hash_data(&combined))
    }

    fn create_proof(
        &self,
        selector: &Selector,
        value: &Self::Value,
    ) -> Result<Self::Proof, String> {
        // Calculate the hash of the value
        let value_hash = self.hash_data(value);

        // Create additional data based on selector type
        let additional_data = match selector {
            Selector::Key(key) => {
                // For key-based selectors, include the key hash
                self.hash_data(key)
            }
            Selector::Position(pos) => {
                // For position-based selectors, include the position
                pos.to_le_bytes().to_vec()
            }
            _ => Vec::new(),
        };

        Ok(HashProof {
            value_hash,
            selector: selector.clone(),
            additional_data,
        })
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        selector: &Selector,
        value: &Self::Value,
        context: &ProofContext,
    ) -> bool {
        // FIX: The compiler detected that `selector` was being compared to itself.
        // We need to compare the proof's selector with the one passed to the function.
        if &proof.selector != selector {
            return false;
        }

        // Verify that the value hash matches
        let computed_hash = self.hash_data(value);
        if computed_hash != proof.value_hash {
            return false;
        }

        // Basic direct verification for simple cases
        match selector {
            Selector::None => {
                // For a single value, directly compare the hash
                proof.value_hash == commitment.as_ref()
            }
            Selector::Key(key) => {
                // For a key-value pair, hash the combination
                let mut combined = Vec::new();
                combined.extend_from_slice(key);
                combined.extend_from_slice(value);
                let key_value_hash = self.hash_data(&combined);

                // Use context if provided
                if let Some(verification_flag) = context.get_data("strict_verification") {
                    if !verification_flag.is_empty() && verification_flag[0] == 1 {
                        // Strict verification mode would go here
                        return key_value_hash == commitment.as_ref();
                    }
                }

                // Simple verification - not suitable for complex structures
                // In practice, state trees would implement proper verification
                key_value_hash == commitment.as_ref()
            }
            _ => {
                // For position or predicate selectors, this basic commitment scheme
                // cannot verify on its own - would require tree structure knowledge
                // This would be handled by state tree implementations
                false
            }
        }
    }

    fn scheme_id() -> SchemeIdentifier {
        SchemeIdentifier::new("hash")
    }
}

// Default implementation
impl Default for HashCommitmentScheme {
    fn default() -> Self {
        Self::new()
    }
}

// Additional utility methods for HashCommitment
impl HashCommitment {
    /// Create a new commitment from raw bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the raw commitment bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert to a new owned Vec<u8>
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
    }
}

// Additional utility methods for HashProof
impl HashProof {
    /// Create a new proof
    pub fn new(value_hash: Vec<u8>, selector: Selector, additional_data: Vec<u8>) -> Self {
        Self {
            value_hash,
            selector,
            additional_data,
        }
    }

    /// Get the selector
    pub fn selector(&self) -> &Selector {
        &self.selector
    }

    /// Get the value hash
    pub fn value_hash(&self) -> &[u8] {
        &self.value_hash
    }

    /// Get the additional data
    pub fn additional_data(&self) -> &[u8] {
        &self.additional_data
    }

    /// Convert to a serializable format
    pub fn to_bytes(&self) -> Vec<u8> {
        // Simplified serialization
        let mut result = Vec::new();

        // Serialize selector
        match &self.selector {
            Selector::Position(pos) => {
                result.push(1); // Selector type
                result.extend_from_slice(&pos.to_le_bytes());
            }
            Selector::Key(key) => {
                result.push(2); // Selector type
                result.extend_from_slice(&(key.len() as u32).to_le_bytes());
                result.extend_from_slice(key);
            }
            Selector::Predicate(pred) => {
                result.push(3); // Selector type
                result.extend_from_slice(&(pred.len() as u32).to_le_bytes());
                result.extend_from_slice(pred);
            }
            Selector::None => {
                result.push(0); // Selector type
            }
        }

        // Serialize value hash
        result.extend_from_slice(&(self.value_hash.len() as u32).to_le_bytes());
        result.extend_from_slice(&self.value_hash);

        // Serialize additional data
        result.extend_from_slice(&(self.additional_data.len() as u32).to_le_bytes());
        result.extend_from_slice(&self.additional_data);

        result
    }

    /// Create from serialized format
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() {
            return Err("Empty bytes".to_string());
        }

        let mut pos = 0;

        // Deserialize selector
        let selector_type = bytes[pos];
        pos += 1;

        let selector = match selector_type {
            0 => Selector::None,
            1 => {
                if pos + 8 > bytes.len() {
                    return Err("Invalid position selector".to_string());
                }
                let mut position_bytes = [0u8; 8];
                position_bytes.copy_from_slice(&bytes[pos..pos + 8]);
                pos += 8;
                Selector::Position(usize::from_le_bytes(position_bytes))
            }
            2 => {
                if pos + 4 > bytes.len() {
                    return Err("Invalid key selector".to_string());
                }
                let mut len_bytes = [0u8; 4];
                len_bytes.copy_from_slice(&bytes[pos..pos + 4]);
                pos += 4;
                let key_len = u32::from_le_bytes(len_bytes) as usize;

                if pos + key_len > bytes.len() {
                    return Err("Invalid key length".to_string());
                }
                let key = bytes[pos..pos + key_len].to_vec();
                pos += key_len;
                Selector::Key(key)
            }
            3 => {
                if pos + 4 > bytes.len() {
                    return Err("Invalid predicate selector".to_string());
                }
                let mut len_bytes = [0u8; 4];
                len_bytes.copy_from_slice(&bytes[pos..pos + 4]);
                pos += 4;
                let pred_len = u32::from_le_bytes(len_bytes) as usize;

                if pos + pred_len > bytes.len() {
                    return Err("Invalid predicate length".to_string());
                }
                let pred = bytes[pos..pos + pred_len].to_vec();
                pos += pred_len;
                Selector::Predicate(pred)
            }
            _ => return Err(format!("Unknown selector type: {}", selector_type)),
        };

        // Deserialize value hash
        if pos + 4 > bytes.len() {
            return Err("Invalid value hash length".to_string());
        }
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&bytes[pos..pos + 4]);
        pos += 4;
        let hash_len = u32::from_le_bytes(len_bytes) as usize;

        if pos + hash_len > bytes.len() {
            return Err("Invalid hash length".to_string());
        }
        let value_hash = bytes[pos..pos + hash_len].to_vec();
        pos += hash_len;

        // Deserialize additional data
        if pos + 4 > bytes.len() {
            return Err("Invalid additional data length".to_string());
        }
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&bytes[pos..pos + 4]);
        pos += 4;
        let add_len = u32::from_le_bytes(len_bytes) as usize;

        if pos + add_len > bytes.len() {
            return Err("Invalid additional data length".to_string());
        }
        let additional_data = bytes[pos..pos + add_len].to_vec();

        Ok(HashProof {
            value_hash,
            selector,
            additional_data,
        })
    }
}```

###### Directory: commitment_schemes/src/kzg

####### File: commitment_schemes/src/kzg/mod.rs
####*Size: 12K, Lines: 320, Type: Unicode text, UTF-8 text*

```rust
//! KZG Polynomial Commitment Scheme Implementation
//!
//! # Implementation Status
//!
//! IMPORTANT: This is still a placeholder implementation with dummy cryptographic operations.
//! A full implementation would require:
//!
//! 1. Integration with an elliptic curve library for bilinear pairings
//!    - Need a pairing-friendly curve like BLS12-381
//!    - Requires efficient implementation of the bilinear map e: G₁ × G₂ → GT
//!
//! 2. Proper finite field arithmetic
//!    - Field operations in Fp for polynomial coefficients
//!    - Polynomial arithmetic (addition, multiplication, division)
//!    - Evaluation at arbitrary points
//!
//! 3. Structured reference string generation or loading
//!    - Implementation of trusted setup ceremony or loading from trusted source
//!    - Secure handling of setup parameters
//!    - Verification of SRS integrity
//!
//! 4. Complete polynomial evaluation logic
//!    - Division by (X - z) to create quotient polynomial
//!    - Batch verification techniques for efficiency
//!    - Handling edge cases and potential attack vectors
//!
//! # Mathematical Background
//!
//! KZG polynomial commitments use a bilinear pairing e: G₁ × G₂ → GT over elliptic curve groups
//! to create and verify commitments to polynomials. The scheme requires a trusted setup to generate
//! a structured reference string (SRS) containing powers of a secret value.
//!
//! The KZG scheme consists of four main operations:
//! - Setup: Generate SRS parameters (G₁ᵢ = [τⁱ]G₁ and G₂ᵢ = [τⁱ]G₂) where τ is a secret
//! - Commit: For a polynomial p(X) = Σᵢ cᵢXⁱ, compute C = Σᵢ cᵢG₁ᵢ
//! - Prove: For a point z, compute proof π that p(z) = y using the quotient polynomial q(X) = (p(X) - y)/(X - z)
//! - Verify: Check if e(C - [y]G₁₀, G₂₁) = e(π, G₂₂ - [z]G₂₁)

use depin_sdk_core::commitment::{CommitmentScheme, ProofContext, SchemeIdentifier, Selector};
use std::fmt::Debug;

/// Structured Reference String (from trusted setup)
#[derive(Debug, Clone)]
pub struct KZGParams {
    /// G1 points
    pub g1_points: Vec<Vec<u8>>, // Simplified - would be actual curve points
    /// G2 points
    pub g2_points: Vec<Vec<u8>>, // Simplified - would be actual curve points
}

/// KZG polynomial commitment scheme
#[derive(Debug)]
pub struct KZGCommitmentScheme {
    /// Cryptographic parameters from trusted setup
    params: KZGParams,
}

/// KZG commitment to a polynomial
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KZGCommitment(Vec<u8>);

/// KZG proof for a polynomial evaluation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KZGProof {
    /// The quotient polynomial commitment
    quotient: Vec<u8>,
    /// The evaluation point
    point: Vec<u8>,
    /// The claimed evaluation value
    value: Vec<u8>,
}

/// Polynomial representation
#[derive(Debug, Clone)]
pub struct Polynomial {
    /// Coefficients of the polynomial
    coefficients: Vec<Vec<u8>>, // Simplified - would be field elements
}

impl KZGCommitmentScheme {
    /// Create a new KZG commitment scheme with the given parameters
    pub fn new(params: KZGParams) -> Self {
        Self { params }
    }

    /// Create a default scheme with dummy parameters (for testing only)
    pub fn default() -> Self {
        Self {
            params: KZGParams {
                g1_points: vec![vec![0; 32]; 10], // Dummy parameters
                g2_points: vec![vec![0; 64]; 10], // Dummy parameters
            },
        }
    }

    /// Commit to a polynomial directly
    pub fn commit_polynomial(&self, polynomial: &Polynomial) -> KZGCommitment {
        // In a real implementation, this would compute:
        // C = ∑ᵢ cᵢ·G₁ᵢ where cᵢ are polynomial coefficients

        // For now, return a dummy commitment
        KZGCommitment(vec![0; 32])
    }

    /// Create a proof for a polynomial evaluation at a point
    pub fn create_evaluation_proof(
        &self,
        polynomial: &Polynomial,
        point: &[u8],
        commitment: &KZGCommitment,
    ) -> Result<KZGProof, String> {
        // In a real implementation, this would:
        // 1. Evaluate the polynomial at the point: y = p(z)
        // 2. Compute the quotient polynomial q(X) = (p(X) - y) / (X - z)
        // 3. Commit to the quotient polynomial

        // For now, return a dummy proof
        let value = vec![0; 32]; // Dummy evaluation result

        Ok(KZGProof {
            quotient: vec![0; 32],
            point: point.to_vec(),
            value,
        })
    }

    /// Verify a polynomial evaluation proof
    pub fn verify_evaluation(&self, commitment: &KZGCommitment, proof: &KZGProof) -> bool {
        // In a real implementation, this would verify:
        // e(C - [y]G₁₀, G₂₁) = e(π, G₂₂ - [z]G₂₁)

        // For now, always return true
        true
    }
}

impl AsRef<[u8]> for KZGCommitment {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// Implement CommitmentScheme trait to integrate with the existing system
impl CommitmentScheme for KZGCommitmentScheme {
    type Commitment = KZGCommitment;
    type Proof = KZGProof;
    type Value = Vec<u8>;

    fn commit(&self, values: &[Option<Self::Value>]) -> Self::Commitment {
        // Convert values to a polynomial
        let coefficients = values.iter().filter_map(|opt| opt.clone()).collect();

        let polynomial = Polynomial { coefficients };

        // Use the specialized method for polynomial commitment
        self.commit_polynomial(&polynomial)
    }

    fn create_proof(
        &self,
        selector: &Selector,
        value: &Self::Value,
    ) -> Result<Self::Proof, String> {
        // Extract point from selector
        let point = match selector {
            Selector::Position(pos) => {
                // Convert position to a field element
                (*pos as u64).to_le_bytes().to_vec()
            }
            Selector::Key(key) => {
                // Use key directly as the evaluation point
                key.clone()
            }
            _ => return Err("KZG only supports Position or Key selectors".to_string()),
        };

        // We don't have the polynomial here, so we create a dummy proof
        // In practice, create_proof would need access to the original polynomial
        let dummy_polynomial = Polynomial {
            coefficients: vec![value.clone()], // Not actually correct
        };

        let dummy_commitment = KZGCommitment(vec![0; 32]);
        self.create_evaluation_proof(&dummy_polynomial, &point, &dummy_commitment)
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        _selector: &Selector,
        _value: &Self::Value,
        _context: &ProofContext,
    ) -> bool {
        // Use the specialized verification method
        self.verify_evaluation(commitment, proof)
    }

    fn scheme_id() -> SchemeIdentifier {
        SchemeIdentifier::new("kzg")
    }
}

// Utility methods for KZGCommitment
impl KZGCommitment {
    /// Create a new KZG commitment from raw data
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    /// Get the commitment data
    pub fn data(&self) -> &[u8] {
        &self.0
    }

    /// Convert to bytes for serialization
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        Ok(Self(bytes.to_vec()))
    }
}

// Utility methods for KZGProof
impl KZGProof {
    /// Create a new KZG proof from components
    pub fn new(quotient: Vec<u8>, point: Vec<u8>, value: Vec<u8>) -> Self {
        Self {
            quotient,
            point,
            value,
        }
    }

    /// Get the quotient polynomial commitment
    pub fn quotient(&self) -> &[u8] {
        &self.quotient
    }

    /// Get the evaluation point
    pub fn point(&self) -> &[u8] {
        &self.point
    }

    /// Get the evaluation value
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Convert to bytes for serialization
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Quotient length and data
        result.extend_from_slice(&(self.quotient.len() as u32).to_le_bytes());
        result.extend_from_slice(&self.quotient);

        // Point length and data
        result.extend_from_slice(&(self.point.len() as u32).to_le_bytes());
        result.extend_from_slice(&self.point);

        // Value length and data
        result.extend_from_slice(&(self.value.len() as u32).to_le_bytes());
        result.extend_from_slice(&self.value);

        result
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 12 {
            return Err("Invalid proof format: too short".to_string());
        }

        let mut pos = 0;

        // Read quotient
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&bytes[pos..pos + 4]);
        pos += 4;
        let quotient_len = u32::from_le_bytes(len_bytes) as usize;

        if pos + quotient_len > bytes.len() {
            return Err("Invalid proof format: quotient truncated".to_string());
        }
        let quotient = bytes[pos..pos + quotient_len].to_vec();
        pos += quotient_len;

        // Read point
        len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&bytes[pos..pos + 4]);
        pos += 4;
        let point_len = u32::from_le_bytes(len_bytes) as usize;

        if pos + point_len > bytes.len() {
            return Err("Invalid proof format: point truncated".to_string());
        }
        let point = bytes[pos..pos + point_len].to_vec();
        pos += point_len;

        // Read value
        len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&bytes[pos..pos + 4]);
        pos += 4;
        let value_len = u32::from_le_bytes(len_bytes) as usize;

        if pos + value_len > bytes.len() {
            return Err("Invalid proof format: value truncated".to_string());
        }
        let value = bytes[pos..pos + value_len].to_vec();

        Ok(Self {
            quotient,
            point,
            value,
        })
    }
}```

####### File: commitment_schemes/src/kzg/mod.rs:108:9
####*Size: 0, Lines: 0, Type: empty*

####*File content not included (exceeds threshold or non-text file)*

####### File: commitment_schemes/src/kzg/mod.rs:110:9
####*Size: 0, Lines: 0, Type: empty*

####*File content not included (exceeds threshold or non-text file)*

####### File: commitment_schemes/src/kzg/mod.rs:128:37
####*Size: 0, Lines: 0, Type: empty*

####*File content not included (exceeds threshold or non-text file)*

####### File: commitment_schemes/src/kzg/mod.rs:128:65
####*Size: 0, Lines: 0, Type: empty*

####*File content not included (exceeds threshold or non-text file)*

####### File: commitment_schemes/src/kzg/mod.rs:55:5
####*Size: 0, Lines: 0, Type: empty*

####*File content not included (exceeds threshold or non-text file)*

####### File: commitment_schemes/src/kzg/mod.rs:77:5
####*Size: 0, Lines: 0, Type: empty*

####*File content not included (exceeds threshold or non-text file)*

####### File: commitment_schemes/src/kzg/mod.rs:97:37
####*Size: 0, Lines: 0, Type: empty*

####*File content not included (exceeds threshold or non-text file)*

###### Directory: commitment_schemes/src/lattice

####### File: commitment_schemes/src/lattice/mod.rs
####*Size: 8.0K, Lines: 231, Type: ASCII text*

```rust
//! Lattice-based commitment scheme implementation
//!
//! This module implements a lattice-based commitment scheme using
//! cryptographic primitives from lattice-based cryptography.

use depin_sdk_core::commitment::{CommitmentScheme, ProofContext, SchemeIdentifier, Selector};
use std::fmt::Debug;

/// Lattice-based commitment scheme
#[derive(Debug)]
pub struct LatticeCommitmentScheme {
    /// Dimension of the lattice
    dimension: usize,
}

/// Lattice-based commitment
#[derive(Debug, Clone)]
pub struct LatticeCommitment(Vec<u8>);

impl AsRef<[u8]> for LatticeCommitment {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Lattice-based proof
#[derive(Debug, Clone)]
pub struct LatticeProof {
    /// Proof data
    data: Vec<u8>,
    /// Position
    position: usize,
}

impl LatticeCommitmentScheme {
    /// Create a new lattice-based commitment scheme with specified dimension
    pub fn new(dimension: usize) -> Self {
        Self { dimension }
    }

    /// Get the dimension of the lattice
    pub fn dimension(&self) -> usize {
        self.dimension
    }

    /// Default parameters suitable for 128-bit security
    pub fn default_params() -> Self {
        Self { dimension: 512 }
    }
}

impl CommitmentScheme for LatticeCommitmentScheme {
    type Commitment = LatticeCommitment;
    type Proof = LatticeProof;
    type Value = Vec<u8>;

    fn commit(&self, values: &[Option<Self::Value>]) -> Self::Commitment {
        // In a real implementation, this would:
        // 1. Convert values to polynomial coefficients
        // 2. Generate a random lattice-based commitment
        // 3. Return the commitment

        // Simplified implementation for now
        let mut combined = Vec::new();
        for maybe_value in values {
            if let Some(value) = maybe_value {
                combined.extend_from_slice(value.as_ref());
            }
        }

        // Add some "randomness" based on the dimension
        combined.extend_from_slice(&self.dimension.to_le_bytes());

        // Return a placeholder commitment
        LatticeCommitment(combined)
    }

    fn create_proof(
        &self,
        selector: &Selector,
        value: &Self::Value,
    ) -> Result<Self::Proof, String> {
        // Extract position from selector
        let position = match selector {
            Selector::Position(pos) => *pos,
            _ => return Err("Only position-based selectors are supported".to_string()),
        };

        // In a real implementation, this would:
        // 1. Generate a zero-knowledge proof that the value at position
        //    is correctly committed to in the commitment
        // 2. Use lattice-based techniques to create the proof

        // For now, return a simple proof that just wraps the value and position
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(value.as_ref());
        proof_data.extend_from_slice(&position.to_le_bytes());

        Ok(LatticeProof {
            data: proof_data,
            position,
        })
    }

    fn verify(
        &self,
        _commitment: &Self::Commitment,
        proof: &Self::Proof,
        selector: &Selector,
        value: &Self::Value,
        _context: &ProofContext,
    ) -> bool {
        // Extract position from selector
        let position = match selector {
            Selector::Position(pos) => *pos,
            _ => return false, // Only support position-based selectors for now
        };

        // Check position matches
        if position != proof.position {
            return false;
        }

        // In a real implementation, this would:
        // 1. Verify the zero-knowledge proof against the commitment
        // 2. Check that the proof correctly authenticates the value

        // For this simplified implementation, we'll check if the proof contains the value
        let mut expected_data = Vec::new();
        expected_data.extend_from_slice(value.as_ref());
        expected_data.extend_from_slice(&position.to_le_bytes());

        proof.data.starts_with(value.as_ref())
    }

    fn scheme_id() -> SchemeIdentifier {
        SchemeIdentifier::new("lattice")
    }
}

impl Default for LatticeCommitmentScheme {
    fn default() -> Self {
        Self::default_params()
    }
}

// Additional utility methods for LatticeCommitment
impl LatticeCommitment {
    /// Create a new commitment from raw bytes
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    /// Get the raw commitment data
    pub fn data(&self) -> &[u8] {
        &self.0
    }

    /// Convert to bytes for serialization
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() {
            return Err("Empty commitment data".to_string());
        }
        Ok(Self(bytes.to_vec()))
    }
}

// Additional utility methods for LatticeProof
impl LatticeProof {
    /// Create a new proof
    pub fn new(data: Vec<u8>, position: usize) -> Self {
        Self { data, position }
    }

    /// Get the proof data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get the position
    pub fn position(&self) -> usize {
        self.position
    }

    /// Convert to bytes for serialization
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        result.extend_from_slice(&self.data);
        result.extend_from_slice(&self.position.to_le_bytes());
        result
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 12 {
            // 4 bytes for length + at least 0 bytes for data + 8 bytes for position
            return Err("Invalid proof format: too short".to_string());
        }

        let mut pos = 0;

        // Read data length
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&bytes[pos..pos + 4]);
        pos += 4;
        let data_len = u32::from_le_bytes(len_bytes) as usize;

        // Read data
        if pos + data_len > bytes.len() {
            return Err("Invalid proof format: data truncated".to_string());
        }
        let data = bytes[pos..pos + data_len].to_vec();
        pos += data_len;

        // Read position
        if pos + 8 > bytes.len() {
            return Err("Invalid proof format: position truncated".to_string());
        }
        let mut pos_bytes = [0u8; 8];
        pos_bytes.copy_from_slice(&bytes[pos..pos + 8]);
        let position = usize::from_le_bytes(pos_bytes);

        Ok(Self { data, position })
    }
}
```

###### File: commitment_schemes/src/lib.rs
###*Size: 4.0K, Lines: 8, Type: ASCII text*

```rust
//! # DePIN SDK Commitment Schemes
//!
//! Implementations of various commitment schemes for the DePIN SDK.

pub mod elliptical_curve;
pub mod hash;
pub mod kzg;
pub mod lattice; // Renamed from module_lwe
```

##### File: commitment_schemes/Cargo.toml
##*Size: 4.0K, Lines: 23, Type: ASCII text*

```toml
[package]
name = "depin-sdk-commitment-schemes"
version = "0.1.0"
edition = "2021"
description = "Commitment scheme implementations for the DePIN SDK"
license = "MIT OR Apache-2.0"

[dependencies]
depin-sdk-core = { path = "../core" }
depin-sdk-crypto = { path = "../crypto" }
dcrypt = { version = "0.12.0-beta.1", features = ["full"] }
log = { workspace = true }
serde = { workspace = true }
thiserror = { workspace = true }
bytes = { workspace = true }
rand = { workspace = true }

[features]
default = []
hash = []
kzg = []
module_lwe = ["depin-sdk-core/post-quantum"]
elliptical_curve = ["depin-sdk-core/homomorphic"]
```

#### Directory: consensus

##### Directory: consensus/src

###### Directory: consensus/src/tests

####### File: consensus/src/tests/mod.rs
####*Size: 0, Lines: 0, Type: empty*

####*File content not included (exceeds threshold or non-text file)*

###### File: consensus/src/lib.rs
###*Size: 4.0K, Lines: 120, Type: ASCII text*

```rust
//! Consensus module implementations for the DePIN SDK

use std::time::Duration;

/// Consensus algorithm types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusAlgorithm {
    /// Proof of Stake
    ProofOfStake,
    /// Delegated Proof of Stake
    DelegatedProofOfStake,
    /// Proof of Authority
    ProofOfAuthority,
    /// Custom consensus algorithm
    Custom(u32),
}

/// Consensus configuration
#[derive(Debug, Clone)]
pub struct ConsensusConfig {
    /// Consensus algorithm
    pub algorithm: ConsensusAlgorithm,
    /// Block time target
    pub block_time: Duration,
    /// Number of validators
    pub validator_count: usize,
    /// Minimum stake amount
    pub min_stake: u64,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            algorithm: ConsensusAlgorithm::ProofOfStake,
            block_time: Duration::from_secs(5),
            validator_count: 21,
            min_stake: 1000,
        }
    }
}

/// Consensus engine interface
pub trait ConsensusEngine {
    /// Start the consensus engine
    fn start(&self) -> Result<(), String>;

    /// Stop the consensus engine
    fn stop(&self) -> Result<(), String>;

    /// Check if the consensus engine is running
    fn is_running(&self) -> bool;

    /// Get the consensus configuration
    fn config(&self) -> &ConsensusConfig;
}

/// Basic implementation of a consensus engine
pub struct BasicConsensusEngine {
    /// Configuration
    config: ConsensusConfig,
    /// Running status
    running: bool,
}

impl BasicConsensusEngine {
    /// Create a new basic consensus engine
    pub fn new(config: ConsensusConfig) -> Self {
        Self {
            config,
            running: false,
        }
    }
}

impl ConsensusEngine for BasicConsensusEngine {
    fn start(&self) -> Result<(), String> {
        // In a real implementation, this would start the consensus process
        Ok(())
    }

    fn stop(&self) -> Result<(), String> {
        // In a real implementation, this would stop the consensus process
        Ok(())
    }

    fn is_running(&self) -> bool {
        self.running
    }

    fn config(&self) -> &ConsensusConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consensus_config_default() {
        let config = ConsensusConfig::default();
        assert_eq!(config.algorithm, ConsensusAlgorithm::ProofOfStake);
        assert_eq!(config.block_time, Duration::from_secs(5));
        assert_eq!(config.validator_count, 21);
        assert_eq!(config.min_stake, 1000);
    }

    #[test]
    fn test_basic_consensus_engine() {
        let config = ConsensusConfig::default();
        let engine = BasicConsensusEngine::new(config);

        assert!(!engine.is_running());
        assert_eq!(engine.config().algorithm, ConsensusAlgorithm::ProofOfStake);

        // Test start and stop
        engine.start().unwrap();
        engine.stop().unwrap();
    }
}
```

##### File: consensus/Cargo.toml
##*Size: 4.0K, Lines: 16, Type: ASCII text*

```toml
[package]
name = "depin-sdk-consensus"
version = "0.1.0"
edition = "2021"
description = "Consensus for the DePIN SDK"
license = "MIT OR Apache-2.0"

[dependencies]
log = { workspace = true }
serde = { workspace = true }
thiserror = { workspace = true }
bytes = { workspace = true }
anyhow = { workspace = true }

[features]
default = []
```

#### Directory: core

##### Directory: core/src

###### Directory: core/src/app

####### File: core/src/app/mod.rs
####*Size: 4.0K, Lines: 46, Type: ASCII text*

```rust
// Path: crates/core/src/app/mod.rs

use crate::transaction::TransactionModel;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct ChainStatus {
    pub height: u64,
    pub latest_timestamp: u64,
    pub total_transactions: u64,
    pub is_running: bool,
}

// FIX: Add derive(Clone, Debug). Clone is needed for block processing,
// and Debug is needed for `.unwrap()` calls on Results containing the block.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block<T> {
    pub header: BlockHeader,
    pub transactions: Vec<T>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockHeader {
    pub height: u64,
    pub prev_hash: Vec<u8>,
    pub state_root: Vec<u8>,
    pub transactions_root: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Debug)]
pub enum ChainError {
    Block(String),
    Transaction(String),
}

/// A struct that holds the core, serializable state of a sovereign chain.
/// This is distinct from its logic, which is defined by the `SovereignChain` trait.
#[derive(Debug)]
pub struct SovereignAppChain<CS, TM: TransactionModel> {
    pub commitment_scheme: CS,
    pub transaction_model: TM,
    pub chain_id: String,
    pub status: ChainStatus,
    pub recent_blocks: Vec<Block<TM::Transaction>>,
    pub max_recent_blocks: usize,
}```

###### Directory: core/src/chain

####### File: core/src/chain/mod.rs
####*Size: 4.0K, Lines: 40, Type: ASCII text*

```rust
// Path: crates/core/src/chain/mod.rs

use crate::app::{Block, ChainError, ChainStatus};
use crate::commitment::CommitmentScheme;
use crate::state::StateManager;
use crate::transaction::TransactionModel;
use crate::validator::WorkloadContainer;
use async_trait::async_trait;
use std::fmt::Debug;

/// A trait that defines the logic and capabilities of a sovereign chain state machine.
#[async_trait]
pub trait SovereignChain<CS, TM, ST>: Debug + Send
where
    CS: CommitmentScheme,
    TM: TransactionModel<CommitmentScheme = CS>,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
{
    fn status(&self) -> &ChainStatus;
    fn transaction_model(&self) -> &TM;

    async fn process_transaction(
        &mut self,
        tx: &TM::Transaction,
        workload: &WorkloadContainer<ST>,
    ) -> Result<(), ChainError>;

    async fn process_block(
        &mut self,
        block: Block<TM::Transaction>,
        workload: &WorkloadContainer<ST>,
    ) -> Result<(), ChainError>;

    fn create_block(
        &self,
        transactions: Vec<TM::Transaction>,
        workload: &WorkloadContainer<ST>,
    ) -> Block<TM::Transaction>;

    fn get_block(&self, height: u64) -> Option<&Block<TM::Transaction>>;
}```

###### Directory: core/src/commitment

####### Directory: core/src/commitment/tests

######## File: core/src/commitment/tests/commitment_tests.rs
#####*Size: 8.0K, Lines: 205, Type: ASCII text*

```rust
//! Tests for the commitment scheme traits

#[cfg(test)]
mod tests {
    use crate::commitment::{
        CommitmentScheme, HomomorphicCommitmentScheme, HomomorphicOperation, ProofContext,
        SchemeIdentifier, Selector,
    };

    // Define a mock commitment scheme for testing
    #[derive(Debug)]
    struct MockCommitmentScheme;

    #[derive(Debug, Clone)]
    struct MockCommitment(Vec<u8>);

    impl AsRef<[u8]> for MockCommitment {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    #[derive(Clone)]
    struct MockProof(Vec<u8>);

    impl CommitmentScheme for MockCommitmentScheme {
        type Commitment = MockCommitment;
        type Proof = MockProof;
        type Value = Vec<u8>; // Added missing Value associated type

        fn commit(&self, values: &[Option<Self::Value>]) -> Self::Commitment {
            // Simple mock implementation for testing
            let combined: Vec<u8> = values
                .iter()
                .flat_map(|v| v.clone().unwrap_or_default())
                .collect();
            MockCommitment(combined)
        }

        fn create_proof(
            &self,
            selector: &Selector,
            value: &Self::Value,
        ) -> Result<Self::Proof, String> {
            // Simple mock implementation for testing
            Ok(MockProof(value.clone()))
        }

        fn verify(
            &self,
            _commitment: &Self::Commitment,
            proof: &Self::Proof,
            _selector: &Selector,
            value: &Self::Value,
            _context: &ProofContext, // Added context parameter
        ) -> bool {
            // Simple mock implementation for testing
            proof.0 == *value
        }

        fn scheme_id() -> SchemeIdentifier {
            SchemeIdentifier::new("mock")
        }
    }

    #[derive(Debug)]
    struct MockHomomorphicCommitmentScheme;

    impl CommitmentScheme for MockHomomorphicCommitmentScheme {
        type Commitment = MockCommitment;
        type Proof = MockProof;
        type Value = Vec<u8>; // Added missing Value associated type

        fn commit(&self, values: &[Option<Self::Value>]) -> Self::Commitment {
            // Simple mock implementation for testing
            let combined: Vec<u8> = values
                .iter()
                .flat_map(|v| v.clone().unwrap_or_default())
                .collect();
            MockCommitment(combined)
        }

        fn create_proof(
            &self,
            selector: &Selector,
            value: &Self::Value,
        ) -> Result<Self::Proof, String> {
            // Simple mock implementation for testing
            Ok(MockProof(value.clone()))
        }

        fn verify(
            &self,
            _commitment: &Self::Commitment,
            proof: &Self::Proof,
            _selector: &Selector,
            value: &Self::Value,
            _context: &ProofContext, // Added context parameter
        ) -> bool {
            // Simple mock implementation for testing
            proof.0 == *value
        }

        fn scheme_id() -> SchemeIdentifier {
            SchemeIdentifier::new("mock-homomorphic")
        }
    }

    impl HomomorphicCommitmentScheme for MockHomomorphicCommitmentScheme {
        fn add(
            &self,
            a: &Self::Commitment,
            b: &Self::Commitment,
        ) -> Result<Self::Commitment, String> {
            // Simple mock implementation for testing
            let mut result = a.0.clone();
            result.extend_from_slice(&b.0);
            Ok(MockCommitment(result))
        }

        fn scalar_multiply(
            &self,
            a: &Self::Commitment,
            scalar: i32,
        ) -> Result<Self::Commitment, String> {
            // Simple mock implementation for testing
            if scalar <= 0 {
                return Err("Scalar must be positive".to_string());
            }

            let mut result = Vec::new();
            for _ in 0..scalar {
                result.extend_from_slice(a.as_ref());
            }

            Ok(MockCommitment(result))
        }

        fn supports_operation(&self, operation: HomomorphicOperation) -> bool {
            // Simple mock implementation for testing
            match operation {
                HomomorphicOperation::Addition | HomomorphicOperation::ScalarMultiplication => true,
                HomomorphicOperation::Custom(_) => false,
            }
        }
    }

    #[test]
    fn test_commitment_scheme() {
        let scheme = MockCommitmentScheme;

        // Test commit
        let values = vec![Some(vec![1, 2, 3]), Some(vec![4, 5, 6])];
        let commitment = scheme.commit(&values);

        // Test create_proof
        let proof = scheme
            .create_proof(&Selector::Position(0), &vec![1, 2, 3])
            .unwrap();

        // Test verify
        let context = ProofContext::default();
        assert!(scheme.verify(
            &commitment,
            &proof,
            &Selector::Position(0),
            &vec![1, 2, 3],
            &context
        ));
        assert!(!scheme.verify(
            &commitment,
            &proof,
            &Selector::Position(0),
            &vec![7, 8, 9],
            &context
        ));

        // Test scheme_id
        assert_eq!(MockCommitmentScheme::scheme_id().0, "mock");
    }

    #[test]
    fn test_homomorphic_commitment_scheme() {
        let scheme = MockHomomorphicCommitmentScheme;

        // Test commit
        let values1 = vec![Some(vec![1, 2, 3])];
        let values2 = vec![Some(vec![4, 5, 6])];
        let commitment1 = scheme.commit(&values1);
        let commitment2 = scheme.commit(&values2);

        // Test add
        let sum = scheme.add(&commitment1, &commitment2).unwrap();
        assert_eq!(sum.0, vec![1, 2, 3, 4, 5, 6]);

        // Test scalar_multiply
        let product = scheme.scalar_multiply(&commitment1, 3).unwrap();
        assert_eq!(product.0, vec![1, 2, 3, 1, 2, 3, 1, 2, 3]);

        // Test supports_operation
        assert!(scheme.supports_operation(HomomorphicOperation::Addition));
        assert!(scheme.supports_operation(HomomorphicOperation::ScalarMultiplication));
        assert!(!scheme.supports_operation(HomomorphicOperation::Custom(42)));
    }
}
```

######## File: core/src/commitment/tests/mod.rs
#####*Size: 4.0K, Lines: 3, Type: ASCII text*

```rust
//! Tests for commitment scheme traits

mod commitment_tests;
```

####### File: core/src/commitment/homomorphic.rs
####*Size: 4.0K, Lines: 25, Type: ASCII text*

```rust
// File: crates/core/src/commitment/homomorphic.rs

use crate::commitment::scheme::CommitmentScheme;

/// Type of homomorphic operation supported
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomomorphicOperation {
    /// Addition of two commitments
    Addition,
    /// Scalar multiplication
    ScalarMultiplication,
    /// Custom operation
    Custom(u32),
}

/// Extended trait for commitment schemes supporting homomorphic operations
pub trait HomomorphicCommitmentScheme: CommitmentScheme {
    /// Add two commitments
    fn add(&self, a: &Self::Commitment, b: &Self::Commitment) -> Result<Self::Commitment, String>;
    
    /// Multiply a commitment by a scalar
    fn scalar_multiply(&self, a: &Self::Commitment, scalar: i32) -> Result<Self::Commitment, String>;
    
    /// Check if this commitment scheme supports specific homomorphic operations
    fn supports_operation(&self, operation: HomomorphicOperation) -> bool;
}```

####### File: core/src/commitment/identifiers.rs
####*Size: 4.0K, Lines: 12, Type: ASCII text*

```rust
//! Scheme identifier definitions for different commitment types

/// Identifier for commitment schemes
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SchemeIdentifier(pub String);

impl SchemeIdentifier {
    /// Create a new scheme identifier
    pub fn new(value: &str) -> Self {
        Self(value.to_string())
    }
}
```

####### File: core/src/commitment/mod.rs
####*Size: 4.0K, Lines: 12, Type: ASCII text*

```rust
//! Commitment scheme trait definitions

mod scheme;
mod homomorphic;
mod identifiers;

#[cfg(test)]
mod tests;

pub use scheme::*;
pub use homomorphic::*;
pub use identifiers::*;
```

####### File: core/src/commitment/scheme.rs
####*Size: 4.0K, Lines: 123, Type: ASCII text*

```rust
// File: crates/core/src/commitment/scheme.rs

use std::fmt::Debug;
use crate::commitment::identifiers::SchemeIdentifier;
use std::collections::HashMap;

/// Selector for addressing elements in a commitment
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    /// Index-based position (for ordered commitments like Merkle trees)
    Position(usize),
    /// Key-based selector (for map-like commitments)
    Key(Vec<u8>),
    /// Predicate-based selector (for advanced schemes)
    Predicate(Vec<u8>), // Serialized predicate
    /// No selector (for single-value commitments)
    None,
}

/// Context for proof verification
#[derive(Debug, Clone, Default)]
pub struct ProofContext {
    /// Additional data for verification
    pub data: HashMap<String, Vec<u8>>,
}

impl ProofContext {
    /// Create a new empty proof context
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }

    /// Add data to the context
    pub fn add_data(&mut self, key: &str, value: Vec<u8>) {
        self.data.insert(key.to_string(), value);
    }

    /// Get data from the context
    pub fn get_data(&self, key: &str) -> Option<&Vec<u8>> {
        self.data.get(key)
    }
}

/// Core trait for all commitment schemes
pub trait CommitmentScheme: Debug + Send + Sync + 'static {
    /// The type of commitment produced
    type Commitment: AsRef<[u8]> + Clone + Send + Sync + 'static;

    /// The type of proof for this commitment scheme
    type Proof: Clone + Send + Sync + 'static;

    /// The type of values this scheme commits to
    type Value: AsRef<[u8]> + Clone + Send + Sync + 'static;

    /// Commit to a vector of values
    fn commit(&self, values: &[Option<Self::Value>]) -> Self::Commitment;

    /// Create a proof for a specific selector and value
    fn create_proof(&self, selector: &Selector, value: &Self::Value)
        -> Result<Self::Proof, String>;

    /// Verify a proof against a commitment
    fn verify(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        selector: &Selector,
        value: &Self::Value,
        context: &ProofContext,
    ) -> bool;

    /// Get scheme identifier
    fn scheme_id() -> SchemeIdentifier;

    /// Create a position-based proof (convenience method)
    fn create_proof_at_position(
        &self,
        position: usize,
        value: &Self::Value,
    ) -> Result<Self::Proof, String> {
        self.create_proof(&Selector::Position(position), value)
    }

    /// Create a key-based proof (convenience method)
    fn create_proof_for_key(&self, key: &[u8], value: &Self::Value) -> Result<Self::Proof, String> {
        self.create_proof(&Selector::Key(key.to_vec()), value)
    }

    /// Verify a position-based proof (convenience method)
    fn verify_at_position(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        position: usize,
        value: &Self::Value,
    ) -> bool {
        self.verify(
            commitment,
            proof,
            &Selector::Position(position),
            value,
            &ProofContext::default(),
        )
    }

    /// Verify a key-based proof (convenience method)
    fn verify_for_key(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &Self::Value,
    ) -> bool {
        self.verify(
            commitment,
            proof,
            &Selector::Key(key.to_vec()),
            value,
            &ProofContext::default(),
        )
    }
}```

###### Directory: core/src/component

####### Directory: core/src/component/tests

######## File: core/src/component/tests/mod.rs
#####*Size: 4.0K, Lines: 58, Type: ASCII text*

```rust
//! Tests for the component classification system

// Change module definition to avoid "tests::tests" inception
#[cfg(test)]
mod component_tests {
    use crate::component::{
        Adaptable, AdaptableComponent, ClassifiedComponent, ComponentClassification, Extensible,
        ExtensibleComponent, Fixed, FixedComponent,
    };

    // Test struct implementing Fixed trait
    struct TestFixedComponent;
    impl Fixed for TestFixedComponent {}

    // Test struct implementing Adaptable trait
    struct TestAdaptableComponent;
    impl Adaptable for TestAdaptableComponent {}

    // Test struct implementing Extensible trait
    struct TestExtensibleComponent;
    impl Extensible for TestExtensibleComponent {}

    #[test]
    fn test_fixed_component() {
        let component = FixedComponent;
        assert_eq!(component.classification(), ComponentClassification::Fixed);
        assert!(!component.can_modify());
        assert!(!component.can_extend());
    }

    #[test]
    fn test_adaptable_component() {
        let component = AdaptableComponent;
        assert_eq!(
            component.classification(),
            ComponentClassification::Adaptable
        );
        assert!(component.can_modify());
        assert!(!component.can_extend());
    }

    #[test]
    fn test_extensible_component() {
        let component = ExtensibleComponent;
        assert_eq!(
            component.classification(),
            ComponentClassification::Extensible
        );
        assert!(component.can_modify());
        assert!(component.can_extend());
    }

    // TODO: Add more comprehensive tests covering:
    // - Custom components with the classification system
    // - Component compatibility checks
    // - Classification inheritance
    // - Component composition with mixed classifications
}
```

####### File: core/src/component/classification.rs
####*Size: 4.0K, Lines: 74, Type: ASCII text*

```rust
//! Fixed/Adaptable/Extensible classification definitions

/// Component classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentClassification {
    /// Fixed component - cannot be modified
    Fixed,
    
    /// Adaptable component - can be parameterized within defined bounds
    Adaptable,
    
    /// Extensible component - can be fully customized
    Extensible,
}

/// Component with classification
pub trait ClassifiedComponent {
    /// Get the component classification
    fn classification(&self) -> ComponentClassification;
    
    /// Check if the component can be modified
    fn can_modify(&self) -> bool {
        match self.classification() {
            ComponentClassification::Fixed => false,
            ComponentClassification::Adaptable | ComponentClassification::Extensible => true,
        }
    }
    
    /// Check if the component can be extended
    fn can_extend(&self) -> bool {
        match self.classification() {
            ComponentClassification::Fixed | ComponentClassification::Adaptable => false,
            ComponentClassification::Extensible => true,
        }
    }
}

/// Marker trait for fixed components
pub trait Fixed {}

/// Marker trait for adaptable components
pub trait Adaptable {}

/// Marker trait for extensible components
pub trait Extensible {}

// Instead of blanket implementations, we'll provide implementation helpers

/// Helper struct for fixed components
pub struct FixedComponent;

impl ClassifiedComponent for FixedComponent {
    fn classification(&self) -> ComponentClassification {
        ComponentClassification::Fixed
    }
}

/// Helper struct for adaptable components
pub struct AdaptableComponent;

impl ClassifiedComponent for AdaptableComponent {
    fn classification(&self) -> ComponentClassification {
        ComponentClassification::Adaptable
    }
}

/// Helper struct for extensible components
pub struct ExtensibleComponent;

impl ClassifiedComponent for ExtensibleComponent {
    fn classification(&self) -> ComponentClassification {
        ComponentClassification::Extensible
    }
}
```

####### File: core/src/component/mod.rs
####*Size: 4.0K, Lines: 8, Type: ASCII text*

```rust
//! Component classification system

mod classification;

#[cfg(test)]
mod tests;

pub use classification::*;
```

###### Directory: core/src/config

####### File: core/src/config/mod.rs
####*Size: 4.0K, Lines: 11, Type: ASCII text*

```rust
// Path: crates/core/src/config/mod.rs

//! Shared configuration structures for core DePIN SDK components.

use serde::Deserialize;

/// Configuration for the Workload container (`workload.toml`).
/// This is defined in `core` because it's part of the public `WorkloadContainer` struct.
#[derive(Debug, Deserialize, Clone)]
pub struct WorkloadConfig {
    pub enabled_vms: Vec<String>,
}```

###### Directory: core/src/crypto

####### Directory: core/src/crypto/tests

######## File: core/src/crypto/tests/mod.rs
#####*Size: 12K, Lines: 308, Type: ASCII text*

```rust
//! Tests for cryptographic primitive interfaces

use crate::crypto::{
        DecapsulationKey, Encapsulated, EncapsulationKey, KemKeyPair, KeyEncapsulation,
        SerializableKey, Signature, SigningKey, SigningKeyPair, VerifyingKey,
    };
    use std::vec::Vec;

    // ============================================================================
    // Mock implementations for signature algorithms
    // ============================================================================
    
    struct MockSigningKeyPair;
    struct MockVerifyingKey(Vec<u8>);
    struct MockSigningKey(Vec<u8>);
    struct MockSignature(Vec<u8>);

    impl SigningKeyPair for MockSigningKeyPair {
        type PublicKey = MockVerifyingKey;
        type PrivateKey = MockSigningKey;
        type Signature = MockSignature;

        fn public_key(&self) -> Self::PublicKey {
            MockVerifyingKey(vec![1, 2, 3])
        }

        fn private_key(&self) -> Self::PrivateKey {
            MockSigningKey(vec![4, 5, 6])
        }

        fn sign(&self, message: &[u8]) -> Self::Signature {
            MockSignature(message.to_vec())
        }
    }

    impl SerializableKey for MockVerifyingKey {
        fn to_bytes(&self) -> Vec<u8> {
            self.0.clone()
        }

        fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
            Ok(MockVerifyingKey(bytes.to_vec()))
        }
    }

    impl VerifyingKey for MockVerifyingKey {
        type Signature = MockSignature;

        fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool {
            message == signature.0
        }
    }

    impl SerializableKey for MockSigningKey {
        fn to_bytes(&self) -> Vec<u8> {
            self.0.clone()
        }

        fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
            Ok(MockSigningKey(bytes.to_vec()))
        }
    }

    impl SigningKey for MockSigningKey {
        type Signature = MockSignature;

        fn sign(&self, message: &[u8]) -> Self::Signature {
            MockSignature(message.to_vec())
        }
    }

    impl SerializableKey for MockSignature {
        fn to_bytes(&self) -> Vec<u8> {
            self.0.clone()
        }

        fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
            Ok(MockSignature(bytes.to_vec()))
        }
    }

    impl Signature for MockSignature {}

    // ============================================================================
    // Mock implementations for KEM algorithms
    // ============================================================================

    struct MockKemKeyPair;
    struct MockEncapsulationKey(Vec<u8>);
    struct MockDecapsulationKey(Vec<u8>);
    struct MockEncapsulated {
        ciphertext: Vec<u8>,
        shared_secret: Vec<u8>,
    }

    impl KemKeyPair for MockKemKeyPair {
        type PublicKey = MockEncapsulationKey;
        type PrivateKey = MockDecapsulationKey;

        fn public_key(&self) -> Self::PublicKey {
            MockEncapsulationKey(vec![7, 8, 9])
        }

        fn private_key(&self) -> Self::PrivateKey {
            MockDecapsulationKey(vec![10, 11, 12])
        }
    }

    impl SerializableKey for MockEncapsulationKey {
        fn to_bytes(&self) -> Vec<u8> {
            self.0.clone()
        }

        fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
            Ok(MockEncapsulationKey(bytes.to_vec()))
        }
    }

    impl EncapsulationKey for MockEncapsulationKey {}

    impl SerializableKey for MockDecapsulationKey {
        fn to_bytes(&self) -> Vec<u8> {
            self.0.clone()
        }

        fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
            Ok(MockDecapsulationKey(bytes.to_vec()))
        }
    }

    impl DecapsulationKey for MockDecapsulationKey {}

    impl SerializableKey for MockEncapsulated {
        fn to_bytes(&self) -> Vec<u8> {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&self.ciphertext);
            bytes
        }

        fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
            Ok(MockEncapsulated {
                ciphertext: bytes.to_vec(),
                shared_secret: vec![0; 32],
            })
        }
    }

    impl Encapsulated for MockEncapsulated {
        fn ciphertext(&self) -> &[u8] {
            &self.ciphertext
        }

        fn shared_secret(&self) -> &[u8] {
            &self.shared_secret
        }
    }

    struct MockKEM;

    impl KeyEncapsulation for MockKEM {
        type KeyPair = MockKemKeyPair;
        type PublicKey = MockEncapsulationKey;
        type PrivateKey = MockDecapsulationKey;
        type Encapsulated = MockEncapsulated;

        fn generate_keypair(&self) -> Self::KeyPair {
            MockKemKeyPair
        }

        fn encapsulate(&self, _public_key: &Self::PublicKey) -> Self::Encapsulated {
            MockEncapsulated {
                ciphertext: vec![7, 8, 9],
                shared_secret: vec![0; 32],
            }
        }

        fn decapsulate(
            &self,
            _private_key: &Self::PrivateKey,
            _encapsulated: &Self::Encapsulated,
        ) -> Option<Vec<u8>> {
            Some(vec![0; 32])
        }
    }

    // ============================================================================
    // Tests
    // ============================================================================

    #[test]
    fn test_signing_operations() {
        let keypair = MockSigningKeyPair;
        let message = b"test message";

        // Test signing
        let signature = keypair.sign(message);
        let public_key = keypair.public_key();

        // Test verification
        assert!(public_key.verify(message, &signature));

        // Test verification with wrong message
        let wrong_message = b"wrong message";
        assert!(!public_key.verify(wrong_message, &signature));
    }

    #[test]
    fn test_signing_key_serialization() {
        let keypair = MockSigningKeyPair;
        let public_key = keypair.public_key();
        let private_key = keypair.private_key();

        // Test public key serialization
        let pk_bytes = public_key.to_bytes();
        let pk_recovered = MockVerifyingKey::from_bytes(&pk_bytes).unwrap();
        assert_eq!(pk_bytes, pk_recovered.to_bytes());

        // Test private key serialization
        let sk_bytes = private_key.to_bytes();
        let sk_recovered = MockSigningKey::from_bytes(&sk_bytes).unwrap();
        assert_eq!(sk_bytes, sk_recovered.to_bytes());
    }

    #[test]
    fn test_signature_serialization() {
        let keypair = MockSigningKeyPair;
        let message = b"test message";
        let signature = keypair.sign(message);

        // Test signature serialization
        let sig_bytes = signature.to_bytes();
        let sig_recovered = MockSignature::from_bytes(&sig_bytes).unwrap();
        assert_eq!(sig_bytes, sig_recovered.to_bytes());
    }

    #[test]
    fn test_kem_operations() {
        let kem = MockKEM;
        let keypair = kem.generate_keypair();
        let public_key = keypair.public_key();
        let private_key = keypair.private_key();

        // Test encapsulation
        let encapsulated = kem.encapsulate(&public_key);
        
        // Test decapsulation
        let shared_secret = kem.decapsulate(&private_key, &encapsulated);
        assert!(shared_secret.is_some());
        assert_eq!(shared_secret.unwrap().len(), 32);
    }

    #[test]
    fn test_kem_key_serialization() {
        let kem = MockKEM;
        let keypair = kem.generate_keypair();
        let public_key = keypair.public_key();
        let private_key = keypair.private_key();

        // Test public key serialization
        let pk_bytes = public_key.to_bytes();
        let pk_recovered = MockEncapsulationKey::from_bytes(&pk_bytes).unwrap();
        assert_eq!(pk_bytes, pk_recovered.to_bytes());

        // Test private key serialization
        let sk_bytes = private_key.to_bytes();
        let sk_recovered = MockDecapsulationKey::from_bytes(&sk_bytes).unwrap();
        assert_eq!(sk_bytes, sk_recovered.to_bytes());
    }

    #[test]
    fn test_encapsulated_serialization() {
        let kem = MockKEM;
        let keypair = kem.generate_keypair();
        let public_key = keypair.public_key();
        let encapsulated = kem.encapsulate(&public_key);

        // Test encapsulated data serialization
        let enc_bytes = encapsulated.to_bytes();
        let enc_recovered = MockEncapsulated::from_bytes(&enc_bytes).unwrap();
        assert_eq!(enc_bytes, enc_recovered.to_bytes());
    }

    #[test]
    fn test_independent_signing() {
        // Test that signing keys can be used independently
        let signing_key = MockSigningKey(vec![1, 2, 3, 4]);
        let message = b"test message";
        
        let signature = signing_key.sign(message);
        assert_eq!(signature.0, message.to_vec());
    }

    #[test]
    fn test_independent_verification() {
        // Test that verifying keys can be used independently
        let verifying_key = MockVerifyingKey(vec![5, 6, 7, 8]);
        let message = b"test message";
        let signature = MockSignature(message.to_vec());
        
        assert!(verifying_key.verify(message, &signature));
        assert!(!verifying_key.verify(b"wrong message", &signature));
    }

    // TODO: Add more comprehensive tests covering:
    // - Post-quantum algorithm interfaces
    // - Mixed cryptographic operations
    // - Security level assertions
    // - Error cases in serialization/deserialization
    // - Cross-compatibility between different implementations```

####### File: core/src/crypto/mod.rs
####*Size: 4.0K, Lines: 137, Type: ASCII text*

```rust
// core/src/crypto/mod.rs
//! Cryptographic primitive interfaces
//!
//! This module provides trait definitions for both traditional and
//! post-quantum cryptographic primitives, creating a unified interface
//! for all cryptographic implementations.

// ============================================================================
// Common traits for all key types
// ============================================================================

/// Base trait for any key that can be serialized
pub trait SerializableKey {
    /// Convert to bytes
    fn to_bytes(&self) -> Vec<u8>;

    /// Create from bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self, String>
    where
        Self: Sized;
}

// ============================================================================
// Signature-specific traits
// ============================================================================

/// Key pair trait for signature algorithms
pub trait SigningKeyPair {
    /// Public key type for verification
    type PublicKey: VerifyingKey<Signature = Self::Signature>;

    /// Private key type for signing
    type PrivateKey: SigningKey<Signature = Self::Signature>;

    /// Signature type produced
    type Signature: Signature;

    /// Get the public key
    fn public_key(&self) -> Self::PublicKey;

    /// Get the private key
    fn private_key(&self) -> Self::PrivateKey;

    /// Sign a message
    fn sign(&self, message: &[u8]) -> Self::Signature;
}

/// Public key trait for signature verification
pub trait VerifyingKey: SerializableKey {
    /// Signature type that this key can verify
    type Signature: Signature;

    /// Verify a signature
    fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool;
}

/// Private key trait for signing operations
pub trait SigningKey: SerializableKey {
    /// Signature type that this key produces
    type Signature: Signature;

    /// Sign a message
    fn sign(&self, message: &[u8]) -> Self::Signature;
}

/// Signature trait
pub trait Signature: SerializableKey {
    // Signature-specific methods could go here
}

// ============================================================================
// KEM-specific traits
// ============================================================================

/// Key pair trait for key encapsulation mechanisms
pub trait KemKeyPair {
    /// Public key type for encapsulation
    type PublicKey: EncapsulationKey;

    /// Private key type for decapsulation
    type PrivateKey: DecapsulationKey;

    /// Get the public key
    fn public_key(&self) -> Self::PublicKey;

    /// Get the private key
    fn private_key(&self) -> Self::PrivateKey;
}

/// Public key trait for encapsulation
pub trait EncapsulationKey: SerializableKey {
    // Encapsulation-specific methods could go here
}

/// Private key trait for decapsulation
pub trait DecapsulationKey: SerializableKey {
    // Decapsulation-specific methods could go here
}

/// Key encapsulation mechanism trait
pub trait KeyEncapsulation {
    /// Key pair type
    type KeyPair: KemKeyPair<PublicKey = Self::PublicKey, PrivateKey = Self::PrivateKey>;

    /// Public key type
    type PublicKey: EncapsulationKey;

    /// Private key type
    type PrivateKey: DecapsulationKey;

    /// Encapsulated key type
    type Encapsulated: Encapsulated;

    /// Generate a new key pair
    fn generate_keypair(&self) -> Self::KeyPair;

    /// Encapsulate a shared secret using a public key
    fn encapsulate(&self, public_key: &Self::PublicKey) -> Self::Encapsulated;

    /// Decapsulate a shared secret using a private key
    fn decapsulate(
        &self,
        private_key: &Self::PrivateKey,
        encapsulated: &Self::Encapsulated,
    ) -> Option<Vec<u8>>;
}

/// Encapsulated key trait
pub trait Encapsulated: SerializableKey {
    /// Get the ciphertext
    fn ciphertext(&self) -> &[u8];

    /// Get the shared secret
    fn shared_secret(&self) -> &[u8];
}

#[cfg(test)]
mod tests;```

###### Directory: core/src/error

####### File: core/src/error/mod.rs
####*Size: 4.0K, Lines: 56, Type: ASCII text*

```rust
// Path: crates/core/src/error/mod.rs

use thiserror::Error;

#[derive(Error, Debug)]
pub enum StateError {
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Validation failed: {0}")]
    Validation(String),
    #[error("Apply failed: {0}")]
    Apply(String),
    #[error("State backend error: {0}")]
    Backend(String),
    // FIX: Add variants for errors that occur in state tree implementations.
    // The `WriteError` is used by `FileStateTree` when file I/O fails.
    // The `InvalidValue` is used by `VerkleTree` when a value can't be converted.
    #[error("State write error: {0}")]
    WriteError(String),
    #[error("Invalid value: {0}")]
    InvalidValue(String),
}

#[derive(Error, Debug)]
pub enum TransactionError {
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Deserialization error: {0}")]
    Deserialization(String),
    #[error("Invalid transaction: {0}")]
    Invalid(String),
    // FIX: Add a variant to wrap StateErrors, which will allow `?` to work.
    #[error("State error: {0}")]
    State(#[from] StateError),
}

#[derive(Error, Debug)]
pub enum ValidatorError {
    #[error("Container '{0}' is already running")]
    AlreadyRunning(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Other error: {0}")]
    Other(String),
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("Service not found: {0}")]
    ServiceNotFound(String),
    #[error("Upgrade error: {0}")]
    UpgradeError(String),
    #[error("Custom error: {0}")]
    Custom(String),
}```

###### Directory: core/src/homomorphic

####### Directory: core/src/homomorphic/tests

######## File: core/src/homomorphic/tests/homorphic_operation_interfaces_tests.rs
#####*Size: 8.0K, Lines: 165, Type: ASCII text*

```rust
//! Tests for homomorphic operation interfaces

#[cfg(test)]
mod tests {
    use crate::homomorphic::{CommitmentOperation, OperationResult};
    use std::any::Any;
    use std::sync::Arc;

    // Simple mock structs for testing
    #[derive(Clone)]
    struct MockCommitment(Vec<u8>);

    impl MockCommitment {
        fn new(value: u8) -> Self {
            Self(vec![value])
        }

        fn value(&self) -> u8 {
            self.0[0]
        }
    }

    // Mock implementation of an operation executor
    struct MockOperationExecutor;

    impl MockOperationExecutor {
        fn execute(&self, operation: &CommitmentOperation) -> OperationResult {
            match operation {
                CommitmentOperation::Add { left, right } => {
                    let left_commitment = match left.downcast_ref::<MockCommitment>() {
                        Some(c) => c,
                        None => {
                            return OperationResult::Failure(
                                "Left operand is not a MockCommitment".to_string(),
                            )
                        }
                    };

                    let right_commitment = match right.downcast_ref::<MockCommitment>() {
                        Some(c) => c,
                        None => {
                            return OperationResult::Failure(
                                "Right operand is not a MockCommitment".to_string(),
                            )
                        }
                    };

                    let result =
                        MockCommitment::new(left_commitment.value() + right_commitment.value());
                    OperationResult::Success(Arc::new(result))
                }
                CommitmentOperation::ScalarMultiply { commitment, scalar } => {
                    let commitment = match commitment.downcast_ref::<MockCommitment>() {
                        Some(c) => c,
                        None => {
                            return OperationResult::Failure(
                                "Commitment is not a MockCommitment".to_string(),
                            )
                        }
                    };

                    if *scalar <= 0 {
                        return OperationResult::Failure("Scalar must be positive".to_string());
                    }

                    let result = MockCommitment::new(commitment.value() * (*scalar as u8));
                    OperationResult::Success(Arc::new(result))
                }
                CommitmentOperation::Custom {
                    operation_id: _,
                    inputs: _,
                    parameters: _,
                } => {
                    // Just a placeholder for custom operations
                    OperationResult::Unsupported
                }
            }
        }
    }

    #[test]
    fn test_add_operation() {
        let executor = MockOperationExecutor;

        let left = Arc::new(MockCommitment::new(5));
        let right = Arc::new(MockCommitment::new(7));

        let operation = CommitmentOperation::Add { left, right };
        let result = executor.execute(&operation);

        match result {
            OperationResult::Success(result_arc) => {
                let result_commitment = result_arc.downcast_ref::<MockCommitment>().unwrap();
                assert_eq!(result_commitment.value(), 12);
            }
            _ => panic!("Operation failed or unsupported"),
        }
    }

    #[test]
    fn test_scalar_multiply_operation() {
        let executor = MockOperationExecutor;

        let commitment = Arc::new(MockCommitment::new(5));
        let scalar = 3;

        let operation = CommitmentOperation::ScalarMultiply { commitment, scalar };
        let result = executor.execute(&operation);

        match result {
            OperationResult::Success(result_arc) => {
                let result_commitment = result_arc.downcast_ref::<MockCommitment>().unwrap();
                assert_eq!(result_commitment.value(), 15);
            }
            _ => panic!("Operation failed or unsupported"),
        }
    }

    #[test]
    fn test_custom_operation() {
        let executor = MockOperationExecutor;

        let inputs = vec![Arc::new(MockCommitment::new(5)) as Arc<dyn Any + Send + Sync>];
        let parameters = vec![0, 1, 2];

        let operation = CommitmentOperation::Custom {
            operation_id: "test_op".to_string(),
            inputs,
            parameters,
        };

        let result = executor.execute(&operation);

        match result {
            OperationResult::Unsupported => {
                // Expected behavior for this test
            }
            _ => panic!("Custom operation should return Unsupported in this test"),
        }
    }

    #[test]
    fn test_operation_failure() {
        let executor = MockOperationExecutor;

        let commitment = Arc::new(MockCommitment::new(5));
        let scalar = -1; // Negative scalar should cause failure

        let operation = CommitmentOperation::ScalarMultiply { commitment, scalar };
        let result = executor.execute(&operation);

        match result {
            OperationResult::Failure(error) => {
                assert_eq!(error, "Scalar must be positive");
            }
            _ => panic!("Operation should have failed"),
        }
    }

    // TODO: Add more comprehensive tests covering:
    // - Complex homomorphic operations
    // - Chained operations
    // - Operation result handling
    // - Type safety checks
}
```

######## File: core/src/homomorphic/tests/mod.rs
#####*Size: 4.0K, Lines: 1, Type: ASCII text*

```rust
pub mod homorphic_operation_interfaces_tests;
```

####### File: core/src/homomorphic/mod.rs
####*Size: 4.0K, Lines: 10, Type: ASCII text*

```rust
//! Homomorphic operation interfaces

mod operations;
mod result;

#[cfg(test)]
mod tests;

pub use operations::*;
pub use result::*;
```

####### File: core/src/homomorphic/operations.rs
####*Size: 4.0K, Lines: 73, Type: ASCII text*

```rust
//! Definition of the CommitmentOperation enum

use std::any::Any;
use std::fmt;
use std::sync::Arc;

/// Type for operations on commitments
pub enum CommitmentOperation {
    /// Add two commitments
    Add {
        left: Arc<dyn Any + Send + Sync>,
        right: Arc<dyn Any + Send + Sync>,
    },

    /// Multiply a commitment by a scalar
    ScalarMultiply {
        commitment: Arc<dyn Any + Send + Sync>,
        scalar: i32,
    },

    /// Apply a custom operation
    Custom {
        operation_id: String,
        inputs: Vec<Arc<dyn Any + Send + Sync>>,
        parameters: Vec<u8>,
    },
}

impl fmt::Debug for CommitmentOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Add { .. } => write!(f, "CommitmentOperation::Add {{ .. }}"),
            Self::ScalarMultiply { scalar, .. } => {
                write!(
                    f,
                    "CommitmentOperation::ScalarMultiply {{ scalar: {}, .. }}",
                    scalar
                )
            }
            Self::Custom { operation_id, .. } => {
                write!(
                    f,
                    "CommitmentOperation::Custom {{ operation_id: {}, .. }}",
                    operation_id
                )
            }
        }
    }
}

impl Clone for CommitmentOperation {
    fn clone(&self) -> Self {
        match self {
            Self::Add { left, right } => Self::Add {
                left: Arc::clone(left),
                right: Arc::clone(right),
            },
            Self::ScalarMultiply { commitment, scalar } => Self::ScalarMultiply {
                commitment: Arc::clone(commitment),
                scalar: *scalar,
            },
            Self::Custom {
                operation_id,
                inputs,
                parameters,
            } => Self::Custom {
                operation_id: operation_id.clone(),
                inputs: inputs.iter().map(Arc::clone).collect(),
                parameters: parameters.clone(),
            },
        }
    }
}
```

####### File: core/src/homomorphic/result.rs
####*Size: 4.0K, Lines: 37, Type: ASCII text*

```rust
//! Definition of the OperationResult enum

use std::any::Any;
use std::fmt;
use std::sync::Arc;

/// Result of a homomorphic operation
pub enum OperationResult {
    /// Successfully computed result
    Success(Arc<dyn Any + Send + Sync>),

    /// Operation failed
    Failure(String),

    /// Operation not supported
    Unsupported,
}

impl fmt::Debug for OperationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success(_) => write!(f, "OperationResult::Success(..)"),
            Self::Failure(msg) => write!(f, "OperationResult::Failure({})", msg),
            Self::Unsupported => write!(f, "OperationResult::Unsupported"),
        }
    }
}

impl Clone for OperationResult {
    fn clone(&self) -> Self {
        match self {
            Self::Success(value) => Self::Success(Arc::clone(value)),
            Self::Failure(msg) => Self::Failure(msg.clone()),
            Self::Unsupported => Self::Unsupported,
        }
    }
}
```

###### Directory: core/src/ibc

####### File: core/src/ibc/mod.rs
####*Size: 4.0K, Lines: 23, Type: ASCII text*

```rust
// In core/src/ibc/mod.rs
use crate::services::BlockchainService;
use crate::error::CoreError as Error; // Or define a specific IBC error type

// Define the missing types
pub type ChainId = String; // Or use a more specific type
pub type ProofType = String; // Define based on your requirements

pub struct Packet {
    pub data: Vec<u8>,
    pub source: ChainId,
    pub destination: ChainId,
    // Add other fields as needed
}

pub trait CrossChainCommunication: BlockchainService {
    fn verify_proof(&self, proof: &dyn CrossChainProof) -> Result<bool, Error>;
    fn create_packet(&self, data: &[u8], destination: ChainId) -> Result<Packet, Error>;
}

pub trait CrossChainProof {
    fn source_chain(&self) -> ChainId;
    fn proof_type(&self) -> ProofType;
}```

###### Directory: core/src/services

####### File: core/src/services/mod.rs
####*Size: 4.0K, Lines: 59, Type: ASCII text*

```rust
use std::any::Any;

// Define the missing error type
#[derive(Debug, thiserror::Error)]
pub enum UpgradeError {
    #[error("Invalid upgrade: {0}")]
    InvalidUpgrade(String),
    #[error("State migration failed: {0}")]
    MigrationFailed(String),
    #[error("Service not found")]
    ServiceNotFound,
    #[error("Health check failed: {0}")]
    HealthCheckFailed(String),
    #[error("Service operation failed: {0}")]
    OperationFailed(String),
}

/// An identifier for a swappable service.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ServiceType {
    Governance,
    Semantic,
    ExternalData,
    // ... other standard services
    Custom(String),
}

/// The base trait for any service managed by the chain.
pub trait BlockchainService: Any + Send + Sync {
    fn service_type(&self) -> ServiceType;
    // Potentially add methods for health checks, metrics, etc.
}

/// A trait for services that support runtime upgrades and rollbacks.
pub trait UpgradableService: BlockchainService {
    /// Prepares the service for an upgrade by validating the new implementation
    /// and providing a state snapshot for migration.
    fn prepare_upgrade(&self, new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError>; // Returns state snapshot

    /// Instantiates a new version of the service from a state snapshot.
    fn complete_upgrade(&mut self, snapshot: &[u8]) -> Result<(), UpgradeError>;
    
    /// Start the service
    fn start(&self) -> Result<(), UpgradeError> {
        // Default implementation - services can override if needed
        Ok(())
    }
    
    /// Stop the service
    fn stop(&self) -> Result<(), UpgradeError> {
        // Default implementation - services can override if needed
        Ok(())
    }
    
    /// Check the health of the service
    fn health_check(&self) -> Result<(), UpgradeError> {
        // Default implementation - services can override if needed
        Ok(())
    }
}```

###### Directory: core/src/state

####### Directory: core/src/state/tests

######## File: core/src/state/tests/mod.rs
#####*Size: 8.0K, Lines: 141, Type: ASCII text*

```rust
#[cfg(test)]
mod basic_state_tests {
    use crate::error::StateError;
    use crate::state::StateManager;
    use std::collections::HashMap;

    // Mock commitment and proof types for testing
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MockCommitment(Vec<u8>);

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MockProof(Vec<u8>);

    // Mock state manager implementation
    struct MockStateManager {
        data: HashMap<Vec<u8>, Vec<u8>>,
    }

    impl MockStateManager {
        fn new() -> Self {
            Self {
                data: HashMap::new(),
            }
        }
    }

    impl StateManager for MockStateManager {
        type Commitment = MockCommitment;
        type Proof = MockProof;

        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
            Ok(self.data.get(key).cloned())
        }

        fn set(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
            self.data.insert(key.to_vec(), value.to_vec());
            Ok(())
        }

        fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
            self.data.remove(key);
            Ok(())
        }
        
        fn root_commitment(&self) -> Self::Commitment {
            // Simple mock implementation
            let mut combined = Vec::new();
            for (k, v) in &self.data {
                combined.extend_from_slice(k);
                combined.extend_from_slice(v);
            }
            MockCommitment(combined)
        }
        
        fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
            // Simple mock implementation
            self.get(key).ok().flatten().map(MockProof)
        }
        
        fn verify_proof(
            &self,
            _commitment: &Self::Commitment,
            proof: &Self::Proof,
            _key: &[u8],
            value: &[u8],
        ) -> bool {
            // Simple mock implementation
            proof.0 == value
        }
    }

    #[test]
    fn test_basic_state_operations() {
        let mut state = MockStateManager::new();
        
        // Test set and get
        let key = b"test_key";
        let value = b"test_value";
        
        state.set(key, value).unwrap();
        assert_eq!(state.get(key).unwrap(), Some(value.to_vec()));
        
        // Test delete
        state.delete(key).unwrap();
        assert_eq!(state.get(key).unwrap(), None);
    }

    #[test]
    fn test_batch_operations() {
        let mut state = MockStateManager::new();
        
        // Test batch set
        let updates = vec![
            (b"key1".to_vec(), b"value1".to_vec()),
            (b"key2".to_vec(), b"value2".to_vec()),
            (b"key3".to_vec(), b"value3".to_vec()),
        ];
        
        state.batch_set(&updates).unwrap();
        
        // Test batch get
        let keys = vec![
            b"key1".to_vec(),
            b"key2".to_vec(),
            b"key3".to_vec(),
            b"nonexistent".to_vec(),
        ];
        
        let values = state.batch_get(&keys).unwrap();
        
        assert_eq!(values.len(), 4);
        assert_eq!(values[0], Some(b"value1".to_vec()));
        assert_eq!(values[1], Some(b"value2".to_vec()));
        assert_eq!(values[2], Some(b"value3".to_vec()));
        assert_eq!(values[3], None);
    }
    
    #[test]
    fn test_commitment_and_proof() {
        let mut state = MockStateManager::new();
        
        // Set up test data
        let key = b"test_key";
        let value = b"test_value";
        state.set(key, value).unwrap();
        
        // Test commitment
        let commitment = state.root_commitment();
        assert!(!commitment.0.is_empty());
        
        // Test proof creation
        let proof = state.create_proof(key).unwrap();
        assert_eq!(proof.0, value);
        
        // Test proof verification
        assert!(state.verify_proof(&commitment, &proof, key, value));
        
        // Test verification with wrong value
        let wrong_value = b"wrong_value";
        assert!(!state.verify_proof(&commitment, &proof, key, wrong_value));
    }
}```

######## File: core/src/state/tests/state_tree_tests.rs
#####*Size: 12K, Lines: 278, Type: ASCII text*

```rust
//! Tests for state tree interface definitions

#[cfg(test)]
mod tests {
    use crate::commitment::{CommitmentScheme, ProofContext, Selector};
    use crate::state::{StateManager, StateTree};
    use crate::test_utils::mock_commitment::{
        helpers, MockCommitment, MockCommitmentScheme, MockProof,
    };
    use std::any::Any;
    use std::collections::HashMap;

    // Mock state tree implementation for testing
    struct MockStateTree {
        data: HashMap<Vec<u8>, Vec<u8>>,
        scheme: MockCommitmentScheme,
    }

    impl MockStateTree {
        fn new() -> Self {
            Self {
                data: HashMap::new(),
                scheme: MockCommitmentScheme,
            }
        }
    }

    impl StateTree for MockStateTree {
        type Commitment = MockCommitment;
        type Proof = MockProof;

        fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), String> {
            self.data.insert(key.to_vec(), value.to_vec());
            Ok(())
        }

        fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.data.get(key).cloned()
        }

        fn delete(&mut self, key: &[u8]) -> Result<(), String> {
            self.data.remove(key);
            Ok(())
        }

        fn root_commitment(&self) -> Self::Commitment {
            let values: Vec<Option<Vec<u8>>> =
                self.data.values().map(|v| Some(v.clone())).collect();

            self.scheme.commit(&values)
        }

        fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
            let value = self.get(key)?;
            // Use key-based selector in proof creation
            let selector = Selector::Key(key.to_vec());
            self.scheme.create_proof(&selector, &value).ok()
        }

        fn verify_proof(
            &self,
            commitment: &Self::Commitment,
            proof: &Self::Proof,
            key: &[u8],
            value: &[u8],
        ) -> bool {
            // Create a context for verification
            let mut context = ProofContext::default();

            // Regenerate the selector from the key - ensure keys actually match
            let selector = Selector::Key(key.to_vec());

            // Check if the proof was created with a matching key
            if let Selector::Key(proof_key) = &proof.selector {
                if proof_key != key {
                    return false;
                }
            }

            // Convert value to Vec<u8> to match the expected type
            self.scheme
                .verify(commitment, proof, &selector, &value.to_vec(), &context)
        }

        fn commitment_scheme(&self) -> &dyn Any {
            &self.scheme
        }
    }

    // Mock state manager implementation for testing
    struct MockStateManager {
        tree: MockStateTree,
    }

    impl MockStateManager {
        fn new() -> Self {
            Self {
                tree: MockStateTree::new(),
            }
        }
    }

    impl StateManager<MockCommitmentScheme> for MockStateManager {
        fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.tree.get(key)
        }

        fn set(&mut self, key: &[u8], value: &[u8]) -> Result<(), String> {
            self.tree.insert(key, value)
        }

        fn delete(&mut self, key: &[u8]) -> Result<(), String> {
            self.tree.delete(key)
        }

        fn root_commitment(&self) -> <MockCommitmentScheme as CommitmentScheme>::Commitment {
            self.tree.root_commitment()
        }

        fn create_proof(
            &self,
            key: &[u8],
        ) -> Option<<MockCommitmentScheme as CommitmentScheme>::Proof> {
            self.tree.create_proof(key)
        }

        fn verify_proof(
            &self,
            commitment: &<MockCommitmentScheme as CommitmentScheme>::Commitment,
            proof: &<MockCommitmentScheme as CommitmentScheme>::Proof,
            key: &[u8],
            value: &[u8],
        ) -> bool {
            // Delegate to tree's verify_proof method which now uses the key
            self.tree.verify_proof(commitment, proof, key, value)
        }
    }

    #[test]
    fn test_state_tree_basic_operations() {
        let mut tree = MockStateTree::new();

        // Test insert and get
        let key1 = b"key1";
        let value1 = b"value1";

        tree.insert(key1, value1).unwrap();
        assert_eq!(tree.get(key1), Some(value1.to_vec()));

        // Test delete
        tree.delete(key1).unwrap();
        assert_eq!(tree.get(key1), None);
    }

    #[test]
    fn test_state_tree_commitments_and_proofs() {
        let mut tree = MockStateTree::new();

        let key1 = b"key1";
        let value1 = b"value1";
        let key2 = b"key2";
        let value2 = b"value2";

        tree.insert(key1, value1).unwrap();
        tree.insert(key2, value2).unwrap();

        // Test root commitment
        let commitment = tree.root_commitment();

        // Test proof creation
        let proof = tree.create_proof(key1).unwrap();

        // Test proof verification
        assert!(tree.verify_proof(&commitment, &proof, key1, value1));

        // Test invalid proof - wrong value
        let wrong_value = b"wrong_value";
        assert!(!tree.scheme.verify(
            &commitment,
            &proof,
            &Selector::Key(key1.to_vec()),
            &wrong_value.to_vec(), // Convert to Vec<u8>
            &ProofContext::default()
        ));

        // Test wrong key
        assert!(!tree.verify_proof(&commitment, &proof, key2, value1));
    }

    #[test]
    fn test_proof_context_usage() {
        let mut tree = MockStateTree::new();
        let key1 = b"key1";
        let value1 = b"value1";

        tree.insert(key1, value1).unwrap();
        let commitment = tree.root_commitment();

        // Get a proof for key1
        let proof = tree.create_proof(key1).unwrap();

        // Create a context with strict verification enabled
        let context = helpers::create_context(true);

        // Verify with context - convert value to Vec<u8>
        assert!(tree.scheme.verify(
            &commitment,
            &proof,
            &Selector::Key(key1.to_vec()),
            &value1.to_vec(), // Convert to Vec<u8>
            &context
        ));

        // Try with wrong key but same value - should fail in strict mode
        let wrong_key = b"wrong_key".to_vec();
        assert!(!tree.scheme.verify(
            &commitment,
            &proof,
            &Selector::Key(wrong_key),
            &value1.to_vec(), // Convert to Vec<u8>
            &context
        ));
    }

    #[test]
    fn test_state_manager() {
        let mut manager = MockStateManager::new();

        let key1 = b"key1";
        let value1 = b"value1";

        // Test set and get
        manager.set(key1, value1).unwrap();
        assert_eq!(manager.get(key1), Some(value1.to_vec()));

        // Test root commitment
        let commitment = manager.root_commitment();

        // Test proof creation and verification
        let proof = manager.create_proof(key1).unwrap();
        assert!(manager.verify_proof(&commitment, &proof, key1, value1));

        // Test delete
        manager.delete(key1).unwrap();
        assert_eq!(manager.get(key1), None);
    }

    #[test]
    fn test_with_helper_functions() {
        // Test the helper functions from the mock_commitment module
        let value = b"test_value";
        let key = b"test_key";

        // Create a commitment
        let commitment = helpers::create_commitment(value);

        // Create a proof
        let proof = helpers::create_key_proof(key, value).unwrap();

        // Create a context
        let context = helpers::create_context(true);

        // Verify the proof - convert value to Vec<u8>
        let scheme = MockCommitmentScheme;
        assert!(scheme.verify(
            &commitment,
            &proof,
            &Selector::Key(key.to_vec()),
            &value.to_vec(), // Convert to Vec<u8>
            &context
        ));
    }
}
// TODO: Add more comprehensive tests covering:
// - Complex state tree operations with multiple keys
// - Proof verification across different states
// - State transition validations
// - Edge cases like empty trees, large values, etc.
```

####### File: core/src/state/manager.rs
####*Size: 4.0K, Lines: 21, Type: ASCII text*

```rust
// Path: crates/core/src/state/manager.rs

use crate::error::StateError;
use crate::state::StateTree;

/// State manager interface for the DePIN SDK.
///
/// `StateManager` is a higher-level abstraction that must also be a `StateTree`.
/// It provides all the same core methods as `StateTree` (via inheritance) and
/// adds batching capabilities.
pub trait StateManager: StateTree {
    // REMOVED: All redundant associated types and method signatures from StateTree are gone.
    // They are inherited automatically.

    /// Set multiple key-value pairs in a single batch operation.
    /// This is now a required method for any implementor of StateManager.
    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError>;

    /// Get multiple values by keys in a single batch operation.
    /// This is now a required method.
    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError>;
}```

####### File: core/src/state/mod.rs
####*Size: 4.0K, Lines: 25, Type: ASCII text*

```rust
// Path: crates/core/src/state/mod.rs

//! State management interfaces for the DePIN SDK Core.

mod manager;
mod tree;

#[cfg(test)]
mod tests;

pub use manager::*;
pub use tree::*;

use crate::commitment::CommitmentScheme;

/// Type alias for a StateManager trait object compatible with a specific CommitmentScheme.
pub type StateManagerFor<CS> = dyn StateManager<
    Commitment = <CS as CommitmentScheme>::Commitment,
    Proof = <CS as CommitmentScheme>::Proof,
>;

/// Type alias for a StateTree trait object compatible with a specific CommitmentScheme.
pub type StateTreeFor<CS> = dyn StateTree<
    Commitment = <CS as CommitmentScheme>::Commitment,
    Proof = <CS as CommitmentScheme>::Proof,
>;```

####### File: core/src/state/tree.rs
####*Size: 4.0K, Lines: 65, Type: ASCII text*

```rust
// File: crates/core/src/state/tree.rs

use std::any::Any;
use crate::error::StateError;

/// Generic state tree operations
///
/// A StateTree provides key-value storage with optional cryptographic
/// commitment and proof capabilities. It's the lower-level interface
/// intended for direct tree implementations (Merkle trees, sparse
/// Merkle trees, Patricia tries, etc.).
pub trait StateTree {
    /// The commitment type this tree uses
    type Commitment;
    
    /// The proof type this tree uses
    type Proof;

    /// Get a value by key
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError>;
    
    /// Insert a key-value pair
    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError>;
    
    /// Delete a key-value pair
    fn delete(&mut self, key: &[u8]) -> Result<(), StateError>;
    
    /// Get the root commitment of the tree
    ///
    /// # Returns
    /// * The current root commitment
    fn root_commitment(&self) -> Self::Commitment;
    
    /// Create a proof for a specific key
    ///
    /// # Arguments
    /// * `key` - The key to create a proof for
    ///
    /// # Returns
    /// * `Some(proof)` - If proof creation succeeded
    /// * `None` - If the key doesn't exist or proof creation isn't supported
    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof>;
    
    /// Verify a proof against the tree's root commitment
    ///
    /// # Arguments
    /// * `commitment` - The commitment to verify against
    /// * `proof` - The proof to verify
    /// * `key` - The key the proof is for
    /// * `value` - The value to verify
    ///
    /// # Returns
    /// * `true` - If the proof is valid
    /// * `false` - If the proof is invalid or verification isn't supported
    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8]
    ) -> bool;

    /// Provide access to the concrete type for downcasting.
    fn as_any(&self) -> &dyn Any;
    
}```

###### Directory: core/src/test_utils

####### File: core/src/test_utils/mock_commitment.rs
####*Size: 8.0K, Lines: 172, Type: ASCII text*

```rust
//! Mock commitment scheme for testing

use crate::commitment::{CommitmentScheme, ProofContext, SchemeIdentifier, Selector};

/// Mock commitment scheme implementation for testing
#[derive(Debug, Clone)]
pub struct MockCommitmentScheme;

/// Mock commitment for testing
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockCommitment(pub Vec<u8>);

impl AsRef<[u8]> for MockCommitment {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Mock proof for testing
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockProof {
    /// Selector used to create this proof
    pub selector: Selector,
    /// Value that this proof is for
    pub value: Vec<u8>,
}

impl CommitmentScheme for MockCommitmentScheme {
    type Commitment = MockCommitment;
    type Proof = MockProof;
    type Value = Vec<u8>;

    fn commit(&self, values: &[Option<Self::Value>]) -> Self::Commitment {
        // Implementation actually combines all values into a single commitment
        let mut combined = Vec::new();
        for v in values {
            if let Some(data) = v {
                combined.extend_from_slice(data.as_ref());
            }
        }
        MockCommitment(combined)
    }

    fn create_proof(
        &self,
        selector: &Selector,
        value: &Self::Value,
    ) -> Result<Self::Proof, String> {
        // Store both selector and value in the proof
        Ok(MockProof {
            selector: selector.clone(),
            value: value.clone(),
        })
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        selector: &Selector,
        value: &Self::Value,
        context: &ProofContext,
    ) -> bool {
        // 1. Check that selector types match
        if !matches!(&proof.selector, selector) {
            return false;
        }

        // 2. Check value matches - comparing the raw bytes
        let value_slice: &[u8] = value.as_ref();
        if proof.value.as_slice() != value_slice {
            return false;
        }

        // 3. Use commitment in verification - in real world this would be cryptographic
        // For our mock, we'll check if the commitment contains the value
        let commitment_slice: &[u8] = commitment.as_ref();
        let contains_value = commitment_slice
            .windows(value_slice.len())
            .any(|window| window == value_slice);
        if !contains_value {
            return false;
        }

        // 4. Use context for additional verification parameters
        // In this mock, we'll check if a special "strict_verify" flag is set
        if let Some(strict_flag) = context.get_data("strict_verify") {
            if !strict_flag.is_empty() && strict_flag[0] == 1 {
                // In strict mode, we also check selector-specific rules
                match selector {
                    Selector::Position(pos) => {
                        // Position-based verification
                        if let Selector::Position(proof_pos) = &proof.selector {
                            if pos != proof_pos {
                                return false;
                            }
                        } else {
                            return false;
                        }
                    }
                    Selector::Key(key) => {
                        // Key-based verification
                        if let Selector::Key(proof_key) = &proof.selector {
                            if key != proof_key {
                                return false;
                            }
                        } else {
                            return false;
                        }
                    }
                    _ => {
                        // For other selectors, just ensure they match exactly
                        if proof.selector != *selector {
                            return false;
                        }
                    }
                }
            }
        }

        // If we made it here, verification passed
        true
    }

    fn scheme_id() -> SchemeIdentifier {
        SchemeIdentifier::new("mock")
    }
}

/// Helper functions for testing with mock commitment scheme
pub mod helpers {
    use super::*;

    /// Create a mock commitment from a single value
    pub fn create_commitment<T: AsRef<[u8]>>(value: T) -> MockCommitment {
        let scheme = MockCommitmentScheme;
        // Convert to Vec<u8> since the CommitmentScheme's Value type is Vec<u8>
        scheme.commit(&[Some(value.as_ref().to_vec())])
    }

    /// Create a mock proof for a value with position selector
    pub fn create_position_proof<T: AsRef<[u8]>>(
        position: usize,
        value: T,
    ) -> Result<MockProof, String> {
        let scheme = MockCommitmentScheme;
        // Convert to Vec<u8> since the CommitmentScheme's Value type is Vec<u8>
        scheme.create_proof(&Selector::Position(position), &value.as_ref().to_vec())
    }

    /// Create a mock proof for a value with key selector
    pub fn create_key_proof<K: AsRef<[u8]>, V: AsRef<[u8]>>(
        key: K,
        value: V,
    ) -> Result<MockProof, String> {
        let scheme = MockCommitmentScheme;
        // Convert to Vec<u8> since the CommitmentScheme's Value type is Vec<u8>
        scheme.create_proof(
            &Selector::Key(key.as_ref().to_vec()),
            &value.as_ref().to_vec(),
        )
    }

    /// Create a verification context for testing
    pub fn create_context(strict: bool) -> ProofContext {
        let mut context = ProofContext::default();
        if strict {
            context.add_data("strict_verify", vec![1]);
        }
        context
    }
}
```

####### File: core/src/test_utils/mod.rs
####*Size: 4.0K, Lines: 3, Type: ASCII text*

```rust
//! Test utilities for the DePIN SDK Core

pub mod mock_commitment;
```

###### Directory: core/src/transaction

####### Directory: core/src/transaction/tests

######## File: core/src/transaction/tests/mod.rs
#####*Size: 4.0K, Lines: 1, Type: ASCII text*

```rust
mod transaction_model_tests;
```

######## File: core/src/transaction/tests/transaction_model_tests.rs
#####*Size: 12K, Lines: 351, Type: ASCII text*

```rust
//! Tests for transaction model trait definitions

#[cfg(test)]
mod tests {
    use crate::commitment::{CommitmentScheme, ProofContext, SchemeIdentifier, Selector};
    use crate::state::StateManager;
    use crate::transaction::{Error, TransactionModel};
    use std::collections::HashMap;

    // Mock commitment scheme implementation for testing
    #[derive(Debug, Clone)]
    struct MockCommitmentScheme;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MockCommitment(Vec<u8>);

    impl AsRef<[u8]> for MockCommitment {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MockProof {
        position: usize,
        value: Vec<u8>,
    }

    impl CommitmentScheme for MockCommitmentScheme {
        type Commitment = MockCommitment;
        type Proof = MockProof;
        type Value = Vec<u8>; // Still using Vec<u8> but will access via as_ref()

        fn commit(&self, values: &[Option<Self::Value>]) -> Self::Commitment {
            // Simple implementation for testing
            let mut combined = Vec::new();
            for v in values {
                if let Some(data) = v {
                    combined.extend_from_slice(data.as_ref());
                }
            }
            MockCommitment(combined)
        }

        fn create_proof(
            &self,
            selector: &Selector,
            value: &Self::Value,
        ) -> Result<Self::Proof, String> {
            // Extract position from selector
            let position = match selector {
                Selector::Position(pos) => *pos,
                _ => 0, // Default to position 0 for other selector types
            };

            Ok(MockProof {
                position,
                value: value.clone(),
            })
        }

        fn verify(
            &self,
            _commitment: &Self::Commitment,
            proof: &Self::Proof,
            selector: &Selector,
            value: &Self::Value,
            _context: &ProofContext, // Added context parameter
        ) -> bool {
            // Extract position from selector if it's a position-based selector
            match selector {
                Selector::Position(pos) => proof.position == *pos && proof.value == *value,
                Selector::Key(_) => proof.value == *value, // For key-based selectors, only check value
                _ => false, // Other selector types not supported in this implementation
            }
        }

        fn scheme_id() -> SchemeIdentifier {
            SchemeIdentifier::new("mock")
        }
    }

    // Mock state manager implementation for testing
    struct MockStateManager {
        state: HashMap<Vec<u8>, Vec<u8>>,
        scheme: MockCommitmentScheme,
    }

    impl MockStateManager {
        fn new() -> Self {
            Self {
                state: HashMap::new(),
                scheme: MockCommitmentScheme,
            }
        }
    }

    impl StateManager<MockCommitmentScheme> for MockStateManager {
        fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.state.get(key).cloned()
        }

        fn set(&mut self, key: &[u8], value: &[u8]) -> Result<(), String> {
            self.state.insert(key.to_vec(), value.to_vec());
            Ok(())
        }

        fn delete(&mut self, key: &[u8]) -> Result<(), String> {
            self.state.remove(key);
            Ok(())
        }

        fn root_commitment(&self) -> <MockCommitmentScheme as CommitmentScheme>::Commitment {
            let values: Vec<Option<Vec<u8>>> =
                self.state.values().map(|v| Some(v.clone())).collect();

            self.scheme.commit(&values)
        }

        fn create_proof(
            &self,
            key: &[u8],
        ) -> Option<<MockCommitmentScheme as CommitmentScheme>::Proof> {
            let value = self.get(key)?;
            self.scheme
                .create_proof(&Selector::Position(0), &value)
                .ok()
        }

        fn verify_proof(
            &self,
            _commitment: &<MockCommitmentScheme as CommitmentScheme>::Commitment,
            proof: &<MockCommitmentScheme as CommitmentScheme>::Proof,
            _key: &[u8],
            value: &[u8],
        ) -> bool {
            // Updated to include context parameter and use Position selector
            self.scheme.verify(
                &self.root_commitment(),
                proof,
                &Selector::Position(proof.position),
                &value.to_vec(), // Convert slice to Vec<u8> for Value type
                &ProofContext::default(),
            )
        }
    }

    // Mock transaction model for testing

    // Mock UTXO-style transaction model
    #[derive(Debug, Clone)]
    struct MockUTXOTransaction {
        txid: Vec<u8>,
        inputs: Vec<MockUTXOInput>,
        outputs: Vec<MockUTXOOutput>,
    }

    #[derive(Debug, Clone)]
    struct MockUTXOInput {
        prev_txid: Vec<u8>,
        prev_index: u32,
        signature: Vec<u8>,
    }

    #[derive(Debug, Clone)]
    struct MockUTXOOutput {
        value: u64,
        recipient: Vec<u8>,
    }

    #[derive(Debug, Clone)]
    struct MockUTXOProof {
        proof: MockProof,
    }

    // Mock transaction model implementation
    struct MockTransactionModel {
        scheme: MockCommitmentScheme,
    }

    impl MockTransactionModel {
        fn new() -> Self {
            Self {
                scheme: MockCommitmentScheme,
            }
        }

        // Helper method to create a unique UTXO key from txid and output index
        fn create_utxo_key(txid: &[u8], output_index: u32) -> Vec<u8> {
            let mut key = txid.to_vec();
            key.extend_from_slice(&output_index.to_le_bytes());
            key
        }
    }

    impl TransactionModel<MockCommitmentScheme> for MockTransactionModel {
        type Transaction = MockUTXOTransaction;
        type Proof = MockUTXOProof;

        fn validate(&self, tx: &Self::Transaction, _commitment: &MockCommitment) -> bool {
            // Simple validation for testing
            !tx.inputs.is_empty() && !tx.outputs.is_empty()
        }

        fn apply(
            &self,
            tx: &Self::Transaction,
            state: &mut dyn StateManager<MockCommitmentScheme>,
        ) -> Result<(), String> {
            // Simple application logic for testing
            for input in &tx.inputs {
                // Create a key for the UTXO being spent using the helper method
                let key = Self::create_utxo_key(&input.prev_txid, input.prev_index);
                state.delete(&key)?;
            }

            for (i, output) in tx.outputs.iter().enumerate() {
                // Create a unique key for each output using the helper method
                let key = Self::create_utxo_key(&tx.txid, i as u32);

                // Simple manual serialization instead of using bincode
                let mut value = Vec::new();
                // Serialize value
                value.extend_from_slice(&output.value.to_le_bytes());
                // Serialize recipient length
                value.extend_from_slice(&(output.recipient.len() as u32).to_le_bytes());
                // Serialize recipient
                value.extend_from_slice(&output.recipient);

                state.set(&key, &value)?;
            }

            Ok(())
        }
    }

    #[test]
    fn test_transaction_validation() {
        let model = MockTransactionModel::new();
        let commitment = MockCommitment(vec![0]);

        // Valid transaction
        let valid_tx = MockUTXOTransaction {
            txid: vec![1, 2, 3],
            inputs: vec![MockUTXOInput {
                prev_txid: vec![4, 5, 6],
                prev_index: 0,
                signature: vec![7, 8, 9],
            }],
            outputs: vec![MockUTXOOutput {
                value: 100,
                recipient: vec![10, 11, 12],
            }],
        };

        assert!(model.validate(&valid_tx, &commitment));

        // Invalid transaction - no inputs
        let invalid_tx = MockUTXOTransaction {
            txid: vec![1, 2, 3],
            inputs: vec![],
            outputs: vec![MockUTXOOutput {
                value: 100,
                recipient: vec![10, 11, 12],
            }],
        };

        assert!(!model.validate(&invalid_tx, &commitment));
    }

    #[test]
    fn test_transaction_application() {
        let model = MockTransactionModel::new();
        let mut state = MockStateManager::new();

        // Set up initial state
        let prev_txid = vec![4, 5, 6];
        let prev_index = 0;

        // Create the UTXO key using the helper method
        let prev_utxo_key = MockTransactionModel::create_utxo_key(&prev_txid, prev_index);

        // Simple manual serialization instead of using bincode
        let mut prev_output = Vec::new();
        // Serialize value
        prev_output.extend_from_slice(&100u64.to_le_bytes());
        // Serialize recipient length
        prev_output.extend_from_slice(&(3u32).to_le_bytes());
        // Serialize recipient
        prev_output.extend_from_slice(&[7, 8, 9]);

        state.set(&prev_utxo_key, &prev_output).unwrap();

        // Create and apply transaction
        let tx = MockUTXOTransaction {
            txid: vec![1, 2, 3],
            inputs: vec![MockUTXOInput {
                prev_txid: prev_txid.clone(),
                prev_index,
                signature: vec![10, 11, 12],
            }],
            outputs: vec![
                MockUTXOOutput {
                    value: 50,
                    recipient: vec![13, 14, 15],
                },
                MockUTXOOutput {
                    value: 50,
                    recipient: vec![16, 17, 18],
                },
            ],
        };

        model.apply(&tx, &mut state).unwrap();

        // Verify state changes
        assert_eq!(state.get(&prev_utxo_key), None); // Input was spent

        // Check that both outputs were created with their proper keys
        let output0_key = MockTransactionModel::create_utxo_key(&tx.txid, 0);
        let output1_key = MockTransactionModel::create_utxo_key(&tx.txid, 1);

        assert!(state.get(&output0_key).is_some()); // First output was created
        assert!(state.get(&output1_key).is_some()); // Second output was created
    }

    #[test]
    fn test_error_handling() {
        // Test the Error enum formatting
        let invalid_error = Error::Invalid("test error".to_string());
        let insufficient_error = Error::InsufficientFunds;
        let nonce_error = Error::NonceMismatch;
        let signature_error = Error::InvalidSignature;
        let other_error = Error::Other("other error".to_string());

        assert_eq!(
            format!("{}", invalid_error),
            "Invalid transaction: test error"
        );
        assert_eq!(format!("{}", insufficient_error), "Insufficient funds");
        assert_eq!(format!("{}", nonce_error), "Nonce mismatch");
        assert_eq!(format!("{}", signature_error), "Invalid signature");
        assert_eq!(format!("{}", other_error), "Other error: other error");
    }

    // TODO: Add more comprehensive tests covering:
    // - Different transaction models (UTXO, account-based)
    // - Transaction validation rules
    // - Error cases in transaction application
    // - Complex state changes
}
```

####### File: core/src/transaction/mod.rs
####*Size: 8.0K, Lines: 153, Type: ASCII text*

```rust
// File: crates/core/src/transaction/mod.rs

use crate::commitment::CommitmentScheme;
use crate::error::TransactionError;
use crate::state::StateManager;
use std::any::Any;
use std::fmt::Debug;

/// Core transaction model trait that defines the interface for all transaction models.
///
/// This trait is intentionally model-agnostic, allowing for different implementations
/// (UTXO, account-based, hybrid, etc.) while providing a consistent interface.
pub trait TransactionModel {
    /// The transaction type for this model.
    type Transaction: Debug;

    /// The proof type for this model.
    type Proof;

    /// The commitment scheme used by this model.
    type CommitmentScheme: CommitmentScheme;

    /// Creates a "coinbase" or block reward transaction.
    ///
    /// This provides a generic way for a block producer (like the OrchestrationContainer)
    /// to create the first, special transaction in a block without needing to know the
    /// specific details of the transaction model.
    ///
    /// # Arguments
    /// * `block_height` - The height of the block this transaction will be in.
    /// * `recipient` - The public key or address of the block producer who should receive the reward.
    ///
    /// # Returns
    /// * `Ok(transaction)` - A valid coinbase transaction.
    /// * `Err(TransactionError)` - If the coinbase transaction could not be created.
    fn create_coinbase_transaction(
        &self,
        block_height: u64,
        recipient: &[u8],
    ) -> Result<Self::Transaction, TransactionError>;

    /// Validate a transaction against the current state.
    ///
    /// # Arguments
    /// * `tx` - The transaction to validate.
    /// * `state` - The state to validate against.
    ///
    /// # Returns
    /// * `Ok(true)` - If the transaction is valid.
    /// * `Ok(false)` - If the transaction is invalid.
    /// * `Err(TransactionError)` - If an error occurred during validation.
    fn validate<S>(&self, tx: &Self::Transaction, state: &S) -> Result<bool, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized;

    /// Apply a transaction to the state.
    ///
    /// # Arguments
    /// * `tx` - The transaction to apply.
    /// * `state` - The state to modify.
    ///
    /// # Returns
    /// * `Ok(())` - If the transaction was successfully applied.
    /// * `Err(TransactionError)` - If an error occurred during application.
    fn apply<S>(&self, tx: &Self::Transaction, state: &mut S) -> Result<(), TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized;

    /// Generate a proof for a transaction.
    ///
    /// # Arguments
    /// * `tx` - The transaction to generate a proof for.
    /// * `state` - The state to generate the proof against.
    ///
    /// # Returns
    /// * `Ok(proof)` - If the proof was successfully generated.
    /// * `Err(TransactionError)` - If an error occurred during proof generation.
    fn generate_proof<S>(
        &self,
        tx: &Self::Transaction,
        state: &S,
    ) -> Result<Self::Proof, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized;

    /// Verify a proof for a transaction.
    ///
    /// # Arguments
    /// * `proof` - The proof to verify.
    /// * `state` - The state to verify against.
    ///
    /// # Returns
    /// * `Ok(true)` - If the proof is valid.
    /// * `Ok(false)` - If the proof is invalid.
    /// * `Err(TransactionError)` - If an error occurred during verification.
    fn verify_proof<S>(&self, proof: &Self::Proof, state: &S) -> Result<bool, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized;

    /// Serialize a transaction to bytes.
    fn serialize_transaction(&self, tx: &Self::Transaction) -> Result<Vec<u8>, TransactionError>;

    /// Deserialize bytes to a transaction.
    fn deserialize_transaction(&self, data: &[u8]) -> Result<Self::Transaction, TransactionError>;

    /// Optional extension point for model-specific functionality.
    fn get_model_extensions(&self) -> Option<&dyn Any> {
        None
    }
}

/// Registry for managing multiple transaction models at runtime.
#[derive(Default)]
pub struct TransactionModelRegistry {
    models: std::collections::HashMap<String, Box<dyn Any>>,
}

impl TransactionModelRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            models: std::collections::HashMap::new(),
        }
    }

    /// Register a transaction model.
    pub fn register<T: TransactionModel + 'static>(&mut self, name: &str, model: T) {
        self.models.insert(name.to_string(), Box::new(model));
    }

    /// Get a registered transaction model.
    pub fn get<T: 'static>(&self, name: &str) -> Option<&T> {
        self.models
            .get(name)
            .and_then(|model| model.downcast_ref::<T>())
    }

    /// Check if a model is registered.
    pub fn has_model(&self, name: &str) -> bool {
        self.models.contains_key(name)
    }
}```

###### Directory: core/src/types

####### File: core/src/types/mod.rs
####*Size: 4.0K, Lines: 50, Type: ASCII text*

```rust
// Path: crates/core/src/types/mod.rs

//! Type aliases and common types for the DePIN SDK

use crate::commitment::CommitmentScheme;
use crate::state::StateManager;
use crate::transaction::TransactionModel;

/// Type aliases for commitment schemes.
pub mod commitment {
    use super::*;

    /// The commitment type for a given commitment scheme.
    pub type CommitmentOf<CS> = <CS as CommitmentScheme>::Commitment;

    /// The proof type for a given commitment scheme.
    pub type ProofOf<CS> = <CS as CommitmentScheme>::Proof;

    /// The value type for a given commitment scheme.
    pub type ValueOf<CS> = <CS as CommitmentScheme>::Value;
}

/// Type aliases for state management.
pub mod state {
    use super::*;

    /// Type alias for a `StateManager` trait object that is compatible with a
    /// specific `CommitmentScheme`. This is now unambiguous because `StateManager`
    /// inherits its associated types directly from its `StateTree` supertrait.
    pub type StateManagerFor<CS>
    where
        CS: CommitmentScheme,
    = dyn StateManager<
        Commitment = <CS as CommitmentScheme>::Commitment,
        Proof = <CS as CommitmentScheme>::Proof,
    >;
}

/// Type aliases for transaction models.
pub mod transaction {
    use super::*;

    /// The transaction type for a given transaction model.
    pub type TransactionOf<TM> = <TM as TransactionModel>::Transaction;

    /// The proof type for a given transaction model.
    pub type ProofOf<TM> = <TM as TransactionModel>::Proof;

    /// The commitment scheme type for a given transaction model.
    pub type CommitmentSchemeOf<TM> = <TM as TransactionModel>::CommitmentScheme;
}```

###### Directory: core/src/validator

####### Directory: core/src/validator/container

######## File: core/src/validator/container/mod.rs
#####*Size: 4.0K, Lines: 24, Type: ASCII text*

```rust
// Path: crates/core/src/validator/container/mod.rs

use crate::error::ValidatorError;
use async_trait::async_trait;

/// A trait for any component that can be started and stopped.
#[async_trait]
pub trait Container {
    /// A unique identifier for the container.
    fn id(&self) -> &'static str;
    /// Returns true if the container is currently running.
    fn is_running(&self) -> bool;
    /// Starts the container's logic.
    async fn start(&self) -> Result<(), ValidatorError>;
    /// Stops the container's logic.
    async fn stop(&self) -> Result<(), ValidatorError>;
}

/// A trait for the Guardian container, responsible for secure boot and attestation.
pub trait GuardianContainer: Container {
    /// Initiates the secure boot process.
    fn start_boot(&self) -> Result<(), ValidatorError>;
    /// Verifies the attestation of other containers.
    fn verify_attestation(&self) -> Result<bool, ValidatorError>;
}```

####### Directory: core/src/validator/tests

######## File: core/src/validator/tests/mod.rs
#####*Size: 8.0K, Lines: 241, Type: ASCII text*

```rust
//! Tests for validator architecture trait definitions

#[cfg(test)]
mod tests {
    use crate::validator::container::GuardianContainer;
    use crate::validator::{Container, ValidatorModel, ValidatorType};

    // Mock container implementation for testing
    struct MockContainer {
        id: String,
        running: bool,
    }

    impl MockContainer {
        fn new(id: &str) -> Self {
            Self {
                id: id.to_string(),
                running: false,
            }
        }
    }

    impl Container for MockContainer {
        fn start(&self) -> Result<(), String> {
            // In a real implementation, this would start the container
            Ok(())
        }

        fn stop(&self) -> Result<(), String> {
            // In a real implementation, this would stop the container
            Ok(())
        }

        fn is_running(&self) -> bool {
            self.running
        }

        fn id(&self) -> &str {
            &self.id
        }
    }

    // Mock guardian container implementation for testing
    struct MockGuardianContainer {
        container: MockContainer,
    }

    impl MockGuardianContainer {
        fn new(id: &str) -> Self {
            Self {
                container: MockContainer::new(id),
            }
        }
    }

    impl Container for MockGuardianContainer {
        fn start(&self) -> Result<(), String> {
            self.container.start()
        }

        fn stop(&self) -> Result<(), String> {
            self.container.stop()
        }

        fn is_running(&self) -> bool {
            self.container.is_running()
        }

        fn id(&self) -> &str {
            self.container.id()
        }
    }

    impl GuardianContainer for MockGuardianContainer {
        fn start_boot(&self) -> Result<(), String> {
            // In a real implementation, this would start the boot process
            Ok(())
        }

        fn verify_attestation(&self) -> Result<bool, String> {
            // In a real implementation, this would verify attestation
            Ok(true)
        }
    }

    // Mock validator model implementation for testing
    struct MockStandardValidator {
        guardian: MockGuardianContainer,
        orchestration: MockContainer,
        workload: MockContainer,
        running: bool,
    }

    impl MockStandardValidator {
        fn new() -> Self {
            Self {
                guardian: MockGuardianContainer::new("guardian"),
                orchestration: MockContainer::new("orchestration"),
                workload: MockContainer::new("workload"),
                running: false,
            }
        }
    }

    impl ValidatorModel for MockStandardValidator {
        fn start(&self) -> Result<(), String> {
            // In a real implementation, this would start all containers in the correct order
            self.guardian.start_boot()?;
            self.orchestration.start()?;
            self.workload.start()?;
            Ok(())
        }

        fn stop(&self) -> Result<(), String> {
            // In a real implementation, this would stop all containers in the correct order
            self.workload.stop()?;
            self.orchestration.stop()?;
            Ok(())
        }

        fn is_running(&self) -> bool {
            self.running
        }

        fn validator_type(&self) -> ValidatorType {
            ValidatorType::Standard
        }
    }

    // Mock hybrid validator implementation for testing
    struct MockHybridValidator {
        guardian: MockGuardianContainer,
        orchestration: MockContainer,
        workload: MockContainer,
        interface: MockContainer,
        api: MockContainer,
        running: bool,
    }

    impl MockHybridValidator {
        fn new() -> Self {
            Self {
                guardian: MockGuardianContainer::new("guardian"),
                orchestration: MockContainer::new("orchestration"),
                workload: MockContainer::new("workload"),
                interface: MockContainer::new("interface"),
                api: MockContainer::new("api"),
                running: false,
            }
        }
    }

    impl ValidatorModel for MockHybridValidator {
        fn start(&self) -> Result<(), String> {
            // In a real implementation, this would start all containers in the correct order
            self.guardian.start_boot()?;
            self.orchestration.start()?;
            self.workload.start()?;
            self.interface.start()?;
            self.api.start()?;
            Ok(())
        }

        fn stop(&self) -> Result<(), String> {
            // In a real implementation, this would stop all containers in the correct order
            self.api.stop()?;
            self.interface.stop()?;
            self.workload.stop()?;
            self.orchestration.stop()?;
            Ok(())
        }

        fn is_running(&self) -> bool {
            self.running
        }

        fn validator_type(&self) -> ValidatorType {
            ValidatorType::Hybrid
        }
    }

    #[test]
    fn test_container() {
        let container = MockContainer::new("test-container");

        assert_eq!(container.id(), "test-container");
        assert!(!container.is_running());

        container.start().unwrap();
        container.stop().unwrap();
    }

    #[test]
    fn test_guardian_container() {
        let guardian = MockGuardianContainer::new("guardian");

        assert_eq!(guardian.id(), "guardian");
        assert!(!guardian.is_running());

        guardian.start().unwrap();
        guardian.start_boot().unwrap();
        assert!(guardian.verify_attestation().unwrap());
        guardian.stop().unwrap();
    }

    #[test]
    fn test_standard_validator() {
        let validator = MockStandardValidator::new();

        assert_eq!(validator.validator_type(), ValidatorType::Standard);
        assert!(!validator.is_running());

        validator.start().unwrap();
        validator.stop().unwrap();
    }

    #[test]
    fn test_hybrid_validator() {
        let validator = MockHybridValidator::new();

        assert_eq!(validator.validator_type(), ValidatorType::Hybrid);
        assert!(!validator.is_running());

        validator.start().unwrap();
        validator.stop().unwrap();
    }

    #[test]
    fn test_validator_type_comparison() {
        assert_eq!(ValidatorType::Standard, ValidatorType::Standard);
        assert_eq!(ValidatorType::Hybrid, ValidatorType::Hybrid);
        assert_ne!(ValidatorType::Standard, ValidatorType::Hybrid);
    }

    // TODO: Add more comprehensive tests covering:
    // - Container lifecycle management
    // - Error handling in container operations
    // - Security boundaries between containers
    // - Container attestation verification
    // - Complex validator configurations
}
```

####### File: core/src/validator/mod.rs
####*Size: 4.0K, Lines: 62, Type: ASCII text*

```rust
// Path: crates/core/src/validator/mod.rs

use crate::{
    config::WorkloadConfig,
    error::ValidatorError,
    state::{StateManager, StateTree},
};
use std::fmt::Debug;
use std::sync::Arc;
use tokio::sync::Mutex;

// FIX: Declare the container module so it's part of the `validator` module.
pub mod container;

// FIX: Publicly re-export the traits using a relative path.
pub use container::{Container, GuardianContainer};

/// A container responsible for executing transactions and managing state.
#[derive(Debug)]
pub struct WorkloadContainer<ST: StateManager> {
    _config: WorkloadConfig,
    state_tree: Arc<Mutex<ST>>,
}

impl<ST> WorkloadContainer<ST>
where
    ST: StateManager,
{
    pub fn new(config: WorkloadConfig, state_tree: ST) -> Self {
        Self {
            _config: config,
            state_tree: Arc::new(Mutex::new(state_tree)),
        }
    }

    pub fn state_tree(&self) -> Arc<Mutex<ST>> {
        self.state_tree.clone()
    }
}

#[async_trait::async_trait]
impl<ST> Container for WorkloadContainer<ST>
where
    ST: StateManager + StateTree + Send + Sync + 'static,
{
    async fn start(&self) -> Result<(), ValidatorError> {
        log::info!("WorkloadContainer started.");
        Ok(())
    }

    async fn stop(&self) -> Result<(), ValidatorError> {
        log::info!("WorkloadContainer stopped.");
        Ok(())
    }

    fn is_running(&self) -> bool {
        true
    }

    fn id(&self) -> &'static str {
        "workload_container"
    }
}```

####### File: core/src/validator/types.rs
####*Size: 4.0K, Lines: 32, Type: ASCII text*

```rust
//! Validator type definitions
use crate::error::ValidatorError;

/// Validator model trait
pub trait ValidatorModel {
    /// An associated type representing the specific WorkloadContainer implementation this validator uses.
    /// This allows us to access it generically without knowing the validator's concrete type.
    type WorkloadContainerType;

    /// Start the validator
    fn start(&self) -> Result<(), ValidatorError>;

    /// Stop the validator
    fn stop(&self) -> Result<(), ValidatorError>;

    /// Check if the validator is running
    fn is_running(&self) -> bool;

    /// Get the validator type
    fn validator_type(&self) -> ValidatorType;

    /// Provides generic access to the validator's workload container.
    fn workload_container(&self) -> &Self::WorkloadContainerType;
}

/// Validator types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorType {
    /// Standard validator (3 containers)
    Standard,
    /// Hybrid validator (5 containers)
    Hybrid,
}```

###### File: core/src/lib.rs
###*Size: 4.0K, Lines: 36, Type: ASCII text*

```rust
//! # DePIN SDK Core
//!
//! Core traits and interfaces for the DePIN SDK.

pub mod app;
pub mod chain;
pub mod commitment;
pub mod component;
// NEW: A module for shared configuration structs.
pub mod config;
pub mod crypto;
pub mod error;
pub mod homomorphic;
pub mod ibc;
pub mod services;
pub mod state;
pub mod transaction;
pub mod types;
pub mod validator;

#[cfg(test)]
pub mod test_utils;

// Re-export key traits and types for convenience
pub use app::*;
pub use chain::*;
pub use commitment::*;
pub use component::*;
pub use config::*;
pub use crypto::*;
pub use error::*;
pub use homomorphic::*;
pub use ibc::*;
pub use services::*;
pub use state::*;
pub use transaction::*;
pub use validator::*;```

##### File: core/Cargo.toml
##*Size: 4.0K, Lines: 23, Type: ASCII text*

```toml
# Path: crates/core/Cargo.toml

[package]
name = "depin-sdk-core"
version = "0.1.0"
edition = "2021"
description = "Core types and traits for the DePIN SDK"
license = "MIT OR Apache-2.0"

[dependencies]
# FIX: Add async-trait as a dependency, which is now required by the Container trait.
async-trait = { workspace = true }
log = { workspace = true }
serde = { workspace = true, features = ["derive"] }
serde_json = { workspace = true }
thiserror = { workspace = true }
bytes = { workspace = true }
tokio = { workspace = true, features = ["sync"] }

[features]
default = []
homomorphic = []
post-quantum = []
```

#### Directory: crypto

##### Directory: crypto/src

###### Directory: crypto/src/algorithms

####### Directory: crypto/src/algorithms/hash

######## File: crypto/src/algorithms/hash/mod.rs
#####*Size: 4.0K, Lines: 104, Type: ASCII text*

```rust
// crates/crypto/src/algorithms/hash/mod.rs
//! Cryptographic hash functions using dcrypt

use dcrypt::algorithms::hash::sha2::{Sha256 as DcryptSha256, Sha512 as DcryptSha512};
use dcrypt::algorithms::hash::{HashFunction as DcryptHashFunction};
use dcrypt::algorithms::ByteSerializable;

pub mod tests;

/// Hash function trait
pub trait HashFunction {
    /// Hash a message and return the digest
    fn hash(&self, message: &[u8]) -> Vec<u8>;
    
    /// Get the digest size in bytes
    fn digest_size(&self) -> usize;
    
    /// Get the name of the hash function
    fn name(&self) -> &str;
}

/// SHA-256 hash function implementation using dcrypt
#[derive(Default, Clone)]
pub struct Sha256Hash;

impl HashFunction for Sha256Hash {
    fn hash(&self, message: &[u8]) -> Vec<u8> {
        // Use dcrypt's SHA-256 implementation
        match DcryptSha256::digest(message) {
            Ok(digest) => digest.to_bytes(),
            Err(_) => panic!("SHA-256 hashing failed"),
        }
    }
    
    fn digest_size(&self) -> usize {
        32 // 256 bits = 32 bytes
    }
    
    fn name(&self) -> &str {
        "SHA-256"
    }
}

/// SHA-512 hash function implementation using dcrypt
#[derive(Default, Clone)]
pub struct Sha512Hash;

impl HashFunction for Sha512Hash {
    fn hash(&self, message: &[u8]) -> Vec<u8> {
        // Use dcrypt's SHA-512 implementation
        match DcryptSha512::digest(message) {
            Ok(digest) => digest.to_bytes(),
            Err(_) => panic!("SHA-512 hashing failed"),
        }
    }
    
    fn digest_size(&self) -> usize {
        64 // 512 bits = 64 bytes
    }
    
    fn name(&self) -> &str {
        "SHA-512"
    }
}

/// Generic hasher that can use any hash function
pub struct GenericHasher<H: HashFunction> {
    /// Hash function implementation
    hash_function: H,
}

impl<H: HashFunction> GenericHasher<H> {
    /// Create a new hasher with the given hash function
    pub fn new(hash_function: H) -> Self {
        Self { hash_function }
    }
    
    /// Hash a message
    pub fn hash(&self, message: &[u8]) -> Vec<u8> {
        self.hash_function.hash(message)
    }
    
    /// Get the digest size in bytes
    pub fn digest_size(&self) -> usize {
        self.hash_function.digest_size()
    }
    
    /// Get the name of the hash function
    pub fn name(&self) -> &str {
        self.hash_function.name()
    }
}

// Additional convenience functions
/// Create a SHA-256 hash of any type that can be referenced as bytes
pub fn sha256<T: AsRef<[u8]>>(data: T) -> Vec<u8> {
    let hasher = Sha256Hash::default();
    hasher.hash(data.as_ref())
}

/// Create a SHA-512 hash of any type that can be referenced as bytes
pub fn sha512<T: AsRef<[u8]>>(data: T) -> Vec<u8> {
    let hasher = Sha512Hash::default();
    hasher.hash(data.as_ref())
}```

######## File: crypto/src/algorithms/hash/tests.rs
#####*Size: 4.0K, Lines: 44, Type: ASCII text*

```rust
//! Tests for hash function implementations

#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn test_hash_functions() {
        let message = b"test message";

        let sha256 = Sha256Hash::default();
        let sha512 = Sha512Hash::default();

        let sha256_hash = sha256.hash(message);
        let sha512_hash = sha512.hash(message);

        assert_eq!(sha256_hash.len(), sha256.digest_size());
        assert_eq!(sha512_hash.len(), sha512.digest_size());

        assert_eq!(sha256.digest_size(), 32);
        assert_eq!(sha512.digest_size(), 64);

        // Verify deterministic behavior
        assert_eq!(sha256.hash(message), sha256.hash(message));
        assert_eq!(sha512.hash(message), sha512.hash(message));
    }

    #[test]
    fn test_generic_hasher() {
        let message = b"test message";

        let sha256_hasher = GenericHasher::new(Sha256Hash::default());
        let sha512_hasher = GenericHasher::new(Sha512Hash::default());

        let sha256_hash = sha256_hasher.hash(message);
        let sha512_hash = sha512_hasher.hash(message);

        assert_eq!(sha256_hash.len(), sha256_hasher.digest_size());
        assert_eq!(sha512_hash.len(), sha512_hasher.digest_size());

        assert_eq!(sha256_hasher.digest_size(), 32);
        assert_eq!(sha512_hasher.digest_size(), 64);
    }
}
```

####### File: crypto/src/algorithms/mod.rs
####*Size: 4.0K, Lines: 0, Type: ASCII text, with no line terminators*

```rust
pub mod hash;```

###### Directory: crypto/src/kem

####### Directory: crypto/src/kem/ecdh

######## Directory: crypto/src/kem/ecdh/tests

######### File: crypto/src/kem/ecdh/tests/mod.rs
######*Size: 8.0K, Lines: 157, Type: ASCII text*

```rust
// crates/crypto/src/kem/ecdh/tests/mod.rs
use super::*;
use crate::security::SecurityLevel;
use depin_sdk_core::crypto::{Encapsulated, KeyEncapsulation, KemKeyPair, DecapsulationKey, EncapsulationKey};

#[test]
fn test_ecdh_keypair_generation() {
    // Test P256 curve (K256)
    let curve = EcdhCurve::P256;
    let kem = EcdhKEM::new(curve);
    let keypair = kem.generate_keypair();

    // Verify key sizes match the expected sizes for K256
    assert_eq!(keypair.public_key.to_bytes().len(), 33); // Compressed K256 point
    assert_eq!(keypair.private_key.to_bytes().len(), 32); // K256 scalar

    // Ensure keys are different
    assert_ne!(
        keypair.public_key.to_bytes(),
        keypair.private_key.to_bytes()
    );
}

#[test]
#[should_panic(expected = "P384 and P521 curves are not yet implemented")]
fn test_ecdh_p384_not_implemented() {
    let kem = EcdhKEM::new(EcdhCurve::P384);
    kem.generate_keypair();
}

#[test]
#[should_panic(expected = "P384 and P521 curves are not yet implemented")]
fn test_ecdh_p521_not_implemented() {
    let kem = EcdhKEM::new(EcdhCurve::P521);
    kem.generate_keypair();
}

#[test]
fn test_ecdh_encapsulation() {
    let curve = EcdhCurve::P256;
    let kem = EcdhKEM::new(curve);
    let keypair = kem.generate_keypair();

    // Encapsulate a key
    let encapsulated = kem.encapsulate(&keypair.public_key);

    // Verify the encapsulated data sizes
    assert_eq!(encapsulated.ciphertext().len(), 33); // Compressed K256 point
    assert_eq!(encapsulated.shared_secret().len(), 32); // SHA-256 output

    // Decapsulate and verify
    let shared_secret = kem.decapsulate(&keypair.private_key, &encapsulated);

    // We should get a valid shared secret
    assert!(shared_secret.is_some());
    let shared_secret = shared_secret.unwrap();

    // The shared secret should match what's in the encapsulated key
    assert_eq!(shared_secret, encapsulated.shared_secret());
}

#[test]
fn test_ecdh_security_level_mapping() {
    // Test Level1 -> P256
    let kem = EcdhKEM::with_security_level(SecurityLevel::Level1);
    assert_eq!(kem.curve, EcdhCurve::P256);

    // Test Level3 -> P384
    let kem = EcdhKEM::with_security_level(SecurityLevel::Level3);
    assert_eq!(kem.curve, EcdhCurve::P384);

    // Test Level5 -> P521
    let kem = EcdhKEM::with_security_level(SecurityLevel::Level5);
    assert_eq!(kem.curve, EcdhCurve::P521);
}

#[test]
fn test_ecdh_serialization() {
    let kem = EcdhKEM::new(EcdhCurve::P256);
    let keypair = kem.generate_keypair();

    // Serialize keys
    let public_key_bytes = keypair.public_key.to_bytes();
    let private_key_bytes = keypair.private_key.to_bytes();

    // Deserialize keys
    let restored_public_key = EcdhPublicKey::from_bytes(&public_key_bytes).unwrap();
    let restored_private_key = EcdhPrivateKey::from_bytes(&private_key_bytes).unwrap();

    // Encapsulate with original key
    let encapsulated = kem.encapsulate(&keypair.public_key);
    let ciphertext_bytes = encapsulated.to_bytes();

    // Deserialize ciphertext
    let restored_encapsulated = EcdhEncapsulated::from_bytes(&ciphertext_bytes).unwrap();

    // Decapsulate with restored key and restored ciphertext
    let shared_secret = kem.decapsulate(&restored_private_key, &restored_encapsulated);

    // We should still get a valid shared secret
    assert!(shared_secret.is_some());

    // Verify that different key pairs produce different shared secrets
    let keypair2 = kem.generate_keypair();
    let encapsulated2 = kem.encapsulate(&keypair2.public_key);

    // Different key pairs should generate different shared secrets
    assert_ne!(encapsulated.shared_secret(), encapsulated2.shared_secret());

    // Different public keys should produce different ciphertexts
    assert_ne!(encapsulated.ciphertext(), encapsulated2.ciphertext());

    // Decapsulating with the wrong private key should produce a different result
    let wrong_shared_secret = kem.decapsulate(&keypair2.private_key, &encapsulated);
    assert!(wrong_shared_secret.is_some());
    assert_ne!(wrong_shared_secret.unwrap(), encapsulated.shared_secret());
}

#[test]
fn test_ecdh_dcrypt_compatibility() {
    // Test that the dcrypt wrapper works correctly
    let kem = EcdhKEM::new(EcdhCurve::P256);
    let keypair1 = kem.generate_keypair();
    let keypair2 = kem.generate_keypair();

    // Test encapsulation/decapsulation cycle
    let encapsulated = kem.encapsulate(&keypair1.public_key);
    let shared_secret = kem.decapsulate(&keypair1.private_key, &encapsulated);
    
    assert!(shared_secret.is_some());
    assert_eq!(shared_secret.unwrap().len(), 32); // K256 produces 32-byte shared secrets

    // Test that using wrong keys produces different results
    let wrong_secret = kem.decapsulate(&keypair2.private_key, &encapsulated);
    assert!(wrong_secret.is_some());
    assert_ne!(wrong_secret.unwrap(), encapsulated.shared_secret());
}

#[test]
fn test_ecdh_independent_verification() {
    // Test that keys can be used independently
    let kem = EcdhKEM::new(EcdhCurve::P256);
    let keypair = kem.generate_keypair();
    
    // Serialize and deserialize to ensure independence
    let pk_bytes = keypair.public_key.to_bytes();
    let sk_bytes = keypair.private_key.to_bytes();
    
    let pk = EcdhPublicKey::from_bytes(&pk_bytes).unwrap();
    let sk = EcdhPrivateKey::from_bytes(&sk_bytes).unwrap();
    
    // Use the deserialized keys
    let encapsulated = kem.encapsulate(&pk);
    let shared_secret = kem.decapsulate(&sk, &encapsulated);
    
    assert!(shared_secret.is_some());
    assert_eq!(shared_secret.unwrap(), encapsulated.shared_secret());
}```

######## File: crypto/src/kem/ecdh/mod.rs
#####*Size: 12K, Lines: 276, Type: ASCII text*

```rust
// crates/crypto/src/kem/ecdh/mod.rs
//! ECDH key encapsulation mechanism using dcrypt

use crate::security::SecurityLevel;
use depin_sdk_core::crypto::{
    DecapsulationKey, Encapsulated, EncapsulationKey, KemKeyPair, KeyEncapsulation,
    SerializableKey,
};
use dcrypt::api::Kem;
use dcrypt::kem::ecdh::{
    EcdhK256,
    EcdhK256Ciphertext,
    EcdhK256PublicKey,
    EcdhK256SecretKey,
    EcdhK256SharedSecret,
    // Note: dcrypt might not have P384/P521 implementations yet
    // This is a simplified version using only K256
};
use rand::{CryptoRng, RngCore};

/// ECDH curve type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdhCurve {
    /// NIST P-256 curve (128-bit security) - using K256 (secp256k1) as substitute
    P256,
    /// NIST P-384 curve (192-bit security) - not available in dcrypt
    P384,
    /// NIST P-521 curve (256-bit security) - not available in dcrypt
    P521,
}

impl EcdhCurve {
    /// Get the appropriate curve for a security level
    pub fn from_security_level(level: SecurityLevel) -> Self {
        match level {
            SecurityLevel::Level1 => EcdhCurve::P256,
            SecurityLevel::Level3 => EcdhCurve::P384,
            SecurityLevel::Level5 => EcdhCurve::P521,
            _ => EcdhCurve::P256, // Default to P256
        }
    }
}

/// ECDH key encapsulation mechanism
pub struct EcdhKEM {
    /// The curve to use
    pub(crate) curve: EcdhCurve,
}

/// ECDH key pair
pub struct EcdhKeyPair {
    /// Public key
    pub public_key: EcdhPublicKey,
    /// Private key
    pub private_key: EcdhPrivateKey,
    /// Curve type
    curve: EcdhCurve,
}

/// ECDH public key wrapper
#[derive(Clone)]
pub enum EcdhPublicKey {
    K256(EcdhK256PublicKey),
    // P384 and P521 would need their own dcrypt implementations
    P384(Vec<u8>), // Placeholder
    P521(Vec<u8>), // Placeholder
}

/// ECDH private key wrapper
#[derive(Clone)]
pub enum EcdhPrivateKey {
    K256(EcdhK256SecretKey),
    // P384 and P521 would need their own dcrypt implementations
    P384(Vec<u8>), // Placeholder
    P521(Vec<u8>), // Placeholder
}

/// ECDH encapsulated key
pub struct EcdhEncapsulated {
    /// Ciphertext
    ciphertext: Vec<u8>,
    /// Shared secret
    shared_secret: Vec<u8>,
    /// Curve type
    curve: EcdhCurve,
}

impl EcdhKEM {
    /// Create a new ECDH KEM with the specified curve
    pub fn new(curve: EcdhCurve) -> Self {
        Self { curve }
    }

    /// Create a new ECDH KEM with the specified security level
    pub fn with_security_level(level: SecurityLevel) -> Self {
        Self {
            curve: EcdhCurve::from_security_level(level),
        }
    }
}

impl KeyEncapsulation for EcdhKEM {
    type KeyPair = EcdhKeyPair;
    type PublicKey = EcdhPublicKey;
    type PrivateKey = EcdhPrivateKey;
    type Encapsulated = EcdhEncapsulated;

    fn generate_keypair(&self) -> Self::KeyPair {
        let mut rng = rand::thread_rng();
        
        match self.curve {
            EcdhCurve::P256 => {
                // Use K256 from dcrypt
                let (pk, sk) = EcdhK256::keypair(&mut rng)
                    .expect("Failed to generate K256 keypair");
                EcdhKeyPair {
                    public_key: EcdhPublicKey::K256(pk),
                    private_key: EcdhPrivateKey::K256(sk),
                    curve: self.curve,
                }
            }
            EcdhCurve::P384 | EcdhCurve::P521 => {
                // Not implemented in dcrypt yet
                panic!("P384 and P521 curves are not yet implemented in dcrypt");
            }
        }
    }

    fn encapsulate(&self, public_key: &Self::PublicKey) -> Self::Encapsulated {
        let mut rng = rand::thread_rng();
        
        match (self.curve, public_key) {
            (EcdhCurve::P256, EcdhPublicKey::K256(pk)) => {
                let (ct, ss) = EcdhK256::encapsulate(&mut rng, pk)
                    .expect("Failed to encapsulate with K256");
                
                EcdhEncapsulated {
                    ciphertext: ct.to_bytes(),
                    shared_secret: ss.to_bytes(),
                    curve: EcdhCurve::P256,
                }
            }
            _ => panic!("Curve mismatch or unsupported curve in encapsulation"),
        }
    }

    fn decapsulate(
        &self,
        private_key: &Self::PrivateKey,
        encapsulated: &Self::Encapsulated,
    ) -> Option<Vec<u8>> {
        match (self.curve, private_key) {
            (EcdhCurve::P256, EcdhPrivateKey::K256(sk)) => {
                // Reconstruct the ciphertext from bytes
                let ct = EcdhK256Ciphertext::from_bytes(&encapsulated.ciphertext)
                    .ok()?;
                
                let ss = EcdhK256::decapsulate(sk, &ct)
                    .ok()?;
                
                Some(ss.to_bytes())
            }
            _ => None,
        }
    }
}

impl KemKeyPair for EcdhKeyPair {
    type PublicKey = EcdhPublicKey;
    type PrivateKey = EcdhPrivateKey;

    fn public_key(&self) -> Self::PublicKey {
        self.public_key.clone()
    }

    fn private_key(&self) -> Self::PrivateKey {
        self.private_key.clone()
    }
}

// EcdhPublicKey implements the EncapsulationKey trait
impl SerializableKey for EcdhPublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            EcdhPublicKey::K256(pk) => pk.to_bytes(),
            EcdhPublicKey::P384(bytes) => bytes.clone(),
            EcdhPublicKey::P521(bytes) => bytes.clone(),
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Try to determine the curve from the public key size
        match bytes.len() {
            33 => {
                // K256 compressed point
                let pk = EcdhK256PublicKey::from_bytes(bytes)
                    .map_err(|e| format!("Failed to deserialize K256 public key: {:?}", e))?;
                Ok(EcdhPublicKey::K256(pk))
            }
            49 => Ok(EcdhPublicKey::P384(bytes.to_vec())),
            67 => Ok(EcdhPublicKey::P521(bytes.to_vec())),
            _ => Err(format!("Invalid ECDH public key size: {}", bytes.len())),
        }
    }
}

impl EncapsulationKey for EcdhPublicKey {
    // EncapsulationKey trait has no additional methods beyond SerializableKey
}

// EcdhPrivateKey implements the DecapsulationKey trait
impl SerializableKey for EcdhPrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            EcdhPrivateKey::K256(sk) => sk.to_bytes().to_vec(),
            EcdhPrivateKey::P384(bytes) => bytes.clone(),
            EcdhPrivateKey::P521(bytes) => bytes.clone(),
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Try to determine the curve from the private key size
        match bytes.len() {
            32 => {
                // K256 scalar
                let sk = EcdhK256SecretKey::from_bytes(bytes)
                    .map_err(|e| format!("Failed to deserialize K256 private key: {:?}", e))?;
                Ok(EcdhPrivateKey::K256(sk))
            }
            48 => Ok(EcdhPrivateKey::P384(bytes.to_vec())),
            66 => Ok(EcdhPrivateKey::P521(bytes.to_vec())),
            _ => Err(format!("Invalid ECDH private key size: {}", bytes.len())),
        }
    }
}

impl DecapsulationKey for EcdhPrivateKey {
    // DecapsulationKey trait has no additional methods beyond SerializableKey
}

// EcdhEncapsulated implements the Encapsulated trait
impl SerializableKey for EcdhEncapsulated {
    fn to_bytes(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Try to determine the curve from the ciphertext size
        let curve = match bytes.len() {
            33 => EcdhCurve::P256,
            49 => EcdhCurve::P384,
            67 => EcdhCurve::P521,
            _ => return Err(format!("Invalid ECDH ciphertext size: {}", bytes.len())),
        };

        // We can't recover the shared secret from just the ciphertext
        // This will need to be decapsulated using a private key to get the shared secret
        Ok(EcdhEncapsulated {
            ciphertext: bytes.to_vec(),
            shared_secret: vec![0; 32], // Placeholder until decapsulated
            curve,
        })
    }
}

impl Encapsulated for EcdhEncapsulated {
    fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    fn shared_secret(&self) -> &[u8] {
        &self.shared_secret
    }
}

#[cfg(test)]
mod tests;```

####### Directory: crypto/src/kem/hybrid

######## Directory: crypto/src/kem/hybrid/tests

######### File: crypto/src/kem/hybrid/tests/mod.rs
######*Size: 8.0K, Lines: 207, Type: ASCII text*

```rust
// crates/crypto/src/kem/hybrid/tests/mod.rs
use super::*;
use crate::security::SecurityLevel;
use depin_sdk_core::crypto::{Encapsulated, KeyEncapsulation, KemKeyPair, DecapsulationKey, EncapsulationKey};

#[test]
fn test_hybrid_keypair_generation() {
    let kem = HybridKEM::new(SecurityLevel::Level3);
    let keypair = kem.generate_keypair();

    // Verify key sizes match the expected sizes
    // ECDH K256 (33) + Kyber768 (1184) = 1217
    assert_eq!(keypair.public_key.to_bytes().len(), 1217);
    // ECDH K256 (32) + Kyber768 (2400) = 2432
    assert_eq!(keypair.private_key.to_bytes().len(), 2432);

    // Ensure keys are different
    assert_ne!(
        keypair.public_key.to_bytes(),
        keypair.private_key.to_bytes()
    );
}

#[test]
#[should_panic(expected = "Hybrid KEM currently only supports Level3 security")]
fn test_hybrid_unsupported_security_levels() {
    // Test Level1
    let _ = HybridKEM::new(SecurityLevel::Level1);
}

#[test]
#[should_panic(expected = "Hybrid KEM currently only supports Level3 security")]
fn test_hybrid_unsupported_security_level5() {
    // Test Level5
    let _ = HybridKEM::new(SecurityLevel::Level5);
}

#[test]
fn test_hybrid_encapsulation() {
    let kem = HybridKEM::new(SecurityLevel::Level3);
    let keypair = kem.generate_keypair();

    // Encapsulate a key
    let encapsulated = kem.encapsulate(&keypair.public_key);

    // Verify the encapsulated data sizes
    // ECDH K256 (33) + Kyber768 (1088) = 1121
    assert_eq!(encapsulated.ciphertext().len(), 1121);
    // Combined shared secret should be 32 bytes (HKDF output)
    assert_eq!(encapsulated.shared_secret().len(), 32);

    // Decapsulate and verify
    let shared_secret = kem.decapsulate(&keypair.private_key, &encapsulated);

    // We should get a valid shared secret
    assert!(shared_secret.is_some());
    let shared_secret = shared_secret.unwrap();

    // The shared secret should match what's in the encapsulated key
    assert_eq!(shared_secret, encapsulated.shared_secret());
    assert_eq!(shared_secret.len(), 32);
}

#[test]
fn test_hybrid_multiple_encapsulations() {
    let kem = HybridKEM::new(SecurityLevel::Level3);
    let keypair = kem.generate_keypair();

    // Multiple encapsulations with the same public key should produce different results
    let encapsulated1 = kem.encapsulate(&keypair.public_key);
    let encapsulated2 = kem.encapsulate(&keypair.public_key);

    // Ciphertexts should be different due to randomness
    assert_ne!(encapsulated1.ciphertext(), encapsulated2.ciphertext());
    // Shared secrets should be different
    assert_ne!(encapsulated1.shared_secret(), encapsulated2.shared_secret());

    // But both should decapsulate correctly
    let shared_secret1 = kem.decapsulate(&keypair.private_key, &encapsulated1).unwrap();
    let shared_secret2 = kem.decapsulate(&keypair.private_key, &encapsulated2).unwrap();

    assert_eq!(shared_secret1, encapsulated1.shared_secret());
    assert_eq!(shared_secret2, encapsulated2.shared_secret());
}

#[test]
fn test_hybrid_wrong_key_decapsulation() {
    let kem = HybridKEM::new(SecurityLevel::Level3);
    let keypair1 = kem.generate_keypair();
    let keypair2 = kem.generate_keypair();

    // Encapsulate with keypair1's public key
    let encapsulated = kem.encapsulate(&keypair1.public_key);

    // Try to decapsulate with keypair2's private key
    let wrong_shared_secret = kem.decapsulate(&keypair2.private_key, &encapsulated);

    // Should still produce a result (KEMs don't fail on wrong key)
    assert!(wrong_shared_secret.is_some());
    // But it should be different from the correct shared secret
    assert_ne!(wrong_shared_secret.unwrap(), encapsulated.shared_secret());
}

#[test]
fn test_hybrid_serialization() {
    let kem = HybridKEM::new(SecurityLevel::Level3);
    let keypair = kem.generate_keypair();

    // Serialize keys
    let public_key_bytes = keypair.public_key.to_bytes();
    let private_key_bytes = keypair.private_key.to_bytes();

    // Deserialize keys
    let restored_public_key = HybridPublicKey::from_bytes(&public_key_bytes).unwrap();
    let restored_private_key = HybridPrivateKey::from_bytes(&private_key_bytes).unwrap();

    // Encapsulate with original key
    let encapsulated = kem.encapsulate(&keypair.public_key);
    let ciphertext_bytes = encapsulated.to_bytes();

    // Deserialize ciphertext
    let restored_encapsulated = HybridEncapsulated::from_bytes(&ciphertext_bytes).unwrap();

    // Decapsulate with restored key and restored ciphertext
    let shared_secret = kem.decapsulate(&restored_private_key, &restored_encapsulated);

    // We should still get a valid shared secret
    assert!(shared_secret.is_some());

    // Verify the original encapsulated ciphertext matches the serialized version
    assert_eq!(encapsulated.ciphertext(), restored_encapsulated.ciphertext());
}

#[test]
fn test_hybrid_invalid_serialization() {
    // Test invalid public key sizes
    let too_short_pk = vec![0u8; 100];
    assert!(HybridPublicKey::from_bytes(&too_short_pk).is_err());
    
    let too_long_pk = vec![0u8; 2000];
    assert!(HybridPublicKey::from_bytes(&too_long_pk).is_err());

    // Test invalid private key sizes
    let too_short_sk = vec![0u8; 100];
    assert!(HybridPrivateKey::from_bytes(&too_short_sk).is_err());
    
    let too_long_sk = vec![0u8; 3000];
    assert!(HybridPrivateKey::from_bytes(&too_long_sk).is_err());

    // Test invalid ciphertext sizes
    let too_short_ct = vec![0u8; 100];
    assert!(HybridEncapsulated::from_bytes(&too_short_ct).is_err());
    
    let too_long_ct = vec![0u8; 2000];
    assert!(HybridEncapsulated::from_bytes(&too_long_ct).is_err());
}

#[test]
fn test_hybrid_security_properties() {
    let kem = HybridKEM::new(SecurityLevel::Level3);
    let keypair = kem.generate_keypair();

    // Test that the shared secret is deterministic for a given ciphertext
    let encapsulated = kem.encapsulate(&keypair.public_key);
    
    // Multiple decapsulations of the same ciphertext should produce the same result
    let shared_secret1 = kem.decapsulate(&keypair.private_key, &encapsulated).unwrap();
    let shared_secret2 = kem.decapsulate(&keypair.private_key, &encapsulated).unwrap();
    
    assert_eq!(shared_secret1, shared_secret2);
}

#[test]
fn test_hybrid_default_constructor() {
    let kem = HybridKEM::default();
    let keypair = kem.generate_keypair();
    
    // Should use Level3 by default
    assert_eq!(keypair.level, SecurityLevel::Level3);
    
    // Should work normally
    let encapsulated = kem.encapsulate(&keypair.public_key);
    let shared_secret = kem.decapsulate(&keypair.private_key, &encapsulated);
    
    assert!(shared_secret.is_some());
    assert_eq!(shared_secret.unwrap(), encapsulated.shared_secret());
}

#[test]
fn test_hybrid_independent_verification() {
    // Test that keys can be used independently after serialization
    let kem = HybridKEM::new(SecurityLevel::Level3);
    let keypair = kem.generate_keypair();
    
    // Serialize and deserialize to ensure independence
    let pk_bytes = keypair.public_key.to_bytes();
    let sk_bytes = keypair.private_key.to_bytes();
    
    let pk = HybridPublicKey::from_bytes(&pk_bytes).unwrap();
    let sk = HybridPrivateKey::from_bytes(&sk_bytes).unwrap();
    
    // Use the deserialized keys
    let encapsulated = kem.encapsulate(&pk);
    let shared_secret = kem.decapsulate(&sk, &encapsulated);
    
    assert!(shared_secret.is_some());
    assert_eq!(shared_secret.unwrap(), encapsulated.shared_secret());
}```

######## File: crypto/src/kem/hybrid/ecdh_kyber.rs
#####*Size: 4.0K, Lines: 36, Type: ASCII text*

```rust
// crates/crypto/src/kem/hybrid/ecdh_kyber.rs
//! ECDH-Kyber hybrid key encapsulation mechanism
//! 
//! This module provides specific hybrid combinations of ECDH and Kyber KEMs.

use super::{HybridKEM, HybridKeyPair, HybridPublicKey, HybridPrivateKey, HybridEncapsulated};
use crate::security::SecurityLevel;
use depin_sdk_core::crypto::{KeyEncapsulation, KemKeyPair, Encapsulated};

/// ECDH-P256 + Kyber768 hybrid KEM
/// 
/// Provides Level3 security by combining:
/// - ECDH on P-256 curve (128-bit classical security)
/// - Kyber768 (192-bit post-quantum security)
/// 
/// This is a convenience type alias for HybridKEM configured with Level3 security.
pub type EcdhP256Kyber768 = HybridKEM;

/// ECDH-P256 + Kyber768 key pair
pub type EcdhP256Kyber768KeyPair = HybridKeyPair;

/// ECDH-P256 + Kyber768 public key
pub type EcdhP256Kyber768PublicKey = HybridPublicKey;

/// ECDH-P256 + Kyber768 private key
pub type EcdhP256Kyber768PrivateKey = HybridPrivateKey;

/// ECDH-P256 + Kyber768 encapsulated ciphertext
pub type EcdhP256Kyber768Encapsulated = HybridEncapsulated;

// Note: EcdhP256Kyber768 is a type alias for HybridKEM and inherits all its methods.
// To create an instance, use: HybridKEM::new(SecurityLevel::Level3)
// or HybridKEM::default() which defaults to Level3.

// Future implementations could include:
// - EcdhP256Kyber512 for Level1 security
// - EcdhP521Kyber1024 for Level5 security```

######## File: crypto/src/kem/hybrid/mod.rs
#####*Size: 12K, Lines: 277, Type: ASCII text*

```rust
// crates/crypto/src/kem/hybrid/mod.rs
//! Hybrid key encapsulation mechanism using dcrypt's EcdhKyber768

use crate::security::SecurityLevel;
use depin_sdk_core::crypto::{
    DecapsulationKey, Encapsulated, EncapsulationKey, KemKeyPair, KeyEncapsulation,
    SerializableKey,
};

// Import from dcrypt - adjust these based on your actual dcrypt dependency structure
// Option 1: If dcrypt re-exports everything from root
use dcrypt::api::Kem;
use dcrypt::kem::ecdh::p256::EcdhP256SecretKey;
use dcrypt::kem::kyber::KyberSecretKey;

// Option 2: If hybrid is a separate crate, use:
// use dcrypt_hybrid::kem::ecdh_kyber::{...}
// 
// For now, assuming the hybrid module is under dcrypt with proper path:
use dcrypt::hybrid::kem::ecdh_kyber::{
    EcdhKyber768, 
    HybridCiphertext, 
    HybridPublicKey as DcryptHybridPublicKey,
    HybridSecretKey as DcryptHybridSecretKey,
};
use rand::thread_rng;

/// Hybrid key encapsulation mechanism
pub struct HybridKEM {
    /// Security level
    level: SecurityLevel,
}

/// Hybrid key pair
pub struct HybridKeyPair {
    /// Public key
    pub public_key: HybridPublicKey,
    /// Private key
    pub private_key: HybridPrivateKey,
    /// Security level
    level: SecurityLevel,
}

/// Hybrid public key wrapper
#[derive(Clone)]
pub struct HybridPublicKey {
    /// The underlying dcrypt hybrid public key
    inner: DcryptHybridPublicKey,
    /// Security level
    level: SecurityLevel,
}

/// Hybrid private key wrapper
#[derive(Clone)]
pub struct HybridPrivateKey {
    /// The underlying dcrypt hybrid secret key
    inner: DcryptHybridSecretKey,
    /// Security level
    level: SecurityLevel,
}

/// Hybrid encapsulated key
pub struct HybridEncapsulated {
    /// The ciphertext bytes
    ciphertext: Vec<u8>,
    /// The shared secret
    shared_secret: Vec<u8>,
    /// Security level
    level: SecurityLevel,
}

impl HybridKEM {
    /// Create a new hybrid KEM with the specified security level
    /// 
    /// Currently only supports Level3 (EcdhKyber768: ECDH P-256 + Kyber768)
    pub fn new(level: SecurityLevel) -> Self {
        match level {
            SecurityLevel::Level3 => Self { level },
            _ => panic!("Hybrid KEM currently only supports Level3 security"),
        }
    }

    /// Create a new hybrid KEM with default security level (Level3)
    pub fn default() -> Self {
        Self::new(SecurityLevel::Level3)
    }
}

impl KeyEncapsulation for HybridKEM {
    type KeyPair = HybridKeyPair;
    type PublicKey = HybridPublicKey;
    type PrivateKey = HybridPrivateKey;
    type Encapsulated = HybridEncapsulated;

    fn generate_keypair(&self) -> Self::KeyPair {
        let mut rng = thread_rng();
        
        // Use dcrypt's hybrid KEM to generate keypair
        let (pk, sk) = EcdhKyber768::keypair(&mut rng)
            .expect("Failed to generate hybrid keypair");

        HybridKeyPair {
            public_key: HybridPublicKey {
                inner: pk,
                level: self.level,
            },
            private_key: HybridPrivateKey {
                inner: sk,
                level: self.level,
            },
            level: self.level,
        }
    }

    fn encapsulate(&self, public_key: &Self::PublicKey) -> Self::Encapsulated {
        let mut rng = thread_rng();
        
        // Use dcrypt's hybrid KEM to encapsulate
        let (ct, ss) = EcdhKyber768::encapsulate(&mut rng, &public_key.inner)
            .expect("Failed to encapsulate with hybrid KEM");

        HybridEncapsulated {
            ciphertext: ct.to_bytes(),
            shared_secret: ss.to_bytes_zeroizing().to_vec(),
            level: public_key.level,
        }
    }

    fn decapsulate(
        &self,
        private_key: &Self::PrivateKey,
        encapsulated: &Self::Encapsulated,
    ) -> Option<Vec<u8>> {
        // Reconstruct the ciphertext from bytes
        let ct = HybridCiphertext::from_bytes(&encapsulated.ciphertext).ok()?;
        
        // Use dcrypt's hybrid KEM to decapsulate
        let ss = EcdhKyber768::decapsulate(&private_key.inner, &ct)
            .ok()?;

        Some(ss.to_bytes_zeroizing().to_vec())
    }
}

impl KemKeyPair for HybridKeyPair {
    type PublicKey = HybridPublicKey;
    type PrivateKey = HybridPrivateKey;

    fn public_key(&self) -> Self::PublicKey {
        self.public_key.clone()
    }

    fn private_key(&self) -> Self::PrivateKey {
        self.private_key.clone()
    }
}

// HybridPublicKey implements the EncapsulationKey trait
impl SerializableKey for HybridPublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        // Use dcrypt's built-in to_bytes method
        self.inner.to_bytes()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Use dcrypt's built-in from_bytes method
        let inner = DcryptHybridPublicKey::from_bytes(bytes)
            .map_err(|e| format!("Failed to deserialize hybrid public key: {:?}", e))?;
        
        // For now, we only support Level3
        Ok(HybridPublicKey { 
            inner, 
            level: SecurityLevel::Level3 
        })
    }
}

impl EncapsulationKey for HybridPublicKey {
    // EncapsulationKey trait has no additional methods beyond SerializableKey
}

// HybridPrivateKey implements the DecapsulationKey trait
impl SerializableKey for HybridPrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        // Note: dcrypt's HybridSecretKey doesn't have a direct to_bytes method
        // We need to serialize the components
        [
            self.inner.ecdh_sk.to_bytes().to_vec(),
            self.inner.kyber_sk.to_bytes_zeroizing().to_vec()
        ].concat()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Expected sizes from dcrypt's implementation
        const ECDH_SK_LEN: usize = 32;  // P-256 scalar
        const KYBER_SK_LEN: usize = 2400; // Kyber768
        const TOTAL_LEN: usize = ECDH_SK_LEN + KYBER_SK_LEN;

        if bytes.len() != TOTAL_LEN {
            return Err(format!(
                "Invalid hybrid private key size: expected {}, got {}",
                TOTAL_LEN,
                bytes.len()
            ));
        }

        let (ecdh_bytes, kyber_bytes) = bytes.split_at(ECDH_SK_LEN);
        
        let ecdh_sk = EcdhP256SecretKey::from_bytes(ecdh_bytes)
            .map_err(|e| format!("Failed to deserialize ECDH private key: {:?}", e))?;
        
        let kyber_sk = KyberSecretKey::from_bytes(kyber_bytes)
            .map_err(|e| format!("Failed to deserialize Kyber private key: {:?}", e))?;

        Ok(HybridPrivateKey {
            inner: DcryptHybridSecretKey { ecdh_sk, kyber_sk },
            level: SecurityLevel::Level3,
        })
    }
}

impl DecapsulationKey for HybridPrivateKey {
    // DecapsulationKey trait has no additional methods beyond SerializableKey
}

// HybridEncapsulated implements the Encapsulated trait
impl SerializableKey for HybridEncapsulated {
    fn to_bytes(&self) -> Vec<u8> {
        // Return the ciphertext bytes
        self.ciphertext.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Try to verify this is a valid hybrid ciphertext size
        // ECDH P-256 (33) + Kyber768 (1088) = 1121
        const EXPECTED_LEN: usize = 1121;
        
        if bytes.len() != EXPECTED_LEN {
            return Err(format!(
                "Invalid hybrid ciphertext size: expected {}, got {}",
                EXPECTED_LEN,
                bytes.len()
            ));
        }

        // We can't recover the shared secret from just the ciphertext
        // This will need to be decapsulated using a private key to get the shared secret
        Ok(HybridEncapsulated {
            ciphertext: bytes.to_vec(),
            shared_secret: vec![0; 32], // Placeholder until decapsulated
            level: SecurityLevel::Level3,
        })
    }
}

impl Encapsulated for HybridEncapsulated {
    fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    fn shared_secret(&self) -> &[u8] {
        &self.shared_secret
    }
}

pub mod ecdh_kyber;

// Re-export commonly used types
pub use ecdh_kyber::{
    EcdhP256Kyber768,
    EcdhP256Kyber768KeyPair,
    EcdhP256Kyber768PublicKey,
    EcdhP256Kyber768PrivateKey,
    EcdhP256Kyber768Encapsulated,
};

#[cfg(test)]
mod tests;```

####### Directory: crypto/src/kem/kyber

######## Directory: crypto/src/kem/kyber/tests

######### File: crypto/src/kem/kyber/tests/mod.rs
######*Size: 8.0K, Lines: 175, Type: ASCII text*

```rust
// crates/crypto/src/kem/kyber/tests/mod.rs
use super::*;
use crate::security::SecurityLevel;
use depin_sdk_core::crypto::{Encapsulated, KeyEncapsulation, KemKeyPair, DecapsulationKey, EncapsulationKey};

#[test]
fn test_kyber_keypair_generation() {
    // Test all security levels
    let levels = vec![
        SecurityLevel::Level1,
        SecurityLevel::Level3,
        SecurityLevel::Level5,
    ];

    for level in levels {
        let kem = KyberKEM::new(level);
        let keypair = kem.generate_keypair();

        // Verify key sizes match the expected sizes for the security level
        match level {
            SecurityLevel::Level1 => {
                assert_eq!(keypair.public_key.to_bytes().len(), 800); // Kyber512
                assert_eq!(keypair.private_key.to_bytes().len(), 1632); // Kyber512
            }
            SecurityLevel::Level3 => {
                assert_eq!(keypair.public_key.to_bytes().len(), 1184); // Kyber768
                assert_eq!(keypair.private_key.to_bytes().len(), 2400); // Kyber768
            }
            SecurityLevel::Level5 => {
                assert_eq!(keypair.public_key.to_bytes().len(), 1568); // Kyber1024
                assert_eq!(keypair.private_key.to_bytes().len(), 3168); // Kyber1024
            }
            _ => panic!("Unexpected security level"),
        }

        // Ensure keys are different
        assert_ne!(
            keypair.public_key.to_bytes(),
            keypair.private_key.to_bytes()
        );
    }
}

#[test]
fn test_kyber_encapsulation() {
    let levels = vec![
        SecurityLevel::Level1,
        SecurityLevel::Level3,
        SecurityLevel::Level5,
    ];

    for level in levels {
        let kem = KyberKEM::new(level);
        let keypair = kem.generate_keypair();

        // Encapsulate a key
        let encapsulated = kem.encapsulate(&keypair.public_key);

        // Verify the encapsulated data sizes
        match level {
            SecurityLevel::Level1 => {
                assert_eq!(encapsulated.ciphertext().len(), 768); // Kyber512
            }
            SecurityLevel::Level3 => {
                assert_eq!(encapsulated.ciphertext().len(), 1088); // Kyber768
            }
            SecurityLevel::Level5 => {
                assert_eq!(encapsulated.ciphertext().len(), 1568); // Kyber1024
            }
            _ => panic!("Unexpected security level"),
        }

        // Shared secret should always be 32 bytes for all Kyber variants
        assert_eq!(encapsulated.shared_secret().len(), 32);

        // Decapsulate and verify
        let shared_secret = kem.decapsulate(&keypair.private_key, &encapsulated);

        // We should get a valid shared secret
        assert!(shared_secret.is_some());
        let shared_secret = shared_secret.unwrap();

        // The shared secret should match what's in the encapsulated key
        assert_eq!(shared_secret, encapsulated.shared_secret());

        // The shared secret should be 32 bytes for all Kyber variants
        assert_eq!(shared_secret.len(), 32);
    }
}

#[test]
fn test_kyber_serialization() {
    let kem = KyberKEM::new(SecurityLevel::Level3);
    let keypair = kem.generate_keypair();

    // Serialize keys
    let public_key_bytes = keypair.public_key.to_bytes();
    let private_key_bytes = keypair.private_key.to_bytes();

    // Deserialize keys
    let restored_public_key = KyberPublicKey::from_bytes(&public_key_bytes).unwrap();
    let restored_private_key = KyberPrivateKey::from_bytes(&private_key_bytes).unwrap();

    // Encapsulate with original key
    let encapsulated = kem.encapsulate(&keypair.public_key);
    let ciphertext_bytes = encapsulated.to_bytes();

    // Deserialize ciphertext
    let restored_encapsulated = KyberEncapsulated::from_bytes(&ciphertext_bytes).unwrap();

    // Decapsulate with restored key and restored ciphertext
    let shared_secret = kem.decapsulate(&restored_private_key, &restored_encapsulated);

    // We should still get a valid shared secret
    assert!(shared_secret.is_some());

    // Verify that different key pairs produce different shared secrets
    let keypair2 = kem.generate_keypair();
    let encapsulated2 = kem.encapsulate(&keypair2.public_key);

    // Different key pairs should generate different shared secrets
    assert_ne!(encapsulated.shared_secret(), encapsulated2.shared_secret());

    // Different public keys should produce different ciphertexts
    assert_ne!(encapsulated.ciphertext(), encapsulated2.ciphertext());

    // Decapsulating with the wrong private key should still produce a result,
    // but it won't match the original shared secret
    let wrong_shared_secret = kem.decapsulate(&keypair2.private_key, &encapsulated);
    assert!(wrong_shared_secret.is_some());
    assert_ne!(wrong_shared_secret.unwrap(), encapsulated.shared_secret());
}

#[test]
fn test_cross_level_compatibility() {
    // Test that keys from different security levels can't be mixed

    let kem512 = KyberKEM::new(SecurityLevel::Level1);
    let kem768 = KyberKEM::new(SecurityLevel::Level3);

    let keypair512 = kem512.generate_keypair();
    let keypair768 = kem768.generate_keypair();

    // Encapsulate with Level1 public key
    let encapsulated512 = kem512.encapsulate(&keypair512.public_key);

    // Try to decapsulate Level1 ciphertext with Level3 private key
    // This should still return a result but it won't be correct
    let _result = kem768.decapsulate(&keypair768.private_key, &encapsulated512);

    // The correct way is to match security levels
    let encapsulated768 = kem768.encapsulate(&keypair768.public_key);
    let shared_secret = kem768.decapsulate(&keypair768.private_key, &encapsulated768);
    assert!(shared_secret.is_some());
    assert_eq!(shared_secret.unwrap(), encapsulated768.shared_secret());
}

#[test]
fn test_dcrypt_compatibility() {
    // Test that the dcrypt wrapper works correctly
    let kem = KyberKEM::new(SecurityLevel::Level3);
    let keypair1 = kem.generate_keypair();
    let keypair2 = kem.generate_keypair();

    // Test encapsulation/decapsulation cycle
    let encapsulated = kem.encapsulate(&keypair1.public_key);
    let shared_secret = kem.decapsulate(&keypair1.private_key, &encapsulated);
    
    assert!(shared_secret.is_some());
    assert_eq!(shared_secret.unwrap().len(), 32);

    // Test that using wrong keys produces different results
    let wrong_secret = kem.decapsulate(&keypair2.private_key, &encapsulated);
    assert!(wrong_secret.is_some());
    assert_ne!(wrong_secret.unwrap(), encapsulated.shared_secret());
}```

######## File: crypto/src/kem/kyber/mod.rs
#####*Size: 12K, Lines: 313, Type: ASCII text*

```rust
// crates/crypto/src/kem/kyber/mod.rs
//! Kyber key encapsulation mechanism using dcrypt

use crate::security::SecurityLevel;
use depin_sdk_core::crypto::{
    DecapsulationKey, Encapsulated, EncapsulationKey, KemKeyPair, KeyEncapsulation,
    SerializableKey,
};
use dcrypt::api::Kem;
use dcrypt::kem::kyber::{
    Kyber512, Kyber768, Kyber1024,
    KyberCiphertext, KyberPublicKey as DcryptPublicKey, 
    KyberSecretKey as DcryptSecretKey,
    KyberSharedSecret,
};
use rand::{CryptoRng, RngCore};

/// Kyber key encapsulation mechanism
pub struct KyberKEM {
    /// Security level
    level: SecurityLevel,
}

/// Kyber key pair
pub struct KyberKeyPair {
    /// Public key
    pub public_key: KyberPublicKey,
    /// Private key
    pub private_key: KyberPrivateKey,
    /// Security level
    level: SecurityLevel,
}

/// Kyber public key wrapper
#[derive(Clone)]
pub struct KyberPublicKey {
    /// The underlying dcrypt public key
    inner: DcryptPublicKey,
    /// Security level
    level: SecurityLevel,
}

/// Kyber private key wrapper
#[derive(Clone)]
pub struct KyberPrivateKey {
    /// The underlying dcrypt secret key
    inner: DcryptSecretKey,
    /// Security level
    level: SecurityLevel,
}

/// Kyber encapsulated key
pub struct KyberEncapsulated {
    /// The ciphertext bytes
    ciphertext: Vec<u8>,
    /// The shared secret
    shared_secret: Vec<u8>,
    /// Security level
    level: SecurityLevel,
}

impl KyberKEM {
    /// Create a new Kyber KEM with the specified security level
    pub fn new(level: SecurityLevel) -> Self {
        Self { level }
    }
}

impl KeyEncapsulation for KyberKEM {
    type KeyPair = KyberKeyPair;
    type PublicKey = KyberPublicKey;
    type PrivateKey = KyberPrivateKey;
    type Encapsulated = KyberEncapsulated;

    fn generate_keypair(&self) -> Self::KeyPair {
        let mut rng = rand::thread_rng();
        
        // Use dcrypt's KEM trait to generate keypair based on security level
        let (pk, sk) = match self.level {
            SecurityLevel::Level1 => {
                let (pk, sk) = Kyber512::keypair(&mut rng)
                    .expect("Failed to generate Kyber512 keypair");
                (
                    KyberPublicKey {
                        inner: pk,
                        level: self.level,
                    },
                    KyberPrivateKey {
                        inner: sk,
                        level: self.level,
                    },
                )
            }
            SecurityLevel::Level3 => {
                let (pk, sk) = Kyber768::keypair(&mut rng)
                    .expect("Failed to generate Kyber768 keypair");
                (
                    KyberPublicKey {
                        inner: pk,
                        level: self.level,
                    },
                    KyberPrivateKey {
                        inner: sk,
                        level: self.level,
                    },
                )
            }
            SecurityLevel::Level5 => {
                let (pk, sk) = Kyber1024::keypair(&mut rng)
                    .expect("Failed to generate Kyber1024 keypair");
                (
                    KyberPublicKey {
                        inner: pk,
                        level: self.level,
                    },
                    KyberPrivateKey {
                        inner: sk,
                        level: self.level,
                    },
                )
            }
            _ => {
                // Default to Level1
                let (pk, sk) = Kyber512::keypair(&mut rng)
                    .expect("Failed to generate Kyber512 keypair");
                (
                    KyberPublicKey {
                        inner: pk,
                        level: SecurityLevel::Level1,
                    },
                    KyberPrivateKey {
                        inner: sk,
                        level: SecurityLevel::Level1,
                    },
                )
            }
        };

        KyberKeyPair {
            public_key: pk,
            private_key: sk,
            level: self.level,
        }
    }

    fn encapsulate(&self, public_key: &Self::PublicKey) -> Self::Encapsulated {
        let mut rng = rand::thread_rng();
        
        // Use dcrypt's KEM trait to encapsulate based on security level
        let (ct, ss) = match public_key.level {
            SecurityLevel::Level1 => {
                Kyber512::encapsulate(&mut rng, &public_key.inner)
                    .expect("Failed to encapsulate with Kyber512")
            }
            SecurityLevel::Level3 => {
                Kyber768::encapsulate(&mut rng, &public_key.inner)
                    .expect("Failed to encapsulate with Kyber768")
            }
            SecurityLevel::Level5 => {
                Kyber1024::encapsulate(&mut rng, &public_key.inner)
                    .expect("Failed to encapsulate with Kyber1024")
            }
            _ => {
                Kyber512::encapsulate(&mut rng, &public_key.inner)
                    .expect("Failed to encapsulate with Kyber512")
            }
        };

        KyberEncapsulated {
            ciphertext: ct.to_bytes(),
            shared_secret: ss.to_bytes_zeroizing().to_vec(),
            level: public_key.level,
        }
    }

    fn decapsulate(
        &self,
        private_key: &Self::PrivateKey,
        encapsulated: &Self::Encapsulated,
    ) -> Option<Vec<u8>> {
        // Reconstruct the ciphertext from bytes
        let ct = KyberCiphertext::from_bytes(&encapsulated.ciphertext).ok()?;
        
        // Use dcrypt's KEM trait to decapsulate based on security level
        let ss = match private_key.level {
            SecurityLevel::Level1 => {
                Kyber512::decapsulate(&private_key.inner, &ct)
                    .ok()?
            }
            SecurityLevel::Level3 => {
                Kyber768::decapsulate(&private_key.inner, &ct)
                    .ok()?
            }
            SecurityLevel::Level5 => {
                Kyber1024::decapsulate(&private_key.inner, &ct)
                    .ok()?
            }
            _ => {
                Kyber512::decapsulate(&private_key.inner, &ct)
                    .ok()?
            }
        };

        Some(ss.to_bytes_zeroizing().to_vec())
    }
}

impl KemKeyPair for KyberKeyPair {
    type PublicKey = KyberPublicKey;
    type PrivateKey = KyberPrivateKey;

    fn public_key(&self) -> Self::PublicKey {
        self.public_key.clone()
    }

    fn private_key(&self) -> Self::PrivateKey {
        self.private_key.clone()
    }
}

// KyberPublicKey implements the EncapsulationKey trait
impl SerializableKey for KyberPublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        // Use dcrypt's built-in to_bytes method
        self.inner.to_bytes()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Use dcrypt's built-in from_bytes method
        let inner = DcryptPublicKey::from_bytes(bytes)
            .map_err(|e| format!("Failed to deserialize Kyber public key: {:?}", e))?;
        
        // Try to determine the security level from the public key size
        let level = match bytes.len() {
            800 => SecurityLevel::Level1,  // Kyber512
            1184 => SecurityLevel::Level3, // Kyber768
            1568 => SecurityLevel::Level5, // Kyber1024
            _ => return Err(format!("Invalid Kyber public key size: {}", bytes.len())),
        };

        Ok(KyberPublicKey { inner, level })
    }
}

impl EncapsulationKey for KyberPublicKey {
    // EncapsulationKey trait has no additional methods beyond SerializableKey
}

// KyberPrivateKey implements the DecapsulationKey trait
impl SerializableKey for KyberPrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        // Use dcrypt's built-in to_bytes_zeroizing method
        self.inner.to_bytes_zeroizing().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Use dcrypt's built-in from_bytes method
        let inner = DcryptSecretKey::from_bytes(bytes)
            .map_err(|e| format!("Failed to deserialize Kyber private key: {:?}", e))?;
        
        // Try to determine the security level from the private key size
        let level = match bytes.len() {
            1632 => SecurityLevel::Level1, // Kyber512
            2400 => SecurityLevel::Level3, // Kyber768
            3168 => SecurityLevel::Level5, // Kyber1024
            _ => return Err(format!("Invalid Kyber private key size: {}", bytes.len())),
        };

        Ok(KyberPrivateKey { inner, level })
    }
}

impl DecapsulationKey for KyberPrivateKey {
    // DecapsulationKey trait has no additional methods beyond SerializableKey
}

// KyberEncapsulated implements the Encapsulated trait
impl SerializableKey for KyberEncapsulated {
    fn to_bytes(&self) -> Vec<u8> {
        // Return the ciphertext bytes
        self.ciphertext.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Try to determine the security level from the ciphertext size
        let level = match bytes.len() {
            768 => SecurityLevel::Level1,  // Kyber512
            1088 => SecurityLevel::Level3, // Kyber768
            1568 => SecurityLevel::Level5, // Kyber1024
            _ => return Err(format!("Invalid Kyber ciphertext size: {}", bytes.len())),
        };

        // We can't recover the shared secret from just the ciphertext
        // This will need to be decapsulated using a private key to get the shared secret
        Ok(KyberEncapsulated {
            ciphertext: bytes.to_vec(),
            shared_secret: vec![0; 32], // Placeholder until decapsulated
            level,
        })
    }
}

impl Encapsulated for KyberEncapsulated {
    fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    fn shared_secret(&self) -> &[u8] {
        &self.shared_secret
    }
}

#[cfg(test)]
mod tests;```

####### File: crypto/src/kem/mod.rs
####*Size: 4.0K, Lines: 2, Type: ASCII text*

```rust
pub mod kyber;
pub mod ecdh;
pub mod hybrid;```

###### Directory: crypto/src/sign

####### Directory: crypto/src/sign/dilithium

######## Directory: crypto/src/sign/dilithium/tests

######### File: crypto/src/sign/dilithium/tests/mod.rs
######*Size: 4.0K, Lines: 104, Type: ASCII text*

```rust
use super::*;

#[test]
fn test_dilithium_level2_sign_verify() {
    let scheme = DilithiumScheme::new(SecurityLevel::Level2);
    let keypair = scheme.generate_keypair();
    
    let message = b"Test message for Dilithium";
    let signature = keypair.sign(message);
    
    assert!(keypair.public_key().verify(message, &signature));
    
    // Test with wrong message
    let wrong_message = b"Wrong message";
    assert!(!keypair.public_key().verify(wrong_message, &signature));
}

#[test]
fn test_dilithium_level3_sign_verify() {
    let scheme = DilithiumScheme::new(SecurityLevel::Level3);
    let keypair = scheme.generate_keypair();
    
    let message = b"Test message for Dilithium Level 3";
    let signature = keypair.sign(message);
    
    assert!(keypair.public_key().verify(message, &signature));
}

#[test]
fn test_dilithium_level5_sign_verify() {
    let scheme = DilithiumScheme::new(SecurityLevel::Level5);
    let keypair = scheme.generate_keypair();
    
    let message = b"Test message for Dilithium Level 5";
    let signature = keypair.sign(message);
    
    assert!(keypair.public_key().verify(message, &signature));
}

#[test]
fn test_key_serialization() {
    let scheme = DilithiumScheme::new(SecurityLevel::Level2);
    let keypair = scheme.generate_keypair();
    
    // Test public key serialization
    let pk_bytes = keypair.public_key().to_bytes();
    let pk_restored = DilithiumPublicKey::from_bytes(&pk_bytes).unwrap();
    assert_eq!(pk_bytes, pk_restored.to_bytes());
    
    // Test private key serialization
    let sk_bytes = keypair.private_key().to_bytes();
    let sk_restored = DilithiumPrivateKey::from_bytes(&sk_bytes).unwrap();
    assert_eq!(sk_bytes, sk_restored.to_bytes());
    
    // Test signature with restored keys
    let message = b"Test serialization";
    let signature = scheme.sign(&sk_restored, message);
    assert!(scheme.verify(&pk_restored, message, &signature));
}

#[test]
fn test_signature_serialization() {
    let scheme = DilithiumScheme::new(SecurityLevel::Level2);
    let keypair = scheme.generate_keypair();
    
    let message = b"Test signature serialization";
    let signature = keypair.sign(message);
    
    // Serialize and deserialize signature
    let sig_bytes = signature.to_bytes();
    let sig_restored = DilithiumSignature::from_bytes(&sig_bytes).unwrap();
    
    // Verify with restored signature
    assert!(keypair.public_key().verify(message, &sig_restored));
}

#[test]
fn test_wrong_key_size_detection() {
    // Test with invalid key sizes
    let invalid_pk = vec![0u8; 1000]; // Invalid size
    let pk = DilithiumPublicKey::from_bytes(&invalid_pk).unwrap();
    
    let message = b"Test";
    let signature = DilithiumSignature(vec![0u8; 2420]); // Dilithium2 signature size
    
    // Should return false for invalid key size
    assert!(!pk.verify(message, &signature));
}

#[test]
fn test_cross_level_verification() {
    // Generate keys at different levels
    let scheme2 = DilithiumScheme::new(SecurityLevel::Level2);
    let keypair2 = scheme2.generate_keypair();
    
    let scheme3 = DilithiumScheme::new(SecurityLevel::Level3);
    let keypair3 = scheme3.generate_keypair();
    
    let message = b"Cross level test";
    let signature2 = keypair2.sign(message);
    
    // Level 3 public key should not verify Level 2 signature
    // (will fail due to key size mismatch detection)
    assert!(!keypair3.public_key().verify(message, &signature2));
}```

######## File: crypto/src/sign/dilithium/mod.rs
#####*Size: 12K, Lines: 316, Type: ASCII text*

```rust
//! Dilithium signature algorithm (using dcrypt implementation)
//!
use crate::security::SecurityLevel;
use depin_sdk_core::crypto::{
    SerializableKey, Signature, SigningKey, SigningKeyPair, VerifyingKey
};
// Import the trait needed for the signature operations
use dcrypt::api::Signature as SignatureTrait;
// Import the Dilithium implementations and types from the correct module path
use dcrypt::sign::pq::dilithium::{
    Dilithium2, Dilithium3, Dilithium5, 
    DilithiumPublicKey as DcryptPublicKey, 
    DilithiumSecretKey as DcryptSecretKey, 
    DilithiumSignatureData as DcryptSignatureData
};

/// Dilithium signature scheme
pub struct DilithiumScheme {
    /// Security level
    level: SecurityLevel,
}

/// Dilithium key pair
pub struct DilithiumKeyPair {
    /// Public key
    public_key: DilithiumPublicKey,
    /// Private key
    private_key: DilithiumPrivateKey,
    /// Security level (needed for signing)
    level: SecurityLevel,
}

/// Dilithium public key
pub struct DilithiumPublicKey(Vec<u8>);

/// Dilithium private key
pub struct DilithiumPrivateKey {
    data: Vec<u8>,
    level: SecurityLevel,
}

/// Dilithium signature
pub struct DilithiumSignature(Vec<u8>);

impl DilithiumScheme {
    /// Create a new Dilithium scheme with the specified security level
    pub fn new(level: SecurityLevel) -> Self {
        Self { level }
    }

    /// Generate a new key pair
    pub fn generate_keypair(&self) -> DilithiumKeyPair {
        let mut rng = rand::rngs::OsRng;
        
        match self.level {
            SecurityLevel::Level2 => {
                let (pk, sk) = Dilithium2::keypair(&mut rng).unwrap();
                DilithiumKeyPair {
                    public_key: DilithiumPublicKey(pk.to_bytes().to_vec()),
                    private_key: DilithiumPrivateKey {
                        data: sk.to_bytes().to_vec(),
                        level: self.level,
                    },
                    level: self.level,
                }
            }
            SecurityLevel::Level3 => {
                let (pk, sk) = Dilithium3::keypair(&mut rng).unwrap();
                DilithiumKeyPair {
                    public_key: DilithiumPublicKey(pk.to_bytes().to_vec()),
                    private_key: DilithiumPrivateKey {
                        data: sk.to_bytes().to_vec(),
                        level: self.level,
                    },
                    level: self.level,
                }
            }
            SecurityLevel::Level5 => {
                let (pk, sk) = Dilithium5::keypair(&mut rng).unwrap();
                DilithiumKeyPair {
                    public_key: DilithiumPublicKey(pk.to_bytes().to_vec()),
                    private_key: DilithiumPrivateKey {
                        data: sk.to_bytes().to_vec(),
                        level: self.level,
                    },
                    level: self.level,
                }
            }
            _ => {
                // Default to Level2 for any other security level
                let (pk, sk) = Dilithium2::keypair(&mut rng).unwrap();
                DilithiumKeyPair {
                    public_key: DilithiumPublicKey(pk.to_bytes().to_vec()),
                    private_key: DilithiumPrivateKey {
                        data: sk.to_bytes().to_vec(),
                        level: SecurityLevel::Level2,
                    },
                    level: SecurityLevel::Level2,
                }
            }
        }
    }

    /// Sign a message
    pub fn sign(&self, private_key: &DilithiumPrivateKey, message: &[u8]) -> DilithiumSignature {
        match private_key.level {
            SecurityLevel::Level2 => {
                let sk = DcryptSecretKey::from_bytes(&private_key.data).unwrap();
                let signature = Dilithium2::sign(message, &sk).unwrap();
                DilithiumSignature(signature.to_bytes().to_vec())
            }
            SecurityLevel::Level3 => {
                let sk = DcryptSecretKey::from_bytes(&private_key.data).unwrap();
                let signature = Dilithium3::sign(message, &sk).unwrap();
                DilithiumSignature(signature.to_bytes().to_vec())
            }
            SecurityLevel::Level5 => {
                let sk = DcryptSecretKey::from_bytes(&private_key.data).unwrap();
                let signature = Dilithium5::sign(message, &sk).unwrap();
                DilithiumSignature(signature.to_bytes().to_vec())
            }
            _ => {
                // Default to Level2
                let sk = DcryptSecretKey::from_bytes(&private_key.data).unwrap();
                let signature = Dilithium2::sign(message, &sk).unwrap();
                DilithiumSignature(signature.to_bytes().to_vec())
            }
        }
    }

    /// Verify a signature
    pub fn verify(
        &self,
        public_key: &DilithiumPublicKey,
        message: &[u8],
        signature: &DilithiumSignature,
    ) -> bool {
        // Determine security level from key size
        let level = match public_key.0.len() {
            1312 => SecurityLevel::Level2,  // Dilithium2
            1952 => SecurityLevel::Level3,  // Dilithium3
            2592 => SecurityLevel::Level5,  // Dilithium5
            _ => return false,
        };

        match level {
            SecurityLevel::Level2 => {
                let pk = DcryptPublicKey::from_bytes(&public_key.0).unwrap();
                let sig = DcryptSignatureData::from_bytes(&signature.0).unwrap();
                Dilithium2::verify(message, &sig, &pk).is_ok()
            }
            SecurityLevel::Level3 => {
                let pk = DcryptPublicKey::from_bytes(&public_key.0).unwrap();
                let sig = DcryptSignatureData::from_bytes(&signature.0).unwrap();
                Dilithium3::verify(message, &sig, &pk).is_ok()
            }
            SecurityLevel::Level5 => {
                let pk = DcryptPublicKey::from_bytes(&public_key.0).unwrap();
                let sig = DcryptSignatureData::from_bytes(&signature.0).unwrap();
                Dilithium5::verify(message, &sig, &pk).is_ok()
            }
            _ => false,
        }
    }
}

impl SigningKeyPair for DilithiumKeyPair {
    type PublicKey = DilithiumPublicKey;
    type PrivateKey = DilithiumPrivateKey;
    type Signature = DilithiumSignature;

    fn public_key(&self) -> Self::PublicKey {
        DilithiumPublicKey(self.public_key.0.clone())
    }

    fn private_key(&self) -> Self::PrivateKey {
        DilithiumPrivateKey {
            data: self.private_key.data.clone(),
            level: self.private_key.level,
        }
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        match self.level {
            SecurityLevel::Level2 => {
                let sk = DcryptSecretKey::from_bytes(&self.private_key.data).unwrap();
                let signature = Dilithium2::sign(message, &sk).unwrap();
                DilithiumSignature(signature.to_bytes().to_vec())
            }
            SecurityLevel::Level3 => {
                let sk = DcryptSecretKey::from_bytes(&self.private_key.data).unwrap();
                let signature = Dilithium3::sign(message, &sk).unwrap();
                DilithiumSignature(signature.to_bytes().to_vec())
            }
            SecurityLevel::Level5 => {
                let sk = DcryptSecretKey::from_bytes(&self.private_key.data).unwrap();
                let signature = Dilithium5::sign(message, &sk).unwrap();
                DilithiumSignature(signature.to_bytes().to_vec())
            }
            _ => {
                // Default to Level2
                let sk = DcryptSecretKey::from_bytes(&self.private_key.data).unwrap();
                let signature = Dilithium2::sign(message, &sk).unwrap();
                DilithiumSignature(signature.to_bytes().to_vec())
            }
        }
    }
}

impl VerifyingKey for DilithiumPublicKey {
    type Signature = DilithiumSignature;

    fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool {
        // Determine security level from key size
        let level = match self.0.len() {
            1312 => SecurityLevel::Level2,  // Dilithium2
            1952 => SecurityLevel::Level3,  // Dilithium3
            2592 => SecurityLevel::Level5,  // Dilithium5
            _ => return false,
        };

        match level {
            SecurityLevel::Level2 => {
                let pk = DcryptPublicKey::from_bytes(&self.0).unwrap();
                let sig = DcryptSignatureData::from_bytes(&signature.0).unwrap();
                Dilithium2::verify(message, &sig, &pk).is_ok()
            }
            SecurityLevel::Level3 => {
                let pk = DcryptPublicKey::from_bytes(&self.0).unwrap();
                let sig = DcryptSignatureData::from_bytes(&signature.0).unwrap();
                Dilithium3::verify(message, &sig, &pk).is_ok()
            }
            SecurityLevel::Level5 => {
                let pk = DcryptPublicKey::from_bytes(&self.0).unwrap();
                let sig = DcryptSignatureData::from_bytes(&signature.0).unwrap();
                Dilithium5::verify(message, &sig, &pk).is_ok()
            }
            _ => false,
        }
    }
}

impl SerializableKey for DilithiumPublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        Ok(DilithiumPublicKey(bytes.to_vec()))
    }
}

impl SigningKey for DilithiumPrivateKey {
    type Signature = DilithiumSignature;

    fn sign(&self, message: &[u8]) -> Self::Signature {
        match self.level {
            SecurityLevel::Level2 => {
                let sk = DcryptSecretKey::from_bytes(&self.data).unwrap();
                let signature = Dilithium2::sign(message, &sk).unwrap();
                DilithiumSignature(signature.to_bytes().to_vec())
            }
            SecurityLevel::Level3 => {
                let sk = DcryptSecretKey::from_bytes(&self.data).unwrap();
                let signature = Dilithium3::sign(message, &sk).unwrap();
                DilithiumSignature(signature.to_bytes().to_vec())
            }
            SecurityLevel::Level5 => {
                let sk = DcryptSecretKey::from_bytes(&self.data).unwrap();
                let signature = Dilithium5::sign(message, &sk).unwrap();
                DilithiumSignature(signature.to_bytes().to_vec())
            }
            _ => {
                // Default to Level2
                let sk = DcryptSecretKey::from_bytes(&self.data).unwrap();
                let signature = Dilithium2::sign(message, &sk).unwrap();
                DilithiumSignature(signature.to_bytes().to_vec())
            }
        }
    }
}

impl SerializableKey for DilithiumPrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Determine security level from key size
        let level = match bytes.len() {
            2560 => SecurityLevel::Level2,  // Dilithium2
            4032 => SecurityLevel::Level3,  // Dilithium3
            4896 => SecurityLevel::Level5,  // Dilithium5
            _ => return Err("Invalid Dilithium private key size".to_string()),
        };
        
        Ok(DilithiumPrivateKey {
            data: bytes.to_vec(),
            level,
        })
    }
}

impl SerializableKey for DilithiumSignature {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        Ok(DilithiumSignature(bytes.to_vec()))
    }
}

impl Signature for DilithiumSignature {}

#[cfg(test)]
mod tests;```

####### Directory: crypto/src/sign/eddsa

######## Directory: crypto/src/sign/eddsa/tests

######### File: crypto/src/sign/eddsa/tests/mod.rs
######*Size: 4.0K, Lines: 98, Type: ASCII text*

```rust
use super::*;

#[test]
fn test_keypair_generation() {
    let keypair = Ed25519KeyPair::generate();
    let message = b"Test message";
    
    // Sign
    let signature = keypair.sign(message);
    
    // Verify
    let public_key = keypair.public_key();
    assert!(public_key.verify(message, &signature));
}

#[test]
fn test_serialization_roundtrip() {
    let keypair = Ed25519KeyPair::generate();
    
    // Serialize keys
    let public_bytes = keypair.public_key().to_bytes();
    let private_bytes = keypair.private_key().to_bytes();
    
    // Verify lengths
    assert_eq!(public_bytes.len(), 32);
    assert_eq!(private_bytes.len(), 32); // Just the seed
    
    // Deserialize
    let public_key = Ed25519PublicKey::from_bytes(&public_bytes).unwrap();
    let private_key = Ed25519PrivateKey::from_bytes(&private_bytes).unwrap();
    
    // Verify we can derive the same public key from the loaded private key
    let derived_public = private_key.public_key().unwrap();
    assert_eq!(public_key.to_bytes(), derived_public.to_bytes());
}

#[test]
fn test_sign_verify_with_loaded_keys() {
    // Generate original keypair
    let original_keypair = Ed25519KeyPair::generate();
    let message = b"Test message for persistence";
    
    // Sign with original
    let original_sig = original_keypair.sign(message);
    
    // Serialize private key
    let private_bytes = original_keypair.private_key().to_bytes();
    
    // Load private key from bytes
    let loaded_private = Ed25519PrivateKey::from_bytes(&private_bytes).unwrap();
    
    // Reconstruct keypair from loaded private key
    let reconstructed_keypair = Ed25519KeyPair::from_private_key(&loaded_private);
    
    // Sign with reconstructed keypair
    let new_sig = reconstructed_keypair.sign(message);
    
    // Signatures should be deterministic and identical
    assert_eq!(original_sig.to_bytes(), new_sig.to_bytes());
    
    // Verify with both public keys
    let original_public = original_keypair.public_key();
    let reconstructed_public = reconstructed_keypair.public_key();
    
    assert!(original_public.verify(message, &original_sig));
    assert!(reconstructed_public.verify(message, &new_sig));
    assert!(original_public.verify(message, &new_sig));
    assert!(reconstructed_public.verify(message, &original_sig));
}

#[test]
fn test_wrong_signature_fails() {
    let keypair1 = Ed25519KeyPair::generate();
    let keypair2 = Ed25519KeyPair::generate();
    
    let message = b"Test message";
    
    // Sign with keypair1
    let signature = keypair1.sign(message);
    
    // Verify with keypair2's public key should fail
    let public_key2 = keypair2.public_key();
    assert!(!public_key2.verify(message, &signature));
}

#[test]
fn test_tampered_message_fails() {
    let keypair = Ed25519KeyPair::generate();
    let message = b"Original message";
    let tampered = b"Tampered message";
    
    // Sign original
    let signature = keypair.sign(message);
    
    // Verify tampered message with same signature should fail
    let public_key = keypair.public_key();
    assert!(public_key.verify(message, &signature));
    assert!(!public_key.verify(tampered, &signature));
}```

######## File: crypto/src/sign/eddsa/mod.rs
#####*Size: 8.0K, Lines: 184, Type: ASCII text*

```rust
// crates/crypto/src/traditional/eddsa/mod.rs
//! Implementation of elliptic curve cryptography using dcrypt

use depin_sdk_core::crypto::{
    SerializableKey, Signature, SigningKey, SigningKeyPair, VerifyingKey
};
use dcrypt::api::Signature as SignatureTrait;
use rand::rngs::OsRng;

// Import dcrypt Ed25519 module with module qualification
use dcrypt::sign::traditional::eddsa;

/// Ed25519 key pair implementation
pub struct Ed25519KeyPair {
    /// Public verification key
    public_key: eddsa::Ed25519PublicKey,
    /// Private signing key
    secret_key: eddsa::Ed25519SecretKey,
}

/// Ed25519 signature implementation
pub struct Ed25519Signature(eddsa::Ed25519Signature);

/// Ed25519 public key implementation
pub struct Ed25519PublicKey(eddsa::Ed25519PublicKey);

/// Ed25519 private key implementation
pub struct Ed25519PrivateKey(eddsa::Ed25519SecretKey);

impl Ed25519KeyPair {
    /// Generate a new Ed25519 key pair
    pub fn generate() -> Self {
        let mut rng = OsRng;
        
        // Generate key pair using dcrypt
        let (public_key, secret_key) = eddsa::Ed25519::keypair(&mut rng)
            .expect("Failed to generate Ed25519 key pair");

        Self {
            public_key,
            secret_key,
        }
    }

    /// Create from an existing private key
    pub fn from_private_key(private_key: &Ed25519PrivateKey) -> Self {
        let secret_key = private_key.0.clone();
        
        // Use the helper method to derive public key
        let public_key = secret_key.public_key()
            .expect("Failed to derive public key from secret key");

        Self {
            public_key,
            secret_key,
        }
    }
}

impl SigningKeyPair for Ed25519KeyPair {
    type PublicKey = Ed25519PublicKey;
    type PrivateKey = Ed25519PrivateKey;
    type Signature = Ed25519Signature;

    fn public_key(&self) -> Self::PublicKey {
        Ed25519PublicKey(self.public_key.clone())
    }

    fn private_key(&self) -> Self::PrivateKey {
        Ed25519PrivateKey(self.secret_key.clone())
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        let signature = eddsa::Ed25519::sign(message, &self.secret_key)
            .expect("Failed to sign message");
        Ed25519Signature(signature)
    }
}

impl VerifyingKey for Ed25519PublicKey {
    type Signature = Ed25519Signature;

    fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool {
        eddsa::Ed25519::verify(message, &signature.0, &self.0).is_ok()
    }
}

impl SerializableKey for Ed25519PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        eddsa::Ed25519PublicKey::from_bytes(bytes)
            .map(Ed25519PublicKey)
            .map_err(|e| format!("Failed to parse public key: {:?}", e))
    }
}

impl SigningKey for Ed25519PrivateKey {
    type Signature = Ed25519Signature;

    fn sign(&self, message: &[u8]) -> Self::Signature {
        let signature = eddsa::Ed25519::sign(message, &self.0)
            .expect("Failed to sign message");
        Ed25519Signature(signature)
    }
}

impl SerializableKey for Ed25519PrivateKey {
    fn to_bytes(&self) -> Vec<u8> {
        // Export just the seed (32 bytes)
        self.0.seed().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 32 {
            return Err("Invalid private key length: expected 32 bytes".to_string());
        }
        
        let mut seed = [0u8; 32];
        seed.copy_from_slice(bytes);
        
        // Use the from_seed method
        eddsa::Ed25519SecretKey::from_seed(&seed)
            .map(Ed25519PrivateKey)
            .map_err(|e| format!("Failed to create secret key from seed: {:?}", e))
    }
}

impl SerializableKey for Ed25519Signature {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        eddsa::Ed25519Signature::from_bytes(bytes)
            .map(Ed25519Signature)
            .map_err(|e| format!("Failed to parse signature: {:?}", e))
    }
}

impl Signature for Ed25519Signature {}

// Additional Ed25519-specific functionality
impl Ed25519Signature {
    /// Get the raw signature bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0.0  // Access the inner array through the public field
    }
}

impl Ed25519PublicKey {
    /// Get the raw public key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0.0  // Access the inner array through the public field
    }

    /// Construct from dcrypt public key
    pub fn from_dcrypt_key(key: eddsa::Ed25519PublicKey) -> Self {
        Self(key)
    }
}

impl Ed25519PrivateKey {
    /// Get the raw private key seed bytes (32 bytes)
    pub fn as_bytes(&self) -> &[u8] {
        self.0.seed()
    }

    /// Construct from dcrypt secret key
    pub fn from_dcrypt_key(key: eddsa::Ed25519SecretKey) -> Self {
        Self(key)
    }
    
    /// Get the public key corresponding to this private key
    pub fn public_key(&self) -> Result<Ed25519PublicKey, String> {
        self.0.public_key()
            .map(Ed25519PublicKey)
            .map_err(|e| format!("Failed to derive public key: {:?}", e))
    }
}

#[cfg(test)]
mod tests;```

####### File: crypto/src/sign/mod.rs
####*Size: 4.0K, Lines: 1, Type: ASCII text*

```rust
pub mod dilithium;
pub mod eddsa;```

###### File: crypto/src/lib.rs
###*Size: 4.0K, Lines: 18, Type: ASCII text*

```rust
//! # DePIN SDK Cryptography
//!
//! Cryptographic implementations for the DePIN SDK including post-quantum algorithms.

pub mod algorithms;
pub mod sign;
pub mod kem;
pub mod security;

// Simpler test module structure - don't re-export test modules
#[cfg(test)]
mod tests {
    // Simple canary test to verify test discovery is working
    #[test]
    fn test_crypto_canary() {
        assert!(true, "Basic test discovery is working");
    }
}
```

###### File: crypto/src/security.rs
###*Size: 4.0K, Lines: 34, Type: ASCII text*

```rust
/// Post-quantum security level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// NIST Level 1 (approximately 128-bit classical security)
    Level1,
    /// NIST Level 2
    Level2,
    /// NIST Level 3 (approximately 192-bit classical security)
    Level3,
    /// NIST Level 5 (approximately 256-bit classical security)
    Level5,
}

impl SecurityLevel {
    /// Get the equivalent classical security bits
    pub fn classical_bits(&self) -> usize {
        match self {
            SecurityLevel::Level1 => 128,
            SecurityLevel::Level2 => 160,
            SecurityLevel::Level3 => 192,
            SecurityLevel::Level5 => 256,
        }
    }

    /// Get the equivalent quantum security bits
    pub fn quantum_bits(&self) -> usize {
        match self {
            SecurityLevel::Level1 => 64,
            SecurityLevel::Level2 => 80,
            SecurityLevel::Level3 => 96,
            SecurityLevel::Level5 => 128,
        }
    }
}
```

##### File: crypto/Cargo.toml
##*Size: 4.0K, Lines: 18, Type: ASCII text*

```toml
[package]
name = "depin-sdk-crypto"
version = "0.1.0"
edition = "2021"
description = "Cryptographic implementations for the DePIN SDK"
license = "MIT OR Apache-2.0"

[dependencies]
depin-sdk-core = { path = "../core" }
log = { workspace = true }
serde = { workspace = true }
thiserror = { workspace = true }
rand = { workspace = true }
bytes = { workspace = true }
dcrypt = { version = "0.12.0-beta.1", features = ["full"] }

[features]
default = []
```

#### Directory: homomorphic

##### Directory: homomorphic/src

###### Directory: homomorphic/src/computation

####### Directory: homomorphic/src/computation/tests

######## File: homomorphic/src/computation/tests/mod.rs
#####*Size: 8.0K, Lines: 146, Type: ASCII text*

```rust
use super::*;
use depin_sdk_commitment_schemes::elliptical_curve::{
    EllipticalCurveCommitment, EllipticalCurveCommitmentScheme,
};
use depin_sdk_core::commitment::CommitmentScheme;
use std::any::Any;

#[test]
fn test_computation_engine() {
    // Create a computation engine with EllipticalCurve commitment scheme
    let scheme = EllipticalCurveCommitmentScheme::new(5);
    let computation = HomomorphicComputation::new(scheme.clone());

    // Test add operation
    let value_a = b"value a";
    let value_b = b"value b";
    let commitment_a = scheme.commit(&[Some(value_a.to_vec())]);
    let commitment_b = scheme.commit(&[Some(value_b.to_vec())]);

    let left: Arc<dyn Any + Send + Sync> = Arc::new(commitment_a.clone());
    let right: Arc<dyn Any + Send + Sync> = Arc::new(commitment_b.clone());

    let add_op = CommitmentOperation::Add { left, right };
    let result = computation.execute(&add_op);

    match result {
        OperationResult::Success(result_arc) => {
            let sum = result_arc
                .downcast_ref::<EllipticalCurveCommitment>()
                .unwrap();

            // Compute expected result directly
            let expected = scheme.add(&commitment_a, &commitment_b).unwrap();
            assert_eq!(sum.as_ref(), expected.as_ref());

            // Create a proof for the operation with a selector
            let selector = Selector::Position(0);
            let proof = computation
                .create_proof_with_selector(&add_op, sum, &selector)
                .unwrap();

            // Verify the proof with context
            let context = ProofContext::default();
            let verified = computation
                .verify_proof_with_context(&proof, &context)
                .unwrap();
            assert!(verified);
        }
        _ => panic!("Add operation failed or unsupported"),
    }

    // Test scalar multiply operation
    let commitment_arc: Arc<dyn Any + Send + Sync> = Arc::new(commitment_a.clone());
    let scalar = 3;

    let scalar_op = CommitmentOperation::ScalarMultiply {
        commitment: commitment_arc,
        scalar,
    };
    let result = computation.execute(&scalar_op);

    match result {
        OperationResult::Success(result_arc) => {
            let product = result_arc
                .downcast_ref::<EllipticalCurveCommitment>()
                .unwrap();

            // Compute expected result directly
            let expected = scheme.scalar_multiply(&commitment_a, scalar).unwrap();
            assert_eq!(product.as_ref(), expected.as_ref());

            // Create a proof for the operation with a key selector
            let key = b"test_key".to_vec();
            let selector = Selector::Key(key);
            let proof = computation
                .create_proof_with_selector(&scalar_op, product, &selector)
                .unwrap();

            // Create a context with some data
            let mut context = ProofContext::default();
            context.add_data("test", vec![1, 2, 3]);

            // Verify the proof with context
            let verified = computation
                .verify_proof_with_context(&proof, &context)
                .unwrap();
            assert!(verified);
        }
        _ => panic!("Scalar multiply operation failed or unsupported"),
    }

    // Test combined operation and proof generation
    let key = b"combined_op_key".to_vec();
    let selector = Selector::Key(key);
    let (result, proof) = computation.apply_and_prove(&add_op, &selector).unwrap();

    // Verify the result and proof
    let verified = computation.verify_proof(&proof).unwrap();
    assert!(verified);

    // The result should match direct computation
    let expected = scheme.add(&commitment_a, &commitment_b).unwrap();
    assert_eq!(result.as_ref(), expected.as_ref());
}

#[test]
fn test_batch_operations() {
    // Create a computation engine with Elliptical Curve commitment scheme
    let scheme = EllipticalCurveCommitmentScheme::new(5);
    let computation = HomomorphicComputation::new(scheme.clone());

    // Create test commitments
    let value_a = b"value a";
    let value_b = b"value b";
    let commitment_a = scheme.commit(&[Some(value_a.to_vec())]);
    let commitment_b = scheme.commit(&[Some(value_b.to_vec())]);

    // Create a batch of operations with selectors
    let operations = vec![
        (
            CommitmentOperation::Add {
                left: Arc::new(commitment_a.clone()),
                right: Arc::new(commitment_b.clone()),
            },
            Selector::Position(0),
        ),
        (
            CommitmentOperation::ScalarMultiply {
                commitment: Arc::new(commitment_a.clone()),
                scalar: 3,
            },
            Selector::Key(b"test_key".to_vec()),
        ),
    ];

    // Apply batch and generate proofs
    let batch_results = computation.apply_batch_and_prove(&operations).unwrap();

    // Check the batch results
    assert_eq!(batch_results.len(), 2);

    // Verify all proofs
    for (_, proof) in &batch_results {
        let verified = computation.verify_proof(proof).unwrap();
        assert!(verified);
    }
}```

####### File: homomorphic/src/computation/mod.rs
####*Size: 8.0K, Lines: 175, Type: ASCII text*

```rust
use crate::error::HomomorphicResult;
use crate::operations::{
    execute_add, execute_custom, execute_scalar_multiply, CustomOperationRegistry,
};
use crate::operations::{execute_batch, execute_composite, BatchResult, CompositeOperation};
use crate::proof::{HomomorphicProof, ProofGenerator};
use depin_sdk_core::commitment::{HomomorphicCommitmentScheme, ProofContext, Selector};
use depin_sdk_core::homomorphic::{CommitmentOperation, OperationResult};
use std::sync::Arc;

/// Computation engine for homomorphic operations
pub struct HomomorphicComputation<CS: HomomorphicCommitmentScheme> {
    /// Commitment scheme
    scheme: CS,
    /// Custom operation registry
    registry: Arc<CustomOperationRegistry>,
    /// Proof generator
    proof_generator: ProofGenerator<CS>,
}

impl<CS: HomomorphicCommitmentScheme + Clone> HomomorphicComputation<CS> {
    /// Create a new computation engine with the given scheme
    pub fn new(scheme: CS) -> Self {
        let registry = Arc::new(CustomOperationRegistry::new());
        let proof_generator = ProofGenerator::new(scheme.clone());

        Self {
            scheme,
            registry,
            proof_generator,
        }
    }

    /// Execute an operation
    pub fn execute(&self, operation: &CommitmentOperation) -> OperationResult {
        match operation {
            CommitmentOperation::Add { .. } => execute_add(&self.scheme, operation),
            CommitmentOperation::ScalarMultiply { .. } => {
                execute_scalar_multiply(&self.scheme, operation)
            }
            CommitmentOperation::Custom { .. } => execute_custom(&self.registry, operation),
        }
    }

    /// Execute a batch of operations
    pub fn execute_batch(&self, operations: &[CommitmentOperation]) -> BatchResult {
        execute_batch(operations, |op| self.execute(op))
    }

    /// Execute a composite operation
    pub fn execute_composite(
        &self,
        operation: &CompositeOperation,
    ) -> HomomorphicResult<OperationResult> {
        execute_composite(operation, |op| self.execute(op))
    }

    /// Get the custom operation registry
    pub fn registry(&self) -> Arc<CustomOperationRegistry> {
        self.registry.clone()
    }

    /// Get the underlying commitment scheme
    pub fn scheme(&self) -> &CS {
        &self.scheme
    }

    /// Create a proof for an operation
    pub fn create_proof(
        &self,
        operation: &CommitmentOperation,
        result: &CS::Commitment,
    ) -> HomomorphicResult<HomomorphicProof<CS>> {
        // Default to None selector for simple proofs
        self.create_proof_with_selector(operation, result, &Selector::None)
    }

    /// Create a proof for an operation with a specific selector
    pub fn create_proof_with_selector(
        &self,
        operation: &CommitmentOperation,
        result: &CS::Commitment,
        selector: &Selector,
    ) -> HomomorphicResult<HomomorphicProof<CS>> {
        self.proof_generator
            .prove_operation_with_selector(operation, result, selector)
    }

    /// Create a proof for an operation with a position selector
    pub fn create_proof_at_position(
        &self,
        operation: &CommitmentOperation,
        result: &CS::Commitment,
        position: usize,
    ) -> HomomorphicResult<HomomorphicProof<CS>> {
        self.create_proof_with_selector(operation, result, &Selector::Position(position))
    }

    /// Create a proof for an operation with a key selector
    pub fn create_proof_for_key(
        &self,
        operation: &CommitmentOperation,
        result: &CS::Commitment,
        key: &[u8],
    ) -> HomomorphicResult<HomomorphicProof<CS>> {
        self.create_proof_with_selector(operation, result, &Selector::Key(key.to_vec()))
    }

    /// Verify a homomorphic proof
    pub fn verify_proof(&self, proof: &HomomorphicProof<CS>) -> HomomorphicResult<bool> {
        // Use default empty context for simple verification
        self.verify_proof_with_context(proof, &ProofContext::default())
    }

    /// Verify a homomorphic proof with context
    pub fn verify_proof_with_context(
        &self,
        proof: &HomomorphicProof<CS>,
        context: &ProofContext,
    ) -> HomomorphicResult<bool> {
        self.proof_generator
            .verify_proof_with_context(proof, context)
    }

    /// Apply an operation and create a proof with a specific selector
    pub fn apply_and_prove(
        &self,
        operation: &CommitmentOperation,
        selector: &Selector,
    ) -> HomomorphicResult<(CS::Commitment, HomomorphicProof<CS>)> {
        // Execute the operation
        let result = match self.execute(operation) {
            OperationResult::Success(result_arc) => {
                match result_arc.downcast_ref::<CS::Commitment>() {
                    Some(commitment) => commitment.clone(),
                    None => {
                        return Err(crate::error::HomomorphicError::InvalidInput(
                            "Operation result is not the correct commitment type".into(),
                        ))
                    }
                }
            }
            OperationResult::Failure(err) => {
                return Err(crate::error::HomomorphicError::Custom(err))
            }
            OperationResult::Unsupported => {
                return Err(crate::error::HomomorphicError::UnsupportedOperation(
                    depin_sdk_core::commitment::HomomorphicOperation::Custom(0),
                ))
            }
        };

        // Create proof for the operation
        let proof = self.create_proof_with_selector(operation, &result, selector)?;

        Ok((result, proof))
    }

    /// Apply a batch of operations and create proofs with specified selectors
    pub fn apply_batch_and_prove(
        &self,
        operations: &[(CommitmentOperation, Selector)],
    ) -> HomomorphicResult<Vec<(CS::Commitment, HomomorphicProof<CS>)>> {
        let mut results = Vec::with_capacity(operations.len());

        for (operation, selector) in operations {
            let (commitment, proof) = self.apply_and_prove(operation, selector)?;
            results.push((commitment, proof));
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests;```

###### Directory: homomorphic/src/operations

####### Directory: homomorphic/src/operations/add

######## Directory: homomorphic/src/operations/add/tests

######### File: homomorphic/src/operations/add/tests/mod.rs
######*Size: 4.0K, Lines: 68, Type: ASCII text*

```rust
use super::*;
use depin_sdk_commitment_schemes::elliptical_curve::{
    EllipticalCurveCommitment, EllipticalCurveCommitmentScheme,
};
use crate::operations::{add, execute_add};

use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_core::homomorphic::CommitmentOperation;
use std::any::Any;
use std::sync::Arc;


#[test]
fn test_add_operation() {
    let scheme = EllipticalCurveCommitmentScheme::new(5);

    // Create two commitments
    let value_a = b"value a";
    let value_b = b"value b";
    let commitment_a = scheme.commit(&[Some(value_a.to_vec())]);
    let commitment_b = scheme.commit(&[Some(value_b.to_vec())]);

    // Test direct add function
    let sum_result = add(&scheme, &commitment_a, &commitment_b);
    assert!(sum_result.is_ok());

    // Test execute_add with CommitmentOperation
    let left: Arc<dyn Any + Send + Sync> = Arc::new(commitment_a.clone());
    let right: Arc<dyn Any + Send + Sync> = Arc::new(commitment_b.clone());

    let operation = CommitmentOperation::Add { left, right };
    let result = execute_add(&scheme, &operation);

    match result {
        OperationResult::Success(result_arc) => {
            let sum = result_arc
                .downcast_ref::<EllipticalCurveCommitment>()
                .unwrap();
            assert_ne!(sum.as_ref(), commitment_a.as_ref());
            assert_ne!(sum.as_ref(), commitment_b.as_ref());
        }
        _ => panic!("Operation failed or unsupported"),
    }
}

#[test]
fn test_add_invalid_input() {
    let scheme = EllipticalCurveCommitmentScheme::new(5);

    // Create a valid commitment
    let value = b"test value";
    let commitment = scheme.commit(&[Some(value.to_vec())]);

    // Create an invalid right operand
    let left: Arc<dyn Any + Send + Sync> = Arc::new(commitment);
    let right: Arc<dyn Any + Send + Sync> = Arc::new("not a commitment");

    let operation = CommitmentOperation::Add { left, right };
    let result = execute_add(&scheme, &operation);

    match result {
        OperationResult::Failure(error) => {
            assert!(error.contains("Right operand is not the correct commitment type"));
        }
        _ => panic!("Expected failure for invalid input"),
    }
}

```

######## File: homomorphic/src/operations/add/mod.rs
#####*Size: 4.0K, Lines: 58, Type: ASCII text*

```rust
use crate::error::{HomomorphicError, HomomorphicResult};
use depin_sdk_core::commitment::HomomorphicCommitmentScheme;
use depin_sdk_core::homomorphic::{CommitmentOperation, OperationResult};
use std::sync::Arc;

/// Add two commitments
pub fn add<C: HomomorphicCommitmentScheme>(
    scheme: &C,
    left: &C::Commitment,
    right: &C::Commitment,
) -> HomomorphicResult<C::Commitment> {
    scheme.add(left, right).map_err(HomomorphicError::from)
}

/// Execute an add operation
pub fn execute_add<C: HomomorphicCommitmentScheme>(
    scheme: &C,
    operation: &CommitmentOperation,
) -> OperationResult {
    match operation {
        CommitmentOperation::Add { left, right } => {
            // Try to downcast the Arc<dyn Any> to the correct commitment type
            let left_commitment = match left.downcast_ref::<C::Commitment>() {
                Some(c) => c,
                None => {
                    return OperationResult::Failure(
                        HomomorphicError::InvalidInput(
                            "Left operand is not the correct commitment type".into(),
                        )
                        .to_string(),
                    )
                }
            };

            let right_commitment = match right.downcast_ref::<C::Commitment>() {
                Some(c) => c,
                None => {
                    return OperationResult::Failure(
                        HomomorphicError::InvalidInput(
                            "Right operand is not the correct commitment type".into(),
                        )
                        .to_string(),
                    )
                }
            };

            // Perform the addition
            match add(scheme, left_commitment, right_commitment) {
                Ok(result) => OperationResult::Success(Arc::new(result)),
                Err(e) => OperationResult::Failure(e.to_string()),
            }
        }
        _ => OperationResult::Unsupported,
    }
}

#[cfg(test)]
mod tests;
```

####### Directory: homomorphic/src/operations/batch

######## Directory: homomorphic/src/operations/batch/tests

######### File: homomorphic/src/operations/batch/tests/mod.rs
######*Size: 8.0K, Lines: 197, Type: ASCII text*

```rust
use super::*;
use depin_sdk_core::homomorphic::OperationResult;
use std::any::Any;

#[test]
fn test_batch_execution() {
    // Create a mock executor
    let executor = |op: &CommitmentOperation| match op {
        CommitmentOperation::Custom { operation_id, .. } => {
            if operation_id == "succeed" {
                OperationResult::Success(Arc::new(true))
            } else if operation_id == "fail" {
                OperationResult::Failure("Operation failed".into())
            } else {
                OperationResult::Unsupported
            }
        }
        _ => OperationResult::Unsupported,
    };

    // Create a batch of operations
    let operations = vec![
        CommitmentOperation::Custom {
            operation_id: "succeed".to_string(),
            inputs: vec![],
            parameters: vec![],
        },
        CommitmentOperation::Custom {
            operation_id: "succeed".to_string(),
            inputs: vec![],
            parameters: vec![],
        },
        CommitmentOperation::Custom {
            operation_id: "fail".to_string(),
            inputs: vec![],
            parameters: vec![],
        },
        CommitmentOperation::Custom {
            operation_id: "unknown".to_string(),
            inputs: vec![],
            parameters: vec![],
        },
    ];

    // Execute the batch
    let batch_result = execute_batch(&operations[..], executor);

    // Check the results
    assert_eq!(batch_result.results.len(), 4);
    assert_eq!(batch_result.success_count, 2);
    assert_eq!(batch_result.failure_count, 1);
    assert_eq!(batch_result.unsupported_count, 1);
    assert!(!batch_result.all_successful());
    assert_eq!(batch_result.success_rate(), 50.0);
}

#[test]
fn test_composite_sequence() {
    // Create a mock executor
    let executor = |op: &CommitmentOperation| match op {
        CommitmentOperation::Custom { operation_id, .. } => {
            if operation_id == "succeed" {
                OperationResult::Success(Arc::new(true))
            } else {
                OperationResult::Failure("Operation failed".into())
            }
        }
        _ => OperationResult::Unsupported,
    };

    // Create a sequence of operations
    let sequence = CompositeOperation::Sequence(vec![
        CommitmentOperation::Custom {
            operation_id: "succeed".to_string(),
            inputs: vec![],
            parameters: vec![],
        },
        CommitmentOperation::Custom {
            operation_id: "succeed".to_string(),
            inputs: vec![],
            parameters: vec![],
        },
    ]);

    // Execute the sequence
    let result = execute_composite(&sequence, executor).unwrap();

    match result {
        OperationResult::Success(_) => {} // Expected
        _ => panic!("Expected successful sequence execution"),
    }

    // Create a sequence with a failure
    let sequence_with_failure = CompositeOperation::Sequence(vec![
        CommitmentOperation::Custom {
            operation_id: "succeed".to_string(),
            inputs: vec![],
            parameters: vec![],
        },
        CommitmentOperation::Custom {
            operation_id: "fail".to_string(),
            inputs: vec![],
            parameters: vec![],
        },
    ]);

    // Execute the sequence with failure
    let result = execute_composite(&sequence_with_failure, executor).unwrap();

    match result {
        OperationResult::Failure(error) => {
            assert_eq!(error, "Operation failed");
        }
        _ => panic!("Expected failure in sequence execution"),
    }
}

#[test]
fn test_composite_conditional() {
    // Create a mock executor
    let executor = |op: &CommitmentOperation| match op {
        CommitmentOperation::Custom { operation_id, .. } => {
            if operation_id == "condition_true" {
                OperationResult::Success(Arc::new(true) as Arc<dyn Any + Send + Sync>)
            } else if operation_id == "condition_false" {
                OperationResult::Success(Arc::new(false) as Arc<dyn Any + Send + Sync>)
            } else if operation_id == "true_path" {
                OperationResult::Success(Arc::new("true_path_result") as Arc<dyn Any + Send + Sync>)
            } else if operation_id == "false_path" {
                OperationResult::Success(Arc::new("false_path_result") as Arc<dyn Any + Send + Sync>)
            } else {
                OperationResult::Unsupported
            }
        }
        _ => OperationResult::Unsupported,
    };

    // Create a conditional operation (true condition)
    let conditional_true = CompositeOperation::Conditional {
        condition: Box::new(CommitmentOperation::Custom {
            operation_id: "condition_true".to_string(),
            inputs: vec![],
            parameters: vec![],
        }),
        if_true: Box::new(CompositeOperation::Single(CommitmentOperation::Custom {
            operation_id: "true_path".to_string(),
            inputs: vec![],
            parameters: vec![],
        })),
        if_false: Box::new(CompositeOperation::Single(CommitmentOperation::Custom {
            operation_id: "false_path".to_string(),
            inputs: vec![],
            parameters: vec![],
        })),
    };

    // Execute the conditional (true path)
    let result = execute_composite(&conditional_true, executor).unwrap();

    match result {
        OperationResult::Success(result_arc) => {
            let result = result_arc.downcast_ref::<&str>().unwrap();
            assert_eq!(*result, "true_path_result");
        }
        _ => panic!("Expected successful conditional execution (true path)"),
    }

    // Create a conditional operation (false condition)
    let conditional_false = CompositeOperation::Conditional {
        condition: Box::new(CommitmentOperation::Custom {
            operation_id: "condition_false".to_string(),
            inputs: vec![],
            parameters: vec![],
        }),
        if_true: Box::new(CompositeOperation::Single(CommitmentOperation::Custom {
            operation_id: "true_path".to_string(),
            inputs: vec![],
            parameters: vec![],
        })),
        if_false: Box::new(CompositeOperation::Single(CommitmentOperation::Custom {
            operation_id: "false_path".to_string(),
            inputs: vec![],
            parameters: vec![],
        })),
    };

    // Execute the conditional (false path)
    let result = execute_composite(&conditional_false, executor).unwrap();

    match result {
        OperationResult::Success(result_arc) => {
            let result = result_arc.downcast_ref::<&str>().unwrap();
            assert_eq!(*result, "false_path_result");
        }
        _ => panic!("Expected successful conditional execution (false path)"),
    }
}
```

######## File: homomorphic/src/operations/batch/mod.rs
#####*Size: 12K, Lines: 249, Type: ASCII text*

```rust
use crate::error::{HomomorphicError, HomomorphicResult};
use depin_sdk_core::homomorphic::{CommitmentOperation, OperationResult};
use std::sync::Arc;

/// Composite operation for complex computations
#[derive(Debug, Clone)]
pub enum CompositeOperation {
    /// Execute operations in sequence
    Sequence(Vec<CommitmentOperation>),

    /// Execute operations in parallel
    Parallel(Vec<CommitmentOperation>),

    /// Conditional operation based on a boolean condition
    Conditional {
        /// Condition operation (expected to return a boolean)
        condition: Box<CommitmentOperation>,
        /// Operation to execute if condition is true
        if_true: Box<CompositeOperation>,
        /// Operation to execute if condition is false
        if_false: Box<CompositeOperation>,
    },

    /// Loop until a condition is met
    Loop {
        /// Maximum number of iterations
        max_iterations: usize,
        /// Condition operation (expected to return a boolean)
        condition: Box<CommitmentOperation>,
        /// Operation to execute in each iteration
        body: Box<CompositeOperation>,
    },

    /// Single operation
    Single(CommitmentOperation),
}

/// Result of a batch operation
#[derive(Debug, Clone)]
pub struct BatchResult {
    /// Results of individual operations
    pub results: Vec<OperationResult>,
    /// Number of successful operations
    pub success_count: usize,
    /// Number of failed operations
    pub failure_count: usize,
    /// Number of unsupported operations
    pub unsupported_count: usize,
}

impl BatchResult {
    /// Create a new empty batch result
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
            success_count: 0,
            failure_count: 0,
            unsupported_count: 0,
        }
    }

    /// Add a result to the batch
    pub fn add_result(&mut self, result: OperationResult) {
        match &result {
            OperationResult::Success(_) => self.success_count += 1,
            OperationResult::Failure(_) => self.failure_count += 1,
            OperationResult::Unsupported => self.unsupported_count += 1,
        }

        self.results.push(result);
    }

    /// Check if all operations were successful
    pub fn all_successful(&self) -> bool {
        self.failure_count == 0 && self.unsupported_count == 0
    }

    /// Get the success rate as a percentage
    pub fn success_rate(&self) -> f64 {
        if self.results.is_empty() {
            0.0
        } else {
            (self.success_count as f64) / (self.results.len() as f64) * 100.0
        }
    }
}

// Add Default implementation for BatchResult
impl Default for BatchResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Execute batch operations
pub fn execute_batch<F>(operations: &[CommitmentOperation], executor: F) -> BatchResult
where
    F: Fn(&CommitmentOperation) -> OperationResult,
{
    let mut result = BatchResult::new();

    for op in operations {
        let op_result = executor(op);
        result.add_result(op_result);
    }

    result
}

/// Execute a composite operation
pub fn execute_composite<F>(
    operation: &CompositeOperation,
    executor: F,
) -> HomomorphicResult<OperationResult>
where
    F: Fn(&CommitmentOperation) -> OperationResult + Copy,
{
    match operation {
        CompositeOperation::Sequence(ops) => {
            let mut last_result = OperationResult::Success(Arc::new(()));

            for op in ops {
                last_result = executor(op);

                // If any operation fails, return immediately
                if let OperationResult::Failure(_) = &last_result {
                    return Ok(last_result);
                }
            }

            Ok(last_result)
        }

        CompositeOperation::Parallel(ops) => {
            let batch = execute_batch(ops, executor);

            // If all operations are successful, return the last result
            if batch.all_successful() && !batch.results.is_empty() {
                if let Some(last) = batch.results.last() {
                    return Ok(last.clone());
                }
            } else if !batch.all_successful() {
                // Return the first failure
                for result in &batch.results {
                    if let OperationResult::Failure(_) = result {
                        return Ok(result.clone());
                    }
                }

                // If no failures but some unsupported, return unsupported
                return Ok(OperationResult::Unsupported);
            }

            // Empty batch
            Ok(OperationResult::Success(Arc::new(())))
        }

        CompositeOperation::Conditional {
            condition,
            if_true,
            if_false,
        } => {
            // Execute the condition
            let condition_result = executor(condition);

            match condition_result {
                OperationResult::Success(result) => {
                    // Try to downcast to bool
                    match result.downcast_ref::<bool>() {
                        Some(&true) => execute_composite(if_true, executor),
                        Some(&false) => execute_composite(if_false, executor),
                        None => Err(HomomorphicError::InvalidInput(
                            "Condition did not return a boolean value".into(),
                        )),
                    }
                }
                OperationResult::Failure(error) => Ok(OperationResult::Failure(format!(
                    "Condition failed: {}",
                    error
                ))),
                OperationResult::Unsupported => Ok(OperationResult::Failure(
                    "Condition operation is unsupported".into(),
                )),
            }
        }

        CompositeOperation::Loop {
            max_iterations,
            condition,
            body,
        } => {
            let mut iterations = 0;

            loop {
                // Check maximum iterations
                if iterations >= *max_iterations {
                    return Ok(OperationResult::Success(Arc::new(iterations)));
                }

                // Evaluate condition
                let condition_result = executor(condition);

                match condition_result {
                    OperationResult::Success(result) => {
                        // Try to downcast to bool
                        match result.downcast_ref::<bool>() {
                            Some(&true) => {
                                // Continue loop, execute body
                                let body_result = execute_composite(body, executor)?;

                                // If body execution fails, propagate the error
                                if let OperationResult::Failure(_) = body_result {
                                    return Ok(body_result);
                                }

                                // Increment iteration count
                                iterations += 1;
                            }
                            Some(&false) => {
                                // Exit loop
                                return Ok(OperationResult::Success(Arc::new(iterations)));
                            }
                            None => {
                                return Err(HomomorphicError::InvalidInput(
                                    "Loop condition did not return a boolean value".into(),
                                ));
                            }
                        }
                    }
                    OperationResult::Failure(error) => {
                        return Ok(OperationResult::Failure(format!(
                            "Loop condition failed after {} iterations: {}",
                            iterations, error
                        )));
                    }
                    OperationResult::Unsupported => {
                        return Ok(OperationResult::Failure(
                            "Loop condition operation is unsupported".into(),
                        ));
                    }
                }
            }
        }

        CompositeOperation::Single(op) => Ok(executor(op)),
    }
}

#[cfg(test)]
mod tests;```

####### Directory: homomorphic/src/operations/custom

######## Directory: homomorphic/src/operations/custom/tests

######### File: homomorphic/src/operations/custom/tests/mod.rs
######*Size: 4.0K, Lines: 128, Type: C source, ASCII text*

```rust
use super::*;

// Mock commitment for testing
#[derive(Debug, Clone)]
struct MockCommitment(i32);

#[test]
fn test_custom_operation_registry() {
    let registry = CustomOperationRegistry::new();

    // Register a custom operation
    registry
        .register("test_op", |inputs, _params| {
            if inputs.is_empty() {
                return Err(HomomorphicError::InvalidInput("No inputs provided".into()));
            }

            // Try to downcast the first input to MockCommitment
            let input = match inputs[0].downcast_ref::<MockCommitment>() {
                Some(c) => c,
                None => return Err(HomomorphicError::InvalidInput("Invalid input type".into())),
            };

            // Double the value
            let result = MockCommitment(input.0 * 2);

            Ok(Arc::new(result) as Arc<dyn Any + Send + Sync>)
        })
        .unwrap();

    // Check that the operation is registered
    assert!(registry.has_operation("test_op"));
    assert_eq!(registry.operation_count(), 1);
    assert_eq!(registry.list_operations(), vec!["test_op".to_string()]);

    // Test the custom operation
    let mock_commitment = MockCommitment(5);
    let inputs = vec![Arc::new(mock_commitment) as Arc<dyn Any + Send + Sync>];
    let parameters = vec![];

    let operation = CommitmentOperation::Custom {
        operation_id: "test_op".to_string(),
        inputs,
        parameters,
    };

    let result = execute_custom(&registry, &operation);

    match result {
        OperationResult::Success(result_arc) => {
            let result = result_arc.downcast_ref::<MockCommitment>().unwrap();
            assert_eq!(result.0, 10); // Should be doubled
        }
        _ => panic!("Operation failed or unsupported"),
    }

    // Test an unregistered operation
    let inputs = vec![Arc::new(MockCommitment(5)) as Arc<dyn Any + Send + Sync>];
    let parameters = vec![];

    let operation = CommitmentOperation::Custom {
        operation_id: "unknown_op".to_string(),
        inputs,
        parameters,
    };

    let result = execute_custom(&registry, &operation);

    match result {
        OperationResult::Unsupported => {} // This is expected
        _ => panic!("Expected unsupported for unknown operation"),
    }

    // Unregister the operation
    let unregistered = registry.unregister("test_op").unwrap();
    assert!(unregistered);
    assert_eq!(registry.operation_count(), 0);
}

#[test]
fn test_invalid_input_to_custom_operation() {
    let registry = CustomOperationRegistry::new();

    // Register a custom operation that expects a specific type
    registry
        .register("type_check", |inputs, _params| {
            if inputs.is_empty() {
                return Err(HomomorphicError::InvalidInput("No inputs provided".into()));
            }

            // Expect a MockCommitment
            if inputs[0].downcast_ref::<MockCommitment>().is_none() {
                return Err(HomomorphicError::InvalidInput(
                    "Expected MockCommitment".into(),
                ));
            }

            Ok(Arc::new(true) as Arc<dyn Any + Send + Sync>)
        })
        .unwrap();

    // Test with wrong input type
    let inputs = vec![Arc::new("not a commitment") as Arc<dyn Any + Send + Sync>];
    let parameters = vec![];

    let operation = CommitmentOperation::Custom {
        operation_id: "type_check".to_string(),
        inputs,
        parameters,
    };

    let result = execute_custom(&registry, &operation);

    match result {
        OperationResult::Failure(error) => {
            assert!(error.contains("Expected MockCommitment"));
        }
        _ => panic!("Expected failure for invalid input type"),
    }
}

#[test]
fn test_default_implementation() {
    // Test that Default creates a new empty registry
    let registry = CustomOperationRegistry::default();
    assert_eq!(registry.operation_count(), 0);
    assert!(registry.list_operations().is_empty());
}
```

######## File: homomorphic/src/operations/custom/mod.rs
#####*Size: 4.0K, Lines: 133, Type: ASCII text*

```rust
use crate::error::{HomomorphicError, HomomorphicResult};
use depin_sdk_core::homomorphic::{CommitmentOperation, OperationResult};
use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Type for custom operation handler
pub type CustomOperationHandler = Arc<
    dyn Fn(&[Arc<dyn Any + Send + Sync>], &[u8]) -> HomomorphicResult<Arc<dyn Any + Send + Sync>>
        + Send
        + Sync,
>;

/// Registry for custom operations
pub struct CustomOperationRegistry {
    /// Map of operation IDs to handlers
    pub(crate) handlers: RwLock<HashMap<String, CustomOperationHandler>>,
}

impl CustomOperationRegistry {
    /// Create a new custom operation registry
    pub fn new() -> Self {
        Self {
            handlers: RwLock::new(HashMap::new()),
        }
    }

    /// Register a custom operation handler
    pub fn register<F>(&self, operation_id: &str, handler: F) -> HomomorphicResult<()>
    where
        F: Fn(
                &[Arc<dyn Any + Send + Sync>],
                &[u8],
            ) -> HomomorphicResult<Arc<dyn Any + Send + Sync>>
            + Send
            + Sync
            + 'static,
    {
        let mut handlers = self
            .handlers
            .write()
            .map_err(|_| HomomorphicError::InternalError("Failed to acquire write lock".into()))?;

        handlers.insert(operation_id.to_string(), Arc::new(handler));
        Ok(())
    }

    /// Unregister a custom operation handler
    pub fn unregister(&self, operation_id: &str) -> HomomorphicResult<bool> {
        let mut handlers = self
            .handlers
            .write()
            .map_err(|_| HomomorphicError::InternalError("Failed to acquire write lock".into()))?;

        Ok(handlers.remove(operation_id).is_some())
    }

    /// Check if a custom operation is registered
    pub fn has_operation(&self, operation_id: &str) -> bool {
        if let Ok(handlers) = self.handlers.read() {
            handlers.contains_key(operation_id)
        } else {
            false
        }
    }

    /// Get the number of registered operations
    pub fn operation_count(&self) -> usize {
        if let Ok(handlers) = self.handlers.read() {
            handlers.len()
        } else {
            0
        }
    }

    /// List all registered operation IDs
    pub fn list_operations(&self) -> Vec<String> {
        if let Ok(handlers) = self.handlers.read() {
            handlers.keys().cloned().collect()
        } else {
            Vec::new()
        }
    }
}

impl Default for CustomOperationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Execute a custom operation
pub fn execute_custom(
    registry: &CustomOperationRegistry,
    operation: &CommitmentOperation,
) -> OperationResult {
    match operation {
        CommitmentOperation::Custom {
            operation_id,
            inputs,
            parameters,
        } => {
            // Check if the operation is registered
            if !registry.has_operation(operation_id) {
                return OperationResult::Unsupported;
            }

            // Get the handler
            let handler = match registry.handlers.read() {
                Ok(handlers) => match handlers.get(operation_id) {
                    Some(h) => h.clone(),
                    None => return OperationResult::Unsupported,
                },
                Err(_) => {
                    return OperationResult::Failure(
                        HomomorphicError::InternalError("Failed to acquire read lock".into())
                            .to_string(),
                    )
                }
            };

            // Execute the handler - inputs are already Arc<dyn Any + Send + Sync>
            match handler(inputs, parameters) {
                Ok(result) => OperationResult::Success(result),
                Err(e) => OperationResult::Failure(e.to_string()),
            }
        }
        _ => OperationResult::Unsupported,
    }
}

#[cfg(test)]
mod tests;
```

####### Directory: homomorphic/src/operations/scalar_multiply

######## Directory: homomorphic/src/operations/scalar_multiply/tests

######### File: homomorphic/src/operations/scalar_multiply/tests/mod.rs
######*Size: 4.0K, Lines: 108, Type: ASCII text*

```rust
use super::*;
use depin_sdk_commitment_schemes::elliptical_curve::{
    EllipticalCurveCommitment, EllipticalCurveCommitmentScheme,
};
use depin_sdk_core::commitment::CommitmentScheme;
use std::any::Any;

#[test]
fn test_scalar_multiply() {
    let scheme = EllipticalCurveCommitmentScheme::new(5);

    // Create a commitment
    let value = b"test value";
    let commitment = scheme.commit(&[Some(value.to_vec())]);

    // Test direct scalar_multiply function with valid scalar
    let scalar = 3;
    let product_result = scalar_multiply(&scheme, &commitment, scalar);
    assert!(product_result.is_ok());

    // Test with negative scalar
    let negative_result = scalar_multiply(&scheme, &commitment, -1);
    assert!(negative_result.is_err());
    assert!(matches!(
        negative_result.unwrap_err(),
        HomomorphicError::NegativeScalar
    ));
}

#[test]
fn test_execute_scalar_multiply() {
    let scheme = EllipticalCurveCommitmentScheme::new(5);

    // Create a commitment
    let value = b"test value";
    let commitment = scheme.commit(&[Some(value.to_vec())]);

    // Test execute_scalar_multiply with CommitmentOperation
    let commitment_arc: Arc<dyn Any + Send + Sync> = Arc::new(commitment.clone());
    let scalar = 3;

    let operation = CommitmentOperation::ScalarMultiply {
        commitment: commitment_arc,
        scalar,
    };

    let result = execute_scalar_multiply(&scheme, &operation);

    match result {
        OperationResult::Success(result_arc) => {
            let product = result_arc
                .downcast_ref::<EllipticalCurveCommitment>()
                .unwrap();
            assert_ne!(product.as_ref(), commitment.as_ref());
        }
        _ => panic!("Operation failed or unsupported"),
    }
}

#[test]
fn test_scalar_multiply_invalid_input() {
    let scheme = EllipticalCurveCommitmentScheme::new(5);

    // Create an invalid commitment
    let commitment_arc: Arc<dyn Any + Send + Sync> = Arc::new("not a commitment");
    let scalar = 3;

    let operation = CommitmentOperation::ScalarMultiply {
        commitment: commitment_arc,
        scalar,
    };

    let result = execute_scalar_multiply(&scheme, &operation);

    match result {
        OperationResult::Failure(error) => {
            assert!(error.contains("Commitment is not the correct type"));
        }
        _ => panic!("Expected failure for invalid input"),
    }
}

#[test]
fn test_scalar_multiply_negative_scalar() {
    let scheme = EllipticalCurveCommitmentScheme::new(5);

    // Create a valid commitment
    let value = b"test value";
    let commitment = scheme.commit(&[Some(value.to_vec())]);
    let commitment_arc: Arc<dyn Any + Send + Sync> = Arc::new(commitment);

    // Use a negative scalar
    let scalar = -1;

    let operation = CommitmentOperation::ScalarMultiply {
        commitment: commitment_arc,
        scalar,
    };

    let result = execute_scalar_multiply(&scheme, &operation);

    match result {
        OperationResult::Failure(error) => {
            assert!(error.contains("Scalar must be positive"));
        }
        _ => panic!("Expected failure for negative scalar"),
    }
}
```

######## File: homomorphic/src/operations/scalar_multiply/mod.rs
#####*Size: 4.0K, Lines: 50, Type: ASCII text*

```rust
use crate::error::{HomomorphicError, HomomorphicResult};
use depin_sdk_core::commitment::HomomorphicCommitmentScheme;
use depin_sdk_core::homomorphic::{CommitmentOperation, OperationResult};
use std::sync::Arc;

/// Multiply a commitment by a scalar
pub fn scalar_multiply<C: HomomorphicCommitmentScheme>(
    scheme: &C,
    commitment: &C::Commitment,
    scalar: i32,
) -> HomomorphicResult<C::Commitment> {
    if scalar <= 0 {
        return Err(HomomorphicError::NegativeScalar);
    }

    scheme
        .scalar_multiply(commitment, scalar)
        .map_err(HomomorphicError::from)
}

/// Execute a scalar multiply operation
pub fn execute_scalar_multiply<C: HomomorphicCommitmentScheme>(
    scheme: &C,
    operation: &CommitmentOperation,
) -> OperationResult {
    match operation {
        CommitmentOperation::ScalarMultiply { commitment, scalar } => {
            // Try to downcast the Arc<dyn Any> to the correct commitment type
            let commitment = match commitment.downcast_ref::<C::Commitment>() {
                Some(c) => c,
                None => {
                    return OperationResult::Failure(
                        HomomorphicError::InvalidInput("Commitment is not the correct type".into())
                            .to_string(),
                    )
                }
            };

            // Perform the scalar multiplication
            match scalar_multiply(scheme, commitment, *scalar) {
                Ok(result) => OperationResult::Success(Arc::new(result)),
                Err(e) => OperationResult::Failure(e.to_string()),
            }
        }
        _ => OperationResult::Unsupported,
    }
}

#[cfg(test)]
mod tests;
```

####### Directory: homomorphic/src/operations/tests

######## File: homomorphic/src/operations/tests/mod.rs
#####*Size: 4.0K, Lines: 1, Type: very short file (no magic)*

#####*File content not included (exceeds threshold or non-text file)*

####### File: homomorphic/src/operations/execute.rs
####*Size: 4.0K, Lines: 55, Type: ASCII text*

```rust
use crate::error::{HomomorphicError, HomomorphicResult};
use depin_sdk_core::commitment::HomomorphicCommitmentScheme;
use depin_sdk_core::homomorphic::{CommitmentOperation, OperationResult};
use std::sync::Arc;

/// Add two commitments
pub fn add<C: HomomorphicCommitmentScheme>(
    scheme: &C,
    left: &C::Commitment,
    right: &C::Commitment,
) -> HomomorphicResult<C::Commitment> {
    scheme.add(left, right).map_err(HomomorphicError::from)
}

/// Execute an add operation
pub fn execute_add<C: HomomorphicCommitmentScheme>(
    scheme: &C,
    operation: &CommitmentOperation,
) -> OperationResult {
    match operation {
        CommitmentOperation::Add { left, right } => {
            // Try to downcast the Arc<dyn Any> to the correct commitment type
            let left_commitment = match left.downcast_ref::<C::Commitment>() {
                Some(c) => c,
                None => {
                    return OperationResult::Failure(
                        HomomorphicError::InvalidInput(
                            "Left operand is not the correct commitment type".into(),
                        )
                        .to_string(),
                    )
                }
            };

            let right_commitment = match right.downcast_ref::<C::Commitment>() {
                Some(c) => c,
                None => {
                    return OperationResult::Failure(
                        HomomorphicError::InvalidInput(
                            "Right operand is not the correct commitment type".into(),
                        )
                        .to_string(),
                    )
                }
            };

            // Perform the addition
            match add(scheme, left_commitment, right_commitment) {
                Ok(result) => OperationResult::Success(Arc::new(result)),
                Err(e) => OperationResult::Failure(e.to_string()),
            }
        }
        _ => OperationResult::Unsupported,
    }
}
```

####### File: homomorphic/src/operations/mod.rs
####*Size: 4.0K, Lines: 14, Type: ASCII text*

```rust
//! Operation implementations on commitments

mod add;
mod batch;
mod custom;
mod scalar_multiply;

#[cfg(test)]
mod tests;

// Use explicit imports instead of glob imports to avoid ambiguity
pub use add::{add, execute_add};
pub use batch::{execute_batch, execute_composite, BatchResult, CompositeOperation};
pub use custom::{execute_custom, CustomOperationHandler, CustomOperationRegistry};
pub use scalar_multiply::{execute_scalar_multiply, scalar_multiply};```

###### File: homomorphic/src/error.rs
###*Size: 4.0K, Lines: 69, Type: ASCII text*

```rust
use depin_sdk_core::commitment::HomomorphicOperation;
use std::error::Error;
use std::fmt;

/// Errors that can occur during homomorphic operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HomomorphicError {
    /// Invalid point in a commitment
    InvalidPoint(String),
    /// Negative or zero scalar in scalar multiplication
    NegativeScalar,
    /// Position is out of bounds
    OutOfBounds(usize, usize),
    /// Operation not supported by the commitment scheme
    UnsupportedOperation(HomomorphicOperation),
    /// Proof verification failed
    VerificationFailure,
    /// Internal operation error
    InternalError(String),
    /// Invalid input for an operation
    InvalidInput(String),
    /// Custom error with message
    Custom(String),
}

impl fmt::Display for HomomorphicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HomomorphicError::InvalidPoint(details) => {
                write!(f, "Invalid point in commitment: {}", details)
            }
            HomomorphicError::NegativeScalar => {
                write!(f, "Scalar must be positive in scalar multiplication")
            }
            HomomorphicError::OutOfBounds(pos, max) => {
                write!(f, "Position {} out of bounds (max: {})", pos, max)
            }
            HomomorphicError::UnsupportedOperation(op) => {
                write!(f, "Operation not supported: {:?}", op)
            }
            HomomorphicError::VerificationFailure => write!(f, "Proof verification failed"),
            HomomorphicError::InternalError(details) => {
                write!(f, "Internal operation error: {}", details)
            }
            HomomorphicError::InvalidInput(details) => {
                write!(f, "Invalid input for operation: {}", details)
            }
            HomomorphicError::Custom(msg) => write!(f, "{}", msg),
        }
    }
}

impl Error for HomomorphicError {}

/// Convenience type for operation results
pub type HomomorphicResult<T> = Result<T, HomomorphicError>;

/// Convert string errors to HomomorphicError
impl From<String> for HomomorphicError {
    fn from(s: String) -> Self {
        HomomorphicError::Custom(s)
    }
}

/// Convert &str errors to HomomorphicError
impl From<&str> for HomomorphicError {
    fn from(s: &str) -> Self {
        HomomorphicError::Custom(s.to_string())
    }
}```

###### File: homomorphic/src/lib.rs
###*Size: 4.0K, Lines: 23, Type: ASCII text*

```rust
// homomorphic/src/lib.rs
//! # DePIN SDK Homomorphic Operations
//!
//! Implementation of homomorphic operations on commitments for the DePIN SDK.

pub mod computation;
pub mod error;
pub mod operations;
pub mod proof;

pub use depin_sdk_core::commitment::{
    CommitmentScheme, HomomorphicCommitmentScheme, HomomorphicOperation,
};
pub use depin_sdk_core::homomorphic::{CommitmentOperation, OperationResult};

// Re-export key components for easier access
pub use computation::HomomorphicComputation;
pub use error::{HomomorphicError, HomomorphicResult};
pub use operations::{
    add, execute_add, execute_batch, execute_composite, execute_custom, execute_scalar_multiply,
    scalar_multiply, BatchResult, CompositeOperation, CustomOperationRegistry,
};
pub use proof::{HomomorphicProof, ProofGenerator};
```

###### File: homomorphic/src/proof.rs
###*Size: 16K, Lines: 356, Type: ASCII text*

```rust
use crate::error::{HomomorphicError, HomomorphicResult};
use depin_sdk_core::commitment::HomomorphicCommitmentScheme;
use depin_sdk_core::commitment::HomomorphicOperation;
// FIX: Remove unused imports.
use depin_sdk_core::commitment::{ProofContext, Selector};
use depin_sdk_core::homomorphic::CommitmentOperation;
use std::fmt::Debug;
use std::marker::PhantomData;

/// Proof that a commitment is the result of a homomorphic operation
#[derive(Debug, Clone)]
pub struct HomomorphicProof<CS: HomomorphicCommitmentScheme> {
    /// Type of operation
    operation_type: HomomorphicOperation,
    /// Input commitments
    inputs: Vec<CS::Commitment>,
    /// Result commitment
    result: CS::Commitment,
    /// Selector used for this proof
    selector: Selector,
    /// Additional data for verification
    auxiliary_data: Vec<u8>,
    /// Phantom data for commitment scheme
    _phantom: PhantomData<CS>,
}

impl<CS: HomomorphicCommitmentScheme> HomomorphicProof<CS> {
    /// Create a new homomorphic proof
    pub fn new(
        operation_type: HomomorphicOperation,
        inputs: Vec<CS::Commitment>,
        result: CS::Commitment,
        selector: Selector,
        auxiliary_data: Vec<u8>,
    ) -> Self {
        Self {
            operation_type,
            inputs,
            result,
            selector,
            auxiliary_data,
            _phantom: PhantomData,
        }
    }

    /// Create a new homomorphic proof with default selector (None)
    pub fn new_simple(
        operation_type: HomomorphicOperation,
        inputs: Vec<CS::Commitment>,
        result: CS::Commitment,
        auxiliary_data: Vec<u8>,
    ) -> Self {
        Self::new(
            operation_type,
            inputs,
            result,
            Selector::None,
            auxiliary_data,
        )
    }

    /// Get the operation type
    pub fn operation_type(&self) -> HomomorphicOperation {
        self.operation_type
    }

    /// Get the input commitments
    pub fn inputs(&self) -> &[CS::Commitment] {
        &self.inputs
    }

    /// Get the result commitment
    pub fn result(&self) -> &CS::Commitment {
        &self.result
    }

    /// Get the selector used for this proof
    pub fn selector(&self) -> &Selector {
        &self.selector
    }

    /// Get the auxiliary data
    pub fn auxiliary_data(&self) -> &[u8] {
        &self.auxiliary_data
    }

    /// Serialize the proof to bytes
    pub fn to_bytes(&self) -> HomomorphicResult<Vec<u8>> {
        // This is a simplified serialization implementation
        // In a real implementation, we would use a proper serialization format

        let mut result = Vec::new();

        // Serialize operation type
        match self.operation_type {
            HomomorphicOperation::Addition => result.push(1),
            HomomorphicOperation::ScalarMultiplication => result.push(2),
            HomomorphicOperation::Custom(id) => {
                result.push(3);
                result.extend_from_slice(&(id).to_le_bytes());
            }
        }

        // Serialize input count
        result.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());

        // Serialize inputs
        for input in &self.inputs {
            let bytes = input.as_ref().to_vec();
            result.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            result.extend_from_slice(&bytes);
        }

        // Serialize result
        let result_bytes = self.result.as_ref().to_vec();
        result.extend_from_slice(&(result_bytes.len() as u32).to_le_bytes());
        result.extend_from_slice(&result_bytes);

        // Serialize selector type
        match &self.selector {
            Selector::Position(_) => result.push(1),
            Selector::Key(_) => result.push(2),
            Selector::Predicate(_) => result.push(3),
            Selector::None => result.push(0),
        }

        // Serialize selector data if present
        match &self.selector {
            Selector::Position(pos) => {
                result.extend_from_slice(&(*pos as u64).to_le_bytes());
            }
            Selector::Key(key) => {
                result.extend_from_slice(&(key.len() as u32).to_le_bytes());
                result.extend_from_slice(key);
            }
            Selector::Predicate(data) => {
                result.extend_from_slice(&(data.len() as u32).to_le_bytes());
                result.extend_from_slice(data);
            }
            Selector::None => {} // No additional data
        }

        // Serialize auxiliary data
        result.extend_from_slice(&(self.auxiliary_data.len() as u32).to_le_bytes());
        result.extend_from_slice(&self.auxiliary_data);

        Ok(result)
    }

    /// Create from bytes
    pub fn from_bytes(_bytes: &[u8]) -> HomomorphicResult<Self>
    where
        CS::Commitment: From<Vec<u8>>,
    {
        // This would be a complete deserialization implementation
        // For now, we'll just return an error
        Err(HomomorphicError::Custom(
            "Deserialization not implemented".to_string(),
        ))
    }
}

/// Generator for homomorphic proofs
pub struct ProofGenerator<CS: HomomorphicCommitmentScheme> {
    /// Commitment scheme
    scheme: CS,
}

impl<CS: HomomorphicCommitmentScheme> ProofGenerator<CS> {
    /// Create a new proof generator
    pub fn new(scheme: CS) -> Self {
        Self { scheme }
    }

    /// Generate a proof for an add operation
    pub fn prove_add(
        &self,
        a: &CS::Commitment,
        b: &CS::Commitment,
        result: &CS::Commitment,
        selector: &Selector,
    ) -> HomomorphicResult<HomomorphicProof<CS>> {
        // Verify that result = a + b
        let computed_result = self.scheme.add(a, b)?;

        // Check that the computed result matches the provided result
        if computed_result.as_ref() != result.as_ref() {
            return Err(HomomorphicError::VerificationFailure);
        }

        // Create the proof with the specified selector
        Ok(HomomorphicProof::new(
            HomomorphicOperation::Addition,
            vec![a.clone(), b.clone()],
            result.clone(),
            selector.clone(),
            Vec::new(), // No auxiliary data needed for addition
        ))
    }

    /// Generate a proof for a scalar multiply operation
    pub fn prove_scalar_multiply(
        &self,
        a: &CS::Commitment,
        scalar: i32,
        result: &CS::Commitment,
        selector: &Selector,
    ) -> HomomorphicResult<HomomorphicProof<CS>> {
        if scalar <= 0 {
            return Err(HomomorphicError::NegativeScalar);
        }

        // Verify that result = a * scalar
        let computed_result = self.scheme.scalar_multiply(a, scalar)?;

        // Check that the computed result matches the provided result
        if computed_result.as_ref() != result.as_ref() {
            return Err(HomomorphicError::VerificationFailure);
        }

        // Create the proof with scalar in auxiliary data
        let mut auxiliary_data = Vec::new();
        auxiliary_data.extend_from_slice(&scalar.to_le_bytes());

        Ok(HomomorphicProof::new(
            HomomorphicOperation::ScalarMultiplication,
            vec![a.clone()],
            result.clone(),
            selector.clone(),
            auxiliary_data,
        ))
    }

    /// Generate a proof for an operation
    pub fn prove_operation(
        &self,
        operation: &CommitmentOperation,
        result: &CS::Commitment,
    ) -> HomomorphicResult<HomomorphicProof<CS>> {
        // Default to None selector for backward compatibility
        self.prove_operation_with_selector(operation, result, &Selector::None)
    }

    /// Generate a proof for an operation with a specific selector
    pub fn prove_operation_with_selector(
        &self,
        operation: &CommitmentOperation,
        result: &CS::Commitment,
        selector: &Selector,
    ) -> HomomorphicResult<HomomorphicProof<CS>> {
        match operation {
            CommitmentOperation::Add { left, right } => {
                // Downcast inputs
                let a = left.downcast_ref::<CS::Commitment>().ok_or_else(|| {
                    HomomorphicError::InvalidInput(
                        "Left operand is not the correct commitment type".into(),
                    )
                })?;
                let b = right.downcast_ref::<CS::Commitment>().ok_or_else(|| {
                    HomomorphicError::InvalidInput(
                        "Right operand is not the correct commitment type".into(),
                    )
                })?;

                self.prove_add(a, b, result, selector)
            }
            CommitmentOperation::ScalarMultiply { commitment, scalar } => {
                // Downcast input
                let a = commitment.downcast_ref::<CS::Commitment>().ok_or_else(|| {
                    HomomorphicError::InvalidInput("Commitment is not the correct type".into())
                })?;

                self.prove_scalar_multiply(a, *scalar, result, selector)
            }
            CommitmentOperation::Custom { .. } => Err(HomomorphicError::UnsupportedOperation(
                HomomorphicOperation::Custom(0),
            )),
        }
    }

    /// Verify a homomorphic proof
    pub fn verify_proof(&self, proof: &HomomorphicProof<CS>) -> HomomorphicResult<bool> {
        // Use default empty context for backward compatibility
        self.verify_proof_with_context(proof, &ProofContext::default())
    }

    /// Verify a homomorphic proof with context
    pub fn verify_proof_with_context(
        &self,
        proof: &HomomorphicProof<CS>,
        context: &ProofContext,
    ) -> HomomorphicResult<bool> {
        match proof.operation_type() {
            HomomorphicOperation::Addition => {
                if proof.inputs().len() != 2 {
                    return Err(HomomorphicError::InvalidInput(
                        "Addition proof requires exactly 2 inputs".into(),
                    ));
                }

                let a = &proof.inputs()[0];
                let b = &proof.inputs()[1];

                // Compute a + b
                let computed_result = self.scheme.add(a, b)?;

                // Check that computed result matches the proof result
                Ok(computed_result.as_ref() == proof.result().as_ref())
            }
            HomomorphicOperation::ScalarMultiplication => {
                if proof.inputs().len() != 1 {
                    return Err(HomomorphicError::InvalidInput(
                        "Scalar multiplication proof requires exactly 1 input".into(),
                    ));
                }

                let a = &proof.inputs()[0];

                // Extract scalar from auxiliary data
                if proof.auxiliary_data().len() < 4 {
                    return Err(HomomorphicError::InvalidInput(
                        "Invalid auxiliary data for scalar multiplication".into(),
                    ));
                }

                let mut scalar_bytes = [0u8; 4];
                scalar_bytes.copy_from_slice(&proof.auxiliary_data()[0..4]);
                let scalar = i32::from_le_bytes(scalar_bytes);

                if scalar <= 0 {
                    return Err(HomomorphicError::NegativeScalar);
                }

                // Check the context for any additional verification parameters
                if let Some(precision_data) = context.get_data("precision") {
                    if !precision_data.is_empty() {
                        // Use precision parameter if provided
                        // This is just an example of how context might be used
                        let precision = precision_data[0];
                        if precision > 0 {
                            // High precision verification logic would go here
                        }
                    }
                }

                // Compute a * scalar
                let computed_result = self.scheme.scalar_multiply(a, scalar)?;

                // Check that computed result matches the proof result
                Ok(computed_result.as_ref() == proof.result().as_ref())
            }
            HomomorphicOperation::Custom(_) => Err(HomomorphicError::UnsupportedOperation(
                proof.operation_type(),
            )),
        }
    }
}```

##### File: homomorphic/Cargo.toml
##*Size: 4.0K, Lines: 16, Type: ASCII text*

```toml
[package]
name = "depin-sdk-homomorphic"
version = "0.1.0"
edition = "2021"
description = "Homomorphic operations implementation for the DePIN SDK"
license = "MIT OR Apache-2.0"

[dependencies]
depin-sdk-core = { path = "../core" }
depin-sdk-commitment-schemes = { path = "../commitment_schemes" }
log = { workspace = true }
serde = { workspace = true }
thiserror = { workspace = true }

[features]
default = []
```

#### Directory: services

##### Directory: services/src

###### Directory: services/src/external_data

####### File: services/src/external_data/mod.rs
####*Size: 4.0K, Lines: 12, Type: ASCII text*

```rust
//! External data module implementation

use depin_sdk_core::services::{BlockchainService, ServiceType};

pub struct ExternalDataService {
    // Add your implementation fields here
}

impl BlockchainService for ExternalDataService {
    fn service_type(&self) -> ServiceType {
        ServiceType::ExternalData
    }
}```

###### Directory: services/src/governance

####### File: services/src/governance/mod.rs
####*Size: 4.0K, Lines: 156, Type: ASCII text*

```rust
//! Governance module implementations for the DePIN SDK

use std::time::Duration;

/// Governance proposal type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalType {
    /// Parameter change proposal
    ParameterChange,
    /// Software upgrade proposal
    SoftwareUpgrade,
    /// Text proposal
    Text,
    /// Custom proposal type
    Custom(String),
}

/// Governance vote option
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoteOption {
    /// Yes vote
    Yes,
    /// No vote
    No,
    /// No with veto vote
    NoWithVeto,
    /// Abstain vote
    Abstain,
}

/// Governance parameters
#[derive(Debug, Clone)]
pub struct GovernanceParams {
    /// Minimum deposit to submit a proposal
    pub min_deposit: u64,
    /// Maximum deposit period
    pub max_deposit_period: Duration,
    /// Voting period
    pub voting_period: Duration,
    /// Quorum percentage (0-100)
    pub quorum: u8,
    /// Threshold percentage (0-100)
    pub threshold: u8,
    /// Veto threshold percentage (0-100)
    pub veto_threshold: u8,
}

impl Default for GovernanceParams {
    fn default() -> Self {
        Self {
            min_deposit: 10000,
            max_deposit_period: Duration::from_secs(60 * 60 * 24 * 14), // 14 days
            voting_period: Duration::from_secs(60 * 60 * 24 * 14),      // 14 days
            quorum: 33,                                                 // 33%
            threshold: 50,                                              // 50%
            veto_threshold: 33,                                         // 33%
        }
    }
}

/// Governance module
pub struct GovernanceModule {
    /// Governance parameters
    params: GovernanceParams,
}

impl GovernanceModule {
    /// Create a new governance module
    pub fn new(params: GovernanceParams) -> Self {
        Self { params }
    }

    /// Create a new governance module with default parameters
    pub fn default() -> Self {
        Self {
            params: GovernanceParams::default(),
        }
    }

    /// Get the governance parameters
    pub fn params(&self) -> &GovernanceParams {
        &self.params
    }

    /// Submit a proposal
    pub fn submit_proposal(
        &self,
        _proposal_type: ProposalType,
        _title: &str,
        _description: &str,
        _proposer: &[u8],
        _deposit: u64,
    ) -> Result<u64, String> {
        // In a real implementation, this would create and store a proposal
        // For now, just return a dummy proposal ID
        Ok(1)
    }

    /// Vote on a proposal
    pub fn vote(
        &self,
        _proposal_id: u64,
        _voter: &[u8],
        _option: VoteOption,
    ) -> Result<(), String> {
        // In a real implementation, this would record a vote
        Ok(())
    }

    /// Get proposal status
    pub fn get_proposal_status(&self, _proposal_id: u64) -> Result<String, String> {
        // In a real implementation, this would fetch the proposal status
        Ok("Voting".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_governance_params_default() {
        let params = GovernanceParams::default();
        assert_eq!(params.min_deposit, 10000);
        assert_eq!(params.quorum, 33);
        assert_eq!(params.threshold, 50);
        assert_eq!(params.veto_threshold, 33);
    }

    #[test]
    fn test_governance_module() {
        let module = GovernanceModule::default();

        // Test proposal submission
        let proposal_id = module
            .submit_proposal(
                ProposalType::Text,
                "Test Proposal",
                "This is a test proposal",
                &[1, 2, 3, 4],
                10000,
            )
            .unwrap();

        assert_eq!(proposal_id, 1);

        // Test voting
        module
            .vote(proposal_id, &[1, 2, 3, 4], VoteOption::Yes)
            .unwrap();

        // Test status query
        let status = module.get_proposal_status(proposal_id).unwrap();
        assert_eq!(status, "Voting");
    }
}
```

###### Directory: services/src/ibc

####### Directory: services/src/ibc/src

######## Directory: services/src/ibc/src/conversion

######### File: services/src/ibc/src/conversion/mod.rs
######*Size: 4.0K, Lines: 21, Type: ASCII text*

```rust
//! Value conversion utilities for IBC module
/// Trait for types that can be converted from/to bytes
/// This unifies the previously separate ValueConversion and FromBytes traits
pub trait ByteConvertible: Sized {
    /// Convert from bytes to this type
    fn from_bytes(bytes: &[u8]) -> Option<Self>;

    /// Convert this type to bytes
    fn to_bytes(&self) -> Vec<u8>;
}

// Implement for Vec<u8> which is the most common value type
impl ByteConvertible for Vec<u8> {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Some(bytes.to_vec())
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.clone()
    }
}
```

######## Directory: services/src/ibc/src/light_client

######### Directory: services/src/ibc/src/light_client/tests

######### File: services/src/ibc/src/light_client/mod.rs
######*Size: 12K, Lines: 341, Type: C source, ASCII text*

```rust
//! IBC light client implementations

use crate::conversion::ByteConvertible;
use crate::translation::ProofTranslatorRegistry;
use depin_sdk_core::commitment::{CommitmentScheme, ProofContext, Selector};
use depin_sdk_core::ibc::{LightClient, UniversalProofFormat};
use std::any::Any;
use std::collections::HashMap;

/// Type-erased commitment scheme wrapper that avoids dynamic dispatch limitations
struct SchemeWrapper {
    /// The actual scheme (boxed as Any)
    inner: Box<dyn Any + Send + Sync>,
    /// Function pointer for commit operation
    commit_fn: fn(&dyn Any, &[Option<Vec<u8>>]) -> Box<dyn AsRef<[u8]> + Send + Sync>,
    /// Function pointer for create_proof operation
    create_proof_fn: fn(&dyn Any, &Selector, &[u8]) -> Result<Box<dyn Any + Send + Sync>, String>,
    /// Function pointer for verify operation
    verify_fn: fn(&dyn Any, &dyn Any, &dyn Any, &Selector, &[u8], &ProofContext) -> bool,
    /// Scheme identifier
    id: String,
}

/// Universal light client that can verify proofs from multiple commitment schemes
pub struct UniversalLightClient {
    /// Supported scheme implementations
    schemes: HashMap<String, SchemeWrapper>,
    /// Translator registry
    translators: ProofTranslatorRegistry,
    /// Default scheme to use
    default_scheme: Option<String>,
}

impl UniversalLightClient {
    /// Create a new universal light client
    pub fn new() -> Self {
        Self {
            schemes: HashMap::new(),
            translators: ProofTranslatorRegistry::new(),
            default_scheme: None,
        }
    }

    /// Register a commitment scheme
    pub fn register_scheme<C>(&mut self, scheme_id: &str, scheme: C)
    where
        C: CommitmentScheme + 'static,
        C::Value: ByteConvertible + AsRef<[u8]>, // Using unified trait
    {
        // Create type-erased wrapper functions
        let commit_fn = |any_scheme: &dyn Any,
                         values: &[Option<Vec<u8>>]|
         -> Box<dyn AsRef<[u8]> + Send + Sync> {
            let scheme = any_scheme.downcast_ref::<C>().unwrap();
            // Convert Vec<u8> to C::Value using ByteConvertible trait
            let typed_values: Vec<Option<C::Value>> = values
                .iter()
                .map(|v| v.as_ref().and_then(|bytes| C::Value::from_bytes(bytes)))
                .collect();

            let commitment = scheme.commit(&typed_values);
            Box::new(commitment)
        };

        let create_proof_fn = |any_scheme: &dyn Any,
                               selector: &Selector,
                               value: &[u8]|
         -> Result<Box<dyn Any + Send + Sync>, String> {
            let scheme = any_scheme.downcast_ref::<C>().unwrap();
            // Convert value to C::Value using ByteConvertible trait
            if let Some(typed_value) = C::Value::from_bytes(value) {
                scheme
                    .create_proof(selector, &typed_value)
                    .map(|proof| Box::new(proof) as Box<dyn Any + Send + Sync>)
            } else {
                Err(format!(
                    "Failed to convert {} bytes to the expected format",
                    value.len()
                ))
            }
        };

        let verify_fn = |any_scheme: &dyn Any,
                         any_commitment: &dyn Any,
                         any_proof: &dyn Any,
                         selector: &Selector,
                         value: &[u8],
                         context: &ProofContext|
         -> bool {
            if let Some(scheme) = any_scheme.downcast_ref::<C>() {
                if let Some(commitment) = any_commitment.downcast_ref::<C::Commitment>() {
                    if let Some(proof) = any_proof.downcast_ref::<C::Proof>() {
                        // Convert value to C::Value
                        if let Some(typed_value) = C::Value::from_bytes(value) {
                            return scheme.verify(
                                commitment,
                                proof,
                                selector,
                                &typed_value,
                                context,
                            );
                        }
                    }
                }
            }
            false
        };

        let wrapper = SchemeWrapper {
            inner: Box::new(scheme),
            commit_fn,
            create_proof_fn,
            verify_fn,
            id: scheme_id.to_string(),
        };

        self.schemes.insert(scheme_id.to_string(), wrapper);
        if self.default_scheme.is_none() {
            self.default_scheme = Some(scheme_id.to_string());
        }
    }

    /// Set the default scheme
    pub fn set_default_scheme(&mut self, scheme_id: &str) -> Result<(), String> {
        if self.schemes.contains_key(scheme_id) {
            self.default_scheme = Some(scheme_id.to_string());
            Ok(())
        } else {
            Err(format!("Scheme '{}' not registered", scheme_id))
        }
    }

    /// Register a proof translator
    pub fn register_translator(
        &mut self,
        translator: Box<dyn depin_sdk_core::ibc::ProofTranslator>,
    ) {
        self.translators.register(translator);
    }

    /// Get supported schemes
    pub fn supported_schemes(&self) -> Vec<String> {
        self.schemes.keys().cloned().collect()
    }

    /// Helper method to convert native proof bytes to a proof object
    fn deserialize_proof(
        &self,
        scheme_id: &str,
        proof_bytes: &[u8],
    ) -> Option<Box<dyn Any + Send + Sync>> {
        // In a real implementation, this would deserialize from the proper format
        // based on the scheme's expected proof format
        let _scheme = self.schemes.get(scheme_id)?;

        // Log the deserialization attempt for debugging
        log::debug!(
            "Deserializing proof for scheme {}, {} bytes",
            scheme_id,
            proof_bytes.len()
        );

        // Simply wrap the bytes for now
        // In a real implementation, you'd have scheme-specific deserialization
        Some(Box::new(proof_bytes.to_vec()))
    }

    /// Helper method to extract selector from proof bytes
    fn extract_selector_from_proof(
        &self,
        scheme_id: &str,
        _proof_bytes: &[u8],
        fallback_key: &[u8],
    ) -> Selector {
        // In a real implementation, this would extract the selector information
        // from the proof bytes based on the scheme's format

        // Log the extraction attempt
        log::debug!(
            "Extracting selector for scheme {}, fallback key: {} bytes",
            scheme_id,
            fallback_key.len()
        );

        // For now, return a key-based selector as a default
        Selector::Key(fallback_key.to_vec())
    }
}

impl LightClient for UniversalLightClient {
    fn verify_native_proof(
        &self,
        commitment: &[u8],
        proof: &[u8],
        key: &[u8],
        value: &[u8],
    ) -> bool {
        // Create a default context for internal use
        let context = ProofContext::default();

        // Use the default scheme if available
        if let Some(scheme_id) = &self.default_scheme {
            if let Some(scheme) = self.schemes.get(scheme_id) {
                // Extract selector from proof (or use key selector as fallback)
                let selector = self.extract_selector_from_proof(scheme_id, proof, key);

                // Deserialize proof data
                if let Some(deserialized_proof) = self.deserialize_proof(scheme_id, proof) {
                    // Attempt to verify with the scheme
                    // We use the type-erased function to avoid dynamic dispatch limitations
                    let result = (scheme.verify_fn)(
                        scheme.inner.as_ref(),
                        &commitment.to_vec(), // Simple wrapper for commitment bytes
                        deserialized_proof.as_ref(),
                        &selector,
                        value,
                        &context,
                    );

                    // Log the verification result
                    log::debug!(
                        "Native proof verification result: {}, scheme: {}",
                        result,
                        scheme_id
                    );

                    return result;
                }
            }
        }

        log::warn!("Native proof verification failed, no suitable scheme found");
        false
    }

    fn verify_universal_proof(
        &self,
        commitment: &[u8],
        proof: &UniversalProofFormat,
        key: &[u8],
        value: &[u8],
    ) -> bool {
        let scheme_id = &proof.scheme_id.0;

        // Log received proof information
        log::debug!(
            "Verifying universal proof: scheme={}, key={} bytes, provided_key={} bytes",
            scheme_id,
            proof.key.len(),
            key.len()
        );

        // Create a context from the proof metadata
        let mut combined_context = ProofContext::new();

        // Migrate metadata from core proof to our context
        for (key, value) in &proof.metadata {
            combined_context.add_data(key, value.clone());
        }

        // Determine which key to use - prefer proof's key if present, otherwise use provided key
        let key_to_use = if !proof.key.is_empty() {
            &proof.key
        } else {
            key
        };

        // Create selector based on the key
        let selector = Selector::Key(key_to_use.to_vec());

        // Log the key decision
        log::debug!(
            "Using {} for verification: {} bytes",
            if key_to_use.as_ptr() == proof.key.as_ptr() {
                "proof key"
            } else {
                "provided key"
            },
            key_to_use.len()
        );

        // If we support this scheme directly, use it
        if let Some(scheme) = self.schemes.get(scheme_id) {
            // Deserialize the proof data
            if let Some(deserialized_proof) = self.deserialize_proof(scheme_id, &proof.proof_data) {
                // Verify using the scheme
                let result = (scheme.verify_fn)(
                    scheme.inner.as_ref(),
                    &commitment.to_vec(), // Simple wrapper for commitment bytes
                    deserialized_proof.as_ref(),
                    &selector,
                    value,
                    &combined_context,
                );

                // Log direct verification result
                log::debug!("Direct verification result: {}", result);

                return result;
            }
        }

        // If we don't support this scheme directly, try to translate it
        if let Some(default_id) = &self.default_scheme {
            log::debug!("Attempting translation to scheme: {}", default_id);

            // Attempt to translate the proof to our default scheme
            if let Some(translated_proof) = self.translators.translate_universal(default_id, proof)
            {
                if let Some(scheme) = self.schemes.get(default_id) {
                    // Verify using the translated proof
                    let result = (scheme.verify_fn)(
                        scheme.inner.as_ref(),
                        &commitment.to_vec(), // Simple wrapper for commitment bytes
                        translated_proof.as_ref(),
                        &selector,
                        value,
                        &combined_context,
                    );

                    // Log translation verification result
                    log::debug!("Translation verification result: {}", result);

                    return result;
                }
            } else {
                log::warn!("Failed to translate proof to scheme: {}", default_id);
            }
        }

        log::warn!(
            "Universal proof verification failed for scheme: {}",
            scheme_id
        );
        false
    }

    fn supported_schemes(&self) -> Vec<String> {
        self.schemes.keys().cloned().collect()
    }
}
```

######## Directory: services/src/ibc/src/proof

######### Directory: services/src/ibc/src/proof/tests

######### File: services/src/ibc/src/proof/formats.rs
######*Size: 4.0K, Lines: 82, Type: ASCII text*

```rust
// File: crates/ibc/src/proof/formats.rs

use depin_sdk_core::commitment::{ProofContext, Selector};
use depin_sdk_core::ibc::UniversalProofFormat as CoreProofFormat;
use std::collections::HashMap;

use crate::proof::UniversalProofFormat as LocalProofFormat;

/// Helper for converting between proof formats
pub struct ProofFormatConverter;

impl ProofFormatConverter {
    /// Convert from core to local proof format
    pub fn core_to_local(core: &CoreProofFormat) -> LocalProofFormat {
        // Extract selector from key
        let selector = if core.key.is_empty() {
            Selector::None
        } else {
            Selector::Key(core.key.clone())
        };

        // Create local proof format
        let mut local = LocalProofFormat::new(
            core.scheme_id.clone(),
            core.proof_data.clone(),
            selector,
            core.value.clone(),
        );

        // Copy metadata
        for (key, value) in &core.metadata {
            local.add_metadata(key, value.clone());
        }

        local
    }

    /// Convert from local to core proof format
    pub fn local_to_core(local: &LocalProofFormat) -> CoreProofFormat {
        // Extract key from selector if available
        let key = match &local.selector {
            Selector::Key(k) => k.clone(),
            _ => local.key.clone(), // Fall back to explicit key field
        };

        // Create core proof format
        let mut core = CoreProofFormat {
            scheme_id: local.scheme_id.clone(),
            format_version: local.format_version,
            proof_data: local.proof_data.clone(),
            metadata: HashMap::new(),
            key, // Using key directly
            value: local.value.clone(),
        };

        // Copy metadata
        for (key, value) in &local.metadata {
            core.metadata.insert(key.clone(), value.clone());
        }

        core
    }

    /// Create a combined context from proof and additional context
    pub fn create_combined_context(
        proof: &LocalProofFormat,
        additional: Option<&ProofContext>,
    ) -> ProofContext {
        let mut combined = proof.context.clone();

        // Add additional context data if provided
        if let Some(additional_ctx) = additional {
            for (key, value) in &additional_ctx.data {
                // Only add if not already present
                if !combined.data.contains_key(key) {
                    combined.add_data(key, value.clone());
                }
            }
        }

        combined
    }
}```

######### File: services/src/ibc/src/proof/mod.rs
######*Size: 8.0K, Lines: 194, Type: ASCII text*

```rust
//! Definition of the UniversalProofFormat
//! 
use depin_sdk_core::commitment::{ProofContext, SchemeIdentifier, Selector};
use std::collections::HashMap;

// Explicitly declare the formats module
pub mod formats;
use formats::ProofFormatConverter;

/// Universal proof format that can represent any commitment scheme's proof
#[derive(Debug, Clone)]
pub struct UniversalProofFormat {
    /// Identifier of the commitment scheme that created this proof
    pub scheme_id: SchemeIdentifier,

    /// Version of the proof format
    pub format_version: u8,

    /// The serialized proof data
    pub proof_data: Vec<u8>,

    /// Additional metadata for the proof
    pub metadata: HashMap<String, Vec<u8>>,

    /// Selector that this proof is for
    pub selector: Selector,

    /// Key that this proof is for (backward compatibility)
    pub key: Vec<u8>,

    /// Value this proof is proving (if known)
    pub value: Option<Vec<u8>>,

    /// Verification context
    pub context: ProofContext,
}

impl UniversalProofFormat {
    /// Create a new universal proof format
    pub fn new(
        scheme_id: SchemeIdentifier,
        proof_data: Vec<u8>,
        selector: Selector,
        value: Option<Vec<u8>>,
    ) -> Self {
        // For backward compatibility, extract a key from the selector if possible
        let key = match &selector {
            Selector::Key(k) => k.clone(),
            _ => Vec::new(),
        };

        Self {
            scheme_id,
            format_version: 1,
            proof_data,
            metadata: HashMap::new(),
            selector,
            key,
            value,
            context: ProofContext::default(),
        }
    }

    /// Add metadata to the proof
    pub fn add_metadata(&mut self, key: &str, value: Vec<u8>) {
        self.metadata.insert(key.to_string(), value);
    }

    /// Get metadata from the proof
    pub fn get_metadata(&self, key: &str) -> Option<&Vec<u8>> {
        self.metadata.get(key)
    }

    /// Add context data
    pub fn add_context_data(&mut self, key: &str, value: Vec<u8>) {
        self.context.add_data(key, value);
    }

    /// Get context data
    pub fn get_context_data(&self, key: &str) -> Option<&Vec<u8>> {
        self.context.get_data(key)
    }

    /// Create a new proof with a position-based selector
    pub fn with_position(
        scheme_id: SchemeIdentifier,
        proof_data: Vec<u8>,
        position: usize,
        value: Option<Vec<u8>>,
    ) -> Self {
        Self::new(scheme_id, proof_data, Selector::Position(position), value)
    }

    /// Create a new proof with a key-based selector
    pub fn with_key(
        scheme_id: SchemeIdentifier,
        proof_data: Vec<u8>,
        key: Vec<u8>,
        value: Option<Vec<u8>>,
    ) -> Self {
        Self::new(scheme_id, proof_data, Selector::Key(key), value)
    }

    /// Create a new proof with a predicate-based selector
    pub fn with_predicate(
        scheme_id: SchemeIdentifier,
        proof_data: Vec<u8>,
        predicate: Vec<u8>,
        value: Option<Vec<u8>>,
    ) -> Self {
        Self::new(scheme_id, proof_data, Selector::Predicate(predicate), value)
    }

    /// Create a new proof with no selector
    pub fn with_no_selector(
        scheme_id: SchemeIdentifier,
        proof_data: Vec<u8>,
        value: Option<Vec<u8>>,
    ) -> Self {
        Self::new(scheme_id, proof_data, Selector::None, value)
    }
}

/// Helper functions for working with UniversalProofFormat
pub struct IBCProofUtils;

impl IBCProofUtils {
    /// Create a new universal proof format
    pub fn create_universal_proof(
        scheme_id: &str,
        proof_data: Vec<u8>,
        selector: Selector,
        value: Option<Vec<u8>>,
    ) -> UniversalProofFormat {
        UniversalProofFormat::new(
            SchemeIdentifier::new(scheme_id),
            proof_data,
            selector,
            value,
        )
    }

    /// Get scheme ID from a universal proof
    pub fn get_scheme_id(proof: &UniversalProofFormat) -> &str {
        &proof.scheme_id.0
    }

    /// Get proof data from a universal proof
    pub fn get_proof_data(proof: &UniversalProofFormat) -> &[u8] {
        &proof.proof_data
    }

    /// Get selector from a universal proof
    pub fn get_selector(proof: &UniversalProofFormat) -> &Selector {
        &proof.selector
    }

    /// Get key from a universal proof
    pub fn get_key(proof: &UniversalProofFormat) -> &[u8] {
        &proof.key
    }

    /// Get value from a universal proof
    ///
    /// This function returns a borrowed slice of the value stored in the proof,
    /// if it exists. The lifetime of the returned slice is bound to the lifetime
    /// of the input `proof`.
    pub fn get_value<'a>(proof: &'a UniversalProofFormat) -> Option<&'a [u8]> {
        proof.value.as_ref().map(|v| v.as_slice())
    }

    /// Add metadata to a universal proof
    pub fn add_metadata(proof: &mut UniversalProofFormat, key: &str, value: Vec<u8>) {
        proof.add_metadata(key, value);
    }

    /// Get metadata from a universal proof
    pub fn get_metadata<'a>(proof: &'a UniversalProofFormat, key: &str) -> Option<&'a Vec<u8>> {
        proof.get_metadata(key)
    }

    /// Add context data to a universal proof
    pub fn add_context_data(proof: &mut UniversalProofFormat, key: &str, value: Vec<u8>) {
        proof.add_context_data(key, value);
    }

    /// Get context data from a universal proof
    pub fn get_context_data<'a>(proof: &'a UniversalProofFormat, key: &str) -> Option<&'a Vec<u8>> {
        proof.get_context_data(key)
    }
}

/// Serialization utilities for proofs (snipped for brevity)
pub struct ProofSerialization;
// Implement serialization methods here...```

######### File: services/src/ibc/src/proof/mod.rs:8:5
######*Size: 0, Lines: 0, Type: empty*

######*File content not included (exceeds threshold or non-text file)*

######## Directory: services/src/ibc/src/translation

######### Directory: services/src/ibc/src/translation/tests

######### File: services/src/ibc/src/translation/generic.rs
######*Size: 4.0K, Lines: 115, Type: ASCII text*

```rust
//! Generic proof translator implementation

use std::any::Any;
use std::marker::PhantomData;

use crate::conversion::ByteConvertible;
use depin_sdk_core::commitment::{CommitmentScheme, SchemeIdentifier, Selector};
use depin_sdk_core::ibc::{ProofTranslator, UniversalProofFormat};
use std::collections::HashMap;

/// Generic proof translator between two commitment schemes
pub struct GenericProofTranslator<S, T>
where
    S: CommitmentScheme,
    T: CommitmentScheme,
{
    /// Source scheme
    source_scheme: S,
    /// Source scheme ID
    source_id: SchemeIdentifier,
    /// Target scheme
    target_scheme: T,
    /// Target scheme ID
    target_id: SchemeIdentifier,
    /// Phantom marker
    _phantom: PhantomData<(S, T)>,
}

impl<S, T> GenericProofTranslator<S, T>
where
    S: CommitmentScheme,
    T: CommitmentScheme,
{
    /// Create a new generic proof translator
    pub fn new(
        source_scheme: S,
        source_id: SchemeIdentifier,
        target_scheme: T,
        target_id: SchemeIdentifier,
    ) -> Self {
        Self {
            source_scheme,
            source_id,
            target_scheme,
            target_id,
            _phantom: PhantomData,
        }
    }
}

impl<S, T> ProofTranslator for GenericProofTranslator<S, T>
where
    S: CommitmentScheme,
    T: CommitmentScheme,
    T::Value: ByteConvertible,
{
    fn source_scheme(&self) -> SchemeIdentifier {
        self.source_id.clone()
    }

    fn target_scheme(&self) -> SchemeIdentifier {
        self.target_id.clone()
    }

    fn to_universal(
        &self,
        proof: &dyn Any,
        key: &[u8],
        value: Option<&[u8]>,
    ) -> Option<UniversalProofFormat> {
        // Try to downcast the proof to source scheme's proof type
        let source_proof = proof.downcast_ref::<S::Proof>()?;

        // Create universal proof format with scheme ID, key, and value
        Some(UniversalProofFormat {
            scheme_id: self.source_id.clone(),
            proof_data: vec![0; 32], // Placeholder - in real code we'd properly serialize
            metadata: HashMap::new(),
            key: key.to_vec(),
            value: value.map(|v| v.to_vec()),
        })
    }

    fn from_universal(&self, universal: &UniversalProofFormat) -> Option<Box<dyn Any>> {
        // Verify scheme ID matches
        if universal.scheme_id != self.source_id {
            log::warn!(
                "Scheme ID mismatch: expected {}, got {}",
                self.source_id.0,
                universal.scheme_id.0
            );
            return None;
        }

        // Convert the value to the target scheme's Value type if it exists
        let value_bytes = universal.value.as_ref()?;
        let target_value = T::Value::from_bytes(value_bytes)?;

        // Create a proof in the target scheme using a key selector
        let selector = if universal.key.is_empty() {
            log::warn!("Empty key in universal proof");
            None
        } else {
            Some(Selector::Key(universal.key.clone()))
        }?;

        // In a real implementation, we would properly deserialize and convert the proof
        match self.target_scheme.create_proof(&selector, &target_value) {
            Ok(target_proof) => Some(Box::new(target_proof)),
            Err(err) => {
                log::error!("Failed to create target proof: {}", err);
                None
            }
        }
    }
}```

######### File: services/src/ibc/src/translation/mod.rs
######*Size: 8.0K, Lines: 182, Type: ASCII text*

```rust
//! IBC proof translation between different commitment schemes

use std::any::Any;
use std::collections::HashMap;

use crate::conversion::ByteConvertible;
use crate::proof::formats::ProofFormatConverter;
use crate::proof::UniversalProofFormat as LocalProofFormat;
use depin_sdk_core::commitment::{CommitmentScheme, ProofContext, SchemeIdentifier, Selector};
use depin_sdk_core::ibc::{ProofTranslator, UniversalProofFormat as CoreProofFormat};

/// Registry for proof translators
pub struct ProofTranslatorRegistry {
    /// Map from (source, target) scheme IDs to translator instances
    translators: HashMap<(String, String), Box<dyn ProofTranslator>>,
}

impl ProofTranslatorRegistry {
    /// Create a new proof translator registry
    pub fn new() -> Self {
        Self {
            translators: HashMap::new(),
        }
    }

    /// Register a proof translator
    pub fn register(&mut self, translator: Box<dyn ProofTranslator>) {
        let source = translator.source_scheme().0.clone();
        let target = translator.target_scheme().0.clone();
        self.translators.insert((source, target), translator);
    }

    /// Get a proof translator
    pub fn get(&self, source: &str, target: &str) -> Option<&dyn ProofTranslator> {
        self.translators
            .get(&(source.to_string(), target.to_string()))
            .map(|t| t.as_ref())
    }

    /// Translate a proof between schemes
    pub fn translate(
        &self,
        source: &str,
        target: &str,
        proof: &dyn Any,
        key: &[u8],
        value: Option<&[u8]>,
    ) -> Option<Box<dyn Any>> {
        // Get the translator and perform translation
        let translator = self.get(source, target)?;

        // Log translation attempt
        log::debug!(
            "Translating proof: {} -> {}, key: {} bytes",
            source,
            target,
            key.len()
        );

        translator.translate(proof, key, value)
    }

    /// Translate with context
    pub fn translate_with_context(
        &self,
        source: &str,
        target: &str,
        proof: &dyn Any,
        key: &[u8],
        value: Option<&[u8]>,
        context: &ProofContext,
    ) -> Option<Box<dyn Any>> {
        // For translators that don't support context directly,
        // we'll convert relevant context data to universal proof metadata
        let translator = self.get(source, target)?;

        // First attempt to use universal format as an intermediate
        if let Some(universal) = translator.to_universal(proof, key, value) {
            // Copy context data to metadata
            let mut enriched = universal;
            for (key, value) in &context.data {
                if !enriched.metadata.contains_key(key) {
                    enriched.metadata.insert(key.clone(), value.clone());
                }
            }

            // Then translate from the enriched universal format
            translator.from_universal(&enriched)
        } else {
            // Fall back to direct translation if universal conversion fails
            translator.translate(proof, key, value)
        }
    }

    /// Translate a universal proof to a specific scheme
    pub fn translate_universal(
        &self,
        target: &str,
        universal: &CoreProofFormat,
    ) -> Option<Box<dyn Any>> {
        let source = &universal.scheme_id.0;
        let translator = self.get(source, target)?;

        // Log translation attempt
        log::debug!("Translating universal proof: {} -> {}", source, target);

        translator.from_universal(universal)
    }

    /// Translate a local proof format to a specific scheme
    pub fn translate_local_universal(
        &self,
        target: &str,
        local_universal: &LocalProofFormat,
    ) -> Option<Box<dyn Any>> {
        // Convert local format to core format
        let core_universal = ProofFormatConverter::local_to_core(local_universal);

        // Then translate using the core format
        self.translate_universal(target, &core_universal)
    }

    /// Convert a proof to universal format
    pub fn to_universal(
        &self,
        source: &str,
        proof: &dyn Any,
        key: &[u8],
        value: Option<&[u8]>,
    ) -> Option<CoreProofFormat> {
        // Find any translator for this source scheme
        for ((src, _), translator) in &self.translators {
            if src == source {
                return translator.to_universal(proof, key, value);
            }
        }
        None
    }

    /// Convert a proof to local universal format
    pub fn to_local_universal(
        &self,
        source: &str,
        proof: &dyn Any,
        key: &[u8],
        value: Option<&[u8]>,
    ) -> Option<LocalProofFormat> {
        // First convert to core format
        let core = self.to_universal(source, proof, key, value)?;

        // Then convert to local format
        Some(ProofFormatConverter::core_to_local(&core))
    }

    /// List all supported source schemes
    pub fn source_schemes(&self) -> Vec<String> {
        let mut schemes = self
            .translators
            .keys()
            .map(|(source, _)| source.clone())
            .collect::<Vec<_>>();
        schemes.sort();
        schemes.dedup();
        schemes
    }

    /// List all supported target schemes
    pub fn target_schemes(&self) -> Vec<String> {
        let mut schemes = self
            .translators
            .keys()
            .map(|(_, target)| target.clone())
            .collect::<Vec<_>>();
        schemes.sort();
        schemes.dedup();
        schemes
    }

    /// List all supported translations
    pub fn supported_translations(&self) -> Vec<(String, String)> {
        self.translators.keys().cloned().collect()
    }
}```

######### File: services/src/ibc/src/translation/mod.rs:6:5
######*Size: 0, Lines: 0, Type: empty*

######*File content not included (exceeds threshold or non-text file)*

######### File: services/src/ibc/src/translation/mod.rs:9:66
######*Size: 0, Lines: 0, Type: empty*

######*File content not included (exceeds threshold or non-text file)*

######## Directory: services/src/ibc/src/verification

######### Directory: services/src/ibc/src/verification/tests

######### File: services/src/ibc/src/verification/mod.rs
######*Size: 8.0K, Lines: 259, Type: ASCII text*

```rust
//! IBC verification utilities

use depin_sdk_core::commitment::{ProofContext, Selector};
use depin_sdk_core::ibc::{LightClient, UniversalProofFormat};
use std::collections::HashMap;
use std::sync::Arc;

/// Registry for light clients
pub struct LightClientRegistry {
    /// Map from chain ID to light client instance
    clients: HashMap<String, Arc<dyn LightClient>>,
}

impl LightClientRegistry {
    /// Create a new light client registry
    pub fn new() -> Self {
        Self {
            clients: HashMap::new(),
        }
    }

    /// Register a light client
    pub fn register(&mut self, chain_id: &str, client: Arc<dyn LightClient>) {
        self.clients.insert(chain_id.to_string(), client);
    }

    /// Get a light client by chain ID
    pub fn get(&self, chain_id: &str) -> Option<Arc<dyn LightClient>> {
        self.clients.get(chain_id).cloned()
    }

    /// Verify a proof against a specific chain
    pub fn verify(
        &self,
        chain_id: &str,
        commitment: &[u8],
        proof: &[u8],
        selector: &Selector,
        value: &[u8],
        context: Option<&ProofContext>,
    ) -> bool {
        if let Some(client) = self.get(chain_id) {
            // Extract key bytes from selector
            let key_bytes = match selector {
                Selector::Key(key) => key.as_slice(),
                Selector::Position(pos) => {
                    // Convert position to bytes if needed
                    // For now just use empty slice or could use position as bytes
                    &[]
                }
                // Handle other selector types
                _ => &[],
            };

            client.verify_native_proof(commitment, proof, key_bytes, value)
        } else {
            false
        }
    }

    /// Verify a universal proof against a specific chain
    pub fn verify_universal(
        &self,
        chain_id: &str,
        commitment: &[u8],
        proof: &UniversalProofFormat,
        value: &[u8],
        context: Option<&ProofContext>,
    ) -> bool {
        if let Some(client) = self.get(chain_id) {
            client.verify_universal_proof(commitment, proof, &proof.key, value)
        } else {
            false
        }
    }

    /// List all registered chain IDs
    pub fn chain_ids(&self) -> Vec<String> {
        self.clients.keys().cloned().collect()
    }
}

/// Proof verification result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationResult {
    /// Proof verified successfully
    Success,
    /// Proof verification failed
    Failure(String),
    /// Chain not found
    ChainNotFound(String),
    /// Unsupported proof format
    UnsupportedProofFormat,
    /// Invalid selector
    InvalidSelector(String),
    /// Missing or invalid context
    InvalidContext(String),
}

/// Cross-chain proof verifier
pub struct CrossChainVerifier {
    /// Light client registry
    registry: LightClientRegistry,
    /// Trusted commitments by chain ID and height
    commitments: HashMap<String, HashMap<u64, Vec<u8>>>,
    /// Cached proof contexts by chain ID
    contexts: HashMap<String, ProofContext>,
}

impl CrossChainVerifier {
    /// Create a new cross-chain proof verifier
    pub fn new(registry: LightClientRegistry) -> Self {
        Self {
            registry,
            commitments: HashMap::new(),
            contexts: HashMap::new(),
        }
    }

    /// Add a trusted commitment
    pub fn add_trusted_commitment(&mut self, chain_id: &str, height: u64, commitment: Vec<u8>) {
        let chain_commitments = self
            .commitments
            .entry(chain_id.to_string())
            .or_insert_with(HashMap::new);

        chain_commitments.insert(height, commitment);
    }

    /// Add a proof context for a chain
    pub fn add_context(&mut self, chain_id: &str, context: ProofContext) {
        self.contexts.insert(chain_id.to_string(), context);
    }

    /// Get proof context for a chain
    pub fn get_context(&self, chain_id: &str) -> Option<&ProofContext> {
        self.contexts.get(chain_id)
    }

    /// Get the latest height for a chain
    pub fn latest_height(&self, chain_id: &str) -> Option<u64> {
        self.commitments
            .get(chain_id)
            .and_then(|commitments| commitments.keys().max().copied())
    }

    /// Get the commitment at a specific height
    pub fn get_commitment(&self, chain_id: &str, height: u64) -> Option<&[u8]> {
        self.commitments
            .get(chain_id)
            .and_then(|commitments| commitments.get(&height))
            .map(|c| c.as_slice())
    }

    /// Verify a proof against the latest commitment for a chain
    pub fn verify_proof(
        &self,
        chain_id: &str,
        proof: &[u8],
        selector: &Selector,
        value: &[u8],
    ) -> VerificationResult {
        // Get the latest height
        let height = match self.latest_height(chain_id) {
            Some(h) => h,
            None => return VerificationResult::ChainNotFound(chain_id.to_string()),
        };

        // Get the commitment at that height
        let commitment = match self.get_commitment(chain_id, height) {
            Some(c) => c,
            None => {
                return VerificationResult::Failure(format!(
                    "No commitment found for chain {} at height {}",
                    chain_id, height
                ))
            }
        };

        // Get the context for the chain
        let context = self.get_context(chain_id);

        // Verify the proof
        if self
            .registry
            .verify(chain_id, commitment, proof, selector, value, context)
        {
            VerificationResult::Success
        } else {
            VerificationResult::Failure(format!(
                "Proof verification failed for chain {} at height {}",
                chain_id, height
            ))
        }
    }

    /// Verify a universal proof against the latest commitment for a chain
    pub fn verify_universal_proof(
        &self,
        chain_id: &str,
        proof: &UniversalProofFormat,
        value: &[u8],
    ) -> VerificationResult {
        // Get the latest height
        let height = match self.latest_height(chain_id) {
            Some(h) => h,
            None => return VerificationResult::ChainNotFound(chain_id.to_string()),
        };

        // Get the commitment at that height
        let commitment = match self.get_commitment(chain_id, height) {
            Some(c) => c,
            None => {
                return VerificationResult::Failure(format!(
                    "No commitment found for chain {} at height {}",
                    chain_id, height
                ))
            }
        };

        // Get the context for the chain
        let context = self.get_context(chain_id);

        // Verify the proof
        if self
            .registry
            .verify_universal(chain_id, commitment, proof, value, context)
        {
            VerificationResult::Success
        } else {
            VerificationResult::Failure(format!(
                "Proof verification failed for chain {} at height {}",
                chain_id, height
            ))
        }
    }

    /// List all registered chain IDs
    pub fn chain_ids(&self) -> Vec<String> {
        self.registry.chain_ids()
    }

    /// Create verification context for a chain
    pub fn create_context(&self, chain_id: &str, height: Option<u64>) -> ProofContext {
        let mut context = ProofContext::new();

        // Add chain ID to context
        context.add_data("chain_id", chain_id.as_bytes().to_vec());

        // Add height to context if specified
        if let Some(h) = height {
            context.add_data("height", h.to_le_bytes().to_vec());
        } else if let Some(h) = self.latest_height(chain_id) {
            context.add_data("height", h.to_le_bytes().to_vec());
        }

        context
    }
}
```

######## File: services/src/ibc/src/lib.rs
#####*Size: 4.0K, Lines: 12, Type: ASCII text*

```rust
//! # DePIN SDK IBC
//!
//! Inter-Blockchain Communication implementation for the DePIN SDK.

pub mod proof;
pub mod translation;
pub mod light_client;
pub mod verification;
pub mod conversion;

use depin_sdk_core::ibc::{ProofTranslator, UniversalProofFormat};
use depin_sdk_core::commitment::{CommitmentScheme, SchemeIdentifier};
```

######## File: services/src/ibc/src/lib.rs:11:27
#####*Size: 0, Lines: 0, Type: empty*

#####*File content not included (exceeds threshold or non-text file)*

######## File: services/src/ibc/src/lib.rs:12:34
#####*Size: 0, Lines: 0, Type: empty*

#####*File content not included (exceeds threshold or non-text file)*

####### File: services/src/ibc/Cargo.toml
####*Size: 4.0K, Lines: 13, Type: ASCII text*

```toml
[package]
name = "depin-sdk-ibc"
version = "0.1.0"
edition = "2021"
description = "Inter-Blockchain Communication implementation for the DePIN SDK"
license = "MIT OR Apache-2.0"

[dependencies]
depin-sdk-core = { path = "../core" }
depin-sdk-commitment-schemes = { path = "../commitment_schemes" }
log = { workspace = true }
serde = { workspace = true }
thiserror = { workspace = true }
```

###### Directory: services/src/semantic

####### File: services/src/semantic/mod.rs
####*Size: 4.0K, Lines: 12, Type: ASCII text*

```rust
//! Semantic module implementation

use depin_sdk_core::services::{BlockchainService, ServiceType};

pub struct SemanticService {
    // Add your implementation fields here
}

impl BlockchainService for SemanticService {
    fn service_type(&self) -> ServiceType {
        ServiceType::Semantic
    }
}```

###### File: services/src/lib.rs
###*Size: 4.0K, Lines: 3, Type: ASCII text*

```rust
pub mod external_data;
pub mod governance;
pub mod semantic;
```

##### File: services/Cargo.toml
##*Size: 4.0K, Lines: 17, Type: ASCII text*

```toml
[package]
name = "depin-sdk-services"
version = "0.1.0"
edition = "2021"
description = "Services for the DePIN SDK"
license = "MIT OR Apache-2.0"

[dependencies]
depin-sdk-core = { path = "../core" }
log = { workspace = true }
serde = { workspace = true }
thiserror = { workspace = true }
bytes = { workspace = true }
anyhow = { workspace = true }

[features]
default = []
```

#### Directory: state_trees

##### Directory: state_trees/src

###### Directory: state_trees/src/file

####### File: state_trees/src/file/mod.rs
####*Size: 8.0K, Lines: 166, Type: ASCII text*

```rust
// Path: crates/state_trees/src/file/mod.rs

use depin_sdk_core::commitment::{CommitmentScheme, ProofContext, Selector};
use depin_sdk_core::error::StateError;
use depin_sdk_core::state::{StateManager, StateTree};
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

/// A simple, file-backed state tree implementation for demonstration purposes.
/// It uses a HashMap internally and serializes to a JSON file.
///
/// FIX: The internal HashMap now uses `String` for keys to be compatible with
/// the JSON format, which requires string keys for objects. Binary keys are
/// hex-encoded before being used with the map.
#[derive(Serialize, Deserialize, Debug)]
pub struct FileStateTree<C: CommitmentScheme> {
    path: PathBuf,
    #[serde(skip, default)]
    scheme: C,
    // FIX: Changed key type from Vec<u8> to String.
    data: HashMap<String, Vec<u8>>,
    #[serde(skip)]
    _phantom: PhantomData<C::Value>,
}

impl<C> FileStateTree<C>
where
    C: CommitmentScheme + Clone + Default,
    C::Value: From<Vec<u8>>,
{
    pub fn new<P: AsRef<Path>>(path: P, scheme: C) -> Self {
        let path_buf = path.as_ref().to_path_buf();
        Self::load(&path_buf, scheme.clone()).unwrap_or_else(|_| Self {
            path: path_buf,
            scheme,
            data: HashMap::new(),
            _phantom: PhantomData,
        })
    }

    fn load<P: AsRef<Path>>(path: P, scheme: C) -> io::Result<Self> {
        let file = File::open(path)?;
        let mut loaded: Self = serde_json::from_reader(file)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        loaded.scheme = scheme;
        Ok(loaded)
    }

    fn save(&self) -> io::Result<()> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.path)?;
        serde_json::to_writer_pretty(file, self)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

impl<C> StateTree for FileStateTree<C>
where
    C: CommitmentScheme + Clone + Send + Sync + Default,
    C::Value: From<Vec<u8>>,
{
    type Commitment = C::Commitment;
    type Proof = C::Proof;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        // FIX: Hex-encode the key for lookup.
        let key_hex = hex::encode(key);
        Ok(self.data.get(&key_hex).cloned())
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        // FIX: Hex-encode the key before insertion.
        let key_hex = hex::encode(key);
        self.data.insert(key_hex, value.to_vec());
        self.save()
            .map_err(|e| StateError::WriteError(e.to_string()))
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        // FIX: Hex-encode the key for removal.
        let key_hex = hex::encode(key);
        self.data.remove(&key_hex);
        self.save()
            .map_err(|e| StateError::WriteError(e.to_string()))
    }

    fn root_commitment(&self) -> Self::Commitment {
        let mut values_to_sort = self.data.values().cloned().collect::<Vec<_>>();
        values_to_sort.sort();

        let values_to_commit: Vec<Option<C::Value>> = values_to_sort
            .into_iter()
            .map(|v| Some(C::Value::from(v)))
            .collect();

        self.scheme.commit(&values_to_commit)
    }

    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        // FIX: Hex-encode the key for lookup.
        let key_hex = hex::encode(key);
        let value = self.data.get(&key_hex)?;
        self.scheme
            .create_proof(
                &Selector::Key(key.to_vec()),
                &C::Value::from(value.clone()),
            )
            .ok()
    }

    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8],
    ) -> bool {
        self.scheme.verify(
            commitment,
            proof,
            &Selector::Key(key.to_vec()),
            &C::Value::from(value.to_vec()),
            &ProofContext::default(),
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl<C> StateManager for FileStateTree<C>
where
    C: CommitmentScheme + Clone + Send + Sync + Default,
    C::Commitment: Send + Sync,
    C::Proof: Send + Sync,
    C::Value: From<Vec<u8>> + Send + Sync,
{
    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        for (key, value) in updates {
            // FIX: Hex-encode each key before batch insertion.
            let key_hex = hex::encode(key);

            self.data.insert(key_hex, value.to_vec());
        }
        self.save()
            .map_err(|e| StateError::WriteError(e.to_string()))
    }

    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        let mut values = Vec::with_capacity(keys.len());
        for key in keys {
            // FIX: Hex-encode each key for batch lookup.
            let key_hex = hex::encode(key);
            values.push(self.data.get(&key_hex).cloned());
        }
        Ok(values)
    }
}```

###### Directory: state_trees/src/hashmap

####### File: state_trees/src/hashmap/mod.rs
####*Size: 4.0K, Lines: 110, Type: ASCII text*

```rust
use depin_sdk_core::commitment::{CommitmentScheme, ProofContext, Selector};
use depin_sdk_core::error::StateError;
use depin_sdk_core::state::{StateManager, StateTree};
use std::any::Any;
use std::collections::HashMap;

/// HashMap-based state tree implementation
pub struct HashMapStateTree<CS: CommitmentScheme> {
    /// Data store. Made `pub(crate)` to allow the `FileStateTree` wrapper to access it.
    pub(crate) data: HashMap<Vec<u8>, CS::Value>,
    /// Commitment scheme. Made `pub(crate)` for consistency.
    pub(crate) scheme: CS,
}

impl<CS: CommitmentScheme> HashMapStateTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    /// Create a new HashMap-based state tree
    pub fn new(scheme: CS) -> Self {
        Self {
            data: HashMap::new(),
            scheme,
        }
    }

    /// Convert Vec<u8> to Value type
    fn to_value(&self, bytes: &[u8]) -> CS::Value {
        CS::Value::from(bytes.to_vec())
    }
}

impl<CS: CommitmentScheme> StateTree for HashMapStateTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    type Commitment = CS::Commitment;
    type Proof = CS::Proof;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.data.get(key).map(|v| v.as_ref().to_vec()))
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.data.insert(key.to_vec(), self.to_value(value));
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        self.data.remove(key);
        Ok(())
    }

    fn root_commitment(&self) -> Self::Commitment {
        // Keys must be sorted to ensure a deterministic commitment.
        let mut sorted_keys: Vec<_> = self.data.keys().collect();
        sorted_keys.sort();

        let values: Vec<Option<CS::Value>> = sorted_keys
            .iter()
            .map(|key| self.data.get(*key).cloned())
            .collect();
        self.scheme.commit(&values)
    }

    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        let value = self.get(key).ok()?.map(|v| self.to_value(&v))?;
        let selector = Selector::Key(key.to_vec());
        self.scheme.create_proof(&selector, &value).ok()
    }

    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8],
    ) -> bool {
        let context = ProofContext::default();
        let typed_value = self.to_value(value);
        let selector = Selector::Key(key.to_vec());

        self.scheme
            .verify(commitment, proof, &selector, &typed_value, &context)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl<CS: CommitmentScheme> StateManager for HashMapStateTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        for (key, value) in updates {
            let value_typed = self.to_value(value);
            self.data.insert(key.to_vec(), value_typed);
        }
        Ok(())
    }

    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        let mut values = Vec::with_capacity(keys.len());
        for key in keys {
            values.push(self.data.get(key).map(|v| v.as_ref().to_vec()));
        }
        Ok(values)
    }
}```

###### Directory: state_trees/src/iavl

####### File: state_trees/src/iavl/mod.rs
####*Size: 4.0K, Lines: 110, Type: ASCII text*

```rust
//! IAVL tree implementation

use depin_sdk_core::commitment::{CommitmentScheme, ProofContext, Selector};
use depin_sdk_core::error::StateError;
use depin_sdk_core::state::{StateManager, StateTree};
use std::any::Any;
use std::collections::HashMap;

/// IAVL tree implementation
pub struct IAVLTree<CS: CommitmentScheme> {
    /// Data store
    data: HashMap<Vec<u8>, CS::Value>,
    /// Commitment scheme
    scheme: CS,
}

impl<CS: CommitmentScheme> IAVLTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    /// Create a new IAVL tree
    pub fn new(scheme: CS) -> Self {
        Self {
            data: HashMap::new(),
            scheme,
        }
    }

    /// Get the underlying commitment scheme
    pub fn scheme(&self) -> &CS {
        &self.scheme
    }

    /// Convert a raw byte value to the commitment scheme's value type
    fn to_value(&self, value: &[u8]) -> CS::Value {
        CS::Value::from(value.to_vec())
    }
}

impl<CS: CommitmentScheme> StateTree for IAVLTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    type Commitment = CS::Commitment;
    type Proof = CS::Proof;

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        let scheme_value = self.to_value(value);
        self.data.insert(key.to_vec(), scheme_value);
        Ok(())
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.data.get(key).map(|v| v.as_ref().to_vec()))
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        self.data.remove(key);
        Ok(())
    }

    fn root_commitment(&self) -> Self::Commitment {
        let values: Vec<Option<CS::Value>> = self.data.values().map(|v| Some(v.clone())).collect();
        self.scheme.commit(&values)
    }

    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        let value = self.data.get(key)?;
        let selector = Selector::Key(key.to_vec());
        self.scheme.create_proof(&selector, value).ok()
    }

    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8],
    ) -> bool {
        let selector = Selector::Key(key.to_vec());
        let context = ProofContext::default();
        let scheme_value = self.to_value(value);
        self.scheme
            .verify(commitment, proof, &selector, &scheme_value, &context)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// FIX: Implement the StateManager trait.
impl<CS: CommitmentScheme> StateManager for IAVLTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        for (key, value) in updates {
            self.insert(key, value)?;
        }
        Ok(())
    }

    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        let mut results = Vec::with_capacity(keys.len());
        for key in keys {
            results.push(self.get(key)?);
        }
        Ok(results)
    }
}```

###### Directory: state_trees/src/sparse_merkle

####### File: state_trees/src/sparse_merkle/mod.rs
####*Size: 4.0K, Lines: 111, Type: ASCII text*

```rust
//! Sparse Merkle tree implementation

use depin_sdk_core::commitment::{CommitmentScheme, ProofContext, Selector};
use depin_sdk_core::error::StateError;
use depin_sdk_core::state::{StateManager, StateTree};
use std::any::Any;
use std::collections::HashMap;

/// Sparse Merkle tree implementation
pub struct SparseMerkleTree<CS: CommitmentScheme> {
    /// Data store
    data: HashMap<Vec<u8>, CS::Value>,
    /// Commitment scheme
    scheme: CS,
}

impl<CS: CommitmentScheme> SparseMerkleTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    /// Create a new sparse Merkle tree
    pub fn new(scheme: CS) -> Self {
        Self {
            data: HashMap::new(),
            scheme,
        }
    }

    fn to_value(&self, bytes: &[u8]) -> CS::Value {
        CS::Value::from(bytes.to_vec())
    }
}

impl<CS: CommitmentScheme> StateTree for SparseMerkleTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    type Commitment = CS::Commitment;
    type Proof = CS::Proof;

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        let value_typed = self.to_value(value);
        self.data.insert(key.to_vec(), value_typed);
        Ok(())
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.data.get(key).map(|v| v.as_ref().to_vec()))
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        self.data.remove(key);
        Ok(())
    }

    fn root_commitment(&self) -> Self::Commitment {
        let values: Vec<Option<CS::Value>> = self.data.values().map(|v| Some(v.clone())).collect();
        self.scheme.commit(&values)
    }

    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        let value_result = self.get(key).ok()?;
        let value = value_result?;
        let value_typed = self.to_value(&value);
        self.scheme
            .create_proof(&Selector::Key(key.to_vec()), &value_typed)
            .ok()
    }

    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8],
    ) -> bool {
        let value_typed = self.to_value(value);
        let context = ProofContext::default();
        self.scheme.verify(
            commitment,
            proof,
            &Selector::Key(key.to_vec()),
            &value_typed,
            &context,
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// FIX: Implement the StateManager trait.
impl<CS: CommitmentScheme> StateManager for SparseMerkleTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        for (key, value) in updates {
            self.insert(key, value)?;
        }
        Ok(())
    }

    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        let mut results = Vec::with_capacity(keys.len());
        for key in keys {
            results.push(self.get(key)?);
        }
        Ok(results)
    }
}```

###### Directory: state_trees/src/verkle

####### File: state_trees/src/verkle/mod.rs
####*Size: 4.0K, Lines: 150, Type: ASCII text*

```rust
//! Verkle tree implementation

use depin_sdk_core::commitment::{CommitmentScheme, ProofContext, Selector};
use depin_sdk_core::error::StateError;
use depin_sdk_core::state::{StateManager, StateTree};
use std::any::Any;
use std::collections::HashMap;

/// Verkle tree implementation
pub struct VerkleTree<CS: CommitmentScheme> {
    /// Data store
    data: HashMap<Vec<u8>, CS::Value>,
    /// Commitment scheme
    scheme: CS,
    /// Branching factor
    branching_factor: usize,
}

impl<CS: CommitmentScheme> VerkleTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    /// Create a new Verkle tree with the specified branching factor
    pub fn new(scheme: CS, branching_factor: usize) -> Self {
        Self {
            data: HashMap::new(),
            scheme,
            branching_factor,
        }
    }

    /// Get the branching factor
    pub fn branching_factor(&self) -> usize {
        self.branching_factor
    }

    /// Get the underlying commitment scheme
    pub fn scheme(&self) -> &CS {
        &self.scheme
    }

    /// Get the number of elements stored in the tree
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the tree is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl<CS: CommitmentScheme> StateTree for VerkleTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    type Commitment = CS::Commitment;
    type Proof = CS::Proof;

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        let cs_value = self
            .convert_value(value)
            .map_err(|e| StateError::InvalidValue(e))?;
        self.data.insert(key.to_vec(), cs_value);
        Ok(())
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.data.get(key).map(|v| self.extract_value(v)))
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        self.data.remove(key);
        Ok(())
    }

    fn root_commitment(&self) -> Self::Commitment {
        let values: Vec<Option<CS::Value>> = self.data.values().map(|v| Some(v.clone())).collect();
        self.scheme.commit(&values)
    }

    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        let value = self.data.get(key)?;
        self.scheme
            .create_proof(&Selector::Key(key.to_vec()), value)
            .ok()
    }

    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8],
    ) -> bool {
        if let Ok(cs_value) = self.convert_value(value) {
            let mut context = ProofContext::new();
            context.add_data(
                "branching_factor",
                self.branching_factor.to_le_bytes().to_vec(),
            );
            self.scheme.verify(
                commitment,
                proof,
                &Selector::Key(key.to_vec()),
                &cs_value,
                &context,
            )
        } else {
            false
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// FIX: Implement the StateManager trait.
impl<CS: CommitmentScheme> StateManager for VerkleTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        for (key, value) in updates {
            self.insert(key, value)?;
        }
        Ok(())
    }

    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        let mut results = Vec::with_capacity(keys.len());
        for key in keys {
            results.push(self.get(key)?);
        }
        Ok(results)
    }
}

impl<CS: CommitmentScheme> VerkleTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    fn convert_value(&self, value: &[u8]) -> Result<CS::Value, String> {
        Ok(CS::Value::from(value.to_vec()))
    }

    fn extract_value(&self, value: &CS::Value) -> Vec<u8> {
        value.as_ref().to_vec()
    }
}```

###### File: state_trees/src/lib.rs
###*Size: 4.0K, Lines: 15, Type: ASCII text*

```rust
//! # DePIN SDK State Trees
//!
//! Implementations of various state tree structures for the DePIN SDK.

pub mod file;
pub mod hashmap;
pub mod iavl;
pub mod sparse_merkle;
pub mod verkle;

// Re-export concrete implementations for convenience
pub use file::FileStateTree;
pub use hashmap::HashMapStateTree;
pub use iavl::IAVLTree;
pub use sparse_merkle::SparseMerkleTree;
pub use verkle::VerkleTree;```

##### File: state_trees/Cargo.toml
##*Size: 4.0K, Lines: 22, Type: ASCII text*

```toml
[package]
name = "depin-sdk-state-trees"
version = "0.1.0"
edition = "2021"
description = "State tree implementations for the DePIN SDK"
license = "MIT OR Apache-2.0"

[dependencies]
depin-sdk-core = { path = "../core" }
depin-sdk-commitment-schemes = { path = "../commitment_schemes" }
log = { workspace = true }
serde = { workspace = true }
thiserror = { workspace = true }
bytes = { workspace = true }
serde_json = { workspace = true }
hex = { workspace = true }

[features]
default = []
verkle = ["depin-sdk-commitment-schemes/kzg"]
sparse_merkle = ["depin-sdk-commitment-schemes/hash"]
iavl = ["depin-sdk-commitment-schemes/hash"]
```

#### Directory: test_utils

##### Directory: test_utils/src

###### Directory: test_utils/src/assertions

####### Directory: test_utils/src/assertions/tests

####### File: test_utils/src/assertions/mod.rs
####*Size: 4.0K, Lines: 57, Type: ASCII text*

```rust
//! Assertion utilities for testing

/// Assert that two byte arrays are equal
#[macro_export]
macro_rules! assert_bytes_eq {
    ($left:expr, $right:expr) => {
        assert_eq!($left.as_ref(), $right.as_ref());
    };
    ($left:expr, $right:expr, $($arg:tt)+) => {
        assert_eq!($left.as_ref(), $right.as_ref(), $($arg)+);
    };
}

/// Assert that a result is OK and unwrap it
#[macro_export]
macro_rules! assert_ok {
    ($expr:expr) => {
        match $expr {
            Ok(val) => val,
            Err(err) => panic!("Expected Ok, got Err: {:?}", err),
        }
    };
    ($expr:expr, $($arg:tt)+) => {
        match $expr {
            Ok(val) => val,
            Err(err) => panic!("Expected Ok, got Err: {:?} ({})", err, format!($($arg)+)),
        }
    };
}

/// Assert that a result is Err and unwrap the error
#[macro_export]
macro_rules! assert_err {
    ($expr:expr) => {
        match $expr {
            Ok(val) => panic!("Expected Err, got Ok: {:?}", val),
            Err(err) => err,
        }
    };
    ($expr:expr, $($arg:tt)+) => {
        match $expr {
            Ok(val) => panic!("Expected Err, got Ok: {:?} ({})", val, format!($($arg)+)),
            Err(err) => err,
        }
    };
}

/// Assert that a value is within a specific range
#[macro_export]
macro_rules! assert_in_range {
    ($value:expr, $min:expr, $max:expr) => {
        assert!($value >= $min && $value <= $max, "{} not in range [{}, {}]", $value, $min, $max);
    };
    ($value:expr, $min:expr, $max:expr, $($arg:tt)+) => {
        assert!($value >= $min && $value <= $max, "{} not in range [{}, {}]: {}", $value, $min, $max, format!($($arg)+));
    };
}
```

###### Directory: test_utils/src/fixtures

####### Directory: test_utils/src/fixtures/tests

####### File: test_utils/src/fixtures/mod.rs
####*Size: 4.0K, Lines: 118, Type: ASCII text*

```rust
//! Test fixtures for reproducible tests

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Test fixture manager
pub struct Fixtures {
    /// Base directory for fixtures
    base_dir: PathBuf,
}

impl Fixtures {
    /// Create a new fixtures manager with the specified base directory
    pub fn new<P: AsRef<Path>>(base_dir: P) -> io::Result<Self> {
        let base_dir = base_dir.as_ref().to_path_buf();
        fs::create_dir_all(&base_dir)?;
        Ok(Self { base_dir })
    }

    /// Get a fixture file path
    pub fn path<P: AsRef<Path>>(&self, relative_path: P) -> PathBuf {
        self.base_dir.join(relative_path)
    }

    /// Read a fixture file
    pub fn read<P: AsRef<Path>>(&self, relative_path: P) -> io::Result<Vec<u8>> {
        let path = self.path(relative_path);
        fs::read(path)
    }

    /// Read a fixture file as a string
    pub fn read_string<P: AsRef<Path>>(&self, relative_path: P) -> io::Result<String> {
        let path = self.path(relative_path);
        fs::read_to_string(path)
    }

    /// Write data to a fixture file
    pub fn write<P: AsRef<Path>, C: AsRef<[u8]>>(
        &self,
        relative_path: P,
        contents: C,
    ) -> io::Result<()> {
        let path = self.path(relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, contents)
    }

    /// Create a temporary fixture directory
    pub fn create_dir<P: AsRef<Path>>(&self, relative_path: P) -> io::Result<PathBuf> {
        let path = self.path(relative_path);
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    /// Check if a fixture file exists
    pub fn exists<P: AsRef<Path>>(&self, relative_path: P) -> bool {
        self.path(relative_path).exists()
    }

    /// Remove a fixture file or directory
    pub fn remove<P: AsRef<Path>>(&self, relative_path: P) -> io::Result<()> {
        let path = self.path(relative_path);
        if path.is_dir() {
            fs::remove_dir_all(path)
        } else {
            fs::remove_file(path)
        }
    }
}

/// Predefined test fixtures
pub struct TestFixtures;

impl TestFixtures {
    /// Get a small sample message for testing
    pub fn small_message() -> &'static [u8] {
        b"This is a small test message"
    }

    /// Get a medium sample message for testing
    pub fn medium_message() -> Vec<u8> {
        let mut data = Vec::with_capacity(1024);
        for i in 0..1024 {
            data.push((i % 256) as u8);
        }
        data
    }

    /// Get a large sample message for testing
    pub fn large_message() -> Vec<u8> {
        let mut data = Vec::with_capacity(65536);
        for i in 0..65536 {
            data.push((i % 256) as u8);
        }
        data
    }

    /// Get a sample key pair for testing
    pub fn sample_keypair() -> (Vec<u8>, Vec<u8>) {
        // These are just dummy values for testing
        let public_key = vec![
            0x04, 0xa3, 0xb2, 0xc1, 0xd0, 0xe5, 0xf4, 0x23, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
            0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
            0xdd, 0xee, 0xff, 0x00,
        ];

        let private_key = vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
            0xdd, 0xee, 0xff, 0x00,
        ];

        (public_key, private_key)
    }
}
```

###### Directory: test_utils/src/randomness

####### Directory: test_utils/src/randomness/tests

####### File: test_utils/src/randomness/mod.rs
####*Size: 4.0K, Lines: 52, Type: ASCII text*

```rust
//! Deterministic randomness for reproducible tests

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

/// Deterministic random number generator for tests
pub struct TestRng {
    /// Internal RNG with fixed seed
    rng: StdRng,
}

impl TestRng {
    /// Create a new test RNG with the specified seed
    pub fn new(seed: u64) -> Self {
        // Convert the u64 seed to a [u8; 32] seed array
        let mut seed_array = [0u8; 32];
        let seed_bytes = seed.to_le_bytes();
        // Copy the u64 bytes into the first 8 bytes of the seed array
        seed_array[..8].copy_from_slice(&seed_bytes);

        Self {
            rng: StdRng::from_seed(seed_array),
        }
    }

    /// Create a test RNG with the default seed 12345
    pub fn with_default_seed() -> Self {
        Self::new(12345)
    }

    /// Fill a buffer with random bytes
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.fill_bytes(dest);
    }

    /// Generate a random value
    pub fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    /// Generate a random value
    pub fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }
}

// Implement Default trait instead of just a method named default
impl Default for TestRng {
    fn default() -> Self {
        Self::with_default_seed()
    }
}
```

###### File: test_utils/src/lib.rs
###*Size: 4.0K, Lines: 7, Type: ASCII text*

```rust
//! # DePIN SDK Test Utilities
//!
//! Utilities for testing the DePIN SDK components.

pub mod assertions;
pub mod fixtures;
pub mod randomness;
```

##### File: test_utils/Cargo.toml
##*Size: 4.0K, Lines: 10, Type: ASCII text*

```toml
[package]
name = "depin-sdk-test-utils"
version = "0.1.0"
edition = "2021"
description = "Utilities for testing the DePIN SDK components"
license = "MIT OR Apache-2.0"

[dependencies]
depin-sdk-core = { path = "../core" }
rand = { workspace = true }
```

#### Directory: transaction_models

##### Directory: transaction_models/src

###### Directory: transaction_models/src/account

####### File: transaction_models/src/account/mod.rs
####*Size: 8.0K, Lines: 178, Type: ASCII text*

```rust
// Path: crates/transaction_models/src/account/mod.rs

use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_core::error::{StateError, TransactionError};
use depin_sdk_core::state::StateManager;
use depin_sdk_core::transaction::TransactionModel;
use serde::{Deserialize, Serialize};

// FIX: Add derive macros for PartialEq and Eq, required by HybridTransaction.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AccountTransaction {
    pub from: Vec<u8>,
    pub to: Vec<u8>,
    pub amount: u64,
    pub nonce: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Account {
    pub balance: u64,
    pub nonce: u64,
}

// FIX: Add derive(Debug) as required by HybridConfig.
#[derive(Debug, Clone, Default)]
pub struct AccountConfig {
    pub initial_balance: u64,
}

// FIX: Add derive(Debug, Clone) as required by HybridModel.
#[derive(Debug, Clone)]
pub struct AccountModel<CS: CommitmentScheme> {
    config: AccountConfig,
    _commitment_scheme: CS,
}

impl<CS: CommitmentScheme> AccountModel<CS> {
    pub fn new(commitment_scheme: CS) -> Self {
        Self {
            config: AccountConfig::default(),
            _commitment_scheme: commitment_scheme,
        }
    }

    pub fn with_config(commitment_scheme: CS, config: AccountConfig) -> Self {
        Self {
            config,
            _commitment_scheme: commitment_scheme,
        }
    }

    fn get_account<S: StateManager + ?Sized>(&self, state: &S, key: &[u8]) -> Result<Account, TransactionError> {
        let value = state.get(key)?;
        match value {
            Some(data) => self.decode_account(&data),
            None => Ok(Account {
                balance: self.config.initial_balance,
                nonce: 0,
            }),
        }
    }

    fn decode_account(&self, data: &[u8]) -> Result<Account, TransactionError> {
        // FIX: Use the correct `Serialization` variant.
        serde_json::from_slice(data).map_err(|e| TransactionError::Serialization(e.to_string()))
    }

    fn encode_account(&self, account: &Account) -> Vec<u8> {
        serde_json::to_vec(account).unwrap()
    }
}

impl<CS: CommitmentScheme + Send + Sync> TransactionModel for AccountModel<CS> {
    type Transaction = AccountTransaction;
    type CommitmentScheme = CS;
    type Proof = ();

    // FIX: Add the required `where` clause to the method signature.
    fn validate<S>(&self, tx: &Self::Transaction, state: &S) -> Result<bool, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        let sender_account = self.get_account(state, &tx.from)?;
        if sender_account.balance < tx.amount {
            // FIX: Use the correct `Invalid` variant.
            return Err(TransactionError::Invalid("Insufficient balance".to_string()));
        }
        if sender_account.nonce != tx.nonce {
            return Err(TransactionError::Invalid("Invalid nonce".to_string()));
        }
        Ok(true)
    }

    // FIX: Add the required `where` clause.
    fn apply<S>(&self, tx: &Self::Transaction, state: &mut S) -> Result<(), TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        // Since we now have `From<StateError>` for `TransactionError`, `?` works.
        if !self.validate(tx, state)? {
            // FIX: Use the correct `Invalid` variant.
            return Err(TransactionError::Invalid("Validation failed".to_string()));
        }

        let sender_key = tx.from.clone();
        let mut sender_account = self.get_account(state, &sender_key)?;
        sender_account.balance -= tx.amount;
        sender_account.nonce += 1;
        state.insert(&sender_key, &self.encode_account(&sender_account))?;

        let receiver_key = tx.to.clone();
        let mut receiver_account = self.get_account(state, &receiver_key)?;
        receiver_account.balance = receiver_account
            .balance
            .checked_add(tx.amount)
            // FIX: Use the correct `Invalid` variant.
            .ok_or(TransactionError::Invalid("Balance overflow".to_string()))?;
        state.insert(&receiver_key, &self.encode_account(&receiver_account))?;

        Ok(())
    }

    fn create_coinbase_transaction(
        &self,
        _block_height: u64,
        _recipient: &[u8],
    ) -> Result<Self::Transaction, TransactionError> {
        // Account models don't typically have coinbase transactions.
        Err(TransactionError::Invalid(
            "Coinbase not supported for account model".to_string(),
        ))
    }

    // FIX: Add the required `where` clause.
    fn generate_proof<S>(
        &self,
        _tx: &Self::Transaction,
        _state: &S,
    ) -> Result<Self::Proof, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        Ok(())
    }

    // FIX: Add the required `where` clause.
    fn verify_proof<S>(
        &self,
        _proof: &Self::Proof,
        _state: &S,
    ) -> Result<bool, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        Ok(true)
    }

    fn serialize_transaction(&self, tx: &Self::Transaction) -> Result<Vec<u8>, TransactionError> {
        // FIX: Use the correct `Serialization` variant.
        serde_json::to_vec(tx).map_err(|e| TransactionError::Serialization(e.to_string()))
    }

    fn deserialize_transaction(&self, data: &[u8]) -> Result<Self::Transaction, TransactionError> {
        // FIX: Use the correct `Deserialization` variant.
        serde_json::from_slice(data).map_err(|e| TransactionError::Deserialization(e.to_string()))
    }
}```

###### Directory: transaction_models/src/hybrid

####### File: transaction_models/src/hybrid/mod.rs
####*Size: 8.0K, Lines: 145, Type: ASCII text*

```rust
// Path: crates/transaction_models/src/hybrid/mod.rs

use crate::account::{AccountConfig, AccountModel, AccountTransaction};
use crate::utxo::{UTXOConfig, UTXOModel, UTXOTransaction};
use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_core::error::TransactionError;
use depin_sdk_core::state::StateManager;
use depin_sdk_core::transaction::TransactionModel;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum HybridTransaction {
    Account(AccountTransaction),
    UTXO(UTXOTransaction),
}

#[derive(Debug, Clone)]
pub enum HybridProof {
    // FIX: Match the inner models' proof types, which are now `()`.
    Account(()),
    UTXO(()),
}

#[derive(Debug, Clone, Default)]
pub struct HybridConfig {
    pub account_config: AccountConfig,
    pub utxo_config: UTXOConfig,
}

#[derive(Debug, Clone)]
pub struct HybridModel<CS: CommitmentScheme> {
    account_model: AccountModel<CS>,
    utxo_model: UTXOModel<CS>,
}

impl<CS: CommitmentScheme + Clone> HybridModel<CS> {
    pub fn new(scheme: CS) -> Self {
        Self {
            account_model: AccountModel::new(scheme.clone()),
            utxo_model: UTXOModel::new(scheme),
        }
    }
    pub fn with_config(scheme: CS, config: HybridConfig) -> Self {
        Self {
            account_model: AccountModel::with_config(scheme.clone(), config.account_config),
            utxo_model: UTXOModel::with_config(scheme, config.utxo_config),
        }
    }
}

impl<CS: CommitmentScheme + Clone + Send + Sync> TransactionModel for HybridModel<CS> {
    type Transaction = HybridTransaction;
    type CommitmentScheme = CS;
    type Proof = HybridProof;

    fn create_coinbase_transaction(
        &self,
        block_height: u64,
        recipient: &[u8],
    ) -> Result<Self::Transaction, TransactionError> {
        let utxo_coinbase = self
            .utxo_model
            .create_coinbase_transaction(block_height, recipient)?;
        Ok(HybridTransaction::UTXO(utxo_coinbase))
    }

    // FIX: Add the required `where` clause to the method signature.
    fn validate<S>(&self, tx: &Self::Transaction, state: &S) -> Result<bool, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        match tx {
            HybridTransaction::Account(account_tx) => self.account_model.validate(account_tx, state),
            HybridTransaction::UTXO(utxo_tx) => self.utxo_model.validate(utxo_tx, state),
        }
    }

    // FIX: Add the required `where` clause.
    fn apply<S>(&self, tx: &Self::Transaction, state: &mut S) -> Result<(), TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        match tx {
            HybridTransaction::Account(account_tx) => self.account_model.apply(account_tx, state),
            HybridTransaction::UTXO(utxo_tx) => self.utxo_model.apply(utxo_tx, state),
        }
    }

    // FIX: Add the required `where` clause.
    fn generate_proof<S>(
        &self,
        tx: &Self::Transaction,
        state: &S,
    ) -> Result<Self::Proof, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        match tx {
            HybridTransaction::Account(account_tx) => {
                let proof = self.account_model.generate_proof(account_tx, state)?;
                Ok(HybridProof::Account(proof))
            }
            HybridTransaction::UTXO(utxo_tx) => {
                let proof = self.utxo_model.generate_proof(utxo_tx, state)?;
                Ok(HybridProof::UTXO(proof))
            }
        }
    }

    // FIX: Add the required `where` clause.
    fn verify_proof<S>(
        &self,
        proof: &Self::Proof,
        state: &S,
    ) -> Result<bool, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        match proof {
            HybridProof::Account(account_proof) => {
                self.account_model.verify_proof(account_proof, state)
            }
            HybridProof::UTXO(utxo_proof) => self.utxo_model.verify_proof(utxo_proof, state),
        }
    }

    fn serialize_transaction(&self, tx: &Self::Transaction) -> Result<Vec<u8>, TransactionError> {
        serde_json::to_vec(tx).map_err(|e| TransactionError::Serialization(e.to_string()))
    }

    fn deserialize_transaction(&self, data: &[u8]) -> Result<Self::Transaction, TransactionError> {
        serde_json::from_slice(data).map_err(|e| TransactionError::Deserialization(e.to_string()))
    }
}```

###### Directory: transaction_models/src/utxo

####### File: transaction_models/src/utxo/mod.rs
####*Size: 8.0K, Lines: 190, Type: ASCII text*

```rust
// Path: crates/transaction_models/src/utxo/mod.rs

use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_core::error::{StateError, TransactionError};
use depin_sdk_core::state::StateManager;
use depin_sdk_core::transaction::TransactionModel;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Default)]
pub struct UTXOConfig {
    pub max_inputs: usize,
    pub max_outputs: usize,
}

pub trait UTXOOperations {
    fn create_utxo_key(&self, tx_hash: &[u8], index: u32) -> Vec<u8>;
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Input {
    pub tx_hash: Vec<u8>,
    pub output_index: u32,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub value: u64,
    pub public_key: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct UTXOTransaction {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
}

impl UTXOTransaction {
    pub fn hash(&self) -> Vec<u8> {
        let serialized = serde_json::to_vec(self).unwrap();
        Sha256::digest(&serialized).to_vec()
    }
}

#[derive(Debug, Clone)]
pub struct UTXOModel<CS: CommitmentScheme> {
    config: UTXOConfig,
    _commitment_scheme: CS,
}

impl<CS: CommitmentScheme + Clone> UTXOModel<CS> {
    pub fn new(commitment_scheme: CS) -> Self {
        Self {
            config: UTXOConfig::default(),
            _commitment_scheme: commitment_scheme,
        }
    }
    pub fn with_config(commitment_scheme: CS, config: UTXOConfig) -> Self {
        Self {
            config,
            _commitment_scheme: commitment_scheme,
        }
    }
}

impl<CS: CommitmentScheme> UTXOOperations for UTXOModel<CS> {
    fn create_utxo_key(&self, tx_hash: &[u8], index: u32) -> Vec<u8> {
        let mut key = b"u".to_vec();
        key.extend_from_slice(tx_hash);
        key.extend_from_slice(&index.to_le_bytes());
        key
    }
}

impl<CS: CommitmentScheme + Clone + Send + Sync> TransactionModel for UTXOModel<CS> {
    type Transaction = UTXOTransaction;
    type CommitmentScheme = CS;
    type Proof = ();

    fn validate<SM>(&self, tx: &Self::Transaction, state: &SM) -> Result<bool, TransactionError>
    where
        SM: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        // --- FIX: Add special validation logic for coinbase transactions ---
        // A coinbase transaction is the only valid transaction type with no inputs.
        if tx.inputs.is_empty() {
            // A valid coinbase should have at least one output to reward the miner.
            // More complex rules (e.g., exactly one output) could be added here.
            return Ok(!tx.outputs.is_empty());
        }
        // --- End Fix ---

        if tx.inputs.len() > self.config.max_inputs || tx.outputs.len() > self.config.max_outputs {
            return Ok(false);
        }

        let mut total_input: u64 = 0;
        for input in &tx.inputs {
            let key = self.create_utxo_key(&input.tx_hash, input.output_index);
            let utxo_bytes = state.get(&key)?.ok_or_else(|| {
                TransactionError::Invalid(format!("Input UTXO not found"))
            })?;
            let utxo: Output = serde_json::from_slice(&utxo_bytes)
                .map_err(|e| TransactionError::Invalid(format!("Deserialize error: {}", e)))?;
            total_input = total_input.checked_add(utxo.value)
                .ok_or_else(|| TransactionError::Invalid("Input value overflow".to_string()))?;
        }

        let total_output: u64 = tx.outputs.iter().map(|o| o.value).sum();
        if total_input < total_output {
            return Ok(false);
        }

        Ok(true)
    }

    fn apply<SM>(&self, tx: &Self::Transaction, state: &mut SM) -> Result<(), TransactionError>
    where
        SM: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        if !self.validate(tx, state)? {
            return Err(TransactionError::Invalid("Validation failed".to_string()));
        }
        for input in &tx.inputs {
            let key = self.create_utxo_key(&input.tx_hash, input.output_index);
            state.delete(&key)?;
        }
        let tx_hash = tx.hash();
        for (index, output) in tx.outputs.iter().enumerate() {
            let key = self.create_utxo_key(&tx_hash, index as u32);
            let value = serde_json::to_vec(output)
                .map_err(|e| TransactionError::Serialization(e.to_string()))?;
            state.insert(&key, &value)?;
        }
        Ok(())
    }

    fn create_coinbase_transaction(
        &self,
        _block_height: u64,
        recipient: &[u8],
    ) -> Result<Self::Transaction, TransactionError> {
        Ok(UTXOTransaction {
            inputs: vec![],
            outputs: vec![Output { value: 50, public_key: recipient.to_vec() }],
        })
    }

    fn generate_proof<S>(
        &self,
        _tx: &Self::Transaction,
        _state: &S,
    ) -> Result<Self::Proof, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        Ok(())
    }

    fn verify_proof<S>(
        &self,
        _proof: &Self::Proof,
        _state: &S,
    ) -> Result<bool, TransactionError>
    where
        S: StateManager<
                Commitment = <Self::CommitmentScheme as CommitmentScheme>::Commitment,
                Proof = <Self::CommitmentScheme as CommitmentScheme>::Proof,
            > + ?Sized,
    {
        Ok(true)
    }

    fn serialize_transaction(&self, tx: &Self::Transaction) -> Result<Vec<u8>, TransactionError> {
        serde_json::to_vec(tx).map_err(|e| TransactionError::Serialization(e.to_string()))
    }

    fn deserialize_transaction(&self, data: &[u8]) -> Result<Self::Transaction, TransactionError> {
        serde_json::from_slice(data).map_err(|e| TransactionError::Deserialization(e.to_string()))
    }
}```

###### File: transaction_models/src/lib.rs
###*Size: 4.0K, Lines: 10, Type: ASCII text*

```rust
// Path: crates/transaction_models/src/lib.rs

#![allow(clippy::new_without_default)]
pub mod account;
pub mod hybrid;
pub mod utxo;

pub use account::{AccountConfig, AccountModel, AccountTransaction};
// FIX: The HybridOperations trait does not exist, so this line is removed.
pub use hybrid::{HybridConfig, HybridModel, HybridTransaction};
pub use utxo::{UTXOConfig, UTXOModel, UTXOTransaction};```

##### File: transaction_models/Cargo.toml
##*Size: 4.0K, Lines: 19, Type: ASCII text*

```toml
[package]
name = "depin-sdk-transaction-models"
version = "0.1.0"
edition = "2021"
description = "Transaction model implementations for the DePIN SDK"
license = "MIT OR Apache-2.0"

[dependencies]
depin-sdk-core = { path = "../core" }
log = { workspace = true }
serde = { workspace = true, features = ["derive"] }
serde_json = { workspace = true }
thiserror = { workspace = true }
sha2 = { workspace = true }
# FIX: Add the missing 'hex' dependency used for logging UTXO hashes.
hex = { workspace = true }

[features]
default = []
```

#### Directory: validator

##### Directory: validator/src

###### Directory: validator/src/bin

####### File: validator/src/bin/validator_hybrid.rs
####*Size: 4.0K, Lines: 73, Type: C source, ASCII text*

```rust
// Path: crates/validator/src/bin/validator_hybrid.rs

use anyhow::anyhow;
use clap::Parser;
// FIX: Import WorkloadContainer from its new, correct location in `core`.
use depin_sdk_core::validator::WorkloadContainer;
use depin_sdk_core::{config::WorkloadConfig, Container};
use depin_sdk_state_trees::file::FileStateTree;
// FIX: Add necessary imports.
use depin_sdk_commitment_schemes::hash::HashCommitmentScheme;
use depin_sdk_validator::{
    common::GuardianContainer,
    hybrid::{ApiContainer, InterfaceContainer},
    standard::OrchestrationContainer,
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;


#[derive(Parser, Debug)]
#[clap(name = "validator_hybrid", about = "A hybrid DePIN SDK validator node with public APIs.")]
struct Opts {
    #[clap(long, default_value = "./config")]
    config_dir: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::builder().filter_level(log::LevelFilter::Info).init();
    let opts = Opts::parse();
    let path = PathBuf::from(opts.config_dir);

    log::info!("Initializing Hybrid Validator...");

    // FIX: Pass borrowed paths (`&`) to the `new` constructors.
    let guardian = GuardianContainer::new(&path.join("guardian.toml"))?;

    let state_tree = FileStateTree::new("state.json", HashCommitmentScheme::new());

    let workload = Arc::new(WorkloadContainer::new(
        WorkloadConfig::default(),
        state_tree,
    ));

    let orchestration = Arc::new(OrchestrationContainer::new(
        &path.join("orchestration.toml"),
    )?);
    
    // Wire up a dummy chain for now.
    orchestration.set_chain_and_workload_ref(Arc::new(Mutex::new(())), workload);

    let interface = InterfaceContainer::new(&path.join("interface.toml"))?;
    let api = ApiContainer::new(&path.join("api.toml"))?;


    log::info!("Starting services...");
    guardian.start()?;
    // FIX: The start method is async and must be awaited.
    orchestration.start().await?;
    interface.start()?;
    api.start()?;

    tokio::signal::ctrl_c().await?;
    log::info!("Shutdown signal received.");

    api.stop()?;
    interface.stop()?;
    orchestration.stop().await?;
    guardian.stop()?;
    log::info!("Validator stopped gracefully.");
    
    Ok(())
}```

####### File: validator/src/bin/validator.rs
####*Size: 4.0K, Lines: 64, Type: C source, ASCII text*

```rust
// Path: crates/validator/src/bin/validator.rs

use anyhow::anyhow;
use clap::Parser;
use depin_sdk_commitment_schemes::hash::HashCommitmentScheme;
// FIX: core::Container is now async
use depin_sdk_core::validator::{Container, WorkloadContainer};
use depin_sdk_core::WorkloadConfig;
use depin_sdk_state_trees::file::FileStateTree;
use depin_sdk_validator::{common::GuardianContainer, standard::OrchestrationContainer};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Parser, Debug)]
#[clap(name = "validator", about = "A standard DePIN SDK validator node.")]
struct Opts {
    #[clap(long, default_value = "./config")]
    config_dir: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::builder().filter_level(log::LevelFilter::Info).init();
    let opts = Opts::parse();
    let path = PathBuf::from(opts.config_dir);

    log::info!("Initializing Standard Validator...");

    let guardian = GuardianContainer::new(&path.join("guardian.toml"))?;

    let state_tree = FileStateTree::new("state.json", HashCommitmentScheme::new());

    let workload_config = WorkloadConfig {
        enabled_vms: vec!["WASM".to_string()],
    };

    let workload = Arc::new(WorkloadContainer::new(workload_config, state_tree));

    // FIX: OrchestrationContainer::new is now async and must be awaited.
    let orchestration = Arc::new(
        OrchestrationContainer::<
            HashCommitmentScheme,
            (), // Placeholder for TM
            FileStateTree<HashCommitmentScheme>,
        >::new(&path.join("orchestration.toml"))
        .await?,
    );

    // Wire up a dummy chain for now. In a real scenario, this would be part of the composition root.
    // orchestration.set_chain_and_workload_ref(Arc::new(Mutex::new(())), workload);

    log::info!("Starting services...");
    orchestration.start().await?;
    guardian.start().await?;

    tokio::signal::ctrl_c().await?;
    log::info!("Shutdown signal received.");

    orchestration.stop().await?;
    guardian.stop().await?;
    log::info!("Validator stopped gracefully.");

    Ok(())
}```

###### Directory: validator/src/common

####### Directory: validator/src/common/tests

######## File: validator/src/common/tests/mod.rs
#####*Size: 4.0K, Lines: 45, Type: ASCII text*

```rust
//! Tests for common validator components

#[cfg(test)]
mod tests {
    use super::super::guardian::{BootStatus, GuardianContainer};
    use super::super::security::SecurityChannel;
    use std::path::Path;

    #[test]
    fn test_guardian_container() {
        let config_path = Path::new("test_config.toml");
        let guardian = GuardianContainer::new(config_path);

        // Initial state
        assert_eq!(guardian.boot_status(), BootStatus::NotStarted);

        // Start boot process
        guardian.start_boot().unwrap();
        assert_eq!(guardian.boot_status(), BootStatus::Completed);

        // Verify attestation
        let attestation_result = guardian.verify_attestation().unwrap();
        assert!(attestation_result);
    }

    #[test]
    fn test_security_channel() {
        let channel = SecurityChannel::new("test_source", "test_destination");

        assert_eq!(channel.source, "test_source");
        assert_eq!(channel.destination, "test_destination");
        assert_eq!(channel.channel_id, "test_source:test_destination");

        // Test establish
        channel.establish().unwrap();

        // Test send and receive
        let data = vec![1, 2, 3, 4];
        channel.send(&data).unwrap();

        let received = channel.receive(10).unwrap();
        // In our implementation, receive returns empty data for testing
        assert_eq!(received.len(), 0);
    }
}
```

####### File: validator/src/common/attestation.rs
####*Size: 16K, Lines: 415, Type: ASCII text*

```rust
// attestation.rs - Container attestation implementation

use crate::chain::ChainState;
use crate::crypto::{CryptoProvider, SignatureScheme};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

/// Attestation data structure that follows chain's signature evolution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerAttestation {
    /// Container identifier
    pub container_id: ContainerId,

    /// Merkle root of measured binaries and memory
    pub merkle_root: MerkleRoot,

    /// Challenge nonce from Guardian
    pub nonce: Vec<u8>,

    /// Timestamp of attestation
    pub timestamp: Timestamp,

    /// Public key for verification (format depends on current scheme)
    pub public_key: Vec<u8>,

    /// Signature over (nonce || merkle_root || timestamp)
    /// Uses the chain's current signature scheme
    pub signature: Vec<u8>,

    /// Metadata about the attestation
    pub metadata: AttestationMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationMetadata {
    /// Which signature scheme was used (for verification)
    pub signature_scheme: SignatureScheme,

    /// Container version
    pub container_version: String,

    /// Additional measurements
    pub extended_measurements: HashMap<String, Vec<u8>>,
}

/// Attestation manager that handles the protocol
pub struct AttestationManager {
    /// Reference to chain state for current signature scheme
    chain_state: Arc<ChainState>,

    /// Cryptographic provider
    crypto_provider: Arc<CryptoProvider>,

    /// Container's key pair (format depends on current scheme)
    key_pair: Arc<RwLock<KeyPair>>,

    /// Configuration
    config: AttestationConfig,

    /// Attestation history for monitoring
    history: RwLock<AttestationHistory>,
}

impl AttestationManager {
    /// Creates attestation using current chain signature scheme
    pub async fn create_attestation(
        &self,
        nonce: &[u8],
        measurements: &ContainerMeasurements,
    ) -> Result<ContainerAttestation, AttestationError> {
        // Get current signature scheme from chain
        let current_scheme = self
            .chain_state
            .get_active_signature_scheme()
            .await
            .map_err(|e| AttestationError::ChainStateError(e))?;

        // Build merkle root from measurements
        let merkle_root = self.compute_merkle_root(measurements)?;

        // Create attestation message
        let timestamp = current_time();
        let message = self.build_attestation_message(nonce, &merkle_root, timestamp)?;

        // Sign using current scheme
        let key_pair = self.key_pair.read().await;
        let (signature, public_key) = match current_scheme {
            SignatureScheme::Ed25519 => {
                let sig = self
                    .crypto_provider
                    .sign_ed25519(&key_pair.ed25519()?, &message)?;
                let pk = key_pair.ed25519()?.public_key();
                (sig, pk)
            }
            SignatureScheme::Dilithium2 => {
                let sig = self
                    .crypto_provider
                    .sign_dilithium2(&key_pair.dilithium2()?, &message)?;
                let pk = key_pair.dilithium2()?.public_key();
                (sig, pk)
            }
            SignatureScheme::Falcon512 => {
                let sig = self
                    .crypto_provider
                    .sign_falcon512(&key_pair.falcon512()?, &message)?;
                let pk = key_pair.falcon512()?.public_key();
                (sig, pk)
            }
            // Add other schemes as needed
            _ => return Err(AttestationError::UnsupportedScheme(current_scheme)),
        };

        // Create attestation
        let attestation = ContainerAttestation {
            container_id: self.get_container_id(),
            merkle_root,
            nonce: nonce.to_vec(),
            timestamp,
            public_key,
            signature,
            metadata: AttestationMetadata {
                signature_scheme: current_scheme,
                container_version: self.get_container_version(),
                extended_measurements: measurements.extended.clone(),
            },
        };

        // Record in history
        self.history.write().await.record_attestation(&attestation);

        Ok(attestation)
    }

    /// Handles key rotation when chain signature scheme changes
    pub async fn handle_signature_rotation(
        &self,
        new_scheme: SignatureScheme,
    ) -> Result<(), RotationError> {
        info!(
            "Rotating attestation keys to {:?} following chain rotation",
            new_scheme
        );

        // Generate new key pair for the scheme
        let new_key_pair = match new_scheme {
            SignatureScheme::Ed25519 => KeyPair::generate_ed25519(&mut self.crypto_provider.rng())?,
            SignatureScheme::Dilithium2 => {
                KeyPair::generate_dilithium2(&mut self.crypto_provider.rng())?
            }
            SignatureScheme::Falcon512 => {
                KeyPair::generate_falcon512(&mut self.crypto_provider.rng())?
            }
            _ => return Err(RotationError::UnsupportedScheme(new_scheme)),
        };

        // Atomic key replacement
        let mut key_pair = self.key_pair.write().await;
        *key_pair = new_key_pair;

        // Notify Guardian of key rotation
        self.notify_guardian_of_rotation(new_scheme).await?;

        Ok(())
    }

    /// Builds the attestation message to be signed
    fn build_attestation_message(
        &self,
        nonce: &[u8],
        merkle_root: &MerkleRoot,
        timestamp: Timestamp,
    ) -> Result<Vec<u8>, AttestationError> {
        let mut message = Vec::new();
        message.extend_from_slice(nonce);
        message.extend_from_slice(merkle_root.as_bytes());
        message.extend_from_slice(&timestamp.to_be_bytes());
        Ok(message)
    }

    /// Monitors chain for signature scheme changes
    pub async fn monitor_scheme_changes(&self) -> Result<(), Error> {
        let mut current_scheme = self.chain_state.get_active_signature_scheme().await?;

        loop {
            // Check every block for scheme changes
            tokio::time::sleep(self.config.scheme_check_interval).await;

            let new_scheme = self.chain_state.get_active_signature_scheme().await?;
            if new_scheme != current_scheme {
                info!(
                    "Detected signature scheme change: {:?} -> {:?}",
                    current_scheme, new_scheme
                );

                // Handle rotation
                self.handle_signature_rotation(new_scheme).await?;
                current_scheme = new_scheme;
            }
        }
    }
}

/// Guardian-side attestation verifier
pub struct AttestationVerifier {
    chain_state: Arc<ChainState>,
    crypto_provider: Arc<CryptoProvider>,
    config: AttestationConfig,
    container_registry: Arc<ContainerRegistry>,
}

impl AttestationVerifier {
    /// Verifies attestation using the scheme it was created with
    pub async fn verify_attestation(
        &self,
        attestation: &ContainerAttestation,
    ) -> Result<(), AttestationError> {
        // Verify timestamp freshness
        let now = current_time();
        let age = now.saturating_sub(attestation.timestamp);
        if age > self.config.max_attestation_age {
            return Err(AttestationError::StaleAttestation { age });
        }

        // Check clock skew
        if attestation.timestamp > now + self.config.max_clock_skew {
            return Err(AttestationError::ClockSkew);
        }

        // Verify container is registered
        let container_info = self
            .container_registry
            .get(&attestation.container_id)
            .await
            .ok_or(AttestationError::UnknownContainer)?;

        // Build message for verification
        let message = self.build_attestation_message(
            &attestation.nonce,
            &attestation.merkle_root,
            attestation.timestamp,
        )?;

        // Verify signature using the scheme specified in metadata
        match attestation.metadata.signature_scheme {
            SignatureScheme::Ed25519 => {
                self.crypto_provider.verify_ed25519(
                    &attestation.public_key,
                    &message,
                    &attestation.signature,
                )?;
            }
            SignatureScheme::Dilithium2 => {
                self.crypto_provider.verify_dilithium2(
                    &attestation.public_key,
                    &message,
                    &attestation.signature,
                )?;
            }
            SignatureScheme::Falcon512 => {
                self.crypto_provider.verify_falcon512(
                    &attestation.public_key,
                    &message,
                    &attestation.signature,
                )?;
            }
            _ => {
                return Err(AttestationError::UnsupportedScheme(
                    attestation.metadata.signature_scheme,
                ))
            }
        }

        // Verify merkle root matches expected manifest
        self.verify_merkle_root_integrity(
            &attestation.merkle_root,
            &container_info.expected_manifest,
        )?;

        Ok(())
    }

    /// Batch verification for efficiency when possible
    pub async fn verify_attestation_batch(
        &self,
        attestations: &[ContainerAttestation],
    ) -> Result<Vec<Result<(), AttestationError>>, Error> {
        // Group by signature scheme for batch verification
        let mut by_scheme: HashMap<SignatureScheme, Vec<&ContainerAttestation>> = HashMap::new();

        for attestation in attestations {
            by_scheme
                .entry(attestation.metadata.signature_scheme)
                .or_default()
                .push(attestation);
        }

        let mut results = Vec::with_capacity(attestations.len());

        // Batch verify each scheme group
        for (scheme, group) in by_scheme {
            match scheme {
                SignatureScheme::Ed25519 => {
                    // Ed25519 supports efficient batch verification
                    let batch_results = self.batch_verify_ed25519(group).await?;
                    results.extend(batch_results);
                }
                _ => {
                    // Other schemes: verify individually
                    for attestation in group {
                        results.push(self.verify_attestation(attestation).await);
                    }
                }
            }
        }

        Ok(results)
    }
}

/// Attestation monitoring and health tracking
#[derive(Debug)]
pub struct AttestationHealth {
    pub success_rate: f64,
    pub average_latency: Duration,
    pub failed_containers: Vec<ContainerId>,
    pub last_rotation: Option<(SignatureScheme, Timestamp)>,
}

impl AttestationManager {
    /// Gets current attestation health metrics
    pub async fn get_health(&self) -> AttestationHealth {
        let history = self.history.read().await;

        AttestationHealth {
            success_rate: history.calculate_success_rate(),
            average_latency: history.calculate_average_latency(),
            failed_containers: history.get_failed_containers(),
            last_rotation: history.get_last_rotation(),
        }
    }
}

/// Errors specific to attestation
#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    #[error("Unsupported signature scheme: {0:?}")]
    UnsupportedScheme(SignatureScheme),

    #[error("Stale attestation (age: {age:?})")]
    StaleAttestation { age: Duration },

    #[error("Clock skew detected")]
    ClockSkew,

    #[error("Unknown container")]
    UnknownContainer,

    #[error("Merkle root mismatch")]
    MerkleRootMismatch,

    #[error("Chain state error: {0}")]
    ChainStateError(#[from] ChainStateError),

    #[error("Cryptographic error: {0}")]
    CryptoError(#[from] CryptoError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_attestation_follows_chain_rotation() {
        // Setup
        let chain_state = Arc::new(mock_chain_state());
        let crypto_provider = Arc::new(CryptoProvider::new());
        let manager = AttestationManager::new(chain_state.clone(), crypto_provider);

        // Initially using Ed25519
        chain_state
            .set_active_scheme(SignatureScheme::Ed25519)
            .await;

        // Create attestation with Ed25519
        let attestation1 = manager
            .create_attestation(b"nonce1", &measurements())
            .await?;
        assert_eq!(
            attestation1.metadata.signature_scheme,
            SignatureScheme::Ed25519
        );

        // Chain rotates to Dilithium2
        chain_state
            .set_active_scheme(SignatureScheme::Dilithium2)
            .await;
        manager
            .handle_signature_rotation(SignatureScheme::Dilithium2)
            .await?;

        // New attestation uses Dilithium2
        let attestation2 = manager
            .create_attestation(b"nonce2", &measurements())
            .await?;
        assert_eq!(
            attestation2.metadata.signature_scheme,
            SignatureScheme::Dilithium2
        );

        // Both attestations can be verified
        let verifier = AttestationVerifier::new(chain_state, crypto_provider);
        verifier.verify_attestation(&attestation1).await?;
        verifier.verify_attestation(&attestation2).await?;
    }
}
```

####### File: validator/src/common/guardian.rs
####*Size: 4.0K, Lines: 63, Type: ASCII text*

```rust
// Path: crates/validator/src/common/guardian.rs

use async_trait::async_trait;
use depin_sdk_core::error::ValidatorError;
use depin_sdk_core::validator::{Container, GuardianContainer as GuardianContainerTrait};
use std::path::Path;
// FIX: Add imports for atomic state management
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[derive(Debug, Default)]
pub struct GuardianContainer {
    // FIX: Use Arc<AtomicBool> for thread-safe interior mutability.
    running: Arc<AtomicBool>,
}

impl GuardianContainer {
    pub fn new(_config_path: &Path) -> anyhow::Result<Self> {
        // FIX: Initialize the atomic bool correctly.
        Ok(Self {
            running: Arc::new(AtomicBool::new(false)),
        })
    }
}

#[async_trait]
impl Container for GuardianContainer {
    async fn start(&self) -> Result<(), ValidatorError> {
        log::info!("Starting GuardianContainer...");
        // FIX: Atomically set the running flag to true.
        self.running.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn stop(&self) -> Result<(), ValidatorError> {
        log::info!("Stopping GuardianContainer...");
        // FIX: Atomically set the running flag to false.
        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn is_running(&self) -> bool {
        // FIX: Atomically load the value of the running flag.
        self.running.load(Ordering::SeqCst)
    }

    fn id(&self) -> &'static str {
        "guardian"
    }
}

impl GuardianContainerTrait for GuardianContainer {
    fn start_boot(&self) -> Result<(), ValidatorError> {
        log::info!("Guardian: Initiating secure boot sequence...");
        Ok(())
    }

    fn verify_attestation(&self) -> Result<bool, ValidatorError> {
        log::info!("Guardian: Verifying inter-container attestation...");
        Ok(true)
    }
}```

####### File: validator/src/common/mod.rs
####*Size: 4.0K, Lines: 10, Type: ASCII text*

```rust
//! Common validator components shared by all types

mod guardian;
mod security;

#[cfg(test)]
mod tests;

pub use guardian::*;
pub use security::*;
```

####### File: validator/src/common/security.rs
####*Size: 4.0K, Lines: 55, Type: ASCII text*

```rust
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
    pub fn establish(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Simplified channel establishment for initial setup
        // In a real implementation, we would:
        // 1. Perform mutual authentication
        // 2. Establish encrypted channel
        // 3. Set up access controls
        
        println!("Establishing security channel: {}", self.channel_id);
        
        Ok(())
    }
    
    /// Send data through the security channel
    pub fn send(&self, data: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Simplified sending for initial setup
        println!("Sending {} bytes through channel {}", data.len(), self.channel_id);
        
        Ok(())
    }
    
    /// Receive data from the security channel
    pub fn receive(&self, max_size: usize) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        // Simplified receiving for initial setup
        println!("Receiving up to {} bytes from channel {}", max_size, self.channel_id);
        
        // Return empty data for now
        Ok(Vec::new())
    }
}```

###### Directory: validator/src/hybrid

####### Directory: validator/src/hybrid/tests

######## File: validator/src/hybrid/tests/mod.rs
#####*Size: 4.0K, Lines: 63, Type: ASCII text*

```rust
//! Tests for hybrid validator components

#[cfg(test)]
mod tests {
    use super::super::{ApiContainer, HybridValidator, InterfaceContainer};
    use std::net::SocketAddr;
    use std::path::Path;

    #[test]
    fn test_interface_container() {
        let config_path = Path::new("test_interface.toml");
        let interface = InterfaceContainer::new(config_path);

        assert!(!interface.is_running());

        interface.start().unwrap();
        // Note: in the current implementation, the running state isn't actually updated

        // Test connection handling
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let data = vec![1, 2, 3, 4];
        let result = interface.handle_connection(addr, &data).unwrap();
        assert_eq!(result, vec![5, 6, 7, 8]); // Should return the mock result defined in the implementation

        interface.stop().unwrap();
    }

    #[test]
    fn test_api_container() {
        let config_path = Path::new("test_api.toml");
        let api = ApiContainer::new(config_path);

        assert!(!api.is_running());

        api.start().unwrap();
        // Note: in the current implementation, the running state isn't actually updated

        // Test API request handling
        let endpoint = "test_endpoint";
        let params = vec![1, 2, 3, 4];
        let result = api.handle_request(endpoint, &params).unwrap();
        assert_eq!(result, vec![9, 10, 11, 12]); // Should return the mock result defined in the implementation

        api.stop().unwrap();
    }

    #[test]
    fn test_hybrid_validator() {
        let temp_dir = std::env::temp_dir();

        // This is just a test, so we're not actually creating these files
        // In a real test, we might want to create temporary config files

        // Create validator
        let validator = HybridValidator::new(&temp_dir).unwrap();

        // Start validator - this should start all containers
        validator.start().unwrap();

        // Stop validator - this should stop all containers
        validator.stop().unwrap();
    }
}
```

####### File: validator/src/hybrid/api.rs
####*Size: 4.0K, Lines: 63, Type: ASCII text*

```rust
// Path: crates/validator/src/hybrid/api.rs

use depin_sdk_core::error::ValidatorError;
use depin_sdk_core::validator::Container;
use serde::Deserialize;
use std::path::Path;
// FIX: Add imports for atomic state management
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use toml;

/// Configuration for the API container, loaded from `api.toml`.
#[derive(Deserialize)]
pub struct ApiConfig {
    pub listen_address: String,
    pub enabled_endpoints: Vec<String>,
}

/// The ApiContainer is responsible for implementing the public-facing JSON-RPC
/// or other state-query APIs for a hybrid validator.
pub struct ApiContainer {
    config: ApiConfig,
    // FIX: Use Arc<AtomicBool> for thread-safe state.
    running: Arc<AtomicBool>,
}

impl ApiContainer {
    pub fn new(config_path: &Path) -> anyhow::Result<Self> {
        let config_str = std::fs::read_to_string(config_path)?;
        let config: ApiConfig = toml::from_str(&config_str)?;
        Ok(Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
        })
    }
}

#[async_trait::async_trait]
impl Container for ApiContainer {
    async fn start(&self) -> Result<(), ValidatorError> {
        log::info!(
            "Starting ApiContainer, listening on {}...",
            self.config.listen_address
        );
        self.running.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn stop(&self) -> Result<(), ValidatorError> {
        log::info!("Stopping ApiContainer...");
        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn id(&self) -> &'static str {
        "api"
    }
}```

####### File: validator/src/hybrid/interface.rs
####*Size: 4.0K, Lines: 63, Type: ASCII text*

```rust
// Path: crates/validator/src/hybrid/interface.rs

use depin_sdk_core::error::ValidatorError;
use depin_sdk_core::validator::Container;
use serde::Deserialize;
use std::path::Path;
// FIX: Add imports for atomic state management
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use toml;

/// Configuration for the Interface container, loaded from `interface.toml`.
#[derive(Deserialize)]
pub struct InterfaceConfig {
    pub max_connections: u32,
    pub rate_limit_per_second: u64,
}

/// The InterfaceContainer manages raw network connections, protocol routing,
/// and basic DDoS protection for a hybrid validator's public-facing services.
pub struct InterfaceContainer {
    config: InterfaceConfig,
    // FIX: Use Arc<AtomicBool> for thread-safe state.
    running: Arc<AtomicBool>,
}

impl InterfaceContainer {
    pub fn new(config_path: &Path) -> anyhow::Result<Self> {
        let config_str = std::fs::read_to_string(config_path)?;
        let config: InterfaceConfig = toml::from_str(&config_str)?;
        Ok(Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
        })
    }
}

#[async_trait::async_trait]
impl Container for InterfaceContainer {
    async fn start(&self) -> Result<(), ValidatorError> {
        log::info!(
            "Starting InterfaceContainer with max {} connections...",
            self.config.max_connections
        );
        self.running.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn stop(&self) -> Result<(), ValidatorError> {
        log::info!("Stopping InterfaceContainer...");
        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn id(&self) -> &'static str {
        "interface"
    }
}```

####### File: validator/src/hybrid/mod.rs
####*Size: 4.0K, Lines: 7, Type: ASCII text*

```rust
// Path: crates/validator/src/hybrid/mod.rs

pub mod api;
pub mod interface;

// FIX: Publicly re-export the containers so they are visible to binaries.
pub use api::ApiContainer;
pub use interface::InterfaceContainer;```

###### Directory: validator/src/standard

####### Directory: validator/src/standard/tests

######## File: validator/src/standard/tests/mod.rs
#####*Size: 4.0K, Lines: 57, Type: ASCII text*

```rust
//! Tests for standard validator components

#[cfg(test)]
mod tests {
    use super::super::{OrchestrationContainer, StandardValidator, WorkloadContainer};
    use crate::common::GuardianContainer;
    use std::path::Path;

    #[test]
    fn test_orchestration_container() {
        let config_path = Path::new("test_orchestration.toml");
        let orchestration = OrchestrationContainer::new(config_path);

        assert!(!orchestration.is_running());

        orchestration.start().unwrap();
        // Note: in the current implementation, the running state isn't actually updated
        // In a real implementation, we'd expect is_running() to return true here

        orchestration.stop().unwrap();
    }

    #[test]
    fn test_workload_container() {
        let config_path = Path::new("test_workload.toml");
        let workload = WorkloadContainer::new(config_path);

        assert!(!workload.is_running());

        workload.start().unwrap();
        // Note: in the current implementation, the running state isn't actually updated

        // Test transaction execution
        let tx_data = vec![1, 2, 3, 4];
        let result = workload.execute_transaction(&tx_data).unwrap();
        assert_eq!(result, vec![1, 2, 3, 4]); // Should return the mock result defined in the implementation

        workload.stop().unwrap();
    }

    #[test]
    fn test_standard_validator() {
        let temp_dir = std::env::temp_dir();

        // This is just a test, so we're not actually creating these files
        // In a real test, we might want to create temporary config files

        // Create validator
        let validator = StandardValidator::new(&temp_dir).unwrap();

        // Start validator - this should start all containers
        validator.start().unwrap();

        // Stop validator - this should stop all containers
        validator.stop().unwrap();
    }
}
```

####### File: validator/src/standard/mod.rs
####*Size: 4.0K, Lines: 6, Type: ASCII text*

```rust
// Path: crates/validator/src/standard/mod.rs

pub mod orchestration;
pub mod workload;

// FIX: Publicly re-export the container so it's visible to binaries in the same crate.
pub use orchestration::OrchestrationContainer;```

####### File: validator/src/standard/orchestration.rs
####*Size: 12K, Lines: 273, Type: ASCII text*

```rust
// Path: crates/validator/src/standard/orchestration.rs

use crate::config::OrchestrationConfig;
use async_trait::async_trait;
use depin_sdk_core::{
    chain::SovereignChain,
    commitment::CommitmentScheme,
    error::ValidatorError,
    state::{StateManager, StateTree},
    transaction::TransactionModel,
    validator::{Container, WorkloadContainer},
};
use futures::StreamExt;
use libp2p::{
    core::upgrade, gossipsub, identity, noise, swarm::SwarmEvent, tcp, yamux, Swarm,
    SwarmBuilder, Transport,
};
use std::fmt::Debug;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::{
    sync::{watch, Mutex, OnceCell},
    task::JoinHandle,
    time::{self, Duration},
};

pub struct OrchestrationContainer<CS, TM, ST>
where
    CS: CommitmentScheme + Send + Sync + 'static,
    TM: TransactionModel<CommitmentScheme = CS> + Clone + Send + Sync + 'static,
    TM::Transaction: Clone + Debug + Send + Sync,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static + Debug,
{
    _config: OrchestrationConfig,
    chain: Arc<OnceCell<Arc<Mutex<dyn SovereignChain<CS, TM, ST> + Send + Sync>>>>,
    workload: Arc<OnceCell<Arc<WorkloadContainer<ST>>>>,
    swarm: Arc<Mutex<Swarm<gossipsub::Behaviour>>>,
    shutdown_sender: Arc<watch::Sender<bool>>,
    task_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
    is_running: Arc<AtomicBool>,
}

impl<CS, TM, ST> OrchestrationContainer<CS, TM, ST>
where
    CS: CommitmentScheme + Send + Sync + 'static,
    TM: TransactionModel<CommitmentScheme = CS> + Clone + Send + Sync + 'static,
    TM::Transaction: Clone + Debug + Send + Sync,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + StateTree<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug,
    CS::Commitment: Send + Sync + Debug,
{
    pub async fn new(config_path: &std::path::Path) -> anyhow::Result<Self> {
        let _config: OrchestrationConfig =
            toml::from_str(&std::fs::read_to_string(config_path)?)?;

        let (shutdown_sender, _) = watch::channel(false);

        let local_key = identity::Keypair::generate_ed25519();

        let swarm = SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_other_transport(|key| {
                let noise_config = noise::Config::new(key)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                let transport = tcp::tokio::Transport::new(tcp::Config::default())
                    .upgrade(upgrade::Version::V1Lazy)
                    .authenticate(noise_config)
                    .multiplex(yamux::Config::default())
                    .timeout(std::time::Duration::from_secs(20))
                    .boxed();
                Ok(transport)
            })?
            .with_behaviour(|key| {
                let gossipsub_config = gossipsub::Config::default();
                gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )
                .expect("Valid gossipsub config")
            })?
            .build();

        Ok(Self {
            _config,
            chain: Arc::new(OnceCell::new()),
            workload: Arc::new(OnceCell::new()),
            swarm: Arc::new(Mutex::new(swarm)),
            shutdown_sender: Arc::new(shutdown_sender),
            task_handles: Arc::new(Mutex::new(Vec::new())),
            is_running: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn set_chain_and_workload_ref(
        &self,
        chain_ref: Arc<Mutex<dyn SovereignChain<CS, TM, ST> + Send + Sync>>,
        workload_ref: Arc<WorkloadContainer<ST>>,
    ) {
        self.chain.set(chain_ref).expect("Chain ref already set");
        self.workload
            .set(workload_ref)
            .expect("Workload ref already set");
    }

    async fn run_event_loop(
        swarm_ref: Arc<Mutex<Swarm<gossipsub::Behaviour>>>,
        mut shutdown_receiver: watch::Receiver<bool>,
    ) {
        loop {
            tokio::select! {
                biased;
                _ = shutdown_receiver.changed() => {
                    if *shutdown_receiver.borrow() {
                        log::info!("Orchestration event loop received shutdown signal.");
                        break;
                    }
                },
                event = async { swarm_ref.lock().await.select_next_some().await } => {
                     match event {
                        SwarmEvent::Behaviour(gossipsub::Event::Message { message, .. }) => {
                            log::info!(
                                "Received block gossip from peer {:?}: '{}'",
                                message.source,
                                String::from_utf8_lossy(&message.data)
                            );
                        }
                        SwarmEvent::NewListenAddr { address, .. } => {
                            log::info!("OrchestrationContainer now listening on {}", address);
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            log::info!("Connection established with peer: {:?}", peer_id);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    async fn run_block_production(
        chain_ref: Arc<Mutex<dyn SovereignChain<CS, TM, ST> + Send + Sync>>,
        workload_ref: Arc<WorkloadContainer<ST>>,
        swarm_ref: Arc<Mutex<Swarm<gossipsub::Behaviour>>>,
        is_running: Arc<AtomicBool>,
    ) {
        let mut interval = time::interval(Duration::from_secs(10));
        while is_running.load(Ordering::SeqCst) {
            interval.tick().await;

            let new_block;
            {
                let mut chain = chain_ref.lock().await;
                let tm = chain.transaction_model().clone();
                let coinbase_result = tm
                    .create_coinbase_transaction(chain.status().height + 1, &[]);
                
                let coinbase = match coinbase_result {
                    Ok(tx) => tx,
                    Err(e) => {
                        log::error!("Failed to create coinbase transaction: {:?}", e);
                        continue;
                    }
                };

                new_block = chain.create_block(vec![coinbase], &workload_ref);

                if let Err(e) = chain
                    .process_block(new_block.clone(), &workload_ref)
                    .await
                {
                    log::error!("Failed to process new block: {:?}", e);
                    continue;
                }
                log::info!("Produced and processed new block #{}", new_block.header.height);
            }
            
            // --- FIX: Decouple network publishing from the main loop ---
            // Spawn a separate task to handle the potentially slow network I/O.
            // This prevents the main block production loop from ever getting stuck.
            let swarm_clone = swarm_ref.clone();
            tokio::spawn(async move {
                let mut swarm = swarm_clone.lock().await;
                let topic = gossipsub::IdentTopic::new("blocks");
                let message_data = serde_json::to_vec(&new_block.header).unwrap_or_default();

                if let Err(e) = swarm.behaviour_mut().publish(topic, message_data) {
                    log::warn!("Failed to publish block (likely no peers): {:?}", e);
                }
            });
        }
        log::info!("Orchestration block production loop finished.");
    }
}

#[async_trait]
impl<CS, TM, ST> Container for OrchestrationContainer<CS, TM, ST>
where
    CS: CommitmentScheme + Send + Sync + 'static,
    TM: TransactionModel<CommitmentScheme = CS> + Clone + Send + Sync + 'static,
    TM::Transaction: Clone + Debug + Send + Sync,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + StateTree<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug,
    CS::Commitment: Send + Sync + Debug,
{
    fn id(&self) -> &'static str {
        "orchestration_container"
    }

    fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }

    async fn start(&self) -> Result<(), ValidatorError> {
        if self.is_running() {
            return Err(ValidatorError::AlreadyRunning(self.id().to_string()));
        }
        log::info!("OrchestrationContainer starting...");
        self.is_running.store(true, Ordering::SeqCst);
        
        let mut handles = self.task_handles.lock().await;

        let event_loop_receiver = self.shutdown_sender.subscribe();
        let swarm_clone = self.swarm.clone();
        handles.push(tokio::spawn(async move {
            Self::run_event_loop(swarm_clone, event_loop_receiver).await;
        }));

        let chain_clone = self.chain.get().unwrap().clone();
        let workload_clone = self.workload.get().unwrap().clone();
        let swarm_clone_2 = self.swarm.clone();
        let is_running_clone = self.is_running.clone();

        handles.push(tokio::spawn(async move {
            Self::run_block_production(
                chain_clone,
                workload_clone,
                swarm_clone_2,
                is_running_clone,
            )
            .await;
        }));

        Ok(())
    }

    async fn stop(&self) -> Result<(), ValidatorError> {
        if !self.is_running() {
            return Ok(());
        }
        log::info!("OrchestrationContainer stopping...");
        self.is_running.store(false, Ordering::SeqCst);
        
        self.shutdown_sender.send(true).map_err(|e| {
            ValidatorError::Other(format!("Failed to send shutdown signal: {}", e))
        })?;

        let mut handles = self.task_handles.lock().await;
        for handle in handles.drain(..) {
            handle.await.map_err(|e| ValidatorError::Other(format!("Task panicked during shutdown: {}", e)))?;
        }

        Ok(())
    }
}```

####### File: validator/src/standard/workload.rs
####*Size: 4.0K, Lines: 50, Type: ASCII text*

```rust
// Path: crates/validator/src/standard/workload.rs

use crate::traits::WorkloadLogic;
use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_core::error::ValidatorError;
use depin_sdk_core::state::{StateManager, StateTree};
use depin_sdk_core::transaction::TransactionModel;
use depin_sdk_core::validator::WorkloadContainer;

impl<ST> WorkloadLogic<ST> for WorkloadContainer<ST>
where
    // FIX: The bound must be StateManager (which implies StateTree) and Sized.
    ST: StateManager + Send + Sync,
{
    fn execute_transaction<CS, TM>(
        &self,
        tx: &TM::Transaction,
        model: &TM,
    ) -> impl std::future::Future<Output = Result<(), ValidatorError>> + Send
    where
        CS: CommitmentScheme<
            Commitment = <ST as StateTree>::Commitment,
            Proof = <ST as StateTree>::Proof,
        >,
        TM: TransactionModel<CommitmentScheme = CS> + Sync,
        TM::Transaction: Sync,
        // FIX: The bound `ST: StateManager` is now satisfied by the impl block's bounds.
        ST: StateManager,
    {
        async move {
            let state_tree_arc = self.state_tree();
            let mut state = state_tree_arc.lock().await;

            let is_valid = model
                .validate(tx, &*state)
                .map_err(|e| ValidatorError::Other(e.to_string()))?;
            if !is_valid {
                return Err(ValidatorError::Other(
                    "Transaction validation failed".to_string(),
                ));
            }

            model
                .apply(tx, &mut *state)
                .map_err(|e| ValidatorError::Other(e.to_string()))?;

            log::info!("Successfully executed transaction and updated state.");
            Ok(())
        }
    }
}```

###### Directory: validator/src/traits

####### File: validator/src/traits/mod.rs
####*Size: 4.0K, Lines: 25, Type: ASCII text*

```rust
// Path: crates/validator/src/traits/mod.rs

use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_core::error::ValidatorError;
use depin_sdk_core::state::{StateManager, StateTree};
use depin_sdk_core::transaction::TransactionModel;
use std::future::Future;

/// Defines the logic for a workload execution container.
pub trait WorkloadLogic<ST: StateTree + ?Sized> {
    /// Executes a single transaction, validating it and applying it to the state tree.
    fn execute_transaction<CS, TM>(
        &self,
        tx: &TM::Transaction,
        model: &TM,
    ) -> impl Future<Output = Result<(), ValidatorError>> + Send
    where
        CS: CommitmentScheme<
            Commitment = <ST as StateTree>::Commitment,
            Proof = <ST as StateTree>::Proof,
        >,
        // FIX: Add Sync bounds to ensure thread safety for captured references.
        TM: TransactionModel<CommitmentScheme = CS> + Sync,
        TM::Transaction: Sync,
        ST: StateManager;
}```

###### File: validator/src/config.rs
###*Size: 4.0K, Lines: 49, Type: ASCII text*

```rust
//! Configuration structures for validator containers.

use serde::Deserialize;

/// Configuration for the Guardian container (`guardian.toml`).
#[derive(Debug, Deserialize)]
pub struct GuardianConfig {
    pub signature_policy: AttestationSignaturePolicy,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum AttestationSignaturePolicy {
    FollowChain,
    Fixed,
}

/// Configuration for the Orchestration container (`orchestration.toml`).
#[derive(Debug, Deserialize)]
pub struct OrchestrationConfig {
    pub consensus_type: ConsensusType,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ConsensusType {
    ProofOfStake,
    ProofOfWork,
    ProofOfAuthority,
}

/// Configuration for the Workload container (`workload.toml`).
#[derive(Debug, Deserialize)]
pub struct WorkloadConfig {
    pub enabled_vms: Vec<String>,
}

/// Configuration for the Interface container (`interface.toml`).
#[derive(Debug, Deserialize)]
pub struct InterfaceConfig {
    pub listen_address: String,
    pub max_connections: u32,
}

/// Configuration for the API container (`api.toml`).
#[derive(Debug, Deserialize)]
pub struct ApiConfig {
    pub listen_address: String,
    pub enabled_endpoints: Vec<String>,
}```

###### File: validator/src/lib.rs
###*Size: 4.0K, Lines: 12, Type: ASCII text*

```rust
//! # DePIN SDK Validator
//!
//! Validator implementation with container architecture for the DePIN SDK.

pub mod config;
pub mod common;
pub mod standard;
pub mod hybrid;
// NEW: Public traits for this crate are defined here.
pub mod traits;

// Re-export the new public trait.
pub use traits::WorkloadLogic;```

##### File: validator/Cargo.toml
##*Size: 4.0K, Lines: 44, Type: ASCII text*

```toml
# Path: crates/validator/Cargo.toml

[package]
name = "depin-sdk-validator"
version = "0.1.0"
edition = "2021"
description = "Validator container implementations for the DePIN SDK"
license = "MIT OR Apache-2.0"

[dependencies]
depin-sdk-core = { path = "../core" }
log = { workspace = true }
anyhow = { workspace = true }
serde = { workspace = true, features = ["derive"] }
serde_json = { workspace = true }
# FIX: The `sync` feature is required for tokio::sync::watch
tokio = { workspace = true, features = ["full", "sync"] }
libp2p = { workspace = true }
futures = { workspace = true }
async-trait = { workspace = true }
toml = { workspace = true }
clap = { workspace = true, features = ["derive"], optional = true }
env_logger = { workspace = true, optional = true }
depin-sdk-state-trees = { path = "../state_trees", optional = true }
depin-sdk-commitment-schemes = { path = "../commitment_schemes", optional = true }

[features]
default = []
validator-bins = [
    "dep:clap",
    "dep:env_logger",
    "dep:depin-sdk-state-trees",
    "dep:depin-sdk-commitment-schemes",
]

[[bin]]
name = "validator"
path = "src/bin/validator.rs"
required-features = ["validator-bins"]

[[bin]]
name = "validator_hybrid"
path = "src/bin/validator_hybrid.rs"
required-features = ["validator-bins"]
```

