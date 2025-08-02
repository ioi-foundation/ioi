// Path: crates/api/src/validator/mod.rs
//! Defines the core traits and structures for the validator architecture.

use crate::{
    commitment::CommitmentScheme,
    state::{StateManager, StateTree, VmStateAccessor},
    transaction::TransactionModel,
    vm::{ExecutionContext, VirtualMachine},
};
use async_trait::async_trait;
use dcrypt::algorithms::{
    hash::{sha2::Sha256 as DcryptSha256, HashFunction},
    ByteSerializable,
};
use depin_sdk_core::{config::WorkloadConfig, error::ValidatorError};
use std::fmt::{self, Debug};
use std::sync::Arc;
use tokio::sync::Mutex;

pub mod container;
pub mod types;

pub use container::{Container, GuardianContainer};
pub use types::ValidatorModel;

/// A trait for any component that can execute transactions against a state tree.
#[async_trait]
pub trait TransactionExecutor<ST: StateTree + ?Sized> {
    /// Executes a single transaction, validating it and applying it to the state tree.
    async fn execute_transaction<CS, TM>(
        &self,
        tx: &TM::Transaction,
        model: &TM,
    ) -> Result<(), ValidatorError>
    where
        CS: CommitmentScheme<
            Commitment = <ST as StateTree>::Commitment,
            Proof = <ST as StateTree>::Proof,
        >,
        TM: TransactionModel<CommitmentScheme = CS> + Sync,
        TM::Transaction: Sync,
        ST: StateManager;
}

/// A container responsible for executing transactions, smart contracts, and managing state.
pub struct WorkloadContainer<ST: StateManager> {
    _config: WorkloadConfig,
    state_tree: Arc<Mutex<ST>>,
    vm: Box<dyn VirtualMachine>,
}

impl<ST: StateManager + Debug> Debug for WorkloadContainer<ST> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkloadContainer")
            .field("_config", &self._config)
            .field("state_tree", &self.state_tree)
            .field("vm", &"Box<dyn VirtualMachine>")
            .finish()
    }
}

/// A private wrapper to provide a dyn-safe view of the generic StateManager for the VM.
struct StateAccessorWrapper<ST: StateManager> {
    state_tree: Arc<Mutex<ST>>,
}

#[async_trait]
impl<ST: StateManager + Send + Sync> VmStateAccessor for StateAccessorWrapper<ST> {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, depin_sdk_core::error::StateError> {
        self.state_tree.lock().await.get(key)
    }

    async fn insert(
        &self,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), depin_sdk_core::error::StateError> {
        self.state_tree.lock().await.insert(key, value)
    }
}

impl<ST> WorkloadContainer<ST>
where
    ST: StateManager + Send + Sync + 'static,
{
    /// Creates a new `WorkloadContainer`.
    pub fn new(config: WorkloadConfig, state_tree: ST, vm: Box<dyn VirtualMachine>) -> Self {
        Self {
            _config: config,
            state_tree: Arc::new(Mutex::new(state_tree)),
            vm,
        }
    }

    /// Returns a thread-safe handle to the state tree.
    pub fn state_tree(&self) -> Arc<Mutex<ST>> {
        self.state_tree.clone()
    }

    /// Deploys a new smart contract to the state.
    pub async fn deploy_contract(
        &self,
        code: Vec<u8>,
        sender: Vec<u8>,
    ) -> Result<Vec<u8>, ValidatorError> {
        let mut state = self.state_tree.lock().await;
        // Generate a deterministic contract address using dcrypt
        let data_to_hash = [sender, code.clone()].concat();
        let address = DcryptSha256::digest(&data_to_hash)
            .unwrap()
            .to_bytes()
            .to_vec();

        let code_key = [b"contract_code::".as_ref(), &address].concat();
        state
            .insert(&code_key, &code)
            .map_err(|e| ValidatorError::Other(e.to_string()))?;

        log::info!("Deployed contract at address: {}", hex::encode(&address));
        Ok(address)
    }

    /// Calls an existing smart contract.
    pub async fn call_contract(
        &self,
        address: Vec<u8>,
        input_data: Vec<u8>,
        context: ExecutionContext,
    ) -> Result<Vec<u8>, ValidatorError> {
        let state = self.state_tree.lock().await;
        let code_key = [b"contract_code::".as_ref(), &address].concat();
        let code = state
            .get(&code_key)
            .map_err(|e| ValidatorError::Other(e.to_string()))?
            .ok_or_else(|| ValidatorError::Other("Contract not found".to_string()))?;
        drop(state); // Drop lock before calling VM

        let accessor = Arc::new(StateAccessorWrapper {
            state_tree: self.state_tree.clone(),
        });

        let output = self
            .vm
            .execute(&code, "call", &input_data, accessor, context)
            .await
            .map_err(|e| ValidatorError::Other(format!("VM Error: {e}")))?;

        log::info!(
            "Contract call successful. Gas used: {}. Return data size: {}",
            output.gas_used,
            output.return_data.len()
        );

        Ok(output.return_data)
    }
}

// FIX: Add the `Container` implementation here.
#[async_trait]
impl<ST> Container for WorkloadContainer<ST>
where
    ST: StateManager + Send + Sync + 'static,
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
        // For simplicity, we assume it's always running once created.
        // A more complex implementation could track state.
        true
    }

    fn id(&self) -> &'static str {
        "workload_container"
    }
}

// FIX: Add the `TransactionExecutor` implementation here.
#[async_trait]
impl<ST> TransactionExecutor<ST> for WorkloadContainer<ST>
where
    ST: StateManager + StateTree + Send + Sync + 'static,
{
    async fn execute_transaction<CS, TM>(
        &self,
        tx: &TM::Transaction,
        model: &TM,
    ) -> Result<(), ValidatorError>
    where
        CS: CommitmentScheme<
            Commitment = <ST as StateTree>::Commitment,
            Proof = <ST as StateTree>::Proof,
        >,
        TM: TransactionModel<CommitmentScheme = CS> + Sync,
        TM::Transaction: Sync,
    {
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
