// Path: crates/core/src/validator/mod.rs

use crate::{
    commitment::CommitmentScheme,
    config::WorkloadConfig,
    error::{StateError, ValidatorError},
    state::{StateManager, StateTree, VmStateAccessor},
    transaction::TransactionModel,
    vm::{ExecutionContext, VirtualMachine},
};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::fmt::{self, Debug};
use std::sync::Arc;
use tokio::sync::Mutex;

pub mod container;
pub use container::{Container, GuardianContainer};

/// Defines the capability of executing transactions against a state tree.
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

/// A container responsible for executing transactions and managing state.
pub struct WorkloadContainer<ST: StateManager> {
    _config: WorkloadConfig,
    state_tree: Arc<Mutex<ST>>,
    vm: Box<dyn VirtualMachine>, // Use a trait object for flexibility
}

// Manual Debug implementation to handle the non-Debug `vm` field and add required trait bound.
impl<ST: StateManager + Debug> Debug for WorkloadContainer<ST> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkloadContainer")
            .field("_config", &self._config)
            .field("state_tree", &self.state_tree)
            .field("vm", &"Box<dyn VirtualMachine>")
            .finish()
    }
}

/// A private wrapper to provide a dyn-safe view of the generic StateManager.
struct StateAccessorWrapper<ST: StateManager> {
    state_tree: Arc<Mutex<ST>>,
}

#[async_trait]
impl<ST: StateManager + Send + Sync> VmStateAccessor for StateAccessorWrapper<ST> {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        self.state_tree.lock().await.get(key)
    }

    async fn insert(&self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.state_tree.lock().await.insert(key, value)
    }
}

impl<ST> WorkloadContainer<ST>
where
    ST: StateManager + Send + Sync + 'static,
{
    pub fn new(config: WorkloadConfig, state_tree: ST, vm: Box<dyn VirtualMachine>) -> Self {
        Self {
            _config: config,
            state_tree: Arc::new(Mutex::new(state_tree)),
            vm,
        }
    }

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
        // Generate a deterministic contract address
        let mut hasher = Sha256::new();
        hasher.update(&sender);
        hasher.update(&code);
        let address = hasher.finalize().to_vec();

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

        // Create the dyn-safe wrapper for the VM.
        let accessor = Arc::new(StateAccessorWrapper {
            state_tree: self.state_tree.clone(),
        });

        let output = self
            .vm
            .execute(
                &code,
                "call", // Standard entrypoint
                &input_data,
                accessor,
                context,
            )
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

#[async_trait]
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
}

#[async_trait]
impl<ST> TransactionExecutor<ST> for WorkloadContainer<ST>
where
    ST: StateManager + Send + Sync + 'static,
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
        ST: StateManager,
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