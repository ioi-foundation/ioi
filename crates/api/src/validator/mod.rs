// Path: crates/api/src/validator/mod.rs
//! Defines the core traits and structures for the validator architecture.

use crate::{
    commitment::CommitmentScheme,
    services::access::ServiceDirectory,
    state::{StateCommitment, StateManager, VmStateAccessor},
    transaction::{context::TxContext, TransactionModel},
    vm::{ExecutionContext, ExecutionOutput, VirtualMachine, VmStateOverlay},
};
use async_trait::async_trait;
use dcrypt::algorithms::{
    hash::{sha2::Sha256 as DcryptSha256, HashFunction},
    ByteSerializable,
};
use depin_sdk_types::app::StateEntry;
use depin_sdk_types::{config::WorkloadConfig, error::ValidatorError};
use std::collections::HashMap;
use std::fmt::{self, Debug};
use std::sync::Arc;
use tokio::sync::Mutex;

pub mod container;
pub mod types;

pub use container::{Container, GuardianContainer};
pub use types::ValidatorModel;

/// A trait for any component that can execute transactions against a state tree.
#[async_trait]
pub trait TransactionExecutor<ST: StateCommitment + ?Sized> {
    /// Executes a single transaction, validating it and applying it to the state tree.
    async fn execute_transaction<CS, TM>(
        &self,
        tx: &TM::Transaction,
        model: &TM,
    ) -> Result<(), ValidatorError>
    where
        CS: CommitmentScheme<
            Commitment = <ST as StateCommitment>::Commitment,
            Proof = <ST as StateCommitment>::Proof,
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
    services: ServiceDirectory,
}

impl<ST: StateManager + Debug> Debug for WorkloadContainer<ST> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkloadContainer")
            .field("_config", &self._config)
            .field("state_tree", &self.state_tree)
            .field("vm", &"Box<dyn VirtualMachine>")
            .field("services", &"ServiceDirectory")
            .finish()
    }
}

/// A private wrapper to provide a dyn-safe, `Arc`-able view of a generic `StateManager`
/// for the VM. Its lifetime is managed by `Arc`, ensuring it lives as long as the VM
/// execution context that holds a reference to it.
struct StateAccessorWrapper<ST: StateManager> {
    state_tree: Arc<Mutex<ST>>,
}

#[async_trait]
impl<ST: StateManager + Send + Sync> VmStateAccessor for StateAccessorWrapper<ST> {
    /// Delegates the `get` call to the underlying state manager, handling the lock.
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, depin_sdk_types::error::StateError> {
        self.state_tree.lock().await.get(key)
    }

    /// Delegates the `insert` call to the underlying state manager, handling the lock.
    async fn insert(
        &self,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), depin_sdk_types::error::StateError> {
        self.state_tree.lock().await.insert(key, value)
    }
}

impl<ST> WorkloadContainer<ST>
where
    ST: StateManager + Send + Sync + 'static,
{
    /// Creates a new `WorkloadContainer`.
    pub fn new(
        config: WorkloadConfig,
        state_tree: ST,
        vm: Box<dyn VirtualMachine>,
        services: ServiceDirectory,
    ) -> Self {
        Self {
            _config: config,
            state_tree: Arc::new(Mutex::new(state_tree)),
            vm,
            services,
        }
    }

    /// Returns a thread-safe handle to the state tree.
    pub fn state_tree(&self) -> Arc<Mutex<ST>> {
        self.state_tree.clone()
    }

    /// Returns a read-only directory of available services.
    pub fn services(&self) -> &ServiceDirectory {
        &self.services
    }

    /// Prepares the deployment of a new smart contract.
    /// Returns the deterministic address and a map of state changes to be applied.
    pub async fn deploy_contract(
        &self,
        code: Vec<u8>,
        sender: Vec<u8>,
    ) -> Result<(Vec<u8>, HashMap<Vec<u8>, Vec<u8>>), ValidatorError> {
        let mut state_changes = HashMap::new();
        let data_to_hash = [sender, code.clone()].concat();
        let address = DcryptSha256::digest(&data_to_hash)
            .unwrap()
            .to_bytes()
            .to_vec();

        let code_key = [b"contract_code::".as_ref(), &address].concat();
        state_changes.insert(code_key, code);

        log::info!(
            "Prepared deployment for contract at address: {}",
            hex::encode(&address)
        );
        Ok((address, state_changes))
    }

    /// Executes a contract call and returns the execution output and state delta.
    /// This method is now read-only with respect to the canonical state.
    pub async fn call_contract(
        &self,
        address: Vec<u8>,
        input_data: Vec<u8>,
        mut context: ExecutionContext,
    ) -> Result<(ExecutionOutput, HashMap<Vec<u8>, Vec<u8>>), ValidatorError> {
        let code = {
            let state = self.state_tree.lock().await;
            let code_key = [b"contract_code::".as_ref(), &address].concat();
            let stored_bytes = state
                .get(&code_key)?
                .ok_or_else(|| ValidatorError::Other("Contract not found".to_string()))?;
            let stored_entry: StateEntry = serde_json::from_slice(&stored_bytes).map_err(|e| {
                ValidatorError::State(depin_sdk_types::error::StateError::InvalidValue(
                    e.to_string(),
                ))
            })?;
            stored_entry.value
        };

        context.contract_address = address.clone();

        let parent_accessor = Arc::new(StateAccessorWrapper {
            state_tree: self.state_tree.clone(),
        });
        let overlay = VmStateOverlay::new(parent_accessor);
        let overlay_arc = Arc::new(overlay);

        let output = self
            .vm
            .execute(&code, "call", &input_data, overlay_arc.clone(), context)
            .await?;

        let state_delta = Arc::try_unwrap(overlay_arc)
            .expect("Arc should have only one strong reference")
            .into_writes();

        log::info!(
            "Contract call successful. Gas used: {}. Return data size: {}. State changes: {}",
            output.gas_used,
            output.return_data.len(),
            state_delta.len()
        );

        Ok((output, state_delta))
    }

    /// Queries an existing smart contract without persisting state changes. Now truly read-only.
    pub async fn query_contract(
        &self,
        address: Vec<u8>,
        input_data: Vec<u8>,
        mut context: ExecutionContext,
    ) -> Result<ExecutionOutput, ValidatorError> {
        let code = {
            let state = self.state_tree.lock().await;
            let code_key = [b"contract_code::".as_ref(), &address].concat();
            let stored_bytes = state
                .get(&code_key)?
                .ok_or_else(|| ValidatorError::Other("Contract not found".to_string()))?;
            let stored_entry: StateEntry = serde_json::from_slice(&stored_bytes).map_err(|e| {
                ValidatorError::State(depin_sdk_types::error::StateError::InvalidValue(
                    e.to_string(),
                ))
            })?;
            stored_entry.value
        };

        context.contract_address = address.clone();

        let parent_accessor = Arc::new(StateAccessorWrapper {
            state_tree: self.state_tree.clone(),
        });
        let overlay = VmStateOverlay::new(parent_accessor);

        let output = self
            .vm
            .execute(&code, "call", &input_data, Arc::new(overlay), context)
            .await?;

        Ok(output)
    }
}

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
        true
    }

    fn id(&self) -> &'static str {
        "workload_container"
    }
}

#[async_trait]
impl<ST> TransactionExecutor<ST> for WorkloadContainer<ST>
where
    ST: StateManager + StateCommitment + Send + Sync + 'static,
{
    async fn execute_transaction<CS, TM>(
        &self,
        tx: &TM::Transaction,
        model: &TM,
    ) -> Result<(), ValidatorError>
    where
        CS: CommitmentScheme<
            Commitment = <ST as StateCommitment>::Commitment,
            Proof = <ST as StateCommitment>::Proof,
        >,
        TM: TransactionModel<CommitmentScheme = CS> + Sync,
        TM::Transaction: Sync,
    {
        model
            .validate_stateless(tx)
            .map_err(|e| ValidatorError::Other(e.to_string()))?;

        // A minimal context for the now-legacy executor trait.
        let ctx = TxContext {
            block_height: 0, // Height is not known in this context
            chain_id: 1,     // Placeholder
            services: self.services(),
        };

        model
            .apply_payload(tx, self, ctx)
            .await
            .map_err(|e| ValidatorError::Other(e.to_string()))?;

        log::info!("Successfully executed transaction and updated state.");
        Ok(())
    }
}
