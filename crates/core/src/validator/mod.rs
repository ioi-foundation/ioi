// Path: crates/core/src/validator/mod.rs

use crate::{
    commitment::CommitmentScheme,
    config::WorkloadConfig,
    error::ValidatorError,
    state::{StateManager, StateTree},
    transaction::TransactionModel,
};
use std::fmt::Debug;
use std::future::Future;
use std::sync::Arc;
use tokio::sync::Mutex;

// FIX: Declare the container module so it's part of the `validator` module.
pub mod container;

// FIX: Publicly re-export the traits using a relative path.
pub use container::{Container, GuardianContainer};

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
}

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
}

// THE FIX: Move the implementation from the validator crate to the core crate.
impl<ST> WorkloadLogic<ST> for WorkloadContainer<ST>
where
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
}