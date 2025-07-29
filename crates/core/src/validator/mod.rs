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
}