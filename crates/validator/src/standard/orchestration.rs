//! Implementation of orchestration container

use crate::config::OrchestrationConfig;
use depin_sdk_core::error::ValidatorError;
use depin_sdk_core::validator::Container;
use std::error::Error;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Orchestration container for node functions and consensus
pub struct OrchestrationContainer {
    /// Parsed configuration for the Orchestration container.
    config: OrchestrationConfig,
    /// Running status
    running: Arc<Mutex<bool>>,
}

impl OrchestrationContainer {
    /// Create a new orchestration container
    pub fn new<P: AsRef<Path>>(config_path: P) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let config_str = std::fs::read_to_string(config_path.as_ref())?;
        let config: OrchestrationConfig = toml::from_str(&config_str)?;

        println!("Orchestration config loaded. Consensus type: {:?}", config.consensus_type);

        Ok(Self {
            config,
            running: Arc::new(Mutex::new(false)),
        })
    }

    /// Check if the container is running
    pub fn is_running(&self) -> bool {
        *self.running.lock().unwrap()
    }
}

impl Container for OrchestrationContainer {
    fn start(&self) -> Result<(), ValidatorError> {
        let mut running = self.running.lock().unwrap();
        *running = true;
        println!("Orchestration container started successfully");
        Ok(())
    }

    fn stop(&self) -> Result<(), ValidatorError> {
        let mut running = self.running.lock().unwrap();
        *running = false;
        println!("Orchestration container stopped successfully");
        Ok(())
    }

    fn is_running(&self) -> bool {
        self.is_running()
    }

    fn id(&self) -> &str {
        "orchestration"
    }
}