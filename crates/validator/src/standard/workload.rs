//! Implementation of workload container

use crate::config::WorkloadConfig;
use depin_sdk_core::error::ValidatorError;
use depin_sdk_core::validator::Container;
use std::error::Error;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Workload container for resource provisioning and execution
pub struct WorkloadContainer {
    /// Parsed configuration for the Workload container.
    config: WorkloadConfig,
    /// Running status
    running: Arc<Mutex<bool>>,
}

impl WorkloadContainer {
    /// Create a new workload container
    pub fn new<P: AsRef<Path>>(config_path: P) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let config_str = std::fs::read_to_string(config_path.as_ref())?;
        let config: WorkloadConfig = toml::from_str(&config_str)?;

        println!("Workload config loaded. Enabled VMs: {:?}", config.enabled_vms);

        Ok(Self {
            config,
            running: Arc::new(Mutex::new(false)),
        })
    }
    /// Execute a transaction
    pub fn execute_transaction(&self, tx_data: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        if !self.is_running() {
            return Err("Workload container is not running".into());
        }
        println!("Executing transaction of {} bytes", tx_data.len());
        Ok(tx_data.to_vec())
    }
    /// Check if the container is running
    pub fn is_running(&self) -> bool {
        *self.running.lock().unwrap()
    }
}

impl Container for WorkloadContainer {
    fn start(&self) -> Result<(), ValidatorError> {
        let mut running = self.running.lock().unwrap();
        *running = true;
        println!("Workload container started successfully");
        Ok(())
    }

    fn stop(&self) -> Result<(), ValidatorError> {
        let mut running = self.running.lock().unwrap();
        *running = false;
        println!("Workload container stopped successfully");
        Ok(())
    }

    fn is_running(&self) -> bool {
        self.is_running()
    }

    fn id(&self) -> &str {
        "workload"
    }
}