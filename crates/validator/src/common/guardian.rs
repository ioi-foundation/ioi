//! Implementation of the guardian container

use crate::config::GuardianConfig;
use depin_sdk_core::error::ValidatorError;
use depin_sdk_core::validator::{Container, GuardianContainer as GuardianTrait};
use std::error::Error;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Guardian container for security, boot process, and attestation
pub struct GuardianContainer {
    /// Parsed configuration for the Guardian.
    config: GuardianConfig,
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
    /// Create a new guardian container from a config file.
    pub fn new<P: AsRef<Path>>(config_path: P) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let config_str = std::fs::read_to_string(config_path.as_ref())?;
        let config: GuardianConfig = toml::from_str(&config_str)?;

        println!(
            "Guardian config loaded. Signature policy: {:?}",
            config.signature_policy
        );

        Ok(Self {
            config,
            boot_status: Arc::new(Mutex::new(BootStatus::NotStarted)),
        })
    }
    
    /// Get the current boot status
    pub fn boot_status(&self) -> BootStatus {
        *self.boot_status.lock().unwrap()
    }
}

impl Container for GuardianContainer {
    fn start(&self) -> Result<(), ValidatorError> {
        self.start_boot()
    }

    fn stop(&self) -> Result<(), ValidatorError> {
        println!("Guardian container stopped.");
        Ok(())
    }

    fn is_running(&self) -> bool {
        *self.boot_status.lock().unwrap() == BootStatus::Completed
    }

    fn id(&self) -> &str {
        "guardian"
    }
}

impl GuardianTrait for GuardianContainer {
    fn start_boot(&self) -> Result<(), ValidatorError> {
        let mut status = self.boot_status.lock().unwrap();
        *status = BootStatus::InProgress;
        println!("Guardian container starting boot process...");
        *status = BootStatus::Completed;
        println!("Guardian container boot process completed.");
        Ok(())
    }

    fn verify_attestation(&self) -> Result<bool, ValidatorError> {
        Ok(true)
    }
}