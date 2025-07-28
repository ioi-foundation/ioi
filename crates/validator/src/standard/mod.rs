//! Standard validator implementation (3 containers)

mod orchestration;
mod workload;

#[cfg(test)]
mod tests;

pub use orchestration::*;
pub use workload::*;
use depin_sdk_core::error::ValidatorError;
use depin_sdk_core::validator::{Container, ValidatorModel, ValidatorType};
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
    pub fn new<P: AsRef<Path>>(config_dir: P) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let config_dir = config_dir.as_ref();
        
        // Create containers
        let guardian = GuardianContainer::new(config_dir.join("guardian.toml"))?;
        let orchestration = OrchestrationContainer::new(config_dir.join("orchestration.toml"))?;
        let workload = WorkloadContainer::new(config_dir.join("workload.toml"))?;
        
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
}

impl ValidatorModel for StandardValidator {
    fn start(&self) -> Result<(), ValidatorError> {
        // Start Guardian first
        self.guardian.start()?;

        // Start Orchestration
        self.orchestration.start()?;

        // Start Workload
        self.workload.start()?;

        println!("Standard validator started successfully");
        Ok(())
    }

    fn stop(&self) -> Result<(), ValidatorError> {
        // Stop in reverse order
        self.workload.stop()?;
        self.orchestration.stop()?;
        self.guardian.stop()?;

        println!("Standard validator stopped successfully");
        Ok(())
    }

    fn is_running(&self) -> bool {
        self.guardian.is_running() && self.orchestration.is_running() && self.workload.is_running()
    }

    fn validator_type(&self) -> ValidatorType {
        ValidatorType::Standard
    }
}