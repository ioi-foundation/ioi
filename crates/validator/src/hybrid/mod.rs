//! Hybrid validator implementation (5 containers)

mod interface;
mod api;

#[cfg(test)]
mod tests;

pub use interface::*;
pub use api::*;

use std::error::Error;
use std::path::Path;
use crate::common::{GuardianContainer, SecurityChannel};
use crate::standard::{OrchestrationContainer, WorkloadContainer};

/// Hybrid validator with 5 containers
pub struct HybridValidator {
    /// Guardian container
    pub guardian: GuardianContainer,
    /// Orchestration container
    pub orchestration: OrchestrationContainer,
    /// Workload container
    pub workload: WorkloadContainer,
    /// Interface container
    pub interface: InterfaceContainer,
    /// API container
    pub api: ApiContainer,
    /// Security channels between containers
    security_channels: Vec<SecurityChannel>,
}

impl HybridValidator {
    /// Create a new hybrid validator
    pub fn new<P: AsRef<Path>>(config_dir: P) -> Result<Self, Box<dyn Error>> {
        let config_dir = config_dir.as_ref();
        
        // Create containers
        let guardian = GuardianContainer::new(config_dir.join("guardian.toml"));
        let orchestration = OrchestrationContainer::new(config_dir.join("orchestration.toml"));
        let workload = WorkloadContainer::new(config_dir.join("workload.toml"));
        let interface = InterfaceContainer::new(config_dir.join("interface.toml"));
        let api = ApiContainer::new(config_dir.join("api.toml"));
        
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
        
        // Orchestration to Interface
        let channel_o_i = SecurityChannel::new("orchestration", "interface");
        channel_o_i.establish()?;
        security_channels.push(channel_o_i);
        
        // Interface to API
        let channel_i_a = SecurityChannel::new("interface", "api");
        channel_i_a.establish()?;
        security_channels.push(channel_i_a);
        
        Ok(Self {
            guardian,
            orchestration,
            workload,
            interface,
            api,
            security_channels,
        })
    }
    
    /// Start the validator
    pub fn start(&self) -> Result<(), Box<dyn Error>> {
        // Start Guardian first
        self.guardian.start_boot()?;
        
        // Start Orchestration
        self.orchestration.start()?;
        
        // Start Workload
        self.workload.start()?;
        
        // Start Interface
        self.interface.start()?;
        
        // Start API
        self.api.start()?;
        
        println!("Hybrid validator started successfully");
        
        Ok(())
    }
    
    /// Stop the validator
    pub fn stop(&self) -> Result<(), Box<dyn Error>> {
        // Stop in reverse order
        self.api.stop()?;
        self.interface.stop()?;
        self.workload.stop()?;
        self.orchestration.stop()?;
        
        println!("Hybrid validator stopped successfully");
        
        Ok(())
    }
}
