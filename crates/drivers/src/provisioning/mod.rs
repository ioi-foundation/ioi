// Path: crates/drivers/src/provisioning/mod.rs

pub mod akash;
pub mod aws;

// Abstract interface for any cloud provider (Web2 or Web3).
use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceSpec {
    pub image: String,
    pub cpu: u32,
    pub memory_mb: u64,
    pub gpu_type: Option<String>,
    pub region: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceHandle {
    pub provider_id: String, // "aws", "akash"
    pub instance_id: String, // Provider-specific ID
    pub public_ip: Option<String>,
    pub status: InstanceStatus,
    /// Ephemeral SSH key for the session (if applicable)
    pub ssh_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstanceStatus {
    Pending,
    Running,
    Terminated,
    Failed(String),
}

/// Abstract interface for any cloud provider (Web2 or Web3).
#[async_trait]
pub trait CloudProvider: Send + Sync {
    /// Returns the provider identifier (e.g. "aws").
    fn id(&self) -> &str;

    /// Estimates cost for the given spec.
    async fn estimate_cost(&self, spec: &InstanceSpec) -> Result<f64>; // USD/hr

    /// Spins up a new instance.
    async fn provision(&self, spec: &InstanceSpec) -> Result<InstanceHandle>;

    /// Terminates an instance.
    async fn terminate(&self, instance_id: &str) -> Result<()>;

    /// Gets current status.
    async fn get_status(&self, instance_id: &str) -> Result<InstanceStatus>;
}
