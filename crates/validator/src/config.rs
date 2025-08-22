// Path: crates/validator/src/config.rs
//! Configuration structures for validator containers.

use depin_sdk_types::config::ConsensusType;
use serde::Deserialize;

/// Configuration for the Guardian container (`guardian.toml`).
#[derive(Debug, Deserialize)]
pub struct GuardianConfig {
    pub signature_policy: AttestationSignaturePolicy,
}

/// The signature policy for container attestation.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum AttestationSignaturePolicy {
    /// The signature suite used for attestation should follow the active on-chain policy.
    FollowChain,
    /// The signature suite is fixed and does not change.
    Fixed,
}

/// Configuration for the Orchestration container (`orchestration.toml`).
#[derive(Debug, Deserialize, Clone)]
pub struct OrchestrationConfig {
    pub consensus_type: ConsensusType,
    pub rpc_listen_address: String,
    #[serde(default = "default_sync_timeout_secs")]
    pub initial_sync_timeout_secs: u64,
}

fn default_sync_timeout_secs() -> u64 {
    5
}

// ConsensusType enum has been moved to `depin-sdk-types` to break a circular dependency.

/// Configuration for the Workload container (`workload.toml`).
#[derive(Debug, Deserialize)]
pub struct WorkloadConfig {
    pub enabled_vms: Vec<String>,
}

/// Configuration for the Interface container (`interface.toml`).
#[derive(Debug, Deserialize)]
pub struct InterfaceConfig {
    pub listen_address: String,
    pub max_connections: u32,
}

/// Configuration for the API container (`api.toml`).
#[derive(Debug, Deserialize)]
pub struct ApiConfig {
    pub listen_address: String,
    pub enabled_endpoints: Vec<String>,
}
