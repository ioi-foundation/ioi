// Path: crates/validator/src/config.rs
//! Configuration structures for validator containers.

use serde::{Deserialize, Serialize};

// Re-export core config types from the central `types` crate
// to avoid circular dependencies and establish a single source of truth.
pub use ioi_types::config::{ConsensusType, OrchestrationConfig, WorkloadConfig};

/// Configuration for the Guardian container (`guardian.toml`).
#[derive(Debug, Serialize, Deserialize)]
pub struct GuardianConfig {
    /// The policy defining which signature suite to use for container attestation.
    pub signature_policy: AttestationSignaturePolicy,
}

/// The signature policy for container attestation.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum AttestationSignaturePolicy {
    /// The signature suite used for attestation should follow the active on-chain policy.
    FollowChain,
    /// The signature suite is fixed and does not change.
    Fixed,
}

/// Configuration for the Interface container (`interface.toml`).
#[derive(Debug, Serialize, Deserialize)]
pub struct InterfaceConfig {
    /// The network address and port for the public-facing interface to listen on.
    pub listen_address: String,
    /// The maximum number of concurrent connections to accept.
    pub max_connections: u32,
}

/// Configuration for the API container (`api.toml`).
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiConfig {
    /// The network address and port for the public API server to listen on.
    pub listen_address: String,
    /// A list of API endpoint identifiers that are enabled.
    pub enabled_endpoints: Vec<String>,
}
