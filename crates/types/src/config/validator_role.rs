// Path: crates/types/src/config/validator_role.rs
use serde::{Deserialize, Serialize};

/// Defines the functional role and hardware capabilities of a validator node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "type", content = "config", rename_all = "PascalCase")]
pub enum ValidatorRole {
    /// Type A: Consensus Validator.
    /// Responsible for block ordering, ledger security, and signature verification.
    /// Hardware requirements: Consumer-grade CPU, moderate RAM.
    #[default]
    Consensus,

    /// Type B: Compute Validator.
    /// Responsible for DIM (Distributed Inference Mesh) execution and ZK proving.
    /// Hardware requirements: GPU acceleration.
    Compute {
        /// Hardware capability class (e.g., "nvidia-h100", "generic-cuda").
        accelerator_type: String,
        /// Available VRAM in bytes, used for model scheduling.
        vram_capacity: u64,
    },
}

#[cfg(test)]
#[path = "validator_role/tests.rs"]
mod tests;
