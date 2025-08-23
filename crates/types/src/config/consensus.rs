// Path: crates/types/src/config/consensus.rs
//! Configuration related to consensus engines.

use serde::{Deserialize, Serialize}; // <-- Add Serialize here

/// The type of consensus engine to use.
/// This enum lives in `depin-sdk-types` to avoid a circular dependency
/// between the `validator` crate (which reads it from config) and the
/// `consensus` crate (which uses it to dispatch logic).
#[derive(Debug, Serialize, Deserialize, Clone)] // <-- Add Serialize
#[serde(rename_all = "PascalCase")]
pub enum ConsensusType {
    /// Proof of Stake consensus.
    ProofOfStake,
    /// Proof of Authority consensus.
    ProofOfAuthority,
}
