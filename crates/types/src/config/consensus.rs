// Path: crates/types/src/config/consensus.rs
//! Configuration related to consensus engines.

use serde::{Deserialize, Serialize};

/// The type of consensus engine to use.
/// This enum lives in `ioi-types` to avoid a circular dependency
/// between the `validator` crate (which reads it from config) and the
/// `consensus` crate (which uses it to dispatch logic).
// --- FIX START: Add Copy trait ---
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
// --- FIX END ---
#[serde(rename_all = "PascalCase")]
pub enum ConsensusType {
    /// Proof of Stake consensus.
    ProofOfStake,
    /// Proof of Authority consensus.
    ProofOfAuthority,
    /// Aft Fault Tolerance consensus family.
    Aft,
}

/// Safety mode for the Aft Fault Tolerance consensus family.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AftSafetyMode {
    /// Classic BFT assumptions and thresholds.
    #[default]
    ClassicBft,
    /// Majority-safety mode under guardianized non-equivocation assumptions.
    GuardianMajority,
    /// Majority fast path with asynchronous asymptote sealing for stronger settlement.
    Asymptote,
    /// Experimental nested-witness mode for research-only deployments.
    /// This mode must be explicitly enabled in config before the node will start.
    ExperimentalNestedGuardian,
}
