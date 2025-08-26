// Path: crates/types/src/service_configs/mod.rs
//! Configuration structures for initial services.

use crate::app::SignatureSuite;
use serde::{Deserialize, Serialize};

/// Configuration for the IdentityHub service.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MigrationConfig {
    /// The number of blocks after a key rotation is initiated before the new key is promoted to active.
    pub grace_period_blocks: u64,
    /// If true, signatures from the new (staged) key are accepted during the grace period.
    pub accept_staged_during_grace: bool,
    /// A list of signature suites that accounts are allowed to rotate to.
    pub allowed_target_suites: Vec<SignatureSuite>,
    /// If true, allows rotating to a cryptographically weaker signature suite (e.g., from Dilithium back to Ed25519).
    pub allow_downgrade: bool,
    /// The unique identifier of the chain, used to prevent cross-chain replay attacks on rotation proofs.
    pub chain_id: u32,
}
