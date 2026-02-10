// Path: crates/api/src/ibc/zk.rs
use crate::error::CoreError;
use anyhow::Result;
use ioi_types::ibc::StateProofScheme;

/// A domain-specific driver for verifying IBC-related ZK proofs.
///
/// This corresponds to the "Interoperability" layer in Blueprint 5.2.1.
/// Implementations of this trait (like `zk-driver-succinct`) will internally
/// use a concrete `ZkProofSystem` (like Groth16 or Plonk).
pub trait IbcZkVerifier: Send + Sync {
    /// Verifies a ZK proof of an Ethereum beacon chain sync committee update.
    fn verify_beacon_update(&self, proof: &[u8], public_inputs: &[u8]) -> Result<(), CoreError>;

    /// Verifies a ZK proof of a state inclusion (MPT or Verkle).
    fn verify_state_inclusion(
        &self,
        scheme: StateProofScheme,
        proof: &[u8],
        root: [u8; 32],
    ) -> Result<(), CoreError>;
}
