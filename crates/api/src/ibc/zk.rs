// Path: crates/api/src/ibc/zk.rs
use anyhow::Result;
use ioi_types::ibc::StateProofScheme;

/// A generic driver for verifying ZK proofs from different vendors (Succinct, etc.).
pub trait ZkDriver: Send + Sync {
    /// Verifies a ZK proof of an Ethereum beacon chain sync committee update.
    fn verify_beacon_update(&self, proof: &[u8], public_inputs: &[u8]) -> Result<()>;

    /// Verifies a ZK proof of a state inclusion (MPT or Verkle).
    fn verify_state_inclusion(
        &self,
        scheme: StateProofScheme,
        proof: &[u8],
        root: [u8; 32],
    ) -> Result<()>;
}
