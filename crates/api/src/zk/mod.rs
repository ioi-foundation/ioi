// Path: crates/api/src/zk/mod.rs
//! Core abstractions for the Zero-Knowledge Stack (Blueprint 5.2).

use crate::error::CryptoError;
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Debug;

/// A generic trait for a ZK Proof System (Blueprint 5.2).
/// This abstracts the mathematical backend (e.g., Halo2, Groth16, Nova).
///
/// It is agnostic to the application domain (IBC, Identity, etc.).
pub trait ZkProofSystem: Send + Sync + 'static {
    /// The proof object (opaque bytes or structured).
    type Proof: Serialize + DeserializeOwned + Send + Sync + Debug;
    /// The verifying key (VK) used to verify proofs.
    type VerifyingKey: Serialize + DeserializeOwned + Send + Sync + Debug;
    /// The public inputs to the circuit.
    type PublicInputs: Serialize + DeserializeOwned + Send + Sync + Debug;

    /// Verifies a proof against a verifying key and public inputs.
    fn verify(
        vk: &Self::VerifyingKey,
        proof: &Self::Proof,
        public_inputs: &Self::PublicInputs,
    ) -> Result<bool, CryptoError>;
}

/// Marker trait for specific ZK backends (Blueprint 5.2.1).
pub trait Groth16Backend: ZkProofSystem {}
pub trait Halo2Backend: ZkProofSystem {}
pub trait Plonky2Backend: ZkProofSystem {}
