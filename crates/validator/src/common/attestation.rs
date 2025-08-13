// Path: crates/validator/src/common/attestation.rs

//! Defines the structures and logic for on-chain verifiable container attestation.
//! This protocol uses the chain's governable signature scheme.

// Note: This enum should ideally live in `depin-sdk-types`. We define it here
// for simplicity in this guide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureSuite {
    Ed25519,
    Dilithium2,
}

use serde::{Deserialize, Serialize};

/// The attestation report produced by a container in response to a challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerAttestation {
    pub container_id: String,
    pub measurement_root: Vec<u8>,
    pub nonce: Vec<u8>,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub signature_suite: SignatureSuite,
}
