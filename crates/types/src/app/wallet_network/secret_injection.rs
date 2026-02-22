// Path: crates/types/src/app/wallet_network/secret_injection.rs

use crate::app::action::ActionTarget;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// Guardian attestation evidence supplied during secret release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct GuardianAttestation {
    /// Hash of runtime quote/certificate chain.
    pub quote_hash: [u8; 32],
    /// Runtime measurement hash.
    pub measurement_hash: [u8; 32],
    /// Ephemeral encryption key of guardian.
    pub guardian_ephemeral_public_key: Vec<u8>,
    /// Challenge nonce bound to the secret injection request.
    pub nonce: [u8; 32],
    /// Issued timestamp.
    pub issued_at_ms: u64,
    /// Expiration timestamp.
    pub expires_at_ms: u64,
}

/// Request to release a secret into an attested runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SecretInjectionRequest {
    /// Deterministic request id.
    pub request_id: [u8; 32],
    /// Session receiving secret material.
    pub session_id: [u8; 32],
    /// Logical agent id.
    pub agent_id: String,
    /// Alias of secret requested.
    pub secret_alias: String,
    /// Action target/context requiring this secret.
    pub target: ActionTarget,
    /// Challenge nonce for attestation binding.
    pub attestation_nonce: [u8; 32],
    /// Requested timestamp.
    pub requested_at_ms: u64,
}

/// Secret injection request bundle with attestation evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SecretInjectionRequestRecord {
    /// Requested secret handoff context.
    pub request: SecretInjectionRequest,
    /// Guardian attestation bound to the request nonce/challenge.
    pub attestation: GuardianAttestation,
}

/// Sealed secret payload encrypted for a specific guardian runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SecretInjectionEnvelope {
    /// Encryption scheme used for the sealed payload.
    pub algorithm: String,
    /// Ciphertext encrypted to guardian ephemeral key.
    pub ciphertext: Vec<u8>,
    /// Optional AAD/metadata bytes.
    #[serde(default)]
    pub aad: Vec<u8>,
}

/// Granted secret handoff material bound to request + attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SecretInjectionGrant {
    /// Request id being fulfilled.
    pub request_id: [u8; 32],
    /// Secret id released.
    pub secret_id: String,
    /// Sealed payload for guardian.
    pub envelope: SecretInjectionEnvelope,
    /// Issued timestamp.
    pub issued_at_ms: u64,
    /// Expiration timestamp.
    pub expires_at_ms: u64,
}
