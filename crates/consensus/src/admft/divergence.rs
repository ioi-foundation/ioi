// Path: crates/consensus/src/admft/divergence.rs

//! Implements the Proof of Divergence verification logic (Algorithm 2).
//!
//! A Proof of Divergence ($\pi_{div}$) is cryptographic evidence that a hardware
//! validator has equivocated (signed two different payloads for the same slot).
//! This is the trigger condition for the Protocol Apex Kill Switch.

use ioi_api::crypto::{SerializableKey, VerifyingKey};
use ioi_crypto::sign::dilithium::MldsaPublicKey;
use ioi_crypto::sign::eddsa::Ed25519PublicKey;
use ioi_types::app::{BlockHeader, ProofOfDivergence, SignatureSuite};
use ioi_types::error::ConsensusError;

/// Verifies a Proof of Divergence against the Protocol Apex rules.
///
/// Returns `Ok(true)` if the proof is valid and indicates a hardware breach.
/// Returns `Ok(false)` if the proof is structurally valid but does not prove divergence (e.g. duplicates).
/// Returns `Err` if the proof is malformed or signatures are invalid.
pub fn verify_divergence_proof(proof: &ProofOfDivergence) -> Result<bool, ConsensusError> {
    let a = &proof.evidence_a;
    let b = &proof.evidence_b;

    // 1. Identity Check
    // Both headers must be signed by the accused offender.
    if a.producer_account_id != proof.offender || b.producer_account_id != proof.offender {
        return Err(ConsensusError::BlockVerificationFailed(
            "Evidence producer does not match accused offender".into(),
        ));
    }

    // 2. Conflict Condition (Same Slot)
    // Divergence is defined as signing two different payloads for the same (height, view).
    if a.height != b.height {
        return Err(ConsensusError::BlockVerificationFailed(
            "Evidence heights do not match".into(),
        ));
    }
    if a.view != b.view {
        return Err(ConsensusError::BlockVerificationFailed(
            "Evidence views do not match".into(),
        ));
    }

    // 3. Divergence (Different Payload)
    // We must verify the payloads are actually different.
    // We check the hash of the headers (excluding signature).
    let hash_a = a
        .hash()
        .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
    let hash_b = b
        .hash()
        .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;

    if hash_a == hash_b {
        // If hashes are identical, this is just a replay, not a divergence.
        return Ok(false);
    }

    // 4. Cryptographic Authenticity
    // We must verify the signatures on both headers to prove the hardware actually signed them.
    verify_header_signature(a)?;
    verify_header_signature(b)?;

    // 5. Epoch Check (Implicit)
    // In a full implementation, we would check that the epochs match.
    // For this version, we assume the signature verification covers the epoch context.

    Ok(true)
}

/// Helper to verify the signature on a block header.
fn verify_header_signature(header: &BlockHeader) -> Result<(), ConsensusError> {
    // 1. Reconstruct the signing preimage
    let preimage = header.to_preimage_for_signing().map_err(|e| {
        ConsensusError::BlockVerificationFailed(format!("Failed to construct preimage: {}", e))
    })?;

    // 2. Hash the preimage (The Oracle signs the hash)
    let preimage_hash = ioi_crypto::algorithms::hash::sha256(&preimage).map_err(|e| {
        ConsensusError::BlockVerificationFailed(format!("Failed to hash preimage: {}", e))
    })?;

    // 3. Construct the Oracle Payload: Hash(Preimage) || Counter || Trace
    // This matches `validator/src/common/guardian.rs` logic.
    let mut oracle_payload = Vec::new();
    oracle_payload.extend_from_slice(&preimage_hash);
    oracle_payload.extend_from_slice(&header.oracle_counter.to_be_bytes());
    oracle_payload.extend_from_slice(&header.oracle_trace_hash);

    // 4. Verify Signature using helper trait
    match header.producer_key_suite {
        SignatureSuite::ED25519 => {
            let pk = Ed25519PublicKey::from_bytes(&header.producer_pubkey).map_err(|e| {
                ConsensusError::BlockVerificationFailed(format!("Invalid Ed25519 key: {}", e))
            })?;
            pk.verify_bytes(&oracle_payload, &header.signature)?;
        }
        SignatureSuite::ML_DSA_44 => {
            let pk = MldsaPublicKey::from_bytes(&header.producer_pubkey).map_err(|e| {
                ConsensusError::BlockVerificationFailed(format!("Invalid ML-DSA key: {}", e))
            })?;
            pk.verify_bytes(&oracle_payload, &header.signature)?;
        }
        // Handle other suites...
        _ => {
            return Err(ConsensusError::BlockVerificationFailed(
                "Unsupported signature suite".into(),
            ))
        }
    }

    Ok(())
}

// Helper trait to unify verification interface and handle type conversion
trait VerifyBytes {
    fn verify_bytes(&self, msg: &[u8], sig: &[u8]) -> Result<(), ConsensusError>;
}

impl VerifyBytes for Ed25519PublicKey {
    fn verify_bytes(&self, msg: &[u8], sig: &[u8]) -> Result<(), ConsensusError> {
        let signature = ioi_crypto::sign::eddsa::Ed25519Signature::from_bytes(sig)
            .map_err(|_| ConsensusError::InvalidSignature)?;
        self.verify(msg, &signature)
            .map_err(|_| ConsensusError::InvalidSignature)
    }
}

impl VerifyBytes for MldsaPublicKey {
    fn verify_bytes(&self, msg: &[u8], sig: &[u8]) -> Result<(), ConsensusError> {
        let signature = ioi_crypto::sign::dilithium::MldsaSignature::from_bytes(sig)
            .map_err(|_| ConsensusError::InvalidSignature)?;
        self.verify(msg, &signature)
            .map_err(|_| ConsensusError::InvalidSignature)
    }
}
