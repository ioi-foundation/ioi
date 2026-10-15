// Path: crates/consensus/src/aft_evidence.rs
//! Self-contained verification of a block header's post-signing evidence: the producer's header
//! signature and a sealed finality proof's producer signature and bindings. The checks need nothing
//! but the header: the expected signer is the header's own `producer_pubkey`, which lies inside the
//! identity preimage.
//!
//! ONE implementation, shared (FU-N11-DURABLE-STATUS-1 D2a round 2): the AFT engine
//! (`aft::guardian_majority`) verifies proposals with it, and the workload's admission-floor fence
//! verifies post-admission evidence updates with it. The module is compiled whatever the consensus
//! features (it is not behind `aft`), because the workload links this crate without them.
//! `verify_guardian_signature` and `verify_sealed_finality_proof_signature` were moved here
//! unchanged from `aft/guardian_majority/mod.rs`, and
//! `verify_sealed_finality_proof_certificate_binding` from the engine's
//! `verify_asymptote_sealed_finality` (`aft/guardian_majority/collapse_verification.rs`).
//!
//! NOT here: the full sealed-finality verification (witness and observer certificates against the
//! epoch's committee, policy and witness seed). It reads chain state and stays the engine's
//! `verify_asymptote_sealed_finality`.

use ioi_api::crypto::{SerializableKey, VerifyingKey};
use ioi_crypto::sign::dilithium::{MldsaPublicKey, MldsaSignature};
use ioi_types::app::{
    canonical_sealed_finality_proof_signing_bytes, BlockHeader, GuardianQuorumCertificate,
    SealedFinalityProof,
};
use ioi_types::error::ConsensusError;
use libp2p::identity::PublicKey;
use tracing::warn;

/// Verifies the block producer's signature against the Oracle-anchored extended payload.
pub fn verify_guardian_signature(
    preimage: &[u8],
    suite: ioi_types::app::SignatureSuite,
    public_key: &[u8],
    signature: &[u8],
    oracle_counter: u64,
    oracle_trace: &[u8; 32],
) -> Result<(), ConsensusError> {
    let header_hash = ioi_crypto::algorithms::hash::sha256(preimage).map_err(|e| {
        warn!("Failed to hash header preimage: {}", e);
        ConsensusError::InvalidSignature
    })?;

    let mut signed_payload = Vec::with_capacity(32 + 8 + 32);
    signed_payload.extend_from_slice(&header_hash);
    signed_payload.extend_from_slice(&oracle_counter.to_be_bytes());
    signed_payload.extend_from_slice(oracle_trace);

    match suite {
        ioi_types::app::SignatureSuite::ED25519 => {
            let pk = PublicKey::try_decode_protobuf(public_key)
                .map_err(|_| ConsensusError::InvalidSignature)?;
            pk.verify(&signed_payload, signature)
                .then_some(())
                .ok_or(ConsensusError::InvalidSignature)
        }
        ioi_types::app::SignatureSuite::ML_DSA_44 => {
            if public_key.len() != 1312 {
                return Err(ConsensusError::InvalidSignature);
            }
            let pk = MldsaPublicKey::from_bytes(public_key)
                .map_err(|_| ConsensusError::InvalidSignature)?;
            let signature = MldsaSignature::from_bytes(signature)
                .map_err(|_| ConsensusError::InvalidSignature)?;
            pk.verify(&signed_payload, &signature)
                .map_err(|_| ConsensusError::InvalidSignature)
        }
        _ => Err(ConsensusError::InvalidSignature),
    }
}

/// Verifies a sealed finality proof's producer signature: the proof is signed, over its canonical
/// signing bytes, by the block's own producer key and suite.
pub fn verify_sealed_finality_proof_signature(
    header: &BlockHeader,
    proof: &SealedFinalityProof,
) -> Result<(), ConsensusError> {
    if proof.proof_signature.public_key.is_empty() || proof.proof_signature.signature.is_empty() {
        return Err(ConsensusError::BlockVerificationFailed(
            "sealed finality proof is missing its producer signature".into(),
        ));
    }
    if proof.proof_signature.public_key != header.producer_pubkey {
        return Err(ConsensusError::BlockVerificationFailed(
            "sealed finality proof signer does not match the block producer".into(),
        ));
    }
    if proof.proof_signature.suite != header.producer_key_suite {
        return Err(ConsensusError::BlockVerificationFailed(
            "sealed finality proof signer suite does not match the block producer".into(),
        ));
    }
    let sign_bytes = canonical_sealed_finality_proof_signing_bytes(proof)
        .map_err(ConsensusError::BlockVerificationFailed)?;
    let valid = match header.producer_key_suite {
        ioi_types::app::SignatureSuite::ED25519 => {
            PublicKey::try_decode_protobuf(&proof.proof_signature.public_key)
                .map(|key| key.verify(&sign_bytes, &proof.proof_signature.signature))
                .unwrap_or(false)
        }
        ioi_types::app::SignatureSuite::ML_DSA_44 => {
            if proof.proof_signature.public_key.len() != 1312 {
                false
            } else {
                MldsaPublicKey::from_bytes(&proof.proof_signature.public_key)
                    .and_then(|key| {
                        MldsaSignature::from_bytes(&proof.proof_signature.signature)
                            .and_then(|signature| key.verify(&sign_bytes, &signature))
                    })
                    .is_ok()
            }
        }
        _ => false,
    };
    if !valid {
        return Err(ConsensusError::BlockVerificationFailed(
            "sealed finality proof producer signature is invalid or uses an unsupported suite"
                .into(),
        ));
    }
    Ok(())
}

/// Verifies that a sealed finality proof is bound to the guardian certificate of the slot it seals.
pub fn verify_sealed_finality_proof_certificate_binding(
    proof: &SealedFinalityProof,
    certificate: &GuardianQuorumCertificate,
) -> Result<(), ConsensusError> {
    if proof.guardian_manifest_hash != certificate.manifest_hash
        || proof.guardian_decision_hash != certificate.decision_hash
        || proof.guardian_counter != certificate.counter
        || proof.guardian_trace_hash != certificate.trace_hash
        || proof.guardian_measurement_root != certificate.measurement_root
    {
        return Err(ConsensusError::BlockVerificationFailed(
            "sealed finality proof is not bound to the guardian certificate".into(),
        ));
    }
    Ok(())
}

/// Verifies `header.signature`: the producer's signature over the identity preimage, the oracle
/// counter and the oracle trace (the engine's proposal check, `verify_guardian_signature`).
pub fn verify_block_header_signature(header: &BlockHeader) -> Result<(), ConsensusError> {
    let preimage = header
        .to_preimage_for_signing()
        .map_err(|e| ConsensusError::BlockVerificationFailed(e.to_string()))?;
    verify_guardian_signature(
        &preimage,
        header.producer_key_suite,
        &header.producer_pubkey,
        &header.signature,
        header.oracle_counter,
        &header.oracle_trace_hash,
    )
}

/// Verifies that `proof` is a sealed finality proof FOR the block `header` names, as far as the
/// header alone decides: the block's producer signed it (`verify_sealed_finality_proof_signature`),
/// it is bound to the block's guardian certificate when the block carries one
/// (`verify_sealed_finality_proof_certificate_binding`), and it is bound to the block's oracle
/// counter and trace. (The engine requires the certificate's counter and trace to equal the
/// header's oracle counter and trace, so a valid proof always satisfies the last binding.)
pub fn verify_sealed_finality_proof_for_block(
    header: &BlockHeader,
    proof: &SealedFinalityProof,
) -> Result<(), ConsensusError> {
    verify_sealed_finality_proof_signature(header, proof)?;
    if let Some(certificate) = header.guardian_certificate.as_ref() {
        verify_sealed_finality_proof_certificate_binding(proof, certificate)?;
    }
    if proof.guardian_counter != header.oracle_counter
        || proof.guardian_trace_hash != header.oracle_trace_hash
    {
        return Err(ConsensusError::BlockVerificationFailed(
            "sealed finality proof is not bound to the block's oracle counter and trace".into(),
        ));
    }
    Ok(())
}
