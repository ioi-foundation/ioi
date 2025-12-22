// Path: crates/crypto/src/sign/batch.rs

use crate::error::CryptoError;
// [FIX] Updated import from DilithiumPublicKey to MldsaPublicKey
use crate::sign::dilithium::MldsaPublicKey;
use crate::sign::eddsa::Ed25519PublicKey;
use ioi_api::crypto::{BatchVerifier, SerializableKey, VerifyingKey};
use ioi_types::app::SignatureSuite;
use libp2p::identity::PublicKey as Libp2pPublicKey;
use rayon::prelude::*;

/// A CPU-based batch verifier that uses Rayon for parallelism.
#[derive(Default, Debug)]
pub struct CpuBatchVerifier;

impl CpuBatchVerifier {
    pub fn new() -> Self {
        Self
    }

    fn verify_single(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
        suite: SignatureSuite,
    ) -> bool {
        match suite {
            // [FIX] Updated constant name
            SignatureSuite::ED25519 => {
                // Try Libp2p first (protobuf encoded)
                if let Ok(pk) = Libp2pPublicKey::try_decode_protobuf(public_key) {
                    return pk.verify(message, signature);
                }
                // Try Raw Ed25519
                if let Ok(pk) = Ed25519PublicKey::from_bytes(public_key) {
                    if let Ok(sig) = crate::sign::eddsa::Ed25519Signature::from_bytes(signature) {
                        return pk.verify(message, &sig).is_ok();
                    }
                }
                false
            }
            // [FIX] Updated constant name and implementation type (Mldsa)
            SignatureSuite::ML_DSA_44 => {
                if let Ok(pk) = MldsaPublicKey::from_bytes(public_key) {
                    // [FIX] Use MldsaSignature
                    if let Ok(sig) = crate::sign::dilithium::MldsaSignature::from_bytes(signature) {
                        return pk.verify(message, &sig).is_ok();
                    }
                }
                false
            }
            // [FIX] Updated constant name
            SignatureSuite::FALCON_512 => false, // Not implemented
            // [FIX] Updated constant name
            SignatureSuite::HYBRID_ED25519_ML_DSA_44 => {
                const ED_PK_LEN: usize = 32;
                const ED_SIG_LEN: usize = 64;

                if public_key.len() < ED_PK_LEN || signature.len() < ED_SIG_LEN {
                    return false;
                }

                let (ed_pk_bytes, dil_pk_bytes) = public_key.split_at(ED_PK_LEN);
                let (ed_sig_bytes, dil_sig_bytes) = signature.split_at(ED_SIG_LEN);

                // Verify Ed25519 part
                let ed_valid = if let Ok(pk) = Ed25519PublicKey::from_bytes(ed_pk_bytes) {
                    if let Ok(sig) = crate::sign::eddsa::Ed25519Signature::from_bytes(ed_sig_bytes)
                    {
                        pk.verify(message, &sig).is_ok()
                    } else {
                        false
                    }
                } else {
                    false
                };

                if !ed_valid {
                    return false;
                }

                // Verify ML-DSA part
                // [FIX] Use MldsaPublicKey and MldsaSignature
                if let Ok(pk) = MldsaPublicKey::from_bytes(dil_pk_bytes) {
                    if let Ok(sig) =
                        crate::sign::dilithium::MldsaSignature::from_bytes(dil_sig_bytes)
                    {
                        pk.verify(message, &sig).is_ok()
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            _ => false, // Fallback for unknown IDs
        }
    }
}

impl BatchVerifier for CpuBatchVerifier {
    fn verify_batch(
        &self,
        items: &[(&[u8], &[u8], &[u8], SignatureSuite)],
    ) -> Result<Vec<bool>, CryptoError> {
        let results: Vec<bool> = items
            .par_iter()
            .map(|(pk, msg, sig, suite)| self.verify_single(pk, msg, sig, *suite))
            .collect();
        Ok(results)
    }
}
