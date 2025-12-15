// Path: crates/crypto/src/sign/batch.rs

use crate::error::CryptoError;
use crate::sign::dilithium::DilithiumPublicKey;
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
            SignatureSuite::Ed25519 => {
                // Try Libp2p first (protobuf encoded)
                if let Ok(pk) = Libp2pPublicKey::try_decode_protobuf(public_key) {
                    return pk.verify(message, signature);
                }
                // Try Raw Ed25519
                if let Ok(pk) = Ed25519PublicKey::from_bytes(public_key) {
                    if let Ok(sig) =
                        crate::sign::eddsa::Ed25519Signature::from_bytes(signature)
                    {
                        return pk.verify(message, &sig).is_ok();
                    }
                }
                false
            }
            SignatureSuite::Dilithium2 => {
                if let Ok(pk) = DilithiumPublicKey::from_bytes(public_key) {
                    if let Ok(sig) =
                        crate::sign::dilithium::DilithiumSignature::from_bytes(signature)
                    {
                        return pk.verify(message, &sig).is_ok();
                    }
                }
                false
            }
            SignatureSuite::Falcon512 => false, // Not implemented
            SignatureSuite::HybridEd25519Dilithium2 => {
                const ED_PK_LEN: usize = 32;
                const ED_SIG_LEN: usize = 64;

                if public_key.len() < ED_PK_LEN || signature.len() < ED_SIG_LEN {
                    return false;
                }

                let (ed_pk_bytes, dil_pk_bytes) = public_key.split_at(ED_PK_LEN);
                let (ed_sig_bytes, dil_sig_bytes) = signature.split_at(ED_SIG_LEN);

                // Verify Ed25519 part
                let ed_valid = if let Ok(pk) = Ed25519PublicKey::from_bytes(ed_pk_bytes) {
                    if let Ok(sig) = crate::sign::eddsa::Ed25519Signature::from_bytes(ed_sig_bytes) {
                        pk.verify(message, &sig).is_ok()
                    } else { false }
                } else { false };

                if !ed_valid { return false; }

                // Verify Dilithium part
                if let Ok(pk) = DilithiumPublicKey::from_bytes(dil_pk_bytes) {
                     if let Ok(sig) = crate::sign::dilithium::DilithiumSignature::from_bytes(dil_sig_bytes) {
                        pk.verify(message, &sig).is_ok()
                    } else { false }
                } else { false }
            }
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