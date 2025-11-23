// Path: crates/zk-driver-succinct/src/sp1_backend.rs

#[cfg(feature = "native")]
use ioi_api::error::CryptoError;
#[cfg(feature = "native")]
use ioi_api::zk::ZkProofSystem;
#[cfg(feature = "native")]
use sp1_verifier::{Groth16Verifier, GROTH16_VK_BYTES};

#[cfg(feature = "native")]
pub struct Sp1ProofSystem;

#[cfg(feature = "native")]
impl ZkProofSystem for Sp1ProofSystem {
    // SP1 Proofs are opaque byte buffers
    type Proof = Vec<u8>;
    // The Verification Key Hash (vkey) as a hex string
    type VerifyingKey = String;
    // The encoded public values (inputs/outputs)
    type PublicInputs = Vec<u8>;

    fn verify(
        vk_hash: &Self::VerifyingKey,
        proof: &Self::Proof,
        public_inputs: &Self::PublicInputs,
    ) -> Result<bool, CryptoError> {
        // sp1-verifier v5.2.3 signature:
        // verify(proof: &[u8], public_inputs: &[u8], vkey_hash: &str, groth16_vk: &[u8])

        // Pass GROTH16_VK_BYTES by reference
        Groth16Verifier::verify(proof, public_inputs, vk_hash, &GROTH16_VK_BYTES)
            .map_err(|_| CryptoError::VerificationFailed)
            .map(|_| true)
    }
}
