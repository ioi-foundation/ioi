// Path: crates/zk-driver-succinct/src/sp1_backend.rs

#[cfg(feature = "native")]
use dcrypt::algorithms::hash::{HashFunction, Sha256};
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
    // The Verification Key bytes (raw)
    type VerifyingKey = Vec<u8>;
    // The encoded public values (inputs/outputs) - these should be bincode serialized
    type PublicInputs = Vec<u8>;

    fn verify(
        vk: &Self::VerifyingKey,
        proof: &Self::Proof,
        public_inputs: &Self::PublicInputs,
    ) -> Result<bool, CryptoError> {
        // 1. Compute the vkey hash string required by sp1-verifier.
        // The verifier expects a hex string of the SHA-256 hash of the VK bytes.
        let vk_digest = Sha256::digest(vk)
            .map_err(|e| CryptoError::OperationFailed(e.to_string()))?;
        let vkey_hash_str = hex::encode(vk_digest);

        // 2. Call sp1-verifier.
        // verify(proof: &[u8], public_inputs: &[u8], vkey_hash: &str, groth16_vk: &[u8])
        Groth16Verifier::verify(proof, public_inputs, &vkey_hash_str, &GROTH16_VK_BYTES)
            .map_err(|e| CryptoError::Custom(format!("SP1 Verification Error: {}", e)))
            .map(|_| true)
    }
}