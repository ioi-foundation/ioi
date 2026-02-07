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
    // The Verification Key bytes (raw hash)
    type VerifyingKey = Vec<u8>;
    // The encoded public values (inputs/outputs) - these should be bincode serialized
    type PublicInputs = Vec<u8>;

    fn verify(
        vk: &Self::VerifyingKey,
        proof: &Self::Proof,
        public_inputs: &Self::PublicInputs,
    ) -> Result<bool, CryptoError> {
        // FIX: The VK provided is already the 32-byte canonical hash (from vk.bytes32()).
        // We simply encode it to a hex string as required by sp1-verifier.
        let vkey_hash_str = hex::encode(vk);

        // Call sp1-verifier.
        // verify(proof: &[u8], public_inputs: &[u8], vkey_hash: &str, groth16_vk: &[u8])
        Groth16Verifier::verify(proof, public_inputs, &vkey_hash_str, &GROTH16_VK_BYTES)
            .map_err(|e| CryptoError::Custom(format!("SP1 Verification Error: {}", e)))
            .map(|_| true)
    }
}
