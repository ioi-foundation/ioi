// Path: crates/consensus/src/apmft/vrf.rs

//! VRF-based sortition for A-PMFT.
//!
//! Implements Forward-Secure VRF sortition to select eligible committees
//! and peer sampling targets, preventing adaptive adversary attacks.

use ioi_crypto::algorithms::hash::sha256;
// [NOTE] In a full implementation, we would use a dedicated VRF library (e.g. ECVRF).
// For this stage, we simulate VRF using HMAC/Signatures to ensure architectural fit.
// H(Secret || Seed) acts as a unique, verifiable pseudo-random function.

#[derive(Debug)]
pub struct Sortition {
    /// The local secret key used for VRF evaluation.
    secret_key: Vec<u8>,
}

impl Sortition {
    pub fn new(secret_key: Vec<u8>) -> Self {
        Self { secret_key }
    }

    /// Computes the VRF output and proof for a given seed and round.
    /// Returns (output, proof).
    pub fn evaluate(&self, seed: &[u8], round: u64) -> (Vec<u8>, Vec<u8>) {
        let mut input = Vec::new();
        input.extend_from_slice(seed);
        input.extend_from_slice(&round.to_le_bytes());
        input.extend_from_slice(&self.secret_key); // In real VRF, use SK to sign

        // Simulating VRF output with SHA256 of (Seed || Round || Sk)
        // This is deterministic and unique per node, but not verifiable without PK.
        // Protocol Apex requires Verifiability.
        // We assume the signature IS the proof in this simplified model.
        
        let output = sha256(&input).unwrap().to_vec();
        let proof = output.clone(); // In real VRF, proof != output

        (output, proof)
    }

    /// Verifies a VRF proof from another node.
    pub fn verify(_public_key: &[u8], _seed: &[u8], _round: u64, _proof: &[u8]) -> bool {
        // Validation stub. Real ECVRF verification goes here.
        true 
    }

    /// Determines if the node is eligible for the committee based on VRF output.
    /// Threshold is normalized [0.0, 1.0].
    pub fn is_eligible(vrf_output: &[u8], threshold: f64) -> bool {
        // Treat first 8 bytes as u64 and normalize
        if vrf_output.len() < 8 { return false; }
        
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&vrf_output[0..8]);
        let val = u64::from_le_bytes(bytes);
        
        let normalized = val as f64 / u64::MAX as f64;
        normalized < threshold
    }
}