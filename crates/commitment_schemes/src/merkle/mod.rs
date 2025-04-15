//! Merkle tree commitment implementation

use std::fmt::Debug;
use sha2::{Sha256, Digest};
use depin-sdk-core::commitment::{CommitmentScheme, SchemeIdentifier};

/// Merkle tree commitment scheme
#[derive(Debug)]
pub struct MerkleCommitmentScheme;

/// Merkle tree commitment
#[derive(Debug, Clone)]
pub struct MerkleCommitment(Vec<u8>);

impl AsRef<[u8]> for MerkleCommitment {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Merkle tree proof
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// Path from leaf to root
    pub path: Vec<Vec<u8>>,
    /// Indices indicating left/right direction
    pub indices: Vec<bool>,
    /// Position of the leaf
    pub position: usize,
}

impl CommitmentScheme for MerkleCommitmentScheme {
    type Commitment = MerkleCommitment;
    type Proof = MerkleProof;

    fn commit(&self, values: &[Option<Vec<u8>>]) -> Self::Commitment {
        // Simple implementation that hashes all values
        let mut hasher = Sha256::new();
        for value in values {
            if let Some(v) = value {
                hasher.update(v);
            } else {
                hasher.update([0u8]);
            }
        }
        MerkleCommitment(hasher.finalize().to_vec())
    }

    fn create_proof(&self, position: usize, value: &[u8]) -> Result<Self::Proof, String> {
        // Simplified implementation for initial setup
        Ok(MerkleProof {
            path: vec![Sha256::digest(value).to_vec()],
            indices: vec![position % 2 == 0],
            position,
        })
    }

    fn verify(&self, commitment: &Self::Commitment, proof: &Self::Proof, position: usize, value: &[u8]) -> bool {
        // Simplified verification for initial setup
        position == proof.position && !proof.path.is_empty()
    }

    fn scheme_id() -> SchemeIdentifier {
        SchemeIdentifier::new("merkle")
    }
}
