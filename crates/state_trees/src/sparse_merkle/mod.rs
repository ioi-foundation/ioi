//! Sparse Merkle tree implementation

use std::collections::HashMap;
use std::any::Any;
use depin-sdk-core::state::StateTree;
use depin-sdk-commitment_schemes::merkle::{MerkleCommitmentScheme, MerkleCommitment, MerkleProof};

/// Sparse Merkle tree implementation
pub struct SparseMerkleTree {
    /// Data store
    data: HashMap<Vec<u8>, Vec<u8>>,
    /// Commitment scheme
    scheme: MerkleCommitmentScheme,
}

impl SparseMerkleTree {
    /// Create a new sparse Merkle tree
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
            scheme: MerkleCommitmentScheme,
        }
    }
}

impl StateTree for SparseMerkleTree {
    type Commitment = MerkleCommitment;
    type Proof = MerkleProof;

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), String> {
        self.data.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.data.get(key).cloned()
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), String> {
        self.data.remove(key);
        Ok(())
    }

    fn root_commitment(&self) -> Self::Commitment {
        // Convert data to format expected by commitment scheme
        let values: Vec<Option<Vec<u8>>> = self.data
            .values()
            .map(|v| Some(v.clone()))
            .collect();
        
        self.scheme.commit(&values)
    }

    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        let value = self.get(key)?;
        self.scheme.create_proof(0, &value).ok()
    }

    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        _key: &[u8],
        value: &[u8],
    ) -> bool {
        self.scheme.verify(commitment, proof, proof.position, value)
    }

    fn commitment_scheme(&self) -> &dyn Any {
        &self.scheme
    }
}
