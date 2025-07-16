//! Sparse Merkle tree implementation

use depin_sdk_core::commitment::{CommitmentScheme, ProofContext, Selector};
use depin_sdk_core::error::StateError;
use depin_sdk_core::state::StateTree;
use std::any::Any;
use std::collections::HashMap;

/// Sparse Merkle tree implementation
pub struct SparseMerkleTree<CS: CommitmentScheme> {
    /// Data store
    data: HashMap<Vec<u8>, CS::Value>,
    /// Commitment scheme
    scheme: CS,
}

impl<CS: CommitmentScheme> SparseMerkleTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    /// Create a new sparse Merkle tree
    pub fn new(scheme: CS) -> Self {
        Self {
            data: HashMap::new(),
            scheme,
        }
    }

    /// Helper to convert raw bytes to the commitment scheme's Value type
    fn to_value(&self, bytes: &[u8]) -> CS::Value {
        CS::Value::from(bytes.to_vec())
    }
}

impl<CS: CommitmentScheme> StateTree for SparseMerkleTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    type Commitment = CS::Commitment;
    type Proof = CS::Proof;

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        let value_typed = self.to_value(value);
        self.data.insert(key.to_vec(), value_typed);
        Ok(())
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.data.get(key).map(|v| v.as_ref().to_vec()))
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        self.data.remove(key);
        Ok(())
    }

    fn root_commitment(&self) -> Self::Commitment {
        // Convert data to format expected by commitment scheme
        let values: Vec<Option<CS::Value>> = self.data.values().map(|v| Some(v.clone())).collect();
        self.scheme.commit(&values)
    }

    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        // Get the value as an Option<Vec<u8>>
        let value_result = self.get(key).ok()?;
        let value = value_result?;
        
        // Now convert value to the typed value and create the proof
        let value_typed = self.to_value(&value);

        // Use key-based selector for sparse Merkle trees
        self.scheme
            .create_proof(&Selector::Key(key.to_vec()), &value_typed)
            .ok()
    }

    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8],
    ) -> bool {
        let value_typed = self.to_value(value);

        // Create context (empty for now, could be extended with tree-specific data)
        let context = ProofContext::default();

        // Use key-based selector for verification
        self.scheme.verify(
            commitment,
            proof,
            &Selector::Key(key.to_vec()),
            &value_typed,
            &context,
        )
    }
}

// Add some utility methods for sparse Merkle trees
impl<CS: CommitmentScheme> SparseMerkleTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    /// Get the number of key-value pairs in the tree
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the tree is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get all keys in the tree
    pub fn keys(&self) -> Vec<Vec<u8>> {
        self.data.keys().cloned().collect()
    }

    /// Clear all data in the tree
    pub fn clear(&mut self) {
        self.data.clear()
    }

    /// Create a proof for multiple keys at once
    pub fn create_multi_proof(&self, keys: &[&[u8]]) -> HashMap<Vec<u8>, Option<CS::Proof>> {
        let mut proofs = HashMap::new();

        for &key in keys {
            let proof = self.create_proof(key);
            proofs.insert(key.to_vec(), proof);
        }

        proofs
    }
}