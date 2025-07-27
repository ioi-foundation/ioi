//! Verkle tree implementation

use depin_sdk_core::commitment::{CommitmentScheme, ProofContext, Selector};
use depin_sdk_core::error::StateError;
use depin_sdk_core::state::{StateManager, StateTree};
use std::any::Any;
use std::collections::HashMap;

/// Verkle tree implementation
pub struct VerkleTree<CS: CommitmentScheme> {
    /// Data store
    data: HashMap<Vec<u8>, CS::Value>,
    /// Commitment scheme
    scheme: CS,
    /// Branching factor
    branching_factor: usize,
}

impl<CS: CommitmentScheme> VerkleTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    /// Create a new Verkle tree with the specified branching factor
    pub fn new(scheme: CS, branching_factor: usize) -> Self {
        Self {
            data: HashMap::new(),
            scheme,
            branching_factor,
        }
    }

    /// Get the branching factor
    pub fn branching_factor(&self) -> usize {
        self.branching_factor
    }

    /// Get the underlying commitment scheme
    pub fn scheme(&self) -> &CS {
        &self.scheme
    }

    /// Get the number of elements stored in the tree
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the tree is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl<CS: CommitmentScheme> StateTree for VerkleTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    type Commitment = CS::Commitment;
    type Proof = CS::Proof;

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        // Convert value to the appropriate type for the commitment scheme
        let cs_value = self
            .convert_value(value)
            .map_err(|e| StateError::InvalidValue(e))?;
        self.data.insert(key.to_vec(), cs_value);
        Ok(())
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        // Convert back from CS::Value to Vec<u8>
        Ok(self.data.get(key).map(|v| self.extract_value(v)))
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
        let value = self.data.get(key)?;

        // Create a key-based proof using the new selector API
        self.scheme
            .create_proof(&Selector::Key(key.to_vec()), value)
            .ok()
    }

    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8],
    ) -> bool {
        // Convert value to the appropriate type
        if let Ok(cs_value) = self.convert_value(value) {
            // Create verification context with additional data if needed
            let mut context = ProofContext::new();

            // For Verkle trees, we might need the branching factor in the context
            context.add_data(
                "branching_factor",
                self.branching_factor.to_le_bytes().to_vec(),
            );

            // Use Key selector for verification
            self.scheme.verify(
                commitment,
                proof,
                &Selector::Key(key.to_vec()),
                &cs_value,
                &context,
            )
        } else {
            false
        }
    }

    fn as_any(&self) -> &dyn Any {
        self        
    }
}

// Helper methods to convert between Vec<u8> and CS::Value
impl<CS: CommitmentScheme> VerkleTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    /// Convert a Vec<u8> to CS::Value
    fn convert_value(&self, value: &[u8]) -> Result<CS::Value, String> {
        Ok(CS::Value::from(value.to_vec()))
    }

    /// Extract a Vec<u8> from CS::Value
    fn extract_value(&self, value: &CS::Value) -> Vec<u8> {
        value.as_ref().to_vec()
    }

    /// Create a CS::Value from bytes - implement appropriate conversion logic
    fn create_cs_value(&self, bytes: &[u8]) -> Result<CS::Value, String> {
        Ok(CS::Value::from(bytes.to_vec()))
    }
}