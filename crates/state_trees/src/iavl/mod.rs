//! IAVL tree implementation

use depin_sdk_core::commitment::{CommitmentScheme, ProofContext, Selector};
use depin_sdk_core::error::StateError;
use depin_sdk_core::state::{StateManager, StateTree};
use std::any::Any;
use std::collections::HashMap;

/// IAVL tree implementation
pub struct IAVLTree<CS: CommitmentScheme> {
    /// Data store
    data: HashMap<Vec<u8>, CS::Value>,
    /// Commitment scheme
    scheme: CS,
}

impl<CS: CommitmentScheme> IAVLTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    /// Create a new IAVL tree
    pub fn new(scheme: CS) -> Self {
        Self {
            data: HashMap::new(),
            scheme,
        }
    }

    /// Get the underlying commitment scheme
    pub fn scheme(&self) -> &CS {
        &self.scheme
    }

    /// Convert a raw byte value to the commitment scheme's value type
    fn to_value(&self, value: &[u8]) -> CS::Value {
        CS::Value::from(value.to_vec())
    }
}

impl<CS: CommitmentScheme> StateTree for IAVLTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    type Commitment = CS::Commitment;
    type Proof = CS::Proof;

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        // Convert to the appropriate value type for this commitment scheme
        let scheme_value = self.to_value(value);
        self.data.insert(key.to_vec(), scheme_value);
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
        let value = self.data.get(key)?;

        // Create a key-based selector for the proof
        let selector = Selector::Key(key.to_vec());

        // Create the proof using the selector
        self.scheme.create_proof(&selector, value).ok()
    }

    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8],
    ) -> bool {
        // Create a key-based selector for verification
        let selector = Selector::Key(key.to_vec());

        // Create an empty context for now
        let context = ProofContext::default();

        // Convert the raw value to the scheme's value type
        let scheme_value = self.to_value(value);

        // Verify the proof using the selector and context
        self.scheme
            .verify(commitment, proof, &selector, &scheme_value, &context)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// Add support for tree-specific operations for IAVL
impl<CS: CommitmentScheme> IAVLTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    /// Get the height of the tree
    pub fn height(&self) -> usize {
        // This would be a real implementation in a complete IAVL tree
        // For now, we just return a placeholder value
        let size = self.data.len();
        if size == 0 {
            0
        } else {
            (size as f64).log2().ceil() as usize
        }
    }

    /// Get the number of nodes in the tree
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Check if the tree is balanced
    pub fn is_balanced(&self) -> bool {
        // This would be a real implementation in a complete IAVL tree
        // For now, we just return true
        true
    }

    /// Create a proof with additional path information
    pub fn create_path_proof(&self, key: &[u8]) -> Option<(CS::Proof, Vec<Vec<u8>>)> {
        // This would create a proof with the complete path from root to leaf
        let value = self.data.get(key)?;

        // Create a key-based selector
        let selector = Selector::Key(key.to_vec());

        // Create the proof
        let proof = self.scheme.create_proof(&selector, value).ok()?;

        // In a real implementation, we would compute the path
        // For now, we just return an empty path
        let path = Vec::new();

        Some((proof, path))
    }
}