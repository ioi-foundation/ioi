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
        let cs_value = self
            .convert_value(value)
            .map_err(|e| StateError::InvalidValue(e))?;
        self.data.insert(key.to_vec(), cs_value);
        Ok(())
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.data.get(key).map(|v| self.extract_value(v)))
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        self.data.remove(key);
        Ok(())
    }

    fn root_commitment(&self) -> Self::Commitment {
        let values: Vec<Option<CS::Value>> = self.data.values().map(|v| Some(v.clone())).collect();
        self.scheme.commit(&values)
    }

    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        let value = self.data.get(key)?;
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
        if let Ok(cs_value) = self.convert_value(value) {
            let mut context = ProofContext::new();
            context.add_data(
                "branching_factor",
                self.branching_factor.to_le_bytes().to_vec(),
            );
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

// FIX: Implement the StateManager trait.
impl<CS: CommitmentScheme> StateManager for VerkleTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        for (key, value) in updates {
            self.insert(key, value)?;
        }
        Ok(())
    }

    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        let mut results = Vec::with_capacity(keys.len());
        for key in keys {
            results.push(self.get(key)?);
        }
        Ok(results)
    }
}

impl<CS: CommitmentScheme> VerkleTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    fn convert_value(&self, value: &[u8]) -> Result<CS::Value, String> {
        Ok(CS::Value::from(value.to_vec()))
    }

    fn extract_value(&self, value: &CS::Value) -> Vec<u8> {
        value.as_ref().to_vec()
    }
}