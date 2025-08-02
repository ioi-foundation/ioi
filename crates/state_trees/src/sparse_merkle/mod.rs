// Path: crates/state_trees/src/sparse_merkle/mod.rs
//! Sparse Merkle tree implementation

use depin_sdk_api::commitment::{CommitmentScheme, ProofContext, Selector};
use depin_sdk_api::state::{StateManager, StateTree};
use depin_sdk_core::error::StateError;
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

    fn to_value(&self, bytes: &[u8]) -> CS::Value {
        CS::Value::from(bytes.to_vec())
    }
}

impl<CS: CommitmentScheme> StateTree for SparseMerkleTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    type Commitment = <CS as CommitmentScheme>::Commitment;
    type Proof = <CS as CommitmentScheme>::Proof;

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
        let values: Vec<Option<CS::Value>> = self.data.values().map(|v| Some(v.clone())).collect();
        self.scheme.commit(&values)
    }

    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        let value_result = self.get(key).ok()?;
        let value = value_result?;
        let value_typed = self.to_value(&value);
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
        let context = ProofContext::default();
        self.scheme.verify(
            commitment,
            proof,
            &Selector::Key(key.to_vec()),
            &value_typed,
            &context,
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl<CS: CommitmentScheme> StateManager for SparseMerkleTree<CS>
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
