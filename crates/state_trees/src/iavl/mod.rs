// Path: crates/state_trees/src/iavl/mod.rs
//! IAVL tree implementation

use depin_sdk_api::commitment::{CommitmentScheme, ProofContext, Selector};
use depin_sdk_api::state::{StateManager, StateTree};
use depin_sdk_core::error::StateError;
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
    type Commitment = <CS as CommitmentScheme>::Commitment;
    type Proof = <CS as CommitmentScheme>::Proof;

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
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
        let values: Vec<Option<CS::Value>> = self.data.values().map(|v| Some(v.clone())).collect();
        self.scheme.commit(&values)
    }

    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        let value = self.data.get(key)?;
        let selector = Selector::Key(key.to_vec());
        self.scheme.create_proof(&selector, value).ok()
    }

    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8],
    ) -> bool {
        let selector = Selector::Key(key.to_vec());
        let context = ProofContext::default();
        let scheme_value = self.to_value(value);
        self.scheme
            .verify(commitment, proof, &selector, &scheme_value, &context)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl<CS: CommitmentScheme> StateManager for IAVLTree<CS>
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