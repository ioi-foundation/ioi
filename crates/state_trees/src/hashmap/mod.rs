use depin_sdk_core::commitment::{CommitmentScheme, ProofContext, Selector};
use depin_sdk_core::error::StateError;
use depin_sdk_core::state::{StateManager, StateTree};
use std::any::Any;
use std::collections::HashMap;

/// HashMap-based state tree implementation
pub struct HashMapStateTree<CS: CommitmentScheme> {
    /// Data store. Made `pub(crate)` to allow the `FileStateTree` wrapper to access it.
    pub(crate) data: HashMap<Vec<u8>, CS::Value>,
    /// Commitment scheme. Made `pub(crate)` for consistency.
    pub(crate) scheme: CS,
}

impl<CS: CommitmentScheme> HashMapStateTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    /// Create a new HashMap-based state tree
    pub fn new(scheme: CS) -> Self {
        Self {
            data: HashMap::new(),
            scheme,
        }
    }

    /// Convert Vec<u8> to Value type
    fn to_value(&self, bytes: &[u8]) -> CS::Value {
        CS::Value::from(bytes.to_vec())
    }
}

impl<CS: CommitmentScheme> StateTree for HashMapStateTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    type Commitment = CS::Commitment;
    type Proof = CS::Proof;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.data.get(key).map(|v| v.as_ref().to_vec()))
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.data.insert(key.to_vec(), self.to_value(value));
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        self.data.remove(key);
        Ok(())
    }

    fn root_commitment(&self) -> Self::Commitment {
        // Keys must be sorted to ensure a deterministic commitment.
        let mut sorted_keys: Vec<_> = self.data.keys().collect();
        sorted_keys.sort();

        let values: Vec<Option<CS::Value>> = sorted_keys
            .iter()
            .map(|key| self.data.get(*key).cloned())
            .collect();
        self.scheme.commit(&values)
    }

    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        // Fixed ambiguous method call by explicitly specifying which trait's method to use
        let value = <Self as StateTree>::get(self, key)
            .ok()?
            .map(|v| self.to_value(&v))?;
        let selector = Selector::Key(key.to_vec());
        self.scheme.create_proof(&selector, &value).ok()
    }

    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8],
    ) -> bool {
        let context = ProofContext::default();
        let typed_value = self.to_value(value);
        let selector = Selector::Key(key.to_vec());

        self.scheme
            .verify(commitment, proof, &selector, &typed_value, &context)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl<CS: CommitmentScheme> StateManager for HashMapStateTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    type Commitment = CS::Commitment;
    type Proof = CS::Proof;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        <Self as StateTree>::get(self, key)
    }

    fn set(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        <Self as StateTree>::insert(self, key, value)
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        <Self as StateTree>::delete(self, key)
    }

    fn root_commitment(&self) -> Self::Commitment {
        <Self as StateTree>::root_commitment(self)
    }

    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        <Self as StateTree>::create_proof(self, key)
    }

    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8],
    ) -> bool {
        <Self as StateTree>::verify_proof(self, commitment, proof, key, value)
    }
}
