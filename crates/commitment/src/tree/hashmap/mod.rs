// Path: crates/commitment/src/trees/hashmap/mod.rs
use depin_sdk_api::commitment::{CommitmentScheme, ProofContext, Selector};
use depin_sdk_api::state::{StateCommitment, StateManager};
use depin_sdk_types::error::StateError;
use std::any::Any;
use std::collections::HashMap;

/// HashMap-based state tree implementation
#[derive(Debug)]
pub struct HashMapStateTree<CS: CommitmentScheme> {
    /// Data store.
    pub(crate) data: HashMap<Vec<u8>, CS::Value>,
    /// Commitment scheme.
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

impl<CS: CommitmentScheme + Default> StateCommitment for HashMapStateTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    type Commitment = <CS as CommitmentScheme>::Commitment;
    type Proof = <CS as CommitmentScheme>::Proof;

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
        let mut sorted_keys: Vec<_> = self.data.keys().collect();
        sorted_keys.sort();

        let values: Vec<Option<CS::Value>> = sorted_keys
            .iter()
            .map(|key| self.data.get(*key).cloned())
            .collect();
        self.scheme.commit(&values)
    }

    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        let value = self.get(key).ok()?.map(|v| self.to_value(&v))?;
        let selector = Selector::Key(key.to_vec());
        self.scheme.create_proof(&selector, &value).ok()
    }

    fn verify_proof(
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8],
    ) -> bool {
        let context = ProofContext::default();
        let typed_value = CS::Value::from(value.to_vec());
        let selector = Selector::Key(key.to_vec());

        CS::default().verify(commitment, proof, &selector, &typed_value, &context)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl<CS: CommitmentScheme + Default> StateManager for HashMapStateTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        for (key, value) in updates {
            let value_typed = self.to_value(value);
            self.data.insert(key.to_vec(), value_typed);
        }
        Ok(())
    }

    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        let mut values = Vec::with_capacity(keys.len());
        for key in keys {
            values.push(self.data.get(key).map(|v| v.as_ref().to_vec()));
        }
        Ok(values)
    }
}
