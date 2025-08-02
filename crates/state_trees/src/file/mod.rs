// Path: crates/state_trees/src/file/mod.rs
use depin_sdk_api::commitment::{CommitmentScheme, ProofContext, Selector};
use depin_sdk_api::state::{StateManager, StateTree};
use depin_sdk_types::error::StateError;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

/// A simple, file-backed state tree implementation for demonstration purposes.
#[derive(Serialize, Deserialize, Debug)]
pub struct FileStateTree<C: CommitmentScheme> {
    path: PathBuf,
    #[serde(skip, default)]
    scheme: C,
    data: HashMap<String, Vec<u8>>,
    #[serde(skip)]
    _phantom: PhantomData<C::Value>,
}

impl<C> FileStateTree<C>
where
    C: CommitmentScheme + Clone + Default,
    C::Value: From<Vec<u8>>,
{
    pub fn new<P: AsRef<Path>>(path: P, scheme: C) -> Self {
        let path_buf = path.as_ref().to_path_buf();
        Self::load(&path_buf, scheme.clone()).unwrap_or_else(|_| Self {
            path: path_buf,
            scheme,
            data: HashMap::new(),
            _phantom: PhantomData,
        })
    }

    fn load<P: AsRef<Path>>(path: P, scheme: C) -> io::Result<Self> {
        let file = File::open(path)?;
        let mut loaded: Self = serde_json::from_reader(file)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        loaded.scheme = scheme;
        Ok(loaded)
    }

    fn save(&self) -> io::Result<()> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.path)?;
        serde_json::to_writer_pretty(file, self).map_err(io::Error::other)
    }
}

impl<C> StateTree for FileStateTree<C>
where
    C: CommitmentScheme + Clone + Send + Sync + Default,
    C::Value: From<Vec<u8>>,
{
    type Commitment = <C as CommitmentScheme>::Commitment;
    type Proof = <C as CommitmentScheme>::Proof;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        let key_hex = hex::encode(key);
        Ok(self.data.get(&key_hex).cloned())
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        let key_hex = hex::encode(key);
        self.data.insert(key_hex, value.to_vec());
        self.save()
            .map_err(|e| StateError::WriteError(e.to_string()))
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        let key_hex = hex::encode(key);
        self.data.remove(&key_hex);
        self.save()
            .map_err(|e| StateError::WriteError(e.to_string()))
    }

    fn root_commitment(&self) -> Self::Commitment {
        let mut sorted_keys: Vec<_> = self.data.keys().collect();
        sorted_keys.sort();
        let values_to_commit: Vec<Option<C::Value>> = sorted_keys
            .iter()
            .map(|key| self.data.get(*key).map(|v| C::Value::from(v.clone())))
            .collect();
        self.scheme.commit(&values_to_commit)
    }

    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        let key_hex = hex::encode(key);
        let value = self.data.get(&key_hex)?;
        self.scheme
            .create_proof(&Selector::Key(key.to_vec()), &C::Value::from(value.clone()))
            .ok()
    }

    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8],
    ) -> bool {
        self.scheme.verify(
            commitment,
            proof,
            &Selector::Key(key.to_vec()),
            &C::Value::from(value.to_vec()),
            &ProofContext::default(),
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl<C> StateManager for FileStateTree<C>
where
    C: CommitmentScheme + Clone + Send + Sync + Default,
    C::Value: From<Vec<u8>> + Send + Sync,
{
    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        for (key, value) in updates {
            let key_hex = hex::encode(key);
            self.data.insert(key_hex, value.to_vec());
        }
        self.save()
            .map_err(|e| StateError::WriteError(e.to_string()))
    }

    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        let mut values = Vec::with_capacity(keys.len());
        for key in keys {
            let key_hex = hex::encode(key);
            values.push(self.data.get(&key_hex).cloned());
        }
        Ok(values)
    }
}
