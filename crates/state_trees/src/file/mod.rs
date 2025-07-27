use depin_sdk_core::commitment::CommitmentScheme;
use depin_sdk_core::error::StateError;
use depin_sdk_core::state::{StateManager, StateTree};
use crate::HashMapStateTree;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::any::Any;
use std::sync::{Arc, RwLock};

// A serializable representation of the state, using hex strings for keys and values.
#[derive(Serialize, Deserialize, Default)]
struct SerializableState(HashMap<String, String>);

/// A state tree that persists its state to a JSON file.
/// It wraps an in-memory HashMapStateTree and adds load/save functionality.
pub struct FileStateTree<CS: CommitmentScheme + Clone>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + Clone,
{
    // The inner, in-memory state tree.
    inner: HashMapStateTree<CS>,
    // Path to the state file on disk.
    path: PathBuf,
    // We use an Arc<RwLock<()>> as a simple, cheap way to prevent saves
    // from happening concurrently, which could corrupt the file.
    save_lock: Arc<RwLock<()>>,
}

impl<CS: CommitmentScheme + Clone> FileStateTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + Clone,
{
    /// Creates a new FileStateTree.
    ///
    /// It attempts to load the initial state from the file at `path`.
    /// If the file doesn't exist, it starts with an empty state.
    pub fn new<P: AsRef<Path>>(path: P, scheme: CS) -> Self {
        let mut tree = Self {
            inner: HashMapStateTree::new(scheme),
            path: path.as_ref().to_path_buf(),
            save_lock: Arc::new(RwLock::new(())),
        };

        if let Err(e) = tree.load() {
            // Log a warning if loading fails, but don't panic.
            // This allows the node to start fresh if the state file is corrupted or unreadable.
            eprintln!("[Warning] Failed to load state from {:?}: {}. Starting with a fresh state.", tree.path, e);
        }
        tree
    }

    /// Loads the state from the JSON file.
    pub fn load(&mut self) -> Result<(), StateError> {
        if !self.path.exists() {
            println!("State file not found at {:?}, starting new state.", self.path);
            return Ok(());
        }

        let json_data = fs::read_to_string(&self.path)
            .map_err(|e| StateError::ReadError(e.to_string()))?;
            
        let serializable_map: SerializableState = serde_json::from_str(&json_data)
            .map_err(|e| StateError::ReadError(format!("JSON deserialization error: {}", e)))?;

        self.inner.data.clear();
        for (k_hex, v_hex) in serializable_map.0 {
            let k = hex::decode(&k_hex)
                .map_err(|e| StateError::InvalidKey(format!("Hex decode error: {}", e)))?;
            let v_bytes = hex::decode(&v_hex)
                .map_err(|e| StateError::InvalidValue(format!("Hex decode error: {}", e)))?;
            
            self.inner.data.insert(k, CS::Value::from(v_bytes));
        }

        println!("Successfully loaded state with {} entries from {:?}", self.inner.data.len(), self.path);
        Ok(())
    }

    /// Saves the current state to the JSON file.
    pub fn save(&self) -> Result<(), StateError> {
        // Acquire a write lock to ensure only one save operation happens at a time.
        let _lock = self.save_lock.write().unwrap();

        let mut serializable_map = SerializableState::default();
        for (k, v) in &self.inner.data {
            serializable_map.0.insert(hex::encode(k), hex::encode(v.as_ref()));
        }

        let json_data = serde_json::to_string_pretty(&serializable_map)
            .map_err(|e| StateError::WriteError(e.to_string()))?;
        
        fs::write(&self.path, json_data)
            .map_err(|e| StateError::WriteError(e.to_string()))?;

        Ok(())
    }
}

// Delegate StateTree and StateManager traits to the inner HashMapStateTree.
impl<CS: CommitmentScheme + Clone> StateTree for FileStateTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + Clone,
{
    type Commitment = CS::Commitment;
    type Proof = CS::Proof;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        StateTree::get(&self.inner, key)
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        StateTree::insert(&mut self.inner, key, value)
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        StateTree::delete(&mut self.inner, key)
    }

    fn root_commitment(&self) -> Self::Commitment {
        StateTree::root_commitment(&self.inner)
    }

    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        StateTree::create_proof(&self.inner, key)
    }

    fn verify_proof(&self, commitment: &Self::Commitment, proof: &Self::Proof, key: &[u8], value: &[u8]) -> bool {
        StateTree::verify_proof(&self.inner, commitment, proof, key, value)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl<CS: CommitmentScheme + Clone> StateManager for FileStateTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + Clone,
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

    fn verify_proof(&self, commitment: &Self::Commitment, proof: &Self::Proof, key: &[u8], value: &[u8]) -> bool {
        <Self as StateTree>::verify_proof(self, commitment, proof, key, value)
    }
}

// Automatically save the state when the FileStateTree is dropped.
// This is a safety net for graceful shutdowns.
impl<CS: CommitmentScheme + Clone> Drop for FileStateTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + Clone,
{
    fn drop(&mut self) {
        println!("Shutting down... saving final state to {:?}", self.path);
        if let Err(e) = self.save() {
            eprintln!("[Error] Failed to save state on shutdown: {}", e);
        }
    }
}