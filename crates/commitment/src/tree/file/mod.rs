// Path: crates/commitment/src/tree/file/mod.rs
//! File-backed state tree with Merkle tree security

use depin_sdk_api::commitment::{CommitmentScheme, CommitmentStructure, Selector};
use depin_sdk_api::state::{StateCommitment, StateManager};
use depin_sdk_crypto::algorithms::hash; // Uses dcrypt::hash::sha2 underneath
use depin_sdk_types::error::StateError;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

/// Persisted state data
#[derive(Serialize, Deserialize, Debug)]
struct PersistedState {
    data: BTreeMap<String, Vec<u8>>,
    merkle_root: Vec<u8>,
    version: u64,
}

/// A file-backed state tree implementation with Merkle tree security
#[derive(Debug)]
pub struct FileStateTree<CS: CommitmentScheme> {
    path: PathBuf,
    scheme: CS,
    state: PersistedState,
    _phantom: PhantomData<CS::Value>,
}

impl<CS> FileStateTree<CS>
where
    CS: CommitmentScheme + Clone + Default,
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    pub fn new<P: AsRef<Path>>(path: P, scheme: CS) -> Self {
        let path_buf = path.as_ref().to_path_buf();
        let state = Self::load_state(&path_buf).unwrap_or_else(|_| PersistedState {
            data: BTreeMap::new(),
            merkle_root: vec![0u8; 32],
            version: 0,
        });

        Self {
            path: path_buf,
            scheme,
            state,
            _phantom: PhantomData,
        }
    }

    fn load_state<P: AsRef<Path>>(path: P) -> io::Result<PersistedState> {
        let file = File::open(path)?;
        serde_json::from_reader(file).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    fn save_state(&self) -> io::Result<()> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.path)?;
        serde_json::to_writer_pretty(file, &self.state).map_err(io::Error::other)
    }

    fn compute_merkle_root(&self) -> Vec<u8> {
        if self.state.data.is_empty() {
            return vec![0u8; 32];
        }

        let leaves: Vec<Vec<u8>> = self
            .state
            .data
            .iter()
            .map(|(key, value)| CS::commit_leaf(key.as_bytes(), value))
            .collect();

        self.build_merkle_tree(&leaves)
    }

    fn build_merkle_tree(&self, leaves: &[Vec<u8>]) -> Vec<u8> {
        if leaves.is_empty() {
            return vec![0u8; 32];
        }
        if leaves.len() == 1 {
            return leaves[0].clone();
        }
        let mut current_level = leaves.to_vec();
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            for i in (0..current_level.len()).step_by(2) {
                let left = &current_level[i];
                let right = if i + 1 < current_level.len() {
                    &current_level[i + 1]
                } else {
                    left
                };
                next_level.push(CS::commit_branch(left, right));
            }
            current_level = next_level;
        }
        current_level[0].clone()
    }

    fn generate_merkle_proof(&self, key_hex: &str) -> Option<Vec<u8>> {
        let keys: Vec<_> = self.state.data.keys().collect();
        let index = keys.iter().position(|k| k.as_str() == key_hex)?;
        let leaves: Vec<Vec<u8>> = self
            .state
            .data
            .iter()
            .map(|(k, v)| {
                let mut data = Vec::new();
                data.push(0x00);
                data.extend_from_slice(k.as_bytes());
                data.extend_from_slice(&(v.len() as u32).to_le_bytes());
                data.extend_from_slice(v);
                hash::sha256(&data)
            })
            .collect();
        let mut siblings = Vec::new();
        let mut path = Vec::new();
        let mut current_index = index;
        let mut current_level = leaves;
        while current_level.len() > 1 {
            let is_right = current_index % 2 == 1;
            path.push(is_right);
            let sibling_index = if is_right {
                current_index - 1
            } else if current_index + 1 < current_level.len() {
                current_index + 1
            } else {
                current_index
            };
            siblings.push(current_level[sibling_index].clone());
            let mut next_level = Vec::new();
            for i in (0..current_level.len()).step_by(2) {
                let left = &current_level[i];
                let right = if i + 1 < current_level.len() {
                    &current_level[i + 1]
                } else {
                    left
                };
                let mut data = Vec::new();
                data.push(0x01);
                data.extend_from_slice(left);
                data.extend_from_slice(right);
                next_level.push(hash::sha256(&data));
            }
            current_level = next_level;
            current_index /= 2;
        }
        let mut proof_data = Vec::new();
        proof_data.extend_from_slice(&(siblings.len() as u32).to_le_bytes());
        for sibling in siblings {
            proof_data.extend_from_slice(&(sibling.len() as u32).to_le_bytes());
            proof_data.extend_from_slice(&sibling);
        }
        proof_data.extend_from_slice(&(path.len() as u32).to_le_bytes());
        for bit in path {
            proof_data.push(if bit { 1 } else { 0 });
        }
        Some(proof_data)
    }

    fn update_merkle_root(&mut self) {
        self.state.merkle_root = self.compute_merkle_root();
        self.state.version += 1;
    }

    /// **[COMPLETED]** Verify a Merkle proof against the commitment
    fn verify_merkle_proof_internal(
        root_hash: &[u8],
        key_hex: &str,
        value: &[u8],
        proof_data: &[u8],
    ) -> bool {
        let (siblings, path) = match Self::deserialize_proof(proof_data) {
            Ok(p) => p,
            Err(e) => {
                log::warn!("Failed to deserialize Merkle proof: {}", e);
                return false;
            }
        };

        let mut leaf_data = Vec::new();
        leaf_data.push(0x00);
        leaf_data.extend_from_slice(key_hex.as_bytes());
        leaf_data.extend_from_slice(&(value.len() as u32).to_le_bytes());
        leaf_data.extend_from_slice(value);
        let mut current_hash = hash::sha256(&leaf_data);

        for (i, sibling) in siblings.iter().enumerate() {
            let mut branch_data = Vec::new();
            branch_data.push(0x01);
            if path.get(i).copied().unwrap_or(false) {
                branch_data.extend_from_slice(sibling);
                branch_data.extend_from_slice(&current_hash);
            } else {
                branch_data.extend_from_slice(&current_hash);
                branch_data.extend_from_slice(sibling);
            }
            current_hash = hash::sha256(&branch_data);
        }
        current_hash == root_hash
    }

    fn deserialize_proof(proof_data: &[u8]) -> Result<(Vec<Vec<u8>>, Vec<bool>), String> {
        let mut pos = 0;
        let read_u32 = |p: &mut usize| -> Result<u32, String> {
            if *p + 4 > proof_data.len() {
                return Err("Proof data too short".to_string());
            }
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&proof_data[*p..*p + 4]);
            *p += 4;
            Ok(u32::from_le_bytes(bytes))
        };
        let num_siblings = read_u32(&mut pos)? as usize;
        let mut siblings = Vec::with_capacity(num_siblings);
        for _ in 0..num_siblings {
            let len = read_u32(&mut pos)? as usize;
            if pos + len > proof_data.len() {
                return Err("Truncated sibling data".to_string());
            }
            siblings.push(proof_data[pos..pos + len].to_vec());
            pos += len;
        }
        let path_len = read_u32(&mut pos)? as usize;
        if pos + path_len > proof_data.len() {
            return Err("Truncated path data".to_string());
        }
        let path = proof_data[pos..pos + path_len]
            .iter()
            .map(|&b| b != 0)
            .collect();
        Ok((siblings, path))
    }
}

impl<CS> StateCommitment for FileStateTree<CS>
where
    CS: CommitmentScheme + Clone + Send + Sync + Default,
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
    CS::Proof: AsRef<[u8]>, // Added this constraint to fix the compiler error
{
    type Commitment = <CS as CommitmentScheme>::Commitment;
    type Proof = <CS as CommitmentScheme>::Proof;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        let key_hex = hex::encode(key);
        Ok(self.state.data.get(&key_hex).cloned())
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        let key_hex = hex::encode(key);
        self.state.data.insert(key_hex, value.to_vec());
        self.update_merkle_root();
        self.save_state()
            .map_err(|e| StateError::WriteError(e.to_string()))
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        let key_hex = hex::encode(key);
        self.state.data.remove(&key_hex);
        self.update_merkle_root();
        self.save_state()
            .map_err(|e| StateError::WriteError(e.to_string()))
    }

    fn root_commitment(&self) -> Self::Commitment {
        let value = CS::Value::from(self.state.merkle_root.clone());
        self.scheme.commit(&[Some(value)])
    }

    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        let key_hex = hex::encode(key);
        let proof_data = self.generate_merkle_proof(&key_hex)?;
        let value = CS::Value::from(proof_data);
        self.scheme
            .create_proof(&Selector::Key(key.to_vec()), &value)
            .ok()
    }

    fn verify_proof(
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8],
    ) -> bool {
        let root_hash = commitment.as_ref();
        let proof_data = proof.as_ref(); // This line (290) was causing the error
        let key_hex = hex::encode(key);
        Self::verify_merkle_proof_internal(root_hash, &key_hex, value, proof_data)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn prefix_scan(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StateError> {
        let prefix_hex = hex::encode(prefix);
        let results = self
            .state
            .data
            .range(prefix_hex.clone()..)
            .take_while(|(key, _)| key.starts_with(&prefix_hex))
            .filter_map(|(key, value)| hex::decode(key).ok().map(|k| (k, value.clone())))
            .collect();
        Ok(results)
    }
}

impl<CS> StateManager for FileStateTree<CS>
where
    CS: CommitmentScheme + Clone + Send + Sync + Default,
    CS::Value: From<Vec<u8>> + Send + Sync + AsRef<[u8]>,
    CS::Proof: AsRef<[u8]>, // Added this constraint for consistency
{
    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        for (key, value) in updates {
            let key_hex = hex::encode(key);
            self.state.data.insert(key_hex, value.to_vec());
        }
        self.update_merkle_root();
        self.save_state()
            .map_err(|e| StateError::WriteError(e.to_string()))
    }

    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        let mut values = Vec::with_capacity(keys.len());
        for key in keys {
            let key_hex = hex::encode(key);
            values.push(self.state.data.get(&key_hex).cloned());
        }
        Ok(values)
    }
}