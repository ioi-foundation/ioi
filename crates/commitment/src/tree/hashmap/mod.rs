// Path: crates/commitment/src/tree/hashmap/mod.rs
//! HashMap-based state tree implementation with Merkle tree security

pub mod verifier;

use depin_sdk_api::commitment::{CommitmentScheme, Selector};
use depin_sdk_api::state::{StateCommitment, StateManager};
use depin_sdk_types::app::Membership;
use depin_sdk_types::error::StateError;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::BTreeMap;

/// Merkle tree proof for HashMap implementation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub siblings: Vec<Vec<u8>>,
    pub path: Vec<bool>,
}

/// HashMap-based state tree implementation with Merkle tree
#[derive(Debug, Clone)]
pub struct HashMapStateTree<CS: CommitmentScheme> {
    pub(crate) data: BTreeMap<Vec<u8>, CS::Value>,
    pub(crate) scheme: CS,
    cached_root: Option<Vec<u8>>,
}

impl<CS: CommitmentScheme> HashMapStateTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    pub fn new(scheme: CS) -> Self {
        Self {
            data: BTreeMap::new(),
            scheme,
            cached_root: None,
        }
    }

    fn to_value(&self, bytes: &[u8]) -> CS::Value {
        CS::Value::from(bytes.to_vec())
    }

    fn compute_merkle_root(&self) -> Vec<u8> {
        if self.data.is_empty() {
            return vec![0u8; 32];
        }

        let leaves: Vec<Vec<u8>> = self
            .data
            .iter()
            .map(|(key, value)| CS::commit_leaf(key, value.as_ref()))
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

    fn generate_merkle_proof(&self, key: &[u8]) -> Option<MerkleProof> {
        let keys: Vec<_> = self.data.keys().collect();
        let index = keys.iter().position(|k| k.as_slice() == key)?;
        let mut current_level: Vec<Vec<u8>> = self
            .data
            .iter()
            .map(|(k, v)| CS::commit_leaf(k.as_slice(), v.as_ref()))
            .collect();
        let mut siblings = Vec::new();
        let mut path = Vec::new();
        let mut current_index = index;
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
                next_level.push(CS::commit_branch(left, right));
            }
            current_level = next_level;
            current_index /= 2;
        }
        Some(MerkleProof { siblings, path })
    }

    /// **[COMPLETED]** Verify a Merkle proof. Made static to be called from the trait impl.
    pub fn verify_merkle_proof_static(
        root: &[u8],
        key: &[u8],
        value: &[u8],
        proof: &MerkleProof,
    ) -> bool {
        let mut current = CS::commit_leaf(key, value);

        for (i, sibling) in proof.siblings.iter().enumerate() {
            current = if proof.path[i] {
                CS::commit_branch(sibling, &current)
            } else {
                CS::commit_branch(&current, sibling)
            };
        }
        current.as_slice() == root
    }

    fn invalidate_cache(&mut self) {
        self.cached_root = None;
    }
}

impl<CS: CommitmentScheme> StateCommitment for HashMapStateTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + std::fmt::Debug,
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
{
    type Commitment = CS::Commitment;
    type Proof = CS::Proof;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.data.get(key).map(|v| v.as_ref().to_vec()))
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.data.insert(key.to_vec(), self.to_value(value));
        self.invalidate_cache();
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        self.data.remove(key);
        self.invalidate_cache();
        Ok(())
    }

    fn root_commitment(&self) -> Self::Commitment {
        // Identity: commitment bytes ARE the Merkle root bytes.
        let root = self
            .cached_root
            .as_ref()
            .cloned()
            .unwrap_or_else(|| self.compute_merkle_root());
        <CS as CommitmentScheme>::Commitment::from(root)
    }

    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        let merkle_proof = self.generate_merkle_proof(key)?;
        let proof_data = serde_json::to_vec(&merkle_proof).ok()?;
        let value = self.to_value(&proof_data);
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
        let root_hash = commitment.as_ref();
        let proof_data = proof.as_ref();

        let merkle_proof: MerkleProof = match serde_json::from_slice(proof_data) {
            Ok(p) => p,
            Err(_) => return false,
        };

        Self::verify_merkle_proof_static(root_hash, key, value, &merkle_proof)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn export_kv_pairs(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.data
            .iter()
            .map(|(k, v)| (k.clone(), v.as_ref().to_vec()))
            .collect()
    }

    fn prefix_scan(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StateError> {
        let results = self
            .data
            .range(prefix.to_vec()..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.as_ref().to_vec()))
            .collect();
        Ok(results)
    }
}

impl<CS: CommitmentScheme> StateManager for HashMapStateTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + std::fmt::Debug,
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
{
    fn get_with_proof_at(
        &self,
        _root: &Self::Commitment,
        key: &[u8],
    ) -> Result<(Membership, Self::Proof), StateError> {
        let membership = match self.data.get(key) {
            Some(value) => Membership::Present(value.as_ref().to_vec()),
            None => Membership::Absent,
        };
        let proof = self.create_proof(key).ok_or_else(|| {
            StateError::Backend("Failed to generate Merkle proof for HashMapStateTree".to_string())
        })?;
        Ok((membership, proof))
    }

    fn commitment_from_bytes(&self, bytes: &[u8]) -> Result<Self::Commitment, StateError> {
        Ok(<CS as CommitmentScheme>::Commitment::from(bytes.to_vec()))
    }

    fn commitment_to_bytes(&self, c: &Self::Commitment) -> Vec<u8> {
        c.as_ref().to_vec()
    }

    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        for (key, value) in updates {
            let value_typed = self.to_value(value);
            self.data.insert(key.to_vec(), value_typed);
        }
        self.invalidate_cache();
        Ok(())
    }

    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        let mut values = Vec::with_capacity(keys.len());
        for key in keys {
            values.push(self.data.get(key).map(|v| v.as_ref().to_vec()));
        }
        Ok(values)
    }

    fn prune(&mut self, _min_height_to_keep: u64) -> Result<(), StateError> {
        // This is an in-memory, non-versioned tree. Pruning is a no-op.
        Ok(())
    }
}