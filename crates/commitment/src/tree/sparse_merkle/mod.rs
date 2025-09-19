// Path: crates/commitment/src/tree/sparse_merkle/mod.rs
//! Sparse Merkle tree implementation with cryptographic security

pub mod verifier;

use depin_sdk_api::commitment::{CommitmentScheme, Selector};
use depin_sdk_api::state::{StateCommitment, StateManager};
use depin_sdk_crypto::algorithms::hash; // Uses dcrypt::hash::sha2 underneath
use depin_sdk_types::app::Membership;
use depin_sdk_types::error::StateError;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;

const TREE_HEIGHT: usize = 256; // For 256-bit keys

/// Sparse Merkle tree node
#[derive(Debug, Clone, PartialEq)]
enum Node {
    Empty,
    Leaf {
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Branch {
        left: Box<Node>,
        right: Box<Node>,
        hash: Vec<u8>,
    },
}

impl Node {
    fn hash(&self) -> Vec<u8> {
        match self {
            Node::Empty => vec![0u8; 32], // Empty hash
            Node::Leaf { key, value } => {
                let mut data = Vec::new();
                data.push(0x00); // Leaf prefix
                data.extend_from_slice(key);
                data.extend_from_slice(value);
                hash::sha256(&data)
            }
            Node::Branch { hash, .. } => hash.clone(),
        }
    }

    fn compute_branch_hash(left: &Node, right: &Node) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(0x01); // Branch prefix
        data.extend_from_slice(&left.hash());
        data.extend_from_slice(&right.hash());
        hash::sha256(&data)
    }
}

/// Sparse Merkle tree proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparseMerkleProof {
    pub siblings: Vec<Vec<u8>>,
    // No explicit path needed; the key itself provides the path.
    pub leaf: Option<(Vec<u8>, Vec<u8>)>, // (key, value) if an item exists at this key.
}

/// Sparse Merkle tree implementation
#[derive(Debug, Clone)]
pub struct SparseMerkleTree<CS: CommitmentScheme> {
    root: Node,
    scheme: CS,
    cache: HashMap<Vec<u8>, Vec<u8>>, // Key-value cache for efficient lookups
    versions: HashMap<Vec<u8>, Node>, // root_hash -> snapshot of that root
}

impl<CS: CommitmentScheme> SparseMerkleTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    /// Create a new sparse Merkle tree
    pub fn new(scheme: CS) -> Self {
        let mut this = Self {
            root: Node::Empty,
            scheme,
            cache: HashMap::new(),
            versions: HashMap::new(),
        };
        // Store the empty root snapshot so queries against the initial anchor work.
        let empty_root = this.root.hash();
        this.versions.insert(empty_root, this.root.clone());
        this
    }

    fn to_value(&self, bytes: &[u8]) -> CS::Value {
        CS::Value::from(bytes.to_vec())
    }

    /// Get the bits of a key for path navigation
    fn get_bit(key: &[u8], position: usize) -> bool {
        if position >= key.len() * 8 {
            return false;
        }
        let byte_index = position / 8;
        let bit_index = 7 - (position % 8);
        (key[byte_index] >> bit_index) & 1 == 1
    }

    /// Update the tree with a new key-value pair
    #[allow(clippy::only_used_in_recursion)]
    fn update_node(&self, node: &Node, key: &[u8], value: Option<&[u8]>, depth: usize) -> Node {
        if depth >= TREE_HEIGHT {
            return if let Some(v) = value {
                Node::Leaf {
                    key: key.to_vec(),
                    value: v.to_vec(),
                }
            } else {
                Node::Empty
            };
        }

        match node {
            Node::Empty => {
                if value.is_none() {
                    return Node::Empty;
                }
                // Path is empty. Create a new path of branches down to the leaf.
                let child = self.update_node(&Node::Empty, key, value, depth + 1);
                let bit = Self::get_bit(key, depth);
                let (left, right) = if bit {
                    (Box::new(Node::Empty), Box::new(child))
                } else {
                    (Box::new(child), Box::new(Node::Empty))
                };
                let hash = Node::compute_branch_hash(&left, &right);
                Node::Branch { left, right, hash }
            }
            Node::Leaf {
                key: leaf_key,
                value: leaf_value,
            } => {
                if leaf_key == key {
                    // Exact key match: update the value or delete the leaf.
                    return if let Some(v) = value {
                        Node::Leaf {
                            key: key.to_vec(),
                            value: v.to_vec(),
                        }
                    } else {
                        Node::Empty
                    };
                }

                // A different key exists at this path. Split them into a new branch.
                // First, create a branch for the new key as if this spot were empty.
                let new_node_branch = self.update_node(&Node::Empty, key, value, depth);
                // Then, insert the old leaf into that new structure.
                self.update_node(&new_node_branch, leaf_key, Some(leaf_value), depth)
            }
            Node::Branch { left, right, .. } => {
                let bit = Self::get_bit(key, depth);
                let (new_left, new_right) = if bit {
                    (
                        left.as_ref().clone(),
                        self.update_node(right, key, value, depth + 1),
                    )
                } else {
                    (
                        self.update_node(left, key, value, depth + 1),
                        right.as_ref().clone(),
                    )
                };

                if new_left == Node::Empty && new_right == Node::Empty {
                    Node::Empty
                } else {
                    let hash = Node::compute_branch_hash(&new_left, &new_right);
                    Node::Branch {
                        left: Box::new(new_left),
                        right: Box::new(new_right),
                        hash,
                    }
                }
            }
        }
    }

    /// Generate a proof for a key
    fn generate_proof(&self, key: &[u8]) -> SparseMerkleProof {
        let mut siblings = Vec::new();
        let mut current = &self.root;

        for depth in 0..TREE_HEIGHT {
            match current {
                Node::Empty => break,
                Node::Leaf { .. } => {
                    break;
                }
                Node::Branch { left, right, .. } => {
                    let bit = Self::get_bit(key, depth);
                    if bit {
                        siblings.push(left.hash());
                        current = right;
                    } else {
                        siblings.push(right.hash());
                        current = left;
                    }
                }
            }
        }

        let leaf = if let Node::Leaf {
            key: leaf_key,
            value,
        } = current
        {
            Some((leaf_key.clone(), value.clone()))
        } else {
            None
        };

        SparseMerkleProof { siblings, leaf }
    }

    fn get_from_snapshot(node: &Node, key: &[u8], depth: usize) -> Option<Vec<u8>> {
        match node {
            Node::Empty => None,
            Node::Leaf { key: k, value: v } => (k.as_slice() == key).then(|| v.clone()),
            Node::Branch { left, right, .. } => {
                if Self::get_bit(key, depth) {
                    Self::get_from_snapshot(right, key, depth + 1)
                } else {
                    Self::get_from_snapshot(left, key, depth + 1)
                }
            }
        }
    }

    fn generate_proof_from_snapshot(start: &Node, key: &[u8]) -> SparseMerkleProof {
        let mut siblings = Vec::new();
        let mut current = start;
        for depth in 0..TREE_HEIGHT {
            match current {
                Node::Empty => break,
                Node::Leaf { .. } => {
                    // Path terminates here. The verifier will determine if this is the
                    // target leaf or a witness for an absence proof.
                    break;
                }
                Node::Branch { left, right, .. } => {
                    if Self::get_bit(key, depth) {
                        siblings.push(left.hash());
                        current = right;
                    } else {
                        siblings.push(right.hash());
                        current = left;
                    }
                }
            }
        }

        let leaf = match current {
            Node::Leaf { key, value } => Some((key.clone(), value.clone())),
            _ => None,
        };

        SparseMerkleProof { siblings, leaf }
    }

    /// **[COMPLETED]** Verify a proof against a root hash. Made static.
    pub fn verify_proof_static(
        root_hash: &[u8],
        key: &[u8],
        value: Option<&[u8]>,
        proof: &SparseMerkleProof,
    ) -> bool {
        // Determine the starting hash for the fold-up based on the proof type.
        let leaf_hash = match (&proof.leaf, value) {
            // Case 1: Proving PRESENCE.
            // proof.leaf must be Some, value must be Some.
            // proof_key must equal the query key.
            (Some((proof_key, proof_value)), Some(val)) => {
                if proof_key != key || proof_value != val {
                    log::debug!("[SMT Verify] Presence proof failed: key or value mismatch.");
                    return false;
                }
                let mut data = Vec::with_capacity(1 + proof_key.len() + proof_value.len());
                data.push(0x00); // leaf prefix
                data.extend_from_slice(proof_key);
                data.extend_from_slice(proof_value);
                hash::sha256(&data)
            }
            // Case 2: Proving ABSENCE because the path ends at an EMPTY node.
            // proof.leaf must be None, value must be None.
            (None, None) => vec![0u8; 32],

            // Case 3: Proving ABSENCE because the path ends at a *different* leaf (a witness).
            // proof.leaf is Some (the witness), value is None.
            // The witness key must NOT be the query key.
            (Some((witness_key, witness_value)), None) => {
                if witness_key == key {
                    log::debug!("[SMT Verify] Absence proof failed: witness key is the same as the query key.");
                    return false;
                }
                let mut data = Vec::new();
                data.push(0x00); // leaf prefix
                data.extend_from_slice(witness_key);
                data.extend_from_slice(witness_value);
                hash::sha256(&data)
            }
            // All other combinations are invalid.
            _ => {
                log::debug!("[SMT Verify] Invalid proof/value combination.");
                return false;
            }
        };

        // Fold up the tree using the siblings from the proof.
        let mut acc = leaf_hash;
        let path_len = proof.siblings.len();
        for i in (0..path_len).rev() {
            let sib = &proof.siblings[i];
            let mut data = Vec::with_capacity(1 + 32 + 32);
            data.push(0x01); // branch prefix
            if Self::get_bit(key, i) {
                data.extend_from_slice(sib);
                data.extend_from_slice(&acc);
            } else {
                data.extend_from_slice(&acc);
                data.extend_from_slice(sib);
            }
            acc = hash::sha256(&data);
        }

        acc.as_slice() == root_hash
    }
}

impl<CS: CommitmentScheme> StateCommitment for SparseMerkleTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + std::fmt::Debug,
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
{
    type Commitment = CS::Commitment;
    type Proof = CS::Proof;

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.root = self.update_node(&self.root, key, Some(value), 0);
        self.cache.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.cache.get(key).cloned())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        self.root = self.update_node(&self.root, key, None, 0);
        self.cache.remove(key);
        Ok(())
    }

    fn root_commitment(&self) -> Self::Commitment {
        // Identity: commitment bytes ARE the SMT root bytes.
        let root_hash = self.root.hash();
        <CS as CommitmentScheme>::Commitment::from(root_hash)
    }

    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        let merkle_proof = self.generate_proof(key);
        let proof_data = serde_json::to_vec(&merkle_proof).ok()?;
        let value_typed = self.to_value(&proof_data);
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
        let root_hash = commitment.as_ref();
        let proof_data = proof.as_ref();

        let smt_proof: SparseMerkleProof = match serde_json::from_slice(proof_data) {
            Ok(p) => p,
            Err(_) => return false,
        };

        Self::verify_proof_static(root_hash, key, Some(value), &smt_proof)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn export_kv_pairs(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.cache
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    fn prefix_scan(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StateError> {
        let results = self
            .cache
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        Ok(results)
    }
}

impl<CS: CommitmentScheme> StateManager for SparseMerkleTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + std::fmt::Debug,
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
{
    fn get_with_proof_at(
        &self,
        root: &Self::Commitment,
        key: &[u8],
    ) -> Result<(Membership, Self::Proof), StateError> {
        let requested = root.as_ref();
        // Resolve snapshot for the requested root.
        let snapshot = if let Some(n) = self.versions.get(requested) {
            n
        } else {
            // If no snapshot was recorded for this root, treat as StaleAnchor (the orchestrator already knows how to retry on this hint).
            return Err(StateError::Backend(format!(
                "StaleAnchor(SMT): unknown root {}",
                hex::encode(requested)
            )));
        };

        // Build membership and proof *from the snapshot*, not from live state.
        let membership = match Self::get_from_snapshot(snapshot, key, 0) {
            Some(v) => Membership::Present(v),
            None => Membership::Absent,
        };
        let merkle_proof = Self::generate_proof_from_snapshot(snapshot, key);

        // Server-side self-check: ensure the proof actually anchors to the requested root.
        let expected_value = membership.clone().into_option();
        if !Self::verify_proof_static(requested, key, expected_value.as_deref(), &merkle_proof) {
            log::error!(
                "[SMT Server] self-verify failed (root={}, key={})",
                hex::encode(requested),
                hex::encode(key)
            );
            return Err(StateError::Backend("SMT self-verify failed".into()));
        }

        // Wrap proof in the outer commitment scheme.
        let proof_bytes =
            serde_json::to_vec(&merkle_proof).map_err(|e| StateError::Backend(e.to_string()))?;
        let value = self.to_value(&proof_bytes);
        let proof = self
            .scheme
            .create_proof(&Selector::Key(key.to_vec()), &value)
            .map_err(|e| StateError::Backend(e.to_string()))?;
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

    fn batch_apply(
        &mut self,
        inserts: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), StateError> {
        for key in deletes {
            self.delete(key)?;
        }
        for (key, value) in inserts {
            self.insert(key, value)?;
        }
        Ok(())
    }

    fn prune(&mut self, _min_height_to_keep: u64) -> Result<(), StateError> {
        // This is an in-memory, non-versioned tree. Pruning is a no-op.
        Ok(())
    }

    fn commit_version(&mut self) {
        // Record a snapshot for the current root so future reads can be anchored.
        let root_hash = self.root.hash();
        self.versions.insert(root_hash, self.root.clone());
        log::debug!(
            "[SMT] commit_version: recorded snapshot for root {}",
            hex::encode(&self.root.hash())
        );
    }

    fn version_exists_for_root(&self, root: &Self::Commitment) -> bool {
        self.versions.contains_key(root.as_ref())
    }
}

#[cfg(test)]
mod tests;
