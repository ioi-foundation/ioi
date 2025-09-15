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
}

impl<CS: CommitmentScheme> SparseMerkleTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    /// Create a new sparse Merkle tree
    pub fn new(scheme: CS) -> Self {
        Self {
            root: Node::Empty,
            scheme,
            cache: HashMap::new(),
        }
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
                if let Some(v) = value {
                    let mut new_node = Node::Leaf {
                        key: key.to_vec(),
                        value: v.to_vec(),
                    };
                    for d in (0..depth).rev() {
                        let bit = Self::get_bit(key, d);
                        let (left, right) = if bit {
                            (Node::Empty, new_node)
                        } else {
                            (new_node, Node::Empty)
                        };
                        let hash = Node::compute_branch_hash(&left, &right);
                        new_node = Node::Branch {
                            left: Box::new(left),
                            right: Box::new(right),
                            hash,
                        };
                    }
                    new_node
                } else {
                    Node::Empty
                }
            }
            Node::Leaf {
                key: leaf_key,
                value: leaf_value,
            } => {
                if leaf_key == key {
                    return if let Some(v) = value {
                        Node::Leaf {
                            key: key.to_vec(),
                            value: v.to_vec(),
                        }
                    } else {
                        Node::Empty
                    };
                }
                let old_leaf_bit = Self::get_bit(leaf_key, depth);
                let new_leaf_bit = Self::get_bit(key, depth);

                if old_leaf_bit == new_leaf_bit {
                    let child = self.update_node(node, key, value, depth + 1);
                    let (left, right) = if old_leaf_bit {
                        (Box::new(Node::Empty), Box::new(child))
                    } else {
                        (Box::new(child), Box::new(Node::Empty))
                    };
                    let hash = Node::compute_branch_hash(&left, &right);
                    Node::Branch { left, right, hash }
                } else {
                    let old_leaf = Node::Leaf {
                        key: leaf_key.clone(),
                        value: leaf_value.clone(),
                    };
                    let new_leaf = if let Some(v) = value {
                        Node::Leaf {
                            key: key.to_vec(),
                            value: v.to_vec(),
                        }
                    } else {
                        Node::Empty
                    };

                    let (left, right) = if old_leaf_bit {
                        (Box::new(new_leaf), Box::new(old_leaf))
                    } else {
                        (Box::new(old_leaf), Box::new(new_leaf))
                    };
                    let hash = Node::compute_branch_hash(&left, &right);
                    Node::Branch { left, right, hash }
                }
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
                Node::Leaf { key: leaf_key, .. } => {
                    if leaf_key == key {
                        // We found the leaf, no more siblings needed up the path
                        break;
                    } else {
                        // The path we are looking for is empty, but we hit a different leaf.
                        // The rest of the proof will be empty placeholder hashes.
                        break;
                    }
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
            if leaf_key == key {
                Some((leaf_key.clone(), value.clone()))
            } else {
                None
            }
        } else {
            None
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
        let leaf_hash = match (&proof.leaf, value) {
            (Some((proof_key, proof_value)), Some(val)) => {
                if proof_key != key || proof_value != val {
                    return false;
                }
                let mut data = Vec::new();
                data.push(0x00);
                data.extend_from_slice(proof_key);
                data.extend_from_slice(proof_value);
                hash::sha256(&data)
            }
            (None, None) => vec![0u8; 32],
            _ => return false,
        };

        let mut current_hash = leaf_hash;
        let mut proof_siblings = proof.siblings.iter().rev();

        for depth in (0..TREE_HEIGHT).rev() {
            let sibling_hash = if let Some(sibling) = proof_siblings.next() {
                sibling.clone()
            } else {
                vec![0u8; 32] // Default hash for empty paths
            };

            let mut data = Vec::new();
            data.push(0x01);

            if Self::get_bit(key, depth) {
                data.extend_from_slice(&sibling_hash);
                data.extend_from_slice(&current_hash);
            } else {
                data.extend_from_slice(&current_hash);
                data.extend_from_slice(&sibling_hash);
            }
            current_hash = hash::sha256(&data);
        }

        current_hash == root_hash
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
        _root: &Self::Commitment,
        key: &[u8],
    ) -> Result<(Membership, Self::Proof), StateError> {
        let membership = match self.get(key)? {
            Some(value) => Membership::Present(value),
            None => Membership::Absent,
        };
        let proof = self
            .create_proof(key)
            .ok_or_else(|| StateError::Backend("Failed to generate SMT proof".to_string()))?;
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
}