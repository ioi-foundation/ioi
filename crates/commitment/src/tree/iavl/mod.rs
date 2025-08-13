// Path: crates/commitment/src/tree/iavl/mod.rs

//! IAVL (Immutable AVL) tree implementation with cryptographic security

use depin_sdk_api::commitment::{CommitmentScheme, Selector};
use depin_sdk_api::state::{StateCommitment, StateManager};
use depin_sdk_crypto::algorithms::hash; // Uses dcrypt::hash::sha2 underneath
use depin_sdk_types::error::StateError;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::cmp::{max, Ordering};
use std::collections::HashMap;
use std::sync::Arc;

/// IAVL tree node with immutable structure
#[derive(Debug, Clone)]
pub struct IAVLNode {
    key: Vec<u8>,
    value: Vec<u8>,
    version: u64,
    height: i32,
    size: u64,
    hash: Vec<u8>,
    left: Option<Arc<IAVLNode>>,
    right: Option<Arc<IAVLNode>>,
}

impl IAVLNode {
    /// Create a new leaf node
    fn new_leaf(key: Vec<u8>, value: Vec<u8>, version: u64) -> Self {
        let mut node = Self {
            key: key.clone(),
            value: value.clone(),
            version,
            height: 0,
            size: 1,
            hash: Vec::new(),
            left: None,
            right: None,
        };
        node.hash = node.compute_hash();
        node
    }

    /// Compute the hash of this node
    fn compute_hash(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Add node type marker
        data.push(if self.is_leaf() { 0x00 } else { 0x01 });
        data.extend_from_slice(&self.version.to_le_bytes());
        data.extend_from_slice(&self.height.to_le_bytes());
        data.extend_from_slice(&self.size.to_le_bytes());
        data.extend_from_slice(&(self.key.len() as u32).to_le_bytes());
        data.extend_from_slice(&self.key);

        if self.is_leaf() {
            data.extend_from_slice(&(self.value.len() as u32).to_le_bytes());
            data.extend_from_slice(&self.value);
        } else {
            let left_hash = self
                .left
                .as_ref()
                .map(|l| l.hash.clone())
                .unwrap_or_else(|| vec![0u8; 32]);
            let right_hash = self
                .right
                .as_ref()
                .map(|r| r.hash.clone())
                .unwrap_or_else(|| vec![0u8; 32]);
            data.extend_from_slice(&left_hash);
            data.extend_from_slice(&right_hash);
        }

        hash::sha256(&data)
    }

    /// Check if this is a leaf node
    fn is_leaf(&self) -> bool {
        self.left.is_none() && self.right.is_none()
    }

    /// Get the height of a node (None is -1)
    fn node_height(node: &Option<Arc<IAVLNode>>) -> i32 {
        node.as_ref().map_or(-1, |n| n.height)
    }

    /// Get the size of a node (None is 0)
    fn node_size(node: &Option<Arc<IAVLNode>>) -> u64 {
        node.as_ref().map_or(0, |n| n.size)
    }

    /// Calculate balance factor
    fn balance_factor(&self) -> i32 {
        Self::node_height(&self.right) - Self::node_height(&self.left)
    }

    /// Create a new node with updated children
    fn with_children(
        key: Vec<u8>,
        value: Vec<u8>,
        version: u64,
        left: Option<Arc<IAVLNode>>,
        right: Option<Arc<IAVLNode>>,
    ) -> Self {
        let height = 1 + max(Self::node_height(&left), Self::node_height(&right));
        let size = 1 + Self::node_size(&left) + Self::node_size(&right);

        let mut node = Self {
            key,
            value,
            version,
            height,
            size,
            hash: Vec::new(),
            left,
            right,
        };
        node.hash = node.compute_hash();
        node
    }

    /// Rotate left
    fn rotate_left(node: Arc<IAVLNode>) -> Arc<IAVLNode> {
        let right = node
            .right
            .as_ref()
            .expect("Right child must exist for left rotation");
        let new_node = Self::with_children(
            node.key.clone(),
            node.value.clone(),
            node.version,
            node.left.clone(),
            right.left.clone(),
        );
        Arc::new(Self::with_children(
            right.key.clone(),
            right.value.clone(),
            right.version,
            Some(Arc::new(new_node)),
            right.right.clone(),
        ))
    }

    /// Rotate right
    fn rotate_right(node: Arc<IAVLNode>) -> Arc<IAVLNode> {
        let left = node
            .left
            .as_ref()
            .expect("Left child must exist for right rotation");
        let new_node = Self::with_children(
            node.key.clone(),
            node.value.clone(),
            node.version,
            left.right.clone(),
            node.right.clone(),
        );
        Arc::new(Self::with_children(
            left.key.clone(),
            left.value.clone(),
            left.version,
            left.left.clone(),
            Some(Arc::new(new_node)),
        ))
    }

    /// Balance the tree if needed
    fn balance(node: Arc<IAVLNode>) -> Arc<IAVLNode> {
        let balance_factor = node.balance_factor();
        if balance_factor > 1 {
            // Right-heavy
            if let Some(right) = &node.right {
                if right.balance_factor() < 0 {
                    // Right-Left case
                    let new_right = Self::rotate_right(right.clone());
                    let new_node = Self::with_children(
                        node.key.clone(),
                        node.value.clone(),
                        node.version,
                        node.left.clone(),
                        Some(new_right),
                    );
                    Self::rotate_left(Arc::new(new_node))
                } else {
                    // Right-Right case
                    Self::rotate_left(node)
                }
            } else {
                node
            }
        } else if balance_factor < -1 {
            // Left-heavy
            if let Some(left) = &node.left {
                if left.balance_factor() > 0 {
                    // Left-Right case
                    let new_left = Self::rotate_left(left.clone());
                    let new_node = Self::with_children(
                        node.key.clone(),
                        node.value.clone(),
                        node.version,
                        Some(new_left),
                        node.right.clone(),
                    );
                    Self::rotate_right(Arc::new(new_node))
                } else {
                    // Left-Left case
                    Self::rotate_right(node)
                }
            } else {
                node
            }
        } else {
            node
        }
    }

    /// Insert a key-value pair into the tree
    fn insert(
        node: Option<Arc<IAVLNode>>,
        key: Vec<u8>,
        value: Vec<u8>,
        version: u64,
    ) -> Arc<IAVLNode> {
        match node {
            None => Arc::new(Self::new_leaf(key, value, version)),
            Some(n) => match key.cmp(&n.key) {
                Ordering::Less => {
                    let new_left = Self::insert(n.left.clone(), key, value, version);
                    let new_node = Self::with_children(
                        n.key.clone(),
                        n.value.clone(),
                        n.version,
                        Some(new_left),
                        n.right.clone(),
                    );
                    Self::balance(Arc::new(new_node))
                }
                Ordering::Greater => {
                    let new_right = Self::insert(n.right.clone(), key, value, version);
                    let new_node = Self::with_children(
                        n.key.clone(),
                        n.value.clone(),
                        n.version,
                        n.left.clone(),
                        Some(new_right),
                    );
                    Self::balance(Arc::new(new_node))
                }
                Ordering::Equal => Arc::new(Self::with_children(
                    n.key.clone(),
                    value,
                    version,
                    n.left.clone(),
                    n.right.clone(),
                )),
            },
        }
    }

    /// Remove a key from the tree
    fn remove(node: Option<Arc<IAVLNode>>, key: &[u8]) -> Option<Arc<IAVLNode>> {
        node.and_then(|n| match key.cmp(&n.key) {
            Ordering::Less => {
                let new_left = Self::remove(n.left.clone(), key);
                let new_node = Self::with_children(
                    n.key.clone(),
                    n.value.clone(),
                    n.version,
                    new_left,
                    n.right.clone(),
                );
                Some(Self::balance(Arc::new(new_node)))
            }
            Ordering::Greater => {
                let new_right = Self::remove(n.right.clone(), key);
                let new_node = Self::with_children(
                    n.key.clone(),
                    n.value.clone(),
                    n.version,
                    n.left.clone(),
                    new_right,
                );
                Some(Self::balance(Arc::new(new_node)))
            }
            Ordering::Equal => match (n.left.clone(), n.right.clone()) {
                (None, None) => None,
                (Some(left), None) => Some(left),
                (None, Some(right)) => Some(right),
                (Some(left), Some(right)) => {
                    let min_right = Self::find_min(&right);
                    let new_right = Self::remove(Some(right), &min_right.key);
                    let new_node = Self::with_children(
                        min_right.key.clone(),
                        min_right.value.clone(),
                        min_right.version,
                        Some(left),
                        new_right,
                    );
                    Some(Self::balance(Arc::new(new_node)))
                }
            },
        })
    }

    /// Find the minimum node in a subtree
    fn find_min(node: &Arc<IAVLNode>) -> Arc<IAVLNode> {
        node.left
            .as_ref()
            .map_or_else(|| node.clone(), Self::find_min)
    }

    /// Get a value by key
    fn get(node: &Option<Arc<IAVLNode>>, key: &[u8]) -> Option<Vec<u8>> {
        node.as_ref().and_then(|n| match key.cmp(&n.key) {
            Ordering::Less => Self::get(&n.left, key),
            Ordering::Greater => Self::get(&n.right, key),
            Ordering::Equal => Some(n.value.clone()),
        })
    }
}

/// IAVL tree proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IAVLProof {
    pub leaf: Option<(Vec<u8>, Vec<u8>, u64)>, // (key, value, version)
    pub path: Vec<IAVLProofNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IAVLProofNode {
    pub key: Vec<u8>,
    pub height: i32,
    pub size: u64,
    pub version: u64,
    pub left_hash: Option<Vec<u8>>,
    pub right_hash: Option<Vec<u8>>,
}

/// IAVL tree implementation
pub struct IAVLTree<CS: CommitmentScheme> {
    root: Option<Arc<IAVLNode>>,
    version: u64,
    scheme: CS,
    cache: HashMap<Vec<u8>, Vec<u8>>,
}

impl<CS: CommitmentScheme> IAVLTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    pub fn new(scheme: CS) -> Self {
        Self {
            root: None,
            version: 0,
            scheme,
            cache: HashMap::new(),
        }
    }

    fn to_value(&self, value: &[u8]) -> CS::Value {
        CS::Value::from(value.to_vec())
    }

    fn generate_proof(&self, key: &[u8]) -> IAVLProof {
        let mut path = Vec::new();
        let mut current = self.root.as_ref();
        while let Some(node) = current {
            let (left_hash, right_hash) = match key.cmp(&node.key) {
                Ordering::Less => (None, node.right.as_ref().map(|r| r.hash.clone())),
                Ordering::Greater => (node.left.as_ref().map(|l| l.hash.clone()), None),
                Ordering::Equal => (
                    node.left.as_ref().map(|l| l.hash.clone()),
                    node.right.as_ref().map(|r| r.hash.clone()),
                ),
            };
            path.push(IAVLProofNode {
                key: node.key.clone(),
                height: node.height,
                size: node.size,
                version: node.version,
                left_hash,
                right_hash,
            });
            match key.cmp(&node.key) {
                Ordering::Less => current = node.left.as_ref(),
                Ordering::Greater => current = node.right.as_ref(),
                Ordering::Equal => {
                    return IAVLProof {
                        leaf: Some((node.key.clone(), node.value.clone(), node.version)),
                        path,
                    }
                }
            }
        }
        IAVLProof { leaf: None, path }
    }

    /// **[COMPLETED]** Statically verify an IAVL proof against a root hash.
    pub fn verify_iavl_proof_static(
        root_hash: &[u8],
        key: &[u8],
        value: Option<&[u8]>,
        proof: &IAVLProof,
    ) -> bool {
        let mut current_hash = if let Some(val) = value {
            if proof.leaf.is_none() {
                return false;
            }
            let (leaf_key, leaf_value, leaf_version) = proof.leaf.as_ref().unwrap();
            if leaf_key != key || leaf_value != val {
                return false;
            }
            let leaf_node = IAVLNode::new_leaf(leaf_key.clone(), leaf_value.clone(), *leaf_version);
            leaf_node.hash
        } else {
            if proof.leaf.is_some() {
                return false;
            }
            vec![0u8; 32]
        };

        for node in proof.path.iter().rev() {
            let (left_h, right_h) = if key < node.key.as_slice() {
                (
                    current_hash.clone(),
                    node.right_hash.clone().unwrap_or_else(|| vec![0u8; 32]),
                )
            } else {
                (
                    node.left_hash.clone().unwrap_or_else(|| vec![0u8; 32]),
                    current_hash.clone(),
                )
            };
            let mut data = Vec::new();
            data.push(0x01);
            data.extend_from_slice(&node.version.to_le_bytes());
            data.extend_from_slice(&node.height.to_le_bytes());
            data.extend_from_slice(&node.size.to_le_bytes());
            data.extend_from_slice(&(node.key.len() as u32).to_le_bytes());
            data.extend_from_slice(&node.key);
            data.extend_from_slice(&left_h);
            data.extend_from_slice(&right_h);
            current_hash = hash::sha256(&data);
        }

        current_hash == root_hash
    }
}

impl<CS: CommitmentScheme + Default> StateCommitment for IAVLTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
    CS::Proof: AsRef<[u8]>,
{
    type Commitment = CS::Commitment;
    type Proof = CS::Proof;

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.version += 1;
        self.root = Some(IAVLNode::insert(
            self.root.clone(),
            key.to_vec(),
            value.to_vec(),
            self.version,
        ));
        self.cache.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        Ok(IAVLNode::get(&self.root, key))
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        self.version += 1;
        self.root = IAVLNode::remove(self.root.clone(), key);
        self.cache.remove(key);
        Ok(())
    }

    fn root_commitment(&self) -> Self::Commitment {
        let root_hash = self
            .root
            .as_ref()
            .map(|n| n.hash.clone())
            .unwrap_or_else(|| vec![0u8; 32]);
        let value = self.to_value(&root_hash);
        self.scheme.commit(&[Some(value)])
    }

    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        let iavl_proof = self.generate_proof(key);
        let proof_data = serde_json::to_vec(&iavl_proof).ok()?;
        let value = self.to_value(&proof_data);
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
        let proof_data = proof.as_ref();
        let iavl_proof: IAVLProof = match serde_json::from_slice(proof_data) {
            Ok(p) => p,
            Err(_) => return false,
        };
        Self::verify_iavl_proof_static(root_hash, key, Some(value), &iavl_proof)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl<CS: CommitmentScheme + Default> StateManager for IAVLTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
    CS::Proof: AsRef<[u8]>,
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
