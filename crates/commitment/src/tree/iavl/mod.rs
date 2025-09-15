// Path: crates/commitment/src/tree/iavl/mod.rs
//! IAVL (Immutable AVL) tree implementation with cryptographic security

mod proof;
pub mod verifier;

use crate::tree::iavl::proof::verify_iavl_proof_bytes;
use depin_sdk_api::commitment::{CommitmentScheme, Selector};
use depin_sdk_api::state::{StateCommitment, StateManager};
use depin_sdk_types::app::Membership;
use depin_sdk_types::error::StateError;
use proof::{ExistenceProof, InnerOp, LeafOp, NonExistenceProof, Side};
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

// --- DEBUGGING HELPERS ---

#[cfg(any(debug_assertions, feature = "strict_iavl"))]
const ENABLE_SNAPSHOT_CHECK: bool = true;
#[cfg(not(any(debug_assertions, feature = "strict_iavl")))]
const ENABLE_SNAPSHOT_CHECK: bool = false;

/// Strict, bottom-up recomputation that ignores cached child hashes.
fn recompute_hash_strict(n: &IAVLNode) -> Vec<u8> {
    let mut data = Vec::new();
    if n.is_leaf() {
        data.push(0x00);
        data.extend_from_slice(&n.version.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&1u64.to_le_bytes());
        data.extend_from_slice(&(n.key.len() as u32).to_le_bytes());
        data.extend_from_slice(&n.key);
        data.extend_from_slice(&(n.value.len() as u32).to_le_bytes());
        data.extend_from_slice(&n.value);
    } else {
        data.push(0x01);
        data.extend_from_slice(&n.version.to_le_bytes());
        data.extend_from_slice(&n.height.to_le_bytes());
        data.extend_from_slice(&n.size.to_le_bytes());
        data.extend_from_slice(&(n.key.len() as u32).to_le_bytes());
        data.extend_from_slice(&n.key);

        let l = n
            .left
            .as_deref()
            .map(recompute_hash_strict)
            .unwrap_or_else(IAVLNode::empty_hash);
        let r = n
            .right
            .as_deref()
            .map(recompute_hash_strict)
            .unwrap_or_else(IAVLNode::empty_hash);
        data.extend_from_slice(&l);
        data.extend_from_slice(&r);
    }
    depin_sdk_crypto::algorithms::hash::sha256(&data)
}

/// Walk the snapshot; at each node compare cached vs strict recomputation.
fn assert_snapshot_consistent(root: &Option<Arc<IAVLNode>>) {
    fn walk(n: &Arc<IAVLNode>) {
        let strict = recompute_hash_strict(n);

        if n.hash != strict {
            let l = n.left.as_ref();
            let r = n.right.as_ref();
            eprintln!(
                "[IAVL DRIFT]\n\
                 key={} v={} h={} sz={}\n\
                 cached={} strict={}\n\
                 -- CHILDREN (cached vs strict heads) --\n\
                 left:  present={} v={} h={} sz={} cached={} strict={}\n\
                 right: present={} v={} h={} sz={} cached={} strict={}",
                hex::encode(&n.key),
                n.version,
                n.height,
                n.size,
                hex::encode(&n.hash),
                hex::encode(&strict),
                l.is_some(),
                l.map(|x| x.version).unwrap_or(0),
                l.map(|x| x.height).unwrap_or(-1),
                l.map(|x| x.size).unwrap_or(0),
                l.map(|x| hex::encode(&x.hash.get(..4).unwrap_or_default()))
                    .unwrap_or_default(),
                l.map(|x| hex::encode(&recompute_hash_strict(x).get(..4).unwrap_or_default()))
                    .unwrap_or_default(),
                r.is_some(),
                r.map(|x| x.version).unwrap_or(0),
                r.map(|x| x.height).unwrap_or(-1),
                r.map(|x| x.size).unwrap_or(0),
                r.map(|x| hex::encode(&x.hash.get(..4).unwrap_or_default()))
                    .unwrap_or_default(),
                r.map(|x| hex::encode(&recompute_hash_strict(x).get(..4).unwrap_or_default()))
                    .unwrap_or_default(),
            );
            panic!("IAVL snapshot drift detected. See details above.");
        }
        if let Some(l) = &n.left {
            walk(l);
        }
        if let Some(r) = &n.right {
            walk(r);
        }
    }
    if let Some(n) = root {
        walk(n);
    }
}

/// Runs the deep check in debug builds, when the `strict_iavl` feature is on,
/// or if IAVL_STRICT_CONSISTENCY is set at runtime.
fn maybe_assert_snapshot_consistent(root: &Option<Arc<IAVLNode>>) {
    let force_check = std::env::var_os("IAVL_STRICT_CONSISTENCY").is_some();
    if ENABLE_SNAPSHOT_CHECK || force_check {
        assert_snapshot_consistent(root);
    }
}

impl IAVLNode {
    /// Create a new leaf node
    fn new_leaf(key: Vec<u8>, value: Vec<u8>, version: u64) -> Self {
        let mut node = Self {
            key,
            value,
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

    /// Compute the hash of this node according to the canonical specification.
    fn compute_hash(&self) -> Vec<u8> {
        let mut data = Vec::new();

        if self.is_leaf() {
            // Canonical Leaf Hash: H(tag || version || height=0 || size=1 || len(key) || key || len(value) || value)
            data.push(0x00); // Leaf tag
            data.extend_from_slice(&self.version.to_le_bytes());
            data.extend_from_slice(&0i32.to_le_bytes()); // Use constant 0 (i32) for leaf height
            data.extend_from_slice(&1u64.to_le_bytes()); // Use constant 1 (u64) for leaf size
            data.extend_from_slice(&(self.key.len() as u32).to_le_bytes());
            data.extend_from_slice(&self.key);
            data.extend_from_slice(&(self.value.len() as u32).to_le_bytes());
            data.extend_from_slice(&self.value);
        } else {
            // Canonical Inner Node Hash: H(tag || version || height || size || len(key) || key || left_hash || right_hash)
            data.push(0x01); // Inner node tag
            data.extend_from_slice(&self.version.to_le_bytes());
            data.extend_from_slice(&self.height.to_le_bytes());
            data.extend_from_slice(&self.size.to_le_bytes());
            data.extend_from_slice(&(self.key.len() as u32).to_le_bytes());
            data.extend_from_slice(&self.key);

            let left_hash = self
                .left
                .as_ref()
                .map(|l| l.hash.clone())
                .unwrap_or_else(Self::empty_hash);
            let right_hash = self
                .right
                .as_ref()
                .map(|r| r.hash.clone())
                .unwrap_or_else(Self::empty_hash);

            data.extend_from_slice(&left_hash);
            data.extend_from_slice(&right_hash);
        }
        depin_sdk_crypto::algorithms::hash::sha256(&data)
    }

    /// Provides the canonical hash of an empty/nil child node.
    fn empty_hash() -> Vec<u8> {
        depin_sdk_crypto::algorithms::hash::sha256(&[])
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
    fn rotate_left(node: Arc<IAVLNode>, version: u64) -> Arc<IAVLNode> {
        let right = node
            .right
            .as_ref()
            .expect("Right child must exist for left rotation");
        let new_node = Self::with_children(
            node.key.clone(),
            node.value.clone(),
            version,
            node.left.clone(),
            right.left.clone(),
        );
        Arc::new(Self::with_children(
            right.key.clone(),
            right.value.clone(),
            version,
            Some(Arc::new(new_node)),
            right.right.clone(),
        ))
    }

    /// Rotate right
    fn rotate_right(node: Arc<IAVLNode>, version: u64) -> Arc<IAVLNode> {
        let left = node
            .left
            .as_ref()
            .expect("Left child must exist for right rotation");
        let new_node = Self::with_children(
            node.key.clone(),
            node.value.clone(),
            version,
            left.right.clone(),
            node.right.clone(),
        );
        Arc::new(Self::with_children(
            left.key.clone(),
            left.value.clone(),
            version,
            left.left.clone(),
            Some(Arc::new(new_node)),
        ))
    }

    /// Balance the tree if needed
    fn balance(node: Arc<IAVLNode>, version: u64) -> Arc<IAVLNode> {
        let balance_factor = node.balance_factor();
        if balance_factor > 1 {
            // Right-heavy
            if let Some(right) = &node.right {
                if right.balance_factor() < 0 {
                    // Right-Left case
                    let new_right = Self::rotate_right(right.clone(), version);
                    let new_node = Self::with_children(
                        node.key.clone(),
                        node.value.clone(),
                        version,
                        node.left.clone(),
                        Some(new_right),
                    );
                    Self::rotate_left(Arc::new(new_node), version)
                } else {
                    // Right-Right case
                    Self::rotate_left(node, version)
                }
            } else {
                node
            }
        } else if balance_factor < -1 {
            // Left-heavy
            if let Some(left) = &node.left {
                if left.balance_factor() > 0 {
                    // Left-Right case
                    let new_left = Self::rotate_left(left.clone(), version);
                    let new_node = Self::with_children(
                        node.key.clone(),
                        node.value.clone(),
                        version,
                        Some(new_left),
                        node.right.clone(),
                    );
                    Self::rotate_right(Arc::new(new_node), version)
                } else {
                    // Left-Left case
                    Self::rotate_right(node, version)
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
                        version,
                        Some(new_left),
                        n.right.clone(),
                    );
                    Self::balance(Arc::new(new_node), version)
                }
                Ordering::Greater => {
                    let new_right = Self::insert(n.right.clone(), key, value, version);
                    let new_node = Self::with_children(
                        n.key.clone(),
                        n.value.clone(),
                        version,
                        n.left.clone(),
                        Some(new_right),
                    );
                    Self::balance(Arc::new(new_node), version)
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
    fn remove(node: Option<Arc<IAVLNode>>, key: &[u8], version: u64) -> Option<Arc<IAVLNode>> {
        node.and_then(|n| match key.cmp(&n.key) {
            Ordering::Less => {
                let new_left = Self::remove(n.left.clone(), key, version);
                let new_node = Self::with_children(
                    n.key.clone(),
                    n.value.clone(),
                    version,
                    new_left,
                    n.right.clone(),
                );
                Some(Self::balance(Arc::new(new_node), version))
            }
            Ordering::Greater => {
                let new_right = Self::remove(n.right.clone(), key, version);
                let new_node = Self::with_children(
                    n.key.clone(),
                    n.value.clone(),
                    version,
                    n.left.clone(),
                    new_right,
                );
                Some(Self::balance(Arc::new(new_node), version))
            }
            Ordering::Equal => match (n.left.clone(), n.right.clone()) {
                (None, None) => None,
                (Some(left), None) => Some(left),
                (None, Some(right)) => Some(right),
                (Some(left), Some(right)) => {
                    let min_right = Self::find_min(&right);
                    let new_right = Self::remove(Some(right), &min_right.key, version);
                    let new_node = Self::with_children(
                        min_right.key.clone(),
                        min_right.value.clone(),
                        version,
                        Some(left),
                        new_right,
                    );
                    Some(Self::balance(Arc::new(new_node), version))
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
            Ordering::Equal => {
                if n.is_leaf() {
                    Some(n.value.clone())
                } else {
                    // Same convention as proof descent: go LEFT on equal
                    Self::get(&n.left, key)
                }
            }
        })
    }

    /// Recursively scan the tree for keys matching a prefix.
    fn range_scan(
        node: &Option<Arc<IAVLNode>>,
        prefix: &[u8],
        results: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) {
        if let Some(n) = node {
            if n.key.as_slice() >= prefix {
                Self::range_scan(&n.left, prefix, results);
            }
            if n.key.starts_with(prefix) {
                results.push((n.key.clone(), n.value.clone()));
            }
            if prefix.starts_with(&n.key) || n.key.as_slice() < prefix {
                Self::range_scan(&n.right, prefix, results);
            }
        }
    }
}

/// IAVL tree implementation
#[derive(Debug, Clone)]
pub struct IAVLTree<CS: CommitmentScheme> {
    root: Option<Arc<IAVLNode>>,
    version: u64,
    versions: HashMap<u64, Arc<IAVLNode>>,
    roots: HashMap<Vec<u8>, u64>,
    rev: HashMap<u64, Vec<u8>>,
    scheme: CS,
    cache: HashMap<Vec<u8>, Vec<u8>>,
}

impl<CS: CommitmentScheme> IAVLTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + std::fmt::Debug,
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
{
    pub fn new(scheme: CS) -> Self {
        let mut tree = Self {
            root: None,
            version: 0,
            versions: HashMap::new(),
            roots: HashMap::new(),
            rev: HashMap::new(),
            scheme,
            cache: HashMap::new(),
        };
        tree.commit();
        tree
    }

    fn commit(&mut self) -> Vec<u8> {
        let commitment_bytes = self.root_commitment().as_ref().to_vec();
        maybe_assert_snapshot_consistent(&self.root);
        if self.root.is_some() {
            log::debug!(
                "[IAVL Commit] Storing root for version {}: hash={}",
                self.version,
                hex::encode(&commitment_bytes)
            );
        } else {
            log::debug!(
                "[IAVL Commit] Storing empty root for version {}: hash={}",
                self.version,
                hex::encode(&commitment_bytes)
            );
        }
        if let Some(root_node) = self.root.clone() {
            self.versions.insert(self.version, root_node);
        }
        self.roots.insert(commitment_bytes.clone(), self.version);
        self.rev.insert(self.version, commitment_bytes.clone());
        self.version += 1;
        commitment_bytes
    }

    fn to_value(&self, value: &[u8]) -> CS::Value {
        CS::Value::from(value.to_vec())
    }

    fn get_from_cache(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.cache.get(key).cloned()
    }

    pub(crate) fn build_proof_for_root(
        &self,
        root_node: Option<Arc<IAVLNode>>,
        key: &[u8],
    ) -> Option<CS::Proof> {
        let proof = if IAVLNode::get(&root_node, key).is_some() {
            self.build_existence_proof_from_root(root_node, key)
                .map(proof::IavlProof::Existence)
        } else {
            self.build_non_existence_proof_from_root(root_node, key)
                .map(proof::IavlProof::NonExistence)
        }?;

        let proof_data = serde_json::to_vec(&proof).ok()?;
        let value = self.to_value(&proof_data);
        self.scheme
            .create_proof(&Selector::Key(key.to_vec()), &value)
            .ok()
    }

    fn build_existence_proof_from_root(
        &self,
        start_node: Option<Arc<IAVLNode>>,
        key: &[u8],
    ) -> Option<ExistenceProof> {
        let mut path = Vec::new();
        let mut current_node_opt = start_node;

        while let Some(current_node) = current_node_opt {
            match key.cmp(&current_node.key) {
                Ordering::Less => {
                    let sibling_hash = current_node
                        .right
                        .as_ref()
                        .map(|sib| sib.hash.clone())
                        .unwrap_or_else(IAVLNode::empty_hash);

                    #[cfg(feature = "strict_iavl")]
                    {
                        let rhs = current_node
                            .right
                            .as_ref()
                            .map(|n| n.compute_hash())
                            .unwrap_or_else(IAVLNode::empty_hash);
                        if sibling_hash != rhs {
                            log::error!(
                                "[IAVL STRICT][existence] Sibling hash drift @ split={}: cached={} strict={}",
                                hex::encode(&current_node.key),
                                hex::encode(&sibling_hash),
                                hex::encode(&rhs),
                            );
                            panic!("IAVL strict sibling hash mismatch (right).");
                        }
                    }

                    path.push(InnerOp {
                        version: current_node.version,
                        height: current_node.height,
                        size: current_node.size,
                        split_key: current_node.key.clone(),
                        side: Side::Right,
                        sibling_hash: sibling_hash.try_into().unwrap(),
                    });
                    current_node_opt = current_node.left.clone();
                }
                Ordering::Greater => {
                    let sibling_hash = current_node
                        .left
                        .as_ref()
                        .map(|sib| sib.hash.clone())
                        .unwrap_or_else(IAVLNode::empty_hash);

                    #[cfg(feature = "strict_iavl")]
                    {
                        let lhs = current_node
                            .left
                            .as_ref()
                            .map(|n| n.compute_hash())
                            .unwrap_or_else(IAVLNode::empty_hash);
                        if sibling_hash != lhs {
                            log::error!(
                                "[IAVL STRICT][existence] Sibling hash drift @ split={}: cached={} strict={}",
                                hex::encode(&current_node.key),
                                hex::encode(&sibling_hash),
                                hex::encode(&lhs),
                            );
                            panic!("IAVL strict sibling hash mismatch (left).");
                        }
                    }

                    path.push(InnerOp {
                        version: current_node.version,
                        height: current_node.height,
                        size: current_node.size,
                        split_key: current_node.key.clone(),
                        side: Side::Left,
                        sibling_hash: sibling_hash.try_into().unwrap(),
                    });
                    current_node_opt = current_node.right.clone();
                }
                Ordering::Equal => {
                    if current_node.is_leaf() {
                        path.reverse();
                        return Some(ExistenceProof {
                            key: current_node.key.clone(),
                            value: current_node.value.clone(),
                            leaf: LeafOp {
                                version: current_node.version,
                            },
                            path,
                        });
                    } else {
                        // IMPORTANT: descend deterministically on equal.
                        // With the common convention "node.key = max(left-subtree)",
                        // the exact key lies in the LEFT subtree.
                        let sibling_hash = current_node
                            .right
                            .as_ref()
                            .map(|sib| sib.hash.clone())
                            .unwrap_or_else(IAVLNode::empty_hash);

                        #[cfg(feature = "strict_iavl")]
                        {
                            let rhs = current_node
                                .right
                                .as_ref()
                                .map(|n| n.compute_hash())
                                .unwrap_or_else(IAVLNode::empty_hash);
                            if sibling_hash != rhs {
                                log::error!(
                                    "[IAVL STRICT][existence-eq] Sibling hash drift @ split={}: cached={} strict={}",
                                    hex::encode(&current_node.key),
                                    hex::encode(&sibling_hash),
                                    hex::encode(&rhs),
                                );
                                panic!("IAVL strict sibling hash mismatch (equal/right).");
                            }
                        }

                        // Record this hop, then continue down LEFT
                        path.push(InnerOp {
                            version: current_node.version,
                            height: current_node.height,
                            size: current_node.size,
                            split_key: current_node.key.clone(),
                            side: Side::Right, // sibling is on the RIGHT
                            sibling_hash: sibling_hash.try_into().unwrap(),
                        });
                        current_node_opt = current_node.left.clone();
                        continue; // don't finalize yet
                    }
                }
            };
        }
        None
    }

    fn build_non_existence_proof_from_root(
        &self,
        start_node: Option<Arc<IAVLNode>>,
        key: &[u8],
    ) -> Option<NonExistenceProof> {
        let left_key = self.find_predecessor(&start_node, key);
        let right_key = self.find_successor(&start_node, key);
        if left_key.is_none() && right_key.is_none() {
            return Some(NonExistenceProof {
                missing_key: key.to_vec(),
                left: None,
                right: None,
            });
        }
        let left_proof =
            left_key.and_then(|k| self.build_existence_proof_from_root(start_node.clone(), &k));
        let right_proof =
            right_key.and_then(|k| self.build_existence_proof_from_root(start_node, &k));
        Some(NonExistenceProof {
            missing_key: key.to_vec(),
            left: left_proof,
            right: right_proof,
        })
    }

    fn find_predecessor(&self, start_node: &Option<Arc<IAVLNode>>, key: &[u8]) -> Option<Vec<u8>> {
        let mut current = start_node.as_ref();
        let mut predecessor = None;
        while let Some(node) = current {
            match key.cmp(&node.key) {
                Ordering::Greater => {
                    predecessor = Some(node.key.clone());
                    current = node.right.as_ref();
                }
                _ => {
                    current = node.left.as_ref();
                }
            }
        }
        predecessor
    }

    fn find_successor(&self, start_node: &Option<Arc<IAVLNode>>, key: &[u8]) -> Option<Vec<u8>> {
        let mut current = start_node.as_ref();
        let mut successor = None;
        while let Some(node) = current {
            match key.cmp(&node.key) {
                Ordering::Less => {
                    successor = Some(node.key.clone());
                    current = node.left.as_ref();
                }
                _ => {
                    current = node.right.as_ref();
                }
            }
        }
        successor
    }
}

impl<CS: CommitmentScheme> StateCommitment for IAVLTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + std::fmt::Debug,
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
{
    type Commitment = CS::Commitment;
    type Proof = CS::Proof;
    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
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
        if let Some(value) = self.get_from_cache(key) {
            Ok(Some(value))
        } else {
            Ok(IAVLNode::get(&self.root, key))
        }
    }
    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        self.root = IAVLNode::remove(self.root.clone(), key, self.version);
        self.cache.remove(key);
        Ok(())
    }
    fn root_commitment(&self) -> Self::Commitment {
        let root_hash = self
            .root
            .as_ref()
            .map(|n| n.hash.clone())
            .unwrap_or_else(IAVLNode::empty_hash);
        <CS as CommitmentScheme>::Commitment::from(root_hash)
    }
    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        self.build_proof_for_root(self.root.clone(), key)
    }
    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8],
    ) -> bool {
        let root_hash: &[u8; 32] = match commitment.as_ref().try_into() {
            Ok(arr) => arr,
            Err(_) => return false,
        };
        let proof_data = proof.as_ref();
        match proof::verify_iavl_proof_bytes(root_hash, key, Some(value), proof_data) {
            Ok(is_valid) => is_valid,
            Err(e) => {
                log::warn!("IAVL proof verification failed with error: {}", e);
                false
            }
        }
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
        let mut results = Vec::new();
        IAVLNode::range_scan(&self.root, prefix, &mut results);
        Ok(results)
    }
}

impl<CS: CommitmentScheme> StateManager for IAVLTree<CS>
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
        let root_bytes = root.as_ref();
        let head = if root_bytes.len() >= 16 {
            &root_bytes[..16]
        } else {
            root_bytes
        };
        log::debug!("[IAVL] get_with_proof_at: root query={}", hex::encode(head));
        let version = self.roots.get(root_bytes).ok_or_else(|| {
            StateError::Backend(format!(
                "Root commitment {} not found in versioned history (commit_version() missing?)",
                hex::encode(root_bytes)
            ))
        })?;
        let historical_root_node = self.versions.get(version);

        maybe_assert_snapshot_consistent(&historical_root_node.cloned());

        if let Some(hrn) = historical_root_node {
            let strict_root = recompute_hash_strict(hrn);
            if strict_root.as_slice() != root_bytes {
                eprintln!(
                    "[IAVL DRIFT@ROOT]\n\
                     version={} key_head={}...\n\
                     requested_root={} \n\
                     strict_root   ={}",
                    version,
                    hex::encode(&hrn.key.get(..4).unwrap_or_default()),
                    hex::encode(root_bytes),
                    hex::encode(&strict_root),
                );
                panic!(
                    "IAVL strict root hash does not match requested commitment. See details above."
                );
            }
        }

        let membership = match IAVLNode::get(&historical_root_node.cloned(), key) {
            Some(value) => Membership::Present(value),
            None => Membership::Absent,
        };
        let proof = self
            .build_proof_for_root(historical_root_node.cloned(), key)
            .ok_or_else(|| StateError::Backend("Failed to generate IAVL proof".to_string()))?;

        {
            let expected_value = membership.clone().into_option();
            let root_hash: &[u8; 32] = root_bytes
                .try_into()
                .expect("Root must be 32 bytes for self-check");
            let proof_bytes = proof.as_ref();
            match verify_iavl_proof_bytes(root_hash, key, expected_value.as_deref(), proof_bytes) {
                Ok(true) => log::debug!(
                    "[IAVL Server]   -> SELF-VERIFICATION PASSED against root {}",
                    hex::encode(root_hash)
                ),
                _ => {
                    // NEW: detailed fold trace from the serialized proof
                    if let Ok(p) = serde_json::from_slice::<proof::IavlProof>(proof_bytes) {
                        if let proof::IavlProof::Existence(ep) = p {
                            use crate::tree::iavl::proof::{hash_inner, hash_leaf, Side};
                            let leaf_val = expected_value.as_deref().unwrap_or(&[]);
                            let mut acc = hash_leaf(&ep.leaf, key, leaf_val);
                            log::error!(
                                "[IAVL Builder][trace] leaf={:.8}",
                                hex::encode(acc).get(..8).unwrap_or("")
                            );
                            for (i, step) in ep.path.iter().enumerate() {
                                let (left, right) = match step.side {
                                    Side::Left => (step.sibling_hash, acc),
                                    Side::Right => (acc, step.sibling_hash),
                                };
                                let newh = hash_inner(step, &left, &right);
                                log::error!(
                                    "[IAVL Builder][trace] i={} side={:?} split={:.8} h={} sz={} acc={:.8} sib={:.8} -> new={:.8}",
                                    i + 1, step.side,
                                    hex::encode(&step.split_key).get(..8).unwrap_or(""),
                                    step.height, step.size,
                                    hex::encode(acc).get(..8).unwrap_or(""),
                                    hex::encode(step.sibling_hash).get(..8).unwrap_or(""),
                                    hex::encode(&newh).get(..8).unwrap_or(""),
                                );
                                acc = newh;
                            }
                            log::error!("[IAVL Builder][trace] final={}", hex::encode(acc));
                            log::error!("[IAVL Builder][trace] trusted={}", hex::encode(root_hash));
                        }
                    }

                    log::error!(
                      "[IAVL Builder] Proof failed to anchor at version {} (key={}): returning error",
                      version, hex::encode(key)
                    );
                    return Err(StateError::Backend(
                        "Failed to generate anchored IAVL proof".to_string(),
                    ));
                }
            }
        }
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
    fn prune(&mut self, min_height_to_keep: u64) -> Result<(), StateError> {
        let versions_to_prune: Vec<u64> = self
            .versions
            .keys()
            .filter(|&&v| v < min_height_to_keep)
            .cloned()
            .collect();
        if !versions_to_prune.is_empty() {
            log::info!(
                "[IAVLTree] Pruning {} old versions.",
                versions_to_prune.len()
            );
            for version in versions_to_prune {
                if self.versions.remove(&version).is_some() {
                    if let Some(commitment) = self.rev.remove(&version) {
                        self.roots.remove(&commitment);
                    }
                }
            }
        }
        Ok(())
    }
    fn commit_version(&mut self) {
        let root = <Self as StateCommitment>::root_commitment(self);
        let hex_preview = if root.as_ref().len() >= 16 {
            &root.as_ref()[..16]
        } else {
            root.as_ref()
        };
        log::debug!(
            "[IAVL] commit_version: root={}, version={}",
            hex::encode(hex_preview),
            self.version
        );
        let _ = self.commit();
    }
    fn version_exists_for_root(&self, root: &Self::Commitment) -> bool {
        self.roots.contains_key(root.as_ref())
    }
}
