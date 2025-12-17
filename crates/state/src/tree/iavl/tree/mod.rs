// Path: crates/state/src/tree/iavl/tree/mod.rs

//! The core IAVLTree implementation. This version is store-aware and uses lazy-loading
//! (demand-faulting) for its nodes, making it suitable for persistent state management.
//! Children are referenced by hash, and nodes are fetched from a cache or the underlying
//! `NodeStore` on-demand during traversal.

use super::indices::Indices;
use super::node::{IAVLNode, NodeHash, EMPTY_HASH};
use super::{proof, proof_builder};
use crate::tree::iavl::proof::IavlProof;
use ioi_api::commitment::CommitmentScheme;
use ioi_api::state::{
    ProofProvider, PrunePlan, StateAccess, StateManager, StateScanIter, VerifiableState,
};
use ioi_api::storage::NodeStore;
use ioi_storage::adapter::{commit_and_persist, DeltaAccumulator};
use ioi_types::app::{to_root_hash, Membership, RootHash};
use ioi_types::error::StateError;
use ioi_types::prelude::OptionExt;
use parity_scale_codec::Decode;
use std::any::Any;
use std::cmp::{max, Ordering};
use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::sync::Arc;
use async_trait::async_trait;

/// Calculates the lexicographical successor of a byte slice.
/// Returns `None` if the slice is all `0xFF` bytes, as there is no successor.
fn lexicographical_successor(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.is_empty() {
        return None;
    }
    let mut successor = bytes.to_vec();
    for i in (0..successor.len()).rev() {
        if let Some(byte) = successor.get_mut(i) {
            if *byte != 0xFF {
                *byte = byte.wrapping_add(1);
                successor.truncate(i + 1);
                return Some(successor);
            }
        }
    }
    // All bytes were 0xFF, no successor exists in this byte space.
    None
}

/// IAVL tree implementation, now store-aware and lazy-loading.
#[derive(Clone)]
pub struct IAVLTree<CS: CommitmentScheme> {
    /// The hash of the root node. This is the primary handle to the tree's state.
    pub(super) root_hash: Option<NodeHash>,
    /// Cache for decoded nodes from the store or newly created nodes for the current version.
    node_cache: HashMap<NodeHash, Arc<IAVLNode>>,
    pub(super) current_height: u64,
    pub(super) indices: Indices,
    pub(super) scheme: CS,
    /// Key-value cache for the latest version, for fast lookups on recently modified data.
    pub(super) kv_cache: HashMap<Vec<u8>, Vec<u8>>,
    pub(super) delta: DeltaAccumulator,
    pub(super) store: Option<Arc<dyn NodeStore>>,
}

impl<CS: CommitmentScheme> Debug for IAVLTree<CS> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IAVLTree")
            .field("root_hash", &self.root_hash.map(hex::encode))
            .field("node_cache_len", &self.node_cache.len())
            .field("current_height", &self.current_height)
            .field("indices", &self.indices)
            .field("scheme", &"...")
            .field("kv_cache_len", &self.kv_cache.len())
            .field("delta", &self.delta)
            .field("store_is_some", &self.store.is_some())
            .finish()
    }
}

impl<CS: CommitmentScheme> IAVLTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + Debug,
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
{
    /// Creates a new, empty IAVLTree.
    pub fn new(scheme: CS) -> Self {
        Self {
            root_hash: None,
            node_cache: HashMap::new(),
            current_height: 0,
            indices: Indices::default(),
            scheme,
            kv_cache: HashMap::new(),
            delta: DeltaAccumulator::default(),
            store: None,
        }
    }

    /// A recursive helper for `prefix_scan` to traverse the tree and collect all key-value pairs
    /// that fall within a given lexicographical range `[start, end)`.
    fn collect_prefix_range(
        &self,
        node_hash_opt: Option<NodeHash>,
        start: &[u8],
        end_opt: Option<&[u8]>,
        prefix: &[u8],
        out: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<(), StateError> {
        let Some(node_hash) = node_hash_opt else {
            return Ok(());
        };

        let Some(node) = self.get_node(node_hash)? else {
            return Ok(());
        };

        if node.is_leaf() {
            let k = node.key.as_slice();
            // Check if the leaf's key falls within our desired range AND starts with the prefix.
            if k >= start && end_opt.map_or(true, |end| k < end) && k.starts_with(prefix) {
                out.push((node.key.clone(), node.value.clone()));
            }
            return Ok(());
        }

        // Inner node: use the split key to prune branches.
        // The invariant is: all keys in left <= split_key, all in right > split_key.
        let split_key = node.key.as_slice();

        // Traverse left subtree if its key range can overlap with [start, end).
        // This is true if `start` is less than or equal to the `split_key`.
        if start <= split_key {
            self.collect_prefix_range(node.left_hash, start, end_opt, prefix, out)?;
        }

        // Traverse right subtree if its key range can overlap with [start, end).
        // This is true unless the `end` bound is set and is less than or equal to the `split_key`.
        match end_opt {
            Some(end) if end <= split_key => {
                // Prune: The entire right subtree is > split_key >= end, so it's out of range.
            }
            _ => {
                // No upper bound, or the upper bound is greater than the split key, so we must traverse.
                self.collect_prefix_range(node.right_hash, start, end_opt, prefix, out)?;
            }
        }

        Ok(())
    }

    pub(super) fn to_value(&self, value: &[u8]) -> CS::Value {
        CS::Value::from(value.to_vec())
    }

    /// The core lazy-loading method. Fetches a node by its hash, consulting the cache first,
    /// then falling back to the persistent store.
    pub(super) fn get_node(&self, hash: NodeHash) -> Result<Option<Arc<IAVLNode>>, StateError> {
        if hash == EMPTY_HASH {
            return Ok(None);
        }
        if let Some(node) = self.node_cache.get(&hash) {
            return Ok(Some(node.clone()));
        }
        if let Some(store) = &self.store {
            let epoch = store.epoch_of(self.current_height);
            if let Some(bytes) =
                super::store_proof::fetch_node_any_epoch(store.as_ref(), epoch, hash)?
            {
                let decoded = super::encode::decode_node(&bytes)
                    .ok_or(StateError::Decode("Invalid node encoding in store".into()))?;
                let node = IAVLNode::from_decoded(decoded)?;
                // NOTE: This method is on &self, so we cannot warm the mutable cache here.
                return Ok(Some(Arc::new(node)));
            }
        }
        Ok(None)
    }

    /// Get the height of a node by hash. Returns -1 for an empty node.
    fn node_height(&self, hash_opt: Option<NodeHash>) -> Result<i32, StateError> {
        Ok(hash_opt
            .and_then(|h| self.get_node(h).transpose())
            .transpose()?
            .map_or(-1, |n| n.height))
    }

    /// Get the size of a node by hash. Returns 0 for an empty node.
    fn node_size(&self, hash_opt: Option<NodeHash>) -> Result<u64, StateError> {
        Ok(hash_opt
            .and_then(|h| self.get_node(h).transpose())
            .transpose()?
            .map_or(0, |n| n.size))
    }

    /// Find the node with the maximum key in the subtree rooted at `hash`.
    pub(super) fn find_max(&self, hash: NodeHash) -> Result<Arc<IAVLNode>, StateError> {
        let mut node = self.get_node(hash)?.required(StateError::KeyNotFound)?;
        while let Some(right_hash) = node.right_hash {
            node = self
                .get_node(right_hash)?
                .required(StateError::KeyNotFound)?;
        }
        Ok(node)
    }

    /// Find the node with the minimum key in the subtree rooted at `hash`.
    pub(super) fn find_min(&self, hash: NodeHash) -> Result<Arc<IAVLNode>, StateError> {
        let mut node = self.get_node(hash)?.required(StateError::KeyNotFound)?;
        while let Some(left_hash) = node.left_hash {
            node = self
                .get_node(left_hash)?
                .required(StateError::KeyNotFound)?;
        }
        Ok(node)
    }

    /// Create a new inner node, compute its hash, and cache it.
    fn create_inner_node(
        &mut self,
        left_hash: Option<NodeHash>,
        right_hash: Option<NodeHash>,
    ) -> Result<NodeHash, StateError> {
        let key = if let Some(lh) = left_hash {
            self.find_max(lh)?.key.clone()
        } else {
            Vec::new()
        };
        let height = 1 + max(self.node_height(left_hash)?, self.node_height(right_hash)?);
        let size = 1 + self.node_size(left_hash)? + self.node_size(right_hash)?;
        let mut node = IAVLNode {
            key,
            value: Vec::new(),
            version: self.current_height,
            height,
            size,
            hash: EMPTY_HASH,
            left_hash,
            right_hash,
        };
        node.hash = node.compute_hash()?;
        let hash = node.hash;
        self.node_cache.insert(hash, Arc::new(node));
        Ok(hash)
    }

    /// Recursive helper for `get`.
    pub(super) fn get_recursive(
        &self,
        node_hash_opt: Option<NodeHash>,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, StateError> {
        let Some(node_hash) = node_hash_opt else {
            return Ok(None);
        };
        let Some(node) = self.get_node(node_hash)? else {
            return Ok(None);
        };

        if node.is_leaf() {
            if key == node.key.as_slice() {
                Ok(Some(node.value.clone()))
            } else {
                Ok(None)
            }
        } else if key <= node.key.as_slice() {
            self.get_recursive(node.left_hash, key)
        } else {
            self.get_recursive(node.right_hash, key)
        }
    }

    /// Recursive helper for `insert`. Returns the hash of the new subtree root.
    fn insert_recursive(
        &mut self,
        node_hash_opt: Option<NodeHash>,
        key: &[u8],
        value: &[u8],
        depth: usize,
    ) -> Result<NodeHash, StateError> {
        let Some(node_hash) = node_hash_opt else {
            let new_leaf = IAVLNode::new_leaf(key.to_vec(), value.to_vec(), self.current_height)?;
            let new_hash = new_leaf.hash;
            self.node_cache.insert(new_hash, Arc::new(new_leaf));
            return Ok(new_hash);
        };

        let node = self
            .get_node(node_hash)?
            .required(StateError::KeyNotFound)?;

        if node.is_leaf() {
            match key.cmp(&node.key) {
                Ordering::Equal => {
                    let new_leaf =
                        IAVLNode::new_leaf(key.to_vec(), value.to_vec(), self.current_height)?;
                    let new_hash = new_leaf.hash;
                    self.node_cache.insert(new_hash, Arc::new(new_leaf));
                    Ok(new_hash)
                }
                Ordering::Less => {
                    let new_leaf =
                        IAVLNode::new_leaf(key.to_vec(), value.to_vec(), self.current_height)?;
                    self.node_cache
                        .insert(new_leaf.hash, Arc::new(new_leaf.clone()));
                    self.create_inner_node(Some(new_leaf.hash), Some(node.hash))
                }
                Ordering::Greater => {
                    let new_leaf =
                        IAVLNode::new_leaf(key.to_vec(), value.to_vec(), self.current_height)?;
                    self.node_cache
                        .insert(new_leaf.hash, Arc::new(new_leaf.clone()));
                    self.create_inner_node(Some(node.hash), Some(new_leaf.hash))
                }
            }
        } else {
            let (new_left, new_right) = if key <= node.key.as_slice() {
                (
                    Some(self.insert_recursive(node.left_hash, key, value, depth + 1)?),
                    node.right_hash,
                )
            } else {
                (
                    node.left_hash,
                    Some(self.insert_recursive(node.right_hash, key, value, depth + 1)?),
                )
            };
            let new_node_hash = self.create_inner_node(new_left, new_right)?;
            self.balance(new_node_hash)
        }
    }

    /// Recursive helper to remove a key and return the new subtree hash, or `None` if the subtree becomes empty.
    fn remove_recursive(
        &mut self,
        node_hash_opt: Option<NodeHash>,
        key: &[u8],
        depth: usize,
    ) -> Result<Option<NodeHash>, StateError> {
        let Some(node_hash) = node_hash_opt else {
            return Ok(None);
        };
        let node = self
            .get_node(node_hash)?
            .required(StateError::KeyNotFound)?;

        match key.cmp(&node.key) {
            Ordering::Less if !node.is_leaf() => {
                let new_left = self.remove_recursive(node.left_hash, key, depth + 1)?;
                if new_left == node.left_hash {
                    return Ok(Some(node_hash));
                }
                let new_node_hash = self.create_inner_node(new_left, node.right_hash)?;
                self.balance(new_node_hash).map(Some)
            }
            Ordering::Greater if !node.is_leaf() => {
                let new_right = self.remove_recursive(node.right_hash, key, depth + 1)?;
                if new_right == node.right_hash {
                    return Ok(Some(node_hash));
                }
                let new_node_hash = self.create_inner_node(node.left_hash, new_right)?;
                self.balance(new_node_hash).map(Some)
            }
            Ordering::Equal => {
                // Found the key to delete
                if node.is_leaf() {
                    Ok(None) // Deleting a leaf removes it entirely.
                } else {
                    match (node.left_hash, node.right_hash) {
                        (Some(left), None) => Ok(Some(left)),
                        (None, Some(right)) => Ok(Some(right)),
                        (Some(left), Some(right)) => {
                            let successor = self.find_min(right)?;
                            let new_right =
                                self.remove_recursive(Some(right), &successor.key, depth + 1)?;

                            let new_height = 1 + max(
                                self.node_height(Some(left))?,
                                self.node_height(new_right)?,
                            );
                            let new_size =
                                1 + self.node_size(Some(left))? + self.node_size(new_right)?;
                            let mut new_node = IAVLNode {
                                key: successor.key.clone(),
                                value: successor.value.clone(),
                                version: self.current_height,
                                height: new_height,
                                size: new_size,
                                hash: EMPTY_HASH,
                                left_hash: Some(left),
                                right_hash: new_right,
                            };
                            new_node.hash = new_node.compute_hash()?;
                            let new_hash = new_node.hash;
                            self.node_cache.insert(new_hash, Arc::new(new_node));
                            self.balance(new_hash).map(Some)
                        }
                        (None, None) => Ok(None), // Should be unreachable for an inner node.
                    }
                }
            }
            _ => Ok(Some(node_hash)), // Key not found, tree is unchanged.
        }
    }

    /// Performs AVL rotations to balance the subtree rooted at `node_hash`.
    fn balance(&mut self, node_hash: NodeHash) -> Result<NodeHash, StateError> {
        let node = self
            .get_node(node_hash)?
            .required(StateError::KeyNotFound)?;
        let bf = self.node_height(node.right_hash)? - self.node_height(node.left_hash)?;

        if bf > 1 {
            // Right-heavy
            let right_node = node
                .right_hash
                .and_then(|h| self.get_node(h).ok().flatten())
                .required(StateError::KeyNotFound)?;
            if self.node_height(right_node.right_hash)? - self.node_height(right_node.left_hash)?
                < 0
            {
                // RL case
                let new_right_hash = self.rotate_right(right_node.hash)?;
                let new_root_hash = self.create_inner_node(node.left_hash, Some(new_right_hash))?;
                return self.rotate_left(new_root_hash);
            }
            // RR case
            return self.rotate_left(node.hash);
        }
        if bf < -1 {
            // Left-heavy
            let left_node = node
                .left_hash
                .and_then(|h| self.get_node(h).ok().flatten())
                .required(StateError::KeyNotFound)?;
            if self.node_height(left_node.right_hash)? - self.node_height(left_node.left_hash)? > 0
            {
                // LR case
                let new_left_hash = self.rotate_left(left_node.hash)?;
                let new_root_hash = self.create_inner_node(Some(new_left_hash), node.right_hash)?;
                return self.rotate_right(new_root_hash);
            }
            // LL case
            return self.rotate_right(node.hash);
        }
        Ok(node_hash)
    }

    /// Performs a single left rotation.
    fn rotate_left(&mut self, node_hash: NodeHash) -> Result<NodeHash, StateError> {
        let node = self
            .get_node(node_hash)?
            .required(StateError::KeyNotFound)?;
        let r_hash = node.right_hash.required(StateError::KeyNotFound)?;
        let r_node = self.get_node(r_hash)?.required(StateError::KeyNotFound)?;
        let new_left_hash = self.create_inner_node(node.left_hash, r_node.left_hash)?;
        self.create_inner_node(Some(new_left_hash), r_node.right_hash)
    }

    /// Performs a single right rotation.
    fn rotate_right(&mut self, node_hash: NodeHash) -> Result<NodeHash, StateError> {
        let node = self
            .get_node(node_hash)?
            .required(StateError::KeyNotFound)?;
        let l_hash = node.left_hash.required(StateError::KeyNotFound)?;
        let l_node = self.get_node(l_hash)?.required(StateError::KeyNotFound)?;
        let new_right_hash = self.create_inner_node(l_node.right_hash, node.right_hash)?;
        self.create_inner_node(l_node.left_hash, Some(new_right_hash))
    }

    /// Collects all new nodes from the current version's operations into the delta accumulator.
    fn collect_height_delta(&mut self) -> Result<(), StateError> {
        for (hash, node) in &self.node_cache {
            let bytes = super::encode::encode_node_canonical(node)?;
            self.delta.record_new(*hash, bytes);
        }
        Ok(())
    }

    pub async fn commit_version_with_store<S: NodeStore + ?Sized>(
        &mut self,
        height: u64,
        store: &S,
    ) -> Result<RootHash, StateError>
    where
        CS::Witness: Default,
    {
        self.current_height = height;
        self.collect_height_delta()?;
        let root_hash = self.root_hash.unwrap_or(EMPTY_HASH);
        commit_and_persist(store, height, root_hash, &self.delta)
            .await
            .map_err(|e| ioi_types::error::StateError::Backend(e.to_string()))?;
        self.delta.clear();

        // Let the StateManager logic update indices, refcounts, etc.
        let _ = <Self as StateManager>::commit_version(self, height)?;

        // Now that everything is persisted, it is safe to drop the caches.
        self.node_cache.clear();
        self.kv_cache.clear();

        Ok(root_hash)
    }
}

impl<CS: CommitmentScheme> StateAccess for IAVLTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + Debug,
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
{
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        if let Some(value) = self.kv_cache.get(key) {
            return Ok(Some(value.clone()));
        }
        self.get_recursive(self.root_hash, key)
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.root_hash = Some(self.insert_recursive(self.root_hash, key, value, 0)?);
        self.kv_cache.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        self.root_hash = self.remove_recursive(self.root_hash, key, 0)?;
        self.kv_cache.remove(key);
        Ok(())
    }

    fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
        let mut committed_kvs = Vec::new();

        // 1. Calculate the lexicographical range for the prefix.
        let start = prefix.to_vec();
        let end_opt_vec = lexicographical_successor(prefix);
        let end_opt = end_opt_vec.as_deref();

        // 2. Traverse the tree using the range to collect committed values, with pruning.
        self.collect_prefix_range(self.root_hash, &start, end_opt, prefix, &mut committed_kvs)?;

        // 3. Merge with the in-memory cache to include uncommitted changes from the current block.
        // This creates a unified view of both committed and pending state.
        let mut merged: BTreeMap<Vec<u8>, Vec<u8>> = committed_kvs.into_iter().collect();
        for (k, v) in &self.kv_cache {
            if k.starts_with(prefix) {
                merged.insert(k.clone(), v.clone());
            }
        }

        // 4. BTreeMap automatically handles sorting and uniqueness. Convert to the required iterator type.
        let iter = merged
            .into_iter()
            .map(|(k, v)| Ok((Arc::from(k), Arc::from(v))));
        Ok(Box::new(iter))
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
}

impl<CS: CommitmentScheme> VerifiableState for IAVLTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + Debug,
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
{
    type Commitment = CS::Commitment;
    type Proof = CS::Proof;

    fn root_commitment(&self) -> Self::Commitment {
        let root_hash = self.root_hash.unwrap_or(EMPTY_HASH);
        CS::Commitment::from(root_hash.to_vec())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

impl<CS: CommitmentScheme> ProofProvider for IAVLTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + Debug,
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
    CS::Witness: Default,
{
    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        proof_builder::build_proof_for_root(self, self.root_hash, key)
    }

    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), StateError> {
        let root_hash: &[u8; 32] = commitment
            .as_ref()
            .try_into()
            .map_err(|_| StateError::InvalidValue("Commitment is not 32 bytes".into()))?;
        let proof_data = proof.as_ref();

        let iavl_proof = IavlProof::decode(&mut &*proof_data)
            .map_err(|e| StateError::Validation(e.to_string()))?;
        match proof::verify_iavl_proof(root_hash, key, Some(value), &iavl_proof) {
            Ok(true) => Ok(()),
            Ok(false) => Err(StateError::Validation(
                "IAVL proof verification failed".into(),
            )),
            Err(e) => {
                log::warn!("IAVL proof verification failed with error: {}", e);
                Err(StateError::Validation(e.to_string()))
            }
        }
    }

    fn get_with_proof_at(
        &self,
        root: &Self::Commitment,
        key: &[u8],
    ) -> Result<(Membership, Self::Proof), StateError> {
        let root_hash = to_root_hash(root.as_ref())?;

        // The logic for historical proofs remains. All queries for a committed root are
        // treated as historical, ensuring consistency between the chain's self-check and
        // external verifiers.
        if let Some(store) = &self.store {
            self.build_proof_from_store_at(store.as_ref(), root_hash, key)
        } else {
            Err(StateError::StaleAnchor)
        }
    }

    fn commitment_from_anchor(&self, anchor: &[u8; 32]) -> Option<Self::Commitment> {
        self.commitment_from_bytes(anchor).ok()
    }

    fn commitment_from_bytes(&self, bytes: &[u8]) -> Result<Self::Commitment, StateError> {
        Ok(CS::Commitment::from(bytes.to_vec()))
    }

    fn commitment_to_bytes(&self, c: &Self::Commitment) -> Vec<u8> {
        c.as_ref().to_vec()
    }
}

#[async_trait]
impl<CS: CommitmentScheme> StateManager for IAVLTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + Debug,
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
    CS::Witness: Default,
{
    fn prune(&mut self, plan: &PrunePlan) -> Result<(), StateError> {
        let to_prune: Vec<u64> = self
            .indices
            .versions_by_height
            .range(..plan.cutoff_height)
            .filter_map(|(h, _)| if plan.excludes(*h) { None } else { Some(*h) })
            .collect();

        for h in to_prune {
            if let Some(root_hash) = self.indices.versions_by_height.remove(&h) {
                self.indices.decrement_refcount(root_hash);
            }
        }
        Ok(())
    }

    fn prune_batch(&mut self, plan: &PrunePlan, limit: usize) -> Result<usize, StateError> {
        let to_prune: Vec<u64> = self
            .indices
            .versions_by_height
            .range(..plan.cutoff_height)
            .filter_map(|(h, _)| if plan.excludes(*h) { None } else { Some(*h) })
            .take(limit)
            .collect();

        let pruned_count = to_prune.len();
        if pruned_count > 0 {
            for h in to_prune {
                if let Some(root_hash) = self.indices.versions_by_height.remove(&h) {
                    self.indices.decrement_refcount(root_hash);
                }
            }
        }
        Ok(pruned_count)
    }

    fn commit_version(&mut self, height: u64) -> Result<RootHash, StateError> {
        self.current_height = height;
        let root_hash = self.root_hash.unwrap_or(EMPTY_HASH);

        if let Some(previous_root_for_height) =
            self.indices.versions_by_height.insert(height, root_hash)
        {
            if previous_root_for_height != root_hash {
                self.indices.decrement_refcount(previous_root_for_height);
            }
        }

        let count = self.indices.root_refcount.entry(root_hash).or_insert(0);
        if *count == 0 && root_hash != EMPTY_HASH {
            if let Some(root_node) = self.node_cache.get(&root_hash) {
                self.indices
                    .roots
                    .insert(root_hash, Some(root_node.clone()));
            } else {
                log::error!(
                    "IAVLTree commit_version: current root hash {} not found in node_cache!",
                    hex::encode(root_hash)
                );
            }
        }
        *count += 1;

        // This logic is now moved to `commit_version_with_store`
        // self.node_cache.clear();
        // self.kv_cache.clear();

        Ok(root_hash)
    }

    fn version_exists_for_root(&self, root: &Self::Commitment) -> bool {
        if let Ok(root_hash) = to_root_hash(root.as_ref()) {
            self.indices.roots.contains_key(&root_hash)
        } else {
            false
        }
    }

    async fn commit_version_persist(
        &mut self,
        height: u64,
        store: &dyn NodeStore,
    ) -> Result<RootHash, StateError> {
        self.commit_version_with_store(height, store).await
    }

    fn adopt_known_root(&mut self, root_bytes: &[u8], version: u64) -> Result<(), StateError> {
        let root_hash = to_root_hash(root_bytes)?;

        self.root_hash = Some(root_hash);
        self.node_cache.clear();
        self.kv_cache.clear();

        self.indices.versions_by_height.insert(version, root_hash);
        if !self.indices.roots.contains_key(&root_hash) {
            self.indices.roots.insert(root_hash, None);
        }
        *self.indices.root_refcount.entry(root_hash).or_insert(0) += 1;

        if self.current_height < version {
            self.current_height = version;
        }

        Ok(())
    }

    fn attach_store(&mut self, store: Arc<dyn NodeStore>) {
        self.store = Some(store);
    }

    fn begin_block_writes(&mut self, height: u64) {
        self.current_height = height;
    }
}

#[cfg(test)]
mod tests;