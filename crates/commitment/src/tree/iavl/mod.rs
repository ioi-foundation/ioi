// Path: crates/commitment/src/tree/iavl/mod.rs
//! IAVL (Immutable AVL) tree implementation with cryptographic security

mod proof;
pub mod verifier;

use crate::tree::iavl::proof::{
    verify_iavl_proof_bytes, ExistenceProof, InnerOp, LeafOp, NonExistenceProof, Side,
};
use depin_sdk_api::commitment::{CommitmentScheme, Selector};
use depin_sdk_api::state::{PrunePlan, StateCommitment, StateManager, StateScanIter};
use depin_sdk_api::storage::{NodeHash as StoreNodeHash, NodeStore};
use depin_sdk_storage::adapter::{commit_and_persist, DeltaAccumulator};
use depin_sdk_types::app::{to_root_hash, Membership, RootHash};
use depin_sdk_types::error::StateError;
use depin_sdk_types::prelude::OptionExt;
use std::any::Any;
use std::cmp::{max, Ordering};
use std::collections::{BTreeMap, HashMap};
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

/// Encodes an `IAVLNode` into its canonical byte format, which is the preimage for its hash.
fn encode_node_canonical(n: &IAVLNode) -> Result<Vec<u8>, StateError> {
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
        let left = n
            .left
            .as_ref()
            .map(|x| x.hash.clone())
            .unwrap_or_else(IAVLNode::empty_hash);
        let right = n
            .right
            .as_ref()
            .map(|x| x.hash.clone())
            .unwrap_or_else(IAVLNode::empty_hash);
        data.extend_from_slice(&left);
        data.extend_from_slice(&right);
    }
    Ok(data)
}

impl IAVLNode {
    /// Create a new leaf node
    fn new_leaf(key: Vec<u8>, value: Vec<u8>, version: u64) -> Result<Self, StateError> {
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
        node.hash = node.compute_hash()?;
        Ok(node)
    }

    /// Compute the hash of this node according to the canonical specification.
    fn compute_hash(&self) -> Result<Vec<u8>, StateError> {
        let data = encode_node_canonical(self)?;
        depin_sdk_crypto::algorithms::hash::sha256(&data)
            .map(|h| h.to_vec())
            .map_err(|e| StateError::Backend(e.to_string()))
    }

    /// Provides the canonical hash of an empty/nil child node.
    fn empty_hash() -> Vec<u8> {
        depin_sdk_crypto::algorithms::hash::sha256([])
            .unwrap_or_else(|e| {
                log::error!("CRITICAL: SHA256 of empty slice should not fail: {}", e);
                [0u8; 32]
            })
            .to_vec()
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

    /// Create a new node with updated children, recomputing the split key.
    fn with_children(
        _key: Vec<u8>, // Key is ignored and recomputed from left subtree
        value: Vec<u8>,
        version: u64,
        left: Option<Arc<IAVLNode>>,
        right: Option<Arc<IAVLNode>>,
    ) -> Result<Self, StateError> {
        let key = if let Some(l) = &left {
            // The check `if !(l.is_leaf() || l.right.is_some())` was here, but it was based on a faulty
            // assumption about IAVL invariants. An inner node's left child is allowed to not have a
            // right child, as `find_max` will correctly traverse its left side. Removing this check
            // fixes the erroneous validation failure during rebalancing.
            Self::find_max(l).key.clone()
        } else {
            // If left is None, an inner node has no split key according to the invariant.
            // This case should not be hit if tree is constructed correctly.
            Vec::new()
        };
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
        node.hash = node.compute_hash()?;
        Ok(node)
    }

    /// Balance factor (right height - left height)
    fn balance_factor(&self) -> i32 {
        Self::node_height(&self.right) - Self::node_height(&self.left)
    }

    /// Single left rotation (RR case around `node`)
    /// Invariant: all internal node values are empty Vec and split_key is recomputed.
    fn rotate_left(node: Arc<IAVLNode>, version: u64) -> Result<Arc<IAVLNode>, StateError> {
        let r = node
            .right
            .as_ref()
            .required(StateError::Validation(
                "rotate_left requires right child".into(),
            ))?
            .clone();

        // New left child of root after rotation is the old node with its right -> r.left
        let new_left = Arc::new(Self::with_children(
            Vec::new(), // split key recomputed from left
            Vec::new(), // inner nodes carry no value
            version,
            node.left.clone(),
            r.left.clone(),
        )?);

        // New root: r with left = new_left, right = r.right
        Ok(Arc::new(Self::with_children(
            Vec::new(),
            Vec::new(),
            version,
            Some(new_left),
            r.right.clone(),
        )?))
    }

    /// Single right rotation (LL case around `node`)
    fn rotate_right(node: Arc<IAVLNode>, version: u64) -> Result<Arc<IAVLNode>, StateError> {
        let l = node
            .left
            .as_ref()
            .required(StateError::Validation(
                "rotate_right requires left child".into(),
            ))?
            .clone();

        // New right child of root after rotation is the old node with its left -> l.right
        let new_right = Arc::new(Self::with_children(
            Vec::new(),
            Vec::new(),
            version,
            l.right.clone(),
            node.right.clone(),
        )?);

        // New root: l with left = l.left, right = new_right
        Ok(Arc::new(Self::with_children(
            Vec::new(),
            Vec::new(),
            version,
            l.left.clone(),
            Some(new_right),
        )?))
    }

    /// AVL rebalancing that preserves split-key invariant by always rebuilding nodes
    /// with `with_children` (which recomputes `split_key = max(left)`).
    fn balance(mut node: Arc<IAVLNode>, version: u64) -> Result<Arc<IAVLNode>, StateError> {
        let bf = node.balance_factor();

        // Right-heavy
        if bf > 1 {
            // If right-left case: rotate right on right child first
            if let Some(r) = &node.right {
                if r.balance_factor() < 0 {
                    let rotated_right = Self::rotate_right(r.clone(), version)?;
                    node = Arc::new(Self::with_children(
                        Vec::new(),
                        Vec::new(),
                        version,
                        node.left.clone(),
                        Some(rotated_right),
                    )?);
                }
            }
            return Self::rotate_left(node, version);
        }

        // Left-heavy
        if bf < -1 {
            // If left-right case: rotate left on left child first
            if let Some(l) = &node.left {
                if l.balance_factor() > 0 {
                    let rotated_left = Self::rotate_left(l.clone(), version)?;
                    node = Arc::new(Self::with_children(
                        Vec::new(),
                        Vec::new(),
                        version,
                        Some(rotated_left),
                        node.right.clone(),
                    )?);
                }
            }
            return Self::rotate_right(node, version);
        }

        // Already balanced
        Ok(node)
    }

    /// Insert a key-value pair into the tree
    fn insert(
        node: Option<Arc<IAVLNode>>,
        key: Vec<u8>,
        value: Vec<u8>,
        version: u64,
    ) -> Result<Arc<IAVLNode>, StateError> {
        match node {
            None => Ok(Arc::new(Self::new_leaf(key, value, version)?)),
            Some(n) => {
                if n.is_leaf() {
                    match key.cmp(&n.key) {
                        Ordering::Less => {
                            let new_leaf = Arc::new(Self::new_leaf(key, value, version)?);
                            let old_leaf = n; // n is already Arc<IAVLNode>
                            Ok(Arc::new(Self::with_children(
                                Vec::new(), // Split key will be recomputed
                                Vec::new(), // Inner nodes have no value
                                version,
                                Some(new_leaf),
                                Some(old_leaf),
                            )?))
                        }
                        Ordering::Greater => {
                            let new_leaf = Arc::new(Self::new_leaf(key, value, version)?);
                            let old_leaf = n;
                            Ok(Arc::new(Self::with_children(
                                Vec::new(), // Split key will be recomputed
                                Vec::new(), // Inner nodes have no value
                                version,
                                Some(old_leaf),
                                Some(new_leaf),
                            )?))
                        }
                        Ordering::Equal => {
                            // Update existing leaf
                            Ok(Arc::new(Self::new_leaf(n.key.clone(), value, version)?))
                        }
                    }
                } else {
                    // Internal node logic
                    let (new_left, new_right) = if key <= n.key {
                        // Recurse left
                        (
                            Some(Self::insert(n.left.clone(), key, value, version)?),
                            n.right.clone(),
                        )
                    } else {
                        // Recurse right
                        (
                            n.left.clone(),
                            Some(Self::insert(n.right.clone(), key, value, version)?),
                        )
                    };
                    let new_node = Self::with_children(
                        Vec::new(), // recompute
                        Vec::new(), // no value
                        version,
                        new_left,
                        new_right,
                    )?;
                    Self::balance(Arc::new(new_node), version)
                }
            }
        }
    }

    /// Remove a key from the tree
    fn remove(
        node: Option<Arc<IAVLNode>>,
        key: &[u8],
        version: u64,
    ) -> Result<Option<Arc<IAVLNode>>, StateError> {
        match node {
            None => Ok(None),
            Some(n) => match key.cmp(&n.key) {
                Ordering::Less => {
                    let new_left = Self::remove(n.left.clone(), key, version)?;
                    let new_node = Self::with_children(
                        n.key.clone(),
                        n.value.clone(),
                        version,
                        new_left,
                        n.right.clone(),
                    )?;
                    Self::balance(Arc::new(new_node), version).map(Some)
                }
                Ordering::Greater => {
                    let new_right = Self::remove(n.right.clone(), key, version)?;
                    let new_node = Self::with_children(
                        n.key.clone(),
                        n.value.clone(),
                        version,
                        n.left.clone(),
                        new_right,
                    )?;
                    Self::balance(Arc::new(new_node), version).map(Some)
                }
                Ordering::Equal => match (n.left.clone(), n.right.clone()) {
                    (None, None) => Ok(None),
                    (Some(left), None) => Ok(Some(left)),
                    (None, Some(right)) => Ok(Some(right)),
                    (Some(left), Some(right)) => {
                        let min_right = Self::find_min(&right);
                        let new_right = Self::remove(Some(right), &min_right.key, version)?;
                        let new_node = Self::with_children(
                            min_right.key.clone(),
                            min_right.value.clone(),
                            version,
                            Some(left),
                            new_right,
                        )?;
                        Self::balance(Arc::new(new_node), version).map(Some)
                    }
                },
            },
        }
    }

    /// Find the minimum node in a subtree
    fn find_min(node: &Arc<IAVLNode>) -> Arc<IAVLNode> {
        node.left
            .as_ref()
            .map_or_else(|| node.clone(), Self::find_min)
    }

    /// Find the maximum node in a subtree
    fn find_max(node: &Arc<IAVLNode>) -> Arc<IAVLNode> {
        node.right
            .as_ref()
            .map_or_else(|| node.clone(), Self::find_max)
    }

    /// Get a value by key
    fn get(node: &Option<Arc<IAVLNode>>, key: &[u8]) -> Option<Vec<u8>> {
        node.as_ref().and_then(|n| {
            if n.is_leaf() {
                if key == n.key.as_slice() {
                    Some(n.value.clone())
                } else {
                    None
                }
            } else if key <= n.key.as_slice() {
                Self::get(&n.left, key)
            } else {
                Self::get(&n.right, key)
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
            if n.is_leaf() {
                if n.key.starts_with(prefix) {
                    results.push((n.key.clone(), n.value.clone()));
                }
            } else {
                // Go left if the prefix is less than or equal to the split key.
                // This means there could be matching keys in the left subtree.
                if prefix <= n.key.as_slice() {
                    Self::range_scan(&n.left, prefix, results);
                }

                // Go right if the prefix is greater than the split key, OR if the split
                // key itself starts with the prefix. The latter case is crucial because
                // longer keys with the same prefix could exist in the right subtree.
                if prefix > n.key.as_slice() || n.key.starts_with(prefix) {
                    Self::range_scan(&n.right, prefix, results);
                }
            }
        }
    }
}

/// IAVL tree implementation
#[derive(Clone)]
pub struct IAVLTree<CS: CommitmentScheme> {
    root: Option<Arc<IAVLNode>>,
    current_height: u64,
    indices: Indices,
    scheme: CS,
    cache: HashMap<Vec<u8>, Vec<u8>>,
    delta: DeltaAccumulator,
    store: Option<Arc<dyn NodeStore>>,
}

impl<CS: CommitmentScheme> std::fmt::Debug for IAVLTree<CS> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IAVLTree")
            .field("root", &self.root)
            .field("current_height", &self.current_height)
            .field("indices", &self.indices)
            .field("scheme", &"...")
            .field("cache_len", &self.cache.len())
            .field("delta", &self.delta)
            .field("store_is_some", &self.store.is_some())
            .finish()
    }
}

#[derive(Debug, Clone, Default)]
struct Indices {
    versions_by_height: BTreeMap<u64, RootHash>,
    root_refcount: HashMap<RootHash, u32>,
    roots: HashMap<RootHash, Option<Arc<IAVLNode>>>,
}

// A parsed inner/leaf view (no allocations beyond what's necessary)
#[derive(Clone)]
struct DecodedNode {
    is_leaf: bool,
    version: u64,
    height: i32,
    size: u64,
    split_key: Vec<u8>,   // for inner
    key: Vec<u8>,         // for leaf
    value: Vec<u8>,       // for leaf
    left_hash: [u8; 32],  // for inner
    right_hash: [u8; 32], // for inner
}

// minimal decoder matching `encode_node_canonical`
fn decode_node(bytes: &[u8]) -> Option<DecodedNode> {
    let mut rd = bytes;
    let mut take = |n: usize| -> Option<&[u8]> {
        if rd.len() < n {
            return None;
        }
        let (a, b) = rd.split_at(n);
        rd = b;
        Some(a)
    };
    let tag = *take(1)?.get(0)?;
    let ver = u64::from_le_bytes(take(8)?.try_into().ok()?);
    if tag == 0x00 {
        let _height = i32::from_le_bytes(take(4)?.try_into().ok()?); // 0
        let _size = u64::from_le_bytes(take(8)?.try_into().ok()?); // 1
        let klen = u32::from_le_bytes(take(4)?.try_into().ok()?) as usize;
        let key = take(klen)?.to_vec();
        let vlen = u32::from_le_bytes(take(4)?.try_into().ok()?) as usize;
        let value = take(vlen)?.to_vec();
        Some(DecodedNode {
            is_leaf: true,
            version: ver,
            height: 0,
            size: 1,
            split_key: Vec::new(),
            key,
            value,
            left_hash: [0u8; 32],
            right_hash: [0u8; 32],
        })
    } else {
        let h = i32::from_le_bytes(take(4)?.try_into().ok()?);
        let sz = u64::from_le_bytes(take(8)?.try_into().ok()?);
        let klen = u32::from_le_bytes(take(4)?.try_into().ok()?) as usize;
        let split = take(klen)?.to_vec();
        let mut lh = [0u8; 32];
        lh.copy_from_slice(take(32)?);
        let mut rh = [0u8; 32];
        rh.copy_from_slice(take(32)?);
        Some(DecodedNode {
            is_leaf: false,
            version: ver,
            height: h,
            size: sz,
            split_key: split,
            key: Vec::new(),
            value: Vec::new(),
            left_hash: lh,
            right_hash: rh,
        })
    }
}

impl<CS: CommitmentScheme> IAVLTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + std::fmt::Debug,
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
{
    pub fn new(scheme: CS) -> Self {
        Self {
            root: None,
            current_height: 0,
            indices: Indices::default(),
            scheme,
            cache: HashMap::new(),
            delta: DeltaAccumulator::default(),
            store: None,
        }
    }

    /// Build a proof for `key` at `root_hash32` by lazily fetching nodes from `store`.
    /// Returns (Membership, Proof) on success.
    pub fn build_proof_from_store_at<S: NodeStore + ?Sized>(
        &self,
        store: &S,
        root_hash32: [u8; 32],
        key: &[u8],
    ) -> Result<(Membership, CS::Proof), StateError> {
        // 1) Find height/epoch for this root so we know which shard to query
        let height = store
            .height_for_root(depin_sdk_api::storage::RootHash(root_hash32))
            .map_err(|e| StateError::Backend(e.to_string()))?
            .ok_or_else(|| StateError::UnknownAnchor(hex::encode(root_hash32)))?;

        let epoch = store.epoch_of(height);

        // 2) Fetch & decode the root node
        let mut cur_hash = root_hash32;
        let mut path: Vec<InnerOp> = Vec::new();

        // We’ll walk until we hit a leaf or fail to descend.
        loop {
            let node_bytes = Self::fetch_node_any_epoch(store, epoch, cur_hash)?
                .ok_or_else(|| StateError::Backend("Missing node bytes in store".into()))?;

            let node = decode_node(&node_bytes)
                .ok_or_else(|| StateError::Decode("Invalid node encoding".into()))?;

            if node.is_leaf {
                if node.key.as_slice() == key {
                    // Build existence proof
                    path.reverse();
                    let leaf = LeafOp {
                        version: node.version,
                    };
                    let existence = ExistenceProof {
                        key: node.key.clone(),
                        value: node.value.clone(),
                        leaf,
                        path,
                    };
                    let proof_obj = proof::IavlProof::Existence(existence);
                    let proof_bytes = serde_json::to_vec(&proof_obj)
                        .map_err(|e| StateError::Backend(e.to_string()))?;
                    let proof_value = self.to_value(&proof_bytes);
                    let scheme_proof = self
                        .scheme
                        .create_proof(&Selector::Key(key.to_vec()), &proof_value)
                        .map_err(|e| StateError::Backend(format!("Failed to wrap proof: {}", e)))?;
                    return Ok((Membership::Present(node.value), scheme_proof));
                } else {
                    // non-existence: we must supply at least one neighbor proof
                    let (left_neighbor, right_neighbor) = self
                        .find_neighbors_from_store(store, epoch, root_hash32, key)
                        .map_err(StateError::Backend)?;

                    let non_existence = NonExistenceProof {
                        missing_key: key.to_vec(),
                        left: left_neighbor,
                        right: right_neighbor,
                    };

                    if non_existence.left.is_none() && non_existence.right.is_none() {
                        return Err(StateError::Backend(
                            "Unable to construct neighbor proof for non-existence".into(),
                        ));
                    }

                    let proof_obj = proof::IavlProof::NonExistence(non_existence);
                    let proof_bytes = serde_json::to_vec(&proof_obj)
                        .map_err(|e| StateError::Backend(e.to_string()))?;
                    let proof_value = self.to_value(&proof_bytes);
                    let scheme_proof = self
                        .scheme
                        .create_proof(&Selector::Key(key.to_vec()), &proof_value)
                        .map_err(|e| StateError::Backend(format!("Failed to wrap proof: {}", e)))?;
                    return Ok((Membership::Absent, scheme_proof));
                }
            } else {
                // inner: decide direction; record sibling as an InnerOp step
                let (next_hash, side, sib_hash) = if key <= node.split_key.as_slice() {
                    (node.left_hash, Side::Right, node.right_hash)
                } else {
                    (node.right_hash, Side::Left, node.left_hash)
                };

                path.push(InnerOp {
                    version: node.version,
                    height: node.height,
                    size: node.size,
                    split_key: node.split_key.clone(),
                    side,
                    sibling_hash: sib_hash,
                });
                cur_hash = next_hash;
            }
        }
    }

    /// Explore to get predecessor/successor proofs by walking subtrees in the opposite side.
    fn find_neighbors_from_store<S: NodeStore + ?Sized>(
        &self,
        store: &S,
        epoch: u64,
        root_hash: [u8; 32],
        key: &[u8],
    ) -> Result<(Option<ExistenceProof>, Option<ExistenceProof>), String> {
        let fetch = |h: [u8; 32]| -> Result<DecodedNode, String> {
            let bytes = Self::fetch_node_any_epoch(store, epoch, h)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "Missing node".to_string())?;
            decode_node(&bytes).ok_or_else(|| "Decode error".to_string())
        };

        let build_extreme = |start_hash: [u8; 32],
                             mut base_path: Vec<InnerOp>,
                             go_right: bool|
         -> Result<ExistenceProof, String> {
            let mut n = fetch(start_hash)?;
            loop {
                if n.is_leaf {
                    break;
                }
                if go_right {
                    base_path.push(InnerOp {
                        version: n.version,
                        height: n.height,
                        size: n.size,
                        split_key: n.split_key.clone(),
                        side: Side::Left,
                        sibling_hash: n.left_hash,
                    });
                    n = fetch(n.right_hash)?;
                } else {
                    base_path.push(InnerOp {
                        version: n.version,
                        height: n.height,
                        size: n.size,
                        split_key: n.split_key.clone(),
                        side: Side::Right,
                        sibling_hash: n.right_hash,
                    });
                    n = fetch(n.left_hash)?;
                }
            }
            base_path.reverse();
            Ok(ExistenceProof {
                key: n.key.clone(),
                value: n.value.clone(),
                leaf: LeafOp { version: n.version },
                path: base_path,
            })
        };

        let mut current_hash = root_hash;
        let mut path: Vec<InnerOp> = Vec::new();
        let mut pred_candidate = None;
        let mut succ_candidate = None;

        while let Ok(node) = fetch(current_hash) {
            if node.is_leaf {
                break;
            }
            if key <= node.split_key.as_slice() {
                succ_candidate = Some((node.right_hash, path.clone()));
                path.push(InnerOp {
                    version: node.version,
                    height: node.height,
                    size: node.size,
                    split_key: node.split_key.clone(),
                    side: Side::Right,
                    sibling_hash: node.right_hash,
                });
                current_hash = node.left_hash;
            } else {
                pred_candidate = Some((node.left_hash, path.clone()));
                path.push(InnerOp {
                    version: node.version,
                    height: node.height,
                    size: node.size,
                    split_key: node.split_key.clone(),
                    side: Side::Left,
                    sibling_hash: node.left_hash,
                });
                current_hash = node.right_hash;
            }
        }

        let left_proof = pred_candidate.and_then(|(h, p)| build_extreme(h, p, true).ok());
        let right_proof = succ_candidate.and_then(|(h, p)| build_extreme(h, p, false).ok());

        Ok((left_proof, right_proof))
    }

    fn decrement_refcount(&mut self, root_hash: RootHash) {
        if let Some(c) = self.indices.root_refcount.get_mut(&root_hash) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                self.indices.root_refcount.remove(&root_hash);
                self.indices.roots.remove(&root_hash);
            }
        }
    }

    fn to_value(&self, value: &[u8]) -> CS::Value {
        CS::Value::from(value.to_vec())
    }

    fn fetch_node_any_epoch<S: NodeStore + ?Sized>(
        store: &S,
        prefer_epoch: u64,
        hash: [u8; 32],
    ) -> Result<Option<Vec<u8>>, StateError> {
        // Try the preferred epoch first, then walk backwards to 0.
        if let Some(bytes) = store
            .get_node(prefer_epoch, StoreNodeHash(hash))
            .map_err(|e| StateError::Backend(e.to_string()))?
        {
            return Ok(Some(bytes));
        }

        // If not found, scan earlier epochs until we find it.
        // (Small networks/tests: this is fine. For prod, add a reverse index.)
        let (head_h, _) = store
            .head()
            .map_err(|e| StateError::Backend(e.to_string()))?;
        let head_epoch = store.epoch_of(head_h);

        let start = prefer_epoch.min(head_epoch);
        for e in (0..start).rev() {
            if let Some(bytes) = store
                .get_node(e, StoreNodeHash(hash))
                .map_err(|e| StateError::Backend(e.to_string()))?
            {
                return Ok(Some(bytes));
            }
        }
        Ok(None)
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
            if current_node.is_leaf() {
                if current_node.key == key {
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
                    return None; // Key not found
                }
            }

            // It's an internal node
            let (next_node, side, sibling_hash) = if key <= current_node.key.as_slice() {
                (
                    current_node.left.clone(),
                    Side::Right, // Sibling is on the right
                    current_node
                        .right
                        .as_ref()
                        .map(|n| n.hash.clone())
                        .unwrap_or_else(IAVLNode::empty_hash),
                )
            } else {
                (
                    current_node.right.clone(),
                    Side::Left, // Sibling is on the left
                    current_node
                        .left
                        .as_ref()
                        .map(|n| n.hash.clone())
                        .unwrap_or_else(IAVLNode::empty_hash),
                )
            };

            let sibling_hash_array: [u8; 32] = match sibling_hash.try_into() {
                Ok(arr) => arr,
                Err(_) => return None, // Or handle error appropriately
            };

            path.push(InnerOp {
                version: current_node.version,
                height: current_node.height,
                size: current_node.size,
                split_key: current_node.key.clone(),
                side,
                sibling_hash: sibling_hash_array,
            });
            current_node_opt = next_node;
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
            if node.is_leaf() {
                if node.key.as_slice() < key {
                    predecessor = Some(node.key.clone());
                }
                // Stop at leaves
                break;
            } else if node.key.as_slice() < key {
                predecessor = Some(node.key.clone());
                current = node.right.as_ref();
            } else {
                current = node.left.as_ref();
            }
        }
        predecessor
    }

    fn find_successor(&self, start_node: &Option<Arc<IAVLNode>>, key: &[u8]) -> Option<Vec<u8>> {
        let mut current = start_node.as_ref();
        let mut successor = None;
        while let Some(node) = current {
            if node.is_leaf() {
                if node.key.as_slice() > key {
                    successor = Some(node.key.clone());
                }
                break;
            } else if node.key.as_slice() >= key {
                successor = Some(node.key.clone());
                current = node.left.as_ref();
            } else {
                current = node.right.as_ref();
            }
        }
        successor
    }

    fn collect_height_delta(&mut self) -> Result<(), StateError> {
        let h = self.current_height;
        if let Some(root) = self.root.clone() {
            self.collect_from_node(&root, h)?;
        }
        Ok(())
    }

    fn collect_from_node(&mut self, n: &Arc<IAVLNode>, h: u64) -> Result<(), StateError> {
        if n.version == h {
            let bytes = encode_node_canonical(n)?;
            let mut nh = [0u8; 32];
            nh.copy_from_slice(&n.hash);
            self.delta.record_new(nh, bytes);
        } else {
            let mut nh = [0u8; 32];
            nh.copy_from_slice(&n.hash);
            self.delta.record_touch(nh);
        }
        if let Some(l) = &n.left {
            self.collect_from_node(l, h)?;
        }
        if let Some(r) = &n.right {
            self.collect_from_node(r, h)?;
        }
        Ok(())
    }

    /// The adapter entry point. Pass a NodeStore handle from the workload.
    pub fn commit_version_with_store<S: NodeStore + ?Sized>(
        &mut self,
        height: u64,
        store: &S,
    ) -> Result<[u8; 32], depin_sdk_types::error::StateError> {
        self.current_height = height;
        self.collect_height_delta()?;
        let root_hash = to_root_hash(self.root_commitment().as_ref())?;
        commit_and_persist(store, height, root_hash, &self.delta)
            .map_err(|e| depin_sdk_types::error::StateError::Backend(e.to_string()))?;
        self.delta.clear();
        let _ = <Self as depin_sdk_api::state::StateManager>::commit_version(self, height)?;
        Ok(root_hash)
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
            self.current_height,
        )?);
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
        self.root = IAVLNode::remove(self.root.clone(), key, self.current_height)?;
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
    ) -> Result<(), StateError> {
        let root_hash: &[u8; 32] = commitment
            .as_ref()
            .try_into()
            .map_err(|_| StateError::InvalidValue("Commitment is not 32 bytes".into()))?;
        let proof_data = proof.as_ref();
        match verify_iavl_proof_bytes(root_hash, key, Some(value), proof_data) {
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
    fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
        // Collect results eagerly for now, but return a streaming iterator over the collection.
        // A true streaming iterator for an AVL tree is complex and will be a future optimization.
        let mut results = Vec::new();
        IAVLNode::range_scan(&self.root, prefix, &mut results);
        results.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let iter = results
            .into_iter()
            .map(|(k, v)| Ok((Arc::from(k), Arc::from(v))));
        Ok(Box::new(iter))
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
        let root_hash: RootHash = to_root_hash(root.as_ref())?;

        // If we have a materialized root node, use the fast in-memory path
        if let Some(historical_root_node) = self.indices.roots.get(&root_hash).cloned() {
            if historical_root_node.is_some() {
                let membership = match IAVLNode::get(&historical_root_node, key) {
                    Some(value) => Membership::Present(value),
                    None => Membership::Absent,
                };
                let proof = self
                    .build_proof_for_root(historical_root_node, key)
                    .required(StateError::Backend(
                        "Failed to generate IAVL proof".to_string(),
                    ))?;

                if !verify_iavl_proof_bytes(
                    &root_hash,
                    key,
                    membership.clone().into_option().as_deref(),
                    proof.as_ref(),
                )
                .map_err(|e| StateError::Validation(e.to_string()))?
                {
                    return Err(StateError::Backend(
                        "Failed to generate anchored IAVL proof".to_string(),
                    ));
                }
                return Ok((membership, proof));
            }
        }

        // Otherwise, hydrate the proof directly from store.
        if let Some(store) = &self.store {
            self.build_proof_from_store_at(store.as_ref(), root_hash, key)
        } else {
            Err(StateError::StaleAnchor)
        }
    }

    fn commitment_from_anchor(&self, anchor: &[u8; 32]) -> Option<Self::Commitment> {
        // For IAVL, the anchor is the commitment.
        self.commitment_from_bytes(anchor).ok()
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
    fn prune(&mut self, plan: &PrunePlan) -> Result<(), StateError> {
        let to_prune: Vec<u64> = self
            .indices
            .versions_by_height
            .range(..plan.cutoff_height)
            .filter_map(|(h, _)| if plan.excludes(*h) { None } else { Some(*h) })
            .collect();

        for h in to_prune {
            if let Some(root_hash) = self.indices.versions_by_height.remove(&h) {
                self.decrement_refcount(root_hash);
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
                    self.decrement_refcount(root_hash);
                }
            }
        }
        Ok(pruned_count)
    }

    fn commit_version(&mut self, height: u64) -> Result<RootHash, StateError> {
        let root_hash = to_root_hash(self.root_commitment().as_ref())?;

        match self.indices.versions_by_height.insert(height, root_hash) {
            // Case 1: This is a new height, or a reorg to a different root.
            None => {
                let count = self.indices.root_refcount.entry(root_hash).or_insert(0);
                if *count == 0 {
                    // First time seeing this root hash, store the actual node.
                    self.indices.roots.insert(root_hash, self.root.clone());
                }
                *count += 1;
            }
            Some(prev_root) if prev_root != root_hash => {
                // It's a reorg. Decrement the old root's count and increment the new one's.
                self.decrement_refcount(prev_root);

                let count = self.indices.root_refcount.entry(root_hash).or_insert(0);
                if *count == 0 {
                    self.indices.roots.insert(root_hash, self.root.clone());
                }
                *count += 1;
            }
            // Case 2: Same root hash was already recorded for this height. Do nothing.
            Some(_prev_same_root) => {
                // The refcount for this root is already correct for this height. No-op.
            }
        }

        self.current_height = height;
        Ok(root_hash)
    }

    fn version_exists_for_root(&self, root: &Self::Commitment) -> bool {
        if let Ok(root_hash) = to_root_hash(root.as_ref()) {
            self.indices.roots.contains_key(&root_hash)
        } else {
            false
        }
    }

    fn commit_version_persist(
        &mut self,
        height: u64,
        store: &dyn NodeStore,
    ) -> Result<RootHash, StateError> {
        self.commit_version_with_store(height, store)
    }

    fn adopt_known_root(&mut self, root_bytes: &[u8], version: u64) -> Result<(), StateError> {
        let root_hash = to_root_hash(root_bytes)?;

        // The purpose of this function is to make the state manager aware of a version
        // that exists *only in durable storage*. We populate the version-to-root mapping
        // and the refcount, but critically, we DO NOT insert into `self.indices.roots`.
        // This ensures that a subsequent `get_with_proof_at` for this root will fail
        // the in-memory lookup and correctly fall back to the store-based proof builder.
        self.indices.versions_by_height.insert(version, root_hash);
        *self.indices.root_refcount.entry(root_hash).or_insert(0) += 1;

        // Ensure the tree's internal version counter is aligned with the recovered state.
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
