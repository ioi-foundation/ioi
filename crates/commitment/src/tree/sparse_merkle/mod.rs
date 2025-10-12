// Path: crates/commitment/src/tree/sparse_merkle/mod.rs

//! Sparse Merkle tree implementation with cryptographic security

pub mod verifier;

use depin_sdk_api::commitment::{CommitmentScheme, Selector};
use depin_sdk_api::state::{PrunePlan, StateCommitment, StateManager, StateScanIter};
// --- MODIFICATION: Add NodeHash import ---
use depin_sdk_api::storage::{NodeHash as StoreNodeHash, NodeStore};
use depin_sdk_storage::adapter::{commit_and_persist, DeltaAccumulator};
use depin_sdk_types::app::{to_root_hash, Membership, RootHash};
use depin_sdk_types::error::{ProofError, StateError};
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug; // <-- Import Debug trait
use std::sync::Arc;

/// Sparse Merkle tree node
#[derive(Clone, PartialEq, Serialize, Deserialize)] // <-- Remove Debug from derive
enum Node {
    Empty,
    Leaf {
        key: Vec<u8>,
        value: Vec<u8>,
        created_at: u64,
    },
    Branch {
        left: Arc<Node>,
        right: Arc<Node>,
        hash: [u8; 32],
        created_at: u64,
    },
}
// --- MODIFICATION: Manual Debug impl for Node ---
impl Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "Empty"),
            Self::Leaf {
                key,
                value,
                created_at,
            } => f
                .debug_struct("Leaf")
                .field("key", &hex::encode(key))
                .field("value", &hex::encode(value))
                .field("created_at", created_at)
                .finish(),
            Self::Branch {
                left,
                right,
                hash,
                created_at,
            } => f
                .debug_struct("Branch")
                .field("left", left)
                .field("right", right)
                .field("hash", &hex::encode(hash))
                .field("created_at", created_at)
                .finish(),
        }
    }
}

fn smt_encode_node(node: &Node) -> Vec<u8> {
    // FIX: Use a stable codec like bincode for canonical serialization.
    bincode::serialize(node).unwrap_or_default()
}

// --- MODIFICATION START: Add node decoder ---
fn smt_decode_node(bytes: &[u8]) -> Option<Node> {
    bincode::deserialize(bytes).ok()
}
// --- MODIFICATION END ---

impl Node {
    fn hash(&self) -> [u8; 32] {
        match self {
            Node::Empty => [0u8; 32], // Empty hash
            Node::Leaf { key, value, .. } => {
                let mut data = Vec::new();
                data.push(0x00); // Leaf prefix
                data.extend_from_slice(key);
                data.extend_from_slice(value);
                depin_sdk_crypto::algorithms::hash::sha256(&data).unwrap_or_else(|e| {
                    log::error!("CRITICAL: sha256 failed in Node::hash: {}", e);
                    [0u8; 32]
                })
            }
            Node::Branch { hash, .. } => *hash,
        }
    }

    fn compute_branch_hash(left: &Node, right: &Node) -> [u8; 32] {
        let mut data = Vec::new();
        data.push(0x01); // Branch prefix
        data.extend_from_slice(&left.hash());
        data.extend_from_slice(&right.hash());
        depin_sdk_crypto::algorithms::hash::sha256(&data).unwrap_or_else(|e| {
            log::error!(
                "CRITICAL: sha256 failed in Node::compute_branch_hash: {}",
                e
            );
            [0u8; 32]
        })
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
#[derive(Clone)] // <-- Remove Debug from derive
pub struct SparseMerkleTree<CS: CommitmentScheme> {
    root: Arc<Node>,
    scheme: CS,
    cache: HashMap<Vec<u8>, Vec<u8>>, // Key-value cache for efficient lookups
    indices: Indices,
    current_height: u64,
    delta: DeltaAccumulator,
    // --- MODIFICATION START: Add store field ---
    store: Option<Arc<dyn NodeStore>>,
    // --- MODIFICATION END ---
}

// --- MODIFICATION START: Manual Debug impl for SparseMerkleTree ---
impl<CS: CommitmentScheme> Debug for SparseMerkleTree<CS> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SparseMerkleTree")
            .field("root", &self.root)
            .field("scheme", &"...")
            .field("cache_len", &self.cache.len())
            .field("indices", &self.indices)
            .field("current_height", &self.current_height)
            .field("delta", &self.delta)
            .field("store_is_some", &self.store.is_some())
            .finish()
    }
}
// --- MODIFICATION END ---

#[derive(Debug, Clone, Default)]
struct Indices {
    versions_by_height: BTreeMap<u64, RootHash>,
    root_refcount: HashMap<RootHash, u32>,
    roots: HashMap<RootHash, Arc<Node>>,
}

impl<CS: CommitmentScheme> SparseMerkleTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    const TREE_HEIGHT: usize = 256; // For 256-bit keys

    /// Create a new sparse Merkle tree
    pub fn new(scheme: CS) -> Self {
        Self {
            root: Arc::new(Node::Empty),
            scheme,
            cache: HashMap::new(),
            indices: Indices::default(),
            current_height: 0,
            delta: DeltaAccumulator::default(),
            // --- MODIFICATION START: Initialize store to None ---
            store: None,
            // --- MODIFICATION END ---
        }
    }

    // --- MODIFICATION START: Add store-backed proof builder ---
    pub fn build_proof_from_store_at(
        &self,
        store: &dyn NodeStore,
        root_hash32: [u8; 32],
        key: &[u8],
    ) -> Result<SparseMerkleProof, StateError> {
        let height = store
            .height_for_root(depin_sdk_api::storage::RootHash(root_hash32))
            .map_err(|e| StateError::Backend(e.to_string()))?
            .ok_or_else(|| StateError::UnknownAnchor(hex::encode(root_hash32)))?;
        let epoch = store.epoch_of(height);

        let mut siblings = Vec::new();
        let mut current_hash = root_hash32;

        for depth in 0..Self::TREE_HEIGHT {
            if current_hash == Node::Empty.hash() {
                break;
            }
            let node_bytes = Self::fetch_node_any_epoch(store, epoch, current_hash)?
                .ok_or_else(|| StateError::Backend("Missing node bytes in store".into()))?;

            let node = smt_decode_node(&node_bytes)
                .ok_or_else(|| StateError::Decode("Invalid node encoding".into()))?;

            match node {
                Node::Empty => break,
                Node::Leaf { .. } => break,
                Node::Branch { left, right, .. } => {
                    if Self::get_bit(key, depth) {
                        siblings.push(left.hash().to_vec());
                        current_hash = right.hash();
                    } else {
                        siblings.push(right.hash().to_vec());
                        current_hash = left.hash();
                    }
                }
            }
        }

        let leaf = if current_hash != Node::Empty.hash() {
            let node_bytes = Self::fetch_node_any_epoch(store, epoch, current_hash)?
                .ok_or_else(|| StateError::Backend("Missing leaf node bytes".into()))?;
            let node = smt_decode_node(&node_bytes)
                .ok_or_else(|| StateError::Decode("Invalid leaf node encoding".into()))?;
            if let Node::Leaf { key, value, .. } = node {
                Some((key, value))
            } else {
                None
            }
        } else {
            None
        };

        Ok(SparseMerkleProof { siblings, leaf })
    }

    fn fetch_node_any_epoch(
        store: &dyn NodeStore,
        prefer_epoch: u64,
        hash: [u8; 32],
    ) -> Result<Option<Vec<u8>>, StateError> {
        if let Some(bytes) = store
            .get_node(prefer_epoch, StoreNodeHash(hash))
            .map_err(|e| StateError::Backend(e.to_string()))?
        {
            return Ok(Some(bytes));
        }
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
    // --- MODIFICATION END ---

    fn decrement_refcount(&mut self, root_hash: RootHash) {
        if let Some(c) = self.indices.root_refcount.get_mut(&root_hash) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                self.indices.root_refcount.remove(&root_hash);
                self.indices.roots.remove(&root_hash);
            }
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
        key.get(byte_index)
            .is_some_and(|&byte| (byte >> bit_index) & 1 == 1)
    }

    /// Update the tree with a new key-value pair
    #[allow(clippy::only_used_in_recursion)]
    fn update_node(
        &self,
        node: &Arc<Node>,
        key: &[u8],
        value: Option<&[u8]>,
        depth: usize,
    ) -> Arc<Node> {
        if depth >= Self::TREE_HEIGHT {
            return if let Some(v) = value {
                Arc::new(Node::Leaf {
                    key: key.to_vec(),
                    value: v.to_vec(),
                    created_at: self.current_height,
                })
            } else {
                Arc::new(Node::Empty)
            };
        }

        match node.as_ref() {
            Node::Empty => {
                if value.is_none() {
                    return Arc::new(Node::Empty);
                }
                // Path is empty. Create a new path of branches down to the leaf.
                let child = self.update_node(&Arc::new(Node::Empty), key, value, depth + 1);
                let bit = Self::get_bit(key, depth);
                let (left, right) = if bit {
                    (Arc::new(Node::Empty), child)
                } else {
                    (child, Arc::new(Node::Empty))
                };
                let hash = Node::compute_branch_hash(&left, &right);
                Arc::new(Node::Branch {
                    left,
                    right,
                    hash,
                    created_at: self.current_height,
                })
            }
            Node::Leaf {
                key: leaf_key,
                value: leaf_value,
                ..
            } => {
                if leaf_key == key {
                    // Exact key match: update the value or delete the leaf.
                    return if let Some(v) = value {
                        Arc::new(Node::Leaf {
                            key: key.to_vec(),
                            value: v.to_vec(),
                            created_at: self.current_height,
                        })
                    } else {
                        Arc::new(Node::Empty)
                    };
                }

                // A different key exists at this path. Split them into a new branch.
                // First, create a branch for the new key as if this spot were empty.
                let new_node_branch = self.update_node(&Arc::new(Node::Empty), key, value, depth);
                // Then, insert the old leaf into that new structure.
                self.update_node(&new_node_branch, leaf_key, Some(leaf_value), depth)
            }
            Node::Branch { left, right, .. } => {
                let bit = Self::get_bit(key, depth);
                let (new_left, new_right) = if bit {
                    (left.clone(), self.update_node(right, key, value, depth + 1))
                } else {
                    (self.update_node(left, key, value, depth + 1), right.clone())
                };

                if matches!(*new_left, Node::Empty) && matches!(*new_right, Node::Empty) {
                    Arc::new(Node::Empty)
                } else {
                    let hash = Node::compute_branch_hash(&new_left, &new_right);
                    Arc::new(Node::Branch {
                        left: new_left,
                        right: new_right,
                        hash,
                        created_at: self.current_height,
                    })
                }
            }
        }
    }

    /// Generate a proof for a key
    fn generate_proof(&self, key: &[u8]) -> SparseMerkleProof {
        let mut siblings = Vec::new();
        let mut current = self.root.clone();

        for depth in 0..Self::TREE_HEIGHT {
            match current.as_ref() {
                Node::Empty => break,
                Node::Leaf { .. } => {
                    break;
                }
                Node::Branch { left, right, .. } => {
                    let bit = Self::get_bit(key, depth);
                    if bit {
                        siblings.push(left.hash().to_vec());
                        current = right.clone();
                    } else {
                        siblings.push(right.hash().to_vec());
                        current = left.clone();
                    }
                }
            }
        }

        let leaf = if let Node::Leaf {
            key: leaf_key,
            value,
            ..
        } = current.as_ref()
        {
            Some((leaf_key.clone(), value.clone()))
        } else {
            None
        };

        SparseMerkleProof { siblings, leaf }
    }

    fn get_from_snapshot(node: &Arc<Node>, key: &[u8], depth: usize) -> Option<Vec<u8>> {
        match node.as_ref() {
            Node::Empty => None,
            Node::Leaf {
                key: k, value: v, ..
            } => (k.as_slice() == key).then(|| v.clone()),
            Node::Branch { left, right, .. } => {
                if Self::get_bit(key, depth) {
                    Self::get_from_snapshot(right, key, depth + 1)
                } else {
                    Self::get_from_snapshot(left, key, depth + 1)
                }
            }
        }
    }

    fn generate_proof_from_snapshot(start: &Arc<Node>, key: &[u8]) -> SparseMerkleProof {
        let mut siblings = Vec::new();
        let mut current = start.clone();
        for depth in 0..Self::TREE_HEIGHT {
            match current.as_ref() {
                Node::Empty => break,
                Node::Leaf { .. } => {
                    // Path terminates here. The verifier will determine if this is the
                    // target leaf or a witness for an absence proof.
                    break;
                }
                Node::Branch { left, right, .. } => {
                    if Self::get_bit(key, depth) {
                        siblings.push(left.hash().to_vec());
                        current = right.clone();
                    } else {
                        siblings.push(right.hash().to_vec());
                        current = left.clone();
                    }
                }
            }
        }

        let leaf = match current.as_ref() {
            Node::Leaf { key, value, .. } => Some((key.clone(), value.clone())),
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
    ) -> Result<bool, ProofError> {
        // Determine the starting hash for the fold-up based on the proof type.
        let leaf_hash = match (&proof.leaf, value) {
            // Case 1: Proving PRESENCE.
            // proof.leaf must be Some, value must be Some.
            // proof_key must equal the query key.
            (Some((proof_key, proof_value)), Some(val)) => {
                if proof_key != key || proof_value != val {
                    log::debug!("[SMT Verify] Presence proof failed: key or value mismatch.");
                    return Ok(false);
                }
                let mut data = Vec::with_capacity(1 + proof_key.len() + proof_value.len());
                data.push(0x00); // leaf prefix
                data.extend_from_slice(proof_key);
                data.extend_from_slice(proof_value);
                depin_sdk_crypto::algorithms::hash::sha256(&data)
                    .map_err(|e| ProofError::Crypto(e.to_string()))?
                    .to_vec()
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
                    return Ok(false);
                }
                let mut data = Vec::new();
                data.push(0x00); // leaf prefix
                data.extend_from_slice(witness_key);
                data.extend_from_slice(witness_value);
                depin_sdk_crypto::algorithms::hash::sha256(&data)
                    .map_err(|e| ProofError::Crypto(e.to_string()))?
                    .to_vec()
            }
            // All other combinations are invalid.
            _ => {
                log::debug!("[SMT Verify] Invalid proof/value combination.");
                return Ok(false);
            }
        };

        // Fold up the tree using the siblings from the proof.
        let mut acc = leaf_hash;
        let path_len = proof.siblings.len();
        for i in (0..path_len).rev() {
            let sib = proof.siblings.get(i).ok_or_else(|| {
                ProofError::InvalidExistence(
                    "Proof has fewer siblings than its path length indicates".into(),
                )
            })?;
            let mut data = Vec::with_capacity(1 + 32 + 32);
            data.push(0x01); // branch prefix
            if Self::get_bit(key, i) {
                data.extend_from_slice(sib);
                data.extend_from_slice(&acc);
            } else {
                data.extend_from_slice(&acc);
                data.extend_from_slice(sib);
            }
            acc = depin_sdk_crypto::algorithms::hash::sha256(&data)
                .map_err(|e| ProofError::Crypto(e.to_string()))?
                .to_vec();
        }

        Ok(acc.as_slice() == root_hash)
    }

    fn collect_height_delta(&mut self) {
        let h = self.current_height;
        let root_clone = self.root.clone();
        self.collect_from_node(&root_clone, h);
    }

    fn collect_from_node(&mut self, n: &Arc<Node>, h: u64) {
        match n.as_ref() {
            Node::Empty => {}
            Node::Leaf { created_at, .. } | Node::Branch { created_at, .. } => {
                let bytes = smt_encode_node(n.as_ref());
                let nh = n.hash();
                if *created_at == h {
                    self.delta.record_new(nh, bytes);
                } else {
                    self.delta.record_touch(nh);
                }
                if let Node::Branch { left, right, .. } = n.as_ref() {
                    self.collect_from_node(left, h);
                    self.collect_from_node(right, h);
                }
            }
        }
    }

    pub fn commit_version_with_store<S: NodeStore + ?Sized>(
        &mut self,
        height: u64,
        store: &S,
    ) -> Result<RootHash, StateError>
    where
        CS: CommitmentScheme,
        CS::Value: From<Vec<u8>> + AsRef<[u8]> + std::fmt::Debug,
        CS::Commitment: From<Vec<u8>>,
        CS::Proof: AsRef<[u8]>,
    {
        self.current_height = height;
        self.collect_height_delta();
        let root_hash = to_root_hash(self.root_commitment().as_ref())?;
        commit_and_persist(store, height, root_hash, &self.delta)
            .map_err(|e| depin_sdk_types::error::StateError::Backend(e.to_string()))?;
        self.delta.clear();
        let _ = <Self as StateManager>::commit_version(self, height)?;
        Ok(root_hash)
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
        <CS as CommitmentScheme>::Commitment::from(root_hash.to_vec())
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
    ) -> Result<(), StateError> {
        let root_hash = commitment.as_ref();
        let proof_data = proof.as_ref();

        let smt_proof: SparseMerkleProof = serde_json::from_slice(proof_data)
            .map_err(|e| StateError::InvalidValue(e.to_string()))?;

        match Self::verify_proof_static(root_hash, key, Some(value), &smt_proof) {
            Ok(true) => Ok(()),
            Ok(false) => Err(StateError::Validation(
                "SMT proof verification failed".into(),
            )),
            Err(e) => Err(StateError::Validation(e.to_string())),
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
        let mut results: Vec<_> = self
            .cache
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        results.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let iter = results
            .into_iter()
            .map(|(k, v)| Ok((Arc::from(k), Arc::from(v))));
        Ok(Box::new(iter))
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
        let root_hash: RootHash = to_root_hash(root.as_ref())?;

        // Try in-memory path first
        if let Some(historical_root_node) = self.indices.roots.get(&root_hash).cloned() {
            let membership = match Self::get_from_snapshot(&historical_root_node, key, 0) {
                Some(v) => Membership::Present(v),
                None => Membership::Absent,
            };
            let merkle_proof = Self::generate_proof_from_snapshot(&historical_root_node, key);
            // Self-verify
            if !Self::verify_proof_static(
                &root_hash,
                key,
                membership.clone().into_option().as_deref(),
                &merkle_proof,
            )
            .map_err(|e| StateError::Validation(e.to_string()))?
            {
                return Err(StateError::Backend("SMT self-verify failed".into()));
            }
            let proof_bytes = serde_json::to_vec(&merkle_proof)
                .map_err(|e| StateError::Backend(e.to_string()))?;
            let proof_value = self.to_value(&proof_bytes);
            let proof = self
                .scheme
                .create_proof(&Selector::Key(key.to_vec()), &proof_value)
                .map_err(|e| StateError::Backend(e.to_string()))?;
            return Ok((membership, proof));
        }

        // --- MODIFICATION START: Fallback to store ---
        if let Some(store) = &self.store {
            let merkle_proof = self.build_proof_from_store_at(store.as_ref(), root_hash, key)?;
            let membership = if let Some((proof_key, proof_value)) = &merkle_proof.leaf {
                if proof_key == key {
                    Membership::Present(proof_value.clone())
                } else {
                    Membership::Absent
                }
            } else {
                Membership::Absent
            };
            if !Self::verify_proof_static(
                &root_hash,
                key,
                membership.clone().into_option().as_deref(),
                &merkle_proof,
            )
            .map_err(|e| StateError::Validation(e.to_string()))?
            {
                return Err(StateError::Backend(
                    "SMT store-backed self-verify failed".into(),
                ));
            }
            let proof_bytes = serde_json::to_vec(&merkle_proof)
                .map_err(|e| StateError::Backend(e.to_string()))?;
            let proof_value = self.to_value(&proof_bytes);
            let proof = self
                .scheme
                .create_proof(&Selector::Key(key.to_vec()), &proof_value)
                .map_err(|e| StateError::Backend(e.to_string()))?;
            return Ok((membership, proof));
        }
        // --- MODIFICATION END ---

        Err(StateError::StaleAnchor)
    }

    fn commitment_from_anchor(&self, anchor: &[u8; 32]) -> Option<Self::Commitment> {
        // For SMT, the anchor is the commitment.
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
        self.current_height = height;
        let root_hash = to_root_hash(self.root.hash())?;

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

        self.indices.versions_by_height.insert(version, root_hash);
        self.indices.roots.insert(root_hash, self.root.clone());
        *self.indices.root_refcount.entry(root_hash).or_insert(0) += 1;

        if self.current_height < version {
            self.current_height = version;
        }

        Ok(())
    }

    // --- MODIFICATION START: Implement attach_store ---
    fn attach_store(&mut self, store: Arc<dyn NodeStore>) {
        self.store = Some(store);
    }
    // --- MODIFICATION END ---
}

#[cfg(test)]
mod tests;
