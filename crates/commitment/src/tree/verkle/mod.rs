// Path: crates/commitment/src/tree/verkle/mod.rs
//! Verkle tree implementation with cryptographic security

mod proof;
pub mod verifier;
mod verify;

use crate::primitives::kzg::{KZGCommitment, KZGCommitmentScheme, KZGProof, KZGWitness};
use crate::tree::verkle::proof::{
    map_child_commitment_to_value, map_leaf_payload_to_value, Terminal, VerklePathProof,
};
use depin_sdk_api::commitment::{CommitmentScheme, Selector};
use depin_sdk_api::state::{PrunePlan, StateCommitment, StateManager};
use depin_sdk_api::storage::NodeStore;
use depin_sdk_storage::adapter::{commit_and_persist, DeltaAccumulator};
use depin_sdk_types::app::{to_root_hash, Membership, RootHash};
use depin_sdk_types::error::StateError;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

/// Verkle tree node
// Note: `Arc<VerkleNode>` can be serialized because the `serde` dependency
// in this crate's Cargo.toml has the `rc` feature enabled.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum VerkleNode {
    Empty,
    Leaf {
        key: Vec<u8>,
        value: Vec<u8>,
        created_at: u64,
    },
    Internal {
        children: HashMap<u8, Arc<VerkleNode>>,
        kzg_commitment: KZGCommitment,
        witness: KZGWitness,
        created_at: u64,
    },
}

/// Encodes a `VerkleNode` into its canonical byte format for storage.
/// Note: This is for the storage adapter, not for the KZG commitment itself.
fn encode_node_canonical(n: &VerkleNode) -> Result<Vec<u8>, StateError> {
    // A simple bincode representation is sufficient for the durable store.
    bincode::serialize(n).map_err(|e| StateError::Backend(e.to_string()))
}

/// Verkle tree implementation
#[derive(Debug)]
pub struct VerkleTree<CS: CommitmentScheme> {
    root: Arc<VerkleNode>,
    scheme: CS,
    _branching_factor: usize,
    cache: HashMap<Vec<u8>, Vec<u8>>,
    indices: Indices,
    empty_commitment: KZGCommitment,
    current_height: u64,
    delta: DeltaAccumulator,
}

#[derive(Debug, Clone, Default)]
struct Indices {
    versions_by_height: BTreeMap<u64, RootHash>,
    root_refcount: HashMap<RootHash, u32>,
    roots: HashMap<RootHash, Arc<VerkleNode>>,
}

// Manual Clone implementation because the generics make it tricky otherwise.
impl<CS: CommitmentScheme + Clone> Clone for VerkleTree<CS> {
    fn clone(&self) -> Self {
        Self {
            root: self.root.clone(),
            scheme: self.scheme.clone(),
            _branching_factor: self._branching_factor,
            cache: self.cache.clone(),
            indices: self.indices.clone(),
            empty_commitment: self.empty_commitment.clone(),
            current_height: self.current_height,
            delta: Default::default(), // delta is transient and should not be cloned
        }
    }
}

impl VerkleTree<KZGCommitmentScheme> {
    pub fn new(scheme: KZGCommitmentScheme, branching_factor: usize) -> Result<Self, String> {
        let empty_child_value = map_child_commitment_to_value(&[]).map_err(|e| e.to_string())?;

        let empty_values = vec![Some(empty_child_value.to_vec()); branching_factor];
        let empty_values_ref: Vec<Option<&[u8]>> =
            empty_values.iter().map(|v| v.as_deref()).collect();
        let (empty_commitment, _) = scheme
            .commit_with_witness(&empty_values_ref)
            .map_err(|e| format!("Failed to create canonical empty commitment: {}", e))?;

        Ok(Self {
            root: Arc::new(VerkleNode::Empty),
            scheme,
            _branching_factor: branching_factor,
            cache: HashMap::new(),
            indices: Indices::default(),
            empty_commitment,
            current_height: 0,
            delta: DeltaAccumulator::default(),
        })
    }

    /// An optimized method to build an internal node from a pre-sorted slice of key-value pairs.
    /// This is much faster than sequential insertion for bootstrapping the tree.
    fn build_from_sorted(
        &self,
        items: &[(&Vec<u8>, &Vec<u8>)],
        depth: usize,
    ) -> Result<Arc<VerkleNode>, StateError> {
        if items.is_empty() {
            return Ok(Arc::new(VerkleNode::Empty));
        }

        // --- START FIX ---
        // BUGFIX: A single item must be wrapped in a path of internal nodes, just like
        // an insert into an empty tree. Returning a raw Leaf node breaks the assumption
        // that a non-empty tree has an Internal root with a KZG commitment.
        if items.len() == 1 {
            let (key, value) = items
                .get(0)
                .ok_or(StateError::InvalidValue("Empty items slice".into()))?;
            // Delegate to update_node, which correctly builds the required path of internal nodes.
            return self.update_node(&Arc::new(VerkleNode::Empty), key, Some(value), depth);
        }
        // --- END FIX ---

        // Group items by the current key byte and recursively build children.
        // Using a BTreeMap naturally groups and sorts items by the key_byte.
        type GroupMap<'a> = BTreeMap<u8, Vec<(&'a Vec<u8>, &'a Vec<u8>)>>;
        let mut groups: GroupMap = BTreeMap::new();
        for item in items {
            if let Some(key_byte) = item.0.get(depth) {
                groups.entry(*key_byte).or_default().push(*item);
            }
        }

        let mut children = HashMap::new();
        for (key_byte, group) in groups {
            let child_node = self.build_from_sorted(&group, depth + 1)?;
            children.insert(key_byte, child_node);
        }

        let (kzg_commitment, witness) = self
            .compute_internal_kzg(&children)
            .map_err(StateError::InvalidValue)?;
        Ok(Arc::new(VerkleNode::Internal {
            children,
            kzg_commitment,
            witness,
            created_at: self.current_height,
        }))
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

    #[allow(clippy::only_used_in_recursion)]
    fn get_from_node(&self, node: &Arc<VerkleNode>, key: &[u8], depth: usize) -> Option<Vec<u8>> {
        match node.as_ref() {
            VerkleNode::Empty => None,
            VerkleNode::Leaf {
                key: k, value: v, ..
            } => (k.as_slice() == key).then(|| v.clone()),
            VerkleNode::Internal { children, .. } => {
                let child_index = key.get(depth)?;
                let child = children.get(child_index)?;
                self.get_from_node(child, key, depth + 1)
            }
        }
    }

    fn build_proof_from_node(
        &self,
        start_node: &Arc<VerkleNode>,
        key_path: &[u8],
    ) -> Option<KZGProof> {
        let vpp = self.build_path_proof(start_node, key_path)?;
        let bytes = bincode::serialize(&vpp).ok()?;
        Some(KZGProof::from(bytes))
    }

    fn build_path_proof(
        &self,
        start_node: &Arc<VerkleNode>,
        key_path: &[u8],
    ) -> Option<VerklePathProof> {
        let mut node_commitments: Vec<Vec<u8>> = Vec::new();
        let mut per_level_proofs: Vec<Vec<u8>> = Vec::new();
        let mut per_level_selectors: Vec<u32> = Vec::new();
        let mut cursor = start_node.clone();

        let start_commitment = match cursor.as_ref() {
            VerkleNode::Internal { kzg_commitment, .. } => kzg_commitment.as_ref().to_vec(),
            VerkleNode::Empty => self.empty_commitment.as_ref().to_vec(),
            VerkleNode::Leaf { .. } => return None,
        };
        node_commitments.push(start_commitment);

        for &idx in key_path.iter() {
            if let VerkleNode::Internal {
                children, witness, ..
            } = cursor.as_ref()
            {
                let domain_idx = idx as u64;

                if !children.contains_key(&idx) {
                    if let Some((nidx, nkey, nval)) =
                        children.iter().find_map(|(k, ch)| match ch.as_ref() {
                            VerkleNode::Leaf { key, value, .. } => {
                                Some((*k, key.clone(), value.clone()))
                            }
                            _ => None,
                        })
                    {
                        let n_selector = Selector::Position(nidx as u64);
                        let n_y_bytes = self.value_at_slot(children, nidx)?;
                        let n_proof = self
                            .scheme
                            .create_proof_from_witness(witness, &n_selector, &n_y_bytes)
                            .ok()?;

                        per_level_proofs.push(n_proof.as_ref().to_vec());
                        per_level_selectors.push(nidx as u32);
                        node_commitments.push(self.empty_commitment.as_ref().to_vec());

                        return Some(VerklePathProof {
                            params_id: self.scheme.params.fingerprint().ok()?,
                            node_commitments,
                            per_level_proofs,
                            per_level_selectors,
                            terminal: Terminal::Neighbor {
                                key_stem: nkey,
                                payload: nval,
                            },
                        });
                    }
                }

                let selector = Selector::Position(domain_idx);
                let y_bytes = self.value_at_slot(children, idx)?;
                let proof = self
                    .scheme
                    .create_proof_from_witness(witness, &selector, &y_bytes)
                    .ok()?;

                let (next_commitment_bytes, next_node) = if let Some(child) = children.get(&idx) {
                    match child.as_ref() {
                        VerkleNode::Internal { kzg_commitment, .. } => {
                            (kzg_commitment.as_ref().to_vec(), child.clone())
                        }
                        VerkleNode::Leaf { .. } | VerkleNode::Empty => {
                            (self.empty_commitment.as_ref().to_vec(), child.clone())
                        }
                    }
                } else {
                    (
                        self.empty_commitment.as_ref().to_vec(),
                        Arc::new(VerkleNode::Empty),
                    )
                };

                per_level_proofs.push(proof.as_ref().to_vec());
                per_level_selectors.push(domain_idx as u32);
                node_commitments.push(next_commitment_bytes);
                cursor = next_node;
            } else {
                break;
            }
        }

        let terminal = match cursor.as_ref() {
            VerkleNode::Leaf {
                key: leaf_key,
                value,
                ..
            } => {
                if leaf_key == key_path {
                    Terminal::Leaf(value.clone())
                } else {
                    Terminal::Neighbor {
                        key_stem: leaf_key.clone(),
                        payload: value.clone(),
                    }
                }
            }
            VerkleNode::Empty | VerkleNode::Internal { .. } => Terminal::Empty,
        };

        Some(VerklePathProof {
            params_id: self.scheme.params.fingerprint().ok()?,
            node_commitments,
            per_level_proofs,
            per_level_selectors,
            terminal,
        })
    }

    fn value_at_slot(&self, children: &HashMap<u8, Arc<VerkleNode>>, idx: u8) -> Option<[u8; 32]> {
        if let Some(child) = children.get(&idx) {
            match child.as_ref() {
                VerkleNode::Internal { kzg_commitment, .. } => {
                    map_child_commitment_to_value(kzg_commitment.as_ref()).ok()
                }
                VerkleNode::Leaf { value, .. } => map_leaf_payload_to_value(value).ok(),
                VerkleNode::Empty => {
                    map_child_commitment_to_value(self.empty_commitment.as_ref()).ok()
                }
            }
        } else {
            map_child_commitment_to_value(self.empty_commitment.as_ref()).ok()
        }
    }

    fn internal_values(
        &self,
        children: &HashMap<u8, Arc<VerkleNode>>,
    ) -> Result<Vec<Option<Vec<u8>>>, String> {
        let mut slots = vec![None; self._branching_factor];
        for (i, slot) in slots.iter_mut().enumerate() {
            if let Some(child) = children.get(&(i as u8)) {
                let val32 = match child.as_ref() {
                    VerkleNode::Internal { kzg_commitment, .. } => {
                        map_child_commitment_to_value(kzg_commitment.as_ref())
                            .map_err(|e| e.to_string())?
                    }
                    VerkleNode::Leaf { value, .. } => {
                        map_leaf_payload_to_value(value).map_err(|e| e.to_string())?
                    }
                    VerkleNode::Empty => {
                        map_child_commitment_to_value(self.empty_commitment.as_ref())
                            .map_err(|e| e.to_string())?
                    }
                };
                *slot = Some(val32.to_vec());
            } else {
                let val32 = map_child_commitment_to_value(self.empty_commitment.as_ref())
                    .map_err(|e| e.to_string())?;
                *slot = Some(val32.to_vec());
            }
        }
        Ok(slots)
    }

    fn compute_internal_kzg(
        &self,
        children: &HashMap<u8, Arc<VerkleNode>>,
    ) -> Result<(KZGCommitment, KZGWitness), String> {
        let values = self.internal_values(children)?;
        let byref: Vec<Option<&[u8]>> = values.iter().map(|o| o.as_deref()).collect();
        self.scheme
            .commit_with_witness(&byref)
            .map_err(|e| e.to_string())
    }

    #[allow(clippy::only_used_in_recursion)]
    fn update_node(
        &self,
        node: &Arc<VerkleNode>,
        key: &[u8],
        value: Option<&[u8]>,
        depth: usize,
    ) -> Result<Arc<VerkleNode>, StateError> {
        if depth >= key.len() {
            return Ok(if let Some(v) = value {
                Arc::new(VerkleNode::Leaf {
                    key: key.to_vec(),
                    value: v.to_vec(),
                    created_at: self.current_height,
                })
            } else {
                Arc::new(VerkleNode::Empty)
            });
        }

        match node.as_ref() {
            VerkleNode::Empty => {
                if let Some(v) = value {
                    let mut path_node = Arc::new(VerkleNode::Leaf {
                        key: key.to_vec(),
                        value: v.to_vec(),
                        created_at: self.current_height,
                    });
                    for d in (depth..key.len()).rev() {
                        let mut children = HashMap::new();
                        let key_byte = *key.get(d).ok_or_else(|| {
                            StateError::InvalidValue(format!("Key index {} out of bounds", d))
                        })?;
                        children.insert(key_byte, path_node);
                        let (kzg_commitment, witness) = self
                            .compute_internal_kzg(&children)
                            .map_err(StateError::InvalidValue)?;
                        path_node = Arc::new(VerkleNode::Internal {
                            children,
                            kzg_commitment,
                            witness,
                            created_at: self.current_height,
                        });
                    }
                    Ok(path_node)
                } else {
                    Ok(Arc::new(VerkleNode::Empty))
                }
            }
            VerkleNode::Leaf {
                key: leaf_key,
                value: leaf_value,
                ..
            } => {
                if leaf_key == key {
                    return Ok(if let Some(v) = value {
                        Arc::new(VerkleNode::Leaf {
                            key: key.to_vec(),
                            value: v.to_vec(),
                            created_at: self.current_height,
                        })
                    } else {
                        Arc::new(VerkleNode::Empty)
                    });
                }
                let mut children = HashMap::new();
                let leaf_key_byte = *leaf_key.get(depth).ok_or_else(|| {
                    StateError::InvalidValue(format!("Leaf key index {} out of bounds", depth))
                })?;
                children.insert(
                    leaf_key_byte,
                    Arc::new(VerkleNode::Leaf {
                        key: leaf_key.clone(),
                        value: leaf_value.clone(),
                        created_at: self.current_height,
                    }),
                );
                if let Some(v) = value {
                    let key_byte = *key.get(depth).ok_or_else(|| {
                        StateError::InvalidValue(format!("Key index {} out of bounds", depth))
                    })?;
                    children.insert(
                        key_byte,
                        Arc::new(VerkleNode::Leaf {
                            key: key.to_vec(),
                            value: v.to_vec(),
                            created_at: self.current_height,
                        }),
                    );
                }
                let (kzg_commitment, witness) = self
                    .compute_internal_kzg(&children)
                    .map_err(StateError::InvalidValue)?;
                Ok(Arc::new(VerkleNode::Internal {
                    children,
                    kzg_commitment,
                    witness,
                    created_at: self.current_height,
                }))
            }
            VerkleNode::Internal { children, .. } => {
                let mut new_children = children.clone();
                let child_index = *key.get(depth).ok_or_else(|| {
                    StateError::InvalidValue(format!("Key index {} out of bounds", depth))
                })?;
                let child = children
                    .get(&child_index)
                    .cloned()
                    .unwrap_or_else(|| Arc::new(VerkleNode::Empty));
                let new_child = self.update_node(&child, key, value, depth + 1)?;

                if matches!(new_child.as_ref(), VerkleNode::Empty) {
                    new_children.remove(&child_index);
                } else {
                    new_children.insert(child_index, new_child);
                }

                if new_children.is_empty() {
                    Ok(Arc::new(VerkleNode::Empty))
                } else {
                    let (kzg_commitment, witness) = self
                        .compute_internal_kzg(&new_children)
                        .map_err(StateError::InvalidValue)?;
                    Ok(Arc::new(VerkleNode::Internal {
                        children: new_children,
                        kzg_commitment,
                        witness,
                        created_at: self.current_height,
                    }))
                }
            }
        }
    }

    fn collect_height_delta(&mut self) -> Result<(), StateError> {
        let h = self.current_height;
        let root_clone = self.root.clone();
        self.collect_from_node(&root_clone, h)
    }

    fn collect_from_node(&mut self, n: &Arc<VerkleNode>, h: u64) -> Result<(), StateError> {
        match n.as_ref() {
            VerkleNode::Empty => Ok(()),
            VerkleNode::Leaf { created_at, .. } | VerkleNode::Internal { created_at, .. } => {
                let bytes = encode_node_canonical(n.as_ref())?;
                let nh = depin_sdk_crypto::algorithms::hash::sha256(&bytes)
                    .map_err(|e| StateError::Backend(e.to_string()))?;
                if *created_at == h {
                    self.delta.record_new(nh, bytes);
                } else {
                    self.delta.record_touch(nh);
                }
                if let VerkleNode::Internal { children, .. } = n.as_ref() {
                    for child in children.values() {
                        self.collect_from_node(child, h)?;
                    }
                }
                Ok(())
            }
        }
    }

    pub fn commit_version_with_store<S: NodeStore + ?Sized>(
        &mut self,
        height: u64,
        store: &S,
    ) -> Result<RootHash, StateError> {
        self.current_height = height;
        self.collect_height_delta()?;
        let root_hash = to_root_hash(self.root_commitment().as_ref())?;
        commit_and_persist(store, height, root_hash, &self.delta)
            .map_err(|e| StateError::Backend(e.to_string()))?;
        self.delta.clear();
        let _ = <Self as StateManager>::commit_version(self, height)?;
        Ok(root_hash)
    }
}

impl StateCommitment for VerkleTree<KZGCommitmentScheme> {
    type Commitment = KZGCommitment;
    type Proof = KZGProof;

    fn root_commitment(&self) -> Self::Commitment {
        match self.root.as_ref() {
            VerkleNode::Internal { kzg_commitment, .. } => kzg_commitment.clone(),
            VerkleNode::Leaf { .. } => {
                // This case should not be reachable in a correctly functioning tree.
                // If it is, it indicates a bug. Using a deterministic "error" commitment.
                self.empty_commitment.clone()
            }
            VerkleNode::Empty => self.empty_commitment.clone(),
        }
    }

    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        let proof = self.build_proof_from_node(&self.root, key)?;

        // --- START DEBUG ASSERT ---
        if cfg!(debug_assertions) {
            if let Ok(vpp) = bincode::deserialize::<VerklePathProof>(proof.as_ref()) {
                let tree_root_bytes = self.root_commitment().as_ref().to_vec();
                if let Some(proof_root_bytes) = vpp.node_commitments.first() {
                    assert_eq!(
                        proof_root_bytes, &tree_root_bytes,
                        "Proof root does not match tree root commitment!"
                    );
                }
            }
        }
        // --- END DEBUG ASSERT ---

        Some(proof)
    }

    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), StateError> {
        let params_id = self
            .scheme
            .params
            .fingerprint()
            .map_err(|e| StateError::Validation(e.to_string()))?;

        if !verify::verify_path_with_scheme(
            &self.scheme,
            commitment,
            &params_id,
            key,
            proof.as_ref(),
        ) {
            return Err(StateError::Validation("Path verification failed".into()));
        }

        let vpp: VerklePathProof = bincode::deserialize(proof.as_ref())
            .map_err(|e| StateError::InvalidValue(format!("Failed to deserialize proof: {}", e)))?;

        match vpp.terminal {
            Terminal::Leaf(payload) => {
                if payload.as_slice() == value {
                    Ok(())
                } else {
                    Err(StateError::Validation("Value mismatch".into()))
                }
            }
            Terminal::Empty | Terminal::Neighbor { .. } => Err(StateError::Validation(
                "Proof does not prove existence".into(),
            )),
        }
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.root = self.update_node(&self.root, key, Some(value), 0)?;
        self.cache.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.cache.get(key).cloned())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        self.root = self.update_node(&self.root, key, None, 0)?;
        self.cache.remove(key);
        Ok(())
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

impl StateManager for VerkleTree<KZGCommitmentScheme> {
    fn get_with_proof_at(
        &self,
        root: &Self::Commitment,
        key: &[u8],
    ) -> Result<(Membership, Self::Proof), StateError> {
        let root_hash = to_root_hash(root.as_ref())?;
        let historical_root = self.indices.roots.get(&root_hash).ok_or_else(|| {
            StateError::Backend(format!(
                "Verkle root commitment {} not found in versioned history",
                hex::encode(root.as_ref())
            ))
        })?;

        let membership = match self.get_from_node(historical_root, key, 0) {
            Some(value) => Membership::Present(value),
            None => Membership::Absent,
        };

        let proof = self
            .build_proof_from_node(historical_root, key)
            .ok_or_else(|| StateError::Backend("Failed to generate Verkle proof".to_string()))?;
        Ok((membership, proof))
    }

    fn commitment_from_anchor(&self, anchor: &[u8; 32]) -> Option<Self::Commitment> {
        let root_hash: RootHash = *anchor;
        let node = self.indices.roots.get(&root_hash)?;
        let commitment = match node.as_ref() {
            VerkleNode::Internal { kzg_commitment, .. } => kzg_commitment.clone(),
            VerkleNode::Leaf { .. } | VerkleNode::Empty => {
                // This case should be rare, but returning the canonical empty commitment
                // is the correct, robust behavior.
                self.empty_commitment.clone()
            }
        };

        // Observability and sanity check
        if let Ok(derived_anchor) = to_root_hash(commitment.as_ref()) {
            if derived_anchor != root_hash {
                log::error!(
                    "CRITICAL INVARIANT VIOLATION: Anchor 0x{} resolved to a commitment with a different hash 0x{}",
                    hex::encode(root_hash),
                    hex::encode(derived_anchor)
                );
                return None;
            }
        }
        log::debug!(
            "Verkle anchor 0x{} resolved to commitment of length {}",
            hex::encode(root_hash),
            commitment.as_ref().len()
        );
        Some(commitment)
    }

    fn commitment_from_bytes(&self, bytes: &[u8]) -> Result<Self::Commitment, StateError> {
        Ok(KZGCommitment::from(bytes.to_vec()))
    }

    fn commitment_to_bytes(&self, c: &Self::Commitment) -> Vec<u8> {
        c.as_ref().to_vec()
    }

    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        // This is a bootstrap optimization. A true batch update would be more complex.
        // We merge the existing cache with the new updates, sort, and rebuild the tree from scratch.
        let mut all_items = self.cache.clone();
        all_items.extend(updates.iter().cloned());

        let mut sorted_items_owned: Vec<(Vec<u8>, Vec<u8>)> = all_items.into_iter().collect();
        sorted_items_owned.sort_unstable_by(|a, b| a.0.cmp(&b.0));

        let sorted_items_ref: Vec<(&Vec<u8>, &Vec<u8>)> =
            sorted_items_owned.iter().map(|(k, v)| (k, v)).collect();

        self.root = self.build_from_sorted(&sorted_items_ref, 0)?;

        self.cache.extend(updates.iter().cloned());
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
        // Slower, but correct implementation for now.
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
        let root_hash = to_root_hash(self.root_commitment().as_ref())?;

        match self.indices.versions_by_height.insert(height, root_hash) {
            // Case 1: This is a new height, or a reorg to a different root.
            None => {
                let count = self.indices.root_refcount.entry(root_hash).or_insert(0);
                if *count == 0 {
                    // First time seeing this root hash, store the actual node.
                    if let Some(root_node) =
                        Some(self.root.clone()).filter(|n| !matches!(n.as_ref(), VerkleNode::Empty))
                    {
                        self.indices.roots.insert(root_hash, root_node);
                    }
                }
                *count += 1;
            }
            Some(prev_root) if prev_root != root_hash => {
                // It's a reorg. Decrement the old root's count and increment the new one's.
                self.decrement_refcount(prev_root);

                let count = self.indices.root_refcount.entry(root_hash).or_insert(0);
                if *count == 0 {
                    if let Some(root_node) =
                        Some(self.root.clone()).filter(|n| !matches!(n.as_ref(), VerkleNode::Empty))
                    {
                        self.indices.roots.insert(root_hash, root_node);
                    }
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
}

#[cfg(test)]
mod tests;