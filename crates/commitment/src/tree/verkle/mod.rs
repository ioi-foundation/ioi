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
use depin_sdk_api::state::{StateCommitment, StateManager};
use depin_sdk_types::app::Membership;
use depin_sdk_types::error::StateError;
use std::any::Any;
use std::collections::HashMap;

/// Verkle tree node
#[derive(Debug, Clone)]
enum VerkleNode {
    Empty,
    Leaf {
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Internal {
        children: HashMap<u8, Box<VerkleNode>>,
        kzg_commitment: KZGCommitment,
        witness: KZGWitness,
    },
}

/// Verkle tree implementation
#[derive(Debug)]
pub struct VerkleTree<CS: CommitmentScheme> {
    root: VerkleNode,
    scheme: CS,
    _branching_factor: usize,
    cache: HashMap<Vec<u8>, Vec<u8>>,
    // Map from root hash to a snapshot of the root node at that version.
    versions: HashMap<Vec<u8>, VerkleNode>,
    // A pre-computed, canonical commitment for an empty child node.
    _empty_commitment: KZGCommitment,
}

// Manual Clone implementation because Mutex isn't Clone
impl<CS: CommitmentScheme + Clone> Clone for VerkleTree<CS> {
    fn clone(&self) -> Self {
        Self {
            root: self.root.clone(),
            scheme: self.scheme.clone(),
            _branching_factor: self._branching_factor,
            cache: self.cache.clone(),
            versions: self.versions.clone(),
            _empty_commitment: self._empty_commitment.clone(),
        }
    }
}

impl VerkleTree<KZGCommitmentScheme> {
    pub fn new(scheme: KZGCommitmentScheme, branching_factor: usize) -> Self {
        let empty_values = vec![Some(vec![0u8; 32]); branching_factor];
        let empty_values_ref: Vec<Option<&[u8]>> =
            empty_values.iter().map(|v| v.as_deref()).collect();
        let (empty_commitment, _) = scheme
            .commit_with_witness(&empty_values_ref)
            .expect("Failed to create canonical empty commitment");

        let mut tree = Self {
            root: VerkleNode::Empty,
            scheme,
            _branching_factor: branching_factor,
            cache: HashMap::new(),
            versions: HashMap::new(),
            _empty_commitment: empty_commitment,
        };
        let empty_root_hash = tree.root_commitment().as_ref().to_vec();
        tree.versions.insert(empty_root_hash, tree.root.clone());
        tree
    }

    fn get_from_node(&self, node: &VerkleNode, key: &[u8], depth: usize) -> Option<Vec<u8>> {
        match node {
            VerkleNode::Empty => None,
            VerkleNode::Leaf { key: k, value: v } => (k.as_slice() == key).then(|| v.clone()),
            VerkleNode::Internal { children, .. } => {
                let child_index = key.get(depth)?;
                let child = children.get(child_index)?;
                self.get_from_node(child, key, depth + 1)
            }
        }
    }

    fn build_proof_from_node(&self, start_node: &VerkleNode, key_path: &[u8]) -> Option<KZGProof> {
        let vpp = self.build_path_proof(start_node, key_path)?;
        let bytes = bincode::serialize(&vpp).ok()?;
        Some(KZGProof::from(bytes))
    }

    fn build_path_proof(
        &self,
        start_node: &VerkleNode,
        key_path: &[u8],
    ) -> Option<VerklePathProof> {
        let mut node_commitments: Vec<Vec<u8>> = Vec::new();
        let mut per_level_proofs: Vec<Vec<u8>> = Vec::new();
        let mut per_level_selectors: Vec<u32> = Vec::new();
        let mut cursor = start_node;

        // The first commitment must correspond to `start_node` (e.g., a historical snapshot),
        // not the *current* tree root.
        match start_node {
            VerkleNode::Internal { kzg_commitment, .. } => {
                node_commitments.push(kzg_commitment.as_ref().to_vec());
            }
            VerkleNode::Empty => {
                // Commitment for an empty node: commit over all-empty children.
                let empty_children = HashMap::new();
                let values = self.internal_values(&empty_children);
                let byref: Vec<Option<&[u8]>> = values.iter().map(|o| o.as_deref()).collect();
                let (c, _) = self
                    .scheme
                    .commit_with_witness(&byref)
                    .expect("empty root commitment must succeed");
                node_commitments.push(c.as_ref().to_vec());
            }
            VerkleNode::Leaf { .. } => return None, // a leaf cannot be a root; treat as invalid
        }

        for &idx in key_path.iter() {
            if let VerkleNode::Internal {
                children, witness, ..
            } = cursor
            {
                // In our KZG scheme, slots map directly to the evaluation domain.
                let domain_idx = idx as usize;

                // If the target child is missing but there is a sibling leaf at this node,
                // produce a Neighbor non-membership proof by opening that sibling slot.
                if !children.contains_key(&idx) {
                    if let Some((nidx, nkey, nval)) =
                        children.iter().find_map(|(k, ch)| match ch.as_ref() {
                            VerkleNode::Leaf { key, value } => {
                                Some((*k, key.clone(), value.clone()))
                            }
                            _ => None,
                        })
                    {
                        let n_selector = Selector::Position(nidx as usize);
                        let n_y_bytes = self.value_at_slot(children, nidx);
                        let n_proof = self
                            .scheme
                            .create_proof_from_witness(witness, &n_selector, &n_y_bytes)
                            .ok()?;

                        per_level_proofs.push(n_proof.as_ref().to_vec());
                        per_level_selectors.push(nidx as u32);
                        // For a leaf child, push the canonical empty commitment as the "next" placeholder.
                        node_commitments.push(self._empty_commitment.as_ref().to_vec());

                        return Some(VerklePathProof {
                            params_id: self.scheme.params.fingerprint(),
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
                let y_bytes = self.value_at_slot(children, idx);
                let proof = self
                    .scheme
                    .create_proof_from_witness(witness, &selector, &y_bytes)
                    .ok()?;

                let (next_commitment_bytes, next_node) = if let Some(child) = children.get(&idx) {
                    match child.as_ref() {
                        VerkleNode::Internal { kzg_commitment, .. } => {
                            (kzg_commitment.as_ref().to_vec(), child.as_ref())
                        }
                        VerkleNode::Leaf { .. } | VerkleNode::Empty => {
                            (self._empty_commitment.as_ref().to_vec(), child.as_ref())
                        }
                    }
                } else {
                    (self._empty_commitment.as_ref().to_vec(), &VerkleNode::Empty)
                };

                per_level_proofs.push(proof.as_ref().to_vec());
                per_level_selectors.push(domain_idx as u32);
                node_commitments.push(next_commitment_bytes);
                cursor = next_node;
            } else {
                break;
            }
        }

        let terminal = match cursor {
            VerkleNode::Leaf {
                key: leaf_key,
                value,
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
            // If the path ends at an empty spot or an internal node (which shouldn't happen for a full key path), it's a proof of absence.
            VerkleNode::Empty | VerkleNode::Internal { .. } => Terminal::Empty,
        };

        Some(VerklePathProof {
            params_id: self.scheme.params.fingerprint(),
            node_commitments,
            per_level_proofs,
            per_level_selectors,
            terminal,
        })
    }

    fn value_at_slot(&self, children: &HashMap<u8, Box<VerkleNode>>, idx: u8) -> [u8; 32] {
        if let Some(child) = children.get(&idx) {
            match child.as_ref() {
                VerkleNode::Internal { kzg_commitment, .. } => {
                    map_child_commitment_to_value(kzg_commitment.as_ref())
                }
                VerkleNode::Leaf { value, .. } => map_leaf_payload_to_value(value),
                VerkleNode::Empty => map_child_commitment_to_value(self._empty_commitment.as_ref()),
            }
        } else {
            // Missing child == empty slot
            map_child_commitment_to_value(self._empty_commitment.as_ref())
        }
    }

    fn internal_values(&self, children: &HashMap<u8, Box<VerkleNode>>) -> Vec<Option<Vec<u8>>> {
        let mut slots = vec![None; self._branching_factor];
        for (i, slot) in slots.iter_mut().enumerate() {
            if let Some(child) = children.get(&(i as u8)) {
                let val32 = match child.as_ref() {
                    VerkleNode::Internal { kzg_commitment, .. } => {
                        map_child_commitment_to_value(kzg_commitment.as_ref())
                    }
                    VerkleNode::Leaf { value, .. } => map_leaf_payload_to_value(value),
                    VerkleNode::Empty => {
                        map_child_commitment_to_value(self._empty_commitment.as_ref())
                    }
                };
                *slot = Some(val32.to_vec());
            } else {
                *slot =
                    Some(map_child_commitment_to_value(self._empty_commitment.as_ref()).to_vec());
            }
        }
        slots
    }

    fn compute_internal_kzg(
        &self,
        children: &HashMap<u8, Box<VerkleNode>>,
    ) -> Result<(KZGCommitment, KZGWitness), String> {
        let values = self.internal_values(children);
        let byref: Vec<Option<&[u8]>> = values.iter().map(|o| o.as_deref()).collect();
        self.scheme.commit_with_witness(&byref)
    }

    #[allow(clippy::only_used_in_recursion)]
    fn update_node(
        &self,
        node: &VerkleNode,
        key: &[u8],
        value: Option<&[u8]>,
        depth: usize,
    ) -> VerkleNode {
        if depth >= key.len() {
            return if let Some(v) = value {
                VerkleNode::Leaf {
                    key: key.to_vec(),
                    value: v.to_vec(),
                }
            } else {
                VerkleNode::Empty
            };
        }

        match node {
            VerkleNode::Empty => {
                if let Some(v) = value {
                    let mut path_node = VerkleNode::Leaf {
                        key: key.to_vec(),
                        value: v.to_vec(),
                    };
                    for d in (depth..key.len()).rev() {
                        let mut children = HashMap::new();
                        children.insert(key[d], Box::new(path_node));
                        let (kzg_commitment, witness) =
                            self.compute_internal_kzg(&children).unwrap();
                        path_node = VerkleNode::Internal {
                            children,
                            kzg_commitment,
                            witness,
                        };
                    }
                    path_node
                } else {
                    VerkleNode::Empty
                }
            }
            VerkleNode::Leaf {
                key: leaf_key,
                value: leaf_value,
            } => {
                if leaf_key == key {
                    return if let Some(v) = value {
                        VerkleNode::Leaf {
                            key: key.to_vec(),
                            value: v.to_vec(),
                        }
                    } else {
                        VerkleNode::Empty
                    };
                }
                let mut children = HashMap::new();
                children.insert(
                    leaf_key[depth],
                    Box::new(VerkleNode::Leaf {
                        key: leaf_key.clone(),
                        value: leaf_value.clone(),
                    }),
                );
                if let Some(v) = value {
                    children.insert(
                        key[depth],
                        Box::new(VerkleNode::Leaf {
                            key: key.to_vec(),
                            value: v.to_vec(),
                        }),
                    );
                }
                let (kzg_commitment, witness) = self.compute_internal_kzg(&children).unwrap();
                VerkleNode::Internal {
                    children,
                    kzg_commitment,
                    witness,
                }
            }
            VerkleNode::Internal { children, .. } => {
                let mut new_children = children.clone();
                let child_index = key[depth];
                let child = children
                    .get(&child_index)
                    .map(|c| c.as_ref())
                    .unwrap_or(&VerkleNode::Empty);
                let new_child = self.update_node(child, key, value, depth + 1);

                if matches!(new_child, VerkleNode::Empty) {
                    new_children.remove(&child_index);
                } else {
                    new_children.insert(child_index, Box::new(new_child));
                }

                if new_children.is_empty() {
                    VerkleNode::Empty
                } else {
                    let (kzg_commitment, witness) =
                        self.compute_internal_kzg(&new_children).unwrap();
                    VerkleNode::Internal {
                        children: new_children,
                        kzg_commitment,
                        witness,
                    }
                }
            }
        }
    }
}

impl StateCommitment for VerkleTree<KZGCommitmentScheme> {
    type Commitment = KZGCommitment;
    type Proof = KZGProof;

    fn root_commitment(&self) -> Self::Commitment {
        match &self.root {
            VerkleNode::Internal { kzg_commitment, .. } => kzg_commitment.clone(),
            VerkleNode::Leaf { .. } => {
                panic!("Invalid Verkle Tree state: root cannot be a leaf node.");
            }
            VerkleNode::Empty => {
                let empty_children = HashMap::new();
                let values = self.internal_values(&empty_children);
                let byref: Vec<Option<&[u8]>> = values.iter().map(|o| o.as_deref()).collect();
                let (c, _) = self.scheme.commit_with_witness(&byref).expect(
                    "Commitment to empty children should not fail; check FFT length requirements",
                );
                c
            }
        }
    }

    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        self.build_proof_from_node(&self.root, key)
    }

    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8],
    ) -> bool {
        if !verify::verify_path_with_scheme(
            &self.scheme,
            commitment,
            &self.scheme.params.fingerprint(),
            key,
            proof.as_ref(),
        ) {
            return false;
        }

        let vpp: VerklePathProof = match bincode::deserialize(proof.as_ref()) {
            Ok(p) => p,
            Err(_) => return false,
        };

        match vpp.terminal {
            Terminal::Leaf(payload) => payload.as_slice() == value,
            Terminal::Empty | Terminal::Neighbor { .. } => false,
        }
    }

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
        let root_bytes = root.as_ref();
        let historical_root = self.versions.get(root_bytes).ok_or_else(|| {
            StateError::Backend(format!(
                "Verkle root commitment {} not found in versioned history",
                hex::encode(root_bytes)
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

    fn commitment_from_bytes(&self, bytes: &[u8]) -> Result<Self::Commitment, StateError> {
        Ok(KZGCommitment::from(bytes.to_vec()))
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
        let root_hash = self.root_commitment().as_ref().to_vec();
        self.versions.insert(root_hash, self.root.clone());
        log::debug!(
            "[Verkle] commit_version: recorded snapshot for root {}",
            hex::encode(&self.root_commitment().as_ref())
        );
    }

    fn version_exists_for_root(&self, root: &Self::Commitment) -> bool {
        self.versions.contains_key(root.as_ref())
    }
}

#[cfg(test)]
mod tests;
