// Path: crates/commitment/src/tree/verkle/mod.rs
//! Verkle tree implementation with cryptographic security

mod proof;
mod proof_builder;
pub mod verifier;
mod verify;

use crate::primitives::kzg::{KZGCommitment, KZGCommitmentScheme, KZGProof, KZGWitness};
use crate::tree::verkle::proof::{
    map_child_commitment_to_value, map_leaf_payload_to_value, Terminal, VerklePathProof,
};
use crate::tree::verkle::verify::verify_path_with_scheme;
use depin_sdk_api::commitment::CommitmentScheme;
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
#[derive(Debug, Clone)]
pub struct VerkleTree<CS: CommitmentScheme> {
    root: VerkleNode,
    scheme: CS,
    _branching_factor: usize,
    cache: HashMap<Vec<u8>, Vec<u8>>,
}

impl VerkleTree<KZGCommitmentScheme> {
    pub fn new(scheme: KZGCommitmentScheme, branching_factor: usize) -> Self {
        Self {
            root: VerkleNode::Empty,
            scheme,
            _branching_factor: branching_factor,
            cache: HashMap::new(),
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
                    VerkleNode::Empty => [0u8; 32],
                };
                *slot = Some(val32.to_vec());
            } else {
                // Represent an empty slot with a commitment to zero.
                *slot = Some([0u8; 32].to_vec());
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
            VerkleNode::Leaf { value, .. } => {
                let y0 = map_leaf_payload_to_value(value);
                let (c, _) = self
                    .scheme
                    .commit_with_witness(&[Some(&y0[..])])
                    .expect("KZG deg-0 commit");
                c
            }
            VerkleNode::Empty => {
                let (c, _) = self
                    .scheme
                    .commit_with_witness(&[Some(&[0u8; 32][..])])
                    .expect("KZG deg-0 commit");
                c
            }
        }
    }

    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        let vpp = self.build_path_proof(key)?;
        let bytes = bincode::serialize(&vpp).ok()?;
        Some(KZGProof::from(bytes))
    }

    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8],
    ) -> bool {
        let proof_bytes = proof.as_ref();
        let ok = verify_path_with_scheme(
            &self.scheme,
            commitment,
            &self.scheme.params.fingerprint(),
            key,
            proof_bytes,
        );
        if !ok {
            return false;
        }

        let vpp: VerklePathProof = match bincode::deserialize(proof_bytes) {
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
        _root: &Self::Commitment,
        key: &[u8],
    ) -> Result<(Membership, Self::Proof), StateError> {
        let membership = match self.get(key)? {
            Some(value) => Membership::Present(value),
            None => Membership::Absent,
        };
        let proof = self
            .create_proof(key)
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
}
