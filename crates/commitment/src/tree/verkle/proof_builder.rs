// Path: crates/commitment/src/tree/verkle/proof_builder.rs
//! Contains the logic to build production-grade proofs by traversing a `VerkleTree`.

use super::{
    proof::{map_child_commitment_to_value, map_leaf_payload_to_value, Terminal, VerklePathProof},
    VerkleNode, VerkleTree,
};
// FIX 2: Remove unused `CommitmentScheme` import.
use depin_sdk_api::commitment::Selector;
// FIX 1: Use `crate::` to refer to a module within the same crate.
use crate::primitives::kzg::KZGCommitmentScheme;

impl VerkleTree<KZGCommitmentScheme> {
    /// Builds a proof of existence for the given key.
    pub(super) fn build_path_proof(&self, key_path: &[u8]) -> Option<VerklePathProof> {
        let mut node_commitments: Vec<Vec<u8>> = Vec::new();
        let mut per_level_proofs: Vec<Vec<u8>> = Vec::new();
        let mut cursor = &self.root;

        match cursor {
            VerkleNode::Internal { kzg_commitment, .. } => {
                node_commitments.push(kzg_commitment.as_ref().to_vec());
            }
            VerkleNode::Leaf { value, .. } => {
                let (c, _) = self
                    .scheme
                    .commit_with_witness(&[Some(&map_leaf_payload_to_value(value)[..])])
                    .ok()?;
                node_commitments.push(c.as_ref().to_vec());
            }
            VerkleNode::Empty => {
                let (c, _) = self
                    .scheme
                    .commit_with_witness(&[Some(&[0u8; 32][..])])
                    .ok()?;
                node_commitments.push(c.as_ref().to_vec());
            }
        }

        for &idx in key_path.iter() {
            if let VerkleNode::Internal {
                children, witness, ..
            } = cursor
            {
                let (next_commitment_bytes, y_bytes, next_node) = if let Some(child) =
                    children.get(&idx)
                {
                    match child.as_ref() {
                        VerkleNode::Internal {
                            kzg_commitment: child_c,
                            ..
                        } => {
                            let y = map_child_commitment_to_value(child_c.as_ref());
                            (child_c.as_ref().to_vec(), y.to_vec(), child.as_ref())
                        }
                        VerkleNode::Leaf { value, .. } => {
                            let y = map_leaf_payload_to_value(value);
                            let (leaf_c, _w) =
                                self.scheme.commit_with_witness(&[Some(&y[..])]).ok()?;
                            (leaf_c.as_ref().to_vec(), y.to_vec(), child.as_ref())
                        }
                        VerkleNode::Empty => {
                            let y = [0u8; 32];
                            let (empty_c, _w) =
                                self.scheme.commit_with_witness(&[Some(&y[..])]).ok()?;
                            (empty_c.as_ref().to_vec(), y.to_vec(), child.as_ref())
                        }
                    }
                } else {
                    let y = [0u8; 32];
                    let (empty_c, _w) = self.scheme.commit_with_witness(&[Some(&y[..])]).ok()?;
                    (empty_c.as_ref().to_vec(), y.to_vec(), &VerkleNode::Empty)
                };

                let selector = Selector::Position(idx as usize);
                let proof = self
                    .scheme
                    .create_proof_from_witness(witness, &selector, &y_bytes)
                    .ok()?;
                per_level_proofs.push(proof.as_ref().to_vec());
                node_commitments.push(next_commitment_bytes);
                cursor = next_node;
            } else {
                break;
            }
        }

        let terminal = match cursor {
            VerkleNode::Leaf { value, .. } => Terminal::Leaf(value.clone()),
            VerkleNode::Empty => Terminal::Empty,
            VerkleNode::Internal { .. } => Terminal::Empty,
        };

        Some(VerklePathProof {
            params_id: self.scheme.params.fingerprint(),
            node_commitments,
            per_level_proofs,
            terminal,
        })
    }
}
