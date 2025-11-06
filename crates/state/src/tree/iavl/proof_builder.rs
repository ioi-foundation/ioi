//! Contains the logic to build production-grade proofs by traversing an `IAVLTree`.

use super::{
    proof::{ExistenceProof, InnerOp, LeafOp, NonExistenceProof, Side},
    IAVLTree,
};
use ioi_api::commitment::CommitmentScheme;
use std::cmp::Ordering;

impl<CS: CommitmentScheme> IAVLTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]>,
{
    /// Builds a proof of existence for the given key.
    pub(super) fn build_existence_proof(&self, key: &[u8]) -> Option<ExistenceProof> {
        let mut path = Vec::new();
        let mut current_node_opt = self.root.clone();

        while let Some(current_node) = current_node_opt {
            let (next_node, side, sibling_hash) = match key.cmp(&current_node.key) {
                Ordering::Less => (
                    current_node.left.clone(),
                    Side::Left,
                    current_node
                        .right
                        .as_ref()
                        .map(|n| n.hash.clone())
                        .unwrap_or_else(|| [0u8; 32].to_vec()),
                ),
                Ordering::Greater => (
                    current_node.right.clone(),
                    Side::Right,
                    current_node
                        .left
                        .as_ref()
                        .map(|n| n.hash.clone())
                        .unwrap_or_else(|| [0u8; 32].to_vec()),
                ),
                Ordering::Equal => {
                    // Leaf found. Finalize proof.
                    let leaf = LeafOp {
                        version: current_node.version,
                    };
                    return Some(ExistenceProof {
                        key: current_node.key.clone(),
                        value: current_node.value.clone(),
                        leaf,
                        path,
                    });
                }
            };

            path.insert(
                0, // Prepend to build path from root to leaf
                InnerOp {
                    version: current_node.version,
                    height: current_node.height,
                    size: current_node.size,
                    split_key: current_node.key.clone(),
                    side,
                    sibling_hash: sibling_hash.try_into().unwrap(),
                },
            );

            current_node_opt = next_node;
        }

        None // Key not found
    }

    /// Builds a proof of non-existence for the given key.
    pub(super) fn build_non_existence_proof(&self, key: &[u8]) -> Option<NonExistenceProof> {
        // Find the predecessor (left neighbor) and successor (right neighbor).
        let left_key = self.find_predecessor(key);
        let right_key = self.find_successor(key);

        if left_key.is_none() && right_key.is_none() {
            // Tree is empty, so no proof is possible or needed.
            return Some(NonExistenceProof {
                missing_key: key.to_vec(),
                left: None,
                right: None,
            });
        }

        let left_proof = left_key.and_then(|k| self.build_existence_proof(&k));
        let right_proof = right_key.and_then(|k| self.build_existence_proof(&k));

        Some(NonExistenceProof {
            missing_key: key.to_vec(),
            left: left_proof,
            right: right_proof,
        })
    }

    // Helper to find the largest key smaller than the given key.
    fn find_predecessor(&self, key: &[u8]) -> Option<Vec<u8>> {
        let mut current = self.root.as_ref();
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

    // Helper to find the smallest key larger than the given key.
    fn find_successor(&self, key: &[u8]) -> Option<Vec<u8>> {
        let mut current = self.root.as_ref();
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
