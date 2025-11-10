// Path: crates/state/src/tree/iavl/proof_builder.rs

use super::node::IAVLNode;
use super::proof::{self, ExistenceProof, HashOp, InnerOp, LeafOp, LengthOp, NonExistenceProof, Side};
use super::tree::IAVLTree;
use ioi_api::commitment::{CommitmentScheme, Selector};
use parity_scale_codec::Encode;
use std::sync::Arc;

impl<CS: CommitmentScheme> IAVLTree<CS>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + std::fmt::Debug,
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
{
    /// Builds the final, scheme-wrapped proof for a given key against a specific tree root.
    pub(super) fn build_proof_for_root(
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

        let proof_data = proof.encode();
        let value = self.to_value(&proof_data);
        self.scheme
            .create_proof(&Selector::Key(key.to_vec()), &value)
            .ok()
    }

    /// Builds a proof of existence for the given key by traversing from `start_node`.
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

                    // Define the canonical LeafOp for your chain's IAVL tree here.
                    // This MUST match the logic in `hash_leaf`.
                    let leaf_op = LeafOp {
                        hash: HashOp::Sha256,
                        prehash_key: HashOp::NoHash,
                        prehash_value: HashOp::NoHash,
                        length: LengthOp::VarProto,
                        prefix: {
                            let mut p = Vec::with_capacity(1 + 8 + 4 + 8);
                            p.push(0x00); // leaf tag
                            p.extend_from_slice(&current_node.version.to_le_bytes());
                            p.extend_from_slice(&0i32.to_le_bytes()); // height is always 0 for leaves
                            p.extend_from_slice(&1u64.to_le_bytes()); // size is always 1 for leaves
                            p
                        },
                    };

                    return Some(ExistenceProof {
                        key: current_node.key.clone(),
                        value: current_node.value.clone(),
                        leaf: leaf_op,
                        path,
                    });
                } else {
                    return None;
                }
            }

            let (next_node, side, sibling_hash) = if key <= current_node.key.as_slice() {
                (
                    current_node.left.clone(),
                    Side::Right,
                    current_node
                        .right
                        .as_ref()
                        .map(|n| n.hash.clone())
                        .unwrap_or_else(IAVLNode::empty_hash),
                )
            } else {
                (
                    current_node.right.clone(),
                    Side::Left,
                    current_node
                        .left
                        .as_ref()
                        .map(|n| n.hash.clone())
                        .unwrap_or_else(IAVLNode::empty_hash),
                )
            };

            let sibling_hash_array: [u8; 32] = match sibling_hash.try_into() {
                Ok(arr) => arr,
                Err(_) => return None,
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

    /// Builds a proof of non-existence by finding the key's neighbors.
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

    /// Helper to find the largest key smaller than the given key.
    fn find_predecessor(&self, start_node: &Option<Arc<IAVLNode>>, key: &[u8]) -> Option<Vec<u8>> {
        let mut current = start_node.as_ref();
        let mut predecessor = None;
        while let Some(node) = current {
            if node.is_leaf() {
                if node.key.as_slice() < key {
                    predecessor = Some(node.key.clone());
                }
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

    /// Helper to find the smallest key larger than the given key.
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
}