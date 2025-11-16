// Path: crates/state/src/tree/iavl/proof_builder.rs
//! Store-aware proof construction logic for the IAVL tree.
//!
//! This module contains the functions responsible for building proofs of existence
//! and non-existence by traversing the tree structure by hash, lazily loading
//! nodes from the `IAVLTree`'s cache or the underlying persistent store.

use super::node::{NodeHash, EMPTY_HASH};
use super::proof::{
    self, ExistenceProof, HashOp, InnerOp, LeafOp, LengthOp, NonExistenceProof, Side,
};
use super::tree::IAVLTree;
use ioi_api::commitment::{CommitmentScheme, Selector};
use parity_scale_codec::Encode;
use std::fmt::Debug;

/// The main entry point for proof generation. It determines whether to build an
/// existence or non-existence proof and wraps it in the commitment scheme's proof type.
pub(super) fn build_proof_for_root<CS: CommitmentScheme>(
    tree: &IAVLTree<CS>,
    root_hash: Option<NodeHash>,
    key: &[u8],
) -> Option<CS::Proof>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + Debug,
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
    CS::Witness: Default,
{
    // Determine membership by performing a store-aware get.
    let proof = if tree.get_recursive(root_hash, key).ok()?.is_some() {
        build_existence_proof_from_root(tree, root_hash, key).map(proof::IavlProof::Existence)
    } else {
        build_non_existence_proof_from_root(tree, root_hash, key)
            .map(proof::IavlProof::NonExistence)
    }?;

    // The inner IAVL proof is SCALE-encoded and becomes the "value" for the outer proof wrapper.
    let proof_data = proof.encode();
    let value = tree.to_value(&proof_data);

    // Create a default witness. For HashCommitmentScheme, this is `()`.
    let witness = CS::Witness::default();

    tree.scheme
        .create_proof(&witness, &Selector::Key(key.to_vec()), &value)
        .ok()
}

/// Builds a proof of existence for the given key by traversing the tree by hash from a starting root.
fn build_existence_proof_from_root<CS: CommitmentScheme>(
    tree: &IAVLTree<CS>,
    start_hash: Option<NodeHash>,
    key: &[u8],
) -> Option<ExistenceProof>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + Debug,
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
{
    let mut path = Vec::new();
    let mut current_hash_opt = start_hash;

    while let Some(current_hash) = current_hash_opt {
        // Lazily load the current node using its hash.
        let current_node = tree.get_node(current_hash).ok()?.unwrap(); // Should exist if hash is valid

        if current_node.is_leaf() {
            // We've reached a leaf. If the key matches, we're done.
            if current_node.key == key {
                path.reverse();

                // Define the canonical LeafOp for the chain's IAVL tree profile.
                // This must be kept in sync with IAVLNode::compute_hash's leaf logic.
                let leaf_op = LeafOp {
                    hash: HashOp::Sha256,
                    prehash_key: HashOp::NoHash,
                    prehash_value: HashOp::Sha256, // The value is hashed before being included in the preimage.
                    length: LengthOp::VarProto,
                    prefix: vec![0x00],
                };

                return Some(ExistenceProof {
                    key: current_node.key.clone(),
                    value: current_node.value.clone(),
                    leaf: leaf_op,
                    path,
                });
            } else {
                // Leaf found, but key doesn't match. This path is invalid for an existence proof.
                return None;
            }
        }

        // If it's an inner node, decide which child to traverse and record the sibling.
        let (next_hash, side, sibling_hash) = if key <= current_node.key.as_slice() {
            (
                current_node.left_hash,
                Side::Right,
                current_node.right_hash.unwrap_or(EMPTY_HASH),
            )
        } else {
            (
                current_node.right_hash,
                Side::Left,
                current_node.left_hash.unwrap_or(EMPTY_HASH),
            )
        };

        path.push(InnerOp {
            version: current_node.version,
            height: current_node.height,
            size: current_node.size,
            split_key: current_node.key.clone(),
            side,
            sibling_hash,
        });
        current_hash_opt = next_hash;
    }
    // If the loop terminates without finding a leaf, the key does not exist.
    None
}

/// Builds a proof of non-existence by finding the key's immediate neighbors (if they exist)
/// and constructing existence proofs for them.
fn build_non_existence_proof_from_root<CS: CommitmentScheme>(
    tree: &IAVLTree<CS>,
    start_hash: Option<NodeHash>,
    key: &[u8],
) -> Option<NonExistenceProof>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + Debug,
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
{
    let left_key = find_predecessor(tree, start_hash, key);
    let right_key = find_successor(tree, start_hash, key);

    // If no neighbors exist, the tree is empty. The proof is valid.
    if left_key.is_none() && right_key.is_none() {
        return Some(NonExistenceProof {
            missing_key: key.to_vec(),
            left: None,
            right: None,
        });
    }

    // Build existence proofs for the neighbors we found.
    let left_proof = left_key.and_then(|k| build_existence_proof_from_root(tree, start_hash, &k));
    let right_proof = right_key.and_then(|k| build_existence_proof_from_root(tree, start_hash, &k));

    Some(NonExistenceProof {
        missing_key: key.to_vec(),
        left: left_proof,
        right: right_proof,
    })
}

/// Helper to find the largest key smaller than the given key. Traverses by hash.
fn find_predecessor<CS: CommitmentScheme>(
    tree: &IAVLTree<CS>,
    start_hash: Option<NodeHash>,
    key: &[u8],
) -> Option<Vec<u8>>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + Debug,
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
{
    let mut current_hash_opt = start_hash;
    let mut predecessor = None;

    while let Some(hash) = current_hash_opt {
        if let Ok(Some(node)) = tree.get_node(hash) {
            if node.is_leaf() {
                if node.key.as_slice() < key {
                    predecessor = Some(node.key.clone());
                }
                break; // End of path
            }

            if key > node.key.as_slice() {
                // This inner node's split key is a predecessor candidate.
                // The actual predecessor might be in the right subtree.
                if let Some(max_of_left) = node.left_hash.and_then(|lh| tree.find_max(lh).ok()) {
                    predecessor = Some(max_of_left.key.clone());
                }
                current_hash_opt = node.right_hash;
            } else {
                // Key is in the left subtree, so this node's key is not a predecessor.
                current_hash_opt = node.left_hash;
            }
        } else {
            break;
        }
    }
    predecessor
}

/// Helper to find the smallest key larger than the given key. Traverses by hash.
fn find_successor<CS: CommitmentScheme>(
    tree: &IAVLTree<CS>,
    start_hash: Option<NodeHash>,
    key: &[u8],
) -> Option<Vec<u8>>
where
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + Debug,
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: AsRef<[u8]>,
{
    let mut current_hash_opt = start_hash;
    let mut successor = None;

    while let Some(hash) = current_hash_opt {
        if let Ok(Some(node)) = tree.get_node(hash) {
            if node.is_leaf() {
                if node.key.as_slice() > key {
                    successor = Some(node.key.clone());
                }
                break; // End of path
            }
            if key < node.key.as_slice() {
                // This inner node's key is a successor candidate.
                // A better successor might be in the left subtree.
                if let Some(min_of_right) = node.right_hash.and_then(|rh| tree.find_min(rh).ok()) {
                    successor = Some(min_of_right.key.clone());
                }
                current_hash_opt = node.left_hash;
            } else {
                // Key is in the right subtree, so this node's key is not a successor.
                current_hash_opt = node.right_hash;
            }
        } else {
            break;
        }
    }
    successor
}
