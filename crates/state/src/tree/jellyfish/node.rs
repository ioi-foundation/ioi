// Path: crates/state/src/tree/jellyfish/node.rs

//! Node definitions for Jellyfish Merkle Tree.

use ioi_api::commitment::CommitmentStructure; // [NEW]
use ioi_crypto::algorithms::hash::sha256;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub type NodeHash = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub enum Node {
    /// Internal node with up to 16 children.
    Internal(InternalNode),
    /// Leaf node containing value hash.
    Leaf(LeafNode),
    /// Null node (empty).
    Null,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct InternalNode {
    /// Sparse children map. Index is the nibble (0-15).
    /// Stores the hash of the child node.
    pub children: Vec<(u8, NodeHash)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct LeafNode {
    /// The full key hash corresponding to this leaf.
    pub account_key: [u8; 32],
    /// The hash of the value stored.
    pub value_hash: [u8; 32],
}

impl Node {
    /// Computes the hash of the node using the provided commitment scheme.
    pub fn hash<CS: CommitmentStructure>(&self, _scheme: &CS) -> NodeHash {
        match self {
            Node::Internal(n) => {
                let encoded = n.encode();
                // Internal nodes in JMT are specific structure; currently using SHA256 default
                // as generic CommitmentStructure is binary-tree oriented.
                // For Phase 3.1 we stick to SHA256 for internal structure to avoid re-arch.
                sha256(&encoded).unwrap_or([0u8; 32])
            }
            Node::Leaf(n) => {
                // [FIX] Use the scheme's leaf commitment logic (e.g. H(key || value))
                // instead of hardcoded encoding.
                // We use CS::commit_leaf (associated function) as the trait defines it static.
                match CS::commit_leaf(&n.account_key, &n.value_hash) {
                    Ok(bytes) => {
                        let mut arr = [0u8; 32];
                        // Handle potential size mismatch if scheme output != 32 bytes
                        let len = bytes.len().min(32usize);
                        arr[..len].copy_from_slice(&bytes[..len]);
                        arr
                    }
                    Err(_) => [0u8; 32], // Fallback/Panic strategy should be improved in prod
                }
            }
            Node::Null => [0u8; 32],
        }
    }
}
