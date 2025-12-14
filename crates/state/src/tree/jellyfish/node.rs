//! Node definitions for Jellyfish Merkle Tree.

use super::nibble::NibblePath;
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
    pub fn hash(&self) -> NodeHash {
        match self {
            Node::Internal(n) => {
                let encoded = n.encode();
                // [Optimization] In a real JMT, we might use a specific node prefix
                sha256(&encoded).unwrap_or([0u8; 32])
            }
            Node::Leaf(n) => {
                let encoded = n.encode();
                sha256(&encoded).unwrap_or([0u8; 32])
            }
            Node::Null => [0u8; 32],
        }
    }
}