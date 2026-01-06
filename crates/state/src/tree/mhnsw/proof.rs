// Path: crates/state/src/tree/mhnsw/proof.rs

use super::node::{NodeHash, NodeId};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// Represents a single node visited during the graph traversal.
/// Contains the data necessary to verify the greedy decision at this step.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq)]
pub struct VisitedNode {
    /// The ID of the node.
    pub id: NodeId,
    /// The Merkle hash of the node.
    pub hash: NodeHash,
    /// The raw vector embedding (used to verify distance calculations).
    pub vector: Vec<u8>,
    /// The neighbors of this node at the specific layer being traversed.
    pub neighbors_at_layer: Vec<NodeId>,
}

/// A proof that a specific search query followed the valid graph edges
/// and reached the claimed nearest neighbors.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq)]
pub struct TraversalProof {
    /// The ID of the entry point node where the search began.
    pub entry_point_id: NodeId,
    /// The hash of the entry point node (must match the State Root).
    pub entry_point_hash: NodeHash,
    /// The sequence of nodes visited, layer by layer.
    pub trace: Vec<VisitedNode>,
    /// The final results found by the search.
    pub results: Vec<NodeId>,
}
