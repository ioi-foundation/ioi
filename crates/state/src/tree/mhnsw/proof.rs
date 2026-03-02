// Path: crates/state/src/tree/mhnsw/proof.rs

use super::node::{NodeHash, NodeId};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// Policy used for ANN candidate generation before exact reranking.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct RetrievalSearchPolicy {
    /// Number of final neighbors to return.
    pub k: u32,
    /// Candidate exploration budget for ANN traversal.
    pub ef_search: u32,
    /// Hard cap on candidates that will be reranked.
    pub candidate_limit: u32,
    /// Metric label used for reranking semantics.
    pub distance_metric: String,
    /// Whether embeddings are expected to be L2-normalized.
    pub embedding_normalized: bool,
}

impl RetrievalSearchPolicy {
    pub fn default_for_k(k: usize) -> Self {
        let k_u32 = k.max(1).min(u32::MAX as usize) as u32;
        let ef = (k_u32.saturating_mul(8)).max(32);
        let cap = (k_u32.saturating_mul(4)).max(16);
        Self {
            k: k_u32,
            ef_search: ef,
            candidate_limit: cap,
            distance_metric: "cosine_distance".to_string(),
            embedding_normalized: false,
        }
    }
}

/// Represents a single node visited during the graph traversal.
/// Contains the data necessary to verify deterministic greedy decisions.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq)]
pub struct TraversalStep {
    /// The ID of the node.
    pub id: NodeId,
    /// Layer where this step was taken.
    pub layer: u32,
    /// The Merkle hash of the node.
    pub hash: NodeHash,
    /// The raw vector embedding (used to verify distance calculations).
    pub vector: Vec<u8>,
    /// The neighbors of this node at the specific layer.
    pub neighbors_at_layer: Vec<NodeId>,
    /// Chosen next node under greedy selection (if movement occurred).
    pub chosen_next: Option<NodeId>,
    /// Distance from query to this node under declared metric.
    pub distance_to_query: f32,
    /// Hash commitment over neighbor-distance material for this step.
    pub distance_commit: [u8; 32],
}

/// Candidate score record used for exact rerank commitments.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq)]
pub struct CandidateScore {
    pub id: NodeId,
    pub distance: f32,
}

/// A proof that a specific search query followed the valid graph edges
/// and reached the claimed nearest neighbors.
#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode, PartialEq)]
pub struct TraversalProof {
    /// Proof schema version.
    pub version: u8,
    /// The ID of the entry point node where the search began.
    pub entry_point_id: NodeId,
    /// The hash of the entry point node (must match the State Root).
    pub entry_point_hash: NodeHash,
    /// Hash of query vector bytes.
    pub query_hash: [u8; 32],
    /// Search policy committed for candidate generation.
    pub policy: RetrievalSearchPolicy,
    /// The sequence of nodes visited, layer by layer.
    pub trace: Vec<TraversalStep>,
    /// Compact commit-chain over traversal steps.
    pub trace_commit: [u8; 32],
    /// Candidate ids produced by ANN traversal before rerank.
    pub candidate_ids: Vec<NodeId>,
    /// Candidate count before any deterministic truncation.
    pub candidate_count_total: u32,
    /// Whether candidates were deterministically truncated to `candidate_limit`.
    pub candidate_truncated: bool,
    /// Exact rerank distances over candidate set.
    pub reranked: Vec<CandidateScore>,
    /// Final results found by the search (top-k over reranked candidates).
    pub results: Vec<NodeId>,
}
