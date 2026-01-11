// Path: crates/scs/src/index.rs

//! Integration of the IOI Merkelized HNSW (mHNSW) index into the SCS format.
//!
//! This module provides the logic to:
//! 1. Build an mHNSW index from a set of frames and embeddings.
//! 2. Serialize the index to the `.scs` file.
//! 3. Generate cryptographic "Proof of Retrieval" for agent queries.

use crate::format::FrameId;
use anyhow::{anyhow, Result};
use ioi_api::state::{ProofProvider, VerifiableState};
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::mhnsw::{
    metric::{CosineSimilarity, Vector},
    node::NodeHash,
    proof::TraversalProof,
    MHnswIndex,
};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// A wrapper for the IOI mHNSW index that handles serialization for the SCS file format.
pub struct VectorIndex {
    /// The underlying mHNSW graph.
    /// We use HashCommitmentScheme (SHA-256) and CosineSimilarity.
    inner: MHnswIndex<HashCommitmentScheme, CosineSimilarity>,
}

/// A serialized artifact of the Vector Index, ready to be written to disk.
#[derive(Debug, Encode, Decode, Serialize, Deserialize)]
pub struct VectorIndexArtifact {
    /// The raw bytes of the serialized mHNSW graph.
    pub bytes: Vec<u8>,
    /// The number of vectors in the index.
    pub count: u64,
    /// The dimension of the vectors.
    pub dimension: u32,
    /// The Merkle Root of the index.
    pub root_hash: [u8; 32],
}

/// A cryptographic proof that a search result was retrieved correctly from the index.
#[derive(Debug, Encode, Decode, Serialize, Deserialize)]
pub struct RetrievalProof {
    /// The Merkle Root of the index against which this proof is valid.
    pub root_hash: [u8; 32],
    /// The traversal trace proving the greedy search path.
    pub traversal: TraversalProof,
}

impl VectorIndex {
    /// Creates a new, empty Vector Index.
    pub fn new(m: usize, ef_construction: usize) -> Self {
        let scheme = HashCommitmentScheme::new();
        let metric = CosineSimilarity::default();
        Self {
            inner: MHnswIndex::new(scheme, metric, m, ef_construction),
        }
    }

    /// Inserts a vector embedding associated with a frame.
    ///
    /// # Arguments
    /// * `frame_id` - The ID of the frame this vector belongs to.
    /// * `vector` - The float vector embedding.
    pub fn insert(&mut self, frame_id: FrameId, vector: Vec<f32>) -> Result<()> {
        let vec = Vector(vector);
        // Payload is just the FrameId (u64 le bytes) for mapping back.
        let payload = frame_id.to_le_bytes().to_vec();

        self.inner
            .insert_vector(vec, payload)
            .map_err(|e| anyhow!("mHNSW insert failed: {}", e))
    }

    /// Searches the index for the nearest neighbors to a query vector.
    ///
    /// Returns a list of (FrameId, Distance) tuples.
    pub fn search(&self, query: &[f32], k: usize) -> Result<Vec<(FrameId, f32)>> {
        let q_vec = Vector(query.to_vec());
        let results = self
            .inner
            .search(&q_vec, k)
            .map_err(|e| anyhow!("mHNSW search failed: {}", e))?;

        let mut mapped_results = Vec::with_capacity(results.len());
        for (payload, dist) in results {
            if payload.len() != 8 {
                return Err(anyhow!(
                    "Corrupt index payload: expected 8 bytes, got {}",
                    payload.len()
                ));
            }
            let frame_id = FrameId::from_le_bytes(payload.try_into().unwrap());
            mapped_results.push((frame_id, dist));
        }
        Ok(mapped_results)
    }

    /// Generates a Proof of Retrieval for a search query.
    ///
    /// This is the key "Trust" feature. It proves that the agent actually searched
    /// this specific memory structure and didn't hallucinate or omit records.
    pub fn generate_proof(&self, query: &[f32], k: usize) -> Result<RetrievalProof> {
        let q_vec = Vector(query.to_vec());

        // We use the search_with_proof method from MHnswIndex
        // Since graph is now public, we can access it.
        let (_, traversal_proof) = self
            .inner
            .graph
            .search_with_proof(&q_vec, k)
            .map_err(|e| anyhow!("Proof generation failed: {}", e))?;

        let commitment = self.inner.root_commitment();
        let root_hash: [u8; 32] = commitment
            .as_ref()
            .try_into()
            .map_err(|_| anyhow!("Invalid root hash length"))?;

        Ok(RetrievalProof {
            root_hash,
            traversal: traversal_proof,
        })
    }

    /// Serializes the index to a byte vector for storage in the .scs file.
    pub fn serialize_to_artifact(&self) -> Result<VectorIndexArtifact> {
        // Serialize the internal graph nodes using SCALE codec.
        // graph is now public
        let graph_bytes = self.inner.graph.encode();

        let count = self.inner.graph.nodes.len() as u64;

        // Infer dimension from the entry point or first node, or default to 0 if empty.
        let dimension = if let Some(eid) = self.inner.graph.entry_point {
            if let Some(node) = self.inner.graph.nodes.get(&eid) {
                // Vector bytes length / 4 (f32)
                (node.vector.len() / 4) as u32
            } else {
                0
            }
        } else {
            0
        };

        let commitment = self.inner.root_commitment();
        let root_hash: [u8; 32] = commitment
            .as_ref()
            .try_into()
            .map_err(|_| anyhow!("Invalid root hash length"))?;

        Ok(VectorIndexArtifact {
            bytes: graph_bytes,
            count,
            dimension,
            root_hash,
        })
    }

    /// Deserializes an index from an artifact read from disk.
    pub fn from_artifact(artifact: &VectorIndexArtifact) -> Result<Self> {
        // Reconstruct the graph from bytes
        let graph = ioi_state::tree::mhnsw::graph::HnswGraph::decode(&mut &*artifact.bytes)
            .map_err(|e| anyhow!("Failed to decode HNSW graph: {}", e))?;

        // Use the new public constructor to rebuild the index
        let index = MHnswIndex::from_graph(graph);

        Ok(Self { inner: index })
    }
}
