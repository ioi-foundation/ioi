// Path: crates/scs/src/index.rs

use crate::format::{FrameId, FrameType}; // [FIX] Import FrameType
use anyhow::{anyhow, Result};
use ioi_api::state::{ProofProvider, VerifiableState};
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::mhnsw::{
    metric::{CosineSimilarity, Vector},
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
        // [COMPATIBILITY] Delegate to insert_with_metadata with default (Observation) type.
        self.insert_with_metadata(frame_id, vector, FrameType::Observation, [0u8; 32])
    }

    /// [NEW] Inserts a vector embedding with rich metadata (FrameType + Visual Hash).
    /// This enables "Hybrid Search" (filtering by type or visual similarity).
    ///
    /// The payload stored in the graph is:
    /// [FrameId (8)] || [FrameType (1)] || [VisualHash (32)]
    /// Total: 41 bytes.
    pub fn insert_with_metadata(
        &mut self, 
        frame_id: FrameId, 
        vector: Vec<f32>, 
        frame_type: FrameType,
        visual_hash: [u8; 32]
    ) -> Result<()> {
        let vec = Vector(vector);
        
        let mut payload = Vec::with_capacity(41);
        payload.extend_from_slice(&frame_id.to_le_bytes());
        
        // Encode FrameType as u8. Assuming basic enum without data variants matches `as u8` or simple match.
        // FrameType implements Encode (SCALE), so we use that for stability.
        // Actually, for compact index, manual byte packing is safer/smaller.
        let type_byte = match frame_type {
            FrameType::Observation => 0,
            FrameType::Thought => 1,
            FrameType::Action => 2,
            FrameType::System => 3,
            FrameType::Skill => 4, 
            FrameType::Overlay => 5, // [FIX] Added Overlay variant
        };
        payload.push(type_byte);
        
        payload.extend_from_slice(&visual_hash);

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
            // [FIX] Update parser to handle new expanded payload (41 bytes) OR legacy (8 bytes)
            if payload.len() == 8 {
                let frame_id = FrameId::from_le_bytes(payload.try_into().unwrap());
                mapped_results.push((frame_id, dist));
            } else if payload.len() == 41 {
                let frame_id = FrameId::from_le_bytes(payload[0..8].try_into().unwrap());
                mapped_results.push((frame_id, dist));
            } else {
                return Err(anyhow!(
                    "Corrupt index payload: expected 8 or 41 bytes, got {}",
                    payload.len()
                ));
            }
        }
        Ok(mapped_results)
    }
    
    /// [NEW] Performs a Hybrid Search, returning detailed metadata.
    /// Used by `retrieve_context` to filter results.
    ///
    /// Returns: (FrameId, Distance, FrameType, VisualHash)
    pub fn search_hybrid(&self, query: &[f32], k: usize) -> Result<Vec<(FrameId, f32, FrameType, [u8; 32])>> {
        let q_vec = Vector(query.to_vec());
        let results = self
            .inner
            .search(&q_vec, k)
            .map_err(|e| anyhow!("mHNSW search failed: {}", e))?;

        let mut mapped_results = Vec::with_capacity(results.len());
        for (payload, dist) in results {
            if payload.len() == 41 {
                let frame_id = FrameId::from_le_bytes(payload[0..8].try_into().unwrap());
                let type_byte = payload[8];
                let mut visual_hash = [0u8; 32];
                visual_hash.copy_from_slice(&payload[9..41]);
                
                let frame_type = match type_byte {
                    0 => FrameType::Observation,
                    1 => FrameType::Thought,
                    2 => FrameType::Action,
                    3 => FrameType::System,
                    4 => FrameType::Skill,
                    5 => FrameType::Overlay, // [FIX] Added Overlay variant
                    _ => FrameType::Observation, // Fallback
                };
                
                mapped_results.push((frame_id, dist, frame_type, visual_hash));
            } else if payload.len() == 8 {
                 // Legacy fallback
                 let frame_id = FrameId::from_le_bytes(payload.try_into().unwrap());
                 mapped_results.push((frame_id, dist, FrameType::Observation, [0u8; 32]));
            }
        }
        Ok(mapped_results)
    }

    /// Generates a Proof of Retrieval for a search query.
    ///
    /// This is the key "Trust" feature. It proves that the agent actually searched
    /// this specific memory structure and didn't hallucinate or omit records.
    pub fn generate_proof(&self, query: &[f32], k: usize) -> Result<RetrievalProof> {
        let q_vec = Vector(query.to_vec());

        // Delegate to the inner graph's proof generation logic.
        // We use the `search_with_proof` method which returns both results and the traversal trace.
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