// Path: crates/state/src/tree/mhnsw/node.rs

use super::metric::Vector;
use ioi_crypto::algorithms::hash::sha256;
use parity_scale_codec::{Decode, Encode};

pub type NodeId = u64;
pub type LayerId = u8;

#[derive(Debug, Clone, Encode, Decode)]
pub struct GraphNode {
    pub id: NodeId,
    /// The raw vector embedding.
    // Note: Floats in canonical encoding must be handled carefully (IEEE 754).
    // For MVP, we serialize raw bytes.
    pub vector: Vec<u8>,
    /// The content payload (e.g., chunk text or external CID).
    pub payload: Vec<u8>,
    /// Neighbors per layer.
    pub neighbors: Vec<Vec<NodeId>>,
    /// The Merkle hash of this node.
    pub hash: [u8; 32],
}

impl GraphNode {
    pub fn new(id: NodeId, vector: Vector, payload: Vec<u8>, max_layers: usize) -> Self {
        // Convert f32 vector to bytes for storage/hashing
        let vec_bytes: Vec<u8> = vector
            .0
            .iter()
            .flat_map(|f| f.to_le_bytes().to_vec())
            .collect();

        Self {
            id,
            vector: vec_bytes,
            payload,
            neighbors: vec![Vec::new(); max_layers],
            hash: [0u8; 32],
        }
    }

    /// Computes the node's commitment hash.
    /// H(ID || Vector || Payload || H(Layer0) || ... || H(LayerN))
    pub fn compute_hash(&mut self) {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&self.id.to_le_bytes());
        preimage.extend_from_slice(&self.vector);
        preimage.extend_from_slice(&self.payload);

        for layer in &self.neighbors {
            // Sort neighbors for deterministic hashing
            let mut sorted = layer.clone();
            sorted.sort();

            let layer_bytes = sorted.encode();
            preimage.extend_from_slice(&sha256(&layer_bytes).unwrap());
        }

        self.hash = sha256(&preimage).unwrap().try_into().unwrap();
    }
}
