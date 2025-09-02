// Create new file: crates/commitment/src/tree/verkle/proof.rs
use depin_sdk_crypto::algorithms::hash;
use serde::{Deserialize, Serialize};

/// Computes a hash for canonical mapping functions.
fn hash(data: &[u8]) -> [u8; 32] {
    hash::sha256(data)
        .try_into()
        .expect("SHA256 must be 32 bytes")
}

/// Domain-separated map of a leaf payload to a field element's byte representation.
pub fn map_leaf_payload_to_value(payload: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(b"verkle-leaf::".len() + payload.len());
    buf.extend_from_slice(b"verkle-leaf::");
    buf.extend_from_slice(payload);
    hash(&buf)
}

/// Domain-separated map of a child commitment to a field element's byte representation.
pub fn map_child_commitment_to_value(commitment_bytes: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(b"verkle-child::".len() + commitment_bytes.len());
    buf.extend_from_slice(b"verkle-child::");
    buf.extend_from_slice(commitment_bytes);
    hash(&buf)
}

/// Map a child index `i ∈ [0,255]` to its evaluation point's byte representation.
/// We use the big-endian encoding of the integer `i` as the scalar.
pub fn index_to_point_bytes(i: u8) -> [u8; 32] {
    let mut be = [0u8; 32];
    be[31] = i;
    be
}

/// A unique identifier for a given KZG SRS or IPA parameter set.
pub type SchemeId = [u8; 32];

/// The final element in a proof path, proving either membership or non-membership.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Terminal {
    /// Proves that the path ends at a leaf with the given payload.
    Leaf(Vec<u8>),
    /// Proves that the path ends at an empty slot.
    Empty,
    /// Proves that the path diverges to a neighbor leaf with a different key stem.
    Neighbor {
        key_stem: Vec<u8>,
        payload: Vec<u8>,
    },
}

/// A complete, self-contained proof for a path in a Verkle tree.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VerklePathProof {
    /// The ID of the cryptographic parameters (e.g., SRS fingerprint) used to generate this proof.
    pub params_id: SchemeId,
    /// A list of commitments for each internal node along the path, starting from the root.
    pub node_commitments: Vec<Vec<u8>>,
    /// A list of per-level proofs, where each proof corresponds to an opening at a specific node.
    pub per_level_proofs: Vec<Vec<u8>>,
    /// The terminal witness that concludes the proof.
    pub terminal: Terminal,
}