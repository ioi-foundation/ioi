// Path: crates/state/src/tree/iavl/proof.rs
//! Production-grade, ICS-23-inspired proof verification for the IAVL tree.
//! This module contains the proof data structures and the pure, stateless verifier function.

use ioi_types::error::ProofError;
use parity_scale_codec::{Decode, Encode};

/// The canonical hash function used for all IAVL operations.
fn hash(data: &[u8]) -> Result<[u8; 32], ProofError> {
    ioi_crypto::algorithms::hash::sha256(data).map_err(|e| ProofError::Crypto(e.to_string()))
}

// --- ICS-23 Style Hashing Primitives ---

/// Defines the hash operation to apply to a key or value before concatenation.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub enum HashOp {
    /// Do not hash the data; use it directly.
    NoHash,
    /// Apply SHA-256 to the data.
    Sha256,
}

/// Defines how the length of a key or value is encoded in the preimage.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub enum LengthOp {
    /// No length prefix is used.
    NoPrefix,
    /// A protobuf-style varint length prefix is used.
    VarProto,
}

// --- Canonical Hashing Rules (Now ICS-23 Compliant) ---

/// Computes the hash of a leaf node by interpreting an `LeafOp` structure.
/// This function is designed to be directly compatible with ICS-23 verifiers.
pub(super) fn hash_leaf(
    leaf_op: &LeafOp,
    key: &[u8],
    value: &[u8],
) -> Result<[u8; 32], ProofError> {
    fn apply_hash(op: &HashOp, data: &[u8]) -> Result<Vec<u8>, ProofError> {
        match op {
            HashOp::NoHash => Ok(data.to_vec()),
            HashOp::Sha256 => hash(data).map(|h| h.to_vec()),
        }
    }

    fn apply_length(op: &LengthOp, data: &[u8]) -> Result<Vec<u8>, ProofError> {
        match op {
            LengthOp::NoPrefix => Ok(data.to_vec()),
            LengthOp::VarProto => {
                let mut len_prefixed =
                    Vec::with_capacity(prost::length_delimiter_len(data.len()) + data.len());
                // prost::encode_length_delimiter can return a prost::EncodeError, which we need to handle.
                prost::encode_length_delimiter(data.len(), &mut len_prefixed)?;
                len_prefixed.extend_from_slice(data);
                Ok(len_prefixed)
            }
        }
    }

    let hashed_key = apply_hash(&leaf_op.prehash_key, key)?;
    let hashed_value = apply_hash(&leaf_op.prehash_value, value)?;

    let mut data = Vec::new();
    data.extend_from_slice(&leaf_op.prefix);
    data.extend_from_slice(&apply_length(&leaf_op.length, &hashed_key)?);
    data.extend_from_slice(&apply_length(&leaf_op.length, &hashed_value)?);

    match leaf_op.hash {
        HashOp::Sha256 => hash(&data),
        HashOp::NoHash => {
            // This case should not be used for Merkle trees but is included for completeness.
            let hash_vec = hash(&data)?;
            let mut h = [0u8; 32];
            h.copy_from_slice(&hash_vec[..32]);
            Ok(h)
        }
    }
}

/// Computes the hash of an inner node according to the canonical specification.
/// H(tag || version || height || size || len(key) || key || left_hash || right_hash)
pub(super) fn hash_inner(
    op: &InnerOp,
    left_hash: &[u8; 32],
    right_hash: &[u8; 32],
) -> Result<[u8; 32], ProofError> {
    let mut data = Vec::with_capacity(
        1 + 8 + 4 + 8 + 4 + op.split_key.len() + left_hash.len() + right_hash.len(),
    );
    data.push(0x01); // Inner node tag
    data.extend_from_slice(&op.version.to_le_bytes());
    data.extend_from_slice(&op.height.to_le_bytes());
    data.extend_from_slice(&op.size.to_le_bytes());
    data.extend_from_slice(&(op.split_key.len() as u32).to_le_bytes());
    data.extend_from_slice(&op.split_key);
    data.extend_from_slice(left_hash);
    data.extend_from_slice(right_hash);
    hash(&data)
}

// --- Proof Data Structures ---

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub enum IavlProof {
    Existence(ExistenceProof),
    NonExistence(NonExistenceProof),
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct ExistenceProof {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub leaf: LeafOp,
    pub path: Vec<InnerOp>,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct NonExistenceProof {
    pub missing_key: Vec<u8>,
    pub left: Option<ExistenceProof>,
    pub right: Option<ExistenceProof>,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct LeafOp {
    pub hash: HashOp,
    pub prehash_key: HashOp,
    pub prehash_value: HashOp,
    pub length: LengthOp,
    pub prefix: Vec<u8>,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
}

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct InnerOp {
    pub version: u64,
    pub height: i32,
    pub size: u64,
    pub split_key: Vec<u8>,
    pub side: Side,
    pub sibling_hash: [u8; 32],
}

// --- Public Root Computation API ---

/// Computes the Merkle root hash implied by the given proof.
///
/// This function does not verify the proof against a known root or key;
/// it simply calculates the root hash that this proof asserts.
pub fn compute_root_from_proof(proof: &IavlProof) -> Result<[u8; 32], ProofError> {
    match proof {
        IavlProof::Existence(p) => compute_root_from_existence(p),
        IavlProof::NonExistence(p) => compute_root_from_non_existence(p),
    }
}

/// Computes the root hash from an ExistenceProof using the key and value contained within it.
pub fn compute_root_from_existence(p: &ExistenceProof) -> Result<[u8; 32], ProofError> {
    let mut current_hash = hash_leaf(&p.leaf, &p.key, &p.value)?;

    for step in &p.path {
        let (left, right) = match step.side {
            Side::Left => (step.sibling_hash, current_hash),
            Side::Right => (current_hash, step.sibling_hash),
        };
        current_hash = hash_inner(step, &left, &right)?;
    }
    Ok(current_hash)
}

/// Computes the root hash from a NonExistenceProof.
///
/// A NonExistenceProof implies a specific root hash by proving the existence of
/// the left and/or right neighbors of the missing key.
pub fn compute_root_from_non_existence(p: &NonExistenceProof) -> Result<[u8; 32], ProofError> {
    // If both are None, it implies an empty tree.
    if p.left.is_none() && p.right.is_none() {
        // Return the hash of an empty tree (SHA256 of empty bytes)
        return hash(&[]);
    }

    let left_root = p
        .left
        .as_ref()
        .map(compute_root_from_existence)
        .transpose()?;
    let right_root = p
        .right
        .as_ref()
        .map(compute_root_from_existence)
        .transpose()?;

    match (left_root, right_root) {
        (Some(l), None) => Ok(l),
        (None, Some(r)) => Ok(r),
        (Some(l), Some(r)) => {
            if l != r {
                return Err(ProofError::RootMismatch); // Neighbors imply different roots
            }
            Ok(l)
        }
        (None, None) => unreachable!(), // Handled by the empty tree check above
    }
}

// --- Verifier Logic ---

/// The single, canonical entry point for all IAVL proof verification.
pub fn verify_iavl_proof(
    root: &[u8; 32],
    key: &[u8],
    expected_value: Option<&[u8]>,
    proof: &IavlProof,
) -> Result<bool, ProofError> {
    // 1. Structure and Semantics Check
    match (expected_value, proof) {
        (Some(val), IavlProof::Existence(p)) => {
            if p.key != key || p.value != val {
                return Err(ProofError::InvalidExistence(
                    "Proof is for a different key/value pair".into(),
                ));
            }
        }
        (None, IavlProof::NonExistence(p)) => {
            if p.missing_key != key {
                return Ok(false);
            }
            // Verify neighbor ordering logic for non-existence
            if let Some(l) = &p.left {
                if l.key >= p.missing_key {
                    return Ok(false);
                }
            }
            if let Some(r) = &p.right {
                if r.key <= p.missing_key {
                    return Ok(false);
                }
            }
            if let (Some(l), Some(r)) = (&p.left, &p.right) {
                if l.key >= r.key {
                    return Ok(false);
                }
            }
        }
        // Mismatched expectations (e.g., expecting a value but got NonExistence proof)
        _ => return Ok(false),
    }

    // 2. Cryptographic Verification
    // Recompute the root hash asserted by the proof.
    let calculated_root = compute_root_from_proof(proof)?;

    // 3. Root Match
    if calculated_root != *root {
        return Err(ProofError::RootMismatch);
    }

    Ok(true)
}
