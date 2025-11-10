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
                let mut len_prefixed = Vec::with_capacity(prost::length_delimiter_len(data.len()) + data.len());
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

// --- Verifier Logic ---

/// The single, canonical entry point for all IAVL proof verification.
pub fn verify_iavl_proof(
    root: &[u8; 32],
    key: &[u8],
    expected_value: Option<&[u8]>,
    proof: &IavlProof,
) -> Result<bool, ProofError> {
    match (expected_value, proof) {
        (Some(value), IavlProof::Existence(existence_proof)) => {
            verify_existence(root, key, value, existence_proof)?;
            Ok(true)
        }
        (None, IavlProof::NonExistence(non_existence_proof)) => {
            verify_non_existence(root, key, non_existence_proof)
        }
        _ => Ok(false),
    }
}

fn verify_existence(
    root: &[u8; 32],
    key: &[u8],
    value: &[u8],
    proof: &ExistenceProof,
) -> Result<(), ProofError> {
    if proof.key != key || proof.value != value {
        return Err(ProofError::InvalidExistence(
            "Proof is for a different key/value pair".into(),
        ));
    }

    let mut current_hash = hash_leaf(&proof.leaf, key, value)?;

    log::debug!(
        "[IAVL Verifier] Verifying existence for key: {}",
        hex::encode(key)
    );
    log::debug!("[IAVL Verifier] Trusted Root: {}", hex::encode(root));
    log::debug!(
        "[IAVL Verifier]   - Step 0 (Leaf): hash={:.8}",
        hex::encode(current_hash).get(..8).unwrap_or("")
    );

    for (i, step) in proof.path.iter().enumerate() {
        let (left, right) = match step.side {
            Side::Left => (step.sibling_hash, current_hash),
            Side::Right => (current_hash, step.sibling_hash),
        };
        let new_hash_vec = hash_inner(step, &left, &right)?;

        log::debug!(
            "[IAVL Verifier] step={} side={:?} split={:.8} h={} sz={} acc={:.8} sib={:.8} -> new={:.8}",
            i + 1, step.side,
            hex::encode(&step.split_key).get(..8).unwrap_or(""),
            step.height, step.size,
            hex::encode(current_hash).get(..8).unwrap_or(""),
            hex::encode(step.sibling_hash).get(..8).unwrap_or(""),
            hex::encode(new_hash_vec).get(..8).unwrap_or(""),
        );
        current_hash = new_hash_vec;
    }

    log::debug!(
        "[IAVL Verifier] Final Recomputed Root: {}",
        hex::encode(current_hash)
    );

    if current_hash != *root {
        return Err(ProofError::RootMismatch);
    }
    Ok(())
}

fn verify_non_existence(
    root: &[u8; 32],
    missing_key: &[u8],
    proof: &NonExistenceProof,
) -> Result<bool, ProofError> {
    if proof.missing_key.as_slice() != missing_key {
        return Ok(false);
    }
    if proof.left.is_none() && proof.right.is_none() {
        // For an empty tree, a proof with no neighbors is valid.
        // A real verifier should check if the root is the empty hash.
        return Ok(*root == ioi_crypto::algorithms::hash::sha256([]).unwrap_or_default());
    }

    let mut left_valid = false;
    if let Some(left_proof) = &proof.left {
        if left_proof.key.as_slice() >= missing_key {
            return Ok(false);
        }
        verify_existence(root, &left_proof.key, &left_proof.value, left_proof)?;
        left_valid = true;
    }

    let mut right_valid = false;
    if let Some(right_proof) = &proof.right {
        if right_proof.key.as_slice() <= missing_key {
            return Ok(false);
        }
        verify_existence(root, &right_proof.key, &right_proof.value, right_proof)?;
        right_valid = true;
    }

    if let (Some(left_proof), Some(right_proof)) = (&proof.left, &proof.right) {
        if left_proof.key >= right_proof.key {
            return Ok(false); // Neighbors are incorrectly ordered.
        }
        Ok(left_valid && right_valid)
    } else {
        Ok(left_valid || right_valid) // At least one must be valid.
    }
}