// Path: crates/state/src/primitives/hash/mod.rs
//! Hash-based commitment scheme implementations

use ioi_api::commitment::{
    CommitmentScheme, CommitmentStructure, ProofContext, SchemeIdentifier, Selector,
};
use ioi_api::error::CryptoError;
use ioi_crypto::algorithms::hash::{self, sha256};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// Hash-based commitment scheme
#[derive(Debug, Clone)]
pub struct HashCommitmentScheme {
    /// Hash function to use (defaults to SHA-256)
    hash_function: HashFunction,
}

/// Available hash functions
#[derive(Debug, Clone, Copy)]
pub enum HashFunction {
    /// SHA-256
    Sha256,
    /// SHA-512
    Sha512,
}

/// Hash-based commitment
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashCommitment(Vec<u8>);

impl From<Vec<u8>> for HashCommitment {
    fn from(v: Vec<u8>) -> Self {
        HashCommitment(v)
    }
}

impl AsRef<[u8]> for HashCommitment {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Hash-based proof
#[derive(Encode, Decode, Debug, Clone, Serialize, Deserialize)]
pub struct HashProof {
    /// The value this proof corresponds to (e.g., serialized Merkle proof data)
    pub value: Vec<u8>,
    /// Selector used for this proof
    pub selector: Selector,
    /// Additional proof data
    pub additional_data: Vec<u8>,
}

impl AsRef<[u8]> for HashProof {
    fn as_ref(&self) -> &[u8] {
        &self.value
    }
}

impl HashCommitmentScheme {
    /// Create a new hash commitment scheme with the default hash function (SHA-256)
    pub fn new() -> Self {
        Self {
            hash_function: HashFunction::Sha256,
        }
    }

    /// Create a new hash commitment scheme with a specific hash function
    pub fn with_hash_function(hash_function: HashFunction) -> Self {
        Self { hash_function }
    }

    /// Helper function to hash data using the selected hash function
    pub fn hash_data(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self.hash_function {
            HashFunction::Sha256 => Ok(hash::sha256(data)?.to_vec()),
            HashFunction::Sha512 => Ok(hash::sha512(data)?.to_vec()),
        }
    }

    /// Get the current hash function
    pub fn hash_function(&self) -> HashFunction {
        self.hash_function
    }

    /// Get the digest size in bytes
    pub fn digest_size(&self) -> usize {
        match self.hash_function {
            HashFunction::Sha256 => 32,
            HashFunction::Sha512 => 64,
        }
    }
}

impl CommitmentStructure for HashCommitmentScheme {
    fn commit_leaf(key: &[u8], value: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // [OPTIMIZED] Pre-allocate buffer to avoid reallocation during extend.
        let mut data = Vec::with_capacity(1 + key.len() + value.len());
        data.push(0x00); // Leaf prefix
        data.extend_from_slice(key);
        data.extend_from_slice(value);
        let hash = sha256(&data)?;
        Ok(hash.to_vec())
    }

    fn commit_branch(left: &[u8], right: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // [OPTIMIZED] Pre-allocate buffer.
        let mut data = Vec::with_capacity(1 + left.len() + right.len());
        data.push(0x01); // Branch prefix
        data.extend_from_slice(left);
        data.extend_from_slice(right);
        let hash = sha256(&data)?;
        Ok(hash.to_vec())
    }
}

impl CommitmentScheme for HashCommitmentScheme {
    type Commitment = HashCommitment;
    type Proof = HashProof;
    type Value = Vec<u8>;
    type Witness = ();

    fn commit_with_witness(
        &self,
        values: &[Option<Self::Value>],
    ) -> Result<(Self::Commitment, Self::Witness), CryptoError> {
        // Simple commitment: hash the concatenation of all values
        let mut combined = Vec::new();

        for value in values {
            if let Some(v) = value {
                // Add length prefix to prevent collision attacks
                combined.extend_from_slice(&(v.len() as u32).to_le_bytes());
                combined.extend_from_slice(v);
            } else {
                // Mark None values with a zero length
                combined.extend_from_slice(&0u32.to_le_bytes());
            }
        }

        // If there are no values, hash an empty array
        let commitment = if combined.is_empty() {
            HashCommitment(self.hash_data(&[])?)
        } else {
            // Return the hash of the combined data
            HashCommitment(self.hash_data(&combined)?)
        };

        Ok((commitment, ()))
    }

    fn create_proof(
        &self,
        _witness: &Self::Witness,
        selector: &Selector,
        value: &Self::Value,
    ) -> Result<Self::Proof, CryptoError> {
        // Create additional data based on selector type
        let additional_data = match selector {
            Selector::Key(key) => {
                // For key-based selectors, include the key hash
                self.hash_data(key)?
            }
            Selector::Position(pos) => {
                // For position-based selectors, include the position
                pos.to_le_bytes().to_vec()
            }
            _ => Vec::new(),
        };

        Ok(HashProof {
            value: value.clone(),
            selector: selector.clone(),
            additional_data,
        })
    }

    fn verify(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        selector: &Selector,
        value: &Self::Value,
        context: &ProofContext,
    ) -> bool {
        if &proof.selector != selector || &proof.value != value {
            return false;
        }

        // Basic direct verification for simple cases
        match selector {
            Selector::None => {
                // For a single value, directly compare the hash
                self.hash_data(value)
                    .is_ok_and(|h| h == commitment.as_ref())
            }
            Selector::Key(key) => {
                // For a key-value pair, hash the combination
                let mut combined = Vec::new();
                combined.extend_from_slice(key);
                combined.extend_from_slice(value);
                let key_value_hash = match self.hash_data(&combined) {
                    Ok(h) => h,
                    Err(_) => return false,
                };

                // Use context if provided
                if let Some(verification_flag) = context.get_data("strict_verification") {
                    // --- FIX: Use .get() to avoid panicking index ---
                    if verification_flag.get(0) == Some(&1) {
                        // Strict verification mode would go here
                        return key_value_hash == commitment.as_ref();
                    }
                }

                key_value_hash == commitment.as_ref()
            }
            _ => {
                // For position or predicate selectors, this basic commitment scheme
                // cannot verify on its own - would require tree structure knowledge
                // This would be handled by state tree implementations
                false
            }
        }
    }

    fn scheme_id() -> SchemeIdentifier {
        SchemeIdentifier::new("hash")
    }
}

// Default implementation
impl Default for HashCommitmentScheme {
    fn default() -> Self {
        Self::new()
    }
}

// Additional utility methods for HashCommitment
impl HashCommitment {
    /// Create a new commitment from raw bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Get the raw commitment bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert to a new owned Vec<u8>
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
    }
}

// Additional utility methods for HashProof
impl HashProof {
    /// Create a new proof
    pub fn new(value: Vec<u8>, selector: Selector, additional_data: Vec<u8>) -> Self {
        Self {
            value,
            selector,
            additional_data,
        }
    }

    /// Get the selector
    pub fn selector(&self) -> &Selector {
        &self.selector
    }

    /// Get the value
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Get the additional data
    pub fn additional_data(&self) -> &[u8] {
        &self.additional_data
    }

    /// Convert to a serializable format
    pub fn to_bytes(&self) -> Vec<u8> {
        // Simplified serialization
        let mut result = Vec::new();

        // Serialize selector
        match &self.selector {
            Selector::Position(pos) => {
                result.push(1); // Selector type
                result.extend_from_slice(&pos.to_le_bytes());
            }
            Selector::Key(key) => {
                result.push(2); // Selector type
                result.extend_from_slice(&(key.len() as u32).to_le_bytes());
                result.extend_from_slice(key);
            }
            Selector::Predicate(pred) => {
                result.push(3); // Selector type
                result.extend_from_slice(&(pred.len() as u32).to_le_bytes());
                result.extend_from_slice(pred);
            }
            Selector::None => {
                result.push(0); // Selector type
            }
        }

        // Serialize value
        result.extend_from_slice(&(self.value.len() as u32).to_le_bytes());
        result.extend_from_slice(&self.value);

        // Serialize additional data
        result.extend_from_slice(&(self.additional_data.len() as u32).to_le_bytes());
        result.extend_from_slice(&self.additional_data);

        result
    }

    /// Create from serialized format
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let err = || CryptoError::Deserialization("Invalid proof bytes".into());
        let mut cursor = bytes;

        let (&selector_type, rest) = cursor.split_first().ok_or_else(err)?;
        cursor = rest;

        let selector = match selector_type {
            0 => Selector::None,
            1 => {
                if cursor.len() < 8 {
                    return Err(err());
                }
                let (pos_bytes, rest) = cursor.split_at(8);
                let mut position_bytes = [0u8; 8];
                position_bytes.copy_from_slice(pos_bytes);
                cursor = rest;
                Selector::Position(u64::from_le_bytes(position_bytes))
            }
            2 => {
                if cursor.len() < 4 {
                    return Err(err());
                }
                let (len_bytes_slice, rest) = cursor.split_at(4);
                let mut len_bytes = [0u8; 4];
                len_bytes.copy_from_slice(len_bytes_slice);
                let key_len = u32::from_le_bytes(len_bytes) as usize;
                cursor = rest;

                if cursor.len() < key_len {
                    return Err(err());
                }
                let (key_bytes, rest) = cursor.split_at(key_len);
                let key = key_bytes.to_vec();
                cursor = rest;

                Selector::Key(key)
            }
            3 => {
                if cursor.len() < 4 {
                    return Err(err());
                }
                let (len_bytes_slice, rest) = cursor.split_at(4);
                let mut len_bytes = [0u8; 4];
                len_bytes.copy_from_slice(len_bytes_slice);
                let pred_len = u32::from_le_bytes(len_bytes) as usize;
                cursor = rest;

                if cursor.len() < pred_len {
                    return Err(err());
                }
                let (pred_bytes, rest) = cursor.split_at(pred_len);
                let pred = pred_bytes.to_vec();
                cursor = rest;

                Selector::Predicate(pred)
            }
            _ => {
                return Err(CryptoError::Deserialization(format!(
                    "Unknown selector type: {selector_type}"
                )))
            }
        };

        // Deserialize value
        if cursor.len() < 4 {
            return Err(err());
        }
        let (len_bytes_slice, rest) = cursor.split_at(4);
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(len_bytes_slice);
        let value_len = u32::from_le_bytes(len_bytes) as usize;
        cursor = rest;

        if cursor.len() < value_len {
            return Err(err());
        }
        let (value_bytes, rest) = cursor.split_at(value_len);
        let value = value_bytes.to_vec();
        cursor = rest;

        // Deserialize additional data
        if cursor.len() < 4 {
            return Err(err());
        }
        let (len_bytes_slice, rest) = cursor.split_at(4);
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(len_bytes_slice);
        let add_len = u32::from_le_bytes(len_bytes) as usize;
        cursor = rest;

        if cursor.len() < add_len {
            return Err(err());
        }
        let (add_data_bytes, _) = cursor.split_at(add_len);
        let additional_data = add_data_bytes.to_vec();

        Ok(HashProof {
            value,
            selector,
            additional_data,
        })
    }
}
