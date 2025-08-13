// Path: crates/commitment/src/primitives/hash/mod.rs
//! Hash-based commitment scheme implementations

use depin_sdk_api::commitment::{CommitmentScheme, ProofContext, SchemeIdentifier, Selector};
use depin_sdk_crypto::algorithms::hash;
use serde::{Deserialize, Serialize}; // Add this line
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

impl AsRef<[u8]> for HashCommitment {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Hash-based proof
// UPDATE: Add Serialize and Deserialize
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashProof {
    /// The value this proof corresponds to (e.g., serialized Merkle proof data)
    pub value: Vec<u8>,
    /// Selector used for this proof
    pub selector: Selector,
    /// Additional proof data
    pub additional_data: Vec<u8>,
}

// FIX: Implement the missing trait bound that caused all the compiler errors.
// This allows state trees to get the raw proof data they need for verification.
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
    pub fn hash_data(&self, data: &[u8]) -> Vec<u8> {
        match self.hash_function {
            HashFunction::Sha256 => hash::sha256(data),
            HashFunction::Sha512 => hash::sha512(data),
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

impl CommitmentScheme for HashCommitmentScheme {
    type Commitment = HashCommitment;
    type Proof = HashProof;
    type Value = Vec<u8>;

    fn commit(&self, values: &[Option<Self::Value>]) -> Self::Commitment {
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
        if combined.is_empty() {
            return HashCommitment(self.hash_data(&[]));
        }

        // Return the hash of the combined data
        HashCommitment(self.hash_data(&combined))
    }

    fn create_proof(
        &self,
        selector: &Selector,
        value: &Self::Value,
    ) -> Result<Self::Proof, String> {
        // Create additional data based on selector type
        let additional_data = match selector {
            Selector::Key(key) => {
                // For key-based selectors, include the key hash
                self.hash_data(key)
            }
            Selector::Position(pos) => {
                // For position-based selectors, include the position
                pos.to_le_bytes().to_vec()
            }
            _ => Vec::new(),
        };

        // FIX: Store the raw value in the proof instead of its hash.
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
        // FIX: The logic here needs to be updated to reflect the new structure of HashProof
        if &proof.selector != selector || &proof.value != value {
            return false;
        }

        // Basic direct verification for simple cases
        match selector {
            Selector::None => {
                // For a single value, directly compare the hash
                self.hash_data(value) == commitment.as_ref()
            }
            Selector::Key(key) => {
                // For a key-value pair, hash the combination
                let mut combined = Vec::new();
                combined.extend_from_slice(key);
                combined.extend_from_slice(value);
                let key_value_hash = self.hash_data(&combined);

                // Use context if provided
                if let Some(verification_flag) = context.get_data("strict_verification") {
                    if !verification_flag.is_empty() && verification_flag[0] == 1 {
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
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() {
            return Err("Empty bytes".to_string());
        }

        let mut pos = 0;

        // Deserialize selector
        let selector_type = bytes[pos];
        pos += 1;

        let selector = match selector_type {
            0 => Selector::None,
            1 => {
                if pos + 8 > bytes.len() {
                    return Err("Invalid position selector".to_string());
                }
                let mut position_bytes = [0u8; 8];
                position_bytes.copy_from_slice(&bytes[pos..pos + 8]);
                pos += 8;
                Selector::Position(usize::from_le_bytes(position_bytes))
            }
            2 => {
                if pos + 4 > bytes.len() {
                    return Err("Invalid key selector".to_string());
                }
                let mut len_bytes = [0u8; 4];
                len_bytes.copy_from_slice(&bytes[pos..pos + 4]);
                pos += 4;
                let key_len = u32::from_le_bytes(len_bytes) as usize;

                if pos + key_len > bytes.len() {
                    return Err("Invalid key length".to_string());
                }
                let key = bytes[pos..pos + key_len].to_vec();
                pos += key_len;
                Selector::Key(key)
            }
            3 => {
                if pos + 4 > bytes.len() {
                    return Err("Invalid predicate selector".to_string());
                }
                let mut len_bytes = [0u8; 4];
                len_bytes.copy_from_slice(&bytes[pos..pos + 4]);
                pos += 4;
                let pred_len = u32::from_le_bytes(len_bytes) as usize;

                if pos + pred_len > bytes.len() {
                    return Err("Invalid predicate length".to_string());
                }
                let pred = bytes[pos..pos + pred_len].to_vec();
                pos += pred_len;
                Selector::Predicate(pred)
            }
            _ => return Err(format!("Unknown selector type: {selector_type}")),
        };

        // Deserialize value
        if pos + 4 > bytes.len() {
            return Err("Invalid value length".to_string());
        }
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&bytes[pos..pos + 4]);
        pos += 4;
        let value_len = u32::from_le_bytes(len_bytes) as usize;

        if pos + value_len > bytes.len() {
            return Err("Invalid value length".to_string());
        }
        let value = bytes[pos..pos + value_len].to_vec();
        pos += value_len;

        // Deserialize additional data
        if pos + 4 > bytes.len() {
            return Err("Invalid additional data length".to_string());
        }
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&bytes[pos..pos + 4]);
        pos += 4;
        let add_len = u32::from_le_bytes(len_bytes) as usize;

        if pos + add_len > bytes.len() {
            return Err("Invalid additional data length".to_string());
        }
        let additional_data = bytes[pos..pos + add_len].to_vec();

        Ok(HashProof {
            value,
            selector,
            additional_data,
        })
    }
}
