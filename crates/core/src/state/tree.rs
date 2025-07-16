// File: crates/core/src/state/tree.rs

use crate::error::StateError;

/// Generic state tree operations
///
/// A StateTree provides key-value storage with optional cryptographic
/// commitment and proof capabilities. It's the lower-level interface
/// intended for direct tree implementations (Merkle trees, sparse
/// Merkle trees, Patricia tries, etc.).
pub trait StateTree {
    /// The commitment type this tree uses
    type Commitment;
    
    /// The proof type this tree uses
    type Proof;

    /// Get a value by key
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError>;
    
    /// Insert a key-value pair
    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError>;
    
    /// Delete a key-value pair
    fn delete(&mut self, key: &[u8]) -> Result<(), StateError>;
    
    /// Get the root commitment of the tree
    ///
    /// # Returns
    /// * The current root commitment
    fn root_commitment(&self) -> Self::Commitment;
    
    /// Create a proof for a specific key
    ///
    /// # Arguments
    /// * `key` - The key to create a proof for
    ///
    /// # Returns
    /// * `Some(proof)` - If proof creation succeeded
    /// * `None` - If the key doesn't exist or proof creation isn't supported
    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof>;
    
    /// Verify a proof against the tree's root commitment
    ///
    /// # Arguments
    /// * `commitment` - The commitment to verify against
    /// * `proof` - The proof to verify
    /// * `key` - The key the proof is for
    /// * `value` - The value to verify
    ///
    /// # Returns
    /// * `true` - If the proof is valid
    /// * `false` - If the proof is invalid or verification isn't supported
    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8]
    ) -> bool;
}