// Path: crates/api/src/state/tree.rs
//! Defines the `StateTree` trait for key-value storage with cryptographic commitments.

use depin_sdk_types::error::StateError;
use std::any::Any;

/// A trait for generic state tree operations.
///
/// A `StateTree` provides key-value storage with optional cryptographic
/// commitment and proof capabilities. It is the lower-level interface
/// intended for direct tree implementations (e.g., Merkle trees).
pub trait StateTree {
    /// The commitment type this tree uses.
    type Commitment;
    /// The proof type this tree uses.
    type Proof;

    /// Gets a value by key.
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError>;
    /// Inserts a key-value pair.
    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError>;
    /// Deletes a key-value pair.
    fn delete(&mut self, key: &[u8]) -> Result<(), StateError>;
    /// Gets the root commitment of the tree.
    fn root_commitment(&self) -> Self::Commitment;
    /// Creates a proof for a specific key.
    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof>;
    /// Verifies a proof against the tree's root commitment.
    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8],
    ) -> bool;
    /// Provides access to the concrete type for downcasting.
    fn as_any(&self) -> &dyn Any;
}
