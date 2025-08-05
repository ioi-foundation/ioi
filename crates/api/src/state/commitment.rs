// Path: crates/api/src/state/commitment.rs
//! Defines the `StateCommitment` trait for key-value storage with cryptographic commitments.

use depin_sdk_types::error::StateError;
use std::any::Any;

/// A trait for generic state commitment operations.
///
/// A `StateCommitment` provides a key-value storage interface that can produce a
/// single, verifiable cryptographic commitment (e.g., a Merkle root) over its entire state.
pub trait StateCommitment {
    /// The commitment type (e.g., a hash or an elliptic curve point).
    type Commitment;
    /// The proof type (e.g., a Merkle proof or a Verkle proof).
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
    /// Verifies a proof against a given root commitment.
    fn verify_proof(
        commitment: &Self::Commitment, // Changed to be a static-like method
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8],
    ) -> bool;
    /// Provides access to the concrete type for downcasting.
    fn as_any(&self) -> &dyn Any;
}
