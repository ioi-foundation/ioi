// Path: crates/api/src/state/commitment.rs
//! Defines the `StateCommitment` trait for key-value storage with cryptographic commitments.

use depin_sdk_types::error::StateError;
use std::any::Any;
use std::fmt::Debug; // Import Debug

/// A key-value pair from the state.
pub type StateKVPair = (Vec<u8>, Vec<u8>);
/// The result type for a prefix scan operation.
pub type StateScanResult = Result<Vec<StateKVPair>, StateError>;

/// A trait for generic state commitment operations.
///
/// A `StateCommitment` provides a key-value storage interface that can produce a
/// single, verifiable cryptographic commitment (e.g., a Merkle root) over its entire state.
pub trait StateCommitment: Debug {
    // A trait for generic state commitment operations.
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
        &self, // <-- FIX: Added &self to make the trait object-safe
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8],
    ) -> bool;
    /// Provides access to the concrete type for downcasting.
    fn as_any(&self) -> &dyn Any;

    /// Scans for all key-value pairs starting with the given prefix.
    fn prefix_scan(&self, prefix: &[u8]) -> StateScanResult;
}

// --- FIX START: Implement StateCommitment for Box<T> ---
impl<T: StateCommitment + ?Sized> StateCommitment for Box<T> {
    type Commitment = T::Commitment;
    type Proof = T::Proof;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        (**self).get(key)
    }
    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        (**self).insert(key, value)
    }
    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        (**self).delete(key)
    }
    fn root_commitment(&self) -> Self::Commitment {
        (**self).root_commitment()
    }
    fn create_proof(&self, key: &[u8]) -> Option<Self::Proof> {
        (**self).create_proof(key)
    }
    fn verify_proof(
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8],
    ) -> bool {
        (**self).verify_proof(commitment, proof, key, value)
    }
    fn as_any(&self) -> &dyn Any {
        (**self).as_any()
    }
    fn prefix_scan(&self, prefix: &[u8]) -> StateScanResult {
        (**self).prefix_scan(prefix)
    }
}
// --- FIX END ---
