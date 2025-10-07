// Path: crates/api/src/state/commitment.rs
//! Defines the `StateCommitment` trait for key-value storage with cryptographic commitments.

use depin_sdk_types::error::StateError;
use std::any::Any;
use std::fmt::Debug;
use std::sync::Arc;

/// An atomically reference-counted, owned key slice.
pub type StateKey = Arc<[u8]>;
/// An atomically reference-counted, owned value slice.
pub type StateVal = Arc<[u8]>;
/// An owned key-value pair from the state, using cheap-to-clone Arcs.
pub type StateKVPair = (StateKey, StateVal);
/// A streaming iterator over key-value pairs from the state. It is Send-safe
/// to be moved across async tasks. `Sync` is omitted as iterators are stateful.
pub type StateScanIter<'a> =
    Box<dyn Iterator<Item = Result<StateKVPair, StateError>> + Send + 'a>;

/// A trait for generic state commitment operations.
///
/// A `StateCommitment` provides a key-value storage interface that can produce a
/// single, verifiable cryptographic commitment (e.g., a Merkle root) over its entire state.
pub trait StateCommitment: Debug {
    /// The commitment type (e.g., a hash or an elliptic curve point).
    type Commitment: Clone + Send + Sync + 'static;
    /// The proof type (e.g., a Merkle proof or a Verkle proof).
    type Proof: Clone + Send + Sync + 'static; // <-- FIX: Added Send + Sync + 'static bounds

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
        &self,
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), StateError>;
    /// Provides access to the concrete type for downcasting.
    fn as_any(&self) -> &dyn Any;
    /// Provides mutable access to the concrete type for downcasting.
    fn as_any_mut(&mut self) -> &mut dyn Any;

    /// TEMPORARY: export all KV pairs for snapshotting.
    /// Object-safe, returns an owned vec so it works behind trait objects.
    /// Implementations should use internal caches for speed.
    fn export_kv_pairs(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        Vec::new() // Default implementation returns empty.
    }

    /// Scans for all key-value pairs starting with the given prefix.
    fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError>;
}

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
    ) -> Result<(), StateError> {
        (**self)
            .verify_proof(commitment, proof, key, value)
            .map_err(Into::into)
    }
    fn as_any(&self) -> &dyn Any {
        (**self).as_any()
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        (**self).as_any_mut()
    }
    fn export_kv_pairs(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        (**self).export_kv_pairs()
    }
    fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
        (**self).prefix_scan(prefix)
    }
}