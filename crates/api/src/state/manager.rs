// Path: crates/api/src/state/manager.rs
//! Defines the `StateManager` trait, a higher-level abstraction over `StateCommitment`.

use crate::state::StateCommitment;
use depin_sdk_types::app::Membership;
use depin_sdk_types::error::StateError;

/// The state manager interface, adding proof generation and batching capabilities.
///
/// `StateManager` is a higher-level abstraction that must also be a `StateCommitment`.
/// It provides all the same core methods as `StateCommitment` (via inheritance) and adds
/// methods for generating historical proofs and managing the state's lifecycle.
pub trait StateManager: StateCommitment {
    /// Generates a proof for a key's membership or non-membership against a historical root.
    fn get_with_proof_at(
        &self,
        root: &Self::Commitment,
        key: &[u8],
    ) -> Result<(Membership, Self::Proof), StateError>;

    /// Converts raw bytes into the concrete Commitment type.
    fn commitment_from_bytes(&self, bytes: &[u8]) -> Result<Self::Commitment, StateError>;

    /// Converts a concrete Commitment type into raw bytes for transport.
    fn commitment_to_bytes(&self, c: &Self::Commitment) -> Vec<u8>;

    /// Sets multiple key-value pairs in a single batch operation.
    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError>;

    /// Gets multiple values by keys in a single batch operation.
    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError>;

    /// Atomically applies a batch of inserts/updates and deletes.
    /// This should be the primary method for committing transactional changes.
    fn batch_apply(
        &mut self,
        inserts: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), StateError>;

    /// Prunes historical state versions older than the specified block height.
    /// This is a hint to the backend; not all state managers may support versioning.
    fn prune(&mut self, min_height_to_keep: u64) -> Result<(), StateError>;

    /// Commits the current pending changes for versioned state managers, creating a snapshot.
    /// For non-versioned backends, this is a no-op.
    fn commit_version(&mut self) {}

    /// (For debug builds) Checks if a given root hash corresponds to a known, persisted version.
    /// The default implementation returns true, assuming non-versioned backends are always queryable at their latest root.
    fn version_exists_for_root(&self, _root: &Self::Commitment) -> bool {
        true
    }
}

// Blanket implementation to allow any `StateManager` to be used behind a `Box` trait object.
impl<T: StateManager + ?Sized> StateManager for Box<T> {
    fn get_with_proof_at(
        &self,
        root: &Self::Commitment,
        key: &[u8],
    ) -> Result<(Membership, Self::Proof), StateError> {
        (**self).get_with_proof_at(root, key)
    }

    fn commitment_from_bytes(&self, bytes: &[u8]) -> Result<Self::Commitment, StateError> {
        (**self).commitment_from_bytes(bytes)
    }

    fn commitment_to_bytes(&self, c: &Self::Commitment) -> Vec<u8> {
        (**self).commitment_to_bytes(c)
    }

    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        (**self).batch_set(updates)
    }

    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        (**self).batch_get(keys)
    }

    fn batch_apply(
        &mut self,
        inserts: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), StateError> {
        (**self).batch_apply(inserts, deletes)
    }

    fn prune(&mut self, min_height_to_keep: u64) -> Result<(), StateError> {
        (**self).prune(min_height_to_keep)
    }

    fn commit_version(&mut self) {
        (**self).commit_version()
    }

    fn version_exists_for_root(&self, root: &Self::Commitment) -> bool {
        (**self).version_exists_for_root(root)
    }
}