// Path: crates/api/src/state/manager.rs
//! Defines the `StateManager` trait, a higher-level abstraction over `StateCommitment`.

use crate::state::PrunePlan;
use crate::state::StateCommitment;
use crate::storage::NodeStore;
use depin_sdk_types::app::{Membership, RootHash};
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

    /// Prunes historical state versions according to a specific plan.
    /// The plan defines a cutoff height and a set of pinned heights to exclude, ensuring
    /// that versions required for consensus or active operations are not deleted.
    fn prune(&mut self, plan: &PrunePlan) -> Result<(), StateError>;

    /// Incrementally prunes a batch of historical state versions according to a plan.
    ///
    /// This method is designed for non-blocking garbage collection. It will prune up to
    /// `limit` eligible versions in a single call.
    ///
    /// # Returns
    /// The number of versions that were successfully pruned. If this number is less than
    /// `limit`, the caller can assume there are no more eligible versions to prune in this cycle.
    fn prune_batch(&mut self, plan: &PrunePlan, limit: usize) -> Result<usize, StateError>;

    /// Commits the current pending changes, creating a snapshot associated with a block height.
    ///
    /// This method is critical for versioned state backends. It must be called once
    /// per block to create a queryable historical state version.
    ///
    /// # Arguments
    /// * `height` - The block height for which this state version is being committed.
    ///
    /// # Returns
    /// The `RootHash` ([u8; 32]) of the committed state.
    fn commit_version(&mut self, height: u64) -> Result<RootHash, StateError>;

    /// (For debug builds) Checks if a given root hash corresponds to a known, persisted version.
    /// The default implementation returns true, assuming non-versioned backends are always queryable at their latest root.
    fn version_exists_for_root(&self, _root: &Self::Commitment) -> bool {
        true
    }

    /// Commits the current pending changes and persists the delta to a durable `NodeStore`.
    /// StateManager implementations that support durable storage should override this method.
    /// The default implementation falls back to the in-memory-only `commit_version`.
    fn commit_version_persist(
        &mut self,
        height: u64,
        _store: &dyn NodeStore,
    ) -> Result<RootHash, StateError> {
        self.commit_version(height)
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

    fn prune(&mut self, plan: &PrunePlan) -> Result<(), StateError> {
        (**self).prune(plan)
    }

    fn prune_batch(&mut self, plan: &PrunePlan, limit: usize) -> Result<usize, StateError> {
        (**self).prune_batch(plan, limit)
    }

    fn commit_version(&mut self, height: u64) -> Result<RootHash, StateError> {
        (**self).commit_version(height)
    }

    fn version_exists_for_root(&self, root: &Self::Commitment) -> bool {
        (**self).version_exists_for_root(root)
    }

    fn commit_version_persist(
        &mut self,
        height: u64,
        store: &dyn NodeStore,
    ) -> Result<RootHash, StateError> {
        (**self).commit_version_persist(height, store)
    }
}