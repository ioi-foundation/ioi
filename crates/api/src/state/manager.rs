// Path: crates/api/src/state/manager.rs
//! Defines the `StateManager` trait for versioning and lifecycle management of state.

use crate::state::{PrunePlan, StateAccess, VerifiableState, ProofProvider};
use crate::storage::NodeStore;
use ioi_types::app::RootHash;
use ioi_types::error::StateError;
use std::sync::Arc;

/// The state manager interface, adding versioning and lifecycle management capabilities
/// on top of the base state and proof traits.
///
/// `StateManager` provides the highest-level abstraction for interacting with the
/// complete state backend, including its history. It inherits key-value, commitment,
/// and proof-generation capabilities from its super-traits.
pub trait StateManager: StateAccess + VerifiableState + ProofProvider {
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

    /// Informs the state manager of a pre-existing, valid version from a durable source.
    ///
    /// This is used during crash recovery to make the in-memory state manager aware of the
    /// last committed version, allowing it to serve anchored queries against that version
    /// without needing to rebuild its entire historical index.
    fn adopt_known_root(&mut self, root_bytes: &[u8], version: u64) -> Result<(), StateError>;

    /// Optional: attach a NodeStore so implementations can hydrate proofs on demand.
    fn attach_store(&mut self, _store: Arc<dyn NodeStore>) {}

    /// Hints to the backend that writes for a specific block height are about to begin.
    /// StateManager implementations can use this to set their internal version/height counters
    /// correctly *before* applying inserts and deletes for the block.
    fn begin_block_writes(&mut self, _height: u64) {}
}

// Blanket implementation to allow any `StateManager` to be used behind a `Box` trait object.
impl<T: StateManager + ?Sized> StateManager for Box<T> {
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

    fn adopt_known_root(&mut self, root_bytes: &[u8], version: u64) -> Result<(), StateError> {
        (**self).adopt_known_root(root_bytes, version)
    }

    fn attach_store(&mut self, store: Arc<dyn NodeStore>) {
        (**self).attach_store(store)
    }

    fn begin_block_writes(&mut self, height: u64) {
        (**self).begin_block_writes(height)
    }
}