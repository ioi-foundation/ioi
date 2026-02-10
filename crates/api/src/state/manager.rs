// Path: crates/api/src/state/manager.rs
//! Defines the `StateManager` trait for versioning and lifecycle management of state.

use crate::state::{ProofProvider, PrunePlan, StateAccess, VerifiableState};
use crate::storage::NodeStore;
use async_trait::async_trait;
use ioi_types::app::RootHash;
use ioi_types::error::StateError;
use std::sync::Arc;

/// The state manager interface, adding versioning and lifecycle management capabilities
/// on top of the base state and proof traits.
#[async_trait]
pub trait StateManager: StateAccess + VerifiableState + ProofProvider {
    /// Prunes historical state versions according to a specific plan.
    fn prune(&mut self, plan: &PrunePlan) -> Result<(), StateError>;

    /// Incrementally prunes a batch of historical state versions according to a plan.
    fn prune_batch(&mut self, plan: &PrunePlan, limit: usize) -> Result<usize, StateError>;

    /// Commits the current pending changes, creating a snapshot associated with a block height.
    fn commit_version(&mut self, height: u64) -> Result<RootHash, StateError>;

    /// (For debug builds) Checks if a given root hash corresponds to a known, persisted version.
    fn version_exists_for_root(&self, _root: &Self::Commitment) -> bool {
        true
    }

    /// Commits the current pending changes and persists the delta to a durable `NodeStore`.
    ///
    /// This is async to allow backpressure handling from the storage backend.
    async fn commit_version_persist(
        &mut self,
        height: u64,
        _store: &dyn NodeStore,
    ) -> Result<RootHash, StateError> {
        self.commit_version(height)
    }

    /// Informs the state manager of a pre-existing, valid version from a durable source.
    fn adopt_known_root(&mut self, root_bytes: &[u8], version: u64) -> Result<(), StateError>;

    /// Optional: attach a NodeStore so implementations can hydrate proofs on demand.
    fn attach_store(&mut self, _store: Arc<dyn NodeStore>) {}

    /// Hints to the backend that writes for a specific block height are about to begin.
    fn begin_block_writes(&mut self, _height: u64) {}
}

#[async_trait]
impl<T: StateManager + ?Sized + Send> StateManager for Box<T> {
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

    async fn commit_version_persist(
        &mut self,
        height: u64,
        store: &dyn NodeStore,
    ) -> Result<RootHash, StateError> {
        (**self).commit_version_persist(height, store).await
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
