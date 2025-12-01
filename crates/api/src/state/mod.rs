// Path: crates/api/src/state/mod.rs
//! Core traits for state management, refactored into a granular, capability-based hierarchy.
//!
//! This module defines the primary interfaces for interacting with the blockchain's state:
//! - `StateAccess`: For basic key-value store operations.
//! - `VerifiableState`: For data structures that can produce a cryptographic root commitment.
//! - `ProofProvider`: For generating and verifying proofs of state.
//! - `StateManager`: The high-level umbrella trait for components that manage the full
//!   lifecycle of versioned, verifiable state.

use crate::commitment::CommitmentScheme;
use async_trait::async_trait;
use ioi_types::app::Membership;
use ioi_types::error::{ProofError, StateError};
use parity_scale_codec::{Decode, Encode};
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::sync::Arc;

// --- Type Aliases for common state patterns ---
/// An atomically reference-counted, owned key slice.
pub type StateKey = Arc<[u8]>;
/// An atomically reference-counted, owned value slice.
pub type StateVal = Arc<[u8]>;
/// An owned key-value pair from the state, using cheap-to-clone Arcs.
pub type StateKVPair = (StateKey, StateVal);
/// A streaming iterator over key-value pairs from the state. It is Send-safe
/// to be moved across async tasks. `Sync` is omitted as iterators are stateful.
pub type StateScanIter<'a> = Box<dyn Iterator<Item = Result<StateKVPair, StateError>> + Send + 'a>;

// --- Module Structure ---

mod accessor;
mod commitment;
mod manager;
pub mod namespaced;
mod overlay;
pub mod pins;
mod proof; // New module for proof-related traits
pub mod retention; // [NEW]

// --- Public Exports ---

pub use accessor::*;
pub use commitment::*;
pub use manager::*;
pub use namespaced::{service_namespace_prefix, NamespacedStateAccess};
pub use overlay::*;
pub use pins::{PinGuard, StateVersionPins};
pub use proof::*;
pub use retention::{RetentionHandle, RetentionManager}; // [NEW]

/// A plan detailing which historical state versions should be pruned.
#[derive(Debug, Clone, Default)]
pub struct PrunePlan {
    /// The primary cutoff height. Any version with a height *strictly less than* this
    /// is a candidate for pruning.
    pub cutoff_height: u64,
    /// A set of heights that must be excluded from pruning, even if they are below the cutoff.
    /// This is used to "pin" versions that are actively in use for tasks like proof generation.
    pub excluded_heights: BTreeSet<u64>,
}

impl PrunePlan {
    /// Checks if a given height is explicitly excluded from this pruning plan.
    #[inline]
    pub fn excludes(&self, height: u64) -> bool {
        self.excluded_heights.contains(&height)
    }
}

/// A trait for components that need to prevent historical state from being pruned.
///
/// Implementing this trait allows a subsystem (e.g., a light client verifier,
/// a long-running computation job, or a fraud proof window tracker) to express
/// a "hard floor" on state retention.
///
/// The Garbage Collector guarantees that no state version `v` where `v >= min_required_height()`
/// will be deleted.
pub trait PruningGuard: Debug + Send + Sync {
    /// Returns the minimum block height that this component requires to remain accessible.
    ///
    /// # Semantics
    /// - Return `u64::MAX` if you have *no constraint* on pruning (GC will ignore you).
    /// - Return `0` if you require that *no historical state is ever pruned* (effectively disabling GC).
    ///
    /// In the context of `WorkloadContainer::run_gc_pass`, the GC determines the cutoff as:
    /// `cutoff = min(config_retention, guard_1.min(), guard_2.min(), ...)`
    fn min_required_height(&self) -> u64;
}

/// A trait for a stateless cryptographic proof verifier.
pub trait Verifier: Send + Sync {
    /// The concrete type of a cryptographic commitment (e.g., a hash, a curve point).
    type Commitment: Clone + Send + Sync + 'static;
    /// The concrete type of a proof (e.g., a Merkle path, a KZG proof).
    type Proof: Encode + Decode + for<'de> serde::Deserialize<'de> + Send + Sync + 'static;

    /// Converts raw bytes (from IPC/storage) into the concrete Commitment type.
    fn commitment_from_bytes(&self, bytes: &[u8]) -> Result<Self::Commitment, StateError>;

    /// Verifies a proof of membership or non-membership against a root commitment.
    fn verify(
        &self,
        root: &Self::Commitment,
        proof: &Self::Proof,
        key: &[u8],
        outcome: &Membership,
    ) -> Result<(), ProofError>;
}

/// A dyn-safe trait for the VM to access state, abstracting away the concrete StateManager type.
#[async_trait]
pub trait VmStateAccessor: Send + Sync {
    /// Retrieves a value from the state by key.
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError>;
    /// Inserts a key-value pair into the state.
    async fn insert(&self, key: &[u8], value: &[u8]) -> Result<(), StateError>;
    /// Deletes a key-value pair from the state.
    async fn delete(&self, key: &[u8]) -> Result<(), StateError>;

    /// Scans keys with the given prefix and returns all matching key-value pairs.
    ///
    /// Returns a vector rather than an iterator because standard Rust iterators/streams
    /// are difficult to make object-safe across async boundaries without pinning/boxing overhead
    /// that complicates the VM host bridge.
    async fn prefix_scan(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StateError>;
}

// --- Type Aliases ---

/// Type alias for a `StateManager` trait object compatible with a specific `CommitmentScheme`.
pub type StateManagerFor<CS> = dyn StateManager<
    Commitment = <CS as CommitmentScheme>::Commitment,
    Proof = <CS as CommitmentScheme>::Proof,
>;
