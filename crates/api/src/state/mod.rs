// Path: crates/api/src/state/mod.rs
//! Core traits for state management, including `StateCommitment` and `StateManager`.

use crate::commitment::CommitmentScheme;
use async_trait::async_trait;
use depin_sdk_types::app::Membership;
use depin_sdk_types::error::ProofError; // FIX: Corrected import path for ProofError
use depin_sdk_types::error::StateError;
use parity_scale_codec::{Decode, Encode};
use std::collections::BTreeSet;

mod accessor;
mod commitment;
mod manager;
mod overlay;
pub mod pins;

pub use accessor::*;
pub use commitment::*;
pub use manager::*;
pub use overlay::*;
pub use pins::{PinGuard, StateVersionPins};

/// A plan detailing which historical state versions should be pruned.
/// This decouples the decision-making (which can be async and involve multiple checks)
/// from the synchronous pruning action within the state manager.
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

/// A trait for a stateless cryptographic proof verifier.
///
/// This decouples the verification logic from the state management implementation,
/// allowing a remote client (like Orchestration's StateView) to verify proofs
/// without needing a full instance of the state tree.
pub trait Verifier: Send + Sync {
    /// The concrete type of a cryptographic commitment (e.g., a hash, a curve point).
    type Commitment: Clone + Send + Sync + 'static;
    /// The concrete type of a proof (e.g., a Merkle path, a KZG proof).
    type Proof: Encode + Decode + for<'de> serde::Deserialize<'de> + Send + Sync + 'static;

    /// Converts raw bytes (from IPC/storage) into the concrete Commitment type.
    /// This is a critical step for deserializing the state root before verification.
    fn commitment_from_bytes(&self, bytes: &[u8]) -> Result<Self::Commitment, StateError>;

    /// Verifies a proof of membership or non-membership against a root commitment.
    ///
    /// # Arguments
    /// * `root` - The trusted root commitment against which to verify.
    /// * `proof` - The deserialized proof object.
    /// * `key` - The key whose membership is being checked.
    /// * `outcome` - The claimed outcome (either `Membership::Present(value)` or `Membership::Absent`).
    ///
    /// # Returns
    /// `Ok(())` if the proof is valid for the given root, key, and outcome.
    /// Otherwise, returns a `ProofError`.
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
}

/// Type alias for a `StateManager` trait object compatible with a specific `CommitmentScheme`.
pub type StateManagerFor<CS> = dyn StateManager<
    Commitment = <CS as CommitmentScheme>::Commitment,
    Proof = <CS as CommitmentScheme>::Proof,
>;

/// Type alias for a `StateCommitment` trait object compatible with a specific `CommitmentScheme`.
pub type StateCommitmentFor<CS> = dyn StateCommitment<
    Commitment = <CS as CommitmentScheme>::Commitment,
    Proof = <CS as CommitmentScheme>::Proof,
>;
