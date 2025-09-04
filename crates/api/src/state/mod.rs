// Path: crates/api/src/state/mod.rs
//! Core traits for state management, including `StateCommitment` and `StateManager`.

use crate::commitment::CommitmentScheme;
use async_trait::async_trait;
use depin_sdk_types::error::StateError;

mod accessor;
mod commitment;
mod manager;
mod overlay;

pub use accessor::*;
pub use commitment::*;
pub use manager::*;
pub use overlay::*;

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
