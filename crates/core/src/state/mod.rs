// Path: crates/core/src/state/mod.rs

//! State management interfaces for the DePIN SDK Core.

use crate::commitment::CommitmentScheme;
use crate::error::StateError;
use async_trait::async_trait;

mod manager;
mod tree;

#[cfg(test)]
mod tests;

pub use manager::*;
pub use tree::*;

/// A dyn-safe trait for the VM to access state, abstracting away the concrete StateManager type.
#[async_trait]
pub trait VmStateAccessor: Send + Sync {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError>;
    async fn insert(&self, key: &[u8], value: &[u8]) -> Result<(), StateError>;
}

/// Type alias for a StateManager trait object compatible with a specific CommitmentScheme.
pub type StateManagerFor<CS> = dyn StateManager<
    Commitment = <CS as CommitmentScheme>::Commitment,
    Proof = <CS as CommitmentScheme>::Proof,
>;

/// Type alias for a StateTree trait object compatible with a specific CommitmentScheme.
pub type StateTreeFor<CS> = dyn StateTree<
    Commitment = <CS as CommitmentScheme>::Commitment,
    Proof = <CS as CommitmentScheme>::Proof,
>;