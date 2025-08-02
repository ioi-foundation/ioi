// Path: crates/api/src/state/manager.rs
//! Defines the `StateManager` trait, a higher-level abstraction over `StateTree`.

use crate::state::StateTree;
use depin_sdk_core::error::StateError;

/// The state manager interface for the DePIN SDK.
///
/// `StateManager` is a higher-level abstraction that must also be a `StateTree`.
/// It provides all the same core methods as `StateTree` (via inheritance) and
/// adds batching capabilities.
pub trait StateManager: StateTree {
    /// Sets multiple key-value pairs in a single batch operation.
    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError>;
    /// Gets multiple values by keys in a single batch operation.
    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError>;
}
