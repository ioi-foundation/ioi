// Path: crates/api/src/state/manager.rs
//! Defines the `StateManager` trait, a higher-level abstraction over `StateCommitment`.

use crate::state::StateCommitment;
use depin_sdk_types::error::StateError;

/// The state manager interface, adding batching capabilities.
///
/// `StateManager` is a higher-level abstraction that must also be a `StateCommitment`.
/// It provides all the same core methods as `StateCommitment` (via inheritance) and adds batching capabilities.
pub trait StateManager: StateCommitment {
    /// Sets multiple key-value pairs in a single batch operation.
    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError>;
    /// Gets multiple values by keys in a single batch operation.
    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError>;
}

// --- FIX START: Implement StateManager for Box<T> ---
impl<T: StateManager + ?Sized> StateManager for Box<T> {
    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        (**self).batch_set(updates)
    }

    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        (**self).batch_get(keys)
    }
}
// --- FIX END ---
