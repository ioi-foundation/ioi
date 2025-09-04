// Path: crates/api/src/state/accessor.rs
//! A dyn-safe trait for state access within decorators and hooks.

use crate::state::StateManager;
use depin_sdk_types::error::StateError;

/// A dyn-safe trait that erases the generic `StateManager` type, allowing
/// services to interact with state without knowing its concrete implementation.
pub trait StateAccessor: Send + Sync {
    /// Gets a value by key.
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError>;
    /// Inserts a key-value pair.
    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError>;
    /// Deletes a key-value pair.
    fn delete(&mut self, key: &[u8]) -> Result<(), StateError>;
    /// Sets multiple key-value pairs in a single batch operation.
    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError>;
}

// Blanket implementation to allow any `StateManager` to be used as a `StateAccessor`.
impl<T: StateManager + Send + Sync + ?Sized> StateAccessor for T {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        // Since we can't call T::get directly on a trait object `self`,
        // we must call the methods defined in the StateCommitment supertrait.
        T::get(self, key)
    }
    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        T::insert(self, key, value)
    }
    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        T::delete(self, key)
    }
    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        T::batch_set(self, updates)
    }
}
