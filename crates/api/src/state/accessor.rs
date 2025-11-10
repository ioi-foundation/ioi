// Path: crates/api/src/state/accessor.rs
//! Defines the `StateAccess` trait for key-value storage operations.

use crate::state::StateScanIter;
use ioi_types::error::StateError;

/// A dyn-safe trait that provides a complete interface for key-value storage operations,
/// including single-item, batch, and scanning methods.
///
/// This trait erases the generic `StateManager` type, allowing services and transaction
/// models to interact with state without needing to know its concrete implementation.
pub trait StateAccess: Send + Sync {
    /// Gets a value by key.
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError>;

    /// Inserts a key-value pair.
    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError>;

    /// Deletes a key-value pair.
    fn delete(&mut self, key: &[u8]) -> Result<(), StateError>;

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

    /// Scans for all key-value pairs starting with the given prefix.
    fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError>;
}

// Blanket implementation to allow `StateAccess` to be used behind a `Box` trait object.
impl<T: StateAccess + ?Sized> StateAccess for Box<T> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        (**self).get(key)
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        (**self).insert(key, value)
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        (**self).delete(key)
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

    fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
        (**self).prefix_scan(prefix)
    }
}