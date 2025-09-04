// Path: crates/api/src/state/overlay.rs

//! A copy-on-write state overlay for transaction simulation.

use crate::state::StateAccessor;
use depin_sdk_types::error::StateError;
use std::collections::HashMap;

/// An in-memory, copy-on-write overlay for any `StateAccessor`.
///
/// Reads are first checked against the local `writes` cache. If a key is not
/// found, the read is passed through to the underlying `base` state.
/// All writes are captured in the local cache and do not affect the `base` state.
#[derive(Clone)]
pub struct StateOverlay<'a> {
    base: &'a dyn StateAccessor,
    writes: HashMap<Vec<u8>, Option<Vec<u8>>>, // Use Option to represent deletions
}

impl<'a> StateOverlay<'a> {
    /// Creates a new, empty overlay on top of a base state accessor.
    pub fn new(base: &'a dyn StateAccessor) -> Self {
        Self {
            base,
            writes: HashMap::new(),
        }
    }
}

impl<'a> StateAccessor for StateOverlay<'a> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        if let Some(value_opt) = self.writes.get(key) {
            // Key is in our write set, return the cached value (which could be None for a delete)
            Ok(value_opt.clone())
        } else {
            // Fall back to the base state
            self.base.get(key)
        }
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.writes.insert(key.to_vec(), Some(value.to_vec()));
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        self.writes.insert(key.to_vec(), None);
        Ok(())
    }

    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        for (key, value) in updates {
            self.insert(key, value)?;
        }
        Ok(())
    }
}