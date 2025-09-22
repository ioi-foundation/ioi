// Path: crates/api/src/state/overlay.rs

//! A copy-on-write state overlay for transaction simulation.

use crate::state::StateAccessor;
use depin_sdk_types::error::StateError;
use std::collections::BTreeMap;

/// A batch of key-value pairs to be inserted or updated in the state.
pub type StateInserts = Vec<(Vec<u8>, Vec<u8>)>;

/// A batch of keys to be deleted from the state.
pub type StateDeletes = Vec<Vec<u8>>;

/// A complete set of state changes (inserts/updates and deletes) from a transaction.
pub type StateChangeSet = (StateInserts, StateDeletes);

/// An in-memory, copy-on-write overlay for any `StateAccessor`.
///
/// Reads are first checked against the local `writes` cache. If a key is not
/// found, the read is passed through to the underlying `base` state.
/// All writes are captured in the local cache and do not affect the `base` state.
#[derive(Clone)]
pub struct StateOverlay<'a> {
    base: &'a dyn StateAccessor,
    writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>, // Use BTreeMap for deterministic commit order.
}

impl<'a> StateOverlay<'a> {
    /// Creates a new, empty overlay on top of a base state accessor.
    pub fn new(base: &'a dyn StateAccessor) -> Self {
        Self {
            base,
            writes: BTreeMap::new(),
        }
    }

    /// Consumes the overlay and returns its writes in a deterministic order.
    /// This is used to commit the transaction's state changes back to the canonical state.
    pub fn into_ordered_batch(self) -> StateChangeSet {
        let mut inserts = Vec::new();
        let mut deletes = Vec::new();

        for (key, value_opt) in self.writes {
            match value_opt {
                Some(value) => inserts.push((key, value)),
                None => deletes.push(key),
            }
        }
        (inserts, deletes)
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

    fn prefix_scan(
        &self,
        prefix: &[u8],
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, depin_sdk_types::error::StateError> {
        // 1. Get the results from the base state.
        let mut base_results: BTreeMap<Vec<u8>, Vec<u8>> =
            self.base.prefix_scan(prefix)?.into_iter().collect();

        // 2. Iterate through the overlay's writes that match the prefix.
        // BTreeMap's range iterator is efficient for this.
        for (key, value_opt) in self.writes.range(prefix.to_vec()..) {
            if !key.starts_with(prefix) {
                // We've moved past the relevant prefix in the sorted map.
                break;
            }

            match value_opt {
                // An insert or update in the overlay.
                Some(value) => {
                    base_results.insert(key.clone(), value.clone());
                }
                // A delete in the overlay.
                None => {
                    base_results.remove(key);
                }
            }
        }

        // 3. Convert the merged BTreeMap back to the required Vec format.
        Ok(base_results.into_iter().collect())
    }
}
