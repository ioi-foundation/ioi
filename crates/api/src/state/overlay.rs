// Path: crates/api/src/state/overlay.rs

//! A copy-on-write state overlay for transaction simulation.

use crate::state::{StateAccess, StateError, StateKVPair, StateScanIter};
use ioi_types::error::StateError as DepinStateError;
use std::collections::btree_map;
use std::collections::BTreeMap;
use std::iter::{Fuse, Peekable};
use std::ops::Bound::{Excluded, Included, Unbounded};
use std::sync::Arc;

/// A batch of key-value pairs to be inserted or updated in the state.
pub type StateInserts = Vec<(Vec<u8>, Vec<u8>)>;

/// A batch of keys to be deleted from the state.
pub type StateDeletes = Vec<Vec<u8>>;

/// A complete set of state changes (inserts/updates and deletes) from a transaction.
pub type StateChangeSet = (StateInserts, StateDeletes);

/// Calculates the smallest byte vector that is strictly greater than all keys
/// starting with the given prefix. Returns None if the prefix is all 0xFF bytes.
fn next_prefix(prefix: &[u8]) -> Option<Vec<u8>> {
    if prefix.is_empty() {
        return None;
    }
    let mut ub = prefix.to_vec();
    for i in (0..ub.len()).rev() {
        if let Some(byte) = ub.get_mut(i) {
            if *byte != 0xFF {
                *byte += 1;
                ub.truncate(i + 1);
                return Some(ub);
            }
        }
    }
    None
}

struct MergingIterator<'a> {
    base: Peekable<Fuse<StateScanIter<'a>>>,
    writes: Peekable<btree_map::Range<'a, Vec<u8>, Option<Vec<u8>>>>,
}

impl<'a> Iterator for MergingIterator<'a> {
    type Item = Result<StateKVPair, StateError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let base_key = self
                .base
                .peek()
                .and_then(|res| res.as_ref().ok().map(|(k, _)| k.as_ref()));
            let write_key = self.writes.peek().map(|(k, _)| k.as_slice());

            let decision = match (base_key, write_key) {
                (Some(bk), Some(wk)) => Some(bk.cmp(wk)),
                (Some(_), None) => Some(std::cmp::Ordering::Less),
                (None, Some(_)) => Some(std::cmp::Ordering::Greater),
                (None, None) => None,
            };

            match decision {
                Some(std::cmp::Ordering::Less) => return self.base.next(),
                Some(std::cmp::Ordering::Greater) => {
                    if let Some((key, val_opt)) = self.writes.next() {
                        if let Some(val) = val_opt {
                            return Some(Ok((Arc::from(key.clone()), Arc::from(val.clone()))));
                        }
                    }
                }
                Some(std::cmp::Ordering::Equal) => {
                    self.base.next(); // Discard base item
                    if let Some((key, val_opt)) = self.writes.next() {
                        if let Some(val) = val_opt {
                            return Some(Ok((Arc::from(key.clone()), Arc::from(val.clone()))));
                        }
                    }
                }
                None => return None,
            }
        }
    }
}

/// An in-memory, copy-on-write overlay for any `StateAccess`.
///
/// Reads are first checked against the local `writes` cache. If a key is not
/// found, the read is passed through to the underlying `base` state.
/// All writes are captured in the local cache and do not affect the `base` state.
#[derive(Clone)]
pub struct StateOverlay<'a> {
    base: &'a dyn StateAccess,
    writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>, // Use BTreeMap for deterministic commit order.
}

impl<'a> StateOverlay<'a> {
    /// Creates a new, empty overlay on top of a base state accessor.
    pub fn new(base: &'a dyn StateAccess) -> Self {
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

impl<'a> StateAccess for StateOverlay<'a> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        // The `if let` was correct, but let's make it more explicit for clarity.
        match self.writes.get(key) {
            // Key is in our write set, return the cached value (which could be None for a delete)
            Some(value_opt) => Ok(value_opt.clone()),
            // Fall back to the base state
            None => self.base.get(key),
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

    fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, DepinStateError> {
        let base = self.base.prefix_scan(prefix)?.fuse().peekable();

        let start = Included(prefix.to_vec());
        let end = match next_prefix(prefix) {
            Some(ub) => Excluded(ub),
            None => Unbounded,
        };
        let writes = self.writes.range((start, end)).peekable();

        Ok(Box::new(MergingIterator { base, writes }))
    }

    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        let mut results = Vec::with_capacity(keys.len());
        for key in keys {
            results.push(self.get(key)?);
        }
        Ok(results)
    }

    fn batch_apply(&mut self, inserts: &[(Vec<u8>, Vec<u8>)], deletes: &[Vec<u8>]) -> Result<(), StateError> {
        for key in deletes { self.delete(key)?; }
        for (key, value) in inserts { self.insert(key, value)?; }
        Ok(())
    }
}