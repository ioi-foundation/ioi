// Path: crates/api/src/vm/overlay.rs
use crate::state::VmStateAccessor;
use async_trait::async_trait;
use dashmap::DashMap;
use ioi_types::{app::StateEntry, codec, error::StateError};
use std::fmt::{self, Debug};
use std::sync::Arc;

/// An in-memory state overlay that captures writes from a VM execution
/// without modifying the underlying state. It is thread-safe for parallel access.
#[derive(Clone)]
pub struct VmStateOverlay {
    parent: Arc<dyn VmStateAccessor>,
    writes: DashMap<Vec<u8>, Option<Vec<u8>>>,
}

impl Debug for VmStateOverlay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VmStateOverlay")
            .field("writes", &self.writes)
            .field("parent", &"Arc<dyn VmStateAccessor>") // Don't print the parent
            .finish()
    }
}

impl VmStateOverlay {
    /// Creates a new state overlay that reads from a parent `VmStateAccessor`
    /// and captures all writes in its own in-memory map.
    pub fn new(parent: Arc<dyn VmStateAccessor>) -> Self {
        Self {
            parent,
            writes: DashMap::new(),
        }
    }

    /// Consumes the overlay and returns the captured writes separated into inserts and deletes.
    pub fn into_writes(self) -> (Vec<(Vec<u8>, Vec<u8>)>, Vec<Vec<u8>>) {
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

    /// Returns a clone of captured writes without consuming the overlay.
    pub fn snapshot_writes(&self) -> (Vec<(Vec<u8>, Vec<u8>)>, Vec<Vec<u8>>) {
        let mut inserts = Vec::new();
        let mut deletes = Vec::new();
        for item in self.writes.iter() {
            match item.value() {
                Some(value) => inserts.push((item.key().clone(), value.clone())),
                None => deletes.push(item.key().clone()),
            }
        }
        (inserts, deletes)
    }
}

#[async_trait]
impl VmStateAccessor for VmStateOverlay {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        if let Some(value_ref) = self.writes.get(key) {
            // If the key is in our writes, it dictates the result.
            // Some(Some(v)) -> Present
            // Some(None) -> Deleted in this tx, so Absent
            return Ok(value_ref.value().clone());
        }
        // Fallback to parent if not in our write set.
        match self.parent.get(key).await? {
            Some(bytes) => {
                let entry: StateEntry = codec::from_bytes_canonical(&bytes)
                    .map_err(|e| StateError::InvalidValue(e.to_string()))?;
                Ok(Some(entry.value))
            }
            None => Ok(None),
        }
    }

    async fn insert(&self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.writes.insert(key.to_vec(), Some(value.to_vec()));
        Ok(())
    }

    async fn delete(&self, key: &[u8]) -> Result<(), StateError> {
        self.writes.insert(key.to_vec(), None);
        Ok(())
    }

    async fn prefix_scan(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StateError> {
        // 1. Get from parent first
        let mut results_map: std::collections::BTreeMap<Vec<u8>, Vec<u8>> =
            self.parent.prefix_scan(prefix).await?.into_iter().collect();

        // 2. Overlay local writes
        // Iterate over the DashMap. Since we need to find keys starting with prefix,
        // and DashMap isn't ordered, we scan all entries.
        // (Note: In a high-throughput scenario with massive write sets, this might need optimization,
        //  but for typical tx execution it's acceptable).
        for entry in self.writes.iter() {
            if entry.key().starts_with(prefix) {
                match entry.value() {
                    Some(val) => {
                        results_map.insert(entry.key().clone(), val.clone());
                    }
                    None => {
                        results_map.remove(entry.key());
                    }
                }
            }
        }

        Ok(results_map.into_iter().collect())
    }
}
