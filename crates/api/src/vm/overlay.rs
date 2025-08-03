// Path: crates/api/src/vm/overlay.rs
use crate::state::VmStateAccessor;
use async_trait::async_trait;
use dashmap::DashMap;
use depin_sdk_types::{app::StateEntry, error::StateError};
use std::collections::HashMap;
use std::fmt::{self, Debug};
use std::sync::Arc;

/// An in-memory state overlay that captures writes from a VM execution
/// without modifying the underlying state. It is thread-safe for parallel access.
pub struct VmStateOverlay {
    parent: Arc<dyn VmStateAccessor>,
    writes: DashMap<Vec<u8>, Vec<u8>>,
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

    /// Consumes the overlay and returns the captured writes.
    pub fn into_writes(self) -> HashMap<Vec<u8>, Vec<u8>> {
        self.writes.into_iter().collect()
    }
}

#[async_trait]
impl VmStateAccessor for VmStateOverlay {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        if let Some(value_ref) = self.writes.get(key) {
            return Ok(Some(value_ref.value().clone()));
        }
        match self.parent.get(key).await? {
            Some(bytes) => {
                let entry: StateEntry = serde_json::from_slice(&bytes)
                    .map_err(|e| StateError::InvalidValue(e.to_string()))?;
                Ok(Some(entry.value))
            }
            None => Ok(None),
        }
    }

    async fn insert(&self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.writes.insert(key.to_vec(), value.to_vec());
        Ok(())
    }
}
