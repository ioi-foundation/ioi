// Path: crates/execution/src/mv_memory.rs
use dashmap::DashMap;
use ioi_api::state::StateAccess;
use ioi_types::error::StateError;
use parking_lot::RwLock;
use std::sync::Arc;

/// The index of a transaction in the current block.
pub type TxIndex = usize;

/// Key type optimized for low-allocation cloning
pub type StateKey = Arc<[u8]>;

/// Represents the source of a value read during execution.
#[derive(Debug, Clone, PartialEq)]
pub enum ReadVersion {
    /// Read from the initial state (storage).
    Storage,
    /// Read from a specific transaction index within the block.
    Transaction(TxIndex),
}

/// A versioned entry in memory.
#[derive(Debug, Clone)]
struct MemoryEntry {
    /// The transaction index that wrote this value.
    version: TxIndex,
    /// The value written (None implies deletion).
    value: Option<Vec<u8>>,
}

/// Multi-Version Memory for optimistic parallel execution.
/// Stores a chain of writes for every key modified in the block.
pub struct MVMemory {
    /// Map from Key -> List of writes (sorted by TxIndex).
    /// Using parking_lot for faster non-async locks.
    data: DashMap<StateKey, Arc<RwLock<Vec<MemoryEntry>>>>,
    /// Reference to the base state (pre-block state).
    base_state: Arc<dyn StateAccess>,
}

impl MVMemory {
    pub fn new(base_state: Arc<dyn StateAccess>) -> Self {
        Self {
            data: DashMap::new(),
            base_state,
        }
    }

    /// Reads the latest value for `key` visible to `tx_idx`.
    /// Returns the value and the version tag (used for validation).
    pub fn read(
        &self,
        key: &[u8],
        tx_idx: TxIndex,
    ) -> Result<(Option<Vec<u8>>, ReadVersion), StateError> {
        if let Some(entry) = self.data.get(key) {
            // Explicitly annotate type for parking_lot::RwLockReadGuard
            let versions: parking_lot::RwLockReadGuard<Vec<MemoryEntry>> = entry.read();

            // Find the highest version < tx_idx
            // Versions are inserted in execution order, but due to re-execution, we might strictly
            // search via iteration or binary search if sorted.
            // For simplicity, we iterate reversed.
            for ver in versions.iter().rev() {
                if ver.version < tx_idx {
                    return Ok((ver.value.clone(), ReadVersion::Transaction(ver.version)));
                }
            }
        }

        // Fallback to storage
        let val = self.base_state.get(key)?;
        Ok((val, ReadVersion::Storage))
    }

    /// Writes a value for `key` at `tx_idx`.
    /// Returns `true` if this write might invalidate higher transactions (optimistic check).
    pub fn write(&self, key: Vec<u8>, value: Option<Vec<u8>>, tx_idx: TxIndex) -> bool {
        // Convert to Arc<[u8]> for efficient map storage
        let key_arc: StateKey = key.into();

        let entry = self
            .data
            .entry(key_arc)
            .or_insert_with(|| Arc::new(RwLock::new(Vec::new())));
        let mut versions = entry.write();

        // Check if we are overwriting a previous execution of the SAME tx_idx
        if let Some(pos) = versions.iter().position(|v| v.version == tx_idx) {
            versions[pos].value = value;
            return false; // Same transaction updating its own write set doesn't trigger global re-validation
        }

        // Insert in sorted order
        let pos = versions.partition_point(|v| v.version < tx_idx);
        versions.insert(
            pos,
            MemoryEntry {
                version: tx_idx,
                value,
            },
        );

        // If there are versions AFTER us, we might have invalidated their reads.
        // In a full Block-STM, this triggers validation for those indices.
        pos < versions.len() - 1
    }

    /// Captures the ReadSet for a transaction to allow validation later.
    /// This struct is used by the `Scheduler`.
    pub fn validate_read_set(
        &self,
        read_set: &[(Vec<u8>, ReadVersion)],
        tx_idx: TxIndex,
    ) -> Result<bool, StateError> {
        for (key, recorded_version) in read_set {
            let (_, current_version) = self.read(key, tx_idx)?;
            if &current_version != recorded_version {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Consumes the MVMemory and produces the final delta for the block.
    pub fn apply_to_overlay(
        &self,
        overlay: &mut ioi_api::state::StateOverlay,
    ) -> Result<(), StateError> {
        // In Block-STM, only the final committed versions matter.
        // We iterate all keys, pick the highest version, and apply.
        for r in self.data.iter() {
            let key: &StateKey = r.key();
            let versions = r.value().read();

            if let Some(last) = versions.last() {
                match &last.value {
                    Some(v) => overlay.insert(key, v)?,
                    None => overlay.delete(key)?,
                }
            }
        }
        Ok(())
    }
}
