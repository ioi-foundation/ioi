// Path: crates/execution/src/mv_memory.rs
use dashmap::DashMap;
use ioi_api::state::StateAccess;
use ioi_types::error::StateError;
use ioi_types::keys::ACCOUNT_NONCE_PREFIX;
use parking_lot::RwLock;
use std::collections::BTreeMap;
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
    /// Tracks which keys each transaction incarnation has touched so stale writes can be
    /// cleared before a retry re-executes with a different read view.
    tx_write_keys: DashMap<TxIndex, Vec<StateKey>>,
    /// Reference to the base state (pre-block state).
    base_state: Arc<dyn StateAccess>,
}

impl MVMemory {
    pub fn new(base_state: Arc<dyn StateAccess>) -> Self {
        Self {
            data: DashMap::new(),
            tx_write_keys: DashMap::new(),
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
        self.read_version_with_bound(key, tx_idx, true)
    }

    fn read_prior_to_tx(
        &self,
        key: &[u8],
        tx_idx: TxIndex,
    ) -> Result<(Option<Vec<u8>>, ReadVersion), StateError> {
        self.read_version_with_bound(key, tx_idx, false)
    }

    fn read_version_with_bound(
        &self,
        key: &[u8],
        tx_idx: TxIndex,
        include_tx_idx: bool,
    ) -> Result<(Option<Vec<u8>>, ReadVersion), StateError> {
        if let Some(entry) = self.data.get(key) {
            // Explicitly annotate type for parking_lot::RwLockReadGuard
            let versions: parking_lot::RwLockReadGuard<Vec<MemoryEntry>> = entry.read();

            // Find the highest version visible to this read. Execution reads must include the
            // current tx index so a transaction can observe its own writes. Validation sometimes
            // needs the pre-self view to distinguish "I changed this key" from "someone else
            // changed what I observed".
            for ver in versions.iter().rev() {
                let visible = if include_tx_idx {
                    ver.version <= tx_idx
                } else {
                    ver.version < tx_idx
                };
                if visible {
                    return Ok((ver.value.clone(), ReadVersion::Transaction(ver.version)));
                }
            }
        }

        // Fallback to storage
        let val = self.base_state.get(key)?;
        Ok((val, ReadVersion::Storage))
    }

    fn trace_nonce_validation_mismatch(
        &self,
        key: &[u8],
        tx_idx: TxIndex,
        recorded_version: &ReadVersion,
        current_version: &ReadVersion,
        prior_version: Option<&ReadVersion>,
    ) {
        if std::env::var_os("IOI_EXEC_TRACE_NONCE_KEYS").is_none()
            || !key.starts_with(ACCOUNT_NONCE_PREFIX)
        {
            return;
        }

        tracing::info!(
            target: "execution",
            tx_index = tx_idx,
            nonce_key = %hex::encode(key),
            recorded_version = ?recorded_version,
            current_version = ?current_version,
            prior_version = ?prior_version,
            "Parallel nonce validation mismatch"
        );
    }

    /// Returns a merged prefix view visible to `tx_idx`.
    ///
    /// The returned rows contain `(key, value, read_version)` and are sorted by key.
    /// Values written by transactions with index `<= tx_idx` shadow base-state rows.
    pub fn scan_visible(
        &self,
        prefix: &[u8],
        tx_idx: TxIndex,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>, ReadVersion)>, StateError> {
        let mut visible: BTreeMap<Vec<u8>, (Option<Vec<u8>>, ReadVersion)> = BTreeMap::new();

        let base_scan = self.base_state.prefix_scan(prefix)?;
        for row in base_scan {
            let (key, value) = row?;
            visible.insert(key.to_vec(), (Some(value.to_vec()), ReadVersion::Storage));
        }

        for entry in self.data.iter() {
            let key = entry.key();
            if !key.as_ref().starts_with(prefix) {
                continue;
            }
            let versions = entry.value().read();
            let Some(version_entry) = versions.iter().rev().find(|ver| ver.version <= tx_idx)
            else {
                continue;
            };

            if let Some(value) = &version_entry.value {
                visible.insert(
                    key.to_vec(),
                    (
                        Some(value.clone()),
                        ReadVersion::Transaction(version_entry.version),
                    ),
                );
            } else {
                visible.remove(key.as_ref());
            }
        }

        Ok(visible
            .into_iter()
            .filter_map(|(key, (value, version))| value.map(|value| (key, value, version)))
            .collect())
    }

    /// Writes a value for `key` at `tx_idx`.
    /// Returns `true` if this write might invalidate higher transactions (optimistic check).
    pub fn write(&self, key: Vec<u8>, value: Option<Vec<u8>>, tx_idx: TxIndex) -> bool {
        // Convert to Arc<[u8]> for efficient map storage
        let key_arc: StateKey = key.into();
        self.tx_write_keys
            .entry(tx_idx)
            .or_insert_with(Vec::new)
            .push(key_arc.clone());

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

    /// Clears every write recorded for a transaction incarnation so a retry starts from a clean
    /// slate and does not leak keys written by a prior aborted attempt.
    pub fn clear_tx_writes(&self, tx_idx: TxIndex) {
        let Some((_, keys)) = self.tx_write_keys.remove(&tx_idx) else {
            return;
        };

        for key in keys {
            let mut remove_key = false;
            if let Some(entry) = self.data.get(key.as_ref()) {
                let mut versions = entry.write();
                versions.retain(|version| version.version != tx_idx);
                remove_key = versions.is_empty();
            }

            if remove_key {
                self.data.remove(key.as_ref());
            }
        }
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
            if &current_version == recorded_version {
                continue;
            }

            // If validation sees the current tx's own write, compare the previously visible
            // version as well. Transactions that read a key and then mutate it should not abort
            // just because their own write is now the newest visible version.
            if current_version == ReadVersion::Transaction(tx_idx)
                && *recorded_version != ReadVersion::Transaction(tx_idx)
            {
                let (_, prior_version) = self.read_prior_to_tx(key, tx_idx)?;
                if &prior_version == recorded_version {
                    continue;
                }

                self.trace_nonce_validation_mismatch(
                    key,
                    tx_idx,
                    recorded_version,
                    &current_version,
                    Some(&prior_version),
                );
            } else {
                self.trace_nonce_validation_mismatch(
                    key,
                    tx_idx,
                    recorded_version,
                    &current_version,
                    None,
                );
            }

            return Ok(false);
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

#[cfg(test)]
#[path = "mv_memory/tests.rs"]
mod tests;
