// Path: crates/execution/src/mv_memory.rs
use dashmap::DashMap;
use ioi_api::state::StateAccess;
use ioi_types::error::StateError;
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

            // Find the highest version <= tx_idx so a transaction can observe
            // its own writes within the same execution attempt.
            // Versions are inserted in sorted order; iterate reversed for simplicity.
            for ver in versions.iter().rev() {
                if ver.version <= tx_idx {
                    return Ok((ver.value.clone(), ReadVersion::Transaction(ver.version)));
                }
            }
        }

        // Fallback to storage
        let val = self.base_state.get(key)?;
        Ok((val, ReadVersion::Storage))
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

#[cfg(test)]
mod tests {
    use super::{MVMemory, ReadVersion};
    use ioi_api::state::{StateAccess, StateScanIter};
    use ioi_types::error::StateError;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    #[derive(Default)]
    struct MockState {
        data: BTreeMap<Vec<u8>, Vec<u8>>,
    }

    impl StateAccess for MockState {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
            Ok(self.data.get(key).cloned())
        }

        fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
            self.data.insert(key.to_vec(), value.to_vec());
            Ok(())
        }

        fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
            self.data.remove(key);
            Ok(())
        }

        fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
            for (key, value) in updates {
                self.insert(key, value)?;
            }
            Ok(())
        }

        fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
            keys.iter().map(|key| self.get(key)).collect()
        }

        fn batch_apply(
            &mut self,
            inserts: &[(Vec<u8>, Vec<u8>)],
            deletes: &[Vec<u8>],
        ) -> Result<(), StateError> {
            for key in deletes {
                self.delete(key)?;
            }
            for (key, value) in inserts {
                self.insert(key, value)?;
            }
            Ok(())
        }

        fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
            let rows: Vec<_> = self
                .data
                .iter()
                .filter(|(key, _)| key.starts_with(prefix))
                .map(|(key, value)| Ok((Arc::from(key.as_slice()), Arc::from(value.as_slice()))))
                .collect();
            Ok(Box::new(rows.into_iter()))
        }
    }

    #[test]
    fn scan_visible_merges_base_rows_and_mv_writes() {
        let mut base = MockState::default();
        base.insert(b"lease::a", b"base_a")
            .expect("insert lease::a");
        base.insert(b"lease::b", b"base_b")
            .expect("insert lease::b");
        base.insert(b"channel::x", b"channel")
            .expect("insert channel::x");

        let memory = MVMemory::new(Arc::new(base));
        let _ = memory.write(b"lease::a".to_vec(), Some(b"tx0_a".to_vec()), 0);
        let _ = memory.write(b"lease::c".to_vec(), Some(b"tx1_c".to_vec()), 1);
        let _ = memory.write(b"lease::b".to_vec(), None, 1);

        let rows = memory
            .scan_visible(b"lease::", 2)
            .expect("scan should succeed");

        assert_eq!(rows.len(), 2, "lease::b should be deleted and filtered out");
        assert_eq!(rows[0].0, b"lease::a".to_vec());
        assert_eq!(rows[0].1, b"tx0_a".to_vec());
        assert_eq!(rows[0].2, ReadVersion::Transaction(0));
        assert_eq!(rows[1].0, b"lease::c".to_vec());
        assert_eq!(rows[1].1, b"tx1_c".to_vec());
        assert_eq!(rows[1].2, ReadVersion::Transaction(1));
    }

    #[test]
    fn scan_visible_respects_transaction_visibility_boundary() {
        let mut base = MockState::default();
        base.insert(b"lease::a", b"base_a")
            .expect("insert lease::a");

        let memory = MVMemory::new(Arc::new(base));
        let _ = memory.write(b"lease::a".to_vec(), Some(b"tx2_a".to_vec()), 2);

        let rows = memory
            .scan_visible(b"lease::", 1)
            .expect("scan should succeed");

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1, b"base_a".to_vec());
        assert_eq!(rows[0].2, ReadVersion::Storage);
    }

    #[test]
    fn read_includes_same_transaction_writes() {
        let mut base = MockState::default();
        base.insert(b"lease::a", b"base_a")
            .expect("insert lease::a");

        let memory = MVMemory::new(Arc::new(base));
        let _ = memory.write(b"lease::a".to_vec(), Some(b"tx2_a".to_vec()), 2);

        let (value, version) = memory.read(b"lease::a", 2).expect("read should succeed");
        assert_eq!(value, Some(b"tx2_a".to_vec()));
        assert_eq!(version, ReadVersion::Transaction(2));
    }

    #[test]
    fn scan_visible_includes_same_transaction_writes() {
        let mut base = MockState::default();
        base.insert(b"lease::a", b"base_a")
            .expect("insert lease::a");

        let memory = MVMemory::new(Arc::new(base));
        let _ = memory.write(b"lease::a".to_vec(), Some(b"tx2_a".to_vec()), 2);

        let rows = memory
            .scan_visible(b"lease::", 2)
            .expect("scan should succeed");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, b"lease::a".to_vec());
        assert_eq!(rows[0].1, b"tx2_a".to_vec());
        assert_eq!(rows[0].2, ReadVersion::Transaction(2));
    }
}
