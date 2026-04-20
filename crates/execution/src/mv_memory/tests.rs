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

#[test]
fn clear_tx_writes_removes_stale_keys_from_prior_incarnation() {
    let base = MockState::default();
    let memory = MVMemory::new(Arc::new(base));

    let _ = memory.write(b"lease::a".to_vec(), Some(b"tx2_a".to_vec()), 2);
    let _ = memory.write(b"lease::b".to_vec(), Some(b"tx2_b".to_vec()), 2);
    memory.clear_tx_writes(2);
    let _ = memory.write(b"lease::a".to_vec(), Some(b"tx2_retry_a".to_vec()), 2);

    let mut overlay = ioi_api::state::StateOverlay::new(memory.base_state.as_ref());
    memory
        .apply_to_overlay(&mut overlay)
        .expect("apply_to_overlay should succeed");
    let (inserts, deletes) = overlay.into_ordered_batch();

    assert_eq!(deletes.len(), 0);
    assert_eq!(inserts.len(), 1);
    assert_eq!(inserts[0].0, b"lease::a".to_vec());
    assert_eq!(inserts[0].1, b"tx2_retry_a".to_vec());
}

#[test]
fn validate_read_set_allows_read_then_own_write() {
    let mut base = MockState::default();
    base.insert(b"account::nonce::a", &0u64.to_le_bytes())
        .expect("insert nonce");

    let memory = MVMemory::new(Arc::new(base));
    let (_, version) = memory
        .read(b"account::nonce::a", 2)
        .expect("read should succeed");
    let _ = memory.write(
        b"account::nonce::a".to_vec(),
        Some(1u64.to_le_bytes().to_vec()),
        2,
    );

    assert!(
        memory
            .validate_read_set(&[(b"account::nonce::a".to_vec(), version)], 2)
            .expect("validation should succeed"),
        "own nonce bump must not invalidate the read that preceded it"
    );
}

#[test]
fn validate_read_set_still_detects_prior_tx_changes() {
    let mut base = MockState::default();
    base.insert(b"account::nonce::a", &0u64.to_le_bytes())
        .expect("insert nonce");

    let memory = MVMemory::new(Arc::new(base));
    let (_, version) = memory
        .read(b"account::nonce::a", 2)
        .expect("read should succeed");
    let _ = memory.write(
        b"account::nonce::a".to_vec(),
        Some(7u64.to_le_bytes().to_vec()),
        1,
    );
    let _ = memory.write(
        b"account::nonce::a".to_vec(),
        Some(1u64.to_le_bytes().to_vec()),
        2,
    );

    assert!(
        !memory
            .validate_read_set(&[(b"account::nonce::a".to_vec(), version)], 2)
            .expect("validation should succeed"),
        "a lower transaction changing the recorded version must still invalidate the read"
    );
}

#[test]
fn validate_read_set_preserves_reads_of_own_write() {
    let mut base = MockState::default();
    base.insert(b"lease::a", b"base_a").expect("insert base");

    let memory = MVMemory::new(Arc::new(base));
    let _ = memory.write(b"lease::a".to_vec(), Some(b"tx2_a".to_vec()), 2);
    let (_, version) = memory.read(b"lease::a", 2).expect("read should succeed");

    assert_eq!(version, ReadVersion::Transaction(2));
    assert!(
        memory
            .validate_read_set(&[(b"lease::a".to_vec(), version)], 2)
            .expect("validation should succeed"),
        "reads that already observed the tx's own write must remain valid"
    );
}
