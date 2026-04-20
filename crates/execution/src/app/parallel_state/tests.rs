use super::ParallelStateAccess;
use crate::mv_memory::{MVMemory, ReadVersion};
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
fn prefix_scan_reads_visible_rows_and_tracks_versions() {
    let mut base = MockState::default();
    base.insert(b"lease::a", b"base_a")
        .expect("insert base row");
    base.insert(b"lease::b", b"base_b")
        .expect("insert base row");

    let memory = MVMemory::new(Arc::new(base));
    let _ = memory.write(b"lease::a".to_vec(), Some(b"tx0_a".to_vec()), 0);
    let _ = memory.write(b"lease::c".to_vec(), Some(b"tx1_c".to_vec()), 1);
    let _ = memory.write(b"lease::b".to_vec(), None, 1);

    let accessor = ParallelStateAccess::new(&memory, 2);
    let rows = accessor
        .prefix_scan(b"lease::")
        .expect("prefix scan should succeed")
        .collect::<Result<Vec<_>, _>>()
        .expect("scan rows");

    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].0.as_ref(), b"lease::a");
    assert_eq!(rows[1].0.as_ref(), b"lease::c");

    let reads = accessor.read_set.lock().unwrap().clone();
    assert_eq!(reads.len(), 2);
    assert_eq!(reads[0].0, b"lease::a".to_vec());
    assert_eq!(reads[0].1, ReadVersion::Transaction(0));
    assert_eq!(reads[1].0, b"lease::c".to_vec());
    assert_eq!(reads[1].1, ReadVersion::Transaction(1));
}
