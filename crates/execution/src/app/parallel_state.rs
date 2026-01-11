// Path: crates/execution/src/app/parallel_state.rs
use crate::mv_memory::{MVMemory, ReadVersion, TxIndex};
use ioi_api::state::{StateAccess, StateScanIter};
use ioi_types::error::StateError;
use std::sync::{Arc, Mutex};

/// A StateAccess implementation that records reads and writes to MVMemory
/// for a specific transaction index.
pub struct ParallelStateAccess<'a> {
    mv_memory: &'a MVMemory,
    tx_idx: TxIndex,
    // We record the read set here to return it to the worker loop
    pub read_set: Arc<Mutex<Vec<(Vec<u8>, ReadVersion)>>>,
}

impl<'a> ParallelStateAccess<'a> {
    pub fn new(mv_memory: &'a MVMemory, tx_idx: TxIndex) -> Self {
        Self {
            mv_memory,
            tx_idx,
            read_set: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl<'a> StateAccess for ParallelStateAccess<'a> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        let (val, version) = self.mv_memory.read(key, self.tx_idx)?;
        self.read_set.lock().unwrap().push((key.to_vec(), version));
        Ok(val)
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.mv_memory
            .write(key.to_vec(), Some(value.to_vec()), self.tx_idx);
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        self.mv_memory.write(key.to_vec(), None, self.tx_idx);
        Ok(())
    }

    // Parallel scanning is tricky. For Phase 2.1, we fall back to base state + simplistic MV check
    // or return error if strict correctness is required (Block-STM usually avoids Scans).
    // Here we implement a "Best Effort" scan that might trigger aborts often.
    fn prefix_scan(&self, _prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
        // Fallback to base state for now to satisfy trait.
        // A full MV-Scan is complex.
        // Warning: This breaks isolation if new keys were inserted by lower indices.
        // In IOI Kernel, scans are mostly used by system txs (governance), which are rare.
        // Ideally, force system txs to run sequentially.
        Err(StateError::Backend(
            "Prefix scan not supported in parallel mode".into(),
        ))
    }

    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        for (k, v) in updates {
            self.insert(k, v)?;
        }
        Ok(())
    }

    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        let mut results = Vec::new();
        for k in keys {
            results.push(self.get(k)?);
        }
        Ok(results)
    }

    fn batch_apply(
        &mut self,
        inserts: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), StateError> {
        for k in deletes {
            self.delete(k)?;
        }
        for (k, v) in inserts {
            self.insert(k, v)?;
        }
        Ok(())
    }
}
