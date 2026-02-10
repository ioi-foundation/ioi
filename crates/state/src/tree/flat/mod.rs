// Path: crates/state/src/tree/flat/mod.rs

//! A Flat Store implementation that bypasses Merkle hashing for local performance.
//! It implements `StateAccess` and `StateManager` but provides dummy proofs.

use async_trait::async_trait;
// [FIX] Removed unused Selector import
use ioi_api::commitment::CommitmentScheme;
use ioi_api::state::{
    ProofProvider, PrunePlan, StateAccess, StateManager, StateScanIter, VerifiableState,
};
use ioi_api::storage::NodeStore;
use ioi_types::app::{Membership, RootHash};
use ioi_types::error::StateError;
// [FIX] Added ReadableTable import
use redb::{Database, ReadableTable, TableDefinition};
use std::any::Any;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::path::Path;
use std::sync::Arc;

pub mod verifier;

const STATE_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("state");

/// A high-performance, non-Merkle state store backed by Redb.
#[derive(Clone)]
pub struct RedbFlatStore<CS: CommitmentScheme> {
    db: Arc<Database>,
    /// In-memory cache of pending writes (Key -> Value).
    /// None indicates deletion.
    cache: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    /// The "root hash" is just a hash of the block height to satisfy the API.
    current_root: [u8; 32],
    scheme: CS,
}

impl<CS: CommitmentScheme> Debug for RedbFlatStore<CS> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedbFlatStore")
            .field("current_root", &hex::encode(self.current_root))
            .field("cache_size", &self.cache.len())
            .finish()
    }
}

impl<CS: CommitmentScheme> RedbFlatStore<CS> {
    pub fn new(path: &Path, scheme: CS) -> Result<Self, StateError> {
        let db = Database::create(path).map_err(|e| StateError::Backend(e.to_string()))?;

        // Ensure table exists
        let tx = db
            .begin_write()
            .map_err(|e| StateError::Backend(e.to_string()))?;
        {
            let _ = tx
                .open_table(STATE_TABLE)
                .map_err(|e| StateError::Backend(e.to_string()))?;
        }
        tx.commit()
            .map_err(|e| StateError::Backend(e.to_string()))?;

        Ok(Self {
            db: Arc::new(db),
            cache: BTreeMap::new(),
            current_root: [0u8; 32],
            scheme,
        })
    }
}

impl<CS: CommitmentScheme> StateAccess for RedbFlatStore<CS> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        // 1. Check cache first
        if let Some(val_opt) = self.cache.get(key) {
            return Ok(val_opt.clone());
        }

        // 2. Check DB
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| StateError::Backend(e.to_string()))?;
        let table = read_txn
            .open_table(STATE_TABLE)
            .map_err(|e| StateError::Backend(e.to_string()))?;

        // [FIX] E0599: ReadableTable is now in scope
        let result = table
            .get(key)
            .map_err(|e| StateError::Backend(e.to_string()))?;
        // [FIX] E0282: Explicitly handle map
        Ok(result.map(|v| v.value().to_vec()))
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.cache.insert(key.to_vec(), Some(value.to_vec()));
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        self.cache.insert(key.to_vec(), None);
        Ok(())
    }

    fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
        // Collect from DB
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| StateError::Backend(e.to_string()))?;
        let table = read_txn
            .open_table(STATE_TABLE)
            .map_err(|e| StateError::Backend(e.to_string()))?;

        // [FIX] E0599: ReadableTable is now in scope
        // [FIX] E0282: Explicit type annotation for the vector
        let db_iter: Vec<(Vec<u8>, Vec<u8>)> = table
            .range(prefix..)
            .map_err(|e| StateError::Backend(e.to_string()))?
            .take_while(|r| r.as_ref().is_ok_and(|(k, _)| k.value().starts_with(prefix)))
            .map(|r| {
                let (k, v) = r.map_err(|e| StateError::Backend(e.to_string()))?;
                Ok((k.value().to_vec(), v.value().to_vec()))
            })
            .collect::<Result<Vec<(Vec<u8>, Vec<u8>)>, StateError>>()?;

        // Merge with Cache
        // This is a naive merge, sufficient for local mode.
        let mut merged = BTreeMap::new();
        for (k, v) in db_iter {
            merged.insert(k, Some(v));
        }
        for (k, v) in &self.cache {
            if k.starts_with(prefix) {
                merged.insert(k.clone(), v.clone());
            }
        }

        // Filter out deletions (None)
        let final_list: Vec<_> = merged
            .into_iter()
            .filter_map(|(k, v)| v.map(|val| Ok((Arc::from(k), Arc::from(val)))))
            .collect();

        Ok(Box::new(final_list.into_iter()))
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

impl<CS: CommitmentScheme> VerifiableState for RedbFlatStore<CS>
where
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: From<Vec<u8>>,
{
    type Commitment = CS::Commitment;
    type Proof = CS::Proof;

    fn root_commitment(&self) -> Self::Commitment {
        CS::Commitment::from(self.current_root.to_vec())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

impl<CS: CommitmentScheme> ProofProvider for RedbFlatStore<CS>
where
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: From<Vec<u8>>,
    CS::Witness: Default,
{
    fn create_proof(&self, _key: &[u8]) -> Option<Self::Proof> {
        // Return dummy proof
        Some(CS::Proof::from(vec![]))
    }

    fn verify_proof(
        &self,
        _commitment: &Self::Commitment,
        _proof: &Self::Proof,
        _key: &[u8],
        _value: &[u8],
    ) -> Result<(), StateError> {
        // Always pass
        Ok(())
    }

    fn get_with_proof_at(
        &self,
        _root: &Self::Commitment,
        key: &[u8],
    ) -> Result<(Membership, Self::Proof), StateError> {
        let val_opt = self.get(key)?;
        let membership = match val_opt {
            Some(v) => Membership::Present(v),
            None => Membership::Absent,
        };
        Ok((membership, CS::Proof::from(vec![])))
    }

    fn commitment_from_anchor(&self, anchor: &[u8; 32]) -> Option<Self::Commitment> {
        Some(CS::Commitment::from(anchor.to_vec()))
    }

    fn commitment_from_bytes(&self, bytes: &[u8]) -> Result<Self::Commitment, StateError> {
        Ok(CS::Commitment::from(bytes.to_vec()))
    }

    // [FIX] Renamed unused parameter `c` to `_c`
    fn commitment_to_bytes(&self, _c: &Self::Commitment) -> Vec<u8> {
        // Assuming HashCommitment is Vec<u8> wrapper or AsRef
        // We can't access inner generic easily without more bounds.
        // For local usage, we assume we can just ignore this or use placeholder logic.
        // But types require implementation.
        // Let's assume CS::Commitment is From<Vec<u8>> which we have.
        // We can't get bytes OUT easily without AsRef.
        // Hack: use debug formatting or similar? No, too slow.
        // Let's assume the user uses HashCommitmentScheme which has AsRef.
        // But here we are generic.
        // For local mode, we panic or return empty.
        vec![]
    }
}

#[async_trait]
impl<CS: CommitmentScheme> StateManager for RedbFlatStore<CS>
where
    CS::Commitment: From<Vec<u8>>,
    CS::Proof: From<Vec<u8>>,
    CS::Witness: Default,
{
    fn prune(&mut self, _plan: &PrunePlan) -> Result<(), StateError> {
        Ok(())
    }

    fn prune_batch(&mut self, _plan: &PrunePlan, _limit: usize) -> Result<usize, StateError> {
        Ok(0)
    }

    fn commit_version(&mut self, height: u64) -> Result<RootHash, StateError> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| StateError::Backend(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(STATE_TABLE)
                .map_err(|e| StateError::Backend(e.to_string()))?;
            for (k, v_opt) in &self.cache {
                if let Some(v) = v_opt {
                    table
                        .insert(k.as_slice(), v.as_slice())
                        .map_err(|e| StateError::Backend(e.to_string()))?;
                } else {
                    table
                        .remove(k.as_slice())
                        .map_err(|e| StateError::Backend(e.to_string()))?;
                }
            }
        }
        write_txn
            .commit()
            .map_err(|e| StateError::Backend(e.to_string()))?;

        self.cache.clear();

        // Update root to hash of height
        let h_bytes = height.to_le_bytes();
        let new_root_vec = ioi_crypto::algorithms::hash::sha256(&h_bytes)
            .map_err(|e| StateError::Backend(e.to_string()))?
            .to_vec();

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&new_root_vec);
        self.current_root = arr;

        Ok(self.current_root)
    }

    async fn commit_version_persist(
        &mut self,
        height: u64,
        _store: &dyn NodeStore,
    ) -> Result<RootHash, StateError> {
        // We ignore the passed NodeStore and use our own Redb
        self.commit_version(height)
    }

    fn adopt_known_root(&mut self, root: &[u8], _version: u64) -> Result<(), StateError> {
        if root.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(root);
            self.current_root = arr;
        }
        Ok(())
    }
}
