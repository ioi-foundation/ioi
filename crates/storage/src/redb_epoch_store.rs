// Path: crates/storage/src/redb_epoch_store.rs

use depin_sdk_api::storage::{
    be32, be64, CommitInput, Epoch, Height, NodeHash, NodeStore, PruneStats, RootHash, StorageError,
};
use redb::{Database, ReadTransaction, ReadableTable, TableDefinition, WriteTransaction};
use std::path::Path;
use std::sync::Arc;

/// ---- Table definitions (single DB, prefix-encoded keys) ----
/// Global - Keys are fixed-size arrays
const ROOT_INDEX: TableDefinition<&[u8; 32], &[u8; 16]> = TableDefinition::new("ROOT_INDEX"); // value = [epoch_be(8)][height_be(8)]
const HEAD: TableDefinition<&[u8; 4], &[u8; 16]> = TableDefinition::new("HEAD"); // key=b"HEAD", value=[height_be(8)][epoch_be(8)]
const MANIFEST: TableDefinition<&[u8; 8], &[u8; 17]> = TableDefinition::new("EPOCH_MANIFEST"); // value = [first(8)][last(8)][sealed(1)]

// Sharded (prefix-encoded) - Keys are variable-length slices
const VERSIONS: TableDefinition<&[u8], &[u8; 32]> = TableDefinition::new("VERSIONS");
const CHANGES: TableDefinition<&[u8], &[u8; 32]> = TableDefinition::new("CHANGES");
const REFS: TableDefinition<&[u8], &[u8; 8]> = TableDefinition::new("REFS");
const NODES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("NODES");

fn key_head() -> [u8; 4] {
    *b"HEAD"
}
fn enc_epoch(e: Epoch) -> [u8; 8] {
    be64(e)
}
fn enc_height(h: Height) -> [u8; 8] {
    be64(h)
}

fn k_versions(e: Epoch, h: Height) -> Vec<u8> {
    [enc_epoch(e).as_slice(), enc_height(h).as_slice()].concat()
}
fn k_changes(e: Epoch, h: Height, seq: u32) -> Vec<u8> {
    [
        enc_epoch(e).as_slice(),
        enc_height(h).as_slice(),
        be32(seq).as_slice(),
    ]
    .concat()
}
fn k_refs(e: Epoch, n: &NodeHash) -> Vec<u8> {
    [enc_epoch(e).as_slice(), &n.0].concat()
}
fn k_nodes(e: Epoch, n: &NodeHash) -> Vec<u8> {
    [enc_epoch(e).as_slice(), &n.0].concat()
}

fn v_u64(x: u64) -> [u8; 8] {
    be64(x)
}
fn parse_u64(bytes: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(bytes);
    u64::from_be_bytes(a)
}

#[derive(Clone)]
pub struct RedbEpochStore {
    db: Arc<Database>,
    epoch_size: u64,
}

impl RedbEpochStore {
    pub fn open<P: AsRef<Path>>(path: P, epoch_size: u64) -> Result<Self, StorageError> {
        let db = Database::create(path).map_err(|e| StorageError::Backend(e.to_string()))?;
        // Ensure tables exist
        {
            let w = db
                .begin_write()
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            {
                w.open_table(ROOT_INDEX)
                    .map_err(|e| StorageError::Backend(e.to_string()))?;
                w.open_table(HEAD)
                    .map_err(|e| StorageError::Backend(e.to_string()))?;
                w.open_table(MANIFEST)
                    .map_err(|e| StorageError::Backend(e.to_string()))?;
                w.open_table(VERSIONS)
                    .map_err(|e| StorageError::Backend(e.to_string()))?;
                w.open_table(CHANGES)
                    .map_err(|e| StorageError::Backend(e.to_string()))?;
                w.open_table(REFS)
                    .map_err(|e| StorageError::Backend(e.to_string()))?;
                w.open_table(NODES)
                    .map_err(|e| StorageError::Backend(e.to_string()))?;
            }
            w.commit()
                .map_err(|e| StorageError::Backend(e.to_string()))?;
        }
        Ok(Self {
            db: Arc::new(db),
            epoch_size,
        })
    }

    #[inline]
    fn tip_epoch_of(&self, h: Height) -> Epoch {
        if self.epoch_size == 0 {
            0
        } else {
            h / self.epoch_size
        }
    }

    fn read_txn(&self) -> Result<ReadTransaction<'_>, StorageError> {
        self.db
            .begin_read()
            .map_err(|e| StorageError::Backend(e.to_string()))
    }
    fn write_txn(&self) -> Result<WriteTransaction<'_>, StorageError> {
        self.db
            .begin_write()
            .map_err(|e| StorageError::Backend(e.to_string()))
    }

    fn read_head(&self) -> Result<Option<(Height, Epoch)>, StorageError> {
        let r = self.read_txn()?;
        let t = r
            .open_table(HEAD)
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let result = t
            .get(&key_head())
            .map_err(|e| StorageError::Backend(e.to_string()))?
            .map(|v| {
                let bytes = v.value();
                let (h_bytes, e_bytes) = bytes.split_at(8);
                (parse_u64(h_bytes), parse_u64(e_bytes))
            });
        Ok(result)
    }

    fn write_head(tx: &WriteTransaction, height: Height, epoch: Epoch) -> Result<(), StorageError> {
        let mut buf = [0u8; 16];
        buf[..8].copy_from_slice(&enc_height(height));
        buf[8..].copy_from_slice(&enc_epoch(epoch));
        let mut t = tx
            .open_table(HEAD)
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        t.insert(&key_head(), &buf)
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }
}

impl NodeStore for RedbEpochStore {
    fn epoch_size(&self) -> u64 {
        self.epoch_size
    }

    fn head(&self) -> Result<(Height, Epoch), StorageError> {
        self.read_head()?.ok_or(StorageError::NotFound)
    }

    fn height_for_root(&self, root: RootHash) -> Result<Option<Height>, StorageError> {
        let r = self.read_txn()?;
        let t = r
            .open_table(ROOT_INDEX)
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let result = t
            .get(&root.0)
            .map_err(|e| StorageError::Backend(e.to_string()))?
            .map(|v| {
                let val = v.value(); // [epoch(8)][height(8)]
                parse_u64(&val[8..16])
            });
        Ok(result)
    }

    fn root_for_height(&self, height: Height) -> Result<Option<RootHash>, StorageError> {
        let epoch = self.tip_epoch_of(height);
        let r = self.read_txn()?;
        let t = r
            .open_table(VERSIONS)
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let result = t
            .get(k_versions(epoch, height).as_slice())
            .map_err(|e| StorageError::Backend(e.to_string()))?
            .map(|v| {
                let mut rh = [0u8; 32];
                rh.copy_from_slice(v.value());
                RootHash(rh)
            });
        Ok(result)
    }

    fn seal_epoch(&self, epoch: Epoch) -> Result<(), StorageError> {
        let w = self.write_txn()?;
        {
            let mut m = w
                .open_table(MANIFEST)
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            let key = &enc_epoch(epoch);
            let val = [0u8; 17];
            let v_bytes = m
                .get(key)
                .map_err(|e| StorageError::Backend(e.to_string()))?
                .map(|g| g.value().to_vec());
            let mut out = v_bytes.unwrap_or_else(|| val.to_vec());
            out[16] = 1u8; // sealed
            let mut array_out = [0u8; 17];
            array_out.copy_from_slice(&out);
            m.insert(key, &array_out)
                .map_err(|e| StorageError::Backend(e.to_string()))?;
        }
        w.commit().map_err(|e| StorageError::Backend(e.to_string()))
    }

    fn is_sealed(&self, epoch: Epoch) -> Result<bool, StorageError> {
        let r = self.read_txn()?;
        let m = r
            .open_table(MANIFEST)
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let result = m
            .get(&enc_epoch(epoch))
            .map_err(|e| StorageError::Backend(e.to_string()))?
            .map(|v| v.value()[16] == 1u8)
            .unwrap_or(false);
        Ok(result)
    }

    fn commit_block(&self, input: &CommitInput<'_>) -> Result<(), StorageError> {
        let epoch = self.tip_epoch_of(input.height);
        let w = self.write_txn()?;
        {
            let mut nodes_tbl = w
                .open_table(NODES)
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            let mut refs_tbl = w
                .open_table(REFS)
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            for (nh, bytes) in input.new_nodes {
                let k = k_nodes(epoch, nh);
                if nodes_tbl
                    .get(k.as_slice())
                    .map_err(|e| StorageError::Backend(e.to_string()))?
                    .is_none()
                {
                    nodes_tbl
                        .insert(k.as_slice(), *bytes)
                        .map_err(|e| StorageError::Backend(e.to_string()))?;
                    let rk = k_refs(epoch, nh);
                    let cnt = refs_tbl
                        .get(rk.as_slice())
                        .map_err(|e| StorageError::Backend(e.to_string()))?
                        .map(|v| parse_u64(v.value()))
                        .unwrap_or(0);
                    let new = v_u64(cnt.saturating_add(1));
                    refs_tbl
                        .insert(rk.as_slice(), &new)
                        .map_err(|e| StorageError::Backend(e.to_string()))?;
                }
            }
            let mut ch = w
                .open_table(CHANGES)
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            for (i, nh) in input.unique_nodes_for_height.iter().enumerate() {
                ch.insert(k_changes(epoch, input.height, i as u32).as_slice(), &nh.0)
                    .map_err(|e| StorageError::Backend(e.to_string()))?;
            }
            let mut ver = w
                .open_table(VERSIONS)
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            ver.insert(k_versions(epoch, input.height).as_slice(), &input.root.0)
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            let mut ri = w
                .open_table(ROOT_INDEX)
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            let mut meta = [0u8; 16];
            meta[..8].copy_from_slice(&enc_epoch(epoch));
            meta[8..].copy_from_slice(&enc_height(input.height));
            ri.insert(&input.root.0, &meta)
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            Self::write_head(&w, input.height, epoch)?;
        }
        w.commit().map_err(|e| StorageError::Backend(e.to_string()))
    }

    fn prune_batch(
        &self,
        cutoff_height: Height,
        excluded_heights: &[Height],
        limit: usize,
    ) -> Result<PruneStats, StorageError> {
        if limit == 0 {
            return Ok(PruneStats::default());
        }
        let cutoff_epoch = self.tip_epoch_of(cutoff_height);
        let excluded: ahash::AHashSet<Height> = excluded_heights.iter().copied().collect();
        let mut stats = PruneStats::default();

        let w = self.write_txn()?;
        {
            let mut ver = w
                .open_table(VERSIONS)
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            let mut refs = w
                .open_table(REFS)
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            let mut nods = w
                .open_table(NODES)
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            let mut chng = w
                .open_table(CHANGES)
                .map_err(|e| StorageError::Backend(e.to_string()))?;

            let end_cutoff_key = k_versions(cutoff_epoch, cutoff_height);
            let mut pruned = 0usize;

            let keys_to_prune: Vec<Vec<u8>> = ver
                .range(..end_cutoff_key.as_slice())
                .map_err(|e| StorageError::Backend(e.to_string()))?
                .filter_map(|entry| {
                    if let Ok((k, _v)) = entry {
                        let key = k.value();
                        let htb = &key[8..16];
                        let height = u64::from_be_bytes(htb.try_into().unwrap());
                        if !excluded.contains(&height) {
                            Some(key.to_vec())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .take(limit)
                .collect();

            for key in keys_to_prune {
                if pruned >= limit {
                    break;
                }
                let epb = &key[0..8];
                let htb = &key[8..16];
                let epoch = u64::from_be_bytes(epb.try_into().unwrap());
                let height = u64::from_be_bytes(htb.try_into().unwrap());

                let changes_to_process: Vec<_> = chng
                    .range(
                        k_changes(epoch, height, 0).as_slice()
                            ..k_changes(epoch, height, u32::MAX).as_slice(),
                    )
                    .map_err(|e| StorageError::Backend(e.to_string()))?
                    .map(|r| r.map(|(k, v)| (k.value().to_vec(), v.value().to_vec())))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| StorageError::Backend(e.to_string()))?;

                for (ck, cv) in changes_to_process {
                    let nh_bytes = cv.as_slice();
                    let mut nh = [0u8; 32];
                    nh.copy_from_slice(nh_bytes);
                    let node = NodeHash(nh);
                    let rk = k_refs(epoch, &node);

                    let old_count = refs
                        .get(rk.as_slice())
                        .map_err(|e| StorageError::Backend(e.to_string()))?
                        .map(|old| parse_u64(old.value()))
                        .unwrap_or(0);

                    let new_count = old_count.saturating_sub(1);
                    if new_count == 0 {
                        refs.remove(rk.as_slice())
                            .map_err(|e| StorageError::Backend(e.to_string()))?;
                        nods.remove(k_nodes(epoch, &node).as_slice())
                            .map_err(|e| StorageError::Backend(e.to_string()))?;
                        stats.nodes_deleted += 1;
                    } else {
                        refs.insert(rk.as_slice(), &v_u64(new_count))
                            .map_err(|e| StorageError::Backend(e.to_string()))?;
                    }
                    chng.remove(ck.as_slice())
                        .map_err(|e| StorageError::Backend(e.to_string()))?;
                }

                ver.remove(&key as &[u8])
                    .map_err(|e| StorageError::Backend(e.to_string()))?;
                pruned += 1;
                stats.heights_pruned += 1;
            }
        }

        w.commit()
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(stats)
    }

    fn drop_sealed_epoch(&self, epoch: Epoch) -> Result<(), StorageError> {
        let w = self.write_txn()?;
        let e_prefix = enc_epoch(epoch);

        fn delete_prefix(
            tx: &WriteTransaction,
            table_name: &str,
            prefix: &[u8],
        ) -> Result<(), StorageError> {
            let def: TableDefinition<&[u8], &[u8]> = TableDefinition::new(table_name);
            let mut table = tx
                .open_table(def)
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            let keys_to_delete: Vec<Vec<u8>> = table
                .range(prefix..)
                .map_err(|e| StorageError::Backend(e.to_string()))?
                .take_while(|r| {
                    r.as_ref()
                        .map_or(false, |(k, _)| k.value().starts_with(prefix))
                })
                .map(|r| r.map(|(k, _)| k.value().to_vec()))
                .collect::<Result<_, _>>()
                .map_err(|e| StorageError::Backend(e.to_string()))?;

            for key in keys_to_delete {
                table
                    .remove(key.as_slice())
                    .map_err(|e| StorageError::Backend(e.to_string()))?;
            }
            Ok(())
        }
        delete_prefix(&w, "VERSIONS", &e_prefix)?;
        delete_prefix(&w, "CHANGES", &e_prefix)?;
        delete_prefix(&w, "REFS", &e_prefix)?;
        delete_prefix(&w, "NODES", &e_prefix)?;

        {
            let mut m = w
                .open_table(MANIFEST)
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            m.remove(&e_prefix)
                .map_err(|e| StorageError::Backend(e.to_string()))?;
        }

        w.commit().map_err(|e| StorageError::Backend(e.to_string()))
    }
}
