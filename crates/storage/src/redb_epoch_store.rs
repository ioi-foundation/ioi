// Path: crates/storage/src/redb_epoch_store.rs
use crate::metrics::metrics;
use crate::wal::{StateDiff, WalWriter};
use async_trait::async_trait;
use ioi_api::storage::{
    be32, be64, CommitInput, Epoch, Height, NodeHash, NodeStore, PruneStats, RootHash, StorageError,
};
use ioi_types::app::{Block, ChainTransaction};
use ioi_types::codec;
use redb::{Database, ReadTransaction, ReadableTable, TableDefinition, WriteTransaction};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::thread;
use tokio::sync::{mpsc, oneshot, Mutex};

/// ---- Table definitions (single DB, prefix-encoded keys) ----
/// Global - Keys are fixed-size arrays
const ROOT_INDEX: TableDefinition<&[u8; 32], &[u8; 16]> = TableDefinition::new("ROOT_INDEX"); // value = [epoch_be(8)][height_be(8)]
const HEAD: TableDefinition<&[u8; 4], &[u8; 16]> = TableDefinition::new("HEAD"); // key=b"HEAD", value=[height_be(8)][epoch_be(8)]
const MANIFEST: TableDefinition<&[u8; 8], &[u8; 17]> = TableDefinition::new("EPOCH_MANIFEST"); // value = [first(8)][last(8)][sealed(1)]
const BLOCKS: TableDefinition<&[u8; 8], &[u8]> = TableDefinition::new("BLOCKS");

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

/// Payload sent to the background persistence thread.
#[derive(Debug)]
struct AsyncCommit {
    height: Height,
    root: RootHash,
    new_nodes: Vec<(NodeHash, Vec<u8>)>,
    unique_nodes: Vec<NodeHash>,
}

/// Enum to multiplex different persistence operations on the same background channel.
#[derive(Debug)]
enum PersistenceOp {
    CommitState(AsyncCommit, oneshot::Sender<Result<(), String>>),
    WriteBlock(Height, Vec<u8>, oneshot::Sender<Result<(), String>>),
}

#[derive(Clone)]
pub struct RedbEpochStore {
    db: Arc<Database>,
    epoch_size: u64,
    // WAL Writer for fast persistence
    _wal: Arc<WalWriter>,
    // Memtable for write-through caching of un-indexed nodes (Hash -> Bytes)
    memtable: Arc<RwLock<HashMap<NodeHash, Vec<u8>>>>,
    // Pending roots cache for read-your-writes consistency on height_for_root
    pending_roots: Arc<RwLock<HashMap<RootHash, Height>>>,
    // Pending blocks cache for read-your-writes consistency on get_block_by_height
    pending_blocks: Arc<RwLock<HashMap<Height, Vec<u8>>>>,
    // Channel for sending commits to background thread with backpressure
    tx_sender: mpsc::Sender<PersistenceOp>,
    // Background flusher handle
    _flusher_handle: Arc<Mutex<Option<thread::JoinHandle<()>>>>,
}

impl RedbEpochStore {
    pub fn open<P: AsRef<Path>>(path: P, epoch_size: u64) -> Result<Self, StorageError> {
        let db_path = path.as_ref();
        let wal_path = db_path.with_extension("wal");

        let db = Database::create(db_path).map_err(|e| StorageError::Backend(e.to_string()))?;

        // Initialize WAL writer
        let wal = WalWriter::new(&wal_path).map_err(|e| StorageError::Backend(e.to_string()))?;
        let wal_arc = Arc::new(wal);

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
                w.open_table(BLOCKS)
                    .map_err(|e| StorageError::Backend(e.to_string()))?;
            }
            w.commit()
                .map_err(|e| StorageError::Backend(e.to_string()))?;
        }

        // --- WAL Replay Logic ---
        if wal_path.exists() {
            let db_head_height = {
                let r = db
                    .begin_read()
                    .map_err(|e| StorageError::Backend(e.to_string()))?;
                // [FIX] Scoped block to ensure table `t` is dropped before `r`
                let res = if let Ok(t) = r.open_table(HEAD) {
                    if let Ok(Some(v)) = t.get(&key_head()) {
                        let bytes = v.value();
                        let (h_bytes, _) = bytes.split_at(8);
                        parse_u64(h_bytes)
                    } else {
                        0
                    }
                } else {
                    0
                };
                res
            };

            eprintln!("[Storage] Replaying WAL from height > {}", db_head_height);

            let iter = crate::wal::WalIterator::new(&wal_path)
                .map_err(|e| StorageError::Backend(e.to_string()))?;

            let mut replayed_count = 0;
            // We use a single write transaction for the replay batch for speed
            let w = db
                .begin_write()
                .map_err(|e| StorageError::Backend(e.to_string()))?;

            {
                let mut nodes_tbl = w
                    .open_table(NODES)
                    .map_err(|e| StorageError::Backend(e.to_string()))?;
                let mut refs_tbl = w
                    .open_table(REFS)
                    .map_err(|e| StorageError::Backend(e.to_string()))?;
                let mut ch = w
                    .open_table(CHANGES)
                    .map_err(|e| StorageError::Backend(e.to_string()))?;
                let mut ver = w
                    .open_table(VERSIONS)
                    .map_err(|e| StorageError::Backend(e.to_string()))?;
                let mut ri = w
                    .open_table(ROOT_INDEX)
                    .map_err(|e| StorageError::Backend(e.to_string()))?;
                let mut t_head = w
                    .open_table(HEAD)
                    .map_err(|e| StorageError::Backend(e.to_string()))?;

                for item in iter {
                    // Log errors but try to continue or break?
                    // Failing replay is critical.
                    let (height, root, diff) =
                        item.map_err(|e| StorageError::Backend(format!("WAL Read Error: {}", e)))?;

                    if height <= db_head_height {
                        continue;
                    }

                    let epoch = if epoch_size == 0 {
                        0
                    } else {
                        height / epoch_size
                    };

                    // Apply Diff
                    for (nh, bytes) in diff.new_nodes {
                        let nh_wrapper = NodeHash(nh);
                        let k = k_nodes(epoch, &nh_wrapper);
                        if nodes_tbl
                            .get(k.as_slice())
                            .map_err(|e| StorageError::Backend(e.to_string()))?
                            .is_none()
                        {
                            nodes_tbl
                                .insert(k.as_slice(), bytes.as_slice())
                                .map_err(|e| StorageError::Backend(e.to_string()))?;
                            let rk = k_refs(epoch, &nh_wrapper);
                            refs_tbl
                                .insert(rk.as_slice(), &v_u64(1))
                                .map_err(|e| StorageError::Backend(e.to_string()))?;
                        }
                    }

                    for (i, nh) in diff.touched_nodes.iter().enumerate() {
                        let nh_wrapper = NodeHash(*nh);
                        ch.insert(k_changes(epoch, height, i as u32).as_slice(), &nh_wrapper.0)
                            .map_err(|e| StorageError::Backend(e.to_string()))?;
                    }

                    // Update Version/Root
                    let root_wrapper = RootHash(root);
                    ver.insert(k_versions(epoch, height).as_slice(), &root_wrapper.0)
                        .map_err(|e| StorageError::Backend(e.to_string()))?;

                    let mut meta = [0u8; 16];
                    meta[..8].copy_from_slice(&enc_epoch(epoch));
                    meta[8..].copy_from_slice(&enc_height(height));
                    ri.insert(&root_wrapper.0, &meta)
                        .map_err(|e| StorageError::Backend(e.to_string()))?;

                    // Update Head
                    let mut head_buf = [0u8; 16];
                    head_buf[..8].copy_from_slice(&enc_height(height));
                    head_buf[8..].copy_from_slice(&enc_epoch(epoch));
                    t_head
                        .insert(&key_head(), &head_buf)
                        .map_err(|e| StorageError::Backend(e.to_string()))?;

                    replayed_count += 1;
                }
            }
            w.commit()
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            if replayed_count > 0 {
                eprintln!(
                    "[Storage] WAL Replay complete. Applied {} blocks.",
                    replayed_count
                );
            }
        }

        // Setup Async Persistence with Bounded Channel.
        // INCREASED BUFFER: Raised from 256 to 1024 to absorb I/O spikes during high throughput.
        let (tx, mut rx) = mpsc::channel::<PersistenceOp>(1024);
        let memtable = Arc::new(RwLock::new(HashMap::new()));
        let pending_roots = Arc::new(RwLock::new(HashMap::new()));
        let pending_blocks = Arc::new(RwLock::new(HashMap::new()));
        let db_arc = Arc::new(db);

        let db_clone = db_arc.clone();
        let memtable_clone = memtable.clone();
        let pending_roots_clone = pending_roots.clone();
        let pending_blocks_clone = pending_blocks.clone();
        let epoch_size_clone = epoch_size;
        let wal_clone = wal_arc.clone(); // Clone WAL for thread

        let handle = thread::spawn(move || {
            eprintln!("[Storage] Background persistence thread started"); // [DEBUG]
            while let Some(op) = rx.blocking_recv() {
                match op {
                    PersistenceOp::CommitState(commit, ack_tx) => {
                        let mut result = Ok(());

                        // 1. Prepare Diff for WAL
                        let diff = StateDiff {
                            new_nodes: commit
                                .new_nodes
                                .iter()
                                .map(|(h, b)| (h.0, b.clone()))
                                .collect(),
                            touched_nodes: commit.unique_nodes.iter().map(|h| h.0).collect(),
                        };

                        // 2. Write to WAL in background (offloading sync I/O)
                        if let Err(e) = wal_clone.append_block(commit.height, commit.root.0, &diff)
                        {
                            eprintln!("[Storage] Async WAL Write Failed: {}", e);
                            result = Err(e.to_string());
                        }

                        let epoch = if epoch_size_clone == 0 {
                            0
                        } else {
                            commit.height / epoch_size_clone
                        };

                        // Perform Redb write
                        // Only proceed with DB write if WAL write succeeded (or if we want best effort)
                        // Here we proceed but track error.
                        if result.is_ok() {
                            let write_res = (|| -> Result<(), redb::Error> {
                                let w = db_clone.begin_write()?;
                                {
                                    let mut nodes_tbl = w.open_table(NODES)?;
                                    let mut refs_tbl = w.open_table(REFS)?;

                                    for (nh, bytes) in &commit.new_nodes {
                                        let k = k_nodes(epoch, nh);
                                        // Only insert if not present (dedup)
                                        if nodes_tbl.get(k.as_slice())?.is_none() {
                                            nodes_tbl.insert(k.as_slice(), bytes.as_slice())?;
                                            let rk = k_refs(epoch, nh);
                                            // Init refcount 1
                                            refs_tbl.insert(rk.as_slice(), &v_u64(1))?;
                                        }
                                    }

                                    let mut ch = w.open_table(CHANGES)?;
                                    for (i, nh) in commit.unique_nodes.iter().enumerate() {
                                        ch.insert(
                                            k_changes(epoch, commit.height, i as u32).as_slice(),
                                            &nh.0,
                                        )?;
                                    }

                                    let mut ver = w.open_table(VERSIONS)?;
                                    ver.insert(
                                        k_versions(epoch, commit.height).as_slice(),
                                        &commit.root.0,
                                    )?;

                                    let mut ri = w.open_table(ROOT_INDEX)?;
                                    let mut meta = [0u8; 16];
                                    meta[..8].copy_from_slice(&enc_epoch(epoch));
                                    meta[8..].copy_from_slice(&enc_height(commit.height));
                                    ri.insert(&commit.root.0, &meta)?;

                                    // Write head
                                    let mut head_buf = [0u8; 16];
                                    head_buf[..8].copy_from_slice(&enc_height(commit.height));
                                    head_buf[8..].copy_from_slice(&enc_epoch(epoch));
                                    let mut t_head = w.open_table(HEAD)?;
                                    t_head.insert(&key_head(), &head_buf)?;
                                }
                                w.commit()?;
                                Ok(())
                            })();

                            if let Err(e) = write_res {
                                eprintln!("[Storage] Async DB Write Failed (State): {}", e);
                                result = Err(e.to_string());
                            }
                        }

                        // Cleanup memtable
                        {
                            let mut guard = memtable_clone.write().unwrap();
                            for (nh, _) in &commit.new_nodes {
                                guard.remove(nh);
                            }
                        }

                        // Cleanup pending_roots
                        {
                            let mut guard = pending_roots_clone.write().unwrap();
                            guard.remove(&commit.root);
                        }

                        // Acknowledge completion
                        let _ = ack_tx.send(result);
                    }
                    PersistenceOp::WriteBlock(height, block_bytes, ack_tx) => {
                        let write_res = (|| -> Result<(), redb::Error> {
                            let w = db_clone.begin_write()?;
                            {
                                let mut table = w.open_table(BLOCKS)?;
                                table.insert(&height.to_be_bytes(), block_bytes.as_slice())?;
                            }
                            w.commit()?;
                            Ok(())
                        })();

                        let result = if let Err(e) = write_res {
                            eprintln!("[Storage] Async DB Write Failed (Block): {}", e);
                            Err(e.to_string())
                        } else {
                            Ok(())
                        };

                        // Cleanup pending_blocks
                        {
                            let mut guard = pending_blocks_clone.write().unwrap();
                            guard.remove(&height);
                        }

                        let _ = ack_tx.send(result);
                    }
                }
            }
            eprintln!("[Storage] Background persistence thread exiting"); // [DEBUG]
        });

        Ok(Self {
            db: db_arc,
            epoch_size,
            _wal: wal_arc,
            memtable,
            pending_roots,
            pending_blocks,
            tx_sender: tx,
            _flusher_handle: Arc::new(Mutex::new(Some(handle))),
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

    #[allow(dead_code)]
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

    pub fn safe_drop_epoch(&self, epoch: Epoch, pins: &[Height]) -> Result<bool, StorageError> {
        let start_height = epoch * self.epoch_size;
        let end_height = (epoch + 1) * self.epoch_size;

        for pin in pins {
            if *pin >= start_height && *pin < end_height {
                // Epoch contains a pinned height, cannot drop.
                return Ok(false);
            }
        }

        self.drop_sealed_epoch(epoch)?;
        Ok(true)
    }
}

#[async_trait]
impl NodeStore for RedbEpochStore {
    fn epoch_size(&self) -> u64 {
        self.epoch_size
    }

    fn epoch_of(&self, height: Height) -> Epoch {
        self.tip_epoch_of(height)
    }

    fn get_node(&self, epoch: Epoch, node: NodeHash) -> Result<Option<Vec<u8>>, StorageError> {
        // 1. Check Memtable (Write-Through Cache)
        {
            let guard = self.memtable.read().unwrap();
            if let Some(val) = guard.get(&node) {
                return Ok(Some(val.clone()));
            }
        }

        // 2. Check Redb
        let r = self.read_txn()?;
        let t = r
            .open_table(NODES)
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let k = k_nodes(epoch, &node);
        let out = t
            .get(k.as_slice())
            .map_err(|e| StorageError::Backend(e.to_string()))?
            .map(|v| v.value().to_vec());
        Ok(out)
    }

    fn head(&self) -> Result<(Height, Epoch), StorageError> {
        self.read_head()?.ok_or(StorageError::NotFound)
    }

    fn height_for_root(&self, root: RootHash) -> Result<Option<Height>, StorageError> {
        // 1. Check Pending Roots (for read-your-writes within async flush window)
        {
            let guard = self.pending_roots.read().unwrap();
            if let Some(&h) = guard.get(&root) {
                return Ok(Some(h));
            }
        }

        // 2. Check Redb
        let r = self.read_txn()?;
        let t = r
            .open_table(ROOT_INDEX)
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let result = t
            .get(&root.0)
            .map_err(|e| StorageError::Backend(e.to_string()))?
            .and_then(|v| {
                v.value()
                    .get(8..16)
                    .and_then(|slice| slice.try_into().ok())
                    .map(u64::from_be_bytes)
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
            if let Some(sealed_byte) = out.get_mut(16) {
                *sealed_byte = 1u8; // sealed
            }
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
            .and_then(|v| v.value().get(16).map(|&b| b == 1u8))
            .unwrap_or(false);
        Ok(result)
    }

    async fn commit_block(&self, input: CommitInput) -> Result<(), StorageError> {
        let bytes_written: u64 = input
            .new_nodes
            .iter()
            .map(|(_, bytes)| bytes.len() as u64)
            .sum();
        metrics().inc_bytes_written_total(bytes_written);

        // Populate memtable synchronously (for read-your-writes)
        {
            let mut guard = self.memtable.write().unwrap();
            for (nh, bytes) in &input.new_nodes {
                guard.insert(*nh, bytes.clone());
            }
        }

        // Populate pending_roots synchronously
        {
            let mut guard = self.pending_roots.write().unwrap();
            guard.insert(input.root, input.height);
        }

        // Setup ack channel
        let (ack_tx, ack_rx) = oneshot::channel();

        // Queue Redb + WAL Write (Async)
        let commit_task = AsyncCommit {
            height: input.height,
            root: input.root,
            new_nodes: input.new_nodes,
            unique_nodes: input.unique_nodes_for_height,
        };

        self.tx_sender
            .send(PersistenceOp::CommitState(commit_task, ack_tx))
            .await
            .map_err(|e| StorageError::Backend(format!("Failed to queue async commit: {}", e)))?;

        // Wait for durability acknowledgment
        match ack_rx.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(StorageError::Backend(format!(
                "Commit failed in background: {}",
                e
            ))),
            Err(e) => Err(StorageError::Backend(format!(
                "Persistence channel closed: {}",
                e
            ))),
        }
    }

    async fn put_block(&self, height: u64, block_bytes: &[u8]) -> Result<(), StorageError> {
        // Cache synchronously for read-your-writes
        {
            let mut guard = self.pending_blocks.write().unwrap();
            guard.insert(height, block_bytes.to_vec());
        }

        let (ack_tx, ack_rx) = oneshot::channel();
        let op = PersistenceOp::WriteBlock(height, block_bytes.to_vec(), ack_tx);

        self.tx_sender
            .send(op)
            .await
            .map_err(|e| StorageError::Backend(format!("Failed to queue block write: {}", e)))?;

        // Wait for durability acknowledgment
        match ack_rx.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(StorageError::Backend(format!(
                "Block write failed in background: {}",
                e
            ))),
            Err(e) => Err(StorageError::Backend(format!(
                "Persistence channel closed: {}",
                e
            ))),
        }
    }

    fn get_block_by_height(
        &self,
        height: u64,
    ) -> Result<Option<Block<ChainTransaction>>, StorageError> {
        // 1. Check Pending
        {
            let guard = self.pending_blocks.read().unwrap();
            if let Some(bytes) = guard.get(&height) {
                let block =
                    codec::from_bytes_canonical(bytes).map_err(|e| StorageError::Decode(e))?;
                return Ok(Some(block));
            }
        }

        // 2. Check DB
        let r = self.read_txn()?;
        let table = r
            .open_table(BLOCKS)
            .map_err(|e| StorageError::Backend(e.to_string()))?;

        let maybe_value = table
            .get(&height.to_be_bytes())
            .map_err(|e| StorageError::Backend(e.to_string()))?;

        if let Some(value) = maybe_value {
            let block: Block<ChainTransaction> =
                codec::from_bytes_canonical(value.value()).map_err(|e| StorageError::Decode(e))?;
            Ok(Some(block))
        } else {
            Ok(None)
        }
    }

    fn get_blocks_range(
        &self,
        start: u64,
        limit: u32,
        max_bytes: u32,
    ) -> Result<Vec<Block<ChainTransaction>>, StorageError> {
        let r = self.read_txn()?;
        let table = r
            .open_table(BLOCKS)
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let mut blocks = Vec::new();
        let mut current_bytes: u32 = 0;

        for i in 0..limit {
            let h = start + i as u64;

            // Check pending first
            let block_opt = {
                let guard = self.pending_blocks.read().unwrap();
                guard.get(&h).cloned()
            };

            let block_bytes = if let Some(b) = block_opt {
                b
            } else {
                // Check DB
                if let Some(v) = table
                    .get(&h.to_be_bytes())
                    .map_err(|e| StorageError::Backend(e.to_string()))?
                {
                    v.value().to_vec()
                } else {
                    // End of chain or gap
                    break;
                }
            };

            let len = block_bytes.len() as u32;
            if current_bytes + len > max_bytes && !blocks.is_empty() {
                break;
            }

            let block: Block<ChainTransaction> =
                codec::from_bytes_canonical(&block_bytes).map_err(|e| StorageError::Decode(e))?;

            current_bytes += len;
            blocks.push(block);
        }
        Ok(blocks)
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
        let nodes_deleted = 0;
        let mut heights_pruned = 0;

        let w = self.write_txn()?;
        {
            let mut ver = w
                .open_table(VERSIONS)
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            let mut chng = w
                .open_table(CHANGES)
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            let mut ri = w
                .open_table(ROOT_INDEX)
                .map_err(|e| StorageError::Backend(e.to_string()))?;

            let end_cutoff_key = k_versions(cutoff_epoch, cutoff_height);

            let items_to_prune: Vec<(Vec<u8>, [u8; 32])> = ver
                .range(..end_cutoff_key.as_slice())
                .map_err(|e| StorageError::Backend(e.to_string()))?
                .filter_map(|entry| {
                    if let Ok((k, v)) = entry {
                        let key = k.value();
                        let height_bytes = key.get(8..16)?;
                        let height_arr: [u8; 8] = height_bytes.try_into().ok()?;
                        let height = u64::from_be_bytes(height_arr);
                        if !excluded.contains(&height) {
                            let val_bytes = v.value();
                            if val_bytes.len() == 32 {
                                let mut rh = [0u8; 32];
                                rh.copy_from_slice(val_bytes);
                                Some((key.to_vec(), rh))
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .take(limit)
                .collect();

            for (key, root_hash) in items_to_prune {
                let epoch_bytes = &key[0..8];
                let height_bytes = &key[8..16];

                let epoch = parse_u64(epoch_bytes);
                let height = parse_u64(height_bytes);

                let changes_to_process: Vec<Vec<u8>> = chng
                    .range(
                        k_changes(epoch, height, 0).as_slice()
                            ..k_changes(epoch, height, u32::MAX).as_slice(),
                    )
                    .map_err(|e| StorageError::Backend(e.to_string()))?
                    .map(|r| r.map(|(k, _)| k.value().to_vec()))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| StorageError::Backend(e.to_string()))?;

                for ck in changes_to_process {
                    chng.remove(ck.as_slice())
                        .map_err(|e| StorageError::Backend(e.to_string()))?;
                }

                let should_remove_index = match ri
                    .get(&root_hash)
                    .map_err(|e| StorageError::Backend(e.to_string()))?
                {
                    Some(v) => {
                        let bytes = v.value();
                        if bytes.len() >= 16 {
                            let indexed_height = parse_u64(&bytes[8..16]);
                            indexed_height == height
                        } else {
                            false
                        }
                    }
                    None => false,
                };

                if should_remove_index {
                    ri.remove(&root_hash)
                        .map_err(|e| StorageError::Backend(e.to_string()))?;
                }

                ver.remove(key.as_slice())
                    .map_err(|e| StorageError::Backend(e.to_string()))?;
                heights_pruned += 1;
            }
        }
        w.commit()
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let stats = PruneStats {
            heights_pruned,
            nodes_deleted,
        };
        metrics().inc_epochs_dropped(heights_pruned as u64);
        metrics().inc_nodes_deleted(nodes_deleted as u64);
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
                .take_while(|r| r.as_ref().is_ok_and(|(k, _)| k.value().starts_with(prefix)))
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
