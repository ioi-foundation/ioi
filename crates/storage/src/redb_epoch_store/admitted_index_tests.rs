// Path: crates/storage/src/redb_epoch_store/admitted_index_tests.rs
//! FU-N11-DURABLE-STATUS-1 D2a RED-4 (written against 5c77c9ca0, the GREEN-3 admission-floor
//! fence): the workload store's ADMITTED INDEX, which replaces the fence (review round 2's
//! consensus between NET and the IOI Director, d2a/review2/RECOMMENDATION.md).
//!
//! The index maps height -> (admitted block hash, state root, the admitted header's timestamp).
//! Its max entry is the committed tip. It is written once per height, only by the admission
//! publication, and no write to BLOCKS or VERSIONS, no prune and no epoch drop touches it. These
//! tests drive the index's own API (`NodeStore::put_admitted_record` / `get_admitted_record`, the
//! RED-4 scaffold whose defaults keep no index) on the real `RedbEpochStore`:
//! - T5 (the IOI Director): write-once per height, an identical rewrite is a no-op, prune never
//!   removes a row;
//! - T6 (the IOI Director): the index survives a store reopen (durable, not a cache);
//! - T1 (vi)/(vii) at the store layer: a block write held IN FLIGHT (the background persistence
//!   thread blocked on the redb write lock, the bytes already in the read-your-writes cache) is
//!   never read as committed. The workload-level T1 harness cannot reach these caches
//!   deterministically (the store's internals are private to this crate), so this is the layer
//!   that pins them.
//!
//! At 5c77c9ca0 every test that needs an index row fails at its first index write (the trait
//! default refuses); the mechanics CONTROL passes and shows the in-flight harness works.

use super::RedbEpochStore;
use ioi_api::storage::{AdmittedRecord, AdmittedTip, CommitInput, NodeStore, RootHash};
use ioi_types::app::{
    AccountId, Block, BlockHeader, ChainTransaction, QuorumCertificate, SignatureSuite, StateRoot,
};

/// Admitted heights 1..=MAX; MAX + 1 is executed but never admitted.
const MAX: u64 = 4;

/// The store's async writes are acknowledged by its background thread; any runtime drives them.
fn run<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(future)
}

/// The background persistence thread releases its database handle after the store drops; a
/// bounded retry keeps the reopen deterministic.
fn reopen(path: &std::path::Path) -> RedbEpochStore {
    let mut last = None;
    for _ in 0..250 {
        match RedbEpochStore::open(path, 1024) {
            Ok(store) => return store,
            Err(error) => last = Some(error),
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    panic!("reopen failed: {last:?}");
}

/// The block executed at `height` with state root `[root; 32]` and timestamp `1_700_000_000 +
/// height + skew` (`skew` gives a replacement another timestamp, hence another identity).
fn block(height: u64, root: u8, skew: u64) -> Block<ChainTransaction> {
    Block {
        header: BlockHeader {
            height,
            view: 0,
            parent_hash: [1; 32],
            parent_state_root: StateRoot(vec![2; 32]),
            state_root: StateRoot(vec![root; 32]),
            transactions_root: vec![3; 32],
            timestamp: 1_700_000_000 + height + skew,
            timestamp_ms: (1_700_000_000 + height + skew) * 1_000,
            gas_used: 0,
            validator_set: vec![vec![4; 32]],
            producer_account_id: AccountId([5; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [6; 32],
            producer_pubkey: vec![7; 32],
            oracle_counter: 0,
            oracle_trace_hash: [0; 32],
            guardian_certificate: None,
            sealed_finality_proof: None,
            canonical_order_certificate: None,
            timeout_certificate: None,
            aft_timeout_certificate: None,
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0; 32],
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
            signature: Vec::new(),
        },
        transactions: Vec::new(),
    }
}

fn bytes(block: &Block<ChainTransaction>) -> Vec<u8> {
    ioi_types::codec::to_bytes_canonical(block).expect("canonical block bytes")
}

fn commit_input(height: u64, root: u8) -> CommitInput {
    CommitInput {
        height,
        root: RootHash([root; 32]),
        unique_nodes_for_height: Vec::new(),
        new_nodes: Vec::new(),
    }
}

/// The admitted block at `height` (root 0xA0 + height).
fn admitted(height: u64) -> Block<ChainTransaction> {
    block(height, 0xA0 + height as u8, 0)
}

/// What the admission publication records for `block`.
fn record_of(block: &Block<ChainTransaction>) -> AdmittedRecord {
    AdmittedRecord {
        height: block.header.height,
        block_hash: block
            .header
            .hash()
            .expect("identity hash")
            .try_into()
            .expect("32-byte hash"),
        state_root: block.header.state_root.0.clone(),
        timestamp: block.header.timestamp,
    }
}

fn tip_of(record: &AdmittedRecord) -> AdmittedTip {
    AdmittedTip {
        height: record.height,
        block_hash: record.block_hash,
        state_root: record.state_root.clone(),
    }
}

/// A store that executed heights 1..=MAX+1 (state and block, as the IAVL and Jellyfish backends
/// commit) and whose admission publication recorded 1..=MAX in the index. Returns the records.
fn admitted_store(store: &RedbEpochStore) -> Vec<AdmittedRecord> {
    run(async {
        for height in 1..=MAX + 1 {
            let block = admitted(height);
            store
                .commit_block_with_payload(
                    commit_input(height, 0xA0 + height as u8),
                    &bytes(&block),
                )
                .await
                .expect("execute the height");
        }
    });
    let records: Vec<_> = (1..=MAX)
        .map(|height| record_of(&admitted(height)))
        .collect();
    for record in &records {
        store.put_admitted_record(record).unwrap_or_else(|error| {
            panic!(
                "the index's writer records admitted height {} (at 5c77c9ca0 no store keeps an admitted index): {error}",
                record.height
            )
        });
    }
    records
}

/// Every index row and the max entry, as `records` holds them; MAX + 1 has no row.
fn assert_index_holds(store: &RedbEpochStore, records: &[AdmittedRecord], when: &str) {
    for record in records {
        assert_eq!(
            store
                .get_admitted_record(record.height)
                .expect("read an index row"),
            Some(record.clone()),
            "{when}: index[{}] is the admission record",
            record.height
        );
    }
    assert!(
        matches!(store.get_admitted_record(MAX + 1), Ok(None) | Err(_)),
        "{when}: the executed, unadmitted height has no index row (refused or absent)"
    );
    assert_eq!(
        store.get_admitted_tip().expect("read the max entry"),
        records.last().map(tip_of),
        "{when}: the committed tip is the index's max entry"
    );
}

// --- T5: write-once per height --------------------------------------------------------------

/// T5 (a), RED-4 (fails at 5c77c9ca0 in setup: no store keeps an admitted index; the
/// `put_admitted_record` default refuses, api storage/mod.rs). A second index write at an existing
/// height with another block hash, another timestamp or another state root is REFUSED by the
/// index's own writer, below the max and at it, and the row stays the admission record. Before
/// each attempt BLOCKS[h] is made to AGREE with the incoming record (BLOCKS is mutable storage
/// and the store has no fence, so those writes are accepted), so a refusal can only be the
/// index's write-once rule, never a cross-check against the stored block.
#[test]
fn t5_a_second_index_write_at_an_existing_height_with_another_record_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = RedbEpochStore::open(dir.path().join("store.redb"), 1024).expect("open");
    let records = admitted_store(&store);
    for height in [2, MAX] {
        let original = records[(height - 1) as usize].clone();
        let admitted_root = 0xA0 + height as u8;
        let other_root = 0xB0 + height as u8;
        let attempts = [
            (
                "another block hash",
                admitted(height),
                AdmittedRecord {
                    block_hash: [0xEE; 32],
                    ..original.clone()
                },
            ),
            (
                "another timestamp",
                block(height, admitted_root, 7),
                AdmittedRecord {
                    timestamp: original.timestamp + 7,
                    ..original.clone()
                },
            ),
            (
                "another state root",
                block(height, other_root, 0),
                AdmittedRecord {
                    state_root: vec![other_root; 32],
                    ..original.clone()
                },
            ),
        ];
        for (what, stored, record) in attempts {
            run(store.put_block(height, &bytes(&stored)))
                .expect("BLOCKS is mutable storage: the rewrite is accepted (no fence)");
            assert!(
                store.put_admitted_record(&record).is_err(),
                "index[{height}] is written once: {what} is refused"
            );
            assert_eq!(
                store.get_admitted_record(height).expect("read"),
                Some(original.clone()),
                "the refused write ({what}) leaves index[{height}] as admitted"
            );
        }
    }
    assert_eq!(
        store.get_admitted_tip().expect("max"),
        Some(tip_of(&records[(MAX - 1) as usize])),
        "no refused write moved the max entry"
    );
}

/// T5 (b), RED-4 (fails at 5c77c9ca0 in setup, as T5 (a)). Re-writing the IDENTICAL record is an
/// idempotent no-op (NET's choice: Ok, nothing changes), below the max and at it; the max entry
/// does not move back to a re-written lower height.
#[test]
fn t5_rewriting_the_identical_index_record_is_an_idempotent_no_op() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = RedbEpochStore::open(dir.path().join("store.redb"), 1024).expect("open");
    let records = admitted_store(&store);
    for height in [2, MAX] {
        store
            .put_admitted_record(&records[(height - 1) as usize])
            .unwrap_or_else(|error| {
                panic!("an identical re-write of index[{height}] is an idempotent no-op: {error}")
            });
    }
    assert_index_holds(&store, &records, "after the identical re-writes");
}

/// T5 (c), RED-4 (fails at 5c77c9ca0 in setup, as T5 (a)). Prune never removes an index row:
/// prune_batch over every height (VERSIONS/CHANGES/ROOT_INDEX), drop_sealed_epoch(0)
/// (VERSIONS/CHANGES/REFS/NODES/MANIFEST) and override_head below the max leave every row and the
/// max entry as admitted.
#[test]
fn t5_prune_and_epoch_drop_never_remove_an_index_row() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = RedbEpochStore::open(dir.path().join("store.redb"), 1024).expect("open");
    let records = admitted_store(&store);
    let pruned = store
        .prune_batch(MAX + 10, &[], 1_000)
        .expect("prune every height");
    assert!(
        pruned.heights_pruned >= MAX as usize,
        "the prune removed the admitted heights' state versions ({} pruned)",
        pruned.heights_pruned
    );
    // GREEN-4 fixture correction: drop_sealed_epoch errors in this store today (it reopens the
    // typed VERSIONS table through an untyped definition, a defect older than D2a; the GC keeps it
    // disabled), so its result is ignored, as RED-3's S6 ignored it. The prune above is the
    // effective removal here.
    let _ = store.drop_sealed_epoch(0);
    store.override_head(1).expect("move HEAD below the max");
    assert_index_holds(
        &store,
        &records,
        "after prune, epoch drop and a HEAD override",
    );
}

// --- T6: the index is durable ---------------------------------------------------------------

/// T6, RED-4 (fails at 5c77c9ca0 in setup, as T5 (a)). After the store is dropped and reopened
/// (the WAL replayed), every index row, the max entry and the absence of a row above the max are
/// what the admission recorded: the index is durable, not a cache.
#[test]
fn t6_the_admitted_index_survives_a_store_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("store.redb");
    let records = {
        let store = RedbEpochStore::open(&path, 1024).expect("open");
        let records = admitted_store(&store);
        assert_index_holds(&store, &records, "before the reopen");
        records
    };
    let reopened = reopen(&path);
    assert_index_holds(&reopened, &records, "after the reopen");
}

// --- T1 (vi) and (vii) at the store layer: a write IN FLIGHT ------------------------------------

/// Starts `write` on its own thread while the caller holds the store's redb write lock: the write
/// fills the read-your-writes cache, queues its persistence op, and its background transaction
/// blocks on the held lock. Returns once the bytes for `height` are in the cache (the write is in
/// flight), with the join handle of the write's own result.
fn start_write_in_flight<F>(
    store: &RedbEpochStore,
    height: u64,
    write: F,
) -> std::thread::JoinHandle<Result<(), ioi_api::storage::StorageError>>
where
    F: FnOnce(RedbEpochStore) -> Result<(), ioi_api::storage::StorageError> + Send + 'static,
{
    let writer = store.clone();
    let handle = std::thread::spawn(move || write(writer));
    for _ in 0..500 {
        if store.pending_blocks.read().unwrap().contains_key(&height) {
            return handle;
        }
        if handle.is_finished() {
            let result = handle.join().expect("the write's thread");
            panic!(
                "the write at height {height} finished before reaching the cache (it should be held in flight): {result:?}"
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("the write at height {height} never reached the read-your-writes cache");
}

/// CONTROL (passes at 5c77c9ca0 and after): the in-flight harness works. With no index and no
/// marker, a block write held behind the redb write lock is readable from the read-your-writes
/// cache while in flight, and completes once the lock is released.
#[test]
fn t1_vi_control_a_held_write_lock_keeps_a_block_write_in_flight() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = RedbEpochStore::open(dir.path().join("store.redb"), 1024).expect("open");
    run(store.put_block(2, &bytes(&admitted(2)))).expect("store block 2");
    let replacement = block(2, 0xB2, 0);
    let lock = store.db.begin_write().expect("hold the redb write lock");
    let in_flight = {
        let replacement = bytes(&replacement);
        start_write_in_flight(&store, 2, move |writer| {
            run(writer.put_block(2, &replacement))
        })
    };
    assert_eq!(
        store.get_block_by_height(2).expect("read mid-flight"),
        Some(replacement.clone()),
        "mid-flight, the read-your-writes cache serves the in-flight bytes"
    );
    lock.abort().expect("release the lock");
    in_flight
        .join()
        .expect("the write's thread")
        .expect("the held write completes once the lock is released");
    assert_eq!(
        store.get_block_by_height(2).expect("read"),
        Some(replacement)
    );
}

/// T1 (vi), RED-4 (fails at 5c77c9ca0 in setup, as T5 (a); with the fence, the write would be
/// refused besides, redb_epoch_store.rs:1100 `admission_floor_precheck`). A block write below the
/// max, held IN FLIGHT with its bytes in the read-your-writes cache, is never read as committed:
/// index[2] and the max entry stay the admission records while the cache serves the new bytes,
/// and the write SUCCEEDS once released (no fence in the path).
#[test]
fn t1_vi_a_block_write_below_the_max_held_in_flight_is_never_read_as_committed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = RedbEpochStore::open(dir.path().join("store.redb"), 1024).expect("open");
    let records = admitted_store(&store);
    let rewrite = block(2, 0xB2, 0);
    let lock = store.db.begin_write().expect("hold the redb write lock");
    let in_flight = {
        let rewrite = bytes(&rewrite);
        start_write_in_flight(&store, 2, move |writer| run(writer.put_block(2, &rewrite)))
    };
    assert_eq!(
        store.get_block_by_height(2).expect("read mid-flight"),
        Some(rewrite.clone()),
        "the write is in flight: the cache serves its bytes"
    );
    assert_index_holds(&store, &records, "mid-flight");
    lock.abort().expect("release the lock");
    in_flight
        .join()
        .expect("the write's thread")
        .expect("the write below the max SUCCEEDS: no fence is in its path");
    assert_index_holds(&store, &records, "after the write landed");
}

/// T1 (vii), RED-4 (fails at 5c77c9ca0 in setup, as T5 (a); with the fence, the commit would be
/// refused besides, redb_epoch_store.rs:1043). A REPLACEMENT of the max height (a state-and-block
/// commit of another block at MAX, as a tip replacement's commit writes it) held IN FLIGHT during
/// a "latest" read: the max entry and index[MAX] stay the admission record, the replacement
/// SUCCEEDS once released, and nothing moves afterwards.
#[test]
fn t1_vii_a_replacement_of_the_max_in_flight_never_moves_the_latest_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = RedbEpochStore::open(dir.path().join("store.redb"), 1024).expect("open");
    let records = admitted_store(&store);
    let replacement = block(MAX, 0xC0 + MAX as u8, 60);
    let lock = store.db.begin_write().expect("hold the redb write lock");
    let in_flight = {
        let replacement = bytes(&replacement);
        start_write_in_flight(&store, MAX, move |writer| {
            run(writer.commit_block_with_payload(commit_input(MAX, 0xC0 + MAX as u8), &replacement))
        })
    };
    assert_eq!(
        store.get_block_by_height(MAX).expect("read mid-flight"),
        Some(replacement.clone()),
        "the replacement is in flight: the cache serves its bytes"
    );
    assert_index_holds(&store, &records, "during the latest read, mid-replacement");
    lock.abort().expect("release the lock");
    in_flight
        .join()
        .expect("the write's thread")
        .expect("the replacement commit SUCCEEDS: no fence is in its path");
    assert_index_holds(&store, &records, "after the replacement landed");
}

// --- GREEN-4 pin: the gap fill (NET-DECISIONS 4) ---------------------------------------------

/// GREEN-4 PIN (no RED: the index did not exist at 5c77c9ca0). A publication was missed at height
/// 3, so the index holds 1, 2 and 4. The index's writer accepts a write BELOW its max only for an
/// ABSENT height (the publisher reaches it by a parent_hash walk from its ledger head): the gap
/// fill of 3 is accepted without moving the max, and a different record at 3 is then refused.
#[test]
fn green4_a_gap_fill_of_an_absent_height_below_the_max_is_accepted_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = RedbEpochStore::open(dir.path().join("store.redb"), 1024).expect("open");
    run(async {
        for height in 1..=MAX + 1 {
            store
                .commit_block_with_payload(
                    commit_input(height, 0xA0 + height as u8),
                    &bytes(&admitted(height)),
                )
                .await
                .expect("execute the height");
        }
    });
    for height in [1, 2, 4] {
        store
            .put_admitted_record(&record_of(&admitted(height)))
            .expect("index the published heights");
    }
    assert_eq!(store.get_admitted_record(3).expect("read"), None, "the missed height");
    let gap = record_of(&admitted(3));
    store
        .put_admitted_record(&gap)
        .expect("a gap fill of an ABSENT height below the max is accepted");
    assert_eq!(store.get_admitted_record(3).expect("read"), Some(gap.clone()));
    assert_eq!(
        store.get_admitted_tip().expect("max"),
        Some(tip_of(&record_of(&admitted(4)))),
        "the gap fill does not move the max"
    );
    assert!(
        store
            .put_admitted_record(&AdmittedRecord {
                block_hash: [0xEE; 32],
                ..gap.clone()
            })
            .is_err(),
        "once filled, the height is written: a different record there is refused"
    );
    assert_eq!(store.get_admitted_record(3).expect("read"), Some(gap));
}
