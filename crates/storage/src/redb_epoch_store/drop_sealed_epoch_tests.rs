// Path: crates/storage/src/redb_epoch_store/drop_sealed_epoch_tests.rs
//! FU-N11-STORE-DROP-SEALED-EPOCH-1 RED (written against c4588e0e2, net/integration = the D2a
//! merge): `drop_sealed_epoch(e)` deletes epoch `e` by key prefix: every VERSIONS, CHANGES, REFS
//! and NODES row whose key starts with `e` (8 bytes, big-endian) and the MANIFEST row keyed by `e`.
//!
//! At c4588e0e2 its local `delete_prefix` reopens every table as `TableDefinition<&[u8], &[u8]>`.
//! redb refuses to reopen a typed table under another value type, so every call fails at its first
//! table, VERSIONS (`VERSIONS is of type Table<&[u8], [u8;32]>`), and its write transaction is
//! dropped uncommitted: nothing is deleted.
//!
//! These tests read the raw rows of the five tables through the store's own read transaction
//! (`read_txn`) and each table's own typed definition; no test-only accessor is added. An epoch's
//! rows are recognised by the big-endian epoch prefix of their keys (`u64::to_be_bytes`), computed
//! here, not by the store's encoders.
//!
//! NOT pinned here (FU-N11-EPOCH-DROP-REFCOUNT-1): a node written in a dropped epoch that a later
//! version still references is dropped with its epoch. The GC call (api validator/mod.rs) stays
//! commented out until reference counting lands.

use super::{RedbEpochStore, CHANGES, MANIFEST, NODES, REFS, VERSIONS};
use ioi_api::storage::{CommitInput, NodeHash, NodeStore, RootHash};
use redb::ReadableTable;

/// Epoch 0 = heights 0..=3, epoch 1 = heights 4..=7.
const EPOCH_SIZE: u64 = 4;
/// The committed heights: 1..=3 in epoch 0, 4..=6 in epoch 1.
const HEIGHTS: [u64; 6] = [1, 2, 3, 4, 5, 6];
/// A node written as new in BOTH epochs (at heights 2 and 5): each epoch holds its own row of it.
const SHARED: NodeHash = NodeHash([0x77; 32]);

/// The raw (key, value) bytes of one table's rows, in key order.
type Rows = Vec<(Vec<u8>, Vec<u8>)>;

/// The store's async writes are acknowledged by its background thread; any runtime drives them.
fn run<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(future)
}

/// A store whose VERSIONS, CHANGES, REFS and NODES hold rows of epochs 0 and 1 (three committed
/// heights in each, every height with a node of its own, SHARED in both), with both epochs sealed
/// (one MANIFEST row each).
fn filled_store(dir: &std::path::Path) -> RedbEpochStore {
    let store = RedbEpochStore::open(dir.join("store.redb"), EPOCH_SIZE).expect("open");
    run(async {
        for height in HEIGHTS {
            let mut new_nodes = vec![(
                NodeHash([0x40 + height as u8; 32]),
                vec![height as u8; 3 + height as usize],
            )];
            if height == 2 || height == 5 {
                new_nodes.push((SHARED, vec![0x77; 5]));
            }
            let unique_nodes_for_height = new_nodes.iter().map(|(hash, _)| *hash).collect();
            store
                .commit_block(CommitInput {
                    height,
                    root: RootHash([0x10 + height as u8; 32]),
                    unique_nodes_for_height,
                    new_nodes,
                })
                .await
                .expect("commit the height");
        }
    });
    store.seal_epoch(0).expect("seal epoch 0");
    store.seal_epoch(1).expect("seal epoch 1");
    store
}

/// Every row of VERSIONS, CHANGES, REFS, NODES and MANIFEST (in that order), read raw through the
/// store's own read transaction and each table's own typed definition.
fn snapshot(store: &RedbEpochStore) -> Vec<(&'static str, Rows)> {
    macro_rules! rows {
        ($txn:expr, $def:expr, $name:literal) => {{
            let table = $txn.open_table($def).expect(concat!("open ", $name));
            let rows: Rows = table
                .iter()
                .expect(concat!("iterate ", $name))
                .map(|row| {
                    let (key, value) = row.expect(concat!("read a row of ", $name));
                    (key.value().to_vec(), value.value().to_vec())
                })
                .collect();
            ($name, rows)
        }};
    }
    let txn = store.read_txn().expect("read transaction");
    vec![
        rows!(txn, VERSIONS, "VERSIONS"),
        rows!(txn, CHANGES, "CHANGES"),
        rows!(txn, REFS, "REFS"),
        rows!(txn, NODES, "NODES"),
        rows!(txn, MANIFEST, "MANIFEST"),
    ]
}

/// The rows of `rows` whose key carries the epoch prefix of `epoch`.
fn epoch_rows(rows: &Rows, epoch: u64) -> Rows {
    rows.iter()
        .filter(|(key, _)| key.starts_with(&epoch.to_be_bytes()))
        .cloned()
        .collect()
}

/// RED (fails at c4588e0e2 on the drop's `expect`: `Backend("VERSIONS is of type Table<&[u8],
/// [u8;32]>")`). drop_sealed_epoch(0) returns Ok; every epoch-1 row of the five tables is
/// byte-identical before and after; no epoch-0 row is left (VERSIONS/CHANGES/REFS/NODES rows with
/// the epoch-0 prefix, the MANIFEST row for 0); and each table is then exactly its epoch-1 rows.
#[test]
fn drop_sealed_epoch_deletes_exactly_its_epochs_rows() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = filled_store(dir.path());
    let before = snapshot(&store);
    for (table, rows) in &before {
        assert!(
            !epoch_rows(rows, 0).is_empty() && !epoch_rows(rows, 1).is_empty(),
            "fixture: {table} holds rows of epoch 0 and of epoch 1"
        );
    }
    store
        .drop_sealed_epoch(0)
        .expect("drop_sealed_epoch(0) of a filled, sealed epoch");
    let after = snapshot(&store);
    for ((table, rows_before), (_, rows_after)) in before.iter().zip(&after) {
        assert_eq!(
            epoch_rows(rows_after, 1),
            epoch_rows(rows_before, 1),
            "{table}: every epoch-1 row is byte-identical after the drop"
        );
    }
    for (table, rows_after) in &after {
        assert_eq!(
            epoch_rows(rows_after, 0),
            Rows::new(),
            "{table}: no epoch-0 row is left after the drop"
        );
    }
    for ((table, rows_before), (_, rows_after)) in before.iter().zip(&after) {
        assert_eq!(
            rows_after,
            &epoch_rows(rows_before, 1),
            "{table}: after the drop the table is exactly its epoch-1 rows"
        );
    }
}

/// RED (fails at c4588e0e2 on the FIRST drop's `expect`, as above). After a successful drop of
/// epoch 0, a second drop_sealed_epoch(0) returns Ok and changes no row of the five tables.
#[test]
fn a_second_drop_of_the_same_epoch_is_an_ok_no_op() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = filled_store(dir.path());
    store
        .drop_sealed_epoch(0)
        .expect("the first drop_sealed_epoch(0)");
    let after_first = snapshot(&store);
    for (table, rows) in &after_first {
        assert!(
            !rows.is_empty(),
            "fixture: {table} still holds rows after the first drop (the comparison is not vacuous)"
        );
    }
    store
        .drop_sealed_epoch(0)
        .expect("a second drop_sealed_epoch(0) of the dropped epoch is Ok");
    assert_eq!(
        snapshot(&store),
        after_first,
        "the second drop of epoch 0 changes no row"
    );
}
