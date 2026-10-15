// Path: crates/storage/src/redb_epoch_store/admitted_tip_txn_fence_tests.rs
//! FU-N11-DURABLE-STATUS-1 D2a round 2, GREEN-3 PINS for the two fence layers the RED-3 tests
//! cannot isolate. Every async write (put_block, commit_block, commit_block_with_payload) is
//! pre-checked before it touches the caches, and that pre-check refuses first, so a test through
//! the public API never reaches:
//! - the AUTHORITATIVE check inside the write's own transaction (it closes the race with a
//!   concurrent marker record);
//! - the WAL replay's check.
//!
//! These tests reach each layer directly: they send a persistence op past the pre-check, and they
//! plant a conflicting WAL entry. Without the layer under test, each one fails. At RED-3 the store
//! had no fence, so each fails there by construction. They were written at GREEN-3 because
//! isolating a layer needs the layer to exist.

use super::{AsyncCommit, PersistenceOp, RedbEpochStore};
use crate::wal::{StateDiff, WalIterator};
use ioi_api::storage::{AdmittedTip, CommitInput, NodeHash, NodeStore, RootHash};
use ioi_types::app::{
    AccountId, Block, BlockHeader, ChainTransaction, QuorumCertificate, SignatureSuite, StateRoot,
};

fn block(height: u64, root: u8) -> Block<ChainTransaction> {
    Block {
        header: BlockHeader {
            height,
            view: 0,
            parent_hash: [0x11; 32],
            parent_state_root: StateRoot(vec![0x22; 32]),
            state_root: StateRoot(vec![root; 32]),
            transactions_root: vec![0x44; 32],
            timestamp: 1,
            timestamp_ms: 1_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([5; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [6; 32],
            producer_pubkey: vec![7; 36],
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

fn run<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(future)
}

fn commit_input(height: u64, root: u8) -> CommitInput {
    CommitInput {
        height,
        root: RootHash([root; 32]),
        unique_nodes_for_height: Vec::new(),
        new_nodes: Vec::new(),
    }
}

/// A store whose height 3 is committed (root and block 0xA3) and admitted.
fn admitted_store(path: &std::path::Path) -> RedbEpochStore {
    let store = RedbEpochStore::open(path, 1024).expect("open");
    for height in 1..=3u64 {
        let root = 0xA0 + height as u8;
        run(store.commit_block_with_payload(commit_input(height, root), &bytes(&block(height, root))))
            .expect("commit");
    }
    store
        .put_admitted_tip(&AdmittedTip {
            height: 3,
            block_hash: [0xAD; 32],
            state_root: vec![0xA3; 32],
        })
        .expect("admit height 3");
    store
}

/// Sends `op` straight to the persistence thread, past the pre-check, and returns its ack.
fn send(
    store: &RedbEpochStore,
    op: impl FnOnce(tokio::sync::oneshot::Sender<Result<(), String>>) -> PersistenceOp,
) -> Result<(), String> {
    run(async {
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        store.tx_sender.send(op(ack_tx)).await.expect("queue the op");
        ack_rx.await.expect("the persistence thread acknowledges")
    })
}

fn wal_entries(path: &std::path::Path) -> Vec<(u64, [u8; 32])> {
    WalIterator::new(&path.with_extension("wal"))
        .expect("open the WAL")
        .map(|entry| entry.map(|(height, root, _)| (height, root)).expect("WAL entry"))
        .collect()
}

/// PIN (M-notxnfence): a block write that skips the pre-check is refused inside its own
/// transaction, and the committed block stays.
#[test]
fn a_block_write_past_the_precheck_is_refused_in_its_own_transaction() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = admitted_store(&dir.path().join("store.redb"));
    let refused = send(&store, |ack| {
        PersistenceOp::WriteBlock(3, bytes(&block(3, 0xB4)), ack)
    });
    assert!(refused.is_err(), "the in-transaction fence refuses the rewrite");
    assert_eq!(store.get_block_by_height(3).expect("read 3"), Some(block(3, 0xA3)));
}

/// PIN (M-notxnfence, state): a state commit that skips the pre-check is refused inside its own
/// transaction BEFORE the WAL append, so the refused root never reaches the WAL.
#[test]
fn a_state_commit_past_the_precheck_is_refused_before_the_wal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("store.redb");
    let store = admitted_store(&path);
    let refused = send(&store, |ack| {
        PersistenceOp::CommitState(
            AsyncCommit {
                height: 3,
                root: RootHash([0xB4; 32]),
                new_nodes: Vec::<(NodeHash, Vec<u8>)>::new(),
                unique_nodes: Vec::new(),
            },
            ack,
        )
    });
    assert!(refused.is_err(), "the in-transaction fence refuses the state commit");
    assert_eq!(
        store.root_for_height(3).expect("root 3"),
        Some(RootHash([0xA3; 32]))
    );
    assert!(
        !wal_entries(&path).contains(&(3, [0xB4; 32])),
        "a refused commit is not in the WAL"
    );
}

/// PIN (M-replay-nofence): a WAL entry that would change a committed state version (planted here
/// as the race the transaction fence leaves: a marker that advanced after the append) is skipped
/// at replay, and the committed version stays.
#[test]
fn the_wal_replay_never_changes_a_committed_state_version() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("store.redb");
    {
        let store = admitted_store(&path);
        store
            ._wal
            .append_block(
                3,
                [0xB4; 32],
                &StateDiff {
                    new_nodes: Vec::new(),
                    touched_nodes: Vec::new(),
                },
            )
            .expect("plant a conflicting WAL entry");
        store.override_head(2).expect("replay from above height 2");
    }
    let mut reopened = None;
    for _ in 0..100 {
        match RedbEpochStore::open(&path, 1024) {
            Ok(store) => {
                reopened = Some(store);
                break;
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
        }
    }
    let reopened = reopened.expect("reopen");
    assert_eq!(
        reopened.root_for_height(3).expect("root 3"),
        Some(RootHash([0xA3; 32])),
        "the replay keeps the committed version"
    );
}
