// Path: crates/storage/src/redb_epoch_store/admitted_tip_no_downgrade_tests.rs
//! FU-N11-DURABLE-STATUS-1 D2a round 2, RED-3b (the IOI Director's no-downgrade condition, 2026-10-15),
//! at the block store, the choke point every write path reaches: at or below the persisted
//! Agentgres-admitted marker, a block write may never STRIP the stored block's post-signing
//! evidence (its producer signature, sealed finality proof or guardian certificate), nor swap its
//! guardian certificate. The refusal leaves the stored block unchanged. (Verifying an ADDED or
//! REPLACED signature or proof needs the producer's key and is the workload fence's job,
//! pinned in ioi-validator grpc_blockchain/admitted_tip_no_downgrade_tests.rs.)
//!
//! Written against RED-3 (4837d4479) using only its API: every test FAILS there, because
//! put_block writes BLOCKS unconditionally (redb_epoch_store.rs:868-873, :522-527).

use super::RedbEpochStore;
use ioi_api::storage::{AdmittedTip, NodeStore};
use ioi_types::app::{
    AccountId, Block, BlockHeader, ChainTransaction, GuardianQuorumCertificate, QuorumCertificate,
    SealedFinalityProof, SignatureSuite, StateRoot,
};

/// The committed block at height 3, carrying a signature, a sealed finality proof and a guardian
/// certificate (all outside its identity preimage).
fn evidenced_block() -> Block<ChainTransaction> {
    Block {
        header: BlockHeader {
            height: 3,
            view: 0,
            parent_hash: [0x11; 32],
            parent_state_root: StateRoot(vec![0x22; 32]),
            state_root: StateRoot(vec![0xA3; 32]),
            transactions_root: vec![0x44; 32],
            timestamp: 1,
            timestamp_ms: 1_000,
            gas_used: 0,
            validator_set: Vec::new(),
            producer_account_id: AccountId([5; 32]),
            producer_key_suite: SignatureSuite::ED25519,
            producer_pubkey_hash: [6; 32],
            producer_pubkey: vec![7; 36],
            oracle_counter: 41,
            oracle_trace_hash: [0x7A; 32],
            guardian_certificate: Some(GuardianQuorumCertificate {
                counter: 41,
                trace_hash: [0x7A; 32],
                decision_hash: [0xDE; 32],
                ..Default::default()
            }),
            sealed_finality_proof: Some(SealedFinalityProof {
                epoch: 1,
                guardian_counter: 41,
                guardian_trace_hash: [0x7A; 32],
                ..Default::default()
            }),
            canonical_order_certificate: None,
            timeout_certificate: None,
            aft_timeout_certificate: None,
            parent_qc: QuorumCertificate::default(),
            previous_canonical_collapse_commitment_hash: [0; 32],
            canonical_collapse_extension_certificate: None,
            publication_frontier: None,
            signature: vec![0x5E; 64],
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

/// A store holding `block` at its height, admitted.
fn admitted_store(dir: &tempfile::TempDir, block: &Block<ChainTransaction>) -> RedbEpochStore {
    let store = RedbEpochStore::open(dir.path().join("store.redb"), 1024).expect("open");
    run(store.put_block(block.header.height, &bytes(block))).expect("store the block");
    store
        .put_admitted_tip(&AdmittedTip {
            height: block.header.height,
            block_hash: [0xAD; 32],
            state_root: block.header.state_root.0.clone(),
        })
        .expect("admit it");
    store
}

/// RED-3b (b), at the store: a rewrite that strips the sealed finality proof is refused.
#[test]
fn the_store_refuses_to_strip_a_committed_blocks_finality_proof() {
    let dir = tempfile::tempdir().expect("tempdir");
    let stored = evidenced_block();
    let store = admitted_store(&dir, &stored);
    let mut stripped = stored.clone();
    stripped.header.sealed_finality_proof = None;
    assert!(
        run(store.put_block(3, &bytes(&stripped))).is_err(),
        "stripping the committed block's sealed finality proof is refused"
    );
    assert_eq!(store.get_block_by_height(3).expect("read 3"), Some(stored));
}

/// RED-3b (b), at the store: a rewrite that strips the producer signature is refused.
#[test]
fn the_store_refuses_to_strip_a_committed_blocks_signature() {
    let dir = tempfile::tempdir().expect("tempdir");
    let stored = evidenced_block();
    let store = admitted_store(&dir, &stored);
    let mut stripped = stored.clone();
    stripped.header.signature = Vec::new();
    assert!(
        run(store.put_block(3, &bytes(&stripped))).is_err(),
        "stripping the committed block's signature is refused"
    );
    assert_eq!(store.get_block_by_height(3).expect("read 3"), Some(stored));
}

/// RED-3b, at the store: a rewrite that strips or swaps the guardian certificate is refused.
#[test]
fn the_store_refuses_to_strip_or_swap_a_committed_blocks_guardian_certificate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let stored = evidenced_block();
    let store = admitted_store(&dir, &stored);
    let mut stripped = stored.clone();
    stripped.header.guardian_certificate = None;
    assert!(
        run(store.put_block(3, &bytes(&stripped))).is_err(),
        "stripping the guardian certificate is refused"
    );
    let mut swapped = stored.clone();
    if let Some(certificate) = swapped.header.guardian_certificate.as_mut() {
        certificate.decision_hash = [0xEE; 32];
    }
    assert!(
        run(store.put_block(3, &bytes(&swapped))).is_err(),
        "swapping the guardian certificate is refused"
    );
    assert_eq!(store.get_block_by_height(3).expect("read 3"), Some(stored));
}
