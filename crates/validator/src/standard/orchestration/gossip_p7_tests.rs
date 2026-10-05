// Path: crates/validator/src/standard/orchestration/gossip_p7_tests.rs
//! P7 round 3 (review round 2's N1): a stale-view proposal refused BEFORE its quorum certificate
//! is known must stay applicable once the certificate is known, with no redelivery by its
//! producer. Driven through the REAL network-event path (`events::handle_network_event`, which
//! calls `gossip::handle_gossip_block`) over the `sync_harness` context. The harness engine
//! refuses the proposal as stale while it holds no certificate for it (the real engine's rule,
//! pinned in ioi-consensus `tests_parts/p7_call_sites.rs`). Written RED against `93ac0d466`,
//! before the fix, where marked.

use super::events::handle_network_event;
use super::sync_harness::{harness_block, harness_hash, Harness, SharedHarness};
use ioi_networking::libp2p::NetworkEvent;
use ioi_types::app::{AccountId, Block, ChainTransaction, ConsensusVote};
use libp2p::PeerId;

/// Delivers `event` through the real network-event path. The future is boxed: the test runtime
/// pins its future on the test thread's stack, and the event handler's state machine is larger
/// than that stack (production spawns it onto the heap).
async fn deliver(h: &SharedHarness, event: NetworkEvent) {
    Box::pin(handle_network_event(event, &h.context)).await;
}

async fn gossip(h: &SharedHarness, block: Block<ChainTransaction>, from: PeerId) {
    deliver(
        h,
        NetworkEvent::GossipBlock {
            block,
            mirror_id: 0,
            from,
        },
    )
    .await;
}

/// A vote some other validator cast (its content is irrelevant to the harness engine).
fn a_vote(height: u64, block_hash: [u8; 32]) -> ConsensusVote {
    ConsensusVote {
        height,
        view: 0,
        block_hash,
        voter: AccountId([9; 32]),
        signature: vec![1; 8],
    }
}

/// The control (a pin: it holds before and after): a fresh proposal at the next height gossiped
/// through the real event path is verified by the engine and applied by the workload. It shows
/// the harness drives the gossip path to execution, so the N1 tests below fail or pass on the
/// mechanism they name.
#[tokio::test]
async fn n1_control_a_fresh_proposal_is_applied_through_the_gossip_path() {
    let h = Harness::new(3).await.shared();
    let b4 = harness_block(h.admitted_hash(3), 4, 0);
    let b4_hash = harness_hash(&b4);
    gossip(&h, b4, PeerId::random()).await;
    assert_eq!(
        h.context
            .lock()
            .await
            .consensus_engine_ref
            .lock()
            .await
            .proposals,
        vec![b4_hash],
        "the engine verified the gossiped proposal once"
    );
    assert_eq!(
        h.held_hash(4),
        Some(b4_hash),
        "the proposal was not applied"
    );
    assert!(!h
        .context
        .lock()
        .await
        .is_quarantined
        .load(std::sync::atomic::Ordering::SeqCst));
}

/// N1 (RED before the fix). NET's S-debug order: a timeout certificate to view 1 has formed here
/// at height 4; the view-0 proposal B arrives and is refused as stale; then the votes cast before
/// the timeouts arrive and a quorum certificate for B is known here. B must be applied, with no
/// redelivery by its producer (which may have crashed): the next height extends B.
#[tokio::test]
async fn n1_a_stale_proposal_refused_before_its_qc_is_applied_once_a_vote_certifies_it() {
    let h = Harness::new(3).await.shared();
    let b = harness_block(h.admitted_hash(3), 4, 0);
    let b_hash = harness_hash(&b);
    h.context
        .lock()
        .await
        .consensus_engine_ref
        .lock()
        .await
        .stale
        .insert(b_hash);
    let producer = PeerId::random();
    gossip(&h, b, producer).await;
    assert_eq!(
        h.held_hash(4),
        None,
        "a stale proposal was applied before its QC"
    );
    // The votes arrive; the engine now holds a certificate for B.
    h.context
        .lock()
        .await
        .consensus_engine_ref
        .lock()
        .await
        .certified
        .insert(b_hash);
    deliver(
        &h,
        NetworkEvent::ConsensusVoteReceived {
            vote: a_vote(4, b_hash),
            from: PeerId::random(),
        },
    )
    .await;
    assert_eq!(
        h.held_hash(4),
        Some(b_hash),
        "a certified stale-view proposal was never applied without a redelivery"
    );
}

/// N1, the quorum-certificate path (RED before the fix): the certificate for B arrives as a
/// propagated QC rather than as votes.
#[tokio::test]
async fn n1_a_stale_proposal_refused_before_its_qc_is_applied_once_a_qc_arrives() {
    let h = Harness::new(3).await.shared();
    let b = harness_block(h.admitted_hash(3), 4, 0);
    let b_hash = harness_hash(&b);
    h.context
        .lock()
        .await
        .consensus_engine_ref
        .lock()
        .await
        .stale
        .insert(b_hash);
    gossip(&h, b.clone(), PeerId::random()).await;
    assert_eq!(h.held_hash(4), None);
    h.context
        .lock()
        .await
        .consensus_engine_ref
        .lock()
        .await
        .certified
        .insert(b_hash);
    let mut qc = b.header.parent_qc.clone();
    qc.height = 4;
    qc.block_hash = b_hash;
    deliver(
        &h,
        NetworkEvent::QuorumCertificateReceived {
            qc,
            from: PeerId::random(),
        },
    )
    .await;
    assert_eq!(
        h.held_hash(4),
        Some(b_hash),
        "a certified stale-view proposal was never applied without a redelivery"
    );
}

/// N1, the negative arm (a pin: it holds before and after): while no certificate for B is known,
/// later consensus traffic does not apply it.
#[tokio::test]
async fn n1_an_uncertified_stale_proposal_stays_unapplied() {
    let h = Harness::new(3).await.shared();
    let b = harness_block(h.admitted_hash(3), 4, 0);
    let b_hash = harness_hash(&b);
    h.context
        .lock()
        .await
        .consensus_engine_ref
        .lock()
        .await
        .stale
        .insert(b_hash);
    gossip(&h, b, PeerId::random()).await;
    deliver(
        &h,
        NetworkEvent::ConsensusVoteReceived {
            vote: a_vote(4, b_hash),
            from: PeerId::random(),
        },
    )
    .await;
    assert_eq!(
        h.held_hash(4),
        None,
        "an uncertified stale proposal was applied"
    );
}
