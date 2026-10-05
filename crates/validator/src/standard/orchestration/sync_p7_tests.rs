// Path: crates/validator/src/standard/orchestration/sync_p7_tests.rs
//! P7 round 2 (build Ruling 12; review round 1's MAJORs M1-M4): the sync findings, driven
//! through the REAL sync handlers (`handle_blocks_response`, `start_catchup_to_peer`) over the
//! `sync_harness` context. Each test states the rule it pins; written RED against 98e89083d,
//! before the fix.

use super::sync::{handle_blocks_response, start_catchup_to_peer};
use super::sync_harness::{harness_block, harness_hash, CertificateAnswer, Harness};
use libp2p::PeerId;

/// M1. Ruling 12 as amended: "(c) the peer's block carries NO valid certificate: REJECT it";
/// T2b halts only on a durable-tier conflict WITH a certified peer block. Here a peer serves, in
/// the already-held prefix, a forged block at an admitted height (2 ≤ floor 3) that nothing in
/// its batch certifies. The node must not halt; the peer is dropped.
#[tokio::test]
async fn m1_an_uncertified_conflicting_block_at_an_admitted_height_does_not_halt() {
    let mut h = Harness::new(3).await;
    let liar = PeerId::random();
    h.start_session(liar, 5).await;
    let forged = harness_block(h.admitted_hash(1), 2, 0xF0);
    assert_ne!(harness_hash(&forged), h.admitted_hash(2));
    let next = harness_block(h.admitted_hash(3), 4, 0);
    handle_blocks_response(&mut h.context, liar, vec![forged, next]).await;
    assert!(
        !h.quarantined(),
        "an uncertified block at an admitted height froze the node"
    );
    assert!(h.refused(&liar), "the peer serving it is dropped");
}

/// M1, the positive arm (a pin: it holds before and after): a conflicting block at an admitted
/// height whose batch CERTIFIES it (the next block's parent certificate binds it and verifies) is
/// a durable-tier conflict: the node halts with evidence.
#[tokio::test]
async fn m1_a_certified_conflicting_block_at_an_admitted_height_halts() {
    let mut h = Harness::new(3).await;
    let peer = PeerId::random();
    h.start_session(peer, 5).await;
    let conflicting = harness_block(h.admitted_hash(2), 3, 0xC3);
    let certifying_child = harness_block(harness_hash(&conflicting), 4, 0);
    h.answer(harness_hash(&conflicting), CertificateAnswer::Verified)
        .await;
    handle_blocks_response(&mut h.context, peer, vec![conflicting, certifying_child]).await;
    assert!(h.quarantined(), "a certified admitted-tier conflict halts");
}

/// Sets up a node holding its own tentative block 4 (executed, not admitted; floor 3) and returns
/// (block 4, a peer block 5 whose parent certificate certifies block 4).
async fn tentative_tip(
    h: &mut Harness,
) -> (
    ioi_types::app::Block<ioi_types::app::ChainTransaction>,
    ioi_types::app::Block<ioi_types::app::ChainTransaction>,
) {
    let b4 = harness_block(h.admitted_hash(3), 4, 0);
    let b5 = harness_block(harness_hash(&b4), 5, 0);
    h.workload.blocks.lock().unwrap().insert(4, b4.clone());
    h.context.last_executed_block = Some(b4.clone());
    super::context::remember_executed_header(&mut h.context.recent_executed_headers, &b4);
    (b4, b5)
}

/// M2. A local "cannot evaluate" is not the peer lying: an honest peer whose block's parent
/// certificate this node cannot evaluate (the asynchronous parent proof of a hash-fallback height
/// is not held here) is NOT dropped.
#[tokio::test]
async fn m2_a_certificate_this_node_cannot_evaluate_does_not_drop_the_peer() {
    let mut h = Harness::new(3).await;
    let honest = PeerId::random();
    let (b4, b5) = tentative_tip(&mut h).await;
    h.start_session(honest, 6).await;
    h.answer(harness_hash(&b4), CertificateAnswer::CannotEvaluate)
        .await;
    handle_blocks_response(&mut h.context, honest, vec![b4, b5]).await;
    assert!(
        !h.refused(&honest),
        "an unevaluable certificate dropped an honest peer"
    );
    assert!(!h.quarantined());
}

/// M2, the second path: the parent state is unavailable here. Not the peer's fault either.
#[tokio::test]
async fn m2_an_unavailable_parent_state_does_not_drop_the_peer() {
    let mut h = Harness::new(3).await;
    let honest = PeerId::random();
    let (b4, b5) = tentative_tip(&mut h).await;
    h.start_session(honest, 6).await;
    h.resolver
        .unavailable_roots
        .lock()
        .unwrap()
        .insert(b5.header.parent_state_root.0.clone());
    handle_blocks_response(&mut h.context, honest, vec![b4, b5]).await;
    assert!(
        !h.refused(&honest),
        "an unavailable parent state dropped an honest peer"
    );
}

/// M2, the negative arm (a pin): a REFUTED certificate still drops the peer.
#[tokio::test]
async fn m2_a_refuted_certificate_still_drops_the_peer() {
    let mut h = Harness::new(3).await;
    let liar = PeerId::random();
    let (b4, b5) = tentative_tip(&mut h).await;
    h.start_session(liar, 6).await;
    h.answer(harness_hash(&b4), CertificateAnswer::Refuted)
        .await;
    handle_blocks_response(&mut h.context, liar, vec![b4, b5]).await;
    assert!(h.refused(&liar));
}

/// M3. T5 is "progress, or an explicit halt within a bounded number of retries": a node whose
/// cursor keeps advancing (here by live gossip, as gossip.rs advances `progress.next`) while sync
/// batches come back empty is PROGRESSING and must not be frozen.
#[tokio::test]
async fn m3_a_node_progressing_by_gossip_is_not_frozen_by_empty_batches() {
    let mut h = Harness::new(3).await;
    let (a, b) = (PeerId::random(), PeerId::random());
    h.start_session(a, 100).await;
    h.context.known_peers_ref.lock().await.insert(b);
    for _ in 0..40 {
        h.expire_backoff();
        let progress = h
            .context
            .sync_progress
            .as_mut()
            .expect("the session continues");
        progress.next += 1; // a gossip block applied (gossip.rs advances the cursor)
        progress.inflight = true;
        // The reply comes from whichever honest peer the session targets now.
        let target = progress.target.unwrap_or(a);
        handle_blocks_response(&mut h.context, target, Vec::new()).await;
    }
    assert!(!h.quarantined(), "a progressing node was frozen by T5");
    assert!(
        h.context.sync_progress.is_some(),
        "a progressing session continues"
    );
}

/// M3, the halt: with NO progress at all, the bound ends the SYNC SESSION explicitly; it does not
/// freeze the node (the claimed tip was never verified: one lying status must not freeze a node).
#[tokio::test]
async fn m3_the_retry_bound_ends_the_session_not_the_node() {
    let mut h = Harness::new(3).await;
    let (a, b) = (PeerId::random(), PeerId::random());
    h.start_session(a, 100).await;
    h.context.known_peers_ref.lock().await.insert(b);
    for _ in 0..40 {
        h.expire_backoff();
        let Some(progress) = h.context.sync_progress.as_mut() else {
            break;
        };
        progress.inflight = true;
        let target = progress.target.unwrap_or(a);
        handle_blocks_response(&mut h.context, target, Vec::new()).await;
    }
    assert!(
        !h.quarantined(),
        "T5 froze the node instead of ending the session"
    );
    assert!(
        h.context.sync_progress.is_none(),
        "the exhausted session ended"
    );
}

/// M4. A peer this sync dropped is never targeted again: a gossiped height gap from it neither
/// becomes the target nor extends the tip.
#[tokio::test]
async fn m4_a_refused_peer_is_not_retargeted_by_a_gossip_height_gap() {
    let mut h = Harness::new(3).await;
    let honest = PeerId::random();
    let liar = PeerId::random();
    h.start_session(honest, 5).await;
    {
        let progress = h.context.sync_progress.as_mut().unwrap();
        progress.authority.refuse_peer(liar);
        progress.target = None;
        progress.inflight = false;
    }
    start_catchup_to_peer(&mut h.context, liar, 50).await;
    let progress = h.context.sync_progress.as_ref().unwrap();
    assert_ne!(
        progress.target,
        Some(liar),
        "a refused peer became the target"
    );
    assert_eq!(progress.tip, 5, "a refused peer's height extended the tip");
}

/// M4. A reply from a refused peer that is (still) the target must not leave the request in
/// flight forever: the session moves on to another peer.
#[tokio::test]
async fn m4_a_refused_targets_reply_is_not_left_in_flight() {
    let mut h = Harness::new(3).await;
    let honest = PeerId::random();
    let liar = PeerId::random();
    h.start_session(liar, 5).await;
    h.context.known_peers_ref.lock().await.insert(honest);
    h.context
        .sync_progress
        .as_mut()
        .unwrap()
        .authority
        .refuse_peer(liar);
    let b4 = harness_block(h.admitted_hash(3), 4, 0);
    handle_blocks_response(&mut h.context, liar, vec![b4]).await;
    let progress = h
        .context
        .sync_progress
        .as_ref()
        .expect("the session continues");
    assert_ne!(
        progress.target,
        Some(liar),
        "the refused target kept the session"
    );
    assert!(
        !progress.inflight || progress.target == Some(honest),
        "the request was left in flight on a refused peer"
    );
}

// --- Added with the round-2 fix (not part of the RED reproduction set) ---------------------

/// M1, the third arm: a conflicting block at an admitted height that ends the batch (nothing
/// certifies it YET) is rejected, never drained, and neither halts the node nor drops the peer.
#[tokio::test]
async fn m1_an_uncertified_conflicting_block_ending_the_batch_is_rejected_and_the_peer_kept() {
    let mut h = Harness::new(3).await;
    let peer = PeerId::random();
    h.start_session(peer, 5).await;
    let conflicting = harness_block(h.admitted_hash(2), 3, 0xC3);
    handle_blocks_response(&mut h.context, peer, vec![conflicting]).await;
    assert!(!h.quarantined(), "an uncertified block froze the node");
    assert!(
        !h.refused(&peer),
        "a merely uncertified block dropped the peer"
    );
    let progress = h
        .context
        .sync_progress
        .as_ref()
        .expect("the session continues");
    assert_eq!(
        progress.authority.consecutive_failures, 1,
        "the wait is counted"
    );
}

/// M4, the lifecycle tick: a due retry never targets a refused peer; with no usable peer it is
/// counted toward T5.
#[tokio::test]
async fn m4_the_retry_tick_never_targets_a_refused_peer() {
    let mut h = Harness::new(3).await;
    let liar = PeerId::random();
    let honest = PeerId::random();
    h.start_session(liar, 5).await;
    {
        let progress = h.context.sync_progress.as_mut().unwrap();
        progress.authority.refuse_peer(liar);
        progress.inflight = false;
        progress.target = None;
        progress.retry_not_before = Some(std::time::Instant::now());
    }
    h.drain_requests();
    super::sync::sync_retry_tick(&mut h.context, &[liar], std::time::Duration::from_secs(2)).await;
    let progress = h.context.sync_progress.as_ref().unwrap();
    assert_ne!(
        progress.target,
        Some(liar),
        "the tick targeted a refused peer"
    );
    assert_eq!(
        progress.authority.consecutive_failures, 1,
        "no usable target is counted"
    );
    assert!(
        h.drain_requests().is_empty(),
        "nothing was requested from the refused peer"
    );
    // With an honest peer available, the tick targets it.
    h.expire_backoff();
    h.context.sync_progress.as_mut().unwrap().retry_not_before = Some(std::time::Instant::now());
    super::sync::sync_retry_tick(
        &mut h.context,
        &[liar, honest],
        std::time::Duration::from_secs(2),
    )
    .await;
    assert_eq!(
        h.context.sync_progress.as_ref().unwrap().target,
        Some(honest)
    );
    assert_eq!(h.drain_requests(), vec![honest]);
}

/// M4, the tick's timeout arm: a timed-out request is a failed batch (counted) and the session
/// moves to another usable peer.
#[tokio::test]
async fn m4_a_timed_out_request_is_counted_and_moves_on() {
    let mut h = Harness::new(3).await;
    let (slow, other) = (PeerId::random(), PeerId::random());
    h.start_session(slow, 5).await;
    h.context.known_peers_ref.lock().await.insert(other);
    h.context.sync_progress.as_mut().unwrap().requested_at =
        std::time::Instant::now() - std::time::Duration::from_secs(10);
    super::sync::sync_retry_tick(
        &mut h.context,
        &[slow, other],
        std::time::Duration::from_secs(2),
    )
    .await;
    let progress = h.context.sync_progress.as_ref().unwrap();
    assert_eq!(progress.authority.consecutive_failures, 1);
    assert_eq!(progress.target, Some(other));
    assert!(!progress.inflight);
}

/// M4, the outbound-failure path: the replacement target honours the refused set.
#[tokio::test]
async fn m4_an_outbound_failure_never_retargets_a_refused_peer() {
    let mut h = Harness::new(3).await;
    let (target, liar) = (PeerId::random(), PeerId::random());
    h.start_session(target, 5).await;
    h.context.known_peers_ref.lock().await.insert(liar);
    h.context
        .sync_progress
        .as_mut()
        .unwrap()
        .authority
        .refuse_peer(liar);
    super::sync::handle_outbound_failure(&mut h.context, target).await;
    let progress = h.context.sync_progress.as_ref().unwrap();
    assert_ne!(progress.target, Some(liar));
    assert_eq!(progress.authority.consecutive_failures, 1);
}

/// An AFT node (floor 0) holding its own tentative blocks 1 and 2 (executed, not admitted), and a
/// peer's different block 2' (another execution: a different state root).
async fn tentative_aft_projection() -> (
    Harness,
    ioi_types::app::Block<ioi_types::app::ChainTransaction>,
    ioi_types::app::Block<ioi_types::app::ChainTransaction>,
    ioi_types::app::Block<ioi_types::app::ChainTransaction>,
) {
    let mut h = Harness::with_profile(
        0,
        ioi_types::config::RuntimeFinalityProfile::BftConsensusAftV1,
    )
    .await;
    let b1 = harness_block([0u8; 32], 1, 0);
    let b2 = harness_block(harness_hash(&b1), 2, 0);
    let mut peer_b2 = harness_block(harness_hash(&b1), 2, 0x22);
    peer_b2.header.state_root = ioi_types::app::StateRoot(vec![0xEE; 32]);
    for block in [&b1, &b2] {
        h.workload
            .blocks
            .lock()
            .unwrap()
            .insert(block.header.height, block.clone());
        super::context::remember_executed_header(&mut h.context.recent_executed_headers, block);
    }
    h.context.last_executed_block = Some(b2.clone());
    (h, b1, b2, peer_b2)
}

/// G1's replacement call site (round 2; the review's m3 asked for executed pins of the sync call
/// sites): a peer block that would REPLACE local tentative state, with nothing in its batch
/// certifying it, replaces nothing, freezes nothing, keeps the peer, and counts the wait.
#[tokio::test]
async fn g1_an_uncertified_replacement_replaces_nothing() {
    let (mut h, b1, b2, peer_b2) = tentative_aft_projection().await;
    let peer = PeerId::random();
    h.start_session(peer, 5).await;
    handle_blocks_response(&mut h.context, peer, vec![b1, peer_b2]).await;
    let held = h.workload.blocks.lock().unwrap().get(&2).cloned().unwrap();
    assert_eq!(
        harness_hash(&held),
        harness_hash(&b2),
        "local state was replaced"
    );
    assert!(!h.quarantined());
    assert!(!h.refused(&peer));
    assert_eq!(
        h.context
            .sync_progress
            .as_ref()
            .unwrap()
            .authority
            .consecutive_failures,
        1
    );
}

/// G1's replacement call site, the refusal arm: a batch whose H+1 does not certify the
/// replacement (it names another parent) replaces nothing and drops the peer.
#[tokio::test]
async fn g1_a_replacement_whose_batch_does_not_certify_it_drops_the_peer() {
    let (mut h, b1, b2, peer_b2) = tentative_aft_projection().await;
    let peer = PeerId::random();
    h.start_session(peer, 5).await;
    let foster = harness_block([0x77; 32], 3, 0);
    handle_blocks_response(&mut h.context, peer, vec![b1, peer_b2, foster]).await;
    let held = h.workload.blocks.lock().unwrap().get(&2).cloned().unwrap();
    assert_eq!(
        harness_hash(&held),
        harness_hash(&b2),
        "local state was replaced"
    );
    assert!(!h.quarantined());
    assert!(h.refused(&peer));
}

/// Source selection, the status path (round 1's mechanism, pinned in round 2): a refused peer's
/// advertised height neither extends the tip nor makes it the target.
#[tokio::test]
async fn a_refused_peers_status_is_not_believed() {
    let mut h = Harness::new(3).await;
    let honest = PeerId::random();
    let liar = PeerId::random();
    h.start_session(honest, 5).await;
    {
        let progress = h.context.sync_progress.as_mut().unwrap();
        progress.authority.refuse_peer(liar);
        progress.target = None;
        progress.inflight = false;
    }
    let chain_id = h.context.chain_id;
    super::sync::handle_status_response(
        &mut h.context,
        liar,
        50,
        [0u8; 32],
        chain_id,
        vec![0; 32],
        None,
    )
    .await;
    let progress = h.context.sync_progress.as_ref().unwrap();
    assert_eq!(progress.tip, 5, "a refused peer's status extended the tip");
    assert_ne!(
        progress.target,
        Some(liar),
        "a refused peer became the target"
    );
}

/// Source selection, the blocks path for a NON-target: blocks from a refused peer that carry the
/// next consecutive height neither retarget the session nor get applied.
#[tokio::test]
async fn a_refused_non_targets_blocks_are_ignored() {
    let mut h = Harness::new(3).await;
    let honest = PeerId::random();
    let liar = PeerId::random();
    h.start_session(honest, 5).await;
    h.context
        .sync_progress
        .as_mut()
        .unwrap()
        .authority
        .refuse_peer(liar);
    let b4 = harness_block(h.admitted_hash(3), 4, 0);
    handle_blocks_response(&mut h.context, liar, vec![b4]).await;
    let progress = h.context.sync_progress.as_ref().unwrap();
    assert_eq!(
        progress.target,
        Some(honest),
        "a refused peer retargeted the session"
    );
    assert_eq!(progress.next, 3, "a refused peer's block was applied");
    assert!(h.workload.blocks.lock().unwrap().get(&4).is_none());
}

// --- Round 2b: crossing a hash-fallback height (review round 1, M2's first need) ---------------
// "The sync check must accept the async-parent reference on evidence the batch or state can
// provide." The child of a hash-fallback virtual block carries the signature-free asynchronous
// reference (`aft_async_canonical_parent_reference`) as its parent certificate; only a node that
// holds the in-memory asynchronous parent proof can evaluate it. The batch's NEXT block carries an
// ordinary certificate for the child itself. Written RED against e33dab3ad, before the fix, where
// marked.
//
// Harness scope: after a FRESH block is executed (`process_block`, which stores it), the sync
// loop hydrates the live engine's collapse chain (aft_collapse.rs,
// `observe_live_committed_chain_through_block`), which harness blocks cannot satisfy (they carry
// no canonical collapse extension certificates), so the loop retries after the first freshly
// executed block. These tests therefore hold the virtual block as this node's own executed block
// (skipped by its exact hash, as in `tentative_tip`), so the FIRST block the loop evaluates is the
// child, and they observe the child's G1 decision at `process_block`.

/// A node at floor 3 holding block 4 (the virtual block, on block 3) as its own executed block,
/// and a peer batch [4, 5, 6]: block 5's parent certificate is the asynchronous reference to
/// block 4, and block 6's parent certificate is an ordinary certificate for block 5. This node
/// does not hold block 4's asynchronous parent proof: the engine answers "cannot evaluate" for it.
async fn across_a_fallback_height(
    h: &mut Harness,
) -> (
    ioi_types::app::Block<ioi_types::app::ChainTransaction>,
    ioi_types::app::Block<ioi_types::app::ChainTransaction>,
    ioi_types::app::Block<ioi_types::app::ChainTransaction>,
) {
    let (b4, mut b5) = tentative_tip(h).await;
    b5.header.parent_qc = ioi_types::app::aft_async_canonical_parent_reference(&b4.header).unwrap();
    assert!(b5.header.parent_qc.signatures.is_empty());
    let b6 = harness_block(harness_hash(&b5), 6, 0);
    h.answer(harness_hash(&b4), CertificateAnswer::CannotEvaluate)
        .await;
    (b4, b5, b6)
}

fn held_hash(h: &Harness, height: u64) -> Option<[u8; 32]> {
    h.workload
        .blocks
        .lock()
        .unwrap()
        .get(&height)
        .map(harness_hash)
}

/// M2 (round 2b; RED before the fix). The batch's block 6 certifies block 5 with an ordinary
/// certificate, and block 5's header binds its asynchronous parent reference: the engine is asked
/// about block 5's OWN certificate, block 5 is executed, and the peer is kept.
#[tokio::test]
async fn m2_an_asynchronous_child_certified_by_its_batch_is_applied() {
    let mut h = Harness::new(3).await;
    let honest = PeerId::random();
    let (b4, b5, b6) = across_a_fallback_height(&mut h).await;
    h.start_session(honest, 10).await;
    let b5_hash = harness_hash(&b5);
    handle_blocks_response(&mut h.context, honest, vec![b4, b5, b6]).await;
    assert!(!h.refused(&honest), "an honest peer was dropped");
    assert!(!h.quarantined());
    assert!(
        h.context
            .consensus_engine_ref
            .lock()
            .await
            .asked
            .iter()
            .any(|qc| qc.height == 5 && qc.block_hash == b5_hash),
        "the child's own certificate was never verified"
    );
    assert_eq!(
        held_hash(&h, 5),
        Some(b5_hash),
        "the child of the asynchronous parent was not executed"
    );
}

/// M2 (round 2b), a pin: a batch that ENDS at the asynchronous child carries nothing that
/// certifies it yet. Nothing is executed at its height, the peer is kept, and the wait is
/// counted.
#[tokio::test]
async fn m2_an_asynchronous_child_ending_the_batch_waits_and_keeps_the_peer() {
    let mut h = Harness::new(3).await;
    let honest = PeerId::random();
    let (b4, b5, _b6) = across_a_fallback_height(&mut h).await;
    h.start_session(honest, 10).await;
    handle_blocks_response(&mut h.context, honest, vec![b4, b5]).await;
    assert!(!h.refused(&honest));
    assert!(!h.quarantined());
    assert_eq!(held_hash(&h, 5), None, "an uncertified child was executed");
    let progress = h
        .context
        .sync_progress
        .as_ref()
        .expect("the session continues");
    // Block 4 was skipped as this node's own (the cursor moved onto it); the child waits.
    assert_eq!(progress.next, 4);
    assert_eq!(
        progress.authority.consecutive_failures, 1,
        "the wait is counted"
    );
}

/// M2 (round 2b; RED before the fix): a signature-free reference that names this node's parent
/// block but is not its canonical asynchronous reference (here another view) is refuted against
/// inputs this node fully holds: the peer is dropped and nothing is executed.
#[tokio::test]
async fn m2_a_non_canonical_asynchronous_reference_drops_the_peer() {
    let mut h = Harness::new(3).await;
    let liar = PeerId::random();
    let (b4, mut b5, _b6) = across_a_fallback_height(&mut h).await;
    h.start_session(liar, 10).await;
    b5.header.parent_qc.view += 7;
    let b6 = harness_block(harness_hash(&b5), 6, 0);
    handle_blocks_response(&mut h.context, liar, vec![b4, b5, b6]).await;
    assert!(
        h.refused(&liar),
        "a forged asynchronous reference kept its peer"
    );
    assert_eq!(held_hash(&h, 5), None);
}

/// M2 (round 2b; RED before the fix): the batch's certificate for the asynchronous child is
/// REFUTED: the peer is dropped and the child is not executed.
#[tokio::test]
async fn m2_an_asynchronous_child_whose_certificate_is_refuted_drops_the_peer() {
    let mut h = Harness::new(3).await;
    let liar = PeerId::random();
    let (b4, b5, b6) = across_a_fallback_height(&mut h).await;
    h.start_session(liar, 10).await;
    h.answer(harness_hash(&b5), CertificateAnswer::Refuted)
        .await;
    handle_blocks_response(&mut h.context, liar, vec![b4, b5, b6]).await;
    assert!(h.refused(&liar), "a refuted certificate kept its peer");
    assert_eq!(held_hash(&h, 5), None);
}

/// M2 (round 2b), a pin: a signature-free reference to a parent this node does NOT hold (here the
/// workload no longer holds block 4, though this node executed it) cannot be evaluated here; it
/// is not evidence against the peer. Nothing is executed, the peer is kept, the wait is counted.
#[tokio::test]
async fn m2_an_asynchronous_reference_to_a_parent_not_held_here_keeps_the_peer() {
    let mut h = Harness::new(3).await;
    let honest = PeerId::random();
    let (b4, b5, b6) = across_a_fallback_height(&mut h).await;
    h.start_session(honest, 10).await;
    h.workload.blocks.lock().unwrap().remove(&4);
    handle_blocks_response(&mut h.context, honest, vec![b4, b5, b6]).await;
    assert!(
        !h.refused(&honest),
        "a reference to a parent not held here dropped the peer"
    );
    assert!(!h.quarantined());
    assert_eq!(held_hash(&h, 5), None);
    assert_eq!(
        h.context
            .sync_progress
            .as_ref()
            .expect("the session continues")
            .authority
            .consecutive_failures,
        1
    );
}
