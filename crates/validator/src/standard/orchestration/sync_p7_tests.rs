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
