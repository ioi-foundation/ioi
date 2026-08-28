// Path: crates/validator/src/standard/orchestration/finalize/tests_parts/solo_parity_post_commit.rs
//
// Commit-path status/durability ordering, and the per-transaction completion
// event published under it.
//
// `finalize_and_broadcast_block` publishes `TxStatus::Committed` into
// `tx_status_cache` -- the same cache `get_transaction_status` serves to
// clients. That publication once ran BEFORE `update_block_header`, so a
// failing durable header update returned `Err` while a client could already
// read `Committed` for a transaction whose finalized header never reached
// durable storage. The error path performs no rollback, so the false
// `Committed` was terminal for the life of the cache entry.
//
// M04.9(a) adds a second observable to the same seam:
// `KernelEvent::TransactionCommitted`, the exact per-transaction completion
// identity the public stream previously could not express. An event that says
// a transaction committed is a durability claim, so it inherits the same
// ordering obligation -- and, because it is PUSHED rather than polled, a
// premature one cannot be corrected by a later read.
//
// These tests pin the ordering at the seam that enforces it,
// `durably_update_header_then_publish_committed`, in both directions: the
// negative cases prove a durable failure publishes neither status nor event,
// and the positive cases prove the negative assertions are not vacuous -- they
// would actually catch a regression that restored publish-before-durability.
//
// This file is `include!`d into one shared test module, so it deliberately
// declares only the single name that is not already in scope and fully
// qualifies everything else.

use super::post_commit::durably_update_header_then_publish_committed;

type CommitPathReceiptMap = Arc<Mutex<lru::LruCache<ioi_types::app::TxHash, String>>>;
type CommitPathStatusCache =
    Arc<Mutex<lru::LruCache<String, crate::standard::orchestration::context::TxStatusEntry>>>;

/// One transaction whose hash is stable across every test here.
fn commit_path_transaction() -> ChainTransaction {
    ChainTransaction::System(Box::new(SystemTransaction {
        header: SignHeader {
            account_id: AccountId([71u8; 32]),
            nonce: 1,
            chain_id: ChainId(1),
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "wallet_network".into(),
            method: "commit_path_status_ordering@v1".into(),
            params: vec![7],
        },
        signature_proof: SignatureProof::default(),
    }))
}

/// A second, distinct transaction that commits at the SAME height.
///
/// Exists so same-height correlation can be tested: two transactions in one
/// block must yield two events distinguishable by transaction hash. A stream
/// that could only say "height 42 committed" would be indistinguishable from a
/// correct one here if only ever exercised with a single transaction.
fn second_commit_path_transaction() -> ChainTransaction {
    ChainTransaction::System(Box::new(SystemTransaction {
        header: SignHeader {
            account_id: AccountId([72u8; 32]),
            nonce: 4,
            chain_id: ChainId(1),
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "wallet_network".into(),
            method: "commit_path_status_ordering@v1".into(),
            params: vec![9],
        },
        signature_proof: SignatureProof::default(),
    }))
}

/// A subscribed broadcast sender, plus its receiver.
///
/// Subscribed BEFORE the seam runs, exactly as a client that must not miss a
/// fast completion has to subscribe before it submits. A receiver created
/// afterwards would see nothing regardless of what the seam did, which would
/// make every negative assertion below vacuous.
fn commit_path_event_channel() -> (
    tokio::sync::broadcast::Sender<ioi_types::app::KernelEvent>,
    tokio::sync::broadcast::Receiver<ioi_types::app::KernelEvent>,
) {
    let (sender, receiver) = tokio::sync::broadcast::channel(64);
    (sender, receiver)
}

/// Drains every `TransactionCommitted` currently buffered on `receiver`.
///
/// Non-blocking on purpose: the claim under test is what the seam has ALREADY
/// published by the time it returned, so a drain that waited could not
/// distinguish "published nothing" from "published late".
fn drained_transaction_committed_events(
    receiver: &mut tokio::sync::broadcast::Receiver<ioi_types::app::KernelEvent>,
) -> Vec<(String, u64, u64, u64)> {
    let mut events = Vec::new();
    while let Ok(event) = receiver.try_recv() {
        if let ioi_types::app::KernelEvent::TransactionCommitted {
            tx_hash,
            height,
            durable_commit_ms,
            published_at_ms,
        } = event
        {
            events.push((tx_hash, height, durable_commit_ms, published_at_ms));
        }
    }
    events
}

/// Empty caches plus the pre-commit status a polling client would already see.
///
/// Seeding `InMempool` matters: it means the negative test distinguishes "not
/// upgraded to Committed" from "absent", so a seam that silently dropped the
/// entry could not pass as a correct refusal.
async fn commit_path_caches(
    tx: &ChainTransaction,
) -> (CommitPathReceiptMap, CommitPathStatusCache, String) {
    let capacity = std::num::NonZeroUsize::new(16).expect("non-zero cache capacity");
    let receipt_map: CommitPathReceiptMap = Arc::new(Mutex::new(lru::LruCache::new(capacity)));
    let status_cache: CommitPathStatusCache = Arc::new(Mutex::new(lru::LruCache::new(capacity)));
    let tx_hash_hex = hex::encode(tx.hash().expect("transaction hashes"));

    status_cache.lock().await.put(
        tx_hash_hex.clone(),
        crate::standard::orchestration::context::TxStatusEntry {
            status: TxStatus::InMempool,
            error: None,
            block_height: None,
        },
    );

    (receipt_map, status_cache, tx_hash_hex)
}

/// Reads the status the cache would serve for `tx_hash_hex`, if any.
async fn observed_commit_path_status(
    cache: &CommitPathStatusCache,
    tx_hash_hex: &str,
) -> Option<(TxStatus, Option<u64>)> {
    let mut guard = cache.lock().await;
    guard
        .get(tx_hash_hex)
        .map(|entry| (entry.status, entry.block_height))
}

#[tokio::test]
async fn durable_header_update_failure_cannot_publish_committed() {
    let tx = commit_path_transaction();
    let (receipt_map, status_cache, tx_hash_hex) = commit_path_caches(&tx).await;
    let (events, mut event_rx) = commit_path_event_channel();
    let transactions = vec![tx];

    let mut durable_update_ran = false;
    let result = durably_update_header_then_publish_committed(
        || {
            durable_update_ran = true;
            async { Err(anyhow!("simulated durable block-header update failure")) }
        },
        &receipt_map,
        &status_cache,
        &events,
        &transactions,
        42,
    )
    .await;

    assert!(
        durable_update_ran,
        "the durable header update must actually be attempted; a seam that never ran it would \
         pass this test trivially while proving nothing about ordering"
    );
    let error = result.expect_err("a failing durable header update must propagate its error");
    assert!(
        error
            .to_string()
            .contains("simulated durable block-header update failure"),
        "the durable failure must propagate verbatim, got: {error}"
    );

    // The claim under test: nothing observable was upgraded to Committed.
    let (status, block_height) = observed_commit_path_status(&status_cache, &tx_hash_hex)
        .await
        .expect("the pre-commit entry must still be present, not dropped");
    assert_eq!(
        status,
        TxStatus::InMempool,
        "a transaction whose finalized block header was never durably updated must not be \
         observable as Committed"
    );
    assert_eq!(
        block_height, None,
        "no block height may be published for a block whose header never reached durable storage"
    );

    // The pushed observable, held to the same bar. A polled status can be
    // re-read and corrected; a delivered event cannot be recalled.
    assert!(
        drained_transaction_committed_events(&mut event_rx).is_empty(),
        "no completion event may be published for a block whose finalized header never reached \
         durable storage; an event is a durability claim a subscriber cannot re-check"
    );
}

#[tokio::test]
async fn successful_durable_header_update_publishes_committed() {
    let tx = commit_path_transaction();
    let (receipt_map, status_cache, tx_hash_hex) = commit_path_caches(&tx).await;
    let (events, _event_rx) = commit_path_event_channel();
    let transactions = vec![tx];

    durably_update_header_then_publish_committed(
        || async { Ok(()) },
        &receipt_map,
        &status_cache,
        &events,
        &transactions,
        42,
    )
    .await
    .expect("a successful durable header update must publish without error");

    let (status, block_height) = observed_commit_path_status(&status_cache, &tx_hash_hex)
        .await
        .expect("the committed entry must be present");
    assert_eq!(
        status,
        TxStatus::Committed,
        "a durably updated finalized header must publish Committed"
    );
    assert_eq!(
        block_height,
        Some(42),
        "the exact block height the commit path recorded must be published"
    );
}

// ---------------------------------------------------------------------------
// Per-transaction completion identity
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_durable_commit_publishes_exactly_one_event_naming_the_exact_transaction() {
    let tx = commit_path_transaction();
    let (receipt_map, status_cache, tx_hash_hex) = commit_path_caches(&tx).await;
    let (events, mut event_rx) = commit_path_event_channel();
    let transactions = vec![tx];

    durably_update_header_then_publish_committed(
        || async { Ok(()) },
        &receipt_map,
        &status_cache,
        &events,
        &transactions,
        42,
    )
    .await
    .expect("a successful durable header update must publish without error");

    let observed = drained_transaction_committed_events(&mut event_rx);
    assert_eq!(
        observed.len(),
        1,
        "exactly one completion event per committed transaction"
    );
    let (event_tx_hash, event_height, durable_commit_ms, published_at_ms) = observed[0].clone();
    assert_eq!(
        event_tx_hash, tx_hash_hex,
        "the event must name the EXACT transaction hash the status cache is keyed under; a \
         different spelling would make the event uncorrelatable with the submission that \
         produced it"
    );
    assert_eq!(
        event_height, 42,
        "the event must carry the exact committing height, never a tip"
    );
    assert!(
        durable_commit_ms > 0 && published_at_ms > 0,
        "both server timestamps must be real observations"
    );
    assert!(
        published_at_ms >= durable_commit_ms,
        "publication cannot precede the durability it asserts; got published_at_ms={published_at_ms} \
         durable_commit_ms={durable_commit_ms}"
    );
}

#[tokio::test]
async fn the_event_carries_the_hash_the_submitting_client_was_given() {
    // `receipt_map` holds the hex the submit RPC returned. The event must use
    // THAT spelling, not a locally recomputed one, or a client holding a
    // submission hash could not match its own completion.
    let tx = commit_path_transaction();
    let (receipt_map, status_cache, _derived_hash) = commit_path_caches(&tx).await;
    let (events, mut event_rx) = commit_path_event_channel();
    let submitted_hash = "ffee".repeat(16);
    receipt_map.lock().await.put(
        tx.hash().expect("transaction hashes"),
        submitted_hash.clone(),
    );
    let transactions = vec![tx];

    durably_update_header_then_publish_committed(
        || async { Ok(()) },
        &receipt_map,
        &status_cache,
        &events,
        &transactions,
        7,
    )
    .await
    .expect("a successful durable header update must publish without error");

    let observed = drained_transaction_committed_events(&mut event_rx);
    assert_eq!(observed.len(), 1);
    assert_eq!(
        observed[0].0, submitted_hash,
        "the event must carry the client-visible submission hash"
    );
    // Not vacuous: the status cache is keyed under the same string, so a
    // subscriber can follow the event with an exact status read.
    let (status, height) = observed_commit_path_status(&status_cache, &submitted_hash)
        .await
        .expect("status must be published under the same key the event names");
    assert_eq!(status, TxStatus::Committed);
    assert_eq!(height, Some(7));
}

#[tokio::test]
async fn two_transactions_at_one_height_produce_two_distinguishable_events() {
    // The defect this rules out: correlating completion by HEIGHT. Both
    // transactions below commit at height 42, so a height-keyed notification
    // could not tell a client which of its submissions completed.
    let first = commit_path_transaction();
    let second = second_commit_path_transaction();
    let capacity = std::num::NonZeroUsize::new(16).expect("non-zero cache capacity");
    let receipt_map: CommitPathReceiptMap = Arc::new(Mutex::new(lru::LruCache::new(capacity)));
    let status_cache: CommitPathStatusCache = Arc::new(Mutex::new(lru::LruCache::new(capacity)));
    let (events, mut event_rx) = commit_path_event_channel();
    let first_hash = hex::encode(first.hash().expect("transaction hashes"));
    let second_hash = hex::encode(second.hash().expect("transaction hashes"));
    assert_ne!(first_hash, second_hash, "the two fixtures must be distinct");
    let transactions = vec![first, second];

    durably_update_header_then_publish_committed(
        || async { Ok(()) },
        &receipt_map,
        &status_cache,
        &events,
        &transactions,
        42,
    )
    .await
    .expect("a successful durable header update must publish without error");

    let observed = drained_transaction_committed_events(&mut event_rx);
    assert_eq!(
        observed.len(),
        2,
        "one event per transaction, not per block"
    );
    assert_eq!(
        observed
            .iter()
            .map(|entry| entry.0.clone())
            .collect::<Vec<_>>(),
        vec![first_hash, second_hash],
        "each event names its own transaction, in block order"
    );
    for (_, height, _, _) in &observed {
        assert_eq!(*height, 42, "both committed at the same height");
    }
}

#[tokio::test]
async fn a_re_finalized_height_republishes_rather_than_inventing_a_new_completion() {
    // Running the seam twice for the same block -- what a replayed or
    // re-finalized height does -- must republish the SAME identity, not a
    // second, different completion. A client that already matched the exact
    // event takes the first and ignores the rest; this pins that the rest are
    // genuinely identical in identity, so ignoring them loses nothing.
    let tx = commit_path_transaction();
    let (receipt_map, status_cache, tx_hash_hex) = commit_path_caches(&tx).await;
    let (events, mut event_rx) = commit_path_event_channel();
    let transactions = vec![tx];

    for _ in 0..2 {
        durably_update_header_then_publish_committed(
            || async { Ok(()) },
            &receipt_map,
            &status_cache,
            &events,
            &transactions,
            42,
        )
        .await
        .expect("a successful durable header update must publish without error");
    }

    let observed = drained_transaction_committed_events(&mut event_rx);
    assert_eq!(observed.len(), 2, "each invocation published once");
    assert_eq!(observed[0].0, tx_hash_hex);
    assert_eq!(observed[1].0, tx_hash_hex);
    assert_eq!(observed[0].1, 42);
    assert_eq!(
        observed[1].1, 42,
        "a duplicate must not report a different height; that would be two completions, not one \
         completion published twice"
    );
}

#[tokio::test]
async fn an_empty_block_publishes_no_completion_event() {
    // A block with no transactions completes no transaction. Emitting a
    // height-shaped event here would give a waiting client something to
    // mistake for its own completion.
    let (receipt_map, status_cache, _hash) = commit_path_caches(&commit_path_transaction()).await;
    let (events, mut event_rx) = commit_path_event_channel();

    durably_update_header_then_publish_committed(
        || async { Ok(()) },
        &receipt_map,
        &status_cache,
        &events,
        &[],
        42,
    )
    .await
    .expect("an empty block still commits");

    assert!(drained_transaction_committed_events(&mut event_rx).is_empty());
}

// ---------------------------------------------------------------------------
// Structural: no early publication path exists at the CALL SITE
// ---------------------------------------------------------------------------
//
// The two tests above bind the helper. That is necessary but not sufficient:
// the defect this cut repaired lived in `finalize_and_broadcast_block`, and a
// regression that re-adds an early publication call THERE would leave both of
// them green.
//
// The primary defence is structural rather than assertive -- the publishing
// function is nested inside `durably_update_header_then_publish_committed`, so
// no other caller has a name to reach. The check below is the backstop that
// notices if someone hoists it back out to module scope, which is the single
// edit that re-opens the defect class.

/// The commit-path source this invariant lives in.
const POST_COMMIT_SOURCE: &str = include_str!("../post_commit.rs");

#[test]
fn committed_publication_has_no_module_level_definition() {
    // A module-level `async fn publish_committed_tx_statuses` is reachable from
    // every sibling in the file, including `finalize_and_broadcast_block`. A
    // nested one is reachable only from its parent. The difference is the whole
    // guarantee, so it is asserted on the source rather than trusted.
    let module_level_definitions = POST_COMMIT_SOURCE
        .lines()
        .filter(|line| {
            line.starts_with("async fn publish_committed_tx_statuses")
                || line.starts_with("pub(super) async fn publish_committed_tx_statuses")
                || line.starts_with("pub(crate) async fn publish_committed_tx_statuses")
                || line.starts_with("pub async fn publish_committed_tx_statuses")
        })
        .count();
    assert_eq!(
        module_level_definitions, 0,
        "publish_committed_tx_statuses must stay NESTED inside \
         durably_update_header_then_publish_committed; a module-level definition gives \
         finalize_and_broadcast_block a name it can call before the durable header update, \
         which is exactly the defect this cut repaired"
    );

    // Not vacuous: the nested definition must actually be present, indented
    // inside its parent. If the function were deleted outright the assertion
    // above would also pass, and nothing would publish Committed at all.
    let nested_definitions = POST_COMMIT_SOURCE
        .lines()
        .filter(|line| line.starts_with("    async fn publish_committed_tx_statuses"))
        .count();
    assert_eq!(
        nested_definitions, 1,
        "the nested publisher must exist exactly once inside its parent"
    );
}

#[test]
fn finalize_and_broadcast_block_reaches_committed_only_through_the_durable_seam() {
    // Every mention of the publisher in this file must be inside the seam.
    // Concretely: the ONLY call site is the one line inside
    // `durably_update_header_then_publish_committed`, and the durable update it
    // guards is awaited before it.
    let call_sites = POST_COMMIT_SOURCE
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with("publish_committed_tx_statuses(")
        })
        .count();
    assert_eq!(
        call_sites, 1,
        "exactly one call site may exist, inside the durable seam"
    );

    let seam_start = POST_COMMIT_SOURCE
        .find("pub(super) async fn durably_update_header_then_publish_committed")
        .expect("the durable seam must exist");
    let seam_body = &POST_COMMIT_SOURCE[seam_start..];
    let update_at = seam_body
        .find("durable_header_update().await?;")
        .expect("the seam must await the durable header update");
    let publish_at = seam_body
        .find("publish_committed_tx_statuses(receipt_map,")
        .expect("the seam must call the publisher");
    assert!(
        update_at < publish_at,
        "the durable header update must be awaited BEFORE Committed is published; \
         reversing these two lines restores the original defect"
    );
}

#[test]
fn the_completion_event_has_no_publication_path_outside_the_durable_seam() {
    // Same defence, extended to the pushed observable. `TransactionCommitted`
    // asserts durability to a subscriber who cannot re-check it, so the set of
    // names able to construct one must be exactly the set inside this seam.
    let module_level_definitions = POST_COMMIT_SOURCE
        .lines()
        .filter(|line| {
            line.starts_with("fn publish_transaction_committed_events")
                || line.starts_with("async fn publish_transaction_committed_events")
                || line.starts_with("pub(super) fn publish_transaction_committed_events")
                || line.starts_with("pub(crate) fn publish_transaction_committed_events")
                || line.starts_with("pub fn publish_transaction_committed_events")
        })
        .count();
    assert_eq!(
        module_level_definitions, 0,
        "publish_transaction_committed_events must stay NESTED inside \
         durably_update_header_then_publish_committed; a module-level definition gives \
         finalize_and_broadcast_block a name it could call before the durable header update"
    );
    let nested_definitions = POST_COMMIT_SOURCE
        .lines()
        .filter(|line| line.starts_with("    fn publish_transaction_committed_events"))
        .count();
    assert_eq!(
        nested_definitions, 1,
        "the nested event publisher must exist exactly once inside its parent"
    );

    // The ONLY construction site for the event is inside that nested
    // publisher. A second `KernelEvent::TransactionCommitted { ... }` anywhere
    // in this file would be a durability claim made outside the seam.
    let construction_sites = POST_COMMIT_SOURCE
        .matches("KernelEvent::TransactionCommitted {")
        .count();
    assert_eq!(
        construction_sites, 1,
        "exactly one place may construct the completion event"
    );

    let call_sites = POST_COMMIT_SOURCE
        .lines()
        .filter(|line| {
            line.trim_start()
                .starts_with("publish_transaction_committed_events(")
        })
        .count();
    assert_eq!(
        call_sites, 1,
        "exactly one call site may exist, inside the durable seam"
    );
}

#[test]
fn the_completion_event_is_published_after_durability_and_after_the_status() {
    // The ordering, read off the source rather than trusted, in BOTH hops:
    //
    //   durable header update  ->  Committed status  ->  completion event
    //
    // The second hop matters on its own. A subscriber's natural reaction to
    // the event is to read `get_transaction_status`; publishing the event
    // first would let that read race, and lose to, its own notification.
    let seam_start = POST_COMMIT_SOURCE
        .find("pub(super) async fn durably_update_header_then_publish_committed")
        .expect("the durable seam must exist");
    let seam_body = &POST_COMMIT_SOURCE[seam_start..];
    let update_at = seam_body
        .find("durable_header_update().await?;")
        .expect("the seam must await the durable header update");
    let status_at = seam_body
        .find("publish_committed_tx_statuses(receipt_map,")
        .expect("the seam must call the status publisher");
    // Matched against the CALL's argument list (`event_broadcaster,`) rather
    // than the nested definition's (`event_broadcaster:`), which appears
    // earlier in the same body and would otherwise be found instead.
    let event_at = seam_body
        .find("publish_transaction_committed_events(\n        event_broadcaster,\n")
        .expect("the seam must call the event publisher");
    assert!(
        update_at < status_at,
        "durability must precede the published status"
    );
    assert!(
        status_at < event_at,
        "the published status must precede the published event"
    );

    // The event's own timestamps are sampled on the same side of the durable
    // update: an event whose `durable_commit_ms` were read before the update
    // would report a durability instant the node had not reached.
    let durable_sample_at = seam_body
        .find("let durable_commit_ms = server_wall_clock_ms();")
        .expect("the seam must sample the durable-commit instant");
    assert!(
        update_at < durable_sample_at,
        "durable_commit_ms must be sampled AFTER the durable header update returns"
    );
}
