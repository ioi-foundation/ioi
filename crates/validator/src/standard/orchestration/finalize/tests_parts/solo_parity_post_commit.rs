// Path: crates/validator/src/standard/orchestration/finalize/tests_parts/solo_parity_post_commit.rs
//
// Commit-path status/durability ordering.
//
// `finalize_and_broadcast_block` publishes `TxStatus::Committed` into
// `tx_status_cache` -- the same cache `get_transaction_status` serves to
// clients. That publication once ran BEFORE `update_block_header`, so a
// failing durable header update returned `Err` while a client could already
// read `Committed` for a transaction whose finalized header never reached
// durable storage. The error path performs no rollback, so the false
// `Committed` was terminal for the life of the cache entry.
//
// These tests pin the repaired ordering at the seam that enforces it,
// `durably_update_header_then_publish_committed`, in both directions: the
// negative case proves a durable failure publishes nothing, and the positive
// case proves the negative assertion is not vacuous -- it would actually catch
// a regression that restored publish-before-durability.
//
// This file is `include!`d into one shared test module, so it deliberately
// declares only the single name that is not already in scope and fully
// qualifies everything else.

use super::post_commit::durably_update_header_then_publish_committed;

type CommitPathReceiptMap = Arc<Mutex<lru::LruCache<ioi_types::app::TxHash, String>>>;
type CommitPathStatusCache =
    Arc<Mutex<lru::LruCache<String, crate::standard::orchestration::context::TxStatusEntry>>>;

/// One transaction whose hash is stable across both tests.
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
    let transactions = vec![tx];

    let mut durable_update_ran = false;
    let result = durably_update_header_then_publish_committed(
        || {
            durable_update_ran = true;
            async { Err(anyhow!("simulated durable block-header update failure")) }
        },
        &receipt_map,
        &status_cache,
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
}

#[tokio::test]
async fn successful_durable_header_update_publishes_committed() {
    let tx = commit_path_transaction();
    let (receipt_map, status_cache, tx_hash_hex) = commit_path_caches(&tx).await;
    let transactions = vec![tx];

    durably_update_header_then_publish_committed(
        || async { Ok(()) },
        &receipt_map,
        &status_cache,
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
