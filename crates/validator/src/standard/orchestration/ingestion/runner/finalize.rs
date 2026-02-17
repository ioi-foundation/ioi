use crate::metrics::rpc_metrics as metrics;
use crate::standard::orchestration::context::TxStatusEntry;
use crate::standard::orchestration::mempool::{AddResult, Mempool};
use ioi_api::chain::WorkloadClientApi;
use ioi_ipc::public::TxStatus;
use ioi_networking::libp2p::SwarmCommand;
use ioi_types::app::ChainTransaction;
use ioi_types::app::StateAnchor;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::standard::orchestration::ingestion::types::ProcessedTx;
use ioi_client::WorkloadClient;

pub(crate) async fn finalize_valid_transactions(
    workload_client: &Arc<WorkloadClient>,
    tx_pool: &Arc<Mempool>,
    swarm_sender: &mpsc::Sender<SwarmCommand>,
    status_cache: &Arc<tokio::sync::Mutex<lru::LruCache<String, TxStatusEntry>>>,
    receipt_map: &Arc<tokio::sync::Mutex<lru::LruCache<ioi_types::app::TxHash, String>>>,
    nonce_cache: &mut lru::LruCache<ioi_types::app::AccountId, u64>,
    semantically_valid_indices: &[usize],
    processed_batch: &[ProcessedTx],
    anchor: StateAnchor,
    expected_ts: u64,
) -> bool {
    let txs_to_check: Vec<ChainTransaction> = semantically_valid_indices
        .iter()
        .map(|&i| processed_batch[i].tx.clone())
        .collect();

    let check_results = match workload_client
        .check_transactions_at(anchor, expected_ts, txs_to_check)
        .await
    {
        Ok(res) => res,
        Err(e) => {
            tracing::error!(target: "ingestion", "Validation IPC failed: {}", e);
            return false;
        }
    };

    let mut status_guard = status_cache.lock().await;
    let mut receipt_guard = receipt_map.lock().await;
    let mut accepted_count = 0;

    for (res_idx, result) in check_results.into_iter().enumerate() {
        let original_idx = semantically_valid_indices[res_idx];
        let p_tx = &processed_batch[original_idx];

        let is_approval_error = if let Err(e) = &result {
            e.contains("Approval required for request")
        } else {
            false
        };

        let validation_ok = result.is_ok() || is_approval_error;

        if validation_ok {
            let tx_info = p_tx.account_id.map(|acc| (acc, p_tx.nonce.unwrap()));
            let committed_nonce = p_tx
                .account_id
                .and_then(|acc| nonce_cache.get(&acc).copied())
                .unwrap_or(0);

            match tx_pool.add(
                p_tx.tx.clone(),
                p_tx.canonical_hash,
                tx_info,
                committed_nonce,
            ) {
                AddResult::Ready | AddResult::Future => {
                    accepted_count += 1;
                    status_guard.put(
                        p_tx.receipt_hash_hex.clone(),
                        TxStatusEntry {
                            status: TxStatus::InMempool,
                            error: None,
                            block_height: None,
                        },
                    );
                    receipt_guard.put(p_tx.canonical_hash, p_tx.receipt_hash_hex.clone());

                    tracing::info!(
                        target: "ingestion",
                        "Added transaction to mempool: {}",
                        p_tx.receipt_hash_hex
                    );

                    let _ = swarm_sender
                        .send(SwarmCommand::PublishTransaction(p_tx.raw_bytes.clone()))
                        .await;
                }
                AddResult::Rejected(r) => {
                    tracing::warn!(
                        target: "ingestion",
                        "Mempool rejected transaction {}: {}",
                        p_tx.receipt_hash_hex,
                        r
                    );
                    status_guard.put(
                        p_tx.receipt_hash_hex.clone(),
                        TxStatusEntry {
                            status: TxStatus::Rejected,
                            error: Some(format!("Mempool: {}", r)),
                            block_height: None,
                        },
                    );
                }
            }
        } else {
            let e = result.unwrap_err();
            tracing::warn!(
                target: "ingestion",
                "Validation failed for transaction {}: {}",
                p_tx.receipt_hash_hex,
                e
            );
            status_guard.put(
                p_tx.receipt_hash_hex.clone(),
                TxStatusEntry {
                    status: TxStatus::Rejected,
                    error: Some(format!("Validation: {}", e)),
                    block_height: None,
                },
            );
        }
    }

    metrics().set_mempool_size(tx_pool.len() as f64);
    accepted_count > 0
}
