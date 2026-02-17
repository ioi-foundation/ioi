use crate::standard::orchestration::context::TxStatusEntry;
use crate::standard::orchestration::mempool::Mempool;
use futures::stream::{self, StreamExt};
use ioi_api::chain::WorkloadClientApi;
use ioi_api::commitment::CommitmentScheme;
use ioi_api::transaction::TransactionModel;
use ioi_client::WorkloadClient;
use ioi_tx::unified::UnifiedTransactionModel;
use ioi_types::app::{compute_next_timestamp, AccountId, ChainTransaction, StateRoot, TxHash};
use ioi_types::codec;
use ioi_types::keys::ACCOUNT_NONCE_PREFIX;
use parity_scale_codec::{Decode, Encode};
use serde::Serialize;
use std::collections::HashSet;
use std::fmt::Debug;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

use crate::standard::orchestration::ingestion::types::{ChainTipInfo, ProcessedTx, TimingCache};

pub(crate) struct CollectedBatch {
    pub processed_batch: Vec<ProcessedTx>,
    pub expected_ts: u64,
    pub anchor: ioi_types::app::StateAnchor,
}

pub(crate) async fn collect_next_batch<CS>(
    first_item: (TxHash, Vec<u8>),
    rx: &mut mpsc::Receiver<(TxHash, Vec<u8>)>,
    batch_size: usize,
    batch_timeout_ms: u64,
    tx_pool: &std::sync::Arc<Mempool>,
    tx_model: &std::sync::Arc<UnifiedTransactionModel<CS>>,
    tip_watcher: &watch::Receiver<ChainTipInfo>,
    status_cache: &std::sync::Arc<tokio::sync::Mutex<lru::LruCache<String, TxStatusEntry>>>,
    workload_client: &std::sync::Arc<WorkloadClient>,
    nonce_cache: &mut lru::LruCache<AccountId, u64>,
    timing_cache: &mut Option<TimingCache>,
) -> Option<CollectedBatch>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
{
    let mut batch = Vec::with_capacity(batch_size);
    let mut processed_batch = Vec::with_capacity(batch_size);
    batch.push(first_item);
    let collect_start = Instant::now();
    let timeout = Duration::from_millis(batch_timeout_ms);

    while batch.len() < batch_size {
        let remaining = timeout.saturating_sub(collect_start.elapsed());
        if remaining.is_zero() {
            break;
        }

        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(item)) => batch.push(item),
            _ => break,
        }
    }

    let mut accounts_needing_nonce = HashSet::new();
    for (receipt_hash, tx_bytes) in batch.drain(..) {
        let receipt_hash_hex = hex::encode(receipt_hash);
        match tx_model.deserialize_transaction(&tx_bytes) {
            Ok(tx) => match tx.hash() {
                Ok(canonical_hash) => {
                    let (account_id, nonce) = match &tx {
                        ChainTransaction::System(s) => {
                            (Some(s.header.account_id), Some(s.header.nonce))
                        }
                        ChainTransaction::Settlement(s) => {
                            (Some(s.header.account_id), Some(s.header.nonce))
                        }
                        ChainTransaction::Application(a) => match a {
                            ioi_types::app::ApplicationTransaction::DeployContract {
                                header,
                                ..
                            }
                            | ioi_types::app::ApplicationTransaction::CallContract {
                                header, ..
                            } => (Some(header.account_id), Some(header.nonce)),
                            _ => (None, None),
                        },
                        _ => (None, None),
                    };

                    if let Some(acc) = account_id {
                        if !tx_pool.contains_account(&acc) && !nonce_cache.contains(&acc) {
                            accounts_needing_nonce.insert(acc);
                        }
                    }

                    processed_batch.push(ProcessedTx {
                        tx,
                        canonical_hash,
                        raw_bytes: tx_bytes,
                        receipt_hash_hex,
                        account_id,
                        nonce,
                    });
                }
                Err(e) => {
                    tracing::warn!(target: "ingestion", "Canonical hashing failed: {}", e);
                    status_cache.lock().await.put(
                        receipt_hash_hex,
                        TxStatusEntry {
                            status: ioi_ipc::public::TxStatus::Rejected,
                            error: Some(format!("Canonical hashing failed: {}", e)),
                            block_height: None,
                        },
                    );
                }
            },
            Err(e) => {
                tracing::warn!(target: "ingestion", "Deserialization failed: {}", e);
                status_cache.lock().await.put(
                    receipt_hash_hex,
                    TxStatusEntry {
                        status: ioi_ipc::public::TxStatus::Rejected,
                        error: Some(format!("Deserialization failed: {}", e)),
                        block_height: None,
                    },
                );
            }
        }
    }

    if processed_batch.is_empty() {
        return None;
    }

    let tip = tip_watcher.borrow().clone();
    let root_struct = StateRoot(if tip.height > 0 {
        tip.state_root.clone()
    } else {
        tip.genesis_root.clone()
    });

    if !accounts_needing_nonce.is_empty() {
        let fetch_results = stream::iter(accounts_needing_nonce)
            .map(|acc| {
                let client = workload_client.clone();
                let root = root_struct.clone();
                async move {
                    let key = [ACCOUNT_NONCE_PREFIX, acc.as_ref()].concat();
                    let nonce = match client.query_state_at(root, &key).await {
                        Ok(resp) => resp
                            .membership
                            .into_option()
                            .map(|b| codec::from_bytes_canonical::<u64>(&b).unwrap_or(0))
                            .unwrap_or(0),
                        _ => 0,
                    };
                    (acc, nonce)
                }
            })
            .buffer_unordered(50)
            .collect::<Vec<_>>()
            .await;

        for (acc, nonce) in fetch_results {
            nonce_cache.put(acc, nonce);
        }
    }

    if timing_cache
        .as_ref()
        .map_or(true, |c| c.last_fetched.elapsed() > Duration::from_secs(2))
    {
        let params_key = ioi_types::keys::BLOCK_TIMING_PARAMS_KEY;
        let runtime_key = ioi_types::keys::BLOCK_TIMING_RUNTIME_KEY;
        if let (Ok(p_resp), Ok(r_resp)) = tokio::join!(
            workload_client.query_state_at(root_struct.clone(), params_key),
            workload_client.query_state_at(root_struct.clone(), runtime_key)
        ) {
            let params = p_resp
                .membership
                .into_option()
                .and_then(|v| codec::from_bytes_canonical(&v).ok())
                .unwrap_or_default();
            let runtime = r_resp
                .membership
                .into_option()
                .and_then(|v| codec::from_bytes_canonical(&v).ok())
                .unwrap_or_default();
            *timing_cache = Some(TimingCache {
                params,
                runtime,
                last_fetched: Instant::now(),
            });
        }
    }

    let expected_ts = timing_cache
        .as_ref()
        .and_then(|c| {
            compute_next_timestamp(
                &c.params,
                &c.runtime,
                tip.height,
                tip.timestamp,
                tip.gas_used,
            )
        })
        .unwrap_or(0);

    let anchor = root_struct.to_anchor().unwrap_or_default();

    Some(CollectedBatch {
        processed_batch,
        expected_ts,
        anchor,
    })
}
