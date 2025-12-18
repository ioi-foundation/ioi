// Path: crates/validator/src/standard/orchestration/ingestion.rs

use crate::metrics::rpc_metrics as metrics;
use crate::standard::orchestration::context::{TxStatusEntry};
use crate::standard::orchestration::mempool::{AddResult, Mempool};
use ioi_api::chain::WorkloadClientApi;
use ioi_api::commitment::CommitmentScheme;
use ioi_api::transaction::TransactionModel;
use ioi_client::WorkloadClient;
use ioi_ipc::public::{TxStatus};
use ioi_networking::libp2p::SwarmCommand;
use ioi_tx::unified::UnifiedTransactionModel;
use ioi_types::app::{
    compute_next_timestamp, AccountId, BlockTimingParams, BlockTimingRuntime, ChainTransaction,
    StateAnchor, StateRoot, TxHash,
};
use ioi_types::{codec};
use ioi_types::keys::ACCOUNT_NONCE_PREFIX;
use futures::stream::{self, StreamExt};
use serde::Serialize;
use std::collections::{HashSet, HashMap};
use std::fmt::Debug;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch, Mutex};
use tracing::{debug, error, info, warn};

/// Configuration for the ingestion worker.
#[derive(Debug, Clone)]
pub struct IngestionConfig {
    /// Maximum number of transactions to process in one batch.
    pub batch_size: usize,
    /// Maximum time to wait for a batch to fill before processing.
    pub batch_timeout_ms: u64,
}

impl Default for IngestionConfig {
    fn default() -> Self {
        Self {
            batch_size: 256,
            batch_timeout_ms: 10,
        }
    }
}

/// A simplified view of the chain tip needed for ante checks.
#[derive(Clone, Debug)]
pub struct ChainTipInfo {
    pub height: u64,
    pub timestamp: u64,
    pub gas_used: u64,
    pub state_root: Vec<u8>,
    pub genesis_root: Vec<u8>,
}

/// Helper struct to keep related transaction data aligned during batch processing.
struct ProcessedTx {
    tx: ChainTransaction,
    canonical_hash: TxHash,
    raw_bytes: Vec<u8>,
    receipt_hash_hex: String,
    account_id: Option<AccountId>,
    nonce: Option<u64>,
}

/// Cache for block timing parameters to avoid constant fetching from state.
struct TimingCache {
    params: BlockTimingParams,
    runtime: BlockTimingRuntime,
    last_fetched: Instant,
}

/// The main loop for the ingestion worker.
/// Decouples RPC receipt from heavy-lifting validation and mempool management.
pub async fn run_ingestion_worker<CS>(
    mut rx: mpsc::Receiver<(TxHash, Vec<u8>)>,
    workload_client: Arc<WorkloadClient>,
    tx_pool: Arc<Mempool>,
    swarm_sender: mpsc::Sender<SwarmCommand>,
    consensus_kick_tx: mpsc::UnboundedSender<()>,
    tx_model: Arc<UnifiedTransactionModel<CS>>,
    mut tip_watcher: watch::Receiver<ChainTipInfo>,
    status_cache: Arc<Mutex<lru::LruCache<String, TxStatusEntry>>>,
    receipt_map: Arc<Mutex<lru::LruCache<TxHash, String>>>,
    config: IngestionConfig,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
{
    info!(
        "Transaction Ingestion Worker started (Batch Size: {}, Timeout: {}ms)",
        config.batch_size, config.batch_timeout_ms
    );

    let mut batch = Vec::with_capacity(config.batch_size);
    let mut processed_batch = Vec::with_capacity(config.batch_size);
    let mut timing_cache: Option<TimingCache> = None;
    
    // Local cache of committed nonces to avoid repeated DB hits for the same account in a burst.
    let mut nonce_cache: lru::LruCache<AccountId, u64> =
        lru::LruCache::new(std::num::NonZeroUsize::new(10000).unwrap());

    loop {
        // --- 1. Collect Batch ---
        let first_item = match rx.recv().await {
            Some(item) => item,
            None => break, // Channel closed
        };

        batch.push(first_item);
        let collect_start = Instant::now();
        let timeout = Duration::from_millis(config.batch_timeout_ms);

        while batch.len() < config.batch_size {
            let remaining = timeout.saturating_sub(collect_start.elapsed());
            if remaining.is_zero() { break; }

            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Some(item)) => batch.push(item),
                _ => break,
            }
        }

        // --- 2. Stateless Processing (Deserialize & Hash) ---
        processed_batch.clear();
        let mut accounts_needing_nonce = HashSet::new();

        for (receipt_hash, tx_bytes) in batch.drain(..) {
            let receipt_hash_hex = hex::encode(receipt_hash);
            match tx_model.deserialize_transaction(&tx_bytes) {
                Ok(tx) => {
                    match tx.hash() {
                        Ok(canonical_hash) => {
                            let (account_id, nonce) = match &tx {
                                ChainTransaction::System(s) => (Some(s.header.account_id), Some(s.header.nonce)),
                                ChainTransaction::Application(a) => match a {
                                    ioi_types::app::ApplicationTransaction::DeployContract { header, .. } |
                                    ioi_types::app::ApplicationTransaction::CallContract { header, .. } => {
                                        (Some(header.account_id), Some(header.nonce))
                                    }
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
                            status_cache.lock().await.put(receipt_hash_hex, TxStatusEntry {
                                status: TxStatus::Rejected,
                                error: Some(format!("Canonical hashing failed: {}", e)),
                                block_height: None,
                            });
                        }
                    }
                }
                Err(e) => {
                    status_cache.lock().await.put(receipt_hash_hex, TxStatusEntry {
                        status: TxStatus::Rejected,
                        error: Some(format!("Deserialization failed: {}", e)),
                        block_height: None,
                    });
                }
            }
        }

        if processed_batch.is_empty() { continue; }

        // --- 3. Context & Nonce Resolution ---
        let tip = tip_watcher.borrow().clone();
        let root_struct = StateRoot(if tip.height > 0 { tip.state_root.clone() } else { tip.genesis_root.clone() });

        if !accounts_needing_nonce.is_empty() {
            let fetch_results = stream::iter(accounts_needing_nonce)
                .map(|acc| {
                    let client = workload_client.clone();
                    let root = root_struct.clone();
                    async move {
                        let key = [ACCOUNT_NONCE_PREFIX, acc.as_ref()].concat();
                        let nonce = match client.query_state_at(root, &key).await {
                            Ok(resp) => resp.membership.into_option().map(|b| codec::from_bytes_canonical::<u64>(&b).unwrap_or(0)).unwrap_or(0),
                            _ => 0,
                        };
                        (acc, nonce)
                    }
                })
                .buffer_unordered(50)
                .collect::<Vec<_>>().await;

            for (acc, nonce) in fetch_results {
                nonce_cache.put(acc, nonce);
            }
        }

        // Timing Parameter Refresh (every 2s)
        if timing_cache.as_ref().map_or(true, |c| c.last_fetched.elapsed() > Duration::from_secs(2)) {
            let params_key = ioi_types::keys::BLOCK_TIMING_PARAMS_KEY;
            let runtime_key = ioi_types::keys::BLOCK_TIMING_RUNTIME_KEY;
            if let (Ok(p_resp), Ok(r_resp)) = tokio::join!(
                workload_client.query_state_at(root_struct.clone(), params_key),
                workload_client.query_state_at(root_struct.clone(), runtime_key)
            ) {
                let params = p_resp.membership.into_option().and_then(|v| codec::from_bytes_canonical(&v).ok()).unwrap_or_default();
                let runtime = r_resp.membership.into_option().and_then(|v| codec::from_bytes_canonical(&v).ok()).unwrap_or_default();
                timing_cache = Some(TimingCache { params, runtime, last_fetched: Instant::now() });
            }
        }

        let expected_ts = timing_cache.as_ref().and_then(|c| {
            compute_next_timestamp(&c.params, &c.runtime, tip.height, tip.timestamp, tip.gas_used)
        }).unwrap_or(0);

        let anchor = root_struct.to_anchor().unwrap_or_default();
        let txs_to_check: Vec<ChainTransaction> = processed_batch.iter().map(|p| p.tx.clone()).collect();

        // --- 4. Workload Validation ---
        let check_results = match workload_client.check_transactions_at(anchor, expected_ts, txs_to_check).await {
            Ok(res) => res,
            Err(e) => {
                error!(target: "ingestion", "Validation IPC failed: {}", e);
                continue;
            }
        };

        // --- 5. Mempool & Status Finalization ---
        let mut status_guard = status_cache.lock().await;
        let mut receipt_guard = receipt_map.lock().await;
        let mut accepted_count = 0;

        for (idx, result) in check_results.into_iter().enumerate() {
            let p_tx = &processed_batch[idx];
            match result {
                Ok(_) => {
                    let tx_info = p_tx.account_id.map(|acc| (acc, p_tx.nonce.unwrap()));
                    let committed_nonce = p_tx.account_id.and_then(|acc| nonce_cache.get(&acc).copied()).unwrap_or(0);
                    
                    match tx_pool.add(p_tx.tx.clone(), p_tx.canonical_hash, tx_info, committed_nonce) {
                        AddResult::Ready | AddResult::Future => {
                            accepted_count += 1;
                            status_guard.put(p_tx.receipt_hash_hex.clone(), TxStatusEntry {
                                status: TxStatus::InMempool,
                                error: None,
                                block_height: None,
                            });
                            receipt_guard.put(p_tx.canonical_hash, p_tx.receipt_hash_hex.clone());
                            let _ = swarm_sender.send(SwarmCommand::PublishTransaction(p_tx.raw_bytes.clone())).await;
                        }
                        AddResult::Rejected(r) => {
                            status_guard.put(p_tx.receipt_hash_hex.clone(), TxStatusEntry {
                                status: TxStatus::Rejected,
                                error: Some(format!("Mempool: {}", r)),
                                block_height: None,
                            });
                        }
                    }
                }
                Err(e) => {
                    status_guard.put(p_tx.receipt_hash_hex.clone(), TxStatusEntry {
                        status: TxStatus::Rejected,
                        error: Some(format!("Validation: {}", e)),
                        block_height: None,
                    });
                }
            }
        }
        
        if accepted_count > 0 {
            let _ = consensus_kick_tx.send(());
        }
        metrics().set_mempool_size(tx_pool.len() as f64);
    }
}