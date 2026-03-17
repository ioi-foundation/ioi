use crate::standard::orchestration::context::TxStatusEntry;
use crate::standard::orchestration::ingestion::types::{
    ChainTipInfo, IngestionConfig, TimingCache,
};
use crate::standard::orchestration::mempool::Mempool;
use ioi_api::commitment::CommitmentScheme;
use ioi_api::vm::drivers::os::OsDriver;
use ioi_api::vm::inference::LocalSafetyModel;
use ioi_client::WorkloadClient;
use ioi_networking::libp2p::SwarmCommand;
use ioi_tx::unified::UnifiedTransactionModel;
use libp2p::PeerId;
use parity_scale_codec::{Decode, Encode};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{fmt::Debug, sync::Arc, time::Duration};
use tokio::sync::{mpsc, watch, Mutex};
use tracing::info;

#[path = "runner/collect.rs"]
mod collect;
#[path = "runner/finalize.rs"]
mod finalize;
#[path = "runner/semantic/mod.rs"]
mod semantic;

use collect::{collect_next_batch, CollectedBatch};
use finalize::finalize_valid_transactions;

/// The main loop for the ingestion worker.
pub async fn run_ingestion_worker<CS>(
    mut rx: mpsc::Receiver<(ioi_types::app::TxHash, Vec<u8>)>,
    workload_client: Arc<WorkloadClient>,
    tx_pool: Arc<Mempool>,
    swarm_sender: mpsc::Sender<SwarmCommand>,
    peer_accounts_ref: Arc<Mutex<HashMap<PeerId, ioi_types::app::AccountId>>>,
    local_account_id: ioi_types::app::AccountId,
    consensus_kick_tx: mpsc::UnboundedSender<()>,
    tx_model: Arc<UnifiedTransactionModel<CS>>,
    tip_watcher: watch::Receiver<ChainTipInfo>,
    status_cache: Arc<Mutex<lru::LruCache<String, TxStatusEntry>>>,
    receipt_map: Arc<Mutex<lru::LruCache<ioi_types::app::TxHash, String>>>,
    safety_model: Arc<dyn LocalSafetyModel>,
    // [NEW] Added os_driver to worker arguments
    os_driver: Arc<dyn OsDriver>,
    config: IngestionConfig,
    event_broadcaster: tokio::sync::broadcast::Sender<ioi_types::app::KernelEvent>,
) where
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
    info!(
        "Transaction Ingestion Worker started (Batch Size: {}, Timeout: {}ms)",
        config.batch_size, config.batch_timeout_ms
    );
    let consensus_kick_debounce_ms = std::env::var("IOI_INGESTION_CONSENSUS_KICK_DEBOUNCE_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let kick_scheduled = Arc::new(AtomicBool::new(false));

    let mut nonce_cache: lru::LruCache<ioi_types::app::AccountId, u64> =
        lru::LruCache::new(std::num::NonZeroUsize::new(10000).unwrap());
    let mut timing_cache: Option<TimingCache> = None;

    loop {
        let first_item = match rx.recv().await {
            Some(item) => item,
            None => break,
        };

        let maybe_batch = collect_next_batch::<CS>(
            first_item,
            &mut rx,
            config.batch_size,
            config.batch_timeout_ms,
            &tx_pool,
            &tx_model,
            &tip_watcher,
            &status_cache,
            &workload_client,
            &mut nonce_cache,
            &mut timing_cache,
        )
        .await;

        let CollectedBatch {
            processed_batch,
            expected_ts,
            anchor,
        } = match maybe_batch {
            Some(v) => v,
            None => continue,
        };

        let semantically_valid_indices: Vec<usize> = semantic::select_semantically_valid_indices(
            &processed_batch,
            expected_ts,
            &workload_client,
            &safety_model,
            &os_driver,
            &status_cache,
            &event_broadcaster,
        )
        .await;

        if semantically_valid_indices.is_empty() {
            continue;
        }

        let current_tip = tip_watcher.borrow().clone();
        let current_tip_height = current_tip.height;

        if finalize_valid_transactions(
            &workload_client,
            &tx_pool,
            &swarm_sender,
            &peer_accounts_ref,
            local_account_id,
            &status_cache,
            &receipt_map,
            &mut nonce_cache,
            &semantically_valid_indices,
            &processed_batch,
            anchor,
            current_tip_height,
            &current_tip.validator_set,
            expected_ts,
        )
        .await
        {
            if consensus_kick_debounce_ms == 0 {
                let _ = consensus_kick_tx.send(());
            } else if !kick_scheduled.swap(true, Ordering::SeqCst) {
                let consensus_kick_tx = consensus_kick_tx.clone();
                let kick_scheduled = kick_scheduled.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(consensus_kick_debounce_ms)).await;
                    let _ = consensus_kick_tx.send(());
                    kick_scheduled.store(false, Ordering::SeqCst);
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn ingestion_is_verify_only_for_scoped_exception_usage() {
        let sources = [
            ("runner.rs", include_str!("runner.rs")),
            ("runner/collect.rs", include_str!("runner/collect.rs")),
            ("runner/finalize.rs", include_str!("runner/finalize.rs")),
            (
                "runner/semantic/system.rs",
                include_str!("runner/semantic/system.rs"),
            ),
            (
                "runner/semantic/review/context.rs",
                include_str!("runner/semantic/review/context.rs"),
            ),
            (
                "runner/semantic/review/scoped_exception.rs",
                include_str!("runner/semantic/review/scoped_exception.rs"),
            ),
            (
                "runner/semantic/policy/mod.rs",
                include_str!("runner/semantic/policy/mod.rs"),
            ),
            (
                "runner/semantic/policy/verdict.rs",
                include_str!("runner/semantic/policy/verdict.rs"),
            ),
            (
                "runner/semantic/policy/egress.rs",
                include_str!("runner/semantic/policy/egress.rs"),
            ),
        ];

        for (name, src) in sources {
            assert!(
                !src.contains("insert(&usage_key"),
                "{}: {}",
                name,
                "ingestion must not persist scoped exception usage counters"
            );
            assert!(
                !src.contains("insert(&usage_key_local"),
                "{}: {}",
                name,
                "ingestion must not persist scoped exception usage counters"
            );
        }
    }
}
