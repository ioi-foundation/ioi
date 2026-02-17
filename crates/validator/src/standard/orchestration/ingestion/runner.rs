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
use parity_scale_codec::{Decode, Encode};
use serde::Serialize;
use std::{fmt::Debug, sync::Arc};
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

        if finalize_valid_transactions(
            &workload_client,
            &tx_pool,
            &swarm_sender,
            &status_cache,
            &receipt_map,
            &mut nonce_cache,
            &semantically_valid_indices,
            &processed_batch,
            anchor,
            expected_ts,
        )
        .await
        {
            let _ = consensus_kick_tx.send(());
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
