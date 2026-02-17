use crate::standard::orchestration::context::TxStatusEntry;
use ioi_api::vm::drivers::os::OsDriver;
use ioi_api::vm::inference::LocalSafetyModel;
use ioi_client::WorkloadClient;
use ioi_types::app::{ChainTransaction, KernelEvent};
use std::sync::Arc;

use crate::standard::orchestration::ingestion::types::ProcessedTx;

mod policy;
mod review;
mod system;

pub(crate) async fn select_semantically_valid_indices(
    processed_batch: &[ProcessedTx],
    expected_ts: u64,
    workload_client: &Arc<WorkloadClient>,
    safety_model: &Arc<dyn LocalSafetyModel>,
    os_driver: &Arc<dyn OsDriver>,
    status_cache: &std::sync::Arc<tokio::sync::Mutex<lru::LruCache<String, TxStatusEntry>>>,
    event_broadcaster: &tokio::sync::broadcast::Sender<KernelEvent>,
) -> Vec<usize> {
    let mut semantically_valid_indices = Vec::new();
    let mut status_guard = status_cache.lock().await;

    for (idx, p_tx) in processed_batch.iter().enumerate() {
        let is_safe = if let ChainTransaction::System(_) = &p_tx.tx {
            system::evaluate_system_transaction(
                p_tx,
                workload_client,
                safety_model,
                os_driver,
                expected_ts,
                &mut status_guard,
                event_broadcaster,
            )
            .await
        } else {
            true
        };

        if is_safe {
            semantically_valid_indices.push(idx);
        }
    }

    drop(status_guard);
    semantically_valid_indices
}
