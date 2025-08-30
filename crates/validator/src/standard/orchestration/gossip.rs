// Path: crates/validator/src/standard/orchestration/gossip.rs
use super::context::MainLoopContext;
use super::oracle::handle_newly_processed_block;
use depin_sdk_api::{
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    state::{StateCommitment, StateManager},
};
use depin_sdk_network::traits::NodeState;
use depin_sdk_types::app::{Block, ChainTransaction, SystemPayload, SystemTransaction};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt::Debug;

/// Handles an incoming gossiped transaction.
pub async fn handle_gossip_transaction<CS, ST, CE>(
    context: &mut MainLoopContext<CS, ST, CE>,
    tx: ChainTransaction,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
{
    let mut pool = context.tx_pool_ref.lock().await;
    pool.push_back(tx);
    log::info!(
        "[Orchestrator] Received transaction via gossip. Pool size: {}",
        pool.len()
    );
}

/// Handles an incoming gossiped block.
pub async fn handle_gossip_block<CS, ST, CE>(
    context: &mut MainLoopContext<CS, ST, CE>,
    block: Block<ChainTransaction>,
) where
    CS: CommitmentScheme + Clone + Default + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + StateCommitment<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
{
    let block_height = block.header.height;
    log::info!(
        "[Orchestrator] Received gossiped block #{}. Verifying...",
        block_height
    );

    let mut engine = context.consensus_engine_ref.lock().await;

    if let Err(e) = engine
        .handle_block_proposal(block.clone(), context.workload_client.as_ref())
        .await
    {
        log::warn!(
            "[Orchestrator] Invalid gossiped block #{}: {}",
            block_height,
            e
        );
        return;
    }
    drop(engine);

    log::info!(
        "[Orchestrator] Block #{} is valid. Forwarding to workload...",
        block_height
    );
    match context.workload_client.process_block(block).await {
        Ok((processed_block, _)) => {
            log::info!("[Orchestrator] Workload processed block successfully.");
            let mut pool = context.tx_pool_ref.lock().await;
            let block_txs_canonical: HashSet<Vec<u8>> = processed_block
                .transactions
                .iter()
                .map(|tx| serde_jcs::to_vec(tx).unwrap())
                .collect();
            let finalized_oracle_ids: HashSet<u64> = processed_block
                .transactions
                .iter()
                .filter_map(|tx| {
                    if let ChainTransaction::System(SystemTransaction {
                        payload: SystemPayload::SubmitOracleData { request_id, .. },
                        ..
                    }) = tx
                    {
                        Some(*request_id)
                    } else {
                        None
                    }
                })
                .collect();
            let original_size = pool.len();
            pool.retain(|tx_in_pool| {
                let tx_in_pool_canonical = serde_jcs::to_vec(tx_in_pool).unwrap();
                if block_txs_canonical.contains(&tx_in_pool_canonical) {
                    return false;
                }
                if let ChainTransaction::System(SystemTransaction {
                    payload: SystemPayload::SubmitOracleData { request_id, .. },
                    ..
                }) = tx_in_pool
                {
                    if finalized_oracle_ids.contains(request_id) {
                        return false;
                    }
                }
                true
            });
            let new_size = pool.len();
            if new_size < original_size {
                log::info!(
                    "[Orchestrator] Pruned {} transaction(s) from mempool. New size: {}",
                    original_size - new_size,
                    new_size
                );
            }
            drop(pool);
            handle_newly_processed_block(context, block_height, &context.external_data_service)
                .await;
            if *context.node_state.lock().await == NodeState::Syncing {
                *context.node_state.lock().await = NodeState::Synced;
                log::info!("[Orchestrator] State -> Synced.");
            }
        }
        Err(e) => {
            log::error!(
                "[Orchestrator] Workload failed to process gossiped block #{}: {}",
                block_height,
                e
            );
        }
    }
}