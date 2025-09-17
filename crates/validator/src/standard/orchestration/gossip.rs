// Path: crates/validator/src/standard/orchestration/gossip.rs
use super::context::MainLoopContext;
use super::oracle::handle_newly_processed_block;
use super::remote_state_view::RemoteStateView;
use async_trait::async_trait;
use depin_sdk_api::chain::StateView;
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_api::consensus::{ConsensusEngine, PenaltyMechanism};
use depin_sdk_api::state::{StateAccessor, StateCommitment, StateManager, Verifier};
use depin_sdk_network::traits::NodeState;
use depin_sdk_types::app::{
    Block, ChainTransaction, FailureReport, StateAnchor, StateRoot, SystemPayload,
};
use depin_sdk_types::config::ConsensusType;
use depin_sdk_types::error::TransactionError;
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::fmt::Debug;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug)]
struct WorkloadChainView<V> {
    client: Arc<depin_sdk_client::WorkloadClient>,
    consensus: ConsensusType,
    verifier: V,
    proof_cache: Arc<Mutex<LruCache<(Vec<u8>, Vec<u8>), Option<Vec<u8>>>>>,
}

impl<V: Clone> WorkloadChainView<V> {
    fn new(
        client: Arc<depin_sdk_client::WorkloadClient>,
        consensus: ConsensusType,
        verifier: V,
        proof_cache: Arc<Mutex<LruCache<(Vec<u8>, Vec<u8>), Option<Vec<u8>>>>>,
    ) -> Self {
        Self {
            client,
            consensus,
            verifier,
            proof_cache,
        }
    }
}

// No-op penalty to satisfy the trait; not used during proposal verification.
struct NoopPenalty;
#[async_trait]
impl PenaltyMechanism for NoopPenalty {
    async fn apply_penalty(
        &self,
        _state: &mut dyn StateAccessor,
        _report: &FailureReport,
    ) -> Result<(), TransactionError> {
        Ok(())
    }
}

#[async_trait]
impl<CS, ST, V> depin_sdk_api::chain::ChainView<CS, ST> for &WorkloadChainView<V>
where
    CS: CommitmentScheme + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof: for<'de> Deserialize<'de>,
{
    async fn view_at(
        &self,
        anchor: &StateAnchor,
    ) -> Result<Box<dyn StateView>, depin_sdk_types::error::ChainError> {
        let root = match self.client.get_state_root().await {
            Ok(r) => r,
            Err(e) => {
                log::warn!(
                    "[Gossip] get_state_root() failed ({}); falling back to anchor bytes as root (weak).",
                    e
                );
                StateRoot(anchor.0.to_vec())
            }
        };
        Ok(Box::new(RemoteStateView::new(
            *anchor,
            root,
            self.client.clone(),
            self.verifier.clone(),
            self.consensus,
            self.proof_cache.clone(),
        )))
    }

    fn get_penalty_mechanism(&self) -> Box<dyn PenaltyMechanism + Send + Sync + '_> {
        Box::new(NoopPenalty)
    }

    fn consensus_type(&self) -> ConsensusType {
        self.consensus
    }

    fn workload_container(&self) -> &depin_sdk_api::validator::WorkloadContainer<ST> {
        todo!("WorkloadChainView is a remote proxy for consensus verification and cannot provide direct access to the WorkloadContainer. This should never be called in this context.")
    }
}

/// Prunes the mempool by removing transactions that were included in a newly processed block.
pub fn prune_mempool(
    pool: &mut VecDeque<ChainTransaction>,
    processed_block: &Block<ChainTransaction>,
) {
    let block_txs_canonical: HashSet<Vec<u8>> = processed_block
        .transactions
        .iter()
        .map(|tx| serde_jcs::to_vec(tx).unwrap())
        .collect();

    let finalized_oracle_ids: HashSet<u64> = processed_block
        .transactions
        .iter()
        .filter_map(|tx| match tx {
            ChainTransaction::System(sys_tx) => match &sys_tx.payload {
                SystemPayload::SubmitOracleData { request_id, .. } => Some(*request_id),
                _ => None,
            },
            _ => None,
        })
        .collect();

    let original_size = pool.len();
    pool.retain(|tx_in_pool| {
        let tx_in_pool_canonical = serde_jcs::to_vec(tx_in_pool).unwrap();
        if block_txs_canonical.contains(&tx_in_pool_canonical) {
            return false;
        }
        if let ChainTransaction::System(sys_tx) = tx_in_pool {
            if let SystemPayload::SubmitOracleData { request_id, .. } = &sys_tx.payload {
                if finalized_oracle_ids.contains(request_id) {
                    return false;
                }
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
}

/// Handles an incoming gossiped block.
pub async fn handle_gossip_block<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    block: Block<ChainTransaction>,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + StateCommitment<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    let block_height = block.header.height;
    log::info!(
        "[Orchestrator] Received gossiped block #{}. Verifying...",
        block_height
    );

    // [+] FIX: To prevent deadlocks, clone needed data, drop the context lock,
    // and then await the consensus engine lock.
    let (engine_ref, cv) = {
        (
            context.consensus_engine_ref.clone(),
            WorkloadChainView::new(
                context.workload_client.clone(),
                context.config.consensus_type,
                context.verifier.clone(),
                context.proof_cache_ref.clone(),
            ),
        )
    };
    // Context lock is now released.

    if let Err(e) = engine_ref
        .lock()
        .await
        .handle_block_proposal::<CS, ST>(block.clone(), &&cv)
        .await
    {
        log::warn!(
            "[Orchestrator] Invalid gossiped block #{}: {}",
            block_height,
            e
        );
        return;
    }

    log::info!(
        "[Orchestrator] Block #{} is valid. Forwarding to workload...",
        block_height
    );
    match context.workload_client.process_block(block).await {
        Ok((processed_block, _)) => {
            log::info!("[Orchestrator] Workload processed block successfully.");

            context.last_committed_block = Some(processed_block.clone());
            log::debug!(
                "[Gossip] Advanced tip to #{} root=0x{}",
                processed_block.header.height,
                hex::encode(processed_block.header.state_root.as_ref())
            );

            let mut pool = context.tx_pool_ref.lock().await;
            prune_mempool(&mut pool, &processed_block);
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
