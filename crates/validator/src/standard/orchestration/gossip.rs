// Path: crates/validator/src/standard/orchestration/gossip.rs
use super::context::MainLoopContext;
use super::oracle::handle_newly_processed_block;
use super::remote_state_view::DefaultAnchoredStateView;
use anyhow::Result;
use async_trait::async_trait;
use depin_sdk_api::chain::{AnchoredStateView, StateRef};
use depin_sdk_api::commitment::CommitmentScheme;
use depin_sdk_api::consensus::{ConsensusEngine, PenaltyMechanism};
use depin_sdk_api::state::{StateAccessor, StateCommitment, StateManager, Verifier};
use depin_sdk_network::traits::NodeState;
use depin_sdk_types::{
    app::{Block, ChainTransaction, FailureReport, StateRoot, SystemPayload},
    config::ConsensusType,
    error::{ChainError, TransactionError},
};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use serde_jcs;
use std::collections::{HashSet, VecDeque};
use std::fmt::Debug;
use std::sync::Arc;
use tokio::sync::Mutex;

// Type alias to simplify the complex proof cache type.
type ProofCache = Arc<Mutex<LruCache<(Vec<u8>, Vec<u8>), Option<Vec<u8>>>>>;

#[derive(Debug)]
struct WorkloadChainView<V> {
    client: Arc<depin_sdk_client::WorkloadClient>,
    consensus: ConsensusType,
    verifier: V,
    proof_cache: ProofCache,
}

impl<V: Clone> WorkloadChainView<V> {
    fn new(
        client: Arc<depin_sdk_client::WorkloadClient>,
        consensus: ConsensusType,
        verifier: V,
        proof_cache: ProofCache,
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
    V: Verifier<Commitment = CS::Commitment, Proof = <CS as CommitmentScheme>::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof: for<'de> Deserialize<'de> + parity_scale_codec::Decode,
{
    async fn view_at(
        &self,
        state_ref: &StateRef,
    ) -> Result<Arc<dyn AnchoredStateView>, ChainError> {
        let anchor = StateRoot(state_ref.state_root.clone())
            .to_anchor()
            .map_err(|e| ChainError::Transaction(e.to_string()))?;
        let root = StateRoot(state_ref.state_root.clone());
        let view = DefaultAnchoredStateView::new(
            anchor,
            root,
            self.client.clone(),
            self.verifier.clone(),
            self.proof_cache.clone(),
        );
        Ok(Arc::new(view))
    }

    fn get_penalty_mechanism(&self) -> Box<dyn PenaltyMechanism + Send + Sync + '_> {
        Box::new(NoopPenalty)
    }

    fn consensus_type(&self) -> ConsensusType {
        self.consensus
    }

    fn workload_container(&self) -> &depin_sdk_api::validator::WorkloadContainer<ST> {
        unreachable!(
            "WorkloadChainView is a remote proxy and does not have a local WorkloadContainer"
        );
    }
}

/// Prunes the mempool by removing transactions that were included in a newly processed block.
pub fn prune_mempool(
    pool: &mut VecDeque<ChainTransaction>,
    processed_block: &Block<ChainTransaction>,
) -> Result<(), serde_json::Error> {
    let block_txs_canonical: HashSet<Vec<u8>> = processed_block
        .transactions
        .iter()
        .map(serde_jcs::to_vec)
        .collect::<Result<_, _>>()?;

    let finalized_oracle_ids: HashSet<u64> = processed_block
        .transactions
        .iter()
        .filter_map(|tx| match tx {
            ChainTransaction::System(sys_tx) => match &sys_tx.payload {
                SystemPayload::CallService {
                    service_id,
                    method,
                    params,
                } if service_id == "oracle" && method == "submit_data@v1" => {
                    use depin_sdk_services::oracle::SubmitDataParams;
                    depin_sdk_types::codec::from_bytes_canonical::<SubmitDataParams>(params)
                        .map(|p| p.request_id)
                        .ok()
                }
                _ => None,
            },
            _ => None,
        })
        .collect();

    let original_size = pool.len();
    pool.retain(|tx_in_pool| {
        if let Ok(tx_in_pool_canonical) = serde_jcs::to_vec(tx_in_pool) {
            if block_txs_canonical.contains(&tx_in_pool_canonical) {
                return false;
            }
        } else {
            return true; // Keep malformed tx in mempool for now
        }

        if let ChainTransaction::System(sys_tx) = tx_in_pool {
            if let SystemPayload::CallService {
                service_id,
                method,
                params,
            } = &sys_tx.payload
            {
                if service_id == "oracle" && method == "submit_data@v1" {
                    if let Ok(p) = depin_sdk_types::codec::from_bytes_canonical::<
                        depin_sdk_services::oracle::SubmitDataParams,
                    >(params)
                    {
                        if finalized_oracle_ids.contains(&p.request_id) {
                            return false;
                        }
                    }
                }
            }
        }
        true
    });

    let new_size = pool.len();
    if new_size < original_size {
        tracing::info!(
            target: "orchestration",
            event = "mempool_pruned",
            num_pruned = original_size - new_size,
            new_size
        );
    }
    Ok(())
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
    // --- GUARD: Ignore gossiped blocks if they are old or if we are syncing ---
    let our_height = {
        context
            .last_committed_block
            .as_ref()
            .map(|b| b.header.height)
            .unwrap_or(0)
    };
    if block.header.height <= our_height {
        tracing::debug!(
            target: "gossip",
            event = "block_ignored",
            height = block.header.height,
            reason = "Already have a block at or after this height"
        );
        return;
    }

    let node_state = { context.node_state.lock().await.clone() };
    if node_state == NodeState::Syncing {
        tracing::debug!(
            target: "gossip",
            event = "block_ignored",
            height = block.header.height,
            reason = "Node is currently syncing"
        );
        return;
    }
    // --- END GUARD ---

    let block_height = block.header.height;
    tracing::info!(
        target: "gossip",
        event = "block_received",
        height = block_height,
        "Verifying gossiped block."
    );

    // To prevent deadlocks, clone needed data, drop the context lock,
    // and then await the consensus engine lock.
    let (engine_ref, cv) = {
        let resolver = match context
            .view_resolver
            .as_any()
            .downcast_ref::<super::view_resolver::DefaultViewResolver<V>>()
        {
            Some(r) => r,
            None => {
                tracing::error!("CRITICAL: Could not downcast ViewResolver in handle_gossip_block. This indicates a severe logic error.");
                return;
            }
        };
        (
            context.consensus_engine_ref.clone(),
            WorkloadChainView::new(
                resolver.workload_client().clone(),
                context.config.consensus_type,
                resolver.verifier().clone(),
                resolver.proof_cache().clone(),
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
        tracing::warn!(
            target: "gossip",
            event = "invalid_block",
            height = block_height,
            error = %e,
        );
        return;
    }

    tracing::info!(
        target: "gossip",
        event = "block_valid",
        height = block_height,
        "Forwarding to workload."
    );
    let resolver = match context
        .view_resolver
        .as_any()
        .downcast_ref::<super::view_resolver::DefaultViewResolver<V>>()
    {
        Some(r) => r,
        None => {
            tracing::error!(
                "CRITICAL: Could not downcast ViewResolver in handle_gossip_block. This indicates a severe logic error."
            );
            return;
        }
    };
    match resolver.workload_client().process_block(block).await {
        Ok((processed_block, _)) => {
            tracing::info!(
                target: "gossip",
                event = "workload_processed_block",
                height = processed_block.header.height
            );

            context.last_committed_block = Some(processed_block.clone());
            {
                let mut chain_guard = context.chain_ref.lock().await;
                let status = chain_guard.status_mut();
                status.height = processed_block.header.height;
                status.latest_timestamp = processed_block.header.timestamp;
            }
            tracing::debug!(
                target: "gossip",
                event = "tip_advanced",
                height = processed_block.header.height,
                root = hex::encode(processed_block.header.state_root.as_ref())
            );

            let mut pool = context.tx_pool_ref.lock().await;
            if let Err(e) = prune_mempool(&mut pool, &processed_block) {
                tracing::error!(target: "gossip", event="mempool_prune_fail", error=%e);
            }
            drop(pool);

            handle_newly_processed_block(context, block_height, &context.oracle_service).await;
            if *context.node_state.lock().await == NodeState::Syncing {
                *context.node_state.lock().await = NodeState::Synced;
                tracing::info!(target: "orchestration", "State -> Synced.");
            }
        }
        Err(e) => {
            tracing::error!(
                target: "gossip",
                event = "workload_process_fail",
                height = block_height,
                error = %e,
            );
        }
    }
}
