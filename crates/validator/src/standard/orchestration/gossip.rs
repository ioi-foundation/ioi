// Path: crates/validator/src/standard/orchestration/gossip.rs
use super::context::MainLoopContext;
use crate::standard::orchestration::mempool::Mempool;
use anyhow::Result;
use async_trait::async_trait;
use ioi_api::chain::{AnchoredStateView, StateRef, WorkloadClientApi};
use ioi_api::commitment::CommitmentScheme;
use ioi_api::consensus::{ConsensusEngine, PenaltyMechanism};
use ioi_api::state::{StateAccess, StateManager, Verifier};
use ioi_networking::traits::NodeState;
// [FIX] Removed SystemPayload, TxHash
use ioi_types::{
    app::{AccountId, Block, ChainTransaction, FailureReport, StateRoot}, 
    config::ConsensusType,
    error::{ChainError, TransactionError},
};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet}; // Added HashMap
use std::fmt::Debug;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::metrics::rpc_metrics as metrics;

type ProofCache = Arc<Mutex<LruCache<(Vec<u8>, Vec<u8>), Option<Vec<u8>>>>>;

#[derive(Debug)]
struct WorkloadChainView<V> {
    client_api: Arc<dyn WorkloadClientApi>,
    consensus: ConsensusType,
    verifier: V,
    proof_cache: ProofCache,
}

impl<V: Clone> WorkloadChainView<V> {
    fn new(
        client_api: Arc<dyn WorkloadClientApi>,
        consensus: ConsensusType,
        verifier: V,
        proof_cache: ProofCache,
    ) -> Self {
        Self {
            client_api,
            consensus,
            verifier,
            proof_cache,
        }
    }
}

struct NoopPenalty;
#[async_trait]
impl PenaltyMechanism for NoopPenalty {
    async fn apply_penalty(
        &self,
        _state: &mut dyn StateAccess,
        _report: &FailureReport,
    ) -> Result<(), TransactionError> {
        Ok(())
    }
}

#[async_trait]
impl<CS, ST, V> ioi_api::chain::ChainView<CS, ST> for &WorkloadChainView<V>
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

        let view = super::remote_state_view::DefaultAnchoredStateView::new(
            anchor,
            root,
            state_ref.height,
            self.client_api.clone(),
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

    fn workload_container(&self) -> &ioi_api::validator::WorkloadContainer<ST> {
        unreachable!(
            "WorkloadChainView is a remote proxy and does not have a local WorkloadContainer"
        );
    }
}

/// Prunes the mempool by removing transactions that were included in a newly processed block.
/// Also updates the Mempool's tracking of committed nonces.
pub fn prune_mempool(
    pool: &mut Mempool,
    processed_block: &Block<ChainTransaction>,
) -> Result<(), anyhow::Error> {
    // 1. Identify transactions to remove.
    // OPTIMIZATION: We ONLY use remove_by_hash for transactions that do NOT have a stable AccountId/Nonce.
    // For Account transactions, `update_account_nonce` will efficiently bulk-remove them from the specific queue.
    // Calling `remove_by_hash` for account txs forces an O(N) scan of all queues, killing performance.

    let mut max_nonce_in_block: HashMap<AccountId, u64> = HashMap::new();

    for tx in &processed_block.transactions {
        if let Some((acct, nonce)) = get_tx_nonce(tx) {
            // It's an account transaction. Record the nonce advancement.
            let entry = max_nonce_in_block.entry(acct).or_insert(0);
            *entry = std::cmp::max(*entry, nonce);
        } else {
            // It's a non-account transaction (e.g., Semantic, UTXO).
            // We must remove these by hash explicitly.
            if let Ok(h) = tx.hash() {
                pool.remove_by_hash(&h);
            }
        }
    }

    // 2. Bulk update account queues.
    // This efficiently removes all processed transactions for these accounts in O(1) per account.
    for (acct, max_nonce) in max_nonce_in_block {
        // The new committed nonce is max_nonce + 1
        pool.update_account_nonce(&acct, max_nonce + 1);
    }

    metrics().set_mempool_size(pool.len() as f64);

    tracing::info!(
        target: "orchestration",
        event = "mempool_pruned",
        new_size = pool.len()
    );

    Ok(())
}

fn get_tx_nonce(tx: &ChainTransaction) -> Option<(AccountId, u64)> {
    match tx {
        ChainTransaction::System(s) => Some((s.header.account_id, s.header.nonce)),
        ChainTransaction::Application(a) => match a {
            ioi_types::app::ApplicationTransaction::DeployContract { header, .. } => {
                Some((header.account_id, header.nonce))
            }
            ioi_types::app::ApplicationTransaction::CallContract { header, .. } => {
                Some((header.account_id, header.nonce))
            }
            _ => None,
        },
        _ => None,
    }
}

/// Handles an incoming gossiped block.
pub async fn handle_gossip_block<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    block: Block<ChainTransaction>,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
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
    if node_state == NodeState::Syncing && block.header.height != our_height + 1 {
        tracing::debug!(
            target: "gossip",
            event = "block_ignored",
            height = block.header.height,
            reason = "Node is currently syncing and block is not immediate successor"
        );
        return;
    }

    let block_height = block.header.height;
    tracing::info!(
        target: "gossip",
        event = "block_received",
        height = block_height,
        "Verifying gossiped block."
    );

    let (engine_ref, cv) = {
        let resolver = context.view_resolver.as_ref();
        let default_resolver: &super::view_resolver::DefaultViewResolver<V> =
            match (*resolver).as_any().downcast_ref() {
                Some(r) => r,
                None => {
                    tracing::error!(
                        "CRITICAL: Could not downcast ViewResolver in handle_gossip_block."
                    );
                    return;
                }
            };

        (
            context.consensus_engine_ref.clone(),
            WorkloadChainView::new(
                resolver.workload_client().clone(),
                context.config.consensus_type,
                default_resolver.verifier().clone(),
                default_resolver.proof_cache().clone(),
            ),
        )
    };

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

    match context
        .view_resolver
        .workload_client()
        .process_block(block)
        .await
    {
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