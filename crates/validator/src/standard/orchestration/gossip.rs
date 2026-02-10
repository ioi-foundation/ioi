// Path: crates/validator/src/standard/orchestration/gossip.rs

use super::context::MainLoopContext;
use crate::standard::orchestration::mempool::Mempool;
use anyhow::Result;
use async_trait::async_trait;
use ioi_api::chain::{AnchoredStateView, StateRef, WorkloadClientApi};
use ioi_api::commitment::CommitmentScheme;
use ioi_api::consensus::{ConsensusEngine, PenaltyMechanism};
use ioi_api::state::{StateAccess, StateManager, Verifier};
use ioi_ipc::public::TxStatus;
use ioi_networking::traits::NodeState;
use ioi_types::{
    app::{AccountId, Block, ChainTransaction, FailureReport, StateRoot},
    config::ConsensusType,
    error::{ChainError, TransactionError},
};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::metrics::rpc_metrics as metrics;

// [FIX] Added imports for voting
use ioi_networking::libp2p::SwarmCommand;
use ioi_types::app::{account_id_from_key_material, to_root_hash, ConsensusVote, SignatureSuite};
use ioi_types::codec;

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
    <CS as CommitmentScheme>::Proof: for<'de> Deserialize<'de> + parity_scale_codec::Decode + Debug,
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
        unreachable!("WorkloadChainView does not have a local WorkloadContainer");
    }
}

/// Prunes the mempool by removing committed transactions and updating account nonces.
pub fn prune_mempool(
    pool: &Mempool,
    processed_block: &Block<ChainTransaction>,
) -> Result<(), anyhow::Error> {
    let mut max_nonce_in_block: HashMap<AccountId, u64> = HashMap::new();

    for tx in &processed_block.transactions {
        if let Some((acct, nonce)) = get_tx_nonce(tx) {
            max_nonce_in_block
                .entry(acct)
                .and_modify(|e| *e = (*e).max(nonce))
                .or_insert(nonce);
        } else if let Ok(h) = tx.hash() {
            pool.remove_by_hash(&h);
        }
    }

    // Bulk update account nonces using the batched API
    let updates: HashMap<AccountId, u64> = max_nonce_in_block
        .into_iter()
        .map(|(acct, max_nonce)| (acct, max_nonce + 1))
        .collect();

    pool.update_account_nonces_batch(&updates);

    metrics().set_mempool_size(pool.len() as f64);
    Ok(())
}

fn get_tx_nonce(tx: &ChainTransaction) -> Option<(AccountId, u64)> {
    match tx {
        ChainTransaction::System(s) => Some((s.header.account_id, s.header.nonce)),
        ChainTransaction::Settlement(s) => Some((s.header.account_id, s.header.nonce)),
        ChainTransaction::Application(a) => match a {
            ioi_types::app::ApplicationTransaction::DeployContract { header, .. }
            | ioi_types::app::ApplicationTransaction::CallContract { header, .. } => {
                Some((header.account_id, header.nonce))
            }
        },
        _ => None,
    }
}

/// Handles an incoming gossiped block.
pub async fn handle_gossip_block<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    block: Block<ChainTransaction>,
    mirror_id: u8,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
{
    let our_height = context
        .last_committed_block
        .as_ref()
        .map_or(0, |b| b.header.height);
    if block.header.height <= our_height {
        return;
    }

    let node_state = { context.node_state.lock().await.clone() };
    if node_state == NodeState::Syncing && block.header.height != our_height + 1 {
        return;
    }

    let (engine_ref, cv) = {
        let resolver = context.view_resolver.as_ref();
        let default_resolver: &super::view_resolver::DefaultViewResolver<V> =
            match (*resolver).as_any().downcast_ref() {
                Some(r) => r,
                None => {
                    tracing::error!("CRITICAL: Could not downcast ViewResolver");
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

    tracing::debug!(target: "admft", "Received block {} on Mirror {}", block.header.height, if mirror_id == 0 { "A" } else { "B" });

    if let Err(e) = engine_ref
        .lock()
        .await
        .handle_block_proposal::<CS, ST>(block.clone(), &&cv)
        .await
    {
        tracing::warn!(target: "gossip", "Invalid block: {}", e);
        return;
    }

    tracing::info!(target: "gossip", "Gossiped block is valid, forwarding to workload.");

    match context
        .view_resolver
        .workload_client()
        .process_block(block)
        .await
    {
        Ok((processed_block, _)) => {
            tracing::info!(target: "gossip", "Workload processed block #{}", processed_block.header.height);
            context.last_committed_block = Some(processed_block.clone());

            {
                let mut chain_guard = context.chain_ref.lock().await;
                let status = chain_guard.status_mut();
                status.height = processed_block.header.height;
                status.latest_timestamp = processed_block.header.timestamp;
            }

            {
                let receipt_guard = context.receipt_map.lock().await;
                let mut status_guard = context.tx_status_cache.lock().await;
                let block_height = processed_block.header.height;

                for tx in &processed_block.transactions {
                    if let Ok(h) = tx.hash() {
                        if let Some(receipt_hex) = receipt_guard.peek(&h) {
                            if let Some(entry) = status_guard.get_mut(receipt_hex) {
                                entry.status = TxStatus::Committed;
                                entry.block_height = Some(block_height);
                            }
                        }
                    }
                }
            }

            if let Err(e) = prune_mempool(&context.tx_pool_ref, &processed_block) {
                tracing::error!(target: "gossip", event="mempool_prune_fail", error=%e);
            }

            // [FIX] Broadcast Vote for the successfully committed block
            if processed_block.header.height > 0 {
                let vote_height = processed_block.header.height;
                let vote_view = processed_block.header.view;
                let vote_hash_vec = processed_block.header.hash().unwrap_or(vec![0u8; 32]);
                let vote_hash = to_root_hash(&vote_hash_vec).unwrap_or([0u8; 32]);

                // Get our ID
                let our_pk = context.local_keypair.public().encode_protobuf();
                let our_id = AccountId(
                    account_id_from_key_material(SignatureSuite::ED25519, &our_pk)
                        .unwrap_or([0u8; 32]),
                );

                // Sign Vote
                let vote_payload = (vote_height, vote_view, vote_hash);
                if let Ok(vote_bytes) = codec::to_bytes_canonical(&vote_payload) {
                    if let Ok(sig) = context.local_keypair.sign(&vote_bytes) {
                        let vote = ConsensusVote {
                            height: vote_height,
                            view: vote_view,
                            block_hash: vote_hash,
                            voter: our_id,
                            signature: sig,
                        };

                        if let Ok(vote_blob) = codec::to_bytes_canonical(&vote) {
                            // Broadcast to network
                            let _ = context
                                .swarm_commander
                                .send(SwarmCommand::BroadcastVote(vote_blob))
                                .await;

                            // Loopback to local engine to ensure we count our own vote
                            let mut engine = engine_ref.lock().await;
                            if let Err(e) = engine.handle_vote(vote).await {
                                tracing::warn!(target: "consensus", "Failed to handle own vote: {}", e);
                            }

                            tracing::info!(target: "consensus", "Voted for block {} (H={} V={})", hex::encode(&vote_hash[..4]), vote_height, vote_view);
                        }
                    }
                }
            }

            if *context.node_state.lock().await == NodeState::Syncing {
                *context.node_state.lock().await = NodeState::Synced;
                tracing::info!(target: "orchestration", "State -> Synced.");
            }
        }
        Err(e) => {
            tracing::error!(target: "gossip", "Workload failed to process gossiped block: {}", e);
        }
    }
}
