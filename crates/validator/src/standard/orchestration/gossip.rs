// Path: crates/validator/src/standard/orchestration/gossip.rs

use super::aft_collapse::observe_live_committed_chain_through_block;
use super::context::MainLoopContext;
use super::finalize::schedule_committed_block_vote_replays;
use super::sync as sync_handlers;
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
    config::{AftSafetyMode, ConsensusType},
    error::{ChainError, TransactionError},
};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio::time::Duration;

use libp2p::{identity::Keypair, PeerId};

use crate::metrics::rpc_metrics as metrics;

// [FIX] Added imports for voting
use ioi_networking::libp2p::SwarmCommand;
use ioi_types::app::{account_id_from_key_material, to_root_hash, ConsensusVote, SignatureSuite};
use ioi_types::codec;

type ProofCache = Arc<Mutex<LruCache<(Vec<u8>, Vec<u8>), Option<Vec<u8>>>>>;
const AFT_ENRICHMENT_SYNC_MAX_BYTES: u32 = 32 * 1024 * 1024;

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
        let mut resolved_root = StateRoot(state_ref.state_root.clone());
        let local_parent = self
            .client_api
            .get_blocks_range(state_ref.height, 1, 10 * 1024 * 1024)
            .await?
            .into_iter()
            .find(|candidate| candidate.header.height == state_ref.height);
        if let Some(local_parent) = local_parent {
            let local_hash = local_parent
                .header
                .hash()
                .ok()
                .and_then(|hash| ioi_types::app::to_root_hash(&hash).ok());
            if local_hash == Some(state_ref.block_hash)
                && local_parent.header.state_root.0 != state_ref.state_root
            {
                tracing::info!(
                    target: "gossip",
                    height = state_ref.height,
                    block = %hex::encode(&state_ref.block_hash[..4]),
                    "Using the locally committed parent state root for anchored verification because the advertised parent state root does not match the local replica."
                );
                resolved_root = local_parent.header.state_root.clone();
            }
        }

        let anchor = resolved_root
            .to_anchor()
            .map_err(|e| ChainError::Transaction(e.to_string()))?;
        let root = resolved_root;

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

fn relay_fanout() -> usize {
    std::env::var("IOI_AFT_TX_RELAY_FANOUT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1)
}

fn post_commit_leader_fanout() -> usize {
    std::env::var("IOI_AFT_POST_COMMIT_LEADER_FANOUT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1)
}

fn post_commit_relay_limit() -> usize {
    std::env::var("IOI_AFT_POST_COMMIT_RELAY_LIMIT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(2048)
}

fn post_commit_rekick_delays_ms() -> Vec<u64> {
    std::env::var("IOI_AFT_POST_COMMIT_REKICK_DELAYS_MS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .filter_map(|part| part.trim().parse::<u64>().ok())
                .filter(|delay| *delay > 0)
                .collect::<Vec<_>>()
        })
        .filter(|delays| !delays.is_empty())
        .unwrap_or_else(|| vec![100, 300, 750])
}

fn dispatch_swarm_command(sender: &tokio::sync::mpsc::Sender<SwarmCommand>, command: SwarmCommand) {
    match sender.try_send(command) {
        Ok(()) => {}
        Err(tokio::sync::mpsc::error::TrySendError::Full(command)) => {
            let sender = sender.clone();
            tokio::spawn(async move {
                let _ = sender.send(command).await;
            });
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
    }
}

fn leader_accounts_for_upcoming_heights(
    local_height: u64,
    validator_ids: &[Vec<u8>],
    fanout: usize,
) -> Vec<AccountId> {
    if validator_ids.is_empty() || fanout == 0 {
        return Vec::new();
    }

    let mut leaders = Vec::new();
    let mut seen = HashSet::new();
    let validator_len = validator_ids.len() as u64;
    let steps = fanout.min(validator_ids.len());
    for offset in 1..=steps {
        let target_height = local_height.saturating_add(offset as u64).max(1);
        let leader_index = ((target_height - 1) % validator_len) as usize;
        let Some(leader_bytes) = validator_ids.get(leader_index) else {
            continue;
        };
        let Ok(leader_bytes) = <[u8; 32]>::try_from(leader_bytes.as_slice()) else {
            continue;
        };
        let account = AccountId(leader_bytes);
        if seen.insert(account) {
            leaders.push(account);
        }
    }
    leaders
}

async fn relay_remaining_mempool_to_upcoming_leaders(
    tx_pool: Arc<Mempool>,
    local_keypair: Keypair,
    peer_accounts_ref: Arc<Mutex<HashMap<PeerId, AccountId>>>,
    swarm_commander: mpsc::Sender<SwarmCommand>,
    committed_block: Block<ChainTransaction>,
    deferred_transactions: Vec<ChainTransaction>,
) {
    let pending = if deferred_transactions.is_empty() {
        let relay_limit = post_commit_relay_limit();
        if relay_limit == 0 {
            return;
        }
        tx_pool.select_transactions(relay_limit)
    } else {
        deferred_transactions
    };
    if pending.is_empty() {
        return;
    }

    let local_account_id = AccountId(
        account_id_from_key_material(
            SignatureSuite::ED25519,
            &local_keypair.public().encode_protobuf(),
        )
        .unwrap_or_default(),
    );
    let leader_accounts = leader_accounts_for_upcoming_heights(
        committed_block.header.height,
        &committed_block.header.validator_set,
        post_commit_leader_fanout(),
    );
    let leader_peer_targets = leader_accounts
        .iter()
        .filter(|account_id| **account_id != local_account_id)
        .count();
    let leader_peers = {
        let peers = peer_accounts_ref.lock().await;
        leader_accounts
            .into_iter()
            .filter(|account_id| *account_id != local_account_id)
            .filter_map(|leader_account_id| {
                peers.iter().find_map(|(peer_id, account_id)| {
                    (*account_id == leader_account_id).then_some(*peer_id)
                })
            })
            .collect::<Vec<_>>()
    };
    for tx in pending {
        if let Ok(data) = codec::to_bytes_canonical(&tx) {
            if leader_peers.is_empty() || leader_peers.len() < leader_peer_targets {
                dispatch_swarm_command(
                    &swarm_commander,
                    SwarmCommand::PublishTransaction(data.clone()),
                );
            }
            for peer in &leader_peers {
                dispatch_swarm_command(
                    &swarm_commander,
                    SwarmCommand::RelayTransactionToPeer {
                        peer: *peer,
                        data: data.clone(),
                    },
                );
            }
        }
    }
}

/// Handles an incoming gossiped block.
pub async fn handle_gossip_block<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    block: Block<ChainTransaction>,
    mirror_id: u8,
    source_peer: libp2p::PeerId,
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
        if let Err(error) = maybe_apply_block_enrichment(context, &block).await {
            tracing::warn!(
                target: "gossip",
                event = "block_enrichment_rejected",
                height = block.header.height,
                view = block.header.view,
                error = %error
            );
        }
        return;
    }

    if block.header.height > our_height + 1 {
        tracing::info!(
            target: "gossip",
            source_peer = %source_peer,
            local_height = our_height,
            received_height = block.header.height,
            "Detected a gossiped block height gap; switching into catch-up sync."
        );
        sync_handlers::start_catchup_to_peer(context, source_peer, block.header.height).await;
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

    tracing::debug!(target: "aft", "Received block {} on Mirror {}", block.header.height, if mirror_id == 0 { "A" } else { "B" });

    if let Err(e) = engine_ref
        .lock()
        .await
        .handle_block_proposal::<CS, ST>(block.clone(), &&cv)
        .await
    {
        tracing::warn!(target: "gossip", "Invalid block: {}", e);
        return;
    }

    if block.header.height > 0 {
        let vote_height = block.header.height;
        let vote_view = block.header.view;
        let vote_hash_vec = block.header.hash().unwrap_or(vec![0u8; 32]);
        let vote_hash = to_root_hash(&vote_hash_vec).unwrap_or([0u8; 32]);

        let our_pk = context.local_keypair.public().encode_protobuf();
        let our_id = AccountId(
            account_id_from_key_material(SignatureSuite::ED25519, &our_pk).unwrap_or([0u8; 32]),
        );

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
                    let _ = context
                        .swarm_commander
                        .send(SwarmCommand::BroadcastVote(vote_blob))
                        .await;

                    let mut engine = engine_ref.lock().await;
                    if let Err(error) = engine.handle_vote(vote).await {
                        tracing::warn!(
                            target: "consensus",
                            "Failed to handle follower vote before local apply: {}",
                            error
                        );
                    } else {
                        let pending_qcs = engine.take_pending_quorum_certificates();
                        drop(engine);
                        for qc in pending_qcs {
                            if let Ok(qc_blob) = codec::to_bytes_canonical(&qc) {
                                let _ = context
                                    .swarm_commander
                                    .send(SwarmCommand::BroadcastQuorumCertificate(qc_blob))
                                    .await;
                            }
                        }
                        tracing::debug!(
                            target: "consensus",
                            "Pre-applied vote for block {} (H={} V={})",
                            hex::encode(&vote_hash[..4]),
                            vote_height,
                            vote_view
                        );
                    }
                }
            }
        }
    }

    tracing::debug!(
        target: "gossip",
        "Gossiped block is valid, forwarding to workload after voting."
    );

    let applying_height = block.header.height;
    match context
        .view_resolver
        .workload_client()
        .process_block(block)
        .await
    {
        Ok((processed_block, _)) => {
            tracing::debug!(target: "gossip", "Workload processed block #{}", processed_block.header.height);
            context.last_committed_block = Some(processed_block.clone());

            {
                let mut chain_guard = context.chain_ref.lock().await;
                let status = chain_guard.status_mut();
                if processed_block.header.height > status.height {
                    status.total_transactions = status
                        .total_transactions
                        .saturating_add(processed_block.transactions.len() as u64);
                }
                status.height = processed_block.header.height;
                status.latest_timestamp = processed_block.header.timestamp;
            }

            {
                let accepted = match observe_live_committed_chain_through_block(
                    &engine_ref,
                    context.config.consensus_type,
                    context.view_resolver.workload_client().as_ref(),
                    &processed_block,
                )
                .await
                {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        tracing::warn!(
                            target: "gossip",
                            height = processed_block.header.height,
                            error = %error,
                            "Skipping committed-block ingestion because the live canonical collapse chain could not be reconciled."
                        );
                        false
                    }
                };
                if !accepted {
                    tracing::warn!(
                        target: "gossip",
                        height = processed_block.header.height,
                        "Consensus engine ignored the processed committed-block hint because it was not collapse-backed."
                    );
                } else {
                    engine_ref.lock().await.reset(processed_block.header.height);
                }
            }

            {
                let receipt_guard = context.receipt_map.lock().await;
                let mut status_guard = context.tx_status_cache.lock().await;
                let block_height = processed_block.header.height;

                for tx in &processed_block.transactions {
                    if let Ok(h) = tx.hash() {
                        let tx_hash_hex = receipt_guard
                            .peek(&h)
                            .cloned()
                            .unwrap_or_else(|| hex::encode(h));
                        if let Some(entry) = status_guard.get_mut(&tx_hash_hex) {
                            entry.status = TxStatus::Committed;
                            entry.block_height = Some(block_height);
                        } else {
                            status_guard.put(
                                tx_hash_hex,
                                crate::standard::orchestration::context::TxStatusEntry {
                                    status: TxStatus::Committed,
                                    error: None,
                                    block_height: Some(block_height),
                                },
                            );
                        }
                    }
                }
            }

            if let Err(e) = prune_mempool(&context.tx_pool_ref, &processed_block) {
                tracing::error!(target: "gossip", event="mempool_prune_fail", error=%e);
            }

            if processed_block.header.sealed_finality_proof.is_none() {
                maybe_request_asymptote_sealed_enrichment(context, processed_block.header.height)
                    .await;
            }

            let mut caught_up_via_gossip = false;
            if let Some(progress) = context.sync_progress.as_mut() {
                if processed_block.header.height > progress.next {
                    tracing::debug!(
                        target: "sync",
                        height = processed_block.header.height,
                        previous_next = progress.next,
                        tip = progress.tip,
                        "Advancing sync cursor from live gossip block."
                    );
                    progress.next = processed_block.header.height;
                }
                caught_up_via_gossip = progress.next >= progress.tip;
            }

            if caught_up_via_gossip {
                context.sync_progress = None;
                if *context.node_state.lock().await == NodeState::Syncing {
                    *context.node_state.lock().await = NodeState::Synced;
                    tracing::info!(
                        target: "orchestration",
                        height = processed_block.header.height,
                        "State -> Synced (caught up via live gossip)."
                    );
                }
            }

            {
                let tx_pool = Arc::clone(&context.tx_pool_ref);
                let local_keypair = context.local_keypair.clone();
                let peer_accounts_ref = Arc::clone(&context.peer_accounts_ref);
                let swarm_commander = context.swarm_commander.clone();
                let relay_block = processed_block.clone();
                tokio::spawn(async move {
                    relay_remaining_mempool_to_upcoming_leaders(
                        tx_pool,
                        local_keypair,
                        peer_accounts_ref,
                        swarm_commander,
                        relay_block,
                        Vec::new(),
                    )
                    .await;
                });
            }

            schedule_committed_block_vote_replays(
                Arc::clone(&engine_ref),
                context.local_keypair.clone(),
                context.swarm_commander.clone(),
                processed_block.clone(),
            );

            let _ = context.consensus_kick_tx.send(());
            if !context.tx_pool_ref.is_empty() {
                let kick_tx = context.consensus_kick_tx.clone();
                let kick_scheduled = context.consensus_kick_scheduled.clone();
                let tx_pool = Arc::clone(&context.tx_pool_ref);
                for delay_ms in post_commit_rekick_delays_ms() {
                    let kick_tx = kick_tx.clone();
                    let kick_scheduled = Arc::clone(&kick_scheduled);
                    let tx_pool = Arc::clone(&tx_pool);
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                        if !tx_pool.is_empty() {
                            crate::standard::orchestration::schedule_consensus_kick(
                                &kick_tx,
                                &kick_scheduled,
                            );
                        }
                    });
                }
            }
        }
        Err(e) => {
            tracing::error!(
                target: "gossip",
                height = applying_height,
                source_peer = %source_peer,
                error = %e,
                "Workload failed to process gossiped block."
            );
        }
    }
}

pub(super) async fn maybe_apply_block_enrichment<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    block: &Block<ChainTransaction>,
) -> Result<()>
where
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
    if block.header.sealed_finality_proof.is_none() {
        return Ok(());
    }

    let workload_client = context.view_resolver.workload_client();
    let existing_block = workload_client
        .get_blocks_range(block.header.height, 1, 10 * 1024 * 1024)
        .await
        .map_err(|e: ChainError| anyhow::anyhow!(e.to_string()))?
        .into_iter()
        .find(|candidate| candidate.header.height == block.header.height);
    let Some(existing_block) = existing_block else {
        return Ok(());
    };

    let existing_hash = existing_block.header.hash().map_err(anyhow::Error::msg)?;
    let incoming_hash = block.header.hash().map_err(anyhow::Error::msg)?;
    if existing_hash != incoming_hash {
        return Ok(());
    }
    if existing_block.header.sealed_finality_proof == block.header.sealed_finality_proof
        && existing_block.header.guardian_certificate == block.header.guardian_certificate
    {
        return Ok(());
    }

    let (engine_ref, cv) = {
        let resolver = context.view_resolver.as_ref();
        let default_resolver: &super::view_resolver::DefaultViewResolver<V> =
            match (*resolver).as_any().downcast_ref() {
                Some(r) => r,
                None => {
                    return Err(anyhow::anyhow!(
                        "failed to downcast view resolver for block enrichment"
                    ));
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

    engine_ref
        .lock()
        .await
        .handle_block_proposal::<CS, ST>(block.clone(), &&cv)
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    workload_client
        .update_block_header(block.clone())
        .await
        .map_err(|e: ChainError| anyhow::anyhow!(e.to_string()))?;

    let accepted = observe_live_committed_chain_through_block(
        &engine_ref,
        context.config.consensus_type,
        workload_client.as_ref(),
        block,
    )
    .await?;
    let mut engine = engine_ref.lock().await;
    if accepted {
        engine.reset(block.header.height);
    } else {
        tracing::warn!(
            target: "gossip",
            height = block.header.height,
            "Consensus engine ignored the sealed block enrichment because it was not collapse-backed."
        );
    }
    drop(engine);

    let enriched_tip_is_current = context
        .last_committed_block
        .as_ref()
        .map(|candidate| candidate.header.height)
        == Some(block.header.height);
    if enriched_tip_is_current && accepted {
        context.last_committed_block = Some(block.clone());
    }

    tracing::info!(
        target: "gossip",
        event = "block_enrichment_applied",
        height = block.header.height,
        view = block.header.view
    );
    Ok(())
}

pub(super) async fn maybe_request_asymptote_sealed_enrichment<CS, ST, CE, V>(
    context: &MainLoopContext<CS, ST, CE, V>,
    height: u64,
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
    if !matches!(context.config.aft_safety_mode, AftSafetyMode::Asymptote) || height == 0 {
        return;
    }

    let swarm_sender = context.swarm_commander.clone();
    let peers_ref = context.known_peers_ref.clone();
    tokio::spawn(async move {
        for delay in [
            Duration::from_millis(200),
            Duration::from_millis(900),
            Duration::from_secs(2),
            Duration::from_secs(5),
        ] {
            tokio::time::sleep(delay).await;
            let peers: Vec<_> = peers_ref.lock().await.iter().cloned().collect();
            if peers.is_empty() {
                continue;
            }
            for peer in peers {
                let _ = swarm_sender
                    .send(SwarmCommand::SendBlocksRequest {
                        peer,
                        since: height.saturating_sub(1),
                        max_blocks: 1,
                        max_bytes: AFT_ENRICHMENT_SYNC_MAX_BYTES,
                    })
                    .await;
            }
        }
    });
}
