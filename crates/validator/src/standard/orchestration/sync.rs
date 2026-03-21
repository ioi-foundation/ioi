// Path: crates/validator/src/standard/orchestration/sync.rs

//! The part of the libp2p implementation handling the BlockSync trait.

use super::{
    context::{MainLoopContext, SyncProgress},
    gossip,
};
use ioi_api::{
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    state::{StateManager, Verifier},
};
use ioi_ipc::public::TxStatus;
use ioi_networking::libp2p::{SwarmCommand, SyncResponse};
use ioi_networking::traits::NodeState;
use ioi_types::app::{Block, ChainTransaction};
use libp2p::{request_response::ResponseChannel, PeerId};
use serde::Serialize;
use std::fmt::Debug;

// [FIX] Imports for catchup voting
use ioi_types::app::{
    account_id_from_key_material, to_root_hash, AccountId, ConsensusVote, SignatureSuite,
};
use ioi_types::codec;
use std::time::Instant;

// --- BlockSync Trait Implementation ---

pub(crate) fn sync_batch_max_bytes() -> u32 {
    std::env::var("IOI_AFT_SYNC_MAX_BYTES")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value >= 4 * 1024 * 1024)
        .unwrap_or(64 * 1024 * 1024)
}

pub(crate) fn sync_batch_max_blocks() -> u32 {
    std::env::var("IOI_AFT_SYNC_MAX_BLOCKS")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(50)
}

pub async fn start_catchup_to_peer<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    peer: PeerId,
    peer_height: u64,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    let local_height = context
        .last_committed_block
        .as_ref()
        .map(|b| b.header.height)
        .unwrap_or(0);

    if peer_height <= local_height {
        return;
    }

    if let Some(progress) = context.sync_progress.as_mut() {
        if peer_height > progress.tip {
            tracing::info!(
                target: "sync",
                %peer,
                local_height,
                previous_tip = progress.tip,
                peer_height,
                current_target = ?progress.target,
                "Extending catch-up sync tip from a gossiped height gap."
            );
            progress.tip = peer_height;
        }

        if progress.target.is_none() {
            progress.target = Some(peer);
        }

        if !progress.inflight {
            request_next_batch(context).await;
        }
        return;
    }

    tracing::info!(
        target: "sync",
        %peer,
        local_height,
        peer_height,
        "Starting catch-up sync from a gossiped height gap."
    );

    *context.node_state.lock().await = NodeState::Syncing;
    context.sync_progress = Some(SyncProgress {
        target: Some(peer),
        tip: peer_height,
        next: local_height,
        inflight: false,
        req_id: 0,
        requested_at: Instant::now(),
    });
    request_next_batch(context).await;
}

/// Handles a request for our node's status.
pub async fn handle_status_request<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    _peer: PeerId,
    channel: ResponseChannel<SyncResponse>,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    let (height, head_hash, chain_id) = {
        let chain = context.chain_ref.lock().await;
        let status = (*chain).status();
        let head_hash = (*chain)
            .get_block(status.height)
            .and_then(|b| b.header.hash().ok())
            .and_then(|h| h.try_into().ok())
            .unwrap_or([0; 32]);
        (status.height, head_hash, context.chain_id)
    };
    let genesis_root = context
        .view_resolver
        .genesis_root()
        .await
        .unwrap_or_default();
    let validator_account_id = Some(AccountId(
        account_id_from_key_material(
            SignatureSuite::ED25519,
            &context.local_keypair.public().encode_protobuf(),
        )
        .unwrap_or_default(),
    ));
    tracing::info!(
        target: "sync",
        %_peer,
        height,
        head = %hex::encode(&head_hash[..4]),
        chain_id = chain_id.0,
        genesis_root = %hex::encode(&genesis_root[..4.min(genesis_root.len())]),
        "Responding to status request."
    );
    context
        .swarm_commander
        .send(SwarmCommand::SendStatusResponse {
            channel,
            height,
            head_hash,
            chain_id,
            genesis_root,
            validator_account_id,
        })
        .await
        .ok();
}

/// Handles a request for blocks from a peer.
pub async fn handle_blocks_request<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    _peer: PeerId,
    since: u64,
    max_blocks: u32,
    max_bytes: u32,
    channel: ResponseChannel<SyncResponse>,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    let blocks = context
        .view_resolver
        .workload_client()
        .get_blocks_range(since + 1, max_blocks, max_bytes)
        .await
        .unwrap_or_default();
    context
        .swarm_commander
        .send(SwarmCommand::SendBlocksResponse(channel, blocks))
        .await
        .ok();
}

/// Handles receiving a status response from a peer, potentially triggering a sync.
pub async fn handle_status_response<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    peer: PeerId,
    peer_height: u64,
    _peer_head_hash: [u8; 32],
    peer_chain_id: ioi_types::app::ChainId,
    peer_genesis_root: Vec<u8>,
    validator_account_id: Option<AccountId>,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    if let Some(account_id) = validator_account_id {
        context
            .peer_accounts_ref
            .lock()
            .await
            .insert(peer, account_id);
    }

    let our_height = context
        .last_committed_block
        .as_ref()
        .map(|b| b.header.height)
        .unwrap_or(0);

    tracing::info!(
        target: "sync",
        %peer,
        peer_height,
        our_height,
        peer_chain_id = peer_chain_id.0,
        our_chain_id = context.chain_id.0,
        peer_genesis_root = %hex::encode(&peer_genesis_root[..4.min(peer_genesis_root.len())]),
        "Received status response."
    );

    if peer_height > our_height {
        let our_chain_id = context.chain_id;
        let our_genesis_root = match context.view_resolver.genesis_root().await {
            Ok(root) => root,
            Err(_) => return,
        };
        if peer_chain_id != our_chain_id || peer_genesis_root != our_genesis_root {
            log::warn!(
                "Ignoring peer {} for sync due to chain identity mismatch. our_chain_id={} peer_chain_id={} our_genesis={} peer_genesis={}",
                peer,
                our_chain_id.0,
                peer_chain_id.0,
                hex::encode(&our_genesis_root[..4.min(our_genesis_root.len())]),
                hex::encode(&peer_genesis_root[..4.min(peer_genesis_root.len())]),
            );
            return;
        }

        if let Some(progress) = context.sync_progress.as_mut() {
            if peer_height > progress.tip {
                tracing::info!(
                    target: "orchestration",
                    %peer,
                    previous_tip = progress.tip,
                    peer_height,
                    current_target = ?progress.target,
                    "Extending existing sync tip from peer status."
                );
                progress.tip = peer_height;
            }
            if progress.target.is_none() {
                progress.target = Some(peer);
            }
            if !progress.inflight {
                request_next_batch(context).await;
            }
        } else {
            tracing::info!(
                target: "orchestration",
                "Initiating sync: target={}",
                peer
            );
            *context.node_state.lock().await = NodeState::Syncing;
            context.sync_progress = Some(SyncProgress {
                target: Some(peer),
                tip: peer_height,
                next: our_height,
                inflight: false,
                req_id: 0,
                requested_at: Instant::now(),
            });
            request_next_batch(context).await;
        }
    } else {
        let bootstrap_no_catchup = our_height == 0 && peer_height == 0;
        let node_state_is_syncing = *context.node_state.lock().await == NodeState::Syncing;
        if node_state_is_syncing && (context.sync_progress.is_none() || bootstrap_no_catchup) {
            if bootstrap_no_catchup {
                context.sync_progress = None;
            }
            *context.node_state.lock().await = NodeState::Synced;
            let _ = context.consensus_kick_tx.send(());
            tracing::info!(
                target: "orchestration",
                %peer,
                peer_height,
                our_height,
                bootstrap_no_catchup,
                "State -> Synced (status confirmed no catch-up needed)."
            );
        }
    }
}

/// Handles receiving a block response from a peer during sync.
pub async fn handle_blocks_response<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    peer: PeerId,
    blocks: Vec<Block<ChainTransaction>>,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    let mut blocks = blocks;
    let workload_client = context.view_resolver.workload_client();
    if context.sync_progress.is_none() {
        let mut local_height = context
            .last_committed_block
            .as_ref()
            .map(|block| block.header.height)
            .unwrap_or(0);
        if let Ok(status) = workload_client.get_status().await {
            if status.height > local_height {
                if let Ok(Some(workload_tip)) =
                    workload_client.get_block_by_height(status.height).await
                {
                    local_height = workload_tip.header.height;
                    context.last_committed_block = Some(workload_tip);
                }
            }
        }
        let first_new_index = blocks
            .iter()
            .position(|block| block.header.height > local_height);
        let sequential_blocks = first_new_index
            .map(|index| blocks.split_off(index))
            .unwrap_or_default();
        let bootstrap_tip = sequential_blocks
            .last()
            .map(|block| block.header.height)
            .unwrap_or(0);
        let first_height = sequential_blocks
            .first()
            .map(|block| block.header.height)
            .unwrap_or(0);

        if !sequential_blocks.is_empty() && first_height == local_height + 1 {
            tracing::info!(
                target: "sync",
                %peer,
                received_blocks = sequential_blocks.len(),
                local_height,
                bootstrap_tip,
                "Adopting opportunistic sequential blocks response."
            );
            context.sync_progress = Some(SyncProgress {
                target: Some(peer),
                tip: bootstrap_tip,
                next: local_height,
                inflight: false,
                req_id: 0,
                requested_at: Instant::now(),
            });
            blocks = sequential_blocks;
        } else {
            for block in &blocks {
                if let Err(error) = gossip::maybe_apply_block_enrichment(context, block).await {
                    tracing::warn!(
                        target: "sync",
                        %peer,
                        height = block.header.height,
                        view = block.header.view,
                        error = %error,
                        "Rejected opportunistic block enrichment from sync response."
                    );
                }
            }
            return;
        }
    }

    let mut local_height = context
        .last_committed_block
        .as_ref()
        .map(|block| block.header.height)
        .unwrap_or(0);
    if let Ok(status) = workload_client.get_status().await {
        if status.height > local_height {
            if let Ok(Some(workload_tip)) = workload_client.get_block_by_height(status.height).await
            {
                local_height = workload_tip.header.height;
                context.last_committed_block = Some(workload_tip);
            }
        }
    }
    {
        let Some(progress) = context.sync_progress.as_mut() else {
            return;
        };
        if progress.target != Some(peer) {
            return;
        }
        progress.inflight = false;
        if local_height > progress.next {
            tracing::debug!(
                target: "sync",
                %peer,
                local_height,
                previous_next = progress.next,
                tip = progress.tip,
                "Advancing sync cursor to local committed height before applying batch."
            );
            progress.next = local_height;
        }
    }

    let (next, tip) = match context.sync_progress.as_ref() {
        Some(progress) => (progress.next, progress.tip),
        None => return,
    };

    tracing::info!(
        target: "sync",
        %peer,
        received_blocks = blocks.len(),
        next,
        tip,
        "Received blocks response."
    );

    let mut blocks = blocks;
    let already_applied_prefix = blocks
        .iter()
        .take_while(|block| block.header.height <= next)
        .count();
    if already_applied_prefix > 0 {
        tracing::debug!(
            target: "sync",
            %peer,
            already_applied_prefix,
            next,
            tip,
            "Skipping already-applied prefix from sync batch."
        );
        blocks.drain(0..already_applied_prefix);
    }

    if blocks.is_empty() {
        if next >= tip {
            finish_sync(context).await;
        } else {
            tracing::warn!(
                target: "sync",
                %peer,
                next,
                tip,
                "Peer returned only already-applied or empty blocks while we are still behind; retrying sync."
            );
            retry_sync_from_peer_set(context, Some(peer)).await;
        }
        return;
    }

    let Some(first_block) = blocks.get(0) else {
        return;
    };
    let first_block_height = first_block.header.height;
    if first_block_height != next + 1 {
        tracing::warn!(
            target: "sync",
            %peer,
            expected_next = next + 1,
            received_first = first_block_height,
            tip,
            received_blocks = blocks.len(),
            "Dropping sync progress because the peer returned a non-consecutive block batch."
        );
        retry_sync_from_peer_set(context, Some(peer)).await;
        return;
    }

    let receipt_map = context.receipt_map.clone();
    let tx_status_cache = context.tx_status_cache.clone();

    for block in blocks {
        let applying_height = block.header.height;
        let workload_height = workload_client
            .get_status()
            .await
            .map(|status| status.height)
            .unwrap_or_else(|_| {
                context
                    .last_committed_block
                    .as_ref()
                    .map(|candidate| candidate.header.height)
                    .unwrap_or(0)
            });

        if workload_height >= applying_height {
            if workload_height == applying_height {
                match workload_client.update_block_header(block.clone()).await {
                    Ok(()) => {
                        if let Ok(Some(reconciled_block)) =
                            workload_client.get_block_by_height(applying_height).await
                        {
                            context.last_committed_block = Some(reconciled_block);
                        } else {
                            context.last_committed_block = Some(block.clone());
                        }
                        if let Some(progress) = context.sync_progress.as_mut() {
                            progress.next = progress.next.max(applying_height);
                        }
                        tracing::info!(
                            target: "sync",
                            %peer,
                            applying_height,
                            workload_height,
                            "Skipping synced block execution because the local workload already committed this height; reconciled header metadata instead."
                        );
                        continue;
                    }
                    Err(error) => {
                        tracing::warn!(
                            target: "sync",
                            %peer,
                            applying_height,
                            workload_height,
                            error = %error,
                            "Local workload is already at this height, but synced block header reconciliation failed."
                        );
                    }
                }
            } else {
                if let Ok(Some(workload_tip)) =
                    workload_client.get_block_by_height(workload_height).await
                {
                    context.last_committed_block = Some(workload_tip);
                }
                if let Some(progress) = context.sync_progress.as_mut() {
                    progress.next = progress.next.max(workload_height);
                }
                tracing::info!(
                    target: "sync",
                    %peer,
                    applying_height,
                    workload_height,
                    "Skipping synced block execution because the local workload is already ahead."
                );
                continue;
            }
        }

        let processed_block = match workload_client.process_block(block.clone()).await {
            Ok((processed_block, _)) => processed_block,
            Err(error) => {
                tracing::warn!(
                    target: "sync",
                    %peer,
                    expected_next = context
                        .sync_progress
                        .as_ref()
                        .map(|progress| progress.next + 1)
                        .unwrap_or(applying_height),
                    applying_height,
                    tip,
                    error = %error,
                    "Dropping sync progress because applying a synced block failed."
                );
                retry_sync_from_peer_set(context, Some(peer)).await;
                return;
            }
        };
        if let Some(progress) = context.sync_progress.as_mut() {
            progress.next = processed_block.header.height;
        }
        {
            let receipt_guard = receipt_map.lock().await;
            let mut status_guard = tx_status_cache.lock().await;
            for tx in &processed_block.transactions {
                if let Ok(h) = tx.hash() {
                    let tx_hash_hex = receipt_guard
                        .peek(&h)
                        .cloned()
                        .unwrap_or_else(|| hex::encode(h));
                    if let Some(entry) = status_guard.get_mut(&tx_hash_hex) {
                        entry.status = TxStatus::Committed;
                        entry.block_height = Some(applying_height);
                    } else {
                        status_guard.put(
                            tx_hash_hex,
                            crate::standard::orchestration::context::TxStatusEntry {
                                status: TxStatus::Committed,
                                error: None,
                                block_height: Some(applying_height),
                            },
                        );
                    }
                }
            }
        }
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
        context.last_committed_block = Some(processed_block);
    }

    if context
        .sync_progress
        .as_ref()
        .map(|progress| progress.next < progress.tip)
        .unwrap_or(false)
    {
        request_next_batch(context).await;
    } else {
        finish_sync(context).await;
    }
}

async fn retry_sync_from_peer_set<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    failed_peer: Option<PeerId>,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    let Some(progress) = context.sync_progress.as_mut() else {
        return;
    };

    let preferred_target = progress.target.filter(|peer| Some(*peer) != failed_peer);
    progress.inflight = false;
    progress.requested_at = Instant::now();

    let fallback_target = {
        let known_peers = context.known_peers_ref.lock().await;
        known_peers
            .iter()
            .copied()
            .find(|peer| Some(*peer) != failed_peer)
    };

    progress.target = preferred_target.or(fallback_target);

    if progress.target.is_some() {
        request_next_batch(context).await;
    } else {
        tracing::warn!(
            target: "sync",
            failed_peer = ?failed_peer,
            next = progress.next,
            tip = progress.tip,
            "No sync target available after retry request."
        );
    }
}

async fn finish_sync<CS, ST, CE, V>(context: &mut MainLoopContext<CS, ST, CE, V>)
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    *context.node_state.lock().await = NodeState::Synced;
    context.sync_progress = None;
    log::info!("Block sync complete!");

    if let Some(tip_block) = context.last_committed_block.clone() {
        // [FIX] Reset the consensus engine to the new tip so it doesn't think it's behind.
        context
            .consensus_engine_ref
            .lock()
            .await
            .reset(tip_block.header.height);

        // [FIX] Trigger a "Catchup Vote" for the tip block.
        // This ensures that even if we synced the block (instead of producing/voting in real-time),
        // we still contribute to the Quorum Certificate for this height.
        // This is critical for liveness in small clusters where >1/3 of nodes might sync initially.
        trigger_catchup_vote(context, &tip_block).await;
    }
}

pub(crate) async fn request_next_batch<CS, ST, CE, V>(context: &mut MainLoopContext<CS, ST, CE, V>)
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    if let Some(progress) = context.sync_progress.as_mut() {
        if progress.inflight {
            return;
        }
        let Some(target_peer) = progress.target else {
            return;
        };
        tracing::info!(
            target: "sync",
            %target_peer,
            since = progress.next,
            tip = progress.tip,
            "Requesting next sync batch."
        );
        progress.inflight = true;
        progress.req_id += 1;
        progress.requested_at = Instant::now();
        context
            .swarm_commander
            .send(SwarmCommand::SendBlocksRequest {
                peer: target_peer,
                since: progress.next,
                max_blocks: sync_batch_max_blocks(),
                max_bytes: sync_batch_max_bytes(),
            })
            .await
            .ok();
    }
}

pub async fn handle_outbound_failure<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    failed_peer: PeerId,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    // Request/response outbound failures are not a strong enough signal to evict a peer
    // from the cluster view. Under heavy relay load they can fire transiently even while
    // the underlying libp2p connection is still healthy or about to recover. Keep the
    // peer/account mappings intact here and let confirmed transport loss be handled by the
    // connection-closed path instead.

    let Some(progress) = context.sync_progress.as_mut() else {
        return;
    };

    if progress.target == Some(failed_peer) {
        progress.inflight = false;
        progress.target = None;

        let new_target = {
            let known_peers = context.known_peers_ref.lock().await;
            known_peers.iter().find(|p| **p != failed_peer).cloned()
        };

        if let Some(new_peer) = new_target {
            tracing::info!(
                target: "orchestration",
                "Sync target {} failed. Switching to new target {}",
                failed_peer,
                new_peer
            );
            progress.target = Some(new_peer);
            request_next_batch(context).await;
        } else {
            tracing::warn!(
                target: "orchestration",
                "Sync target {} failed. No other peers available.",
                failed_peer
            );
        }
    }
}

/// Helper to cast a vote for a block we just synced, ensuring liveness.
async fn trigger_catchup_vote<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    block: &Block<ChainTransaction>,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    // Don't vote for Genesis (Height 0)
    if block.header.height == 0 {
        return;
    }

    let vote_height = block.header.height;
    let vote_view = block.header.view;
    let vote_hash_vec = block.header.hash().unwrap_or(vec![0u8; 32]);
    let vote_hash = to_root_hash(&vote_hash_vec).unwrap_or([0u8; 32]);

    let our_pk = context.local_keypair.public().encode_protobuf();
    let our_id = AccountId(
        account_id_from_key_material(SignatureSuite::ED25519, &our_pk).unwrap_or([0u8; 32]),
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
                // 1. Broadcast to network
                let _ = context
                    .swarm_commander
                    .send(SwarmCommand::BroadcastVote(vote_blob))
                    .await;

                tracing::info!(
                    target: "consensus",
                    "Broadcast catchup vote for block {} (H={} V={})",
                    hex::encode(&vote_hash[..4]),
                    vote_height,
                    vote_view
                );
            }
        }
    }
}
