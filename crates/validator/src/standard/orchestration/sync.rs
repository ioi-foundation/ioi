// Path: crates/validator/src/standard/orchestration/sync.rs

//! The part of the libp2p implementation handling the BlockSync trait.

use super::context::{MainLoopContext, SyncProgress};
use ioi_api::{
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    state::{StateManager, Verifier},
};
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

// --- BlockSync Trait Implementation ---

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
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof> + Clone + Send + Sync + 'static,
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
    context
        .swarm_commander
        .send(SwarmCommand::SendStatusResponse {
            channel,
            height,
            head_hash,
            chain_id,
            genesis_root,
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
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof> + Clone + Send + Sync + 'static,
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
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof> + Clone + Send + Sync + 'static,
{
    let our_height = context
        .last_committed_block
        .as_ref()
        .map(|b| b.header.height)
        .unwrap_or(0);

    if peer_height > our_height {
        let our_chain_id = context.chain_id;
        let our_genesis_root = match context.view_resolver.genesis_root().await {
            Ok(root) => root,
            Err(_) => return,
        };
        if peer_chain_id != our_chain_id || peer_genesis_root != our_genesis_root {
            log::warn!(
                "Ignoring peer {} for sync due to chain identity mismatch.",
                peer
            );
            return;
        }

        tracing::info!(
            target: "orchestration",
            "Initiating or re-initiating sync: target={}",
            peer
        );
        *context.node_state.lock().await = NodeState::Syncing;
        context.sync_progress = Some(SyncProgress {
            target: Some(peer),
            tip: peer_height,
            next: our_height,
            inflight: false,
            req_id: 0,
        });
        request_next_batch(context).await;
    } else if *context.node_state.lock().await == NodeState::Syncing
        && context.sync_progress.is_none()
    {
        *context.node_state.lock().await = NodeState::Synced;
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
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof> + Clone + Send + Sync + 'static,
{
    let Some(progress) = context.sync_progress.as_mut() else {
        return;
    };
    if progress.target != Some(peer) {
        return;
    }
    progress.inflight = false;

    if blocks.is_empty() {
        if progress.next >= progress.tip {
            finish_sync(context).await;
        }
        return;
    }

    let Some(first_block) = blocks.get(0) else {
        return;
    };
    let first_block_height = first_block.header.height;
    if first_block_height != progress.next + 1 {
        context.sync_progress = None;
        return;
    }

    let workload_client = context.view_resolver.workload_client();

    for block in blocks {
        if workload_client.process_block(block.clone()).await.is_err() {
            context.sync_progress = None;
            return;
        }
        progress.next = block.header.height;
        context.last_committed_block = Some(block);
    }

    if progress.next < progress.tip {
        request_next_batch(context).await;
    } else {
        finish_sync(context).await;
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
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof> + Clone + Send + Sync + 'static,
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

async fn request_next_batch<CS, ST, CE, V>(context: &mut MainLoopContext<CS, ST, CE, V>)
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
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof> + Clone + Send + Sync + 'static,
{
    if let Some(progress) = context.sync_progress.as_mut() {
        if progress.inflight {
            return;
        }
        let Some(target_peer) = progress.target else {
            return;
        };
        progress.inflight = true;
        progress.req_id += 1;
        context
            .swarm_commander
            .send(SwarmCommand::SendBlocksRequest {
                peer: target_peer,
                since: progress.next,
                max_blocks: 50,
                max_bytes: 4 * 1024 * 1024,
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
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof> + Clone + Send + Sync + 'static,
{
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
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof> + Clone + Send + Sync + 'static,
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

                // 2. Feed back to local engine to update local QC aggregation
                let mut engine = context.consensus_engine_ref.lock().await;
                if let Err(e) = engine.handle_vote(vote).await {
                    tracing::warn!(target: "consensus", "Failed to handle catchup vote: {}", e);
                }

                tracing::info!(
                    target: "consensus",
                    "Cast Catchup Vote for block {} (H={} V={})",
                    hex::encode(&vote_hash[..4]),
                    vote_height,
                    vote_view
                );
            }
        }
    }
}
