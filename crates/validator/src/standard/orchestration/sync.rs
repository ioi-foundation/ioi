// Path: crates/validator/src/standard/orchestration/sync.rs

//! The part of the libp2p implementation handling the BlockSync trait.

use super::context::{MainLoopContext, SyncProgress};
use ioi_api::{
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    state::{StateManager, Verifier},
};
// [+] CORRECTED: Import the canonical definitions from the network crate.
use ioi_networking::libp2p::{SwarmCommand, SyncResponse};
use ioi_networking::traits::NodeState;
use ioi_types::app::{Block, ChainTransaction};
use libp2p::{request_response::ResponseChannel, PeerId};
use serde::Serialize;
use std::fmt::Debug;

// [-] REMOVED: Unused imports flagged by the compiler.
// use ioi_networking::libp2p::SyncRequest;
// use tokio::sync::Mutex;

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
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
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
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof> + Clone + Send + Sync + 'static,
{
    let workload_client = match context
        .view_resolver
        .as_any()
        .downcast_ref::<super::view_resolver::DefaultViewResolver<V>>()
    {
        Some(resolver) => resolver.workload_client(),
        None => return,
    };
    let blocks = workload_client
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
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
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
            Err(_) => return, // Cannot verify peer if we don't know our own genesis
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
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
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
            *context.node_state.lock().await = NodeState::Synced;
            context.sync_progress = None;
            log::info!("Block sync complete!");
        }
        return;
    }

    let Some(first_block) = blocks.get(0) else {
        return;
    };
    let first_block_height = first_block.header.height;
    if first_block_height != progress.next + 1 {
        // Reorg or bad peer, reset sync
        context.sync_progress = None;
        return;
    }

    let workload_client = match context
        .view_resolver
        .as_any()
        .downcast_ref::<super::view_resolver::DefaultViewResolver<V>>()
    {
        Some(resolver) => resolver.workload_client(),
        None => {
            context.sync_progress = None;
            return;
        }
    };

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
        *context.node_state.lock().await = NodeState::Synced;
        context.sync_progress = None;
        log::info!("Block sync complete!");
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
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
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

/// Handles a failure to get a response from a peer, potentially resetting sync state
/// and finding a new peer to sync from.
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
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof> + Clone + Send + Sync + 'static,
{
    let Some(progress) = context.sync_progress.as_mut() else {
        return;
    };

    if progress.target == Some(failed_peer) {
        progress.inflight = false;
        progress.target = None;

        // Find a new peer to sync from that isn't the one that just failed.
        let new_target = {
            let known_peers = context.known_peers_ref.lock().await;
            known_peers.iter().find(|p| **p != failed_peer).cloned()
        };

        if let Some(new_peer) = new_target {
            // Log the fallback action for observability in tests.
            tracing::info!(
                target: "orchestration",
                "Sync target {} failed. Switching to new target {}",
                failed_peer,
                new_peer
            );
            progress.target = Some(new_peer);
            // Kick off the sync with the new peer immediately.
            request_next_batch(context).await;
        } else {
            tracing::warn!(
                target: "orchestration",
                "Sync target {} failed. No other peers available to continue sync.",
                failed_peer
            );
            // The node remains in Syncing state. The discoverer will eventually find a new peer.
        }
    }
}