// Path: crates/validator/src/standard/orchestration/sync.rs
use super::context::MainLoopContext;
use depin_sdk_api::{commitment::CommitmentScheme, state::StateManager};
use depin_sdk_consensus::ConsensusEngine;
use depin_sdk_network::{
    libp2p::{SwarmCommand, SyncResponse},
    traits::NodeState,
};
use depin_sdk_types::app::{Block, ChainTransaction};
use libp2p::{request_response::ResponseChannel, PeerId};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// Handles a request for our node's status.
pub async fn handle_status_request<CS, ST, CE>(
    context: &mut MainLoopContext<CS, ST, CE>,
    _peer: PeerId,
    channel: ResponseChannel<SyncResponse>,
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
    let height = context
        .workload_client
        .get_status()
        .await
        .map_or(0, |s| s.height);
    context
        .swarm_commander
        .send(SwarmCommand::SendStatusResponse(channel, height))
        .await
        .ok();
}

/// Handles a request for blocks from a peer.
pub async fn handle_blocks_request<CS, ST, CE>(
    context: &mut MainLoopContext<CS, ST, CE>,
    _peer: PeerId,
    since: u64,
    channel: ResponseChannel<SyncResponse>,
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
    let blocks = context.chain_ref.lock().await.get_blocks_since(since);
    context
        .swarm_commander
        .send(SwarmCommand::SendBlocksResponse(channel, blocks))
        .await
        .ok();
}

/// Handles receiving a status response from a peer, potentially triggering a sync.
pub async fn handle_status_response<CS, ST, CE>(
    context: &mut MainLoopContext<CS, ST, CE>,
    peer: PeerId,
    peer_height: u64,
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
    let our_height = context
        .workload_client
        .get_status()
        .await
        .map_or(0, |s| s.height);
    if peer_height > our_height {
        context
            .swarm_commander
            .send(SwarmCommand::SendBlocksRequest(peer, our_height))
            .await
            .ok();
    } else if *context.node_state.lock().await == NodeState::Syncing {
        *context.node_state.lock().await = NodeState::Synced;
        log::info!("[Orchestrator] Synced with peer {}. State -> Synced.", peer);
    }
}

/// Handles receiving a block response from a peer during sync.
pub async fn handle_blocks_response<CS, ST, CE>(
    context: &mut MainLoopContext<CS, ST, CE>,
    _peer: PeerId,
    blocks: Vec<Block<ChainTransaction>>,
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
    for block in blocks {
        if context.workload_client.process_block(block).await.is_err() {
            log::error!("[Orchestrator] Workload failed to process synced block.");
            break;
        }
    }
    if *context.node_state.lock().await == NodeState::Syncing {
        *context.node_state.lock().await = NodeState::Synced;
        log::info!("[Orchestrator] Finished processing blocks. State -> Synced.");
    }
}
