// Path: crates/validator/src/standard/orchestration/sync.rs

//! The part of the libp2p implementation handling the BlockSync trait.

use super::context::MainLoopContext;
use depin_sdk_api::{
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    state::{StateManager, Verifier},
};
use depin_sdk_network::{
    libp2p::{SwarmCommand, SyncResponse},
    traits::NodeState,
};
use depin_sdk_types::app::{Block, ChainTransaction};
use libp2p::{request_response::ResponseChannel, PeerId};
use serde::Serialize;
use std::fmt::Debug;

/// Converts a vector of `api` crate Blocks to `types` crate Blocks.
/// This is necessary because the `AppChain` trait deals with `api` types,
/// while the networking layer deals with `types` types for serialization.
fn convert_api_blocks_to_types(
    api_blocks: Vec<depin_sdk_api::app::Block<depin_sdk_api::app::ChainTransaction>>,
) -> Vec<depin_sdk_types::app::Block<depin_sdk_types::app::ChainTransaction>> {
    api_blocks
        .into_iter()
        .filter_map(|api_block| {
            // Since they are SCALE compatible, we can serialize and deserialize.
            let bytes = match depin_sdk_types::codec::to_bytes_canonical(&api_block) {
                Ok(b) => b,
                Err(e) => {
                    log::error!("Failed to serialize api::Block for conversion: {}", e);
                    return None;
                }
            };
            match depin_sdk_types::codec::from_bytes_canonical(&bytes) {
                Ok(b) => Some(b),
                Err(e) => {
                    log::error!(
                        "Failed to deserialize into types::Block for conversion: {}",
                        e
                    );
                    None
                }
            }
        })
        .collect()
}

/// Handles a request for our node's status.
pub async fn handle_status_request<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    _peer: PeerId,
    channel: ResponseChannel<SyncResponse>,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof> + Clone + Send + Sync + 'static,
{
    let workload_client = match context
        .view_resolver
        .as_any()
        .downcast_ref::<super::view_resolver::DefaultViewResolver<V>>()
    {
        Some(resolver) => resolver.workload_client(),
        None => {
            log::error!("CRITICAL: Could not downcast ViewResolver in handle_status_request.");
            return;
        }
    };
    let height = workload_client.get_status().await.map_or(0, |s| s.height);
    context
        .swarm_commander
        .send(SwarmCommand::SendStatusResponse(channel, height))
        .await
        .ok();
}

/// Handles a request for blocks from a peer.
pub async fn handle_blocks_request<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    _peer: PeerId,
    since: u64,
    channel: ResponseChannel<SyncResponse>,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof> + Clone + Send + Sync + 'static,
{
    let api_blocks = context.chain_ref.lock().await.get_blocks_since(since);
    let blocks = convert_api_blocks_to_types(api_blocks);
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
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof> + Clone + Send + Sync + 'static,
{
    let workload_client = match context
        .view_resolver
        .as_any()
        .downcast_ref::<super::view_resolver::DefaultViewResolver<V>>()
    {
        Some(resolver) => resolver.workload_client(),
        None => {
            log::error!("CRITICAL: Could not downcast ViewResolver in handle_status_response.");
            return;
        }
    };
    let our_height = workload_client.get_status().await.map_or(0, |s| s.height);
    if peer_height > our_height {
        context
            .swarm_commander
            .send(SwarmCommand::SendBlocksRequest(peer, our_height))
            .await
            .ok();
    } else if *context.node_state.lock().await == NodeState::Syncing {
        *context.node_state.lock().await = NodeState::Synced;
        tracing::info!(target: "orchestration", event = "synced", %peer);
    }
}

/// Handles receiving a block response from a peer during sync.
pub async fn handle_blocks_response<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    _peer: PeerId,
    blocks: Vec<Block<ChainTransaction>>,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof> + Clone + Send + Sync + 'static,
{
    let mut all_blocks_processed_successfully = true;
    for block in blocks {
        // The orchestrator's job is just to forward the block. The workload handles processing.
        // The two-phase commit logic lives inside the workload's RPC handler.
        let workload_client = match context
            .view_resolver
            .as_any()
            .downcast_ref::<super::view_resolver::DefaultViewResolver<V>>()
        {
            Some(resolver) => resolver.workload_client(),
            None => {
                log::error!("CRITICAL: Could not downcast ViewResolver in handle_blocks_response.");
                all_blocks_processed_successfully = false;
                break;
            }
        };
        if workload_client.process_block(block).await.is_err() {
            all_blocks_processed_successfully = false;
            break;
        }
    }
    if all_blocks_processed_successfully {
        *context.node_state.lock().await = NodeState::Synced;
        tracing::info!(target: "orchestration", event = "sync_complete");
    }
}
