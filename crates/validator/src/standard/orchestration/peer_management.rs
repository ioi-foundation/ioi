// Path: crates/validator/src/standard/orchestration/peer_management.rs
use super::context::MainLoopContext;
use depin_sdk_api::{
    commitment::CommitmentScheme, consensus::ConsensusEngine, state::StateManager,
};
use depin_sdk_network::libp2p::SwarmCommand;
use depin_sdk_types::app::ChainTransaction;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// Handles a new peer connecting.
pub async fn handle_connection_established<CS, ST, CE>(
    context: &mut MainLoopContext<CS, ST, CE>,
    peer_id: PeerId,
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
    log::info!(
        "[Orchestrator] Connection established with peer {}",
        peer_id
    );
    context.known_peers_ref.lock().await.insert(peer_id);
    context
        .swarm_commander
        .send(SwarmCommand::SendStatusRequest(peer_id))
        .await
        .ok();
}

/// Handles a peer disconnecting.
pub async fn handle_connection_closed<CS, ST, CE>(
    context: &mut MainLoopContext<CS, ST, CE>,
    peer_id: PeerId,
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
    context.known_peers_ref.lock().await.remove(&peer_id);
}
