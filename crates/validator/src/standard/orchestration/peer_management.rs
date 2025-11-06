// Path: crates/validator/src/standard/orchestration/peer_management.rs
use super::context::MainLoopContext;
use ioi_networking::libp2p::SwarmCommand;
use ioi_types::app::ChainTransaction;
use ioi_api::{
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    state::{StateManager, Verifier},
};
use libp2p::PeerId;
use serde::Serialize;
use std::fmt::Debug;

/// Handles a new peer connecting.
pub async fn handle_connection_established<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    peer_id: PeerId,
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
    tracing::info!(target: "network", event = "peer_connected", %peer_id);
    context.known_peers_ref.lock().await.insert(peer_id);
    context
        .swarm_commander
        .send(SwarmCommand::SendStatusRequest(peer_id))
        .await
        .ok();
}

/// Handles a peer disconnecting.
pub async fn handle_connection_closed<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    peer_id: PeerId,
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
    tracing::info!(target: "network", event = "peer_disconnected", %peer_id);
    context.known_peers_ref.lock().await.remove(&peer_id);
}
