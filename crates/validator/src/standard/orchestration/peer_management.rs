// Path: crates/validator/src/standard/orchestration/peer_management.rs
use super::context::MainLoopContext;
use ioi_api::{
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    state::{StateManager, Verifier},
};
use ioi_networking::libp2p::SwarmCommand;
use ioi_types::app::ChainTransaction;
use libp2p::PeerId;
use serde::Serialize;
use std::fmt::Debug;

/// Handles a new peer connecting to the swarm.
/// Records the peer and sends a `GetStatus` request to initiate a handshake.
pub async fn handle_connection_established<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    peer_id: PeerId,
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
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
{
    tracing::info!(target: "network", event = "peer_connected", %peer_id);
    context.known_peers_ref.lock().await.insert(peer_id);
    context
        .swarm_commander
        .send(SwarmCommand::SendStatusRequest(peer_id))
        .await
        .ok();
}

/// Handles the swarm erasing an unproven PQ enrollment for a still-connected
/// peer. Re-enrollment is derived only from a fresh status exchange (the same
/// path as first contact), never from any retained claim, so a repeat request
/// is the whole recovery. The swarm bounds how often this fires per connection
/// and the session manager keeps its provisional lifetime and per-account caps.
pub async fn handle_pq_enrollment_lost<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    peer_id: PeerId,
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
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
{
    if !context.known_peers_ref.lock().await.contains(&peer_id) {
        tracing::debug!(target: "network", event = "pq_enrollment_lost_for_unknown_peer", %peer_id);
        return;
    }
    tracing::info!(target: "network", event = "pq_enrollment_lost_status_refresh", %peer_id);
    context
        .swarm_commander
        .send(SwarmCommand::SendStatusRequest(peer_id))
        .await
        .ok();
}

/// Handles a peer disconnecting from the swarm.
/// Removes the peer from the known peers set.
pub async fn handle_connection_closed<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    peer_id: PeerId,
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
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
{
    tracing::info!(target: "network", event = "peer_disconnected", %peer_id);
    context.known_peers_ref.lock().await.remove(&peer_id);
    context.peer_accounts_ref.lock().await.remove(&peer_id);
}
