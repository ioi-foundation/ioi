// Path: crates/validator/src/standard/orchestration/events.rs

use super::context::MainLoopContext;
use super::{gossip, oracle, peer_management, sync as sync_handlers};
use ioi_api::{
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    crypto::{SerializableKey, SigningKeyPair},
    state::{StateManager, Verifier},
};

use ioi_networking::libp2p::{NetworkEvent, SwarmCommand}; // [FIX] Added SwarmCommand import
use ioi_networking::traits::NodeState;
use ioi_types::app::{account_id_from_key_material, ChainTransaction, SignatureSuite};
use ioi_types::codec;
use parity_scale_codec::{Decode, Encode};
use serde::Serialize;
use std::fmt::Debug;
use std::sync::Arc;
use tokio::sync::Mutex;

// [NEW] Import verification logic and transition handler
use crate::standard::orchestration::transition::execute_kill_switch;
use ioi_consensus::admft::divergence::verify_divergence_proof;
use ioi_types::app::PanicMessage;

pub async fn handle_network_event<CS, ST, CE, V>(
    event: NetworkEvent,
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    match event {
        NetworkEvent::GossipTransaction(tx) => {
            let tx_hash = match tx.hash() {
                Ok(h) => h,
                Err(e) => {
                    tracing::warn!(target: "gossip", "Failed to hash gossiped transaction: {}", e);
                    return;
                }
            };

            let (tx_pool_ref, kick_tx) = {
                let ctx = context_arc.lock().await;
                (ctx.tx_pool_ref.clone(), ctx.consensus_kick_tx.clone())
            };

            let tx_info = match tx.as_ref() {
                ChainTransaction::System(s) => Some((s.header.account_id, s.header.nonce)),
                ChainTransaction::Settlement(s) => Some((s.header.account_id, s.header.nonce)),
                ChainTransaction::Application(a) => match a {
                    ioi_types::app::ApplicationTransaction::DeployContract { header, .. } => {
                        Some((header.account_id, header.nonce))
                    }
                    ioi_types::app::ApplicationTransaction::CallContract { header, .. } => {
                        Some((header.account_id, header.nonce))
                    }
                },
                _ => None,
            };

            {
                tx_pool_ref.add(*tx, tx_hash, tx_info, 0);
                log::debug!("[Orchestrator] Mempool size is now {}", tx_pool_ref.len());
                let _ = kick_tx.send(());
            }
        }
        NetworkEvent::GossipBlock { block, mirror_id } => {
            let node_state = { context_arc.lock().await.node_state.lock().await.clone() };

            // [MODIFIED] Reject standard blocks if in Panic/Transition/Survival modes
            if matches!(
                node_state,
                NodeState::Transitioning | NodeState::SurvivalMode
            ) {
                tracing::debug!(target: "gossip", "Block ignored: Node is in {:?} state.", node_state);
                return;
            }

            if node_state == NodeState::Syncing {
                tracing::debug!(
                    target: "gossip",
                    event = "block_ignored",
                    height = block.header.height,
                    reason = "Node is currently syncing"
                );
                return;
            }

            let (our_ed_id, our_pqc_id_opt, kick_tx) = {
                let ctx = context_arc.lock().await;

                let ed_pk = ctx.local_keypair.public().encode_protobuf();
                let ed_id = account_id_from_key_material(SignatureSuite::ED25519, &ed_pk)
                    .unwrap_or_default();

                let pqc_id_opt = ctx.pqc_signer.as_ref().map(|kp| {
                    let pqc_pk: Vec<u8> = SigningKeyPair::public_key(kp).to_bytes();
                    account_id_from_key_material(SignatureSuite::ML_DSA_44, &pqc_pk)
                        .unwrap_or_default()
                });

                (ed_id, pqc_id_opt, ctx.consensus_kick_tx.clone())
            };

            let producer_id = block.header.producer_pubkey_hash;
            let is_ours = producer_id == our_ed_id
                || our_pqc_id_opt
                    .map(|id: [u8; 32]| id == producer_id)
                    .unwrap_or(false);

            if is_ours {
                tracing::info!(target: "orchestration",
                    "[Orchestrator] Skipping verification of our own gossiped block #{}.",
                    block.header.height
                );
                let _ = kick_tx.send(());
                return;
            }

            let mut ctx = context_arc.lock().await;
            gossip::handle_gossip_block(&mut ctx, block, mirror_id).await
        }

        NetworkEvent::ConsensusVoteReceived { vote, from } => {
            // [MODIFIED] Ignore votes if panicked
            let node_state = { context_arc.lock().await.node_state.lock().await.clone() };
            if matches!(
                node_state,
                NodeState::Transitioning | NodeState::SurvivalMode
            ) {
                return;
            }

            let (engine_ref, kick_tx) = {
                let ctx = context_arc.lock().await;
                (
                    ctx.consensus_engine_ref.clone(),
                    ctx.consensus_kick_tx.clone(),
                )
            };

            let mut engine = engine_ref.lock().await;

            tracing::debug!(target: "consensus",
                event = "vote_received",
                %from,
                height = vote.height,
                view = vote.view,
                block = hex::encode(&vote.block_hash[..4])
            );

            if let Err(e) = engine.handle_vote(vote).await {
                tracing::warn!(target: "consensus", "Failed to handle incoming vote from {}: {}", from, e);
            } else {
                let _ = kick_tx.send(());
            }
        }

        NetworkEvent::ViewChangeVoteReceived { vote, from } => {
            // [MODIFIED] Ignore view changes if panicked
            let node_state = { context_arc.lock().await.node_state.lock().await.clone() };
            if matches!(
                node_state,
                NodeState::Transitioning | NodeState::SurvivalMode
            ) {
                return;
            }

            let (engine_ref, kick_tx) = {
                let ctx = context_arc.lock().await;
                (
                    ctx.consensus_engine_ref.clone(),
                    ctx.consensus_kick_tx.clone(),
                )
            };

            let mut engine = engine_ref.lock().await;

            match codec::to_bytes_canonical(&vote) {
                Ok(vote_blob) => {
                    if let Err(e) = engine.handle_view_change(from, &vote_blob).await {
                        tracing::warn!(target: "consensus", "Failed to handle view change from {}: {}", from, e);
                    } else {
                        let _ = kick_tx.send(());
                    }
                }
                Err(e) => {
                    tracing::warn!(target: "consensus", "Failed to serialize incoming view change vote: {}", e);
                }
            }
        }

        // [NEW] Handle Protocol Apex Panic (Kill Switch)
        NetworkEvent::PanicReceived { panic, from } => {
            tracing::warn!(target: "orchestration", "Received Panic Message from peer {}", from);

            // 1. Verify Divergence Proof
            match verify_divergence_proof(&panic.proof) {
                Ok(true) => {
                    tracing::error!(target: "orchestration", "Panic Validated! Hardware Compromise Confirmed.");

                    // 2. Trigger Kill Switch (Transition Node State)
                    if let Err(e) = execute_kill_switch(context_arc, panic.proof.clone()).await {
                        tracing::error!(target: "orchestration", "Failed to execute Kill Switch: {}", e);
                    }

                    // 3. Re-gossip (Epidemic Propagation)
                    if let Ok(data) = codec::to_bytes_canonical(&panic) {
                        // Must unlock context to get commander, but execute_kill_switch already used it.
                        // We re-acquire briefly.
                        let swarm_sender = context_arc.lock().await.swarm_commander.clone();
                        let _ = swarm_sender.send(SwarmCommand::BroadcastPanic(data)).await;
                    }
                }
                Ok(false) => {
                    tracing::warn!(target: "orchestration", "Panic invalid: Proof does not show divergence.");
                }
                Err(e) => {
                    tracing::warn!(target: "orchestration", "Panic malformed: {}", e);
                }
            }
        }

        // [NEW] Echo Handler
        NetworkEvent::EchoReceived { echo, from } => {
            // [MODIFIED] Ignore echoes if panicked
            let node_state = { context_arc.lock().await.node_state.lock().await.clone() };
            if matches!(
                node_state,
                NodeState::Transitioning | NodeState::SurvivalMode
            ) {
                return;
            }

            tracing::debug!(target: "consensus", "Echo received from {} (H={} V={})", from, echo.height, echo.view);
            // In a full integration, we'd call `engine.handle_echo(echo)`.
            // For now, assume engine handles internal gossip or we extend trait later.
        }

        // [NEW] Handle A-PMFT Sample Request
        NetworkEvent::SampleRequestReceived {
            peer,
            height: _,
            channel,
        } => {
            let (engine_ref, swarm_sender) = {
                let ctx = context_arc.lock().await;
                (
                    ctx.consensus_engine_ref.clone(),
                    ctx.swarm_commander.clone(),
                )
            };

            // We lock the engine via the Consensus wrapper helper
            let mut engine = engine_ref.lock().await;

            // This method `get_apmft_tip` is defined on the `Consensus` enum wrapper in `consensus/src/lib.rs`
            // It safely downcasts/matches the internal engine variant.
            // If the engine is A-DMFT, it returns None.
            if let Some((block_hash, confidence)) = engine.get_apmft_tip() {
                tracing::debug!(target: "apmft", "Replying to sample from {}: {:?} (C={})", peer, block_hash, confidence);
                let _ = swarm_sender
                    .send(SwarmCommand::SendSampleResponse {
                        channel,
                        block_hash,
                        confidence,
                    })
                    .await;
            }
        }

        // [NEW] Handle A-PMFT Sample Response
        NetworkEvent::SampleResponseReceived {
            peer,
            block_hash,
            confidence,
        } => {
            let engine_ref = context_arc.lock().await.consensus_engine_ref.clone();
            let mut engine = engine_ref.lock().await;

            // Feed sample back to engine
            tracing::debug!(target: "apmft", "Sample received from {}: {:?} (C={})", peer, block_hash, confidence);
            engine.feed_apmft_sample(block_hash);
        }

        NetworkEvent::ConnectionEstablished(peer_id) => {
            let mut ctx = context_arc.lock().await;
            peer_management::handle_connection_established(&mut ctx, peer_id).await
        }
        NetworkEvent::ConnectionClosed(peer_id) => {
            let mut ctx = context_arc.lock().await;
            peer_management::handle_connection_closed(&mut ctx, peer_id).await
        }
        NetworkEvent::StatusRequest(peer, channel) => {
            let mut ctx = context_arc.lock().await;
            sync_handlers::handle_status_request(&mut ctx, peer, channel).await
        }
        NetworkEvent::BlocksRequest {
            peer,
            since,
            max_blocks,
            max_bytes,
            channel,
        } => {
            let mut ctx = context_arc.lock().await;
            sync_handlers::handle_blocks_request(
                &mut ctx, peer, since, max_blocks, max_bytes, channel,
            )
            .await
        }
        NetworkEvent::StatusResponse {
            peer,
            height,
            head_hash,
            chain_id,
            genesis_root,
        } => {
            let mut ctx = context_arc.lock().await;
            sync_handlers::handle_status_response(
                &mut ctx,
                peer,
                height,
                head_hash,
                chain_id,
                genesis_root,
            )
            .await
        }
        NetworkEvent::BlocksResponse(peer, blocks) => {
            let mut ctx = context_arc.lock().await;
            sync_handlers::handle_blocks_response(&mut ctx, peer, blocks).await
        }
        NetworkEvent::OracleAttestationReceived { from, attestation } => {
            let mut ctx = context_arc.lock().await;
            oracle::handle_oracle_attestation_received(&mut ctx, from, attestation).await
        }
        NetworkEvent::OutboundFailure(peer) => {
            let mut ctx = context_arc.lock().await;
            sync_handlers::handle_outbound_failure(&mut ctx, peer).await
        }
        _ => {}
    }
}
