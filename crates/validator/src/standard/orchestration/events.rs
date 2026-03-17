// Path: crates/validator/src/standard/orchestration/events.rs

use super::context::MainLoopContext;
use super::{gossip, oracle, peer_management, sync as sync_handlers};
use ioi_api::{
    commitment::CommitmentScheme,
    consensus::{ConsensusControl, ConsensusEngine},
    crypto::{SerializableKey, SigningKeyPair},
    state::{StateManager, Verifier},
};

use ioi_ipc::public::TxStatus;
use ioi_networking::libp2p::{NetworkEvent, SwarmCommand};
use ioi_types::app::{account_id_from_key_material, ChainTransaction, SignatureSuite};
use ioi_types::codec;
use parity_scale_codec::{Decode, Encode};
use serde::Serialize;
use std::fmt::Debug;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::metrics::rpc_metrics as metrics;
use crate::standard::orchestration::context::TxStatusEntry;
use crate::standard::orchestration::transition::execute_divergence_response;
use ioi_consensus::aft::guardian_majority::divergence::verify_divergence_proof;
use ioi_types::config::AftSafetyMode;

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
    CE: ConsensusEngine<ChainTransaction> + ConsensusControl + Send + Sync + 'static,
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

            let (
                tx_pool_ref,
                consensus_kick_tx,
                receipt_map,
                tx_status_cache,
                consensus_kick_scheduled,
            ) = {
                let ctx = context_arc.lock().await;
                (
                    ctx.tx_pool_ref.clone(),
                    ctx.consensus_kick_tx.clone(),
                    ctx.receipt_map.clone(),
                    ctx.tx_status_cache.clone(),
                    ctx.consensus_kick_scheduled.clone(),
                )
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
            let add_result = tx_pool_ref.add(*tx, tx_hash, tx_info, 0);

            if !matches!(
                add_result,
                crate::standard::orchestration::mempool::AddResult::Rejected(_)
            ) {
                if !matches!(
                    add_result,
                    crate::standard::orchestration::mempool::AddResult::Known
                ) {
                    metrics().inc_mempool_transactions_added();
                }
                metrics().set_mempool_size(tx_pool_ref.len() as f64);
                let tx_hash_hex = hex::encode(tx_hash);
                {
                    let mut receipts = receipt_map.lock().await;
                    receipts.put(tx_hash, tx_hash_hex.clone());
                }
                {
                    let mut cache = tx_status_cache.lock().await;
                    cache.put(
                        tx_hash_hex,
                        TxStatusEntry {
                            status: TxStatus::InMempool,
                            error: None,
                            block_height: None,
                        },
                    );
                }
            }

            if !matches!(
                add_result,
                crate::standard::orchestration::mempool::AddResult::Rejected(_)
            ) {
                if !matches!(
                    add_result,
                    crate::standard::orchestration::mempool::AddResult::Known
                ) {
                    // This transaction already arrived through the network. Admit it locally and
                    // wake consensus, but do not re-publish it into the same gossip mesh or we
                    // create an amplification loop under burst load.
                    crate::standard::orchestration::schedule_consensus_kick(
                        &consensus_kick_tx,
                        &consensus_kick_scheduled,
                    );
                }
            }
        }
        NetworkEvent::GossipBlock {
            block,
            mirror_id,
            from,
        } => {
            let is_quarantined = {
                let ctx = context_arc.lock().await;
                ctx.is_quarantined.load(std::sync::atomic::Ordering::SeqCst)
            };

            if is_quarantined {
                tracing::debug!(target: "gossip", "Block ignored: node is quarantined.");
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
            gossip::handle_gossip_block(&mut ctx, block, mirror_id, from).await
        }

        NetworkEvent::ConsensusVoteReceived { vote, from } => {
            let is_quarantined = context_arc
                .lock()
                .await
                .is_quarantined
                .load(std::sync::atomic::Ordering::SeqCst);
            if is_quarantined {
                return;
            }

            let (engine_ref, kick_tx, swarm_sender) = {
                let ctx = context_arc.lock().await;
                (
                    ctx.consensus_engine_ref.clone(),
                    ctx.consensus_kick_tx.clone(),
                    ctx.swarm_commander.clone(),
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
                let pending_qcs = engine.take_pending_quorum_certificates();
                drop(engine);
                for qc in pending_qcs {
                    match codec::to_bytes_canonical(&qc) {
                        Ok(qc_blob) => {
                            let _ = swarm_sender
                                .send(SwarmCommand::BroadcastQuorumCertificate(qc_blob))
                                .await;
                        }
                        Err(e) => {
                            tracing::warn!(
                                target: "consensus",
                                height = qc.height,
                                view = qc.view,
                                "Failed to serialize QC for broadcast: {}",
                                e
                            );
                        }
                    }
                }
                let _ = kick_tx.send(());
            }
        }

        NetworkEvent::QuorumCertificateReceived { qc, from } => {
            let is_quarantined = context_arc
                .lock()
                .await
                .is_quarantined
                .load(std::sync::atomic::Ordering::SeqCst);
            if is_quarantined {
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
            tracing::debug!(
                target: "consensus",
                event = "qc_received",
                %from,
                height = qc.height,
                view = qc.view,
                block = hex::encode(&qc.block_hash[..4])
            );
            if let Err(e) = engine.handle_quorum_certificate(qc).await {
                tracing::warn!(
                    target: "consensus",
                    "Failed to handle incoming quorum certificate from {}: {}",
                    from,
                    e
                );
            } else {
                let _ = kick_tx.send(());
            }
        }

        NetworkEvent::ViewChangeVoteReceived { vote, from } => {
            let is_quarantined = context_arc
                .lock()
                .await
                .is_quarantined
                .load(std::sync::atomic::Ordering::SeqCst);
            if is_quarantined {
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

        NetworkEvent::PanicReceived { panic, from } => {
            tracing::warn!(
                target: "orchestration",
                "Received divergence alert from peer {}",
                from
            );

            match verify_divergence_proof(&panic.proof) {
                Ok(true) => {
                    tracing::error!(
                        target: "orchestration",
                        "Divergence alert validated; quarantining local node and propagating evidence."
                    );

                    if let Err(e) =
                        execute_divergence_response(context_arc, panic.proof.clone()).await
                    {
                        tracing::error!(
                            target: "orchestration",
                            "Failed to execute divergence response: {}",
                            e
                        );
                    }

                    if let Ok(data) = codec::to_bytes_canonical(&panic) {
                        let swarm_sender = context_arc.lock().await.swarm_commander.clone();
                        let _ = swarm_sender.send(SwarmCommand::BroadcastPanic(data)).await;
                    }
                }
                Ok(false) => {
                    tracing::warn!(
                        target: "orchestration",
                        "Divergence alert invalid: proof does not show divergence."
                    );
                }
                Err(e) => {
                    tracing::warn!(target: "orchestration", "Divergence alert malformed: {}", e);
                }
            }
        }

        NetworkEvent::EchoReceived { echo, from } => {
            let is_quarantined = context_arc
                .lock()
                .await
                .is_quarantined
                .load(std::sync::atomic::Ordering::SeqCst);
            if is_quarantined {
                return;
            }

            tracing::debug!(target: "consensus", "Echo received from {} (H={} V={})", from, echo.height, echo.view);
            // In a full integration, we'd call `engine.handle_echo(echo)`.
            // For now, assume engine handles internal gossip or we extend trait later.
        }

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
            let engine = engine_ref.lock().await;

            if let Some((block_hash, confidence)) = engine.experimental_sample_tip() {
                tracing::debug!(
                    target: "experimental_nested_guardian",
                    "Replying to audit sample from {}: {:?} (C={})",
                    peer,
                    block_hash,
                    confidence
                );
                let _ = swarm_sender
                    .send(SwarmCommand::SendSampleResponse {
                        channel,
                        block_hash,
                        confidence,
                    })
                    .await;
            }
        }

        NetworkEvent::SampleResponseReceived {
            peer,
            block_hash,
            confidence,
        } => {
            let engine_ref = context_arc.lock().await.consensus_engine_ref.clone();
            let mut engine = engine_ref.lock().await;

            tracing::debug!(
                target: "experimental_nested_guardian",
                "Audit sample received from {}: {:?} (C={})",
                peer,
                block_hash,
                confidence
            );
            engine.observe_experimental_sample(block_hash);
        }

        NetworkEvent::ConfidenceVoteReceived(_vote) => {
            let is_experimental = {
                let ctx = context_arc.lock().await;
                matches!(
                    ctx.config.aft_safety_mode,
                    AftSafetyMode::ExperimentalNestedGuardian
                )
            };

            if !is_experimental {
                return;
            }

            tracing::debug!(
                target: "experimental_nested_guardian",
                "Received research-only confidence gossip."
            );
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
            validator_account_id,
        } => {
            let mut ctx = context_arc.lock().await;
            sync_handlers::handle_status_response(
                &mut ctx,
                peer,
                height,
                head_hash,
                chain_id,
                genesis_root,
                validator_account_id,
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
