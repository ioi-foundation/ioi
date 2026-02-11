// Path: crates/networking/src/libp2p/swarm.rs

use futures::StreamExt;
use libp2p::gossipsub::PublishError;
use libp2p::swarm::SwarmEvent;
use libp2p::{gossipsub, Swarm};
use std::collections::VecDeque;
use tokio::sync::{mpsc, watch};
use tokio::time::{interval, Duration};

use crate::metrics::metrics;
use ioi_types::codec;

use super::behaviour::{SyncBehaviour, SyncBehaviourEvent};
use super::sync::{SyncRequest, SyncResponse};
use super::types::{SwarmCommand, SwarmInternalEvent};

const PENDING_BLOCK_OUTBOX_MAX: usize = 128;
const PENDING_VOTE_OUTBOX_MAX: usize = 256;

/// Enqueues a block for later gossiping, dropping the oldest if the outbox is full.
fn enqueue_block(pending: &mut VecDeque<Vec<u8>>, data: Vec<u8>) {
    if pending.len() >= PENDING_BLOCK_OUTBOX_MAX {
        pending.pop_front();
        tracing::warn!(target: "gossip", "outbox full; dropping oldest pending block");
    }
    pending.push_back(data);
}

fn enqueue_vote(
    pending: &mut VecDeque<(Vec<u8>, gossipsub::IdentTopic)>,
    data: Vec<u8>,
    topic: gossipsub::IdentTopic,
) {
    if pending.len() >= PENDING_VOTE_OUTBOX_MAX {
        pending.pop_front();
    }
    pending.push_back((data, topic));
}

fn drain_pending_blocks(
    pending: &mut VecDeque<Vec<u8>>,
    gossipsub: &mut gossipsub::Behaviour,
    block_topic_a: &gossipsub::IdentTopic,
    block_topic_b: &gossipsub::IdentTopic,
) {
    if pending.is_empty() {
        return;
    }

    tracing::info!(target: "gossip", "Attempting to drain {} pending blocks from outbox.", pending.len());

    pending.retain(|block_data| {
        let ok_a = gossipsub.publish(block_topic_a.clone(), block_data.clone()).is_ok();
        let ok_b = gossipsub.publish(block_topic_b.clone(), block_data.clone()).is_ok();

        if ok_a || ok_b {
            tracing::info!(target: "gossip", event = "published_queued_block", mirror_a=ok_a, mirror_b=ok_b);
            false // Remove from queue
        } else {
            tracing::debug!("Failed to publish queued block (likely no peers yet), retrying later");
            true // Keep in queue
        }
    });
}

fn drain_pending_votes(
    pending: &mut VecDeque<(Vec<u8>, gossipsub::IdentTopic)>,
    gossipsub: &mut gossipsub::Behaviour,
) {
    if pending.is_empty() {
        return;
    }

    let count = pending.len();
    for _ in 0..count {
        if let Some((data, topic)) = pending.pop_front() {
            match gossipsub.publish(topic.clone(), data.clone()) {
                Ok(_) => {
                    tracing::debug!(target: "gossip", "Flushed pending vote");
                }
                Err(e) => {
                    if !matches!(e, PublishError::InsufficientPeers) {
                        tracing::warn!(target: "gossip", "Failed to flush vote: {:?}", e);
                    }
                    pending.push_back((data, topic));
                }
            }
        }
    }
}

pub async fn run_swarm_loop(
    mut swarm: Swarm<SyncBehaviour>,
    mut command_receiver: mpsc::Receiver<SwarmCommand>,
    event_sender: mpsc::Sender<SwarmInternalEvent>,
    mut shutdown_receiver: watch::Receiver<bool>,
) {
    eprintln!("[Network] Swarm loop started.");

    // Topics
    let block_topic_a = gossipsub::IdentTopic::new("blocks_mirror_a");
    let block_topic_b = gossipsub::IdentTopic::new("blocks_mirror_b");
    let tx_topic = gossipsub::IdentTopic::new("transactions");
    let vote_topic = gossipsub::IdentTopic::new("consensus_votes");
    let timeout_topic = gossipsub::IdentTopic::new("consensus_timeouts");
    let echo_topic = gossipsub::IdentTopic::new("consensus_echoes");
    let panic_topic = gossipsub::IdentTopic::new("consensus_panic");
    let confidence_topic = gossipsub::IdentTopic::new("apmft_confidence");
    let oracle_attestations_topic = gossipsub::IdentTopic::new("oracle-attestations");
    let agentic_vote_topic = gossipsub::IdentTopic::new("agentic-votes");

    let mut pending_blocks: VecDeque<Vec<u8>> = VecDeque::new();
    let mut pending_votes: VecDeque<(Vec<u8>, gossipsub::IdentTopic)> = VecDeque::new();

    let mut retry_interval = interval(Duration::from_millis(500));
    retry_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Subscribe
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&block_topic_a);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&block_topic_b);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&tx_topic);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&vote_topic);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&timeout_topic);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&echo_topic);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&panic_topic);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&confidence_topic);
    let _ = swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&oracle_attestations_topic);
    let _ = swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&agentic_vote_topic);

    loop {
        tokio::select! {
            _ = retry_interval.tick() => {
                drain_pending_blocks(&mut pending_blocks, &mut swarm.behaviour_mut().gossipsub, &block_topic_a, &block_topic_b);
                drain_pending_votes(&mut pending_votes, &mut swarm.behaviour_mut().gossipsub);
            },
            _ = shutdown_receiver.changed() => if *shutdown_receiver.borrow() { break; },

            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    tracing::info!(target: "network", event = "listening", %address);
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    metrics().inc_connected_peers();
                    tracing::info!(target: "network", event = "connected", %peer_id);
                    event_sender.send(SwarmInternalEvent::ConnectionEstablished(peer_id)).await.ok();
                    drain_pending_blocks(&mut pending_blocks, &mut swarm.behaviour_mut().gossipsub, &block_topic_a, &block_topic_b);
                    drain_pending_votes(&mut pending_votes, &mut swarm.behaviour_mut().gossipsub);
                }
                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    metrics().dec_connected_peers();
                    tracing::info!(target: "network", event = "disconnected", %peer_id);
                    event_sender.send(SwarmInternalEvent::ConnectionClosed(peer_id)).await.ok();
                }
                SwarmEvent::IncomingConnectionError { local_addr, send_back_addr, error, .. } => {
                    tracing::warn!(target: "network", event = "incoming_conn_error", %local_addr, %send_back_addr, ?error);
                }
                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                     tracing::warn!(target: "network", event = "outgoing_conn_error", ?peer_id, ?error);
                     if let Some(p) = peer_id {
                         event_sender.send(SwarmInternalEvent::OutboundFailure(p)).await.ok();
                     }
                }
                SwarmEvent::Dialing { peer_id, .. } => {
                     tracing::debug!(target: "network", event = "dialing_peer", ?peer_id);
                }
                SwarmEvent::Behaviour(event) => match event {
                    SyncBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. }) => {
                        let mirror_id = if message.topic == block_topic_a.hash() { Some(0u8) }
                                        else if message.topic == block_topic_b.hash() { Some(1u8) }
                                        else { None };

                        let topic_name = if mirror_id.is_some() { "blocks" }
                                         else if message.topic == tx_topic.hash() { "transactions" }
                                         else { "other" }; // Simplified for brevity
                        metrics().inc_gossip_messages_received(topic_name);

                        if let Some(source) = message.source {
                            if let Some(mid) = mirror_id {
                                event_sender.send(SwarmInternalEvent::GossipBlock(message.data, source, mid)).await.ok();
                            } else if message.topic == tx_topic.hash() {
                                event_sender.send(SwarmInternalEvent::GossipTransaction(message.data, source)).await.ok();
                            } else if message.topic == vote_topic.hash() {
                                event_sender.send(SwarmInternalEvent::ConsensusVoteReceived(message.data, source)).await.ok();
                            } else if message.topic == timeout_topic.hash() {
                                event_sender.send(SwarmInternalEvent::ViewChangeVoteReceived(message.data, source)).await.ok();
                            } else if message.topic == echo_topic.hash() {
                                event_sender.send(SwarmInternalEvent::EchoReceived(message.data, source)).await.ok();
                            } else if message.topic == panic_topic.hash() {
                                event_sender.send(SwarmInternalEvent::PanicReceived(message.data, source)).await.ok();
                            } else if message.topic == confidence_topic.hash() {
                                event_sender.send(SwarmInternalEvent::ConfidenceVoteReceived(message.data, source)).await.ok();
                            } else if message.topic == oracle_attestations_topic.hash() {
                                event_sender.send(SwarmInternalEvent::GossipOracleAttestation(message.data, source)).await.ok();
                            } else if message.topic == agentic_vote_topic.hash() {
                                if let Ok((prompt_hash, vote_hash)) = codec::from_bytes_canonical::<(String, Vec<u8>)>(&message.data) {
                                    event_sender.send(SwarmInternalEvent::AgenticConsensusVote { from: source, prompt_hash, vote_hash }).await.ok();
                                }
                            }
                        }
                    }
                    // [FIX] Handle other Gossipsub events (Subscribed, Unsubscribed, etc.)
                    SyncBehaviourEvent::Gossipsub(_) => {}

                    SyncBehaviourEvent::RequestResponse(event) => match event {
                        libp2p::request_response::Event::Message { peer, message } => match message {
                            libp2p::request_response::Message::Request { request, channel, .. } => match request {
                                SyncRequest::GetStatus => { event_sender.send(SwarmInternalEvent::StatusRequest(peer, channel)).await.ok(); }
                                SyncRequest::GetBlocks { since, max_blocks, max_bytes } => { event_sender.send(SwarmInternalEvent::BlocksRequest { peer, since, max_blocks, max_bytes, channel }).await.ok(); }
                                SyncRequest::AgenticPrompt(prompt) => {
                                    event_sender.send(SwarmInternalEvent::AgenticPrompt { from: peer, prompt, channel }).await.ok();
                                }
                                SyncRequest::RequestMissingTxs(indices) => {
                                    event_sender.send(SwarmInternalEvent::RequestMissingTxs { peer, indices, channel }).await.ok();
                                }
                                SyncRequest::SamplePreference(height) => {
                                    event_sender.send(SwarmInternalEvent::SampleRequest(peer, height, channel)).await.ok();
                                }
                            },
                            libp2p::request_response::Message::Response { response, .. } => match response {
                                SyncResponse::Status { height, head_hash, chain_id, genesis_root } => { event_sender.send(SwarmInternalEvent::StatusResponse { peer, height, head_hash, chain_id, genesis_root }).await.ok(); }
                                SyncResponse::Blocks(blocks) => { event_sender.send(SwarmInternalEvent::BlocksResponse(peer, blocks)).await.ok(); }
                                SyncResponse::SampleResult { block_hash, confidence } => {
                                    event_sender.send(SwarmInternalEvent::SampleResponse(peer, block_hash, confidence)).await.ok();
                                }
                                _ => {}
                            }
                        },
                        libp2p::request_response::Event::OutboundFailure { peer, error, .. } => {
                            tracing::warn!(target: "network", event = "outbound_failure", %peer, ?error);
                            event_sender.send(SwarmInternalEvent::OutboundFailure(peer)).await.ok();
                        },
                        _ => {}
                    },
                    // [NEW] Ignore Ping events, they are handled automatically by the behaviour
                    SyncBehaviourEvent::Ping(_) => {}
                }
                _ => {}
            },
            command = command_receiver.recv() => match command {
                Some(cmd) => match cmd {
                    SwarmCommand::Listen(addr) => { let _ = swarm.listen_on(addr); }
                    SwarmCommand::Dial(addr) => { let _ = swarm.dial(addr); }
                    SwarmCommand::PublishBlock(data) => {
                        let res_a = swarm.behaviour_mut().gossipsub.publish(block_topic_a.clone(), data.clone());
                        let res_b = swarm.behaviour_mut().gossipsub.publish(block_topic_b.clone(), data.clone());
                        if matches!(res_a, Err(PublishError::InsufficientPeers)) || matches!(res_b, Err(PublishError::InsufficientPeers)) {
                            enqueue_block(&mut pending_blocks, data);
                        }
                    }
                    SwarmCommand::PublishTransaction(data) => { let _ = swarm.behaviour_mut().gossipsub.publish(tx_topic.clone(), data); }
                    SwarmCommand::BroadcastVote(data) => {
                         if let Err(PublishError::InsufficientPeers) = swarm.behaviour_mut().gossipsub.publish(vote_topic.clone(), data.clone()) {
                             enqueue_vote(&mut pending_votes, data, vote_topic.clone());
                         }
                    }
                    SwarmCommand::BroadcastViewChange(data) => { let _ = swarm.behaviour_mut().gossipsub.publish(timeout_topic.clone(), data); }
                    SwarmCommand::BroadcastEcho(data) => { let _ = swarm.behaviour_mut().gossipsub.publish(echo_topic.clone(), data); }
                    SwarmCommand::BroadcastPanic(data) => { let _ = swarm.behaviour_mut().gossipsub.publish(panic_topic.clone(), data); }
                    SwarmCommand::BroadcastConfidence(data) => { let _ = swarm.behaviour_mut().gossipsub.publish(confidence_topic.clone(), data); }
                    SwarmCommand::GossipOracleAttestation(data) => { let _ = swarm.behaviour_mut().gossipsub.publish(oracle_attestations_topic.clone(), data); }

                    SwarmCommand::SendStatusRequest(p) => { swarm.behaviour_mut().request_response.send_request(&p, SyncRequest::GetStatus); }
                    SwarmCommand::SendBlocksRequest { peer, since, max_blocks, max_bytes } => { swarm.behaviour_mut().request_response.send_request(&peer, SyncRequest::GetBlocks { since, max_blocks, max_bytes }); }
                    SwarmCommand::SendStatusResponse { channel, height, head_hash, chain_id, genesis_root } => { let _ = swarm.behaviour_mut().request_response.send_response(channel, SyncResponse::Status { height, head_hash, chain_id, genesis_root }); }
                    SwarmCommand::SendBlocksResponse(c, blocks) => { let _ = swarm.behaviour_mut().request_response.send_response(c, SyncResponse::Blocks(blocks)); }
                    SwarmCommand::BroadcastToCommittee(peers, prompt) => {
                        for peer_id in peers {
                            swarm.behaviour_mut().request_response.send_request(&peer_id, SyncRequest::AgenticPrompt(prompt.clone()));
                        }
                    }
                    SwarmCommand::AgenticConsensusVote(prompt_hash, vote_hash) => {
                        if let Ok(data) = codec::to_bytes_canonical(&(prompt_hash, vote_hash)) {
                            let _ = swarm.behaviour_mut().gossipsub.publish(agentic_vote_topic.clone(), data);
                        }
                    }
                    SwarmCommand::SendAgenticAck(channel) => { let _ = swarm.behaviour_mut().request_response.send_response(channel, SyncResponse::AgenticAck); }
                    SwarmCommand::RequestMissingTxs { peer, indices } => {
                        swarm.behaviour_mut().request_response.send_request(&peer, SyncRequest::RequestMissingTxs(indices));
                    }
                    SwarmCommand::SendSampleRequest { peer, height } => {
                        swarm.behaviour_mut().request_response.send_request(&peer, SyncRequest::SamplePreference(height));
                    }
                    SwarmCommand::SendSampleResponse { channel, block_hash, confidence } => {
                        let _ = swarm.behaviour_mut().request_response.send_response(channel, SyncResponse::SampleResult { block_hash, confidence });
                    }
                    SwarmCommand::SimulateAgenticTx => {}
                },
                None => { return; }
            }
        }
    }
}
