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
const PENDING_TX_OUTBOX_MAX: usize = 65_536;
const PENDING_VOTE_OUTBOX_MAX: usize = 256;
const BLOCK_SYNC_MAX_BYTES: u32 = 64 * 1024 * 1024;

fn initial_sync_max_blocks() -> u32 {
    std::env::var("IOI_AFT_INITIAL_SYNC_MAX_BLOCKS")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(8)
}

fn block_direct_relay_max_bytes() -> usize {
    std::env::var("IOI_AFT_BLOCK_DIRECT_RELAY_MAX_BYTES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(BLOCK_SYNC_MAX_BYTES as usize)
}

fn block_direct_relay_when_gossip_succeeds() -> bool {
    std::env::var("IOI_AFT_BLOCK_DIRECT_RELAY")
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "True"))
        .unwrap_or(false)
}

fn consensus_direct_relay_when_gossip_succeeds() -> bool {
    std::env::var("IOI_AFT_CONSENSUS_DIRECT_RELAY")
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "True"))
        .unwrap_or(false)
}

fn consensus_direct_relay_peer_limit() -> usize {
    std::env::var("IOI_AFT_CONSENSUS_DIRECT_RELAY_PEER_LIMIT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0)
}

fn publish_consensus_directly(
    swarm: &mut Swarm<SyncBehaviour>,
    request: SyncRequest,
    peer_limit: usize,
) {
    let peers = swarm
        .connected_peers()
        .cloned()
        .take(peer_limit)
        .collect::<Vec<_>>();
    for peer in peers {
        swarm
            .behaviour_mut()
            .request_response
            .send_request(&peer, request.clone());
    }
}

/// Enqueues a block for later gossiping, dropping the oldest if the outbox is full.
fn enqueue_block(pending: &mut VecDeque<Vec<u8>>, data: Vec<u8>) {
    if pending.len() >= PENDING_BLOCK_OUTBOX_MAX {
        pending.pop_front();
        tracing::warn!(target: "gossip", "outbox full; dropping oldest pending block");
    }
    pending.push_back(data);
}

fn enqueue_tx(pending: &mut VecDeque<Vec<u8>>, data: Vec<u8>) {
    if pending.len() >= PENDING_TX_OUTBOX_MAX {
        pending.pop_front();
        tracing::warn!(target: "gossip", "outbox full; dropping oldest pending transaction");
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

fn drain_pending_txs(
    pending: &mut VecDeque<Vec<u8>>,
    gossipsub: &mut gossipsub::Behaviour,
    tx_topic: &gossipsub::IdentTopic,
) {
    if pending.is_empty() {
        return;
    }

    let count = pending.len();
    for _ in 0..count {
        if let Some(data) = pending.pop_front() {
            match gossipsub.publish(tx_topic.clone(), data.clone()) {
                Ok(_) => {
                    tracing::debug!(target: "gossip", "Flushed pending transaction");
                }
                Err(e) => {
                    if !matches!(e, PublishError::InsufficientPeers) {
                        tracing::warn!(target: "gossip", "Failed to flush transaction: {:?}", e);
                    }
                    pending.push_back(data);
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
    let qc_topic = gossipsub::IdentTopic::new("consensus_quorum_certificates");
    let timeout_topic = gossipsub::IdentTopic::new("consensus_timeouts");
    let echo_topic = gossipsub::IdentTopic::new("consensus_echoes");
    let panic_topic = gossipsub::IdentTopic::new("consensus_panic");
    let confidence_topic = gossipsub::IdentTopic::new("experimental_nested_guardian_confidence");
    let oracle_attestations_topic = gossipsub::IdentTopic::new("oracle-attestations");
    let agentic_vote_topic = gossipsub::IdentTopic::new("agentic-votes");

    let mut pending_blocks: VecDeque<Vec<u8>> = VecDeque::new();
    let mut pending_txs: VecDeque<Vec<u8>> = VecDeque::new();
    let mut pending_votes: VecDeque<(Vec<u8>, gossipsub::IdentTopic)> = VecDeque::new();

    let mut retry_interval = interval(Duration::from_millis(500));
    retry_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Subscribe
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&block_topic_a);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&block_topic_b);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&tx_topic);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&vote_topic);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&qc_topic);
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
                drain_pending_txs(&mut pending_txs, &mut swarm.behaviour_mut().gossipsub, &tx_topic);
                drain_pending_votes(&mut pending_votes, &mut swarm.behaviour_mut().gossipsub);
            },
            _ = shutdown_receiver.changed() => if *shutdown_receiver.borrow() { break; },

            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    tracing::info!(target: "network", event = "listening", %address);
                }
                SwarmEvent::ConnectionEstablished { peer_id, num_established, .. } => {
                    if num_established.get() == 1 {
                        metrics().inc_connected_peers();
                        tracing::info!(target: "network", event = "connected", %peer_id);
                        swarm
                            .behaviour_mut()
                            .request_response
                            .send_request(&peer_id, SyncRequest::GetStatus);
                        swarm.behaviour_mut().request_response.send_request(
                            &peer_id,
                            SyncRequest::GetBlocks {
                                since: 0,
                                max_blocks: initial_sync_max_blocks(),
                                max_bytes: BLOCK_SYNC_MAX_BYTES,
                            },
                        );
                        event_sender.send(SwarmInternalEvent::ConnectionEstablished(peer_id)).await.ok();
                    }
                    drain_pending_blocks(&mut pending_blocks, &mut swarm.behaviour_mut().gossipsub, &block_topic_a, &block_topic_b);
                    drain_pending_txs(&mut pending_txs, &mut swarm.behaviour_mut().gossipsub, &tx_topic);
                    drain_pending_votes(&mut pending_votes, &mut swarm.behaviour_mut().gossipsub);
                }
                SwarmEvent::ConnectionClosed { peer_id, num_established, .. } => {
                    if num_established == 0 {
                        metrics().dec_connected_peers();
                        tracing::info!(target: "network", event = "disconnected", %peer_id);
                        event_sender.send(SwarmInternalEvent::ConnectionClosed(peer_id)).await.ok();
                        if let Err(error) = swarm.dial(peer_id) {
                            tracing::debug!(
                                target: "network",
                                event = "redial_after_disconnect_failed",
                                %peer_id,
                                ?error
                            );
                        }
                    }
                }
                SwarmEvent::IncomingConnectionError { local_addr, send_back_addr, error, .. } => {
                    tracing::warn!(target: "network", event = "incoming_conn_error", %local_addr, %send_back_addr, ?error);
                }
                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                     tracing::warn!(target: "network", event = "outgoing_conn_error", ?peer_id, ?error);
                     if let Some(p) = peer_id {
                         event_sender.send(SwarmInternalEvent::OutboundFailure(p)).await.ok();
                         if let Err(redial_error) = swarm.dial(p) {
                             tracing::debug!(
                                 target: "network",
                                 event = "redial_after_outbound_failure_failed",
                                 peer = %p,
                                 ?redial_error
                             );
                         }
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
                            } else if message.topic == qc_topic.hash() {
                                event_sender.send(SwarmInternalEvent::QuorumCertificateReceived(message.data, source)).await.ok();
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
                    SyncBehaviourEvent::Gossipsub(_) => {
                        drain_pending_blocks(&mut pending_blocks, &mut swarm.behaviour_mut().gossipsub, &block_topic_a, &block_topic_b);
                        drain_pending_txs(&mut pending_txs, &mut swarm.behaviour_mut().gossipsub, &tx_topic);
                        drain_pending_votes(&mut pending_votes, &mut swarm.behaviour_mut().gossipsub);
                    }

                    SyncBehaviourEvent::RequestResponse(event) => match event {
                        libp2p::request_response::Event::Message { peer, message } => match message {
                            libp2p::request_response::Message::Request { request, channel, .. } => match request {
                                SyncRequest::GetStatus => { event_sender.send(SwarmInternalEvent::StatusRequest(peer, channel)).await.ok(); }
                                SyncRequest::GetBlocks { since, max_blocks, max_bytes } => { event_sender.send(SwarmInternalEvent::BlocksRequest { peer, since, max_blocks, max_bytes, channel }).await.ok(); }
                                SyncRequest::RelayBlock(data) => {
                                    event_sender.send(SwarmInternalEvent::GossipBlock(data, peer, 2)).await.ok();
                                    let _ = swarm.behaviour_mut().request_response.send_response(channel, SyncResponse::RelayBlockAck);
                                }
                                SyncRequest::RelayTransaction(data) => {
                                    event_sender.send(SwarmInternalEvent::GossipTransaction(data, peer)).await.ok();
                                    let _ = swarm.behaviour_mut().request_response.send_response(channel, SyncResponse::RelayTransactionAck);
                                }
                                SyncRequest::RelayConsensusVote(data) => {
                                    event_sender.send(SwarmInternalEvent::ConsensusVoteReceived(data, peer)).await.ok();
                                    let _ = swarm.behaviour_mut().request_response.send_response(channel, SyncResponse::RelayConsensusAck);
                                }
                                SyncRequest::RelayQuorumCertificate(data) => {
                                    event_sender.send(SwarmInternalEvent::QuorumCertificateReceived(data, peer)).await.ok();
                                    let _ = swarm.behaviour_mut().request_response.send_response(channel, SyncResponse::RelayConsensusAck);
                                }
                                SyncRequest::RelayViewChange(data) => {
                                    event_sender.send(SwarmInternalEvent::ViewChangeVoteReceived(data, peer)).await.ok();
                                    let _ = swarm.behaviour_mut().request_response.send_response(channel, SyncResponse::RelayConsensusAck);
                                }
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
                                SyncResponse::Status { height, head_hash, chain_id, genesis_root, validator_account_id } => { event_sender.send(SwarmInternalEvent::StatusResponse { peer, height, head_hash, chain_id, genesis_root, validator_account_id }).await.ok(); }
                                SyncResponse::Blocks(blocks) => { event_sender.send(SwarmInternalEvent::BlocksResponse(peer, blocks)).await.ok(); }
                                SyncResponse::RelayBlockAck
                                | SyncResponse::RelayTransactionAck
                                | SyncResponse::RelayConsensusAck
                                | SyncResponse::AgenticAck => {}
                                SyncResponse::MissingTxs(_) => {}
                                SyncResponse::SampleResult { block_hash, confidence } => {
                                    event_sender.send(SwarmInternalEvent::SampleResponse(peer, block_hash, confidence)).await.ok();
                                }
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
                        let gossip_insufficient_peers =
                            matches!(res_a, Err(PublishError::InsufficientPeers))
                                || matches!(res_b, Err(PublishError::InsufficientPeers));
                        let gossip_publish_failed = res_a.is_err() || res_b.is_err();
                        if gossip_insufficient_peers {
                            enqueue_block(&mut pending_blocks, data.clone());
                        } else {
                            if let Err(e) = res_a {
                                tracing::warn!(target: "gossip", "Failed to publish block on mirror A: {:?}", e);
                            }
                            if let Err(e) = res_b {
                                tracing::warn!(target: "gossip", "Failed to publish block on mirror B: {:?}", e);
                            }
                        }

                        let block_len = data.len();
                        let allow_direct_relay = gossip_publish_failed
                            || (block_direct_relay_when_gossip_succeeds()
                                && block_len <= block_direct_relay_max_bytes());
                        if allow_direct_relay {
                            let peers: Vec<_> = swarm.connected_peers().cloned().collect();
                            for peer in peers {
                                swarm
                                    .behaviour_mut()
                                    .request_response
                                    .send_request(&peer, SyncRequest::RelayBlock(data.clone()));
                            }
                        } else {
                            tracing::debug!(
                                target: "gossip",
                                block_bytes = block_len,
                                direct_relay_max_bytes = block_direct_relay_max_bytes(),
                                "Skipping direct block relay because gossip publish succeeded and the block is above the direct-relay threshold."
                            );
                        }
                    }
                    SwarmCommand::PublishTransaction(data) => {
                        let mut direct_relay_fallback = false;
                        match swarm
                            .behaviour_mut()
                            .gossipsub
                            .publish(tx_topic.clone(), data.clone())
                        {
                            Ok(_) => {}
                            Err(PublishError::InsufficientPeers) => {
                                enqueue_tx(&mut pending_txs, data.clone());
                                direct_relay_fallback = true;
                            }
                            Err(e) => {
                                tracing::warn!(
                                    target: "gossip",
                                    "Failed to publish transaction: {:?}",
                                    e
                                );
                                direct_relay_fallback = true;
                            }
                        }

                        if direct_relay_fallback {
                            let peers: Vec<_> = swarm.connected_peers().cloned().collect();
                            for peer in peers {
                                swarm
                                    .behaviour_mut()
                                    .request_response
                                    .send_request(&peer, SyncRequest::RelayTransaction(data.clone()));
                            }
                        }
                    }
                    SwarmCommand::RelayTransactionToPeer { peer, data } => {
                        swarm
                            .behaviour_mut()
                            .request_response
                            .send_request(&peer, SyncRequest::RelayTransaction(data));
                    }
                    SwarmCommand::BroadcastVote(data) => {
                         let direct_peer_limit = consensus_direct_relay_peer_limit();
                         let gossip_result = swarm.behaviour_mut().gossipsub.publish(vote_topic.clone(), data.clone());
                         let should_direct_relay = match gossip_result {
                             Ok(_) => consensus_direct_relay_when_gossip_succeeds() && direct_peer_limit > 0,
                             Err(PublishError::InsufficientPeers) => {
                                 enqueue_vote(&mut pending_votes, data.clone(), vote_topic.clone());
                                 direct_peer_limit > 0 || swarm.connected_peers().next().is_some()
                             }
                             Err(error) => {
                                 tracing::warn!(target: "gossip", "Failed to publish vote: {:?}", error);
                                 direct_peer_limit > 0 || swarm.connected_peers().next().is_some()
                             }
                         };
                         if should_direct_relay {
                             let peer_limit = if direct_peer_limit > 0 {
                                 direct_peer_limit
                             } else {
                                 usize::MAX
                             };
                             publish_consensus_directly(
                                 &mut swarm,
                                 SyncRequest::RelayConsensusVote(data),
                                 peer_limit,
                             );
                         }
                    }
                    SwarmCommand::BroadcastQuorumCertificate(data) => {
                         let direct_peer_limit = consensus_direct_relay_peer_limit();
                         let gossip_result = swarm.behaviour_mut().gossipsub.publish(qc_topic.clone(), data.clone());
                         let should_direct_relay = match gossip_result {
                             Ok(_) => consensus_direct_relay_when_gossip_succeeds() && direct_peer_limit > 0,
                             Err(PublishError::InsufficientPeers) => {
                                 enqueue_vote(&mut pending_votes, data.clone(), qc_topic.clone());
                                 direct_peer_limit > 0 || swarm.connected_peers().next().is_some()
                             }
                             Err(error) => {
                                 tracing::warn!(target: "gossip", "Failed to publish quorum certificate: {:?}", error);
                                 direct_peer_limit > 0 || swarm.connected_peers().next().is_some()
                             }
                         };
                         if should_direct_relay {
                             let peer_limit = if direct_peer_limit > 0 {
                                 direct_peer_limit
                             } else {
                                 usize::MAX
                             };
                             publish_consensus_directly(
                                 &mut swarm,
                                 SyncRequest::RelayQuorumCertificate(data),
                                 peer_limit,
                             );
                         }
                    }
                    SwarmCommand::BroadcastViewChange(data) => {
                         let direct_peer_limit = consensus_direct_relay_peer_limit();
                         let should_direct_relay = match swarm.behaviour_mut().gossipsub.publish(timeout_topic.clone(), data.clone()) {
                             Ok(_) => consensus_direct_relay_when_gossip_succeeds() && direct_peer_limit > 0,
                             Err(PublishError::InsufficientPeers) => direct_peer_limit > 0 || swarm.connected_peers().next().is_some(),
                             Err(error) => {
                                 tracing::warn!(target: "gossip", "Failed to publish view-change vote: {:?}", error);
                                 direct_peer_limit > 0 || swarm.connected_peers().next().is_some()
                             }
                         };
                         if should_direct_relay {
                             let peer_limit = if direct_peer_limit > 0 {
                                 direct_peer_limit
                             } else {
                                 usize::MAX
                             };
                             publish_consensus_directly(
                                 &mut swarm,
                                 SyncRequest::RelayViewChange(data),
                                 peer_limit,
                             );
                         }
                    }
                    SwarmCommand::BroadcastEcho(data) => { let _ = swarm.behaviour_mut().gossipsub.publish(echo_topic.clone(), data); }
                    SwarmCommand::BroadcastPanic(data) => { let _ = swarm.behaviour_mut().gossipsub.publish(panic_topic.clone(), data); }
                    SwarmCommand::BroadcastConfidence(data) => { let _ = swarm.behaviour_mut().gossipsub.publish(confidence_topic.clone(), data); }
                    SwarmCommand::GossipOracleAttestation(data) => { let _ = swarm.behaviour_mut().gossipsub.publish(oracle_attestations_topic.clone(), data); }

                    SwarmCommand::SendStatusRequest(p) => { swarm.behaviour_mut().request_response.send_request(&p, SyncRequest::GetStatus); }
                    SwarmCommand::SendBlocksRequest { peer, since, max_blocks, max_bytes } => { swarm.behaviour_mut().request_response.send_request(&peer, SyncRequest::GetBlocks { since, max_blocks, max_bytes }); }
                    SwarmCommand::SendStatusResponse { channel, height, head_hash, chain_id, genesis_root, validator_account_id } => { let _ = swarm.behaviour_mut().request_response.send_response(channel, SyncResponse::Status { height, head_hash, chain_id, genesis_root, validator_account_id }); }
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
