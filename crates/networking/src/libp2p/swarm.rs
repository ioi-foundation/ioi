// Path: crates/networking/src/libp2p/swarm.rs

use futures::StreamExt;
use libp2p::gossipsub::PublishError;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::SwarmEvent;
use libp2p::{gossipsub, Multiaddr, PeerId, Swarm};
use std::collections::{HashMap, HashSet, VecDeque};
use tokio::sync::{mpsc, watch};
use tokio::time::{interval, Duration};

use crate::metrics::metrics;
use ioi_types::codec;

use super::behaviour::{SyncBehaviour, SyncBehaviourEvent};
use super::pq_channel::{PqChannelLocalConfig, PqChannelSessionManager, PqPeerEnrollment};
use super::sync::{PqConsensusPayloadV1, SyncRequest, SyncResponse};
use super::types::{SwarmCommand, SwarmInternalEvent};

const PENDING_BLOCK_OUTBOX_MAX: usize = 128;
const PENDING_TX_OUTBOX_MAX: usize = 65_536;
const PENDING_VOTE_OUTBOX_MAX: usize = 256;
const BLOCK_SYNC_MAX_BYTES: u32 = 64 * 1024 * 1024;

fn addressed_peer(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|protocol| match protocol {
        Protocol::P2p(peer) => Some(peer),
        _ => None,
    })
}

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

fn replace_pq_channel_manager(
    current: &mut Option<PqChannelSessionManager>,
    config: PqChannelLocalConfig,
    enrollments: Vec<PqPeerEnrollment>,
) -> Result<(), String> {
    // The old configuration must become unusable before any fallible work on
    // the replacement. A construction or enrollment failure therefore leaves
    // strict transport disabled, never silently active under stale authority.
    *current = None;
    let mut replacement =
        PqChannelSessionManager::new(config).map_err(|error| error.to_string())?;
    for enrollment in enrollments {
        replacement
            .enroll_peer(enrollment)
            .map_err(|error| error.to_string())?;
    }
    *current = Some(replacement);
    Ok(())
}

fn begin_strict_pq_reconfiguration(
    current: &mut Option<PqChannelSessionManager>,
    legacy_consensus_transport_allowed: &mut bool,
) {
    // This transition is intentionally irreversible for the lifetime of the
    // swarm. A failed replacement may be retried, but may never reactivate a
    // classical consensus path by making `current` empty.
    *legacy_consensus_transport_allowed = false;
    *current = None;
}

struct InflightPqRequest {
    request_id: libp2p::request_response::OutboundRequestId,
    message_id: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PqHandshakeStage {
    ClientHello,
    ClientFinish,
}

struct InflightPqHandshake {
    request_id: libp2p::request_response::OutboundRequestId,
    stage: PqHandshakeStage,
}

fn start_pq_handshake(
    swarm: &mut Swarm<SyncBehaviour>,
    manager: &mut PqChannelSessionManager,
    inflight: &mut HashMap<libp2p::PeerId, InflightPqHandshake>,
    peer: libp2p::PeerId,
) {
    if manager.is_established(&peer)
        || inflight.contains_key(&peer)
        || !manager.should_initiate(&peer)
        || !swarm.is_connected(&peer)
    {
        return;
    }
    match manager.start(peer) {
        Ok(hello) => {
            let request_id = swarm
                .behaviour_mut()
                .request_response
                .send_request(&peer, SyncRequest::PqChannelClientHello(hello));
            inflight.insert(
                peer,
                InflightPqHandshake {
                    request_id,
                    stage: PqHandshakeStage::ClientHello,
                },
            );
        }
        Err(error) => {
            tracing::debug!(
                target: "network",
                event = "pq_channel_start_deferred",
                %peer,
                %error
            );
        }
    }
}

fn flush_pq_peer(
    swarm: &mut Swarm<SyncBehaviour>,
    manager: &mut PqChannelSessionManager,
    inflight: &mut HashMap<libp2p::PeerId, InflightPqRequest>,
    peer: libp2p::PeerId,
) {
    if !manager.is_application_ready(&peer) || inflight.contains_key(&peer) {
        return;
    }
    let Some((message_id, payload)) = manager.pending_front(&peer) else {
        return;
    };
    let content_type = payload.content_type();
    let plaintext = match codec::to_bytes_canonical(&payload) {
        Ok(plaintext) => plaintext,
        Err(error) => {
            tracing::error!(target: "network", event = "pq_payload_encode_failed", %peer, %error);
            return;
        }
    };
    match manager.seal(&peer, content_type, &plaintext) {
        Ok(record) => {
            let request_id = swarm
                .behaviour_mut()
                .request_response
                .send_request(&peer, SyncRequest::PqChannelRecord(record));
            inflight.insert(
                peer,
                InflightPqRequest {
                    request_id,
                    message_id,
                },
            );
        }
        Err(error) => {
            tracing::warn!(target: "network", event = "pq_record_seal_failed", %peer, %error);
        }
    }
}

fn broadcast_pq_consensus(
    swarm: &mut Swarm<SyncBehaviour>,
    manager: &mut PqChannelSessionManager,
    handshakes: &mut HashMap<libp2p::PeerId, InflightPqHandshake>,
    inflight: &mut HashMap<libp2p::PeerId, InflightPqRequest>,
    payload: PqConsensusPayloadV1,
) {
    let peers = manager.enrolled_peers().collect::<Vec<_>>();
    for peer in peers {
        if let Err(error) = manager.enqueue(peer, payload.clone()) {
            tracing::error!(target: "network", event = "pq_consensus_durable_enqueue_failed", %peer, %error);
            continue;
        }
        if manager.is_established(&peer) {
            flush_pq_peer(swarm, manager, inflight, peer);
        } else {
            start_pq_handshake(swarm, manager, handshakes, peer);
        }
    }
}

fn send_pq_consensus(
    swarm: &mut Swarm<SyncBehaviour>,
    manager: &mut PqChannelSessionManager,
    handshakes: &mut HashMap<libp2p::PeerId, InflightPqHandshake>,
    inflight: &mut HashMap<libp2p::PeerId, InflightPqRequest>,
    peer: libp2p::PeerId,
    payload: PqConsensusPayloadV1,
) {
    if let Err(error) = manager.enqueue(peer, payload) {
        tracing::error!(target: "network", event = "pq_consensus_durable_enqueue_failed", %peer, %error);
        return;
    }
    if manager.is_established(&peer) {
        flush_pq_peer(swarm, manager, inflight, peer);
    } else {
        start_pq_handshake(swarm, manager, handshakes, peer);
    }
}

fn queue_pq_consensus_for_account(
    swarm: &mut Swarm<SyncBehaviour>,
    manager: &mut PqChannelSessionManager,
    handshakes: &mut HashMap<libp2p::PeerId, InflightPqHandshake>,
    inflight: &mut HashMap<libp2p::PeerId, InflightPqRequest>,
    recipient: ioi_types::app::AccountId,
    payload: PqConsensusPayloadV1,
) {
    if let Err(error) = manager.enqueue_for_account(recipient, payload) {
        tracing::error!(target: "network", event = "pq_consensus_durable_enqueue_failed", ?recipient, %error);
        return;
    }
    let Some(peer) = manager.peer_for_account(recipient) else {
        tracing::debug!(target: "network", event = "pq_consensus_waiting_for_enrollment", ?recipient);
        return;
    };
    if manager.is_established(&peer) {
        flush_pq_peer(swarm, manager, inflight, peer);
    } else {
        start_pq_handshake(swarm, manager, handshakes, peer);
    }
}

async fn deliver_pq_record(
    event_sender: &mpsc::Sender<SwarmInternalEvent>,
    manager: &mut PqChannelSessionManager,
    peer: libp2p::PeerId,
    record: ioi_crypto::transport::pq_authenticated_channel::PqChannelRecordV1,
) -> anyhow::Result<()> {
    let declared_type = record.content_type;
    let plaintext = manager.open(&peer, &record)?;
    let authenticated_account = manager
        .remote_account(&peer)
        .ok_or_else(|| anyhow::anyhow!("PQ channel lacks its authenticated remote account"))?;
    let payload = codec::from_bytes_canonical::<PqConsensusPayloadV1>(&plaintext)
        .map_err(anyhow::Error::msg)?;
    if payload.content_type() != declared_type {
        anyhow::bail!("protected consensus payload type does not match authenticated record type");
    }
    let event = match payload {
        PqConsensusPayloadV1::Vote(data) => SwarmInternalEvent::ConsensusVoteReceived(data, peer),
        PqConsensusPayloadV1::QuorumCertificate(data) => {
            SwarmInternalEvent::QuorumCertificateReceived(data, peer)
        }
        PqConsensusPayloadV1::ViewChange(data) => {
            SwarmInternalEvent::ViewChangeVoteReceived(data, peer)
        }
        PqConsensusPayloadV1::AftTimeoutVote(data) => {
            SwarmInternalEvent::AftTimeoutVoteReceived(data, peer)
        }
        PqConsensusPayloadV1::TimeoutCertificate(data) => {
            SwarmInternalEvent::TimeoutCertificateReceived(data, peer)
        }
        PqConsensusPayloadV1::AftTimeoutCertificate(data) => {
            SwarmInternalEvent::AftTimeoutCertificateReceived(data, peer)
        }
        PqConsensusPayloadV1::FallbackStart(data) => {
            SwarmInternalEvent::FallbackStartReceived(data, peer)
        }
        PqConsensusPayloadV1::AftAsyncOrdering(data) => {
            SwarmInternalEvent::AftAsyncOrderingReceived(data, authenticated_account, peer)
        }
        PqConsensusPayloadV1::Echo(data) => SwarmInternalEvent::EchoReceived(data, peer),
        PqConsensusPayloadV1::Panic(data) => SwarmInternalEvent::PanicReceived(data, peer),
        PqConsensusPayloadV1::Confidence(data) => {
            SwarmInternalEvent::ConfidenceVoteReceived(data, peer)
        }
    };
    event_sender
        .send(event)
        .await
        .map_err(|_| anyhow::anyhow!("network event receiver closed"))
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
    let mut pq_channels: Option<PqChannelSessionManager> = None;
    // A missing manager has two distinct meanings: the legacy profile has not
    // requested PQ transport, or a requested strict-PQ configuration is not
    // currently usable.  Keep that authority bit separate so a failed PQ
    // rotation cannot silently reopen classical consensus transport.
    let mut legacy_consensus_transport_allowed = true;
    let mut inflight_pq_handshakes: HashMap<libp2p::PeerId, InflightPqHandshake> = HashMap::new();
    let mut inflight_pq_consensus: HashMap<libp2p::PeerId, InflightPqRequest> = HashMap::new();
    let mut dialing_peers: HashSet<PeerId> = HashSet::new();

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
                if let Some(manager) = pq_channels.as_mut() {
                    for peer in manager.pending_peers() {
                        if manager.is_application_ready(&peer) {
                            flush_pq_peer(&mut swarm, manager, &mut inflight_pq_consensus, peer);
                        } else if !manager.is_established(&peer) {
                            start_pq_handshake(
                                &mut swarm,
                                manager,
                                &mut inflight_pq_handshakes,
                                peer,
                            );
                        }
                    }
                }
            },
            _ = shutdown_receiver.changed() => if *shutdown_receiver.borrow() { break; },

            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    tracing::info!(target: "network", event = "listening", %address);
                }
                SwarmEvent::ConnectionEstablished { peer_id, num_established, .. } => {
                    dialing_peers.remove(&peer_id);
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
                        if let Some(manager) = pq_channels.as_mut() {
                            start_pq_handshake(
                                &mut swarm,
                                manager,
                                &mut inflight_pq_handshakes,
                                peer_id,
                            );
                        }
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
                        if let Some(manager) = pq_channels.as_mut() {
                            manager.disconnect(&peer_id);
                        }
                        inflight_pq_handshakes.remove(&peer_id);
                        inflight_pq_consensus.remove(&peer_id);
                        if let Err(error) = swarm.dial(peer_id) {
                            tracing::debug!(
                                target: "network",
                                event = "redial_after_disconnect_failed",
                                %peer_id,
                                ?error
                            );
                        } else {
                            dialing_peers.insert(peer_id);
                        }
                    }
                }
                SwarmEvent::IncomingConnectionError { local_addr, send_back_addr, error, .. } => {
                    tracing::warn!(target: "network", event = "incoming_conn_error", %local_addr, %send_back_addr, ?error);
                }
                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                     tracing::warn!(target: "network", event = "outgoing_conn_error", ?peer_id, ?error);
                     if let Some(p) = peer_id {
                         dialing_peers.remove(&p);
                         event_sender.send(SwarmInternalEvent::OutboundFailure(p)).await.ok();
                         if !swarm.is_connected(&p) {
                             if let Err(redial_error) = swarm.dial(p) {
                                 tracing::debug!(
                                     target: "network",
                                     event = "redial_after_outbound_failure_failed",
                                     peer = %p,
                                     ?redial_error
                                 );
                             } else {
                                 dialing_peers.insert(p);
                             }
                         }
                     }
                }
                SwarmEvent::Dialing { peer_id, .. } => {
                     if let Some(peer) = peer_id {
                         dialing_peers.insert(peer);
                     }
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
                            } else if message.topic == vote_topic.hash() && legacy_consensus_transport_allowed {
                                event_sender.send(SwarmInternalEvent::ConsensusVoteReceived(message.data, source)).await.ok();
                            } else if message.topic == qc_topic.hash() && legacy_consensus_transport_allowed {
                                event_sender.send(SwarmInternalEvent::QuorumCertificateReceived(message.data, source)).await.ok();
                            } else if message.topic == timeout_topic.hash() && legacy_consensus_transport_allowed {
                                event_sender.send(SwarmInternalEvent::ViewChangeVoteReceived(message.data, source)).await.ok();
                            } else if message.topic == echo_topic.hash() && legacy_consensus_transport_allowed {
                                event_sender.send(SwarmInternalEvent::EchoReceived(message.data, source)).await.ok();
                            } else if message.topic == panic_topic.hash() && legacy_consensus_transport_allowed {
                                event_sender.send(SwarmInternalEvent::PanicReceived(message.data, source)).await.ok();
                            } else if message.topic == confidence_topic.hash() && legacy_consensus_transport_allowed {
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
                                    if legacy_consensus_transport_allowed {
                                        event_sender.send(SwarmInternalEvent::ConsensusVoteReceived(data, peer)).await.ok();
                                    } else {
                                        tracing::warn!(target: "network", event = "classical_consensus_relay_refused", %peer, kind = "vote");
                                    }
                                    let _ = swarm.behaviour_mut().request_response.send_response(channel, SyncResponse::RelayConsensusAck);
                                }
                                SyncRequest::RelayQuorumCertificate(data) => {
                                    if legacy_consensus_transport_allowed {
                                        event_sender.send(SwarmInternalEvent::QuorumCertificateReceived(data, peer)).await.ok();
                                    } else {
                                        tracing::warn!(target: "network", event = "classical_consensus_relay_refused", %peer, kind = "quorum_certificate");
                                    }
                                    let _ = swarm.behaviour_mut().request_response.send_response(channel, SyncResponse::RelayConsensusAck);
                                }
                                SyncRequest::RelayViewChange(data) => {
                                    if legacy_consensus_transport_allowed {
                                        event_sender.send(SwarmInternalEvent::ViewChangeVoteReceived(data, peer)).await.ok();
                                    } else {
                                        tracing::warn!(target: "network", event = "classical_consensus_relay_refused", %peer, kind = "view_change");
                                    }
                                    let _ = swarm.behaviour_mut().request_response.send_response(channel, SyncResponse::RelayConsensusAck);
                                }
                                SyncRequest::RelayTimeoutCertificate(data) => {
                                    if legacy_consensus_transport_allowed {
                                        event_sender.send(SwarmInternalEvent::TimeoutCertificateReceived(data, peer)).await.ok();
                                    } else {
                                        tracing::warn!(target: "network", event = "classical_consensus_relay_refused", %peer, kind = "timeout_certificate");
                                    }
                                    let _ = swarm.behaviour_mut().request_response.send_response(channel, SyncResponse::RelayConsensusAck);
                                }
                                SyncRequest::RelayFallbackStart(data) => {
                                    if legacy_consensus_transport_allowed {
                                        event_sender.send(SwarmInternalEvent::FallbackStartReceived(data, peer)).await.ok();
                                    } else {
                                        tracing::warn!(target: "network", event = "classical_consensus_relay_refused", %peer, kind = "fallback_start");
                                    }
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
                                SyncRequest::PqChannelClientHello(hello) => {
                                    let response = pq_channels
                                        .as_mut()
                                        .ok_or_else(|| anyhow::anyhow!("strict PQ channels are not configured"))
                                        .and_then(|manager| manager.accept(peer, hello));
                                    match response {
                                        Ok(server) => {
                                            let _ = swarm.behaviour_mut().request_response.send_response(
                                                channel,
                                                SyncResponse::PqChannelServerHello(server),
                                            );
                                        }
                                        Err(error) => {
                                            tracing::warn!(target: "network", event = "pq_client_hello_refused", %peer, %error);
                                        }
                                    }
                                }
                                SyncRequest::PqChannelClientFinish(finish) => {
                                    let result = pq_channels
                                        .as_mut()
                                        .ok_or_else(|| anyhow::anyhow!("strict PQ channels are not configured"))
                                        .and_then(|manager| manager.complete(peer, finish));
                                    match result {
                                        Ok(()) => {
                                            let _ = swarm.behaviour_mut().request_response.send_response(channel, SyncResponse::PqChannelAck);
                                            if let Some(manager) = pq_channels.as_mut() {
                                                flush_pq_peer(&mut swarm, manager, &mut inflight_pq_consensus, peer);
                                            }
                                        }
                                        Err(error) => {
                                            tracing::warn!(target: "network", event = "pq_client_finish_refused", %peer, %error);
                                        }
                                    }
                                }
                                SyncRequest::PqChannelRecord(record) => {
                                    let result = match pq_channels.as_mut() {
                                        Some(manager) => deliver_pq_record(&event_sender, manager, peer, record).await,
                                        None => Err(anyhow::anyhow!("strict PQ channels are not configured")),
                                    };
                                    match result {
                                        Ok(()) => {
                                            let _ = swarm.behaviour_mut().request_response.send_response(channel, SyncResponse::PqChannelAck);
                                        }
                                        Err(error) => {
                                            tracing::warn!(target: "network", event = "pq_record_refused", %peer, %error);
                                        }
                                    }
                                }
                            },
                            libp2p::request_response::Message::Response { request_id, response } => match response {
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
                                SyncResponse::PqChannelServerHello(server) => {
                                    let expected = inflight_pq_handshakes.get(&peer).is_some_and(
                                        |pending| {
                                            pending.request_id == request_id
                                                && pending.stage == PqHandshakeStage::ClientHello
                                        },
                                    );
                                    if !expected {
                                        tracing::warn!(target: "network", event = "pq_server_hello_stale", %peer);
                                        continue;
                                    }
                                    inflight_pq_handshakes.remove(&peer);
                                    let finish = pq_channels
                                        .as_mut()
                                        .ok_or_else(|| anyhow::anyhow!("strict PQ channels are not configured"))
                                        .and_then(|manager| manager.finish(peer, server));
                                    match finish {
                                        Ok(finish) => {
                                            let request_id = swarm.behaviour_mut().request_response.send_request(
                                                &peer,
                                                SyncRequest::PqChannelClientFinish(finish),
                                            );
                                            inflight_pq_handshakes.insert(
                                                peer,
                                                InflightPqHandshake {
                                                    request_id,
                                                    stage: PqHandshakeStage::ClientFinish,
                                                },
                                            );
                                        }
                                        Err(error) => {
                                            tracing::warn!(target: "network", event = "pq_server_hello_refused", %peer, %error);
                                            if let Some(manager) = pq_channels.as_mut() {
                                                manager.disconnect(&peer);
                                                start_pq_handshake(
                                                    &mut swarm,
                                                    manager,
                                                    &mut inflight_pq_handshakes,
                                                    peer,
                                                );
                                            }
                                        }
                                    }
                                }
                                SyncResponse::PqChannelAck => {
                                    if let Some(manager) = pq_channels.as_mut() {
                                        let handshake_acknowledged = inflight_pq_handshakes
                                            .get(&peer)
                                            .is_some_and(|pending| {
                                                pending.request_id == request_id
                                                    && pending.stage == PqHandshakeStage::ClientFinish
                                            });
                                        if handshake_acknowledged {
                                            inflight_pq_handshakes.remove(&peer);
                                            if let Err(error) = manager.confirm_application_ready(&peer) {
                                                tracing::warn!(target: "network", event = "pq_channel_ack_refused", %peer, %error);
                                                manager.disconnect(&peer);
                                                start_pq_handshake(
                                                    &mut swarm,
                                                    manager,
                                                    &mut inflight_pq_handshakes,
                                                    peer,
                                                );
                                                continue;
                                            }
                                            flush_pq_peer(&mut swarm, manager, &mut inflight_pq_consensus, peer);
                                            continue;
                                        }
                                        let acknowledged = inflight_pq_consensus
                                            .get(&peer)
                                            .is_some_and(|pending| pending.request_id == request_id);
                                        if acknowledged {
                                            if let Some(pending) = inflight_pq_consensus.remove(&peer) {
                                                if let Err(error) = manager.acknowledge(&peer, pending.message_id) {
                                                    tracing::error!(target: "network", event = "pq_consensus_ack_persist_failed", %peer, %error);
                                                    manager.disconnect(&peer);
                                                    inflight_pq_handshakes.remove(&peer);
                                                    start_pq_handshake(
                                                        &mut swarm,
                                                        manager,
                                                        &mut inflight_pq_handshakes,
                                                        peer,
                                                    );
                                                    continue;
                                                }
                                            }
                                        }
                                        flush_pq_peer(&mut swarm, manager, &mut inflight_pq_consensus, peer);
                                    }
                                }
                            }
                        },
                        libp2p::request_response::Event::OutboundFailure { peer, request_id, error } => {
                            let handshake_failed = inflight_pq_handshakes
                                .get(&peer)
                                .is_some_and(|pending| pending.request_id == request_id);
                            let protected_failed = inflight_pq_consensus
                                .get(&peer)
                                .is_some_and(|pending| pending.request_id == request_id);
                            let pq_handshake_stage = inflight_pq_handshakes
                                .get(&peer)
                                .filter(|pending| pending.request_id == request_id)
                                .map(|pending| match pending.stage {
                                    PqHandshakeStage::ClientHello => "client_hello",
                                    PqHandshakeStage::ClientFinish => "client_finish",
                                })
                                .unwrap_or("none");
                            tracing::warn!(
                                target: "network",
                                event = "outbound_failure",
                                %peer,
                                ?error,
                                pq_handshake = handshake_failed,
                                pq_handshake_stage,
                                pq_protected_consensus = protected_failed,
                            );
                            if handshake_failed || protected_failed {
                                inflight_pq_handshakes.remove(&peer);
                                inflight_pq_consensus.remove(&peer);
                                if let Some(manager) = pq_channels.as_mut() {
                                    // The durable plaintext remains pending. Drop all
                                    // ephemeral keys so retry uses a fresh transcript
                                    // and starts its sequence at zero under a new key.
                                    manager.disconnect(&peer);
                                    start_pq_handshake(
                                        &mut swarm,
                                        manager,
                                        &mut inflight_pq_handshakes,
                                        peer,
                                    );
                                }
                            }
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
                    SwarmCommand::Dial(addr) => {
                        // Bootstrap maintenance is periodic. Treat a dial to an
                        // already-connected /p2p address as an idempotent no-op;
                        // otherwise each tick creates redundant TCP/Yamux
                        // connections whose teardown can abort unrelated
                        // request-response streams.
                        let peer = addressed_peer(&addr);
                        let already_active = peer.is_some_and(|peer| {
                            swarm.is_connected(&peer) || dialing_peers.contains(&peer)
                        });
                        if !already_active {
                            match swarm.dial(addr) {
                                Ok(()) => {
                                    if let Some(peer) = peer {
                                        dialing_peers.insert(peer);
                                    }
                                }
                                Err(error) => {
                                    tracing::debug!(
                                        target: "network",
                                        event = "dial_command_deferred",
                                        ?peer,
                                        ?error,
                                    );
                                }
                            }
                        }
                    }
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
                         if let Some(manager) = pq_channels.as_mut() {
                             broadcast_pq_consensus(
                                 &mut swarm,
                                 manager,
                                 &mut inflight_pq_handshakes,
                                 &mut inflight_pq_consensus,
                                 PqConsensusPayloadV1::Vote(data),
                             );
                         } else if legacy_consensus_transport_allowed {
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
                         } else {
                             tracing::warn!(target: "network", event = "classical_consensus_broadcast_refused", kind = "vote", "Strict PQ transport is required but unavailable");
                         }
                         }
                    }
                    SwarmCommand::BroadcastQuorumCertificate(data) => {
                         if let Some(manager) = pq_channels.as_mut() {
                             broadcast_pq_consensus(
                                 &mut swarm,
                                 manager,
                                 &mut inflight_pq_handshakes,
                                 &mut inflight_pq_consensus,
                                 PqConsensusPayloadV1::QuorumCertificate(data),
                             );
                         } else if legacy_consensus_transport_allowed {
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
                         } else {
                             tracing::warn!(target: "network", event = "classical_consensus_broadcast_refused", kind = "quorum_certificate", "Strict PQ transport is required but unavailable");
                         }
                         }
                    }
                    SwarmCommand::BroadcastViewChange(data) => {
                         if let Some(manager) = pq_channels.as_mut() {
                             broadcast_pq_consensus(
                                 &mut swarm,
                                 manager,
                                 &mut inflight_pq_handshakes,
                                 &mut inflight_pq_consensus,
                                 PqConsensusPayloadV1::ViewChange(data),
                             );
                         } else if legacy_consensus_transport_allowed {
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
                         } else {
                             tracing::warn!(target: "network", event = "classical_consensus_broadcast_refused", kind = "view_change", "Strict PQ transport is required but unavailable");
                         }
                         }
                    }
                    SwarmCommand::BroadcastAftTimeoutVote(data) => {
                        if let Some(manager) = pq_channels.as_mut() {
                            broadcast_pq_consensus(
                                &mut swarm,
                                manager,
                                &mut inflight_pq_handshakes,
                                &mut inflight_pq_consensus,
                                PqConsensusPayloadV1::AftTimeoutVote(data),
                            );
                        } else {
                            tracing::warn!(target: "network", event = "scoped_aft_timeout_refused", kind = "vote", "Scoped AFT timeout evidence requires strict PQ channels");
                        }
                    }
                    SwarmCommand::BroadcastTimeoutCertificate(data) => {
                        if let Some(manager) = pq_channels.as_mut() {
                            broadcast_pq_consensus(
                                &mut swarm,
                                manager,
                                &mut inflight_pq_handshakes,
                                &mut inflight_pq_consensus,
                                PqConsensusPayloadV1::TimeoutCertificate(data),
                            );
                        } else if legacy_consensus_transport_allowed {
                            publish_consensus_directly(
                                &mut swarm,
                                SyncRequest::RelayTimeoutCertificate(data),
                                usize::MAX,
                            );
                        } else {
                            tracing::warn!(target: "network", event = "classical_consensus_broadcast_refused", kind = "timeout_certificate", "Strict PQ transport is required but unavailable");
                        }
                    }
                    SwarmCommand::BroadcastAftTimeoutCertificate(data) => {
                        if let Some(manager) = pq_channels.as_mut() {
                            broadcast_pq_consensus(
                                &mut swarm,
                                manager,
                                &mut inflight_pq_handshakes,
                                &mut inflight_pq_consensus,
                                PqConsensusPayloadV1::AftTimeoutCertificate(data),
                            );
                        } else {
                            tracing::warn!(target: "network", event = "scoped_aft_timeout_refused", kind = "certificate", "Scoped AFT timeout evidence requires strict PQ channels");
                        }
                    }
                    SwarmCommand::BroadcastFallbackStart(data) => {
                        if let Some(manager) = pq_channels.as_mut() {
                            broadcast_pq_consensus(
                                &mut swarm,
                                manager,
                                &mut inflight_pq_handshakes,
                                &mut inflight_pq_consensus,
                                PqConsensusPayloadV1::FallbackStart(data),
                            );
                        } else if legacy_consensus_transport_allowed {
                            publish_consensus_directly(
                                &mut swarm,
                                SyncRequest::RelayFallbackStart(data),
                                usize::MAX,
                            );
                        } else {
                            tracing::warn!(target: "network", event = "classical_consensus_broadcast_refused", kind = "fallback_start", "Strict PQ transport is required but unavailable");
                        }
                    }
                    SwarmCommand::BroadcastAftAsyncOrdering(data) => {
                        if let Some(manager) = pq_channels.as_mut() {
                            broadcast_pq_consensus(
                                &mut swarm,
                                manager,
                                &mut inflight_pq_handshakes,
                                &mut inflight_pq_consensus,
                                PqConsensusPayloadV1::AftAsyncOrdering(data),
                            );
                        } else {
                            tracing::warn!(target: "network", event = "aft_async_ordering_refused", "Hash-only asynchronous ordering requires strict PQ channels");
                        }
                    }
                    SwarmCommand::SendAftAsyncOrdering { peer, data } => {
                        if let Some(manager) = pq_channels.as_mut() {
                            send_pq_consensus(
                                &mut swarm,
                                manager,
                                &mut inflight_pq_handshakes,
                                &mut inflight_pq_consensus,
                                peer,
                                PqConsensusPayloadV1::AftAsyncOrdering(data),
                            );
                        } else {
                            tracing::warn!(target: "network", event = "aft_async_private_share_refused", %peer, "Private ASKS traffic requires an enrolled strict PQ channel");
                        }
                    }
                    SwarmCommand::QueueAftAsyncOrdering { recipient, data } => {
                        if let Some(manager) = pq_channels.as_mut() {
                            queue_pq_consensus_for_account(
                                &mut swarm,
                                manager,
                                &mut inflight_pq_handshakes,
                                &mut inflight_pq_consensus,
                                recipient,
                                PqConsensusPayloadV1::AftAsyncOrdering(data),
                            );
                        } else {
                            tracing::warn!(target: "network", event = "aft_async_account_queue_refused", ?recipient, "Account-addressed asynchronous traffic requires configured strict PQ channels");
                        }
                    }
                    SwarmCommand::RetireAftAsyncOrdering { instance_hash } => {
                        if let Some(manager) = pq_channels.as_mut() {
                            match manager.retire_aft_async_instance(instance_hash) {
                                Ok(retired) => {
                                    inflight_pq_consensus.retain(|_, pending| {
                                        !retired.contains(&pending.message_id)
                                    });
                                    for peer in manager.pending_peers() {
                                        flush_pq_peer(
                                            &mut swarm,
                                            manager,
                                            &mut inflight_pq_consensus,
                                            peer,
                                        );
                                    }
                                    tracing::info!(
                                        target: "network",
                                        event = "aft_async_outbox_retired",
                                        ?instance_hash,
                                        retired_messages = retired.len()
                                    );
                                }
                                Err(error) => {
                                    tracing::error!(target: "network", event = "aft_async_outbox_retirement_failed", %error);
                                }
                            }
                        }
                    }
                    SwarmCommand::ConfigurePqChannels { config, enrollments, response } => {
                        // Reconfiguration is a fail-closed authority boundary.
                        // Retire the old manager and every session before
                        // validating replacement custody so a failed rotation
                        // cannot continue under stale scope or keys.
                        begin_strict_pq_reconfiguration(
                            &mut pq_channels,
                            &mut legacy_consensus_transport_allowed,
                        );
                        pending_votes.clear();
                        inflight_pq_handshakes.clear();
                        inflight_pq_consensus.clear();
                        if config.peer_id != *swarm.local_peer_id() {
                            let error = format!(
                                "configured carrier identity {} does not match running swarm {}",
                                config.peer_id,
                                swarm.local_peer_id()
                            );
                            tracing::error!(
                                target: "network",
                                event = "pq_channel_configuration_refused",
                                configured_peer = %config.peer_id,
                                swarm_peer = %swarm.local_peer_id(),
                                "configured carrier identity does not match the running swarm"
                            );
                            let _ = response.send(Err(error));
                        } else {
                            match replace_pq_channel_manager(&mut pq_channels, config, enrollments) {
                                Ok(()) => {
                                    tracing::info!(target: "network", event = "pq_channel_strict_mode_enabled");
                                    let _ = response.send(Ok(()));
                                }
                                Err(error) => {
                                    tracing::error!(target: "network", event = "pq_channel_configuration_refused", %error);
                                    let _ = response.send(Err(error.to_string()));
                                }
                            }
                        }
                    }
                    SwarmCommand::EnrollPqPeer(enrollment) => {
                        let peer = enrollment.peer_id;
                        match pq_channels.as_mut() {
                            Some(manager) => match manager.enroll_peer(enrollment) {
                                Ok(()) => start_pq_handshake(
                                    &mut swarm,
                                    manager,
                                    &mut inflight_pq_handshakes,
                                    peer,
                                ),
                                Err(error) => tracing::warn!(target: "network", event = "pq_peer_enrollment_refused", %peer, %error),
                            },
                            None => tracing::warn!(target: "network", event = "pq_peer_enrollment_refused", %peer, "strict PQ channels are not configured"),
                        }
                    }
                    SwarmCommand::EstablishPqChannel(peer) => {
                        if let Some(manager) = pq_channels.as_mut() {
                            start_pq_handshake(
                                &mut swarm,
                                manager,
                                &mut inflight_pq_handshakes,
                                peer,
                            );
                        }
                    }
                    SwarmCommand::BroadcastEcho(data) => {
                        if let Some(manager) = pq_channels.as_mut() {
                            broadcast_pq_consensus(&mut swarm, manager, &mut inflight_pq_handshakes, &mut inflight_pq_consensus, PqConsensusPayloadV1::Echo(data));
                        } else if legacy_consensus_transport_allowed {
                            let _ = swarm.behaviour_mut().gossipsub.publish(echo_topic.clone(), data);
                        } else {
                            tracing::warn!(target: "network", event = "classical_consensus_broadcast_refused", kind = "echo", "Strict PQ transport is required but unavailable");
                        }
                    }
                    SwarmCommand::BroadcastPanic(data) => {
                        if let Some(manager) = pq_channels.as_mut() {
                            broadcast_pq_consensus(&mut swarm, manager, &mut inflight_pq_handshakes, &mut inflight_pq_consensus, PqConsensusPayloadV1::Panic(data));
                        } else if legacy_consensus_transport_allowed {
                            let _ = swarm.behaviour_mut().gossipsub.publish(panic_topic.clone(), data);
                        } else {
                            tracing::warn!(target: "network", event = "classical_consensus_broadcast_refused", kind = "panic", "Strict PQ transport is required but unavailable");
                        }
                    }
                    SwarmCommand::BroadcastConfidence(data) => {
                        if let Some(manager) = pq_channels.as_mut() {
                            broadcast_pq_consensus(&mut swarm, manager, &mut inflight_pq_handshakes, &mut inflight_pq_consensus, PqConsensusPayloadV1::Confidence(data));
                        } else if legacy_consensus_transport_allowed {
                            let _ = swarm.behaviour_mut().gossipsub.publish(confidence_topic.clone(), data);
                        } else {
                            tracing::warn!(target: "network", event = "classical_consensus_broadcast_refused", kind = "confidence", "Strict PQ transport is required but unavailable");
                        }
                    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_api::crypto::{SerializableKey, SigningKeyPair};
    use ioi_crypto::security::SecurityLevel;
    use ioi_crypto::sign::dilithium::MldsaScheme;
    use ioi_crypto::transport::pq_authenticated_channel::PqChannelContentTypeV1;
    use ioi_types::app::{account_id_from_key_material, AccountId, SignatureSuite};
    use libp2p::identity::Keypair;

    #[test]
    fn addressed_peer_extracts_only_explicit_p2p_identity() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let addressed: Multiaddr = format!("/ip4/127.0.0.1/tcp/9000/p2p/{peer}")
            .parse()
            .unwrap();
        assert_eq!(addressed_peer(&addressed), Some(peer));

        let transport_only: Multiaddr = "/ip4/127.0.0.1/tcp/9000".parse().unwrap();
        assert_eq!(addressed_peer(&transport_only), None);
    }

    #[test]
    fn failed_pq_reconfiguration_retires_old_authority() {
        let temp = tempfile::tempdir().unwrap();
        let old_config = local_config(1, temp.path().join("old.outbox"));
        let mut active = Some(PqChannelSessionManager::new(old_config).unwrap());
        let mut legacy_consensus_transport_allowed = true;

        begin_strict_pq_reconfiguration(&mut active, &mut legacy_consensus_transport_allowed);
        assert!(
            active.is_none(),
            "strict transition retires the old manager"
        );
        assert!(
            !legacy_consensus_transport_allowed,
            "strict transition permanently closes classical consensus transport"
        );

        let mut invalid_replacement = local_config(2, temp.path().join("invalid.outbox"));
        invalid_replacement.configuration_hash = [0; 32];
        assert!(replace_pq_channel_manager(&mut active, invalid_replacement, Vec::new()).is_err());
        assert!(
            active.is_none(),
            "failed construction must retire the old manager"
        );

        let replacement = local_config(3, temp.path().join("replacement.outbox"));
        let aliases_local_endpoint = PqPeerEnrollment {
            peer_id: replacement.peer_id,
            account_id: replacement.account_id,
            identity_key_hash: replacement.identity_key_hash,
        };
        assert!(
            replace_pq_channel_manager(&mut active, replacement, vec![aliases_local_endpoint],)
                .is_err()
        );
        assert!(
            active.is_none(),
            "failed enrollment must leave strict transport disabled"
        );
    }

    fn local_config(account: u8, outbox_path: std::path::PathBuf) -> PqChannelLocalConfig {
        let identity = MldsaScheme::new(SecurityLevel::Level2)
            .generate_keypair()
            .unwrap();
        let identity_key_hash = account_id_from_key_material(
            SignatureSuite::ML_DSA_44,
            &identity.public_key().to_bytes(),
        )
        .unwrap();
        PqChannelLocalConfig {
            network_id: [1; 32],
            configuration_hash: [2; 32],
            epoch: 3,
            account_id: AccountId([account; 32]),
            peer_id: Keypair::generate_ed25519().public().to_peer_id(),
            identity,
            identity_key_hash,
            outbox_path,
        }
    }

    fn established_managers() -> (
        tempfile::TempDir,
        PqChannelSessionManager,
        libp2p::PeerId,
        PqChannelSessionManager,
        libp2p::PeerId,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let mut a_config = local_config(10, temp.path().join("a.outbox"));
        let mut b_config = local_config(11, temp.path().join("b.outbox"));
        if a_config.peer_id.to_bytes() > b_config.peer_id.to_bytes() {
            std::mem::swap(&mut a_config, &mut b_config);
        }
        let a_peer = a_config.peer_id;
        let b_peer = b_config.peer_id;
        let a_enrollment = PqPeerEnrollment {
            peer_id: a_peer,
            account_id: a_config.account_id,
            identity_key_hash: a_config.identity_key_hash,
        };
        let b_enrollment = PqPeerEnrollment {
            peer_id: b_peer,
            account_id: b_config.account_id,
            identity_key_hash: b_config.identity_key_hash,
        };
        let mut a = PqChannelSessionManager::new(a_config).unwrap();
        let mut b = PqChannelSessionManager::new(b_config).unwrap();
        a.enroll_peer(b_enrollment).unwrap();
        b.enroll_peer(a_enrollment).unwrap();
        let hello = a.start(b_peer).unwrap();
        let server = b.accept(a_peer, hello).unwrap();
        let finish = a.finish(b_peer, server).unwrap();
        b.complete(a_peer, finish).unwrap();
        a.confirm_application_ready(&b_peer).unwrap();
        (temp, a, a_peer, b, b_peer)
    }

    #[tokio::test]
    async fn protected_payload_routes_only_after_aead_and_type_agreement() {
        let (_temp, mut initiator, initiator_peer, mut responder, responder_peer) =
            established_managers();
        let (event_sender, mut event_receiver) = mpsc::channel(4);

        let vote_payload = PqConsensusPayloadV1::Vote(b"canonical vote".to_vec());
        let vote_plaintext = codec::to_bytes_canonical(&vote_payload).unwrap();
        let vote_record = initiator
            .seal(
                &responder_peer,
                PqChannelContentTypeV1::ConsensusVote,
                &vote_plaintext,
            )
            .unwrap();
        deliver_pq_record(&event_sender, &mut responder, initiator_peer, vote_record)
            .await
            .unwrap();
        assert!(matches!(
            event_receiver.recv().await,
            Some(SwarmInternalEvent::ConsensusVoteReceived(data, peer))
                if data == b"canonical vote" && peer == initiator_peer
        ));

        let fallback_payload =
            PqConsensusPayloadV1::TimeoutCertificate(b"formed timeout certificate".to_vec());
        let fallback_plaintext = codec::to_bytes_canonical(&fallback_payload).unwrap();
        let fallback_record = initiator
            .seal(
                &responder_peer,
                PqChannelContentTypeV1::FallbackControl,
                &fallback_plaintext,
            )
            .unwrap();
        deliver_pq_record(
            &event_sender,
            &mut responder,
            initiator_peer,
            fallback_record,
        )
        .await
        .unwrap();
        assert!(matches!(
            event_receiver.recv().await,
            Some(SwarmInternalEvent::TimeoutCertificateReceived(data, peer))
                if data == b"formed timeout certificate" && peer == initiator_peer
        ));

        let scoped_payload =
            PqConsensusPayloadV1::AftTimeoutCertificate(b"scoped PQ timeout certificate".to_vec());
        let scoped_plaintext = codec::to_bytes_canonical(&scoped_payload).unwrap();
        let scoped_record = initiator
            .seal(
                &responder_peer,
                PqChannelContentTypeV1::FallbackControl,
                &scoped_plaintext,
            )
            .unwrap();
        deliver_pq_record(&event_sender, &mut responder, initiator_peer, scoped_record)
            .await
            .unwrap();
        assert!(matches!(
            event_receiver.recv().await,
            Some(SwarmInternalEvent::AftTimeoutCertificateReceived(data, peer))
                if data == b"scoped PQ timeout certificate" && peer == initiator_peer
        ));

        let async_payload =
            PqConsensusPayloadV1::AftAsyncOrdering(b"private-channel ASKS share".to_vec());
        let async_plaintext = codec::to_bytes_canonical(&async_payload).unwrap();
        let async_record = initiator
            .seal(
                &responder_peer,
                PqChannelContentTypeV1::AsynchronousConsensus,
                &async_plaintext,
            )
            .unwrap();
        deliver_pq_record(&event_sender, &mut responder, initiator_peer, async_record)
            .await
            .unwrap();
        assert!(matches!(
            event_receiver.recv().await,
            Some(SwarmInternalEvent::AftAsyncOrderingReceived(data, account, peer))
                if data == b"private-channel ASKS share" && peer == initiator_peer
                    && account == responder.remote_account(&initiator_peer).unwrap()
        ));

        // Even a valid AEAD record cannot launder one payload class into
        // another authenticated content type.
        let qc_payload = PqConsensusPayloadV1::QuorumCertificate(b"qc".to_vec());
        let qc_plaintext = codec::to_bytes_canonical(&qc_payload).unwrap();
        let mismatched_record = initiator
            .seal(
                &responder_peer,
                PqChannelContentTypeV1::ConsensusVote,
                &qc_plaintext,
            )
            .unwrap();
        assert!(deliver_pq_record(
            &event_sender,
            &mut responder,
            initiator_peer,
            mismatched_record,
        )
        .await
        .is_err());
        assert!(event_receiver.try_recv().is_err());
    }
}
