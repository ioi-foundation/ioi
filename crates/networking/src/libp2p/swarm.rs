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
use ioi_types::app::{AccountId, QuvNonce, QuvPushQueryV0, QuvReplyV0};
use ioi_types::codec;

use super::behaviour::{SyncBehaviour, SyncBehaviourEvent};
use super::pq_channel::{PqChannelLocalConfig, PqChannelSessionManager, PqPeerEnrollment};
use super::sync::{PqConsensusPayloadV1, SyncRequest, SyncResponse};
use super::types::{SwarmCommand, SwarmInternalEvent};

const PENDING_BLOCK_OUTBOX_MAX: usize = 128;
const PENDING_TX_OUTBOX_MAX: usize = 65_536;
const PENDING_VOTE_OUTBOX_MAX: usize = 256;
const BLOCK_SYNC_MAX_BYTES: u32 = 64 * 1024 * 1024;
/// How many times one connection may report an erased provisional PQ
/// enrollment. Each report asks the validator for one status-driven
/// re-enrollment; the session manager's provisional lifetime and per-account
/// caps still bound what such a re-enrollment can hold.
const PQ_ENROLLMENT_LOST_REPORTS_PER_CONNECTION: u32 = 4;

/// What the transport owes the sender for one authenticated protected record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PqRecordAdmission {
    /// The record reached its handler; acknowledge on the transport now.
    ///
    /// An admitted QUV PUSHQUERY is acknowledged here too, right after the
    /// mpsc forward. Withholding that ACK until durable member processing
    /// was tried and reverted: it serialized the member's own QUV reply
    /// behind the requester's push on the single-in-flight peer lane and
    /// missed the rooted decision cutoff under saturation, while a member
    /// that crashes between ACK and processing is outside the theorem's
    /// timely-correct-member premise for that operation (the verifier
    /// aborts by deadline; no authority is minted from the loss).
    AckNow,
}

/// Releases the requester's timing lane for this exact push. Returns whether
/// a lane was released.
fn complete_quv_push(
    quv_push_inflight: &mut HashMap<AccountId, QuvNonce>,
    requester: AccountId,
    nonce: QuvNonce,
) -> bool {
    if quv_push_inflight.get(&requester) == Some(&nonce) {
        quv_push_inflight.remove(&requester);
        true
    } else {
        false
    }
}

/// A NACK names a record the member refused without durable admission (lane
/// occupied by another nonce, or nonce-stale). Only the transport attempt is
/// over: the durable record stays queued and the next tick may resend it.
/// Returns whether the NACK matched the request in flight for that peer.
fn release_nacked_pq_record(
    inflight: &mut HashMap<PeerId, InflightPqRequest>,
    peer: PeerId,
    request_id: libp2p::request_response::OutboundRequestId,
) -> bool {
    let matched = inflight
        .get(&peer)
        .is_some_and(|pending| pending.request_id == request_id);
    if matched {
        inflight.remove(&peer);
    }
    matched
}

/// Decides whether an erased provisional enrollment is reported to the
/// validator. Only a still-connected carrier is worth a status refresh (a
/// disconnected one is re-derived on reconnect), and each connection may ask
/// at most `PQ_ENROLLMENT_LOST_REPORTS_PER_CONNECTION` times.
fn pq_enrollment_lost_report(
    lost_reports: &mut HashMap<PeerId, u32>,
    peer: PeerId,
    connected: bool,
) -> Option<SwarmInternalEvent> {
    if !connected {
        return None;
    }
    let reports = lost_reports.entry(peer).or_insert(0);
    if *reports >= PQ_ENROLLMENT_LOST_REPORTS_PER_CONNECTION {
        return None;
    }
    *reports += 1;
    Some(SwarmInternalEvent::PqEnrollmentLost(peer))
}

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
    handoff_only: bool,
) -> Result<(), String> {
    // The old configuration must become unusable before any fallible work on
    // the replacement. A construction or enrollment failure therefore leaves
    // strict transport disabled, never silently active under stale authority.
    *current = None;
    let mut replacement = if handoff_only {
        PqChannelSessionManager::new_handoff_only(config)
    } else {
        PqChannelSessionManager::new(config)
    }
    .map_err(|error| error.to_string())?;
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

/// Recovery after a handshake or protected-record failure. Ephemeral keys are
/// dropped so a retry uses a fresh transcript. A still-enrolled (authenticated
/// or provisional-and-live) peer retries in place, exactly as before. An
/// enrollment the disconnect erased cannot be retried locally, because
/// `start` requires one; the caller forwards the returned event so the
/// validator re-derives it from a fresh status exchange.
fn recover_pq_peer_after_failure(
    swarm: &mut Swarm<SyncBehaviour>,
    manager: &mut PqChannelSessionManager,
    inflight: &mut HashMap<libp2p::PeerId, InflightPqHandshake>,
    lost_reports: &mut HashMap<PeerId, u32>,
    peer: libp2p::PeerId,
) -> Option<SwarmInternalEvent> {
    manager.disconnect(&peer);
    if manager.enrolled_peers().any(|enrolled| enrolled == peer) {
        start_pq_handshake(swarm, manager, inflight, peer);
        return None;
    }
    tracing::info!(
        target: "network",
        event = "pq_provisional_enrollment_lost",
        %peer,
        connected = swarm.is_connected(&peer)
    );
    pq_enrollment_lost_report(lost_reports, peer, swarm.is_connected(&peer))
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
        if !manager.permits_sent_payload(&peer, &payload) {
            continue;
        }
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
) -> anyhow::Result<()> {
    manager.enqueue_for_account(recipient, payload)?;
    let Some(peer) = manager.peer_for_account(recipient) else {
        tracing::debug!(target: "network", event = "pq_consensus_waiting_for_enrollment", ?recipient);
        return Ok(());
    };
    if manager.is_established(&peer) {
        flush_pq_peer(swarm, manager, inflight, peer);
    } else {
        start_pq_handshake(swarm, manager, handshakes, peer);
    }
    Ok(())
}

async fn deliver_pq_record(
    event_sender: &mpsc::Sender<SwarmInternalEvent>,
    quv_event_sender: &mpsc::Sender<SwarmInternalEvent>,
    quv_push_inflight: &mut HashMap<ioi_types::app::AccountId, QuvNonce>,
    quv_reply_inflight: &mut HashSet<ioi_types::app::AccountId>,
    active_quv_operation: Option<QuvNonce>,
    manager: &mut PqChannelSessionManager,
    peer: libp2p::PeerId,
    record: ioi_crypto::transport::pq_authenticated_channel::PqChannelRecordV1,
) -> anyhow::Result<PqRecordAdmission> {
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
    if !manager.permits_received_payload(&peer, &payload) {
        anyhow::bail!("protected consensus payload exceeds the rooted PQ endpoint capability");
    }
    let push_nonce = match &payload {
        PqConsensusPayloadV1::QuvPushQuery(bytes) => Some(
            codec::from_bytes_canonical::<QuvPushQueryV0>(bytes)
                .map_err(anyhow::Error::msg)?
                .verifier_nonce,
        ),
        _ => None,
    };
    let reply_nonce = match &payload {
        PqConsensusPayloadV1::QuvReply(bytes) => Some(
            codec::from_bytes_canonical::<QuvReplyV0>(bytes)
                .map_err(anyhow::Error::msg)?
                .verifier_nonce,
        ),
        _ => None,
    };
    let admitted_quv_push = if let Some(nonce) = push_nonce {
        match quv_push_inflight.get(&authenticated_account).copied() {
            None => {
                quv_push_inflight.insert(authenticated_account, nonce);
                true
            }
            Some(existing) if existing == nonce => {
                // The push is already in member work; acknowledge the retry
                // without forwarding it a second time.
                tracing::debug!(
                    target: "quv",
                    ?authenticated_account,
                    "Acknowledged a duplicate QUV PUSHQUERY after the push was admitted"
                );
                return Ok(PqRecordAdmission::AckNow);
            }
            Some(_) => {
                anyhow::bail!(
                    "authenticated QUV requester already occupies its timing lane with another nonce"
                );
            }
        }
    } else {
        false
    };
    let admitted_quv_reply = if let Some(nonce) = reply_nonce {
        if active_quv_operation != Some(nonce) {
            // Retire the sender's stale durable record without letting it
            // occupy the current operation's per-member admission slot.
            tracing::debug!(
                target: "quv",
                ?authenticated_account,
                "Acknowledged a nonce-stale QUV reply outside the active verifier operation"
            );
            return Ok(PqRecordAdmission::AckNow);
        }
        if !quv_reply_inflight.insert(authenticated_account) {
            tracing::debug!(
                target: "quv",
                ?authenticated_account,
                "Acknowledged a duplicate QUV reply after the member's response was admitted"
            );
            return Ok(PqRecordAdmission::AckNow);
        }
        true
    } else {
        false
    };
    let is_quv = matches!(
        &payload,
        PqConsensusPayloadV1::QuvPushQuery(_) | PqConsensusPayloadV1::QuvReply(_)
    );
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
        PqConsensusPayloadV1::QuvPushQuery(data) => {
            SwarmInternalEvent::QuvPushQueryReceived(data, authenticated_account, peer)
        }
        PqConsensusPayloadV1::QuvReply(data) => {
            SwarmInternalEvent::QuvReplyReceived(data, authenticated_account, peer)
        }
    };
    let sender = if is_quv {
        quv_event_sender
    } else {
        event_sender
    };
    if let Some(nonce) = reply_nonce {
        tracing::debug!(target: "quv", event = "reply_network_admitted", nonce_bytes = ?nonce, ?authenticated_account);
    }
    let sent = sender
        .send(event)
        .await
        .map_err(|_| anyhow::anyhow!("network event receiver closed"));
    if let Some(nonce) = reply_nonce {
        // These diagnostics delimit channel forwarding, not verifier observation.
        tracing::debug!(target: "quv", event = "reply_event_forwarded", nonce_bytes = ?nonce, ?authenticated_account, succeeded = sent.is_ok());
    }
    if sent.is_err() && admitted_quv_push {
        if let Some(nonce) = push_nonce {
            if quv_push_inflight.get(&authenticated_account) == Some(&nonce) {
                quv_push_inflight.remove(&authenticated_account);
            }
        }
    }
    if sent.is_err() && admitted_quv_reply {
        quv_reply_inflight.remove(&authenticated_account);
    }
    sent?;
    Ok(PqRecordAdmission::AckNow)
}

async fn handle_quv_command(
    command: SwarmCommand,
    swarm: &mut Swarm<SyncBehaviour>,
    pq_channels: &mut Option<PqChannelSessionManager>,
    inflight_pq_handshakes: &mut HashMap<libp2p::PeerId, InflightPqHandshake>,
    inflight_pq_consensus: &mut HashMap<libp2p::PeerId, InflightPqRequest>,
    quv_push_inflight: &mut HashMap<ioi_types::app::AccountId, QuvNonce>,
    quv_reply_inflight: &mut HashSet<ioi_types::app::AccountId>,
    active_quv_operation: &mut Option<QuvNonce>,
) {
    match command {
        SwarmCommand::BeginQuvOperation { nonce, response } => {
            quv_reply_inflight.clear();
            if let Some(manager) = pq_channels.as_mut() {
                match manager.retire_stale_quv_pushes(nonce) {
                    Ok(retired) => inflight_pq_consensus
                        .retain(|_, pending| !retired.contains(&pending.message_id)),
                    Err(error) => {
                        tracing::error!(target: "quv", %error, "Failed to retire stale durable QUV requests before operation admission");
                        return;
                    }
                }
            }
            *active_quv_operation = Some(nonce);
            let _ = response.send(());
        }
        SwarmCommand::QueueQuvPushQuery {
            recipient,
            data,
            response,
        } => {
            let result = if let Some(manager) = pq_channels.as_mut() {
                queue_pq_consensus_for_account(
                    swarm,
                    manager,
                    inflight_pq_handshakes,
                    inflight_pq_consensus,
                    recipient,
                    PqConsensusPayloadV1::QuvPushQuery(data),
                )
                .map_err(|error| error.to_string())
            } else {
                tracing::warn!(target: "network", event = "aft_quv_query_refused", ?recipient, "QUV requires configured strict PQ channels");
                Err("QUV requires configured strict PQ channels".to_string())
            };
            let _ = response.send(result);
        }
        SwarmCommand::QueueQuvReply { recipient, data } => {
            if let Some(manager) = pq_channels.as_mut() {
                match manager
                    .enqueue_quv_reply_for_account(recipient, PqConsensusPayloadV1::QuvReply(data))
                {
                    Ok((_, retired)) => {
                        inflight_pq_consensus
                            .retain(|_, pending| !retired.contains(&pending.message_id));
                        if let Some(peer) = manager.peer_for_account(recipient) {
                            if manager.is_established(&peer) {
                                flush_pq_peer(swarm, manager, inflight_pq_consensus, peer);
                            } else {
                                start_pq_handshake(swarm, manager, inflight_pq_handshakes, peer);
                            }
                        }
                    }
                    Err(error) => {
                        tracing::error!(target: "network", event = "aft_quv_reply_enqueue_failed", ?recipient, %error);
                    }
                }
            } else {
                tracing::warn!(target: "network", event = "aft_quv_reply_refused", ?recipient, "QUV requires configured strict PQ channels");
            }
        }
        SwarmCommand::CompleteQuvPush { requester, nonce } => {
            // The validator reports member processing (or a closed refusal)
            // at every terminal point; the transport ACK was already sent at
            // admission, so only the requester's timing lane is released.
            if !complete_quv_push(quv_push_inflight, requester, nonce) {
                tracing::debug!(
                    target: "quv",
                    ?requester,
                    "CompleteQuvPush named a push that no longer holds the requester's lane"
                );
            }
        }
        SwarmCommand::CompleteQuvOperation { nonce } => {
            if *active_quv_operation == Some(nonce) {
                if let Some(manager) = pq_channels.as_mut() {
                    match manager.retire_quv_operation(nonce) {
                        Ok(retired) => inflight_pq_consensus
                            .retain(|_, pending| !retired.contains(&pending.message_id)),
                        Err(error) => {
                            tracing::error!(target: "quv", %error, "Failed to retire completed durable QUV requests")
                        }
                    }
                }
                *active_quv_operation = None;
                quv_reply_inflight.clear();
            }
        }
        _ => {
            tracing::error!(target: "quv", "Non-QUV swarm command was sent through the isolated QUV lane");
        }
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
    mut quv_command_receiver: mpsc::Receiver<SwarmCommand>,
    event_sender: mpsc::Sender<SwarmInternalEvent>,
    quv_event_sender: mpsc::Sender<SwarmInternalEvent>,
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
    let mut quv_push_inflight: HashMap<ioi_types::app::AccountId, QuvNonce> = HashMap::new();
    let mut quv_reply_inflight: HashSet<ioi_types::app::AccountId> = HashSet::new();
    let mut pq_enrollment_lost_reports: HashMap<PeerId, u32> = HashMap::new();
    let mut active_quv_operation = None;
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
            biased;
            Some(command) = quv_command_receiver.recv() => {
                handle_quv_command(
                    command,
                    &mut swarm,
                    &mut pq_channels,
                    &mut inflight_pq_handshakes,
                    &mut inflight_pq_consensus,
                    &mut quv_push_inflight,
                    &mut quv_reply_inflight,
                    &mut active_quv_operation,
                ).await;
            },
            _ = retry_interval.tick() => {
                drain_pending_blocks(&mut pending_blocks, &mut swarm.behaviour_mut().gossipsub, &block_topic_a, &block_topic_b);
                drain_pending_txs(&mut pending_txs, &mut swarm.behaviour_mut().gossipsub, &tx_topic);
                drain_pending_votes(&mut pending_votes, &mut swarm.behaviour_mut().gossipsub);
                if let Some(manager) = pq_channels.as_mut() {
                    manager.expire_provisional_enrollments();
                    let enrolled = manager.enrolled_peers().collect::<std::collections::HashSet<_>>();
                    // Drop only ephemeral retry handles for expired/evicted
                    // carriers. Protected outbox entries remain durable.
                    inflight_pq_handshakes.retain(|peer, _| enrolled.contains(peer));
                    inflight_pq_consensus.retain(|peer, _| enrolled.contains(peer));
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
                        pq_enrollment_lost_reports.remove(&peer_id);
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
                                    let result = pq_channels.as_mut()
                                        .ok_or_else(|| anyhow::anyhow!("strict PQ channels are not configured"))
                                        .and_then(|manager| {
                                            manager.complete(peer, finish)?;
                                            manager.remote_account(&peer)
                                                .ok_or_else(|| anyhow::anyhow!("completed PQ carrier lacks authenticated account"))
                                        });
                                    match result {
                                        Ok(account) => {
                                            let _ = swarm.behaviour_mut().request_response.send_response(channel, SyncResponse::PqChannelAck);
                                            pq_enrollment_lost_reports.remove(&peer);
                                            event_sender.send(SwarmInternalEvent::PqCarrierAuthenticated(peer, account)).await.ok();
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
                                        Some(manager) => deliver_pq_record(
                                            &event_sender,
                                            &quv_event_sender,
                                            &mut quv_push_inflight,
                                            &mut quv_reply_inflight,
                                            active_quv_operation,
                                            manager,
                                            peer,
                                            record,
                                        ).await,
                                        None => Err(anyhow::anyhow!("strict PQ channels are not configured")),
                                    };
                                    match result {
                                        Ok(PqRecordAdmission::AckNow) => {
                                            let _ = swarm.behaviour_mut().request_response.send_response(channel, SyncResponse::PqChannelAck);
                                        }
                                        Err(error) => {
                                            // Refused without durable admission: tell the
                                            // requester explicitly so it keeps its record
                                            // and retries without a session teardown.
                                            tracing::warn!(target: "network", event = "pq_record_refused", %peer, %error);
                                            let _ = swarm.behaviour_mut().request_response.send_response(channel, SyncResponse::PqChannelNack);
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
                                                let lost = recover_pq_peer_after_failure(
                                                    &mut swarm,
                                                    manager,
                                                    &mut inflight_pq_handshakes,
                                                    &mut pq_enrollment_lost_reports,
                                                    peer,
                                                );
                                                if let Some(lost) = lost {
                                                    event_sender.send(lost).await.ok();
                                                }
                                            }
                                        }
                                    }
                                }
                                SyncResponse::PqChannelNack => {
                                    // Only the transport attempt ended; the durable
                                    // record stays queued for the next retry tick.
                                    if release_nacked_pq_record(&mut inflight_pq_consensus, peer, request_id) {
                                        tracing::debug!(target: "network", event = "pq_record_nacked", %peer, "member refused the record without durable admission; retaining it for a later attempt");
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
                                            let authenticated = manager
                                                .confirm_application_ready(&peer)
                                                .and_then(|()| manager.remote_account(&peer)
                                                    .ok_or_else(|| anyhow::anyhow!("confirmed PQ carrier lacks authenticated account")));
                                            let account = match authenticated {
                                                Ok(account) => account,
                                                Err(error) => {
                                                tracing::warn!(target: "network", event = "pq_channel_ack_refused", %peer, %error);
                                                let lost = recover_pq_peer_after_failure(
                                                    &mut swarm,
                                                    manager,
                                                    &mut inflight_pq_handshakes,
                                                    &mut pq_enrollment_lost_reports,
                                                    peer,
                                                );
                                                if let Some(lost) = lost {
                                                    event_sender.send(lost).await.ok();
                                                }
                                                continue;
                                                }
                                            };
                                            pq_enrollment_lost_reports.remove(&peer);
                                            event_sender.send(SwarmInternalEvent::PqCarrierAuthenticated(peer, account)).await.ok();
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
                                                    inflight_pq_handshakes.remove(&peer);
                                                    let lost = recover_pq_peer_after_failure(
                                                        &mut swarm,
                                                        manager,
                                                        &mut inflight_pq_handshakes,
                                                        &mut pq_enrollment_lost_reports,
                                                        peer,
                                                    );
                                                    if let Some(lost) = lost {
                                                        event_sender.send(lost).await.ok();
                                                    }
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
                                    // An unproven enrollment is erased by that drop and
                                    // cannot be restarted here; report it instead so the
                                    // validator re-derives it from a fresh status exchange.
                                    let lost = recover_pq_peer_after_failure(
                                        &mut swarm,
                                        manager,
                                        &mut inflight_pq_handshakes,
                                        &mut pq_enrollment_lost_reports,
                                        peer,
                                    );
                                    if let Some(lost) = lost {
                                        event_sender.send(lost).await.ok();
                                    }
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
                            if let Err(error) = queue_pq_consensus_for_account(
                                &mut swarm,
                                manager,
                                &mut inflight_pq_handshakes,
                                &mut inflight_pq_consensus,
                                recipient,
                                PqConsensusPayloadV1::AftAsyncOrdering(data),
                            ) {
                                tracing::error!(target: "network", event = "pq_consensus_durable_enqueue_failed", ?recipient, %error);
                            }
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
                    SwarmCommand::QueueQuvPushQuery { .. }
                    | SwarmCommand::QueueQuvReply { .. }
                    | SwarmCommand::CompleteQuvPush { .. }
                    | SwarmCommand::BeginQuvOperation { .. }
                    | SwarmCommand::CompleteQuvOperation { .. } => {
                        tracing::error!(target: "quv", "QUV command was sent through the general swarm lane and refused");
                    }
                    SwarmCommand::ConfigurePqChannels { config, enrollments, handoff_only, response } => {
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
                        quv_push_inflight.clear();
                        quv_reply_inflight.clear();
                        pq_enrollment_lost_reports.clear();
                        active_quv_operation = None;
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
                            match replace_pq_channel_manager(&mut pq_channels, config, enrollments, handoff_only) {
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
                    SwarmCommand::EnrollPqHandoffPeer(enrollment) => {
                        let peer = enrollment.peer_id;
                        match pq_channels.as_mut() {
                            Some(manager) => match manager.enroll_handoff_peer(enrollment) {
                                Ok(()) => start_pq_handshake(
                                    &mut swarm,
                                    manager,
                                    &mut inflight_pq_handshakes,
                                    peer,
                                ),
                                Err(error) => tracing::warn!(target: "network", event = "pq_handoff_peer_enrollment_refused", %peer, %error),
                            },
                            None => tracing::warn!(target: "network", event = "pq_handoff_peer_enrollment_refused", %peer, "strict PQ channels are not configured"),
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
        assert!(
            replace_pq_channel_manager(&mut active, invalid_replacement, Vec::new(), false)
                .is_err()
        );
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
        assert!(replace_pq_channel_manager(
            &mut active,
            replacement,
            vec![aliases_local_endpoint],
            false,
        )
        .is_err());
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
            rooted_accounts: (0..=255)
                .map(|id| ioi_types::app::AccountId([id; 32]))
                .collect(),
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
        let (quv_event_sender, mut quv_event_receiver) = mpsc::channel(4);
        let mut quv_push_inflight = HashMap::new();
        let mut quv_reply_inflight = HashSet::new();
        let quv_nonce = [31; 32];

        let vote_payload = PqConsensusPayloadV1::Vote(b"canonical vote".to_vec());
        let vote_plaintext = codec::to_bytes_canonical(&vote_payload).unwrap();
        let vote_record = initiator
            .seal(
                &responder_peer,
                PqChannelContentTypeV1::ConsensusVote,
                &vote_plaintext,
            )
            .unwrap();
        deliver_pq_record(
            &event_sender,
            &quv_event_sender,
            &mut quv_push_inflight,
            &mut quv_reply_inflight,
            Some(quv_nonce),
            &mut responder,
            initiator_peer,
            vote_record,
        )
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
            &quv_event_sender,
            &mut quv_push_inflight,
            &mut quv_reply_inflight,
            Some(quv_nonce),
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
        deliver_pq_record(
            &event_sender,
            &quv_event_sender,
            &mut quv_push_inflight,
            &mut quv_reply_inflight,
            Some(quv_nonce),
            &mut responder,
            initiator_peer,
            scoped_record,
        )
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
        deliver_pq_record(
            &event_sender,
            &quv_event_sender,
            &mut quv_push_inflight,
            &mut quv_reply_inflight,
            Some(quv_nonce),
            &mut responder,
            initiator_peer,
            async_record,
        )
        .await
        .unwrap();
        assert!(matches!(
            event_receiver.recv().await,
            Some(SwarmInternalEvent::AftAsyncOrderingReceived(data, account, peer))
                if data == b"private-channel ASKS share" && peer == initiator_peer
                    && account == responder.remote_account(&initiator_peer).unwrap()
        ));

        let slot = ioi_types::app::QuvSlotV0 {
            configuration_root: [1; 32],
            policy_root: [2; 32],
            network_id: [3; 32],
            domain_id: [4; 32],
            slot: 1,
            predecessor: [5; 32],
            authority_mode: ioi_types::app::QuvAuthorityModeV0::Owned,
        };
        let candidate = ioi_types::app::QuvCandidateV0 {
            slot: slot.clone(),
            payload_hash: [6; 32],
            authorizer: responder.remote_account(&initiator_peer).unwrap(),
            authority_signature: vec![7],
        };
        let query = QuvPushQueryV0 {
            verifier_nonce: quv_nonce,
            candidate: candidate.clone(),
        };
        let reply = QuvReplyV0 {
            verifier_nonce: quv_nonce,
            member: responder.remote_account(&initiator_peer).unwrap(),
            slot,
            candidate_hash: [8; 32],
            snapshot_hash: [9; 32],
            complete_snapshot: vec![candidate],
            signature: vec![10],
        };
        let query_bytes = codec::to_bytes_canonical(&query).unwrap();
        let reply_bytes = codec::to_bytes_canonical(&reply).unwrap();
        for (payload, expected_bytes, expected_request) in [
            (
                PqConsensusPayloadV1::QuvPushQuery(query_bytes.clone()),
                query_bytes,
                true,
            ),
            (
                PqConsensusPayloadV1::QuvReply(reply_bytes.clone()),
                reply_bytes,
                false,
            ),
        ] {
            let plaintext = codec::to_bytes_canonical(&payload).unwrap();
            let record = initiator
                .seal(
                    &responder_peer,
                    PqChannelContentTypeV1::OnlineAuthorization,
                    &plaintext,
                )
                .unwrap();
            deliver_pq_record(
                &event_sender,
                &quv_event_sender,
                &mut quv_push_inflight,
                &mut quv_reply_inflight,
                Some(quv_nonce),
                &mut responder,
                initiator_peer,
                record,
            )
            .await
            .unwrap();
            let event = quv_event_receiver.recv().await;
            if expected_request {
                assert!(matches!(
                    event,
                    Some(SwarmInternalEvent::QuvPushQueryReceived(data, account, peer))
                        if data == expected_bytes && peer == initiator_peer
                            && account == responder.remote_account(&initiator_peer).unwrap()
                ));
                let duplicate_payload = payload.clone();
                let duplicate_plaintext = codec::to_bytes_canonical(&duplicate_payload).unwrap();
                let duplicate_record = initiator
                    .seal(
                        &responder_peer,
                        PqChannelContentTypeV1::OnlineAuthorization,
                        &duplicate_plaintext,
                    )
                    .unwrap();
                deliver_pq_record(
                    &event_sender,
                    &quv_event_sender,
                    &mut quv_push_inflight,
                    &mut quv_reply_inflight,
                    Some(quv_nonce),
                    &mut responder,
                    initiator_peer,
                    duplicate_record,
                )
                .await
                .unwrap();
                assert!(quv_event_receiver.try_recv().is_err());
            } else {
                assert!(matches!(
                    event,
                    Some(SwarmInternalEvent::QuvReplyReceived(data, account, peer))
                        if data == expected_bytes && peer == initiator_peer
                            && account == responder.remote_account(&initiator_peer).unwrap()
                ));
                let duplicate_payload = payload.clone();
                let duplicate_plaintext = codec::to_bytes_canonical(&duplicate_payload).unwrap();
                let duplicate_record = initiator
                    .seal(
                        &responder_peer,
                        PqChannelContentTypeV1::OnlineAuthorization,
                        &duplicate_plaintext,
                    )
                    .unwrap();
                deliver_pq_record(
                    &event_sender,
                    &quv_event_sender,
                    &mut quv_push_inflight,
                    &mut quv_reply_inflight,
                    Some(quv_nonce),
                    &mut responder,
                    initiator_peer,
                    duplicate_record,
                )
                .await
                .unwrap();
                assert!(quv_event_receiver.try_recv().is_err());
            }
        }

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
            &quv_event_sender,
            &mut quv_push_inflight,
            &mut quv_reply_inflight,
            Some(quv_nonce),
            &mut responder,
            initiator_peer,
            mismatched_record,
        )
        .await
        .is_err());
        assert!(event_receiver.try_recv().is_err());
        assert!(quv_event_receiver.try_recv().is_err());
    }

    fn quv_slot() -> ioi_types::app::QuvSlotV0 {
        ioi_types::app::QuvSlotV0 {
            configuration_root: [1; 32],
            policy_root: [2; 32],
            network_id: [3; 32],
            domain_id: [4; 32],
            slot: 1,
            predecessor: [5; 32],
            authority_mode: ioi_types::app::QuvAuthorityModeV0::Owned,
        }
    }

    fn quv_push_payload(nonce: QuvNonce, authorizer: AccountId) -> PqConsensusPayloadV1 {
        let query = QuvPushQueryV0 {
            verifier_nonce: nonce,
            candidate: ioi_types::app::QuvCandidateV0 {
                slot: quv_slot(),
                payload_hash: [6; 32],
                authorizer,
                authority_signature: vec![7],
            },
        };
        PqConsensusPayloadV1::QuvPushQuery(codec::to_bytes_canonical(&query).unwrap())
    }

    fn quv_reply_payload(nonce: QuvNonce, member: AccountId) -> PqConsensusPayloadV1 {
        let reply = QuvReplyV0 {
            verifier_nonce: nonce,
            member,
            slot: quv_slot(),
            candidate_hash: [8; 32],
            snapshot_hash: [9; 32],
            complete_snapshot: vec![ioi_types::app::QuvCandidateV0 {
                slot: quv_slot(),
                payload_hash: [6; 32],
                authorizer: member,
                authority_signature: vec![7],
            }],
            signature: vec![10],
        };
        PqConsensusPayloadV1::QuvReply(codec::to_bytes_canonical(&reply).unwrap())
    }

    /// Seals `payload` at the initiator and delivers it at the responder the
    /// way the swarm loop does for `SyncRequest::PqChannelRecord`.
    #[allow(clippy::too_many_arguments)]
    async fn deliver(
        initiator: &mut PqChannelSessionManager,
        responder: &mut PqChannelSessionManager,
        initiator_peer: libp2p::PeerId,
        responder_peer: libp2p::PeerId,
        payload: &PqConsensusPayloadV1,
        active_quv_operation: Option<QuvNonce>,
        senders: (
            &mpsc::Sender<SwarmInternalEvent>,
            &mpsc::Sender<SwarmInternalEvent>,
        ),
        lanes: (&mut HashMap<AccountId, QuvNonce>, &mut HashSet<AccountId>),
    ) -> anyhow::Result<PqRecordAdmission> {
        let plaintext = codec::to_bytes_canonical(payload).unwrap();
        let record = initiator
            .seal(&responder_peer, payload.content_type(), &plaintext)
            .unwrap();
        deliver_pq_record(
            senders.0,
            senders.1,
            lanes.0,
            lanes.1,
            active_quv_operation,
            responder,
            initiator_peer,
            record,
        )
        .await
    }

    #[tokio::test]
    async fn stale_reply_is_acked_without_holding_the_current_operation_lane() {
        let (_temp, mut member, member_peer, mut verifier, verifier_peer) = established_managers();
        let (event_sender, _event_receiver) = mpsc::channel(4);
        let (quv_event_sender, mut quv_event_receiver) = mpsc::channel(4);
        let mut push_lane = HashMap::new();
        let mut reply_lane = HashSet::new();
        let member_account = verifier.remote_account(&member_peer).unwrap();
        let stale_nonce = [0; 32];
        let current_nonce = [1; 32];

        // (a) A reply for the retired operation N0 arrives while N1 is
        // active: it is positively acknowledged (the sender retires it) but it
        // never enters the current operation's per-member admission slot.
        let stale = deliver(
            &mut member,
            &mut verifier,
            member_peer,
            verifier_peer,
            &quv_reply_payload(stale_nonce, member_account),
            Some(current_nonce),
            (&event_sender, &quv_event_sender),
            (&mut push_lane, &mut reply_lane),
        )
        .await
        .unwrap();
        assert_eq!(stale, PqRecordAdmission::AckNow);
        assert!(reply_lane.is_empty());
        assert!(quv_event_receiver.try_recv().is_err());

        // The same member's current N1 reply is still forwarded.
        let current_payload = quv_reply_payload(current_nonce, member_account);
        let current = deliver(
            &mut member,
            &mut verifier,
            member_peer,
            verifier_peer,
            &current_payload,
            Some(current_nonce),
            (&event_sender, &quv_event_sender),
            (&mut push_lane, &mut reply_lane),
        )
        .await
        .unwrap();
        assert_eq!(current, PqRecordAdmission::AckNow);
        assert_eq!(reply_lane, HashSet::from([member_account]));
        assert!(matches!(
            quv_event_receiver.try_recv(),
            Ok(SwarmInternalEvent::QuvReplyReceived(data, account, peer))
                if PqConsensusPayloadV1::QuvReply(data.clone()) == current_payload
                    && account == member_account
                    && peer == member_peer
        ));

        // (c) A duplicate delivery of the admitted N1 reply is acknowledged and
        // not forwarded twice.
        let duplicate = deliver(
            &mut member,
            &mut verifier,
            member_peer,
            verifier_peer,
            &current_payload,
            Some(current_nonce),
            (&event_sender, &quv_event_sender),
            (&mut push_lane, &mut reply_lane),
        )
        .await
        .unwrap();
        assert_eq!(duplicate, PqRecordAdmission::AckNow);
        assert_eq!(reply_lane, HashSet::from([member_account]));
        assert!(quv_event_receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn current_push_is_refused_without_ack_while_a_stale_push_holds_the_lane() {
        let (_temp, mut verifier, verifier_peer, mut member, member_peer) = established_managers();
        let (event_sender, _event_receiver) = mpsc::channel(4);
        let (quv_event_sender, mut quv_event_receiver) = mpsc::channel(4);
        let mut push_lane = HashMap::new();
        let mut reply_lane = HashSet::new();
        let requester = member.remote_account(&verifier_peer).unwrap();
        let stale_nonce = [0; 32];
        let current_nonce = [1; 32];

        // (b) A crash-recovered stale push N0 is admitted first, acknowledged
        // at admission, and holds the requester's lane until the member
        // reports completion.
        let stale = deliver(
            &mut verifier,
            &mut member,
            verifier_peer,
            member_peer,
            &quv_push_payload(stale_nonce, requester),
            None,
            (&event_sender, &quv_event_sender),
            (&mut push_lane, &mut reply_lane),
        )
        .await
        .unwrap();
        assert_eq!(stale, PqRecordAdmission::AckNow);
        assert_eq!(push_lane.get(&requester), Some(&stale_nonce));
        assert!(quv_event_receiver.try_recv().is_ok());

        // The current push N1 from the same requester is refused outright: no
        // positive ACK, nothing forwarded, so the requester keeps its record.
        let current_payload = quv_push_payload(current_nonce, requester);
        let refused = deliver(
            &mut verifier,
            &mut member,
            verifier_peer,
            member_peer,
            &current_payload,
            None,
            (&event_sender, &quv_event_sender),
            (&mut push_lane, &mut reply_lane),
        )
        .await;
        assert!(refused.is_err());
        assert_eq!(push_lane.get(&requester), Some(&stale_nonce));
        assert!(quv_event_receiver.try_recv().is_err());

        // CompleteQuvPush(N0) releases the lane; N1 is then admitted on its
        // own retry.
        assert!(complete_quv_push(&mut push_lane, requester, stale_nonce));
        assert!(push_lane.is_empty());
        let admitted = deliver(
            &mut verifier,
            &mut member,
            verifier_peer,
            member_peer,
            &current_payload,
            None,
            (&event_sender, &quv_event_sender),
            (&mut push_lane, &mut reply_lane),
        )
        .await
        .unwrap();
        assert_eq!(admitted, PqRecordAdmission::AckNow);
        assert_eq!(push_lane.get(&requester), Some(&current_nonce));
        assert!(matches!(
            quv_event_receiver.try_recv(),
            Ok(SwarmInternalEvent::QuvPushQueryReceived(data, account, peer))
                if PqConsensusPayloadV1::QuvPushQuery(data.clone()) == current_payload
                    && account == requester
                    && peer == verifier_peer
        ));
    }

    #[tokio::test]
    async fn admitted_push_is_acked_on_admission_and_completion_releases_lane() {
        let (_temp, mut verifier, verifier_peer, mut member, member_peer) = established_managers();
        let (event_sender, _event_receiver) = mpsc::channel(4);
        let (quv_event_sender, mut quv_event_receiver) = mpsc::channel(4);
        let mut push_lane = HashMap::new();
        let mut reply_lane = HashSet::new();
        let requester = member.remote_account(&verifier_peer).unwrap();
        let nonce = [21; 32];
        let other_nonce = [22; 32];
        let payload = quv_push_payload(nonce, requester);

        // Forwarded to member work and acknowledged at admission; the
        // requester's timing lane is held by this nonce.
        let admission = deliver(
            &mut verifier,
            &mut member,
            verifier_peer,
            member_peer,
            &payload,
            None,
            (&event_sender, &quv_event_sender),
            (&mut push_lane, &mut reply_lane),
        )
        .await
        .unwrap();
        assert_eq!(admission, PqRecordAdmission::AckNow);
        assert!(quv_event_receiver.try_recv().is_ok());
        assert_eq!(push_lane.get(&requester), Some(&nonce));

        // A requester retry of the same nonce while the lane is held is
        // acknowledged now and not forwarded a second time.
        let duplicate = deliver(
            &mut verifier,
            &mut member,
            verifier_peer,
            member_peer,
            &payload,
            None,
            (&event_sender, &quv_event_sender),
            (&mut push_lane, &mut reply_lane),
        )
        .await
        .unwrap();
        assert_eq!(duplicate, PqRecordAdmission::AckNow);
        assert!(quv_event_receiver.try_recv().is_err());
        assert_eq!(push_lane.get(&requester), Some(&nonce));

        // A different nonce while the lane is held is refused (NACK path):
        // nothing forwarded, lane unchanged.
        let refused = deliver(
            &mut verifier,
            &mut member,
            verifier_peer,
            member_peer,
            &quv_push_payload(other_nonce, requester),
            None,
            (&event_sender, &quv_event_sender),
            (&mut push_lane, &mut reply_lane),
        )
        .await;
        assert!(refused.is_err());
        assert!(quv_event_receiver.try_recv().is_err());
        assert_eq!(push_lane.get(&requester), Some(&nonce));

        // CompleteQuvPush releases exactly this lane, once.
        assert!(complete_quv_push(&mut push_lane, requester, nonce));
        assert!(push_lane.is_empty());
        assert!(!complete_quv_push(&mut push_lane, requester, nonce));

        // The next push from the requester is admitted and forwarded.
        let next_payload = quv_push_payload(other_nonce, requester);
        let next = deliver(
            &mut verifier,
            &mut member,
            verifier_peer,
            member_peer,
            &next_payload,
            None,
            (&event_sender, &quv_event_sender),
            (&mut push_lane, &mut reply_lane),
        )
        .await
        .unwrap();
        assert_eq!(next, PqRecordAdmission::AckNow);
        assert_eq!(push_lane.get(&requester), Some(&other_nonce));
        assert!(matches!(
            quv_event_receiver.try_recv(),
            Ok(SwarmInternalEvent::QuvPushQueryReceived(data, account, peer))
                if PqConsensusPayloadV1::QuvPushQuery(data.clone()) == next_payload
                    && account == requester
                    && peer == verifier_peer
        ));
    }

    #[tokio::test]
    async fn nack_keeps_the_senders_durable_record() {
        let (_temp, mut verifier, _verifier_peer, _member, member_peer) = established_managers();
        let requester_account = verifier.remote_account(&member_peer).unwrap();
        let payload = quv_push_payload([5; 32], requester_account);
        let message_id = verifier.enqueue(member_peer, payload.clone()).unwrap();
        let mut swarm = crate::libp2p::transport::build_swarm(Keypair::generate_ed25519()).unwrap();
        let request_id = swarm
            .behaviour_mut()
            .request_response
            .send_request(&member_peer, SyncRequest::GetStatus);
        let other_request_id = swarm
            .behaviour_mut()
            .request_response
            .send_request(&member_peer, SyncRequest::GetStatus);
        let mut inflight = HashMap::from([(
            member_peer,
            InflightPqRequest {
                request_id,
                message_id,
            },
        )]);

        // A NACK for another request leaves the attempt in flight.
        assert!(!release_nacked_pq_record(
            &mut inflight,
            member_peer,
            other_request_id
        ));
        assert!(inflight.contains_key(&member_peer));
        // The matching NACK ends only the transport attempt: the durable
        // record is untouched and is the next record to flush.
        assert!(release_nacked_pq_record(
            &mut inflight,
            member_peer,
            request_id
        ));
        assert!(inflight.is_empty());
        assert_eq!(
            verifier.pending_front(&member_peer),
            Some((message_id, payload))
        );
    }

    #[test]
    fn enrollment_loss_reports_are_bounded_per_connection_and_skip_disconnected_peers() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let mut reports = HashMap::new();
        assert!(pq_enrollment_lost_report(&mut reports, peer, false).is_none());
        assert!(reports.is_empty());
        for _ in 0..PQ_ENROLLMENT_LOST_REPORTS_PER_CONNECTION {
            assert!(matches!(
                pq_enrollment_lost_report(&mut reports, peer, true),
                Some(SwarmInternalEvent::PqEnrollmentLost(reported)) if reported == peer
            ));
        }
        assert!(pq_enrollment_lost_report(&mut reports, peer, true).is_none());
        assert_eq!(
            reports.get(&peer),
            Some(&PQ_ENROLLMENT_LOST_REPORTS_PER_CONNECTION)
        );
        // A new connection (the loop clears the entry) starts over.
        reports.remove(&peer);
        assert!(pq_enrollment_lost_report(&mut reports, peer, true).is_some());
    }

    #[tokio::test]
    async fn recovery_keeps_authenticated_enrollment_and_erases_provisional_claims() {
        let (temp, mut verifier, _verifier_peer, _member, member_peer) = established_managers();
        let mut swarm = crate::libp2p::transport::build_swarm(Keypair::generate_ed25519()).unwrap();
        let mut handshakes = HashMap::new();
        let mut reports = HashMap::new();
        let claimed = local_config(12, temp.path().join("claimed.outbox"));
        let squatter = Keypair::generate_ed25519().public().to_peer_id();
        verifier
            .enroll_peer(PqPeerEnrollment {
                peer_id: squatter,
                account_id: claimed.account_id,
                identity_key_hash: claimed.identity_key_hash,
            })
            .unwrap();

        // Authenticated carrier: keys are dropped, the enrollment stays, and a
        // handshake retry is attempted in place (a no-op without a connection).
        assert!(recover_pq_peer_after_failure(
            &mut swarm,
            &mut verifier,
            &mut handshakes,
            &mut reports,
            member_peer
        )
        .is_none());
        assert!(verifier.enrolled_peers().any(|peer| peer == member_peer));
        assert!(!verifier.is_established(&member_peer));

        // Provisional claim: erased; not reported while disconnected because
        // reconnection re-derives status on its own.
        assert!(recover_pq_peer_after_failure(
            &mut swarm,
            &mut verifier,
            &mut handshakes,
            &mut reports,
            squatter
        )
        .is_none());
        assert!(!verifier.enrolled_peers().any(|peer| peer == squatter));
        assert!(reports.is_empty());
    }

    struct LiveSwarm {
        peer: PeerId,
        address: Multiaddr,
        commands: mpsc::Sender<SwarmCommand>,
        quv_commands: mpsc::Sender<SwarmCommand>,
        events: mpsc::Receiver<SwarmInternalEvent>,
        quv_events: mpsc::Receiver<SwarmInternalEvent>,
        _shutdown: watch::Sender<bool>,
    }

    async fn spawn_live_swarm(keypair: Keypair) -> LiveSwarm {
        let peer = keypair.public().to_peer_id();
        let mut swarm = crate::libp2p::transport::build_swarm(keypair).unwrap();
        swarm
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        let address = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                break address.with(Protocol::P2p(peer));
            }
        };
        let (commands, command_receiver) = mpsc::channel(64);
        let (quv_commands, quv_command_receiver) = mpsc::channel(64);
        let (event_sender, events) = mpsc::channel(512);
        let (quv_event_sender, quv_events) = mpsc::channel(64);
        let (shutdown, shutdown_receiver) = watch::channel(false);
        tokio::spawn(run_swarm_loop(
            swarm,
            command_receiver,
            quv_command_receiver,
            event_sender,
            quv_event_sender,
            shutdown_receiver,
        ));
        LiveSwarm {
            peer,
            address,
            commands,
            quv_commands,
            events,
            quv_events,
            _shutdown: shutdown,
        }
    }

    fn keypair_ordered_after(reference: &PeerId) -> Keypair {
        loop {
            let candidate = Keypair::generate_ed25519();
            if candidate.public().to_peer_id().to_bytes() > reference.to_bytes() {
                return candidate;
            }
        }
    }

    fn local_config_for_peer(
        account: u8,
        outbox_path: std::path::PathBuf,
        peer_id: PeerId,
    ) -> PqChannelLocalConfig {
        let mut config = local_config(account, outbox_path);
        config.peer_id = peer_id;
        config
    }

    fn enrollment_of(config: &PqChannelLocalConfig) -> PqPeerEnrollment {
        PqPeerEnrollment {
            peer_id: config.peer_id,
            account_id: config.account_id,
            identity_key_hash: config.identity_key_hash,
        }
    }

    async fn configure_strict(swarm: &LiveSwarm, config: PqChannelLocalConfig) {
        let (response, configured) = tokio::sync::oneshot::channel();
        swarm
            .commands
            .send(SwarmCommand::ConfigurePqChannels {
                config,
                enrollments: Vec::new(),
                handoff_only: false,
                response,
            })
            .await
            .unwrap();
        configured.await.unwrap().unwrap();
    }

    async fn next_live_event(
        receiver: &mut mpsc::Receiver<SwarmInternalEvent>,
    ) -> SwarmInternalEvent {
        tokio::time::timeout(Duration::from_secs(30), receiver.recv())
            .await
            .expect("timed out waiting for a swarm event")
            .expect("swarm loop ended")
    }

    async fn wait_connected(swarm: &mut LiveSwarm, peer: PeerId) {
        loop {
            if let SwarmInternalEvent::ConnectionEstablished(connected) =
                next_live_event(&mut swarm.events).await
            {
                if connected == peer {
                    return;
                }
            }
        }
    }

    /// Plays the validator for a pair of live swarms: answers every
    /// `PqEnrollmentLost` with the status-derived re-enrollment, refuses to
    /// ever accept an authentication for `forbidden`, and returns once `local`
    /// reports an authenticated carrier for `expected_peer`.
    async fn drive_until_authenticated(
        local: &mut LiveSwarm,
        local_enrollment: PqPeerEnrollment,
        remote: &mut LiveSwarm,
        remote_enrollment: PqPeerEnrollment,
        expected_peer: PeerId,
        forbidden: PeerId,
    ) -> AccountId {
        let deadline = tokio::time::sleep(Duration::from_secs(45));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => panic!("timed out waiting for PQ carrier authentication"),
                event = local.events.recv() => match event.expect("local swarm loop ended") {
                    SwarmInternalEvent::PqCarrierAuthenticated(peer, account) => {
                        assert_ne!(peer, forbidden, "an unproven claim must never authenticate");
                        if peer == expected_peer {
                            return account;
                        }
                    }
                    SwarmInternalEvent::PqEnrollmentLost(peer) => {
                        assert_ne!(peer, forbidden);
                        local
                            .commands
                            .send(SwarmCommand::EnrollPqPeer(remote_enrollment.clone()))
                            .await
                            .unwrap();
                    }
                    _ => {}
                },
                event = remote.events.recv() => match event.expect("remote swarm loop ended") {
                    SwarmInternalEvent::PqEnrollmentLost(_) => {
                        remote
                            .commands
                            .send(SwarmCommand::EnrollPqPeer(local_enrollment.clone()))
                            .await
                            .unwrap();
                    }
                    _ => {}
                },
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn live_squatter_enrollment_never_authenticates_and_genuine_carrier_routes() {
        let temp = tempfile::tempdir().unwrap();
        let verifier_key = Keypair::generate_ed25519();
        let verifier_peer = verifier_key.public().to_peer_id();
        // The verifier is the deterministic initiator toward both carriers.
        let genuine_key = keypair_ordered_after(&verifier_peer);
        let squatter = keypair_ordered_after(&verifier_peer).public().to_peer_id();
        let mut verifier = spawn_live_swarm(verifier_key).await;
        let mut genuine = spawn_live_swarm(genuine_key).await;
        let verifier_config =
            local_config_for_peer(20, temp.path().join("verifier.outbox"), verifier.peer);
        let genuine_config =
            local_config_for_peer(21, temp.path().join("genuine.outbox"), genuine.peer);
        let genuine_account = genuine_config.account_id;
        let verifier_enrollment = enrollment_of(&verifier_config);
        let genuine_enrollment = enrollment_of(&genuine_config);
        configure_strict(&verifier, verifier_config).await;
        configure_strict(&genuine, genuine_config).await;
        genuine
            .commands
            .send(SwarmCommand::EnrollPqPeer(verifier_enrollment.clone()))
            .await
            .unwrap();

        verifier
            .commands
            .send(SwarmCommand::Dial(genuine.address.clone()))
            .await
            .unwrap();
        wait_connected(&mut verifier, genuine.peer).await;

        // Status metadata from an unproven carrier claims the genuine account
        // first; the genuine carrier's status arrives afterwards.
        verifier
            .commands
            .send(SwarmCommand::EnrollPqPeer(PqPeerEnrollment {
                peer_id: squatter,
                account_id: genuine_enrollment.account_id,
                identity_key_hash: genuine_enrollment.identity_key_hash,
            }))
            .await
            .unwrap();
        verifier
            .commands
            .send(SwarmCommand::EnrollPqPeer(genuine_enrollment.clone()))
            .await
            .unwrap();
        let genuine_peer = genuine.peer;
        let account = drive_until_authenticated(
            &mut verifier,
            verifier_enrollment,
            &mut genuine,
            genuine_enrollment,
            genuine_peer,
            squatter,
        )
        .await;
        assert_eq!(account, genuine_account);

        // Routing for the account follows the proven carrier: a QUV request
        // queued by rooted account reaches the genuine member over its
        // authenticated channel.
        let nonce = [40; 32];
        let (response, begun) = tokio::sync::oneshot::channel();
        verifier
            .quv_commands
            .send(SwarmCommand::BeginQuvOperation { nonce, response })
            .await
            .unwrap();
        begun.await.unwrap();
        let PqConsensusPayloadV1::QuvPushQuery(data) = quv_push_payload(nonce, account) else {
            unreachable!()
        };
        let (response, queued) = tokio::sync::oneshot::channel();
        verifier
            .quv_commands
            .send(SwarmCommand::QueueQuvPushQuery {
                recipient: genuine_account,
                data: data.clone(),
                response,
            })
            .await
            .unwrap();
        queued.await.unwrap().unwrap();
        let verifier_account = AccountId([20; 32]);
        assert!(matches!(
            next_live_event(&mut genuine.quv_events).await,
            SwarmInternalEvent::QuvPushQueryReceived(received, requester, from)
                if received == data && requester == verifier_account && from == verifier.peer
        ));
        genuine
            .quv_commands
            .send(SwarmCommand::CompleteQuvPush {
                requester: verifier_account,
                nonce,
            })
            .await
            .unwrap();
        verifier
            .quv_commands
            .send(SwarmCommand::CompleteQuvOperation { nonce })
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn live_outbound_failure_on_unproven_enrollment_reports_loss_and_status_reenrollment_recovers(
    ) {
        let temp = tempfile::tempdir().unwrap();
        let verifier_key = Keypair::generate_ed25519();
        let verifier_peer = verifier_key.public().to_peer_id();
        let impostor_key = keypair_ordered_after(&verifier_peer);
        let genuine_key = keypair_ordered_after(&verifier_peer);
        let mut verifier = spawn_live_swarm(verifier_key).await;
        // The impostor is a live carrier with no strict-PQ configuration: it
        // refuses every client hello, which the initiator sees as an outbound
        // failure of its handshake request.
        let mut impostor = spawn_live_swarm(impostor_key).await;
        let mut genuine = spawn_live_swarm(genuine_key).await;
        let impostor_peer = impostor.peer;
        let impostor_address = impostor.address.clone();
        tokio::spawn(async move { while impostor.events.recv().await.is_some() {} });
        let verifier_config =
            local_config_for_peer(30, temp.path().join("verifier-loss.outbox"), verifier.peer);
        let genuine_config =
            local_config_for_peer(31, temp.path().join("genuine-loss.outbox"), genuine.peer);
        let genuine_account = genuine_config.account_id;
        let verifier_enrollment = enrollment_of(&verifier_config);
        let genuine_enrollment = enrollment_of(&genuine_config);
        configure_strict(&verifier, verifier_config).await;
        configure_strict(&genuine, genuine_config).await;
        genuine
            .commands
            .send(SwarmCommand::EnrollPqPeer(verifier_enrollment.clone()))
            .await
            .unwrap();

        verifier
            .commands
            .send(SwarmCommand::Dial(impostor_address))
            .await
            .unwrap();
        wait_connected(&mut verifier, impostor_peer).await;
        let impostor_claim = PqPeerEnrollment {
            peer_id: impostor_peer,
            account_id: genuine_enrollment.account_id,
            identity_key_hash: genuine_enrollment.identity_key_hash,
        };

        // Each status-driven re-enrollment of the unproven claim fails its
        // handshake, is erased, and is reported so the validator can refresh
        // status; the report is bounded per connection.
        let mut reports = 0;
        for attempt in 0..=PQ_ENROLLMENT_LOST_REPORTS_PER_CONNECTION {
            verifier
                .commands
                .send(SwarmCommand::EnrollPqPeer(impostor_claim.clone()))
                .await
                .unwrap();
            let expected_report = attempt < PQ_ENROLLMENT_LOST_REPORTS_PER_CONNECTION;
            let wait = tokio::time::timeout(
                Duration::from_secs(if expected_report { 30 } else { 2 }),
                async {
                    loop {
                        match verifier.events.recv().await.expect("verifier loop ended") {
                            SwarmInternalEvent::PqEnrollmentLost(peer) => {
                                assert_eq!(peer, impostor_peer);
                                break;
                            }
                            SwarmInternalEvent::PqCarrierAuthenticated(peer, _) => {
                                panic!("unproven carrier {peer} must never authenticate");
                            }
                            _ => {}
                        }
                    }
                },
            )
            .await;
            if expected_report {
                wait.expect("erased provisional enrollment was not reported");
                reports += 1;
            } else {
                assert!(
                    wait.is_err(),
                    "loss reports must stop at the per-connection bound"
                );
            }
        }
        assert_eq!(reports, PQ_ENROLLMENT_LOST_REPORTS_PER_CONNECTION);

        // The genuine carrier's status-driven enrollment then proves the key.
        verifier
            .commands
            .send(SwarmCommand::Dial(genuine.address.clone()))
            .await
            .unwrap();
        wait_connected(&mut verifier, genuine.peer).await;
        verifier
            .commands
            .send(SwarmCommand::EnrollPqPeer(genuine_enrollment.clone()))
            .await
            .unwrap();
        let genuine_peer = genuine.peer;
        let account = drive_until_authenticated(
            &mut verifier,
            verifier_enrollment,
            &mut genuine,
            genuine_enrollment,
            genuine_peer,
            impostor_peer,
        )
        .await;
        assert_eq!(account, genuine_account);
    }
}
