// Path: crates/network/src/libp2p/mod.rs

//! A libp2p-based implementation of the network traits.

// Declare submodules for sync and mempool logic.
pub mod mempool;
pub mod sync;

use crate::metrics::metrics;
use crate::traits::NodeState;
use futures::StreamExt;
use ioi_api::transaction::TransactionModel;
use ioi_tx::unified::UnifiedTransactionModel;
use ioi_types::app::{Block, ChainId, ChainTransaction, OracleAttestation};
use ioi_types::codec;
use libp2p::{
    gossipsub, identity, noise,
    request_response::{self, ResponseChannel},
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder, Transport,
};
use std::{collections::HashSet, iter, sync::Arc};
use tokio::{
    sync::{mpsc, watch, Mutex},
    task::JoinHandle,
    time::Duration,
};

// --- FIX START: Add imports for gossip retry logic ---
use libp2p::gossipsub::{Behaviour as GossipsubBehaviour, PublishError};
use std::collections::VecDeque;
use tokio::time::interval;
// --- FIX END ---

// Re-export concrete types from submodules for a cleaner public API.
pub use self::sync::{SyncCodec, SyncRequest, SyncResponse};

// --- Core Network Behaviour and Event/Command Types ---

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "SyncBehaviourEvent")]
pub struct SyncBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub request_response: request_response::Behaviour<SyncCodec>,
}

#[derive(Debug)]
pub enum SyncBehaviourEvent {
    Gossipsub(gossipsub::Event),
    RequestResponse(request_response::Event<SyncRequest, SyncResponse>),
}

impl From<gossipsub::Event> for SyncBehaviourEvent {
    fn from(event: gossipsub::Event) -> Self {
        SyncBehaviourEvent::Gossipsub(event)
    }
}

impl From<request_response::Event<SyncRequest, SyncResponse>> for SyncBehaviourEvent {
    fn from(event: request_response::Event<SyncRequest, SyncResponse>) -> Self {
        SyncBehaviourEvent::RequestResponse(event)
    }
}

#[derive(Debug)]
pub enum SwarmCommand {
    Listen(Multiaddr),
    Dial(Multiaddr),
    PublishBlock(Vec<u8>),
    PublishTransaction(Vec<u8>),
    SendStatusRequest(PeerId),
    SendBlocksRequest {
        peer: PeerId,
        since: u64,
        max_blocks: u32,
        max_bytes: u32,
    },
    SendStatusResponse {
        channel: ResponseChannel<SyncResponse>,
        height: u64,
        head_hash: [u8; 32],
        chain_id: ChainId,
        genesis_root: Vec<u8>,
    },
    SendBlocksResponse(ResponseChannel<SyncResponse>, Vec<Block<ChainTransaction>>),
    BroadcastToCommittee(Vec<PeerId>, String),
    AgenticConsensusVote(String, Vec<u8>),
    SendAgenticAck(ResponseChannel<SyncResponse>),
    SimulateAgenticTx,
    GossipOracleAttestation(Vec<u8>),
}

#[derive(Debug)]
pub enum NetworkEvent {
    ConnectionEstablished(PeerId),
    ConnectionClosed(PeerId),
    GossipBlock(Block<ChainTransaction>),
    GossipTransaction(Box<ChainTransaction>),
    StatusRequest(PeerId, ResponseChannel<SyncResponse>),
    BlocksRequest {
        peer: PeerId,
        since: u64,
        max_blocks: u32,
        max_bytes: u32,
        channel: ResponseChannel<SyncResponse>,
    },
    StatusResponse {
        peer: PeerId,
        height: u64,
        head_hash: [u8; 32],
        chain_id: ChainId,
        genesis_root: Vec<u8>,
    },
    BlocksResponse(PeerId, Vec<Block<ChainTransaction>>),
    AgenticPrompt {
        from: PeerId,
        prompt: String,
    },
    AgenticConsensusVote {
        from: PeerId,
        prompt_hash: String,
        vote_hash: Vec<u8>,
    },
    OracleAttestationReceived {
        from: PeerId,
        attestation: OracleAttestation,
    },
    OutboundFailure(PeerId),
}

// Internal event type for swarm -> forwarder communication
#[derive(Debug)]
enum SwarmInternalEvent {
    ConnectionEstablished(PeerId),
    ConnectionClosed(PeerId),
    GossipBlock(Vec<u8>, PeerId),
    GossipTransaction(Vec<u8>, PeerId),
    StatusRequest(PeerId, ResponseChannel<SyncResponse>),
    BlocksRequest {
        peer: PeerId,
        since: u64,
        max_blocks: u32,
        max_bytes: u32,
        channel: ResponseChannel<SyncResponse>,
    },
    StatusResponse {
        peer: PeerId,
        height: u64,
        head_hash: [u8; 32],
        chain_id: ChainId,
        genesis_root: Vec<u8>,
    },
    BlocksResponse(PeerId, Vec<Block<ChainTransaction>>),
    AgenticPrompt {
        from: PeerId,
        prompt: String,
        channel: ResponseChannel<SyncResponse>,
    },
    AgenticConsensusVote {
        from: PeerId,
        prompt_hash: String,
        vote_hash: Vec<u8>,
    },
    GossipOracleAttestation(Vec<u8>, PeerId),
    OutboundFailure(PeerId),
}

// --- Libp2pSync Implementation ---

pub struct Libp2pSync {
    swarm_command_sender: mpsc::Sender<SwarmCommand>,
    shutdown_sender: Arc<watch::Sender<bool>>,
    task_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
    node_state: Arc<Mutex<NodeState>>,
    known_peers: Arc<Mutex<HashSet<PeerId>>>,
    local_peer_id: PeerId,
}

impl Libp2pSync {
    pub fn new(
        local_key: identity::Keypair,
        listen_addr: Multiaddr,
        dial_addrs: Option<&[Multiaddr]>,
    ) -> anyhow::Result<(
        Arc<Self>,
        mpsc::Sender<SwarmCommand>,
        mpsc::Receiver<NetworkEvent>,
    )> {
        let (shutdown_sender, _) = watch::channel(false);
        let (swarm_command_sender, swarm_command_receiver) = mpsc::channel(100);
        let (internal_event_sender, mut internal_event_receiver) = mpsc::channel(100);
        let (network_event_sender, network_event_receiver) = mpsc::channel(100);

        let local_peer_id = local_key.public().to_peer_id();
        let node_state = Arc::new(Mutex::new(NodeState::Initializing));
        let known_peers = Arc::new(Mutex::new(HashSet::new()));

        let swarm = Self::build_swarm(local_key.clone())?;
        let swarm_task = tokio::spawn(Self::run_swarm_loop(
            swarm,
            swarm_command_receiver,
            internal_event_sender,
            shutdown_sender.subscribe(),
        ));

        let swarm_command_sender_clone = swarm_command_sender.clone();
        let event_forwarder_task = tokio::spawn(async move {
            while let Some(event) = internal_event_receiver.recv().await {
                if let SwarmInternalEvent::AgenticPrompt {
                    from,
                    prompt,
                    channel,
                } = event
                {
                    let translated_event = NetworkEvent::AgenticPrompt { from, prompt };
                    if network_event_sender.send(translated_event).await.is_err() {
                        tracing::info!(target: "network", event = "shutdown", reason = "event channel closed", component="forwarder");
                        break;
                    }
                    if swarm_command_sender_clone
                        .send(SwarmCommand::SendAgenticAck(channel))
                        .await
                        .is_err()
                    {
                        tracing::warn!(target: "network", event = "send_fail", command = "AgenticAck");
                    }
                    continue;
                }
                if let SwarmInternalEvent::AgenticConsensusVote {
                    from,
                    prompt_hash,
                    vote_hash,
                } = event
                {
                    let translated_event = NetworkEvent::AgenticConsensusVote {
                        from,
                        prompt_hash,
                        vote_hash,
                    };
                    if network_event_sender.send(translated_event).await.is_err() {
                        tracing::info!(target: "network", event = "shutdown", reason = "event channel closed", component="forwarder");
                        break;
                    }
                    continue;
                }

                if let SwarmInternalEvent::GossipOracleAttestation(data, from) = event {
                    match codec::from_bytes_canonical::<OracleAttestation>(&data) {
                        Ok(attestation) => {
                            if network_event_sender
                                .send(NetworkEvent::OracleAttestationReceived { from, attestation })
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(target: "gossip", event = "deser_fail", kind = "oracle_attestation", error = %e)
                        }
                    }
                    continue;
                }

                let translated_event = match event {
                    SwarmInternalEvent::ConnectionEstablished(p) => {
                        Some(NetworkEvent::ConnectionEstablished(p))
                    }
                    SwarmInternalEvent::ConnectionClosed(p) => {
                        Some(NetworkEvent::ConnectionClosed(p))
                    }
                    SwarmInternalEvent::StatusRequest(p, c) => {
                        Some(NetworkEvent::StatusRequest(p, c))
                    }
                    SwarmInternalEvent::BlocksRequest {
                        peer,
                        since,
                        max_blocks,
                        max_bytes,
                        channel,
                    } => Some(NetworkEvent::BlocksRequest {
                        peer,
                        since,
                        max_blocks,
                        max_bytes,
                        channel,
                    }),
                    SwarmInternalEvent::StatusResponse {
                        peer,
                        height,
                        head_hash,
                        chain_id,
                        genesis_root,
                    } => Some(NetworkEvent::StatusResponse {
                        peer,
                        height,
                        head_hash,
                        chain_id,
                        genesis_root,
                    }),
                    SwarmInternalEvent::BlocksResponse(p, b) => {
                        Some(NetworkEvent::BlocksResponse(p, b))
                    }
                    SwarmInternalEvent::GossipBlock(data, _source) => {
                        match codec::from_bytes_canonical(&data) {
                            Ok(block) => Some(NetworkEvent::GossipBlock(block)),
                            Err(e) => {
                                tracing::warn!(target: "gossip", event = "deser_fail", kind = "block", error = %e);
                                None
                            }
                        }
                    }
                    SwarmInternalEvent::GossipTransaction(data, _source) => {
                        let dummy_model = UnifiedTransactionModel::new(
                            ioi_state::primitives::hash::HashCommitmentScheme::new(),
                        );
                        match dummy_model.deserialize_transaction(&data) {
                            Ok(tx) => Some(NetworkEvent::GossipTransaction(Box::new(tx))),
                            Err(e) => {
                                tracing::warn!(target: "gossip", event = "deser_fail", kind = "transaction", error = %e);
                                None
                            }
                        }
                    }
                    SwarmInternalEvent::OutboundFailure(peer) => {
                        Some(NetworkEvent::OutboundFailure(peer))
                    }
                    SwarmInternalEvent::AgenticPrompt { .. } => unreachable!(),
                    SwarmInternalEvent::AgenticConsensusVote { .. } => unreachable!(),
                    SwarmInternalEvent::GossipOracleAttestation(..) => unreachable!(),
                };

                if let Some(event) = translated_event {
                    if network_event_sender.send(event).await.is_err() {
                        tracing::info!(target: "network", event = "shutdown", reason = "event channel closed", component="forwarder");
                        break;
                    }
                }
            }
        });

        let initial_cmds_task = tokio::spawn({
            let cmd_sender = swarm_command_sender.clone();
            let listen_addr_clone = listen_addr.clone();
            let dial_addrs_owned = dial_addrs.map(|s| s.to_vec());
            async move {
                cmd_sender
                    .send(SwarmCommand::Listen(listen_addr_clone))
                    .await
                    .ok();
                if let Some(addrs) = dial_addrs_owned {
                    for addr in addrs {
                        cmd_sender.send(SwarmCommand::Dial(addr)).await.ok();
                    }
                }
            }
        });

        let sync_service = Arc::new(Self {
            swarm_command_sender: swarm_command_sender.clone(),
            shutdown_sender: Arc::new(shutdown_sender),
            task_handles: Arc::new(Mutex::new(vec![
                swarm_task,
                event_forwarder_task,
                initial_cmds_task,
            ])),
            node_state,
            known_peers,
            local_peer_id,
        });

        Ok((sync_service, swarm_command_sender, network_event_receiver))
    }

    fn build_swarm(local_key: identity::Keypair) -> anyhow::Result<Swarm<SyncBehaviour>> {
        let swarm = SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_other_transport(|key| {
                let noise_config = noise::Config::new(key)?;
                let transport = tcp::tokio::Transport::new(tcp::Config::default())
                    .upgrade(libp2p::core::upgrade::Version::V1Lazy)
                    .authenticate(noise_config)
                    .multiplex(yamux::Config::default())
                    .timeout(Duration::from_secs(20))
                    .boxed();
                Ok(transport)
            })?
            .with_behaviour(|key| {
                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub::Config::default(),
                )?;
                let mut cfg = request_response::Config::default();
                cfg.set_request_timeout(Duration::from_secs(30));
                let request_response = request_response::Behaviour::new(
                    iter::once(("/ioi/sync/2", request_response::ProtocolSupport::Full)),
                    cfg,
                );
                Ok(SyncBehaviour {
                    gossipsub,
                    request_response,
                })
            })?
            .build();
        Ok(swarm)
    }

    async fn run_swarm_loop(
        mut swarm: Swarm<SyncBehaviour>,
        mut command_receiver: mpsc::Receiver<SwarmCommand>,
        event_sender: mpsc::Sender<SwarmInternalEvent>,
        mut shutdown_receiver: watch::Receiver<bool>,
    ) {
        let block_topic = gossipsub::IdentTopic::new("blocks");
        let tx_topic = gossipsub::IdentTopic::new("transactions");
        let oracle_attestations_topic = gossipsub::IdentTopic::new("oracle-attestations");
        let agentic_vote_topic = gossipsub::IdentTopic::new("agentic-votes");

        // --- Outbox for resilient block publishing ---
        let mut pending_blocks: VecDeque<Vec<u8>> = VecDeque::new();
        let mut retry_interval = interval(Duration::from_millis(500));
        retry_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        if let Err(e) = swarm.behaviour_mut().gossipsub.subscribe(&block_topic) {
            tracing::warn!(error=%e, "Failed to subscribe to gossipsub topic: blocks");
        }
        if let Err(e) = swarm.behaviour_mut().gossipsub.subscribe(&tx_topic) {
            tracing::warn!(error=%e, "Failed to subscribe to gossipsub topic: transactions");
        }
        if let Err(e) = swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&oracle_attestations_topic)
        {
            tracing::warn!(error=%e, "Failed to subscribe to gossipsub topic: oracle-attestations");
        }
        if let Err(e) = swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&agentic_vote_topic)
        {
            tracing::warn!(error=%e, "Failed to subscribe to gossipsub topic: agentic-votes");
        }

        loop {
            tokio::select! {
                _ = retry_interval.tick() => {
                    drain_pending_blocks(
                        &mut pending_blocks,
                        &mut swarm.behaviour_mut().gossipsub,
                        &block_topic,
                    );
                },
                _ = shutdown_receiver.changed() => if *shutdown_receiver.borrow() { break; },
                event = swarm.select_next_some() => match event {
                    SwarmEvent::NewListenAddr { address, .. } => { tracing::info!(target: "network", event = "listening", %address); }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        metrics().inc_connected_peers();
                        event_sender.send(SwarmInternalEvent::ConnectionEstablished(peer_id)).await.ok();
                        drain_pending_blocks(
                            &mut pending_blocks,
                            &mut swarm.behaviour_mut().gossipsub,
                            &block_topic,
                        );
                    }
                    SwarmEvent::ConnectionClosed { peer_id, .. } => {
                        metrics().dec_connected_peers();
                        event_sender.send(SwarmInternalEvent::ConnectionClosed(peer_id)).await.ok();
                    }
                    SwarmEvent::Behaviour(event) => match event {
                        SyncBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. }) => {
                            let topic_name = if message.topic == block_topic.hash() {
                                "blocks"
                            } else if message.topic == tx_topic.hash() {
                                "transactions"
                            } else if message.topic == oracle_attestations_topic.hash() {
                                "oracle-attestations"
                            } else if message.topic == agentic_vote_topic.hash() {
                                "agentic-votes"
                            } else {
                                "unknown"
                            };
                            metrics().inc_gossip_messages_received(topic_name);

                            if let Some(source) = message.source {
                                if message.topic == block_topic.hash() {
                                    event_sender.send(SwarmInternalEvent::GossipBlock(message.data, source)).await.ok();
                                } else if message.topic == tx_topic.hash() {
                                    event_sender.send(SwarmInternalEvent::GossipTransaction(message.data, source)).await.ok();
                                }
                                else if message.topic == oracle_attestations_topic.hash() {
                                    event_sender.send(SwarmInternalEvent::GossipOracleAttestation(message.data, source)).await.ok();
                                }
                                else if message.topic == agentic_vote_topic.hash() {
                                    if let Ok((prompt_hash, vote_hash)) = codec::from_bytes_canonical::<(String, Vec<u8>)>(&message.data) {
                                        event_sender.send(SwarmInternalEvent::AgenticConsensusVote { from: source, prompt_hash, vote_hash }).await.ok();
                                    }
                                }
                            }
                        }
                        SyncBehaviourEvent::RequestResponse(event) => match event {
                            request_response::Event::Message { peer, message } => match message {
                                request_response::Message::Request { request, channel, .. } => match request {
                                    SyncRequest::GetStatus => { event_sender.send(SwarmInternalEvent::StatusRequest(peer, channel)).await.ok(); }
                                    SyncRequest::GetBlocks { since, max_blocks, max_bytes } => { event_sender.send(SwarmInternalEvent::BlocksRequest { peer, since, max_blocks, max_bytes, channel }).await.ok(); }
                                    SyncRequest::AgenticPrompt(prompt) => {
                                        tracing::info!(target: "network", event = "request_received", kind="AgenticPrompt", %peer);
                                        event_sender.send(SwarmInternalEvent::AgenticPrompt { from: peer, prompt, channel }).await.ok();
                                    }
                                },
                                request_response::Message::Response { response, .. } => match response {
                                    SyncResponse::Status { height, head_hash, chain_id, genesis_root } => { event_sender.send(SwarmInternalEvent::StatusResponse { peer, height, head_hash, chain_id, genesis_root }).await.ok(); }
                                    SyncResponse::Blocks(blocks) => { event_sender.send(SwarmInternalEvent::BlocksResponse(peer, blocks)).await.ok(); }
                                    SyncResponse::AgenticAck => {
                                        tracing::info!(target: "network", event = "response_received", kind="AgenticAck", %peer);
                                    }
                                }
                            },
                            request_response::Event::OutboundFailure { peer, error, .. } => {
                                tracing::warn!(target: "network", event = "outbound_failure", %peer, ?error);
                                event_sender.send(SwarmInternalEvent::OutboundFailure(peer)).await.ok();
                            },
                            request_response::Event::InboundFailure { peer, error, .. } => {
                                tracing::warn!(target: "network", event = "inbound_failure", %peer, ?error);
                            }
                            _ => {}
                        },
                        _ => {}
                    }
                    _ => {}
                },
                command = command_receiver.recv() => match command {
                    Some(cmd) => match cmd {
                        SwarmCommand::Listen(addr) => { swarm.listen_on(addr).ok(); }
                        SwarmCommand::Dial(addr) => { swarm.dial(addr).ok(); }
                        SwarmCommand::PublishBlock(data) => {
                            match swarm.behaviour_mut().gossipsub.publish(block_topic.clone(), data.clone()) {
                                Ok(_) => { /* Success */ }
                                Err(PublishError::InsufficientPeers) => {
                                    tracing::warn!(target: "gossip", "Insufficient peers to publish block, queueing for later.");
                                    enqueue_block(&mut pending_blocks, data);
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "Failed to publish block to gossipsub");
                                }
                            }
                        }
                        SwarmCommand::PublishTransaction(data) => {
                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(tx_topic.clone(), data) {
                                tracing::warn!(error = %e, "Failed to publish transaction to gossipsub");
                            }
                        }
                        SwarmCommand::GossipOracleAttestation(data) => {
                             if let Err(e) = swarm.behaviour_mut().gossipsub.publish(oracle_attestations_topic.clone(), data) {
                                 tracing::warn!(error = %e, "Failed to publish oracle attestation to gossipsub");
                             }
                        }
                        SwarmCommand::SendStatusRequest(p) => { swarm.behaviour_mut().request_response.send_request(&p, SyncRequest::GetStatus); }
                        SwarmCommand::SendBlocksRequest { peer, since, max_blocks, max_bytes } => { swarm.behaviour_mut().request_response.send_request(&peer, SyncRequest::GetBlocks { since, max_blocks, max_bytes }); }
                        SwarmCommand::SendStatusResponse { channel, height, head_hash, chain_id, genesis_root } => { swarm.behaviour_mut().request_response.send_response(channel, SyncResponse::Status { height, head_hash, chain_id, genesis_root }).ok(); }
                        SwarmCommand::SendBlocksResponse(c, blocks) => { swarm.behaviour_mut().request_response.send_response(c, SyncResponse::Blocks(blocks)).ok(); }
                        SwarmCommand::SimulateAgenticTx => {
                            // This is a test-only command to trigger a log cascade.
                            // It does not interact with the network.
                        }
                        SwarmCommand::BroadcastToCommittee(peers, prompt) => {
                            tracing::info!(target: "network", event = "broadcast", kind="AgenticPrompt", committee_size=peers.len());
                            for peer_id in peers {
                                let request = SyncRequest::AgenticPrompt(prompt.clone());
                                swarm.behaviour_mut().request_response.send_request(&peer_id, request);
                            }
                        }
                        SwarmCommand::AgenticConsensusVote(prompt_hash, vote_hash) => {
                            match codec::to_bytes_canonical(&(prompt_hash, vote_hash)) {
                                Ok(data) => {
                                    if let Err(e) = swarm.behaviour_mut().gossipsub.publish(agentic_vote_topic.clone(), data) {
                                        tracing::warn!(error = %e, "Failed to publish agentic consensus vote");
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(error = %e, "Failed to serialize agentic consensus vote");
                                }
                            }
                        }
                        SwarmCommand::SendAgenticAck(channel) => {
                            swarm.behaviour_mut().request_response.send_response(channel, SyncResponse::AgenticAck).ok();
                        }
                    },
                    None => { return; }
                }
            }
        }
    }
}

// --- FIX START: Add helper functions for gossip retry logic ---
const PENDING_BLOCK_OUTBOX_MAX: usize = 128;

/// Enqueues a block for later gossiping, dropping the oldest if the outbox is full.
fn enqueue_block(pending: &mut VecDeque<Vec<u8>>, data: Vec<u8>) {
    if pending.len() >= PENDING_BLOCK_OUTBOX_MAX {
        pending.pop_front(); // Drop oldest to prevent unbounded growth.
        tracing::warn!(
            target: "gossip",
            "outbox full; dropping oldest pending block"
        );
    }
    pending.push_back(data);
}

/// Attempts to drain the queue of pending blocks by publishing them to the gossipsub mesh.
fn drain_pending_blocks(
    pending: &mut VecDeque<Vec<u8>>,
    gossipsub: &mut GossipsubBehaviour,
    block_topic: &gossipsub::IdentTopic,
) {
    if pending.is_empty() {
        return;
    }

    // Crucially, check for peers subscribed to the specific topic, not just any connected peer.
    if gossipsub.mesh_peers(&block_topic.hash()).next().is_none() {
        return;
    }

    tracing::info!(
        target: "gossip",
        "Attempting to drain {} pending blocks from outbox.",
        pending.len()
    );

    // Use retain to efficiently re-queue items that still fail to send.
    pending.retain(|block_data| {
        match gossipsub.publish(block_topic.clone(), block_data.clone()) {
            Ok(_) => {
                tracing::info!(target: "gossip", event = "published_queued_block");
                false // Remove from queue
            }
            Err(PublishError::InsufficientPeers) => {
                // This can happen if the mesh changes between our check and the publish call.
                true // Keep in queue for next retry
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to publish queued block from outbox");
                false // Drop on other errors
            }
        }
    });
}
// --- FIX END ---
