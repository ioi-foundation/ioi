// Path: crates/network/src/libp2p/mod.rs

//! A libp2p-based implementation of the network traits.

// Declare submodules for sync and mempool logic.
pub mod mempool;
pub mod sync;

use crate::traits::NodeState;
use futures::StreamExt;
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

// Re-export concrete types from submodules for a cleaner public API.
pub use self::sync::{SyncCodec, SyncRequest, SyncResponse};
use depin_sdk_types::app::{Block, ProtocolTransaction};

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
    PublishTransaction(Vec<u8>), // New command for mempool gossip
    SendStatusRequest(PeerId),
    SendBlocksRequest(PeerId, u64),
    SendStatusResponse(ResponseChannel<SyncResponse>, u64),
    SendBlocksResponse(
        ResponseChannel<SyncResponse>,
        Vec<Block<ProtocolTransaction>>,
    ),
    BroadcastToCommittee(Vec<PeerId>, String), // For semantic consensus
    SimulateSemanticTx,                        // For E2E test
}

#[derive(Debug)]
pub enum NetworkEvent {
    ConnectionEstablished(PeerId),
    ConnectionClosed(PeerId),
    GossipBlock(Block<ProtocolTransaction>),
    GossipTransaction(ProtocolTransaction), // New event for mempool gossip
    StatusRequest(PeerId, ResponseChannel<SyncResponse>),
    BlocksRequest(PeerId, u64, ResponseChannel<SyncResponse>),
    StatusResponse(PeerId, u64),
    BlocksResponse(PeerId, Vec<Block<ProtocolTransaction>>),
}

// Internal event type for swarm -> forwarder communication
#[derive(Debug)]
enum SwarmInternalEvent {
    ConnectionEstablished(PeerId),
    ConnectionClosed(PeerId),
    GossipBlock(Vec<u8>, PeerId),
    GossipTransaction(Vec<u8>, PeerId), // New internal event
    StatusRequest(PeerId, ResponseChannel<SyncResponse>),
    BlocksRequest(PeerId, u64, ResponseChannel<SyncResponse>),
    StatusResponse(PeerId, u64),
    BlocksResponse(PeerId, Vec<Block<ProtocolTransaction>>),
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
        dial_addr: Option<Multiaddr>,
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

        let event_forwarder_task = tokio::spawn(async move {
            while let Some(event) = internal_event_receiver.recv().await {
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
                    SwarmInternalEvent::BlocksRequest(p, h, c) => {
                        Some(NetworkEvent::BlocksRequest(p, h, c))
                    }
                    SwarmInternalEvent::StatusResponse(p, h) => {
                        Some(NetworkEvent::StatusResponse(p, h))
                    }
                    SwarmInternalEvent::BlocksResponse(p, b) => {
                        Some(NetworkEvent::BlocksResponse(p, b))
                    }
                    SwarmInternalEvent::GossipBlock(data, _source) => {
                        match serde_json::from_slice(&data) {
                            Ok(block) => Some(NetworkEvent::GossipBlock(block)),
                            Err(e) => {
                                log::warn!("Failed to deserialize gossiped block: {e}");
                                None
                            }
                        }
                    }
                    SwarmInternalEvent::GossipTransaction(data, _source) => {
                        match serde_json::from_slice(&data) {
                            Ok(tx) => Some(NetworkEvent::GossipTransaction(tx)),
                            Err(e) => {
                                log::warn!("Failed to deserialize gossiped transaction: {e}");
                                None
                            }
                        }
                    }
                };

                if let Some(event) = translated_event {
                    if network_event_sender.send(event).await.is_err() {
                        log::info!("[Sync] Network event channel closed. Shutting down forwarder.");
                        break;
                    }
                }
            }
        });

        let initial_cmds_task = tokio::spawn({
            let cmd_sender = swarm_command_sender.clone();
            async move {
                cmd_sender
                    .send(SwarmCommand::Listen(listen_addr))
                    .await
                    .ok();
                if let Some(addr) = dial_addr {
                    cmd_sender.send(SwarmCommand::Dial(addr)).await.ok();
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
                let request_response = request_response::Behaviour::new(
                    iter::once(("/depin/sync/1", request_response::ProtocolSupport::Full)),
                    request_response::Config::default(),
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
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&block_topic)
            .unwrap();
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&tx_topic)
            .unwrap();

        loop {
            tokio::select! {
                _ = shutdown_receiver.changed() => if *shutdown_receiver.borrow() { break; },
                event = swarm.select_next_some() => match event {
                    SwarmEvent::NewListenAddr { address, .. } => { log::info!("[Sync] Swarm listening on {address}"); }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => { event_sender.send(SwarmInternalEvent::ConnectionEstablished(peer_id)).await.ok(); }
                    SwarmEvent::ConnectionClosed { peer_id, .. } => { event_sender.send(SwarmInternalEvent::ConnectionClosed(peer_id)).await.ok(); }
                    SwarmEvent::Behaviour(event) => match event {
                        SyncBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. }) => {
                            if let Some(source) = message.source {
                                if message.topic == block_topic.hash() {
                                    event_sender.send(SwarmInternalEvent::GossipBlock(message.data, source)).await.ok();
                                } else if message.topic == tx_topic.hash() {
                                    event_sender.send(SwarmInternalEvent::GossipTransaction(message.data, source)).await.ok();
                                }
                            }
                        }
                        SyncBehaviourEvent::RequestResponse(request_response::Event::Message { peer, message }) => {
                            match message {
                                request_response::Message::Request { request, channel, .. } => match request {
                                    SyncRequest::GetStatus => { event_sender.send(SwarmInternalEvent::StatusRequest(peer, channel)).await.ok(); }
                                    SyncRequest::GetBlocks(h) => { event_sender.send(SwarmInternalEvent::BlocksRequest(peer, h, channel)).await.ok(); }
                                },
                                request_response::Message::Response { response, .. } => match response {
                                    SyncResponse::Status(h) => { event_sender.send(SwarmInternalEvent::StatusResponse(peer, h)).await.ok(); }
                                    SyncResponse::Blocks(blocks) => { event_sender.send(SwarmInternalEvent::BlocksResponse(peer, blocks)).await.ok(); }
                                }
                            }
                        }
                        _ => {}
                    }
                    _ => {}
                },
                command = command_receiver.recv() => match command {
                    Some(cmd) => match cmd {
                        SwarmCommand::Listen(addr) => { swarm.listen_on(addr).ok(); }
                        SwarmCommand::Dial(addr) => { swarm.dial(addr).ok(); }
                        SwarmCommand::PublishBlock(data) => {
                            swarm.behaviour_mut().gossipsub.publish(block_topic.clone(), data).ok();
                        }
                        SwarmCommand::PublishTransaction(data) => {
                             swarm.behaviour_mut().gossipsub.publish(tx_topic.clone(), data).ok();
                        }
                        SwarmCommand::SendStatusRequest(p) => { swarm.behaviour_mut().request_response.send_request(&p, SyncRequest::GetStatus); }
                        SwarmCommand::SendBlocksRequest(p, h) => { swarm.behaviour_mut().request_response.send_request(&p, SyncRequest::GetBlocks(h)); }
                        SwarmCommand::SendStatusResponse(c, h) => { swarm.behaviour_mut().request_response.send_response(c, SyncResponse::Status(h)).ok(); }
                        SwarmCommand::SendBlocksResponse(c, blocks) => { swarm.behaviour_mut().request_response.send_response(c, SyncResponse::Blocks(blocks)).ok(); }
                        SwarmCommand::SimulateSemanticTx => {
                            // This is a test-only command to trigger a log cascade.
                            // It does not interact with the network.
                        }
                        SwarmCommand::BroadcastToCommittee(_, _) => {
                            // Placeholder for real broadcast logic
                        }
                    },
                    None => { return; }
                }
            }
        }
    }
}
