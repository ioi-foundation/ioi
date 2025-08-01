// Path: crates/sync/src/libp2p.rs

//! A libp2p-based implementation of the BlockSync trait.

use crate::traits::{BlockSync, NodeState, SyncError};
use async_trait::async_trait;
use depin_sdk_core::app::{Block, ProtocolTransaction};
use futures::{
    io::{AsyncRead, AsyncWrite},
    StreamExt,
};
use libp2p::{
    core::upgrade::{read_length_prefixed, write_length_prefixed, Version},
    gossipsub, identity, noise,
    request_response::{self, Codec, ProtocolSupport, ResponseChannel},
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder, Transport,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, iter, sync::Arc};
use tokio::{
    sync::{mpsc, watch, Mutex},
    task::JoinHandle,
    time::Duration,
};

// --- Network Protocol Definitions ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncRequest {
    GetStatus,
    GetBlocks(u64),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncResponse {
    Status(u64),
    Blocks(Vec<Block<ProtocolTransaction>>),
}

#[derive(Debug, Clone, Default)]
pub struct SyncCodec;

#[async_trait]
impl Codec for SyncCodec {
    type Protocol = &'static str;
    type Request = SyncRequest;
    type Response = SyncResponse;

    async fn read_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let vec = read_length_prefixed(io, 1_000_000).await?;
        serde_json::from_slice(&vec)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let vec = read_length_prefixed(io, 10_000_000).await?;
        serde_json::from_slice(&vec)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let vec = serde_json::to_vec(&req)?;
        write_length_prefixed(io, vec).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let vec = serde_json::to_vec(&res)?;
        write_length_prefixed(io, vec).await
    }
}

mod behaviour {
    use super::*;

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
}

use behaviour::{SyncBehaviour, SyncBehaviourEvent};

#[derive(Debug)]
pub enum SwarmCommand {
    Listen(Multiaddr),
    Dial(Multiaddr),
    PublishBlock(Vec<u8>),
    SendStatusRequest(PeerId),
    SendBlocksRequest(PeerId, u64),
    SendStatusResponse(ResponseChannel<SyncResponse>, u64),
    SendBlocksResponse(ResponseChannel<SyncResponse>, Vec<Block<ProtocolTransaction>>),
}

#[derive(Debug)]
pub enum NetworkEvent {
    ConnectionEstablished(PeerId),
    ConnectionClosed(PeerId),
    GossipBlock(Block<ProtocolTransaction>),
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
                    SwarmInternalEvent::ConnectionEstablished(p) => Some(NetworkEvent::ConnectionEstablished(p)),
                    SwarmInternalEvent::ConnectionClosed(p) => Some(NetworkEvent::ConnectionClosed(p)),
                    SwarmInternalEvent::StatusRequest(p, c) => Some(NetworkEvent::StatusRequest(p, c)),
                    SwarmInternalEvent::BlocksRequest(p, h, c) => Some(NetworkEvent::BlocksRequest(p, h, c)),
                    SwarmInternalEvent::StatusResponse(p, h) => Some(NetworkEvent::StatusResponse(p, h)),
                    SwarmInternalEvent::BlocksResponse(p, b) => Some(NetworkEvent::BlocksResponse(p, b)),
                    SwarmInternalEvent::GossipBlock(data, _source) => {
                        match serde_json::from_slice(&data) {
                            Ok(block) => Some(NetworkEvent::GossipBlock(block)),
                            Err(e) => {
                                log::warn!("Failed to deserialize gossiped block: {}", e);
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
                cmd_sender.send(SwarmCommand::Listen(listen_addr)).await.ok();
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
                    .upgrade(Version::V1Lazy)
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
                    iter::once(("/depin/sync/1", ProtocolSupport::Full)),
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
        let topic = gossipsub::IdentTopic::new("blocks");
        swarm.behaviour_mut().gossipsub.subscribe(&topic).unwrap();

        loop {
            tokio::select! {
                _ = shutdown_receiver.changed() => if *shutdown_receiver.borrow() {
                    log::info!("[Sync] Swarm loop received shutdown signal.");
                    break;
                },
                event = swarm.select_next_some() => match event {
                    SwarmEvent::NewListenAddr { address, .. } => { log::info!("[Sync] Swarm listening on {}", address); }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => { event_sender.send(SwarmInternalEvent::ConnectionEstablished(peer_id)).await.ok(); }
                    SwarmEvent::ConnectionClosed { peer_id, .. } => { event_sender.send(SwarmInternalEvent::ConnectionClosed(peer_id)).await.ok(); }
                    SwarmEvent::Behaviour(event) => match event {
                        SyncBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. }) => {
                            if let Some(source) = message.source {
                                event_sender.send(SwarmInternalEvent::GossipBlock(message.data, source)).await.ok();
                            }
                        }
                        SyncBehaviourEvent::RequestResponse(request_response::Event::Message { peer, message }) => {
                            match message {
                                request_response::Message::Request { request, channel, .. } => match request {
                                    SyncRequest::GetStatus => { event_sender.send(SwarmInternalEvent::StatusRequest(peer, channel)).await.ok(); }
                                    SyncRequest::GetBlocks(h) => { event_sender.send(SwarmInternalEvent::BlocksRequest(peer, h, channel)).await.ok(); }
                                },
                                request_response::Message::Response { request_id: _, response } => match response {
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
                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), data) {
                                log::warn!("[Sync] Failed to publish block: {:?}", e);
                            }
                        }
                        SwarmCommand::SendStatusRequest(p) => { swarm.behaviour_mut().request_response.send_request(&p, SyncRequest::GetStatus); }
                        SwarmCommand::SendBlocksRequest(p, h) => { swarm.behaviour_mut().request_response.send_request(&p, SyncRequest::GetBlocks(h)); }
                        SwarmCommand::SendStatusResponse(c, h) => { swarm.behaviour_mut().request_response.send_response(c, SyncResponse::Status(h)).ok(); }
                        SwarmCommand::SendBlocksResponse(c, blocks) => { swarm.behaviour_mut().request_response.send_response(c, SyncResponse::Blocks(blocks)).ok(); }
                    },
                    None => {
                        log::info!("[Sync] Swarm command channel closed. Shutting down swarm loop.");
                        return;
                    }
                }
            }
        }
        log::info!("[Sync] Swarm loop finished.");
    }
}

#[async_trait]
impl BlockSync for Libp2pSync {
    async fn start(&self) -> Result<(), SyncError> {
        log::info!("[Sync] Libp2pSync started.");
        Ok(())
    }

    async fn stop(&self) -> Result<(), SyncError> {
        log::info!("[Sync] Libp2pSync stopping...");
        self.shutdown_sender.send(true).ok();

        let mut handles = self.task_handles.lock().await;
        for handle in handles.drain(..) {
            handle
                .await
                .map_err(|e| SyncError::Internal(format!("Task panicked: {}", e)))?;
        }
        Ok(())
    }

    async fn publish_block(&self, block: &Block<ProtocolTransaction>) -> Result<(), SyncError> {
        let data =
            serde_json::to_vec(block).map_err(|e| SyncError::Decode(e.to_string()))?;
        self.swarm_command_sender
            .send(SwarmCommand::PublishBlock(data))
            .await
            .map_err(|e| SyncError::Network(e.to_string()))
    }

    fn get_node_state(&self) -> Arc<Mutex<NodeState>> {
        self.node_state.clone()
    }

    fn get_local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    fn get_known_peers(&self) -> Arc<Mutex<HashSet<PeerId>>> {
        self.known_peers.clone()
    }
}