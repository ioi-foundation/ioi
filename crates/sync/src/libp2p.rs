// Path: crates/sync/src/libp2p.rs
// Change: Prefixed unused fields, removed unreachable match arm.

//! A libp2p-based implementation of the BlockSync trait.

use crate::traits::{BlockSync, NodeState, SyncError};
use async_trait::async_trait;
use depin_sdk_core::{
    app::{Block, ProtocolTransaction},
    chain::SovereignChain,
    commitment::CommitmentScheme,
    state::{StateManager, StateTree},
    transaction::TransactionModel,
    validator::WorkloadContainer,
};
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
use std::{collections::HashSet, fmt::Debug, iter, sync::Arc};
use tokio::{
    sync::{mpsc, watch, Mutex},
    task::JoinHandle,
    time::{self, Duration},
};

// --- Network Protocol Definitions (previously in orchestration.rs) ---

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
enum SwarmEventOut {
    ConnectionEstablished(PeerId),
    ConnectionClosed(PeerId),
    GossipBlock(Vec<u8>, PeerId),
    StatusRequest(PeerId, ResponseChannel<SyncResponse>),
    BlocksRequest(PeerId, u64, ResponseChannel<SyncResponse>),
    StatusResponse(PeerId, u64),
    BlocksResponse(PeerId, Vec<Block<ProtocolTransaction>>),
}

// --- Libp2pSync Implementation ---

pub struct Libp2pSync<CS, TM, ST>
where
    CS: CommitmentScheme + Send + Sync + 'static,
    TM: TransactionModel<CommitmentScheme = CS> + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
{
    _chain: Arc<Mutex<dyn SovereignChain<CS, TM, ST> + Send + Sync>>,
    _workload: Arc<WorkloadContainer<ST>>,
    swarm_command_sender: mpsc::Sender<SwarmCommand>,
    shutdown_sender: Arc<watch::Sender<bool>>,
    task_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
    pub node_state: Arc<Mutex<NodeState>>,
    pub known_peers: Arc<Mutex<HashSet<PeerId>>>,
    pub local_peer_id: PeerId,
}

impl<CS, TM, ST> Libp2pSync<CS, TM, ST>
where
    CS: CommitmentScheme + Send + Sync + 'static,
    TM: TransactionModel<CommitmentScheme = CS> + Clone + Send + Sync + 'static,
    TM::Transaction:
        Clone + Debug + Send + Sync + for<'de> serde::Deserialize<'de> + serde::Serialize,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + StateTree<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug,
    CS::Commitment: Send + Sync + Debug,
{
    pub fn new(
        chain: Arc<Mutex<dyn SovereignChain<CS, TM, ST> + Send + Sync>>,
        workload: Arc<WorkloadContainer<ST>>,
        local_key: identity::Keypair,
        listen_addr: Multiaddr,
        dial_addr: Option<Multiaddr>,
    ) -> anyhow::Result<Self> {
        let (shutdown_sender, _) = watch::channel(false);
        let (swarm_command_sender, swarm_command_receiver) = mpsc::channel(100);
        let (swarm_event_sender, swarm_event_receiver) = mpsc::channel(100);

        let local_peer_id = local_key.public().to_peer_id();
        let node_state = Arc::new(Mutex::new(NodeState::Initializing));
        let known_peers = Arc::new(Mutex::new(HashSet::new()));

        let swarm = Self::build_swarm(local_key.clone())?;
        let swarm_task = tokio::spawn(Self::run_swarm_loop(
            swarm,
            swarm_command_receiver,
            swarm_event_sender,
            shutdown_sender.subscribe(),
        ));
        let event_task = tokio::spawn(Self::run_event_loop(
            swarm_command_sender.clone(),
            swarm_event_receiver,
            shutdown_sender.subscribe(),
            chain.clone(),
            workload.clone(),
            node_state.clone(),
            known_peers.clone(),
        ));

        let initial_cmds_task = tokio::spawn({
            let cmd_sender = swarm_command_sender.clone();
            async move {
                cmd_sender.send(SwarmCommand::Listen(listen_addr)).await.ok();
                if let Some(addr) = dial_addr {
                    cmd_sender.send(SwarmCommand::Dial(addr)).await.ok();
                }
            }
        });

        Ok(Self {
            _chain: chain,
            _workload: workload,
            swarm_command_sender,
            shutdown_sender: Arc::new(shutdown_sender),
            task_handles: Arc::new(Mutex::new(vec![swarm_task, event_task, initial_cmds_task])),
            node_state,
            known_peers,
            local_peer_id,
        })
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
        event_sender: mpsc::Sender<SwarmEventOut>,
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
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => { event_sender.send(SwarmEventOut::ConnectionEstablished(peer_id)).await.ok(); }
                    SwarmEvent::ConnectionClosed { peer_id, .. } => { event_sender.send(SwarmEventOut::ConnectionClosed(peer_id)).await.ok(); }
                    SwarmEvent::Behaviour(event) => match event {
                        SyncBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. }) => {
                            if let Some(source) = message.source {
                                event_sender.send(SwarmEventOut::GossipBlock(message.data, source)).await.ok();
                            }
                        }
                        SyncBehaviourEvent::RequestResponse(request_response::Event::Message { peer, message }) => {
                            match message {
                                request_response::Message::Request { request, channel, .. } => match request {
                                    SyncRequest::GetStatus => { event_sender.send(SwarmEventOut::StatusRequest(peer, channel)).await.ok(); }
                                    SyncRequest::GetBlocks(h) => { event_sender.send(SwarmEventOut::BlocksRequest(peer, h, channel)).await.ok(); }
                                },
                                request_response::Message::Response { request_id: _, response } => match response {
                                    SyncResponse::Status(h) => { event_sender.send(SwarmEventOut::StatusResponse(peer, h)).await.ok(); }
                                    SyncResponse::Blocks(blocks) => { event_sender.send(SwarmEventOut::BlocksResponse(peer, blocks)).await.ok(); }
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

    async fn run_event_loop(
        swarm_commander: mpsc::Sender<SwarmCommand>,
        mut event_receiver: mpsc::Receiver<SwarmEventOut>,
        mut shutdown_receiver: watch::Receiver<bool>,
        chain_ref: Arc<Mutex<dyn SovereignChain<CS, TM, ST> + Send + Sync>>,
        workload_ref: Arc<WorkloadContainer<ST>>,
        node_state: Arc<Mutex<NodeState>>,
        known_peers: Arc<Mutex<HashSet<PeerId>>>,
    ) {
        *node_state.lock().await = NodeState::Syncing;
        let initial_sync_timer = time::sleep(Duration::from_secs(5));
        tokio::pin!(initial_sync_timer);

        loop {
            tokio::select! {
                _ = &mut initial_sync_timer, if *node_state.lock().await == NodeState::Syncing => {
                    if known_peers.lock().await.is_empty() {
                         log::info!("[Sync] No peers found after timeout. Assuming genesis node. State -> Synced.");
                        *node_state.lock().await = NodeState::Synced;
                    }
                },
                _ = shutdown_receiver.changed() => if *shutdown_receiver.borrow() { break; },
                Some(event) = event_receiver.recv() => { match event {
                    SwarmEventOut::ConnectionEstablished(peer_id) => {
                        known_peers.lock().await.insert(peer_id);
                        swarm_commander.send(SwarmCommand::SendStatusRequest(peer_id)).await.ok();
                    }
                    SwarmEventOut::ConnectionClosed(peer_id) => {
                        known_peers.lock().await.remove(&peer_id);
                    }
                    SwarmEventOut::GossipBlock(data, source) => {
                        if let Ok(block) = serde_json::from_slice::<Block<ProtocolTransaction>>(&data) {
                            log::info!("[Sync] Received block #{} via gossip from peer {:?}.", block.header.height, source);
                            let mut chain = chain_ref.lock().await;
                            if let Err(e) = chain.process_block(block, &workload_ref).await {
                                log::warn!("[Sync] Failed to process gossiped block from peer {:?}: {:?}", source, e);
                            }
                        }
                    }
                    SwarmEventOut::StatusRequest(peer, channel) => {
                        let height = chain_ref.lock().await.status().height;
                        swarm_commander.send(SwarmCommand::SendStatusResponse(channel, height)).await.ok();
                        log::info!("[Sync] Responded to GetStatus request from {} with height {}.", peer, height);
                    }
                    SwarmEventOut::BlocksRequest(peer, since, channel) => {
                        let blocks = chain_ref.lock().await.get_blocks_since(since);
                        swarm_commander.send(SwarmCommand::SendBlocksResponse(channel, blocks)).await.ok();
                        log::info!("[Sync] Responded to GetBlocks request from {} for blocks since {}.", peer, since);
                    }
                    SwarmEventOut::StatusResponse(peer, peer_height) => {
                        let our_height = chain_ref.lock().await.status().height;
                        if peer_height > our_height {
                            log::info!("[Sync] Peer {} has longer chain ({} vs {}). Requesting blocks.", peer, peer_height, our_height);
                            swarm_commander.send(SwarmCommand::SendBlocksRequest(peer, our_height)).await.ok();
                        } else if *node_state.lock().await == NodeState::Syncing {
                            log::info!("[Sync] Synced with peer {}. State -> Synced", peer);
                            *node_state.lock().await = NodeState::Synced;
                        }
                    }
                    SwarmEventOut::BlocksResponse(peer, blocks) => {
                        log::info!("[Sync] Received {} blocks from {} for syncing.", blocks.len(), peer);
                        let mut chain = chain_ref.lock().await;
                        for block in blocks {
                            if let Err(e) = chain.process_block(block, &workload_ref).await {
                                log::error!("[Sync] Error syncing block from {}: {:?}", peer, e);
                                break;
                            }
                        }
                        if *node_state.lock().await == NodeState::Syncing {
                            log::info!("[Sync] Finished applying blocks from {}. State -> Synced.", peer);
                            *node_state.lock().await = NodeState::Synced;
                        }
                    }
                }}
            }
        }
        log::info!("[Sync] Event loop finished.");
    }
}

#[async_trait]
impl<CS, TM, ST> BlockSync<CS, TM, ST> for Libp2pSync<CS, TM, ST>
where
    CS: CommitmentScheme + Send + Sync + 'static,
    TM: TransactionModel<CommitmentScheme = CS> + Clone + Send + Sync + 'static,
    TM::Transaction:
        Clone + Debug + Send + Sync + for<'de> serde::Deserialize<'de> + serde::Serialize,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + StateTree<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug,
    CS::Commitment: Send + Sync + Debug,
{
    async fn start(&self) -> Result<(), SyncError> {
        // The tasks are already started in the constructor, so this is a no-op.
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