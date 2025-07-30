// Path: crates/validator/src/standard/orchestration.rs

use crate::config::OrchestrationConfig;
use anyhow::anyhow;
use async_trait::async_trait;
use depin_sdk_core::{
    app::Block,
    chain::SovereignChain,
    commitment::CommitmentScheme,
    error::ValidatorError,
    state::{StateManager, StateTree},
    transaction::TransactionModel,
    validator::{Container, WorkloadContainer},
};
use futures::io::{AsyncRead, AsyncWrite};
use futures::StreamExt;
use libp2p::{
    core::{
        upgrade::{read_length_prefixed, write_length_prefixed, Version},
    },
    gossipsub, identity, noise,
    request_response::{self, Codec, ProtocolSupport, ResponseChannel},
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, SwarmBuilder, Transport,
};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::fs;
use std::io::{Read, Write};
use std::io;
use std::iter;
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::{
    sync::{mpsc, watch, Mutex, OnceCell},
    task::JoinHandle,
    time::{self, Duration},
};

/// The overall state of the node.
#[derive(Debug, Clone, PartialEq, Eq)]
enum NodeState {
    Syncing,
    Synced,
}

// MODIFICATION: Add a sub-state for followers to manage timeouts gracefully.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FollowerSubState {
    Listening, // Normal state, waiting for a block.
    Querying,  // Timed out, now querying peers before proposing a view change.
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncRequest {
    GetStatus,
    GetBlocks(u64),
    ViewChangeProposal(u64, u64), // (height, new_view)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncResponse {
    Status(u64),
    Blocks(Vec<Block<serde_bytes::ByteBuf>>),
    ViewChangeAck,
}

#[derive(Debug, Clone, Default)]
pub struct SyncCodec;

#[async_trait]
impl Codec for SyncCodec {
    type Protocol = &'static str;
    type Request = SyncRequest;
    type Response = SyncResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where T: AsyncRead + Unpin + Send {
        let vec = read_length_prefixed(io, 1_000_000).await?;
        serde_json::from_slice(&vec).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Response>
    where T: AsyncRead + Unpin + Send {
        let vec = read_length_prefixed(io, 10_000_000).await?;
        serde_json::from_slice(&vec).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(&mut self, _: &Self::Protocol, io: &mut T, req: Self::Request) -> io::Result<()>
    where T: AsyncWrite + Unpin + Send {
        let vec = serde_json::to_vec(&req)?;
        write_length_prefixed(io, vec).await
    }

    async fn write_response<T>(&mut self, _: &Self::Protocol, io: &mut T, res: Self::Response) -> io::Result<()>
    where T: AsyncWrite + Unpin + Send {
        let vec = serde_json::to_vec(&res)?;
        write_length_prefixed(io, vec).await
    }
}

/// Network behaviour module
mod behaviour {
    use super::*;

    #[derive(NetworkBehaviour)]
    #[behaviour(to_swarm = "OrchestrationBehaviourEvent")]
    pub struct OrchestrationBehaviour {
        pub gossipsub: gossipsub::Behaviour,
        pub request_response: request_response::Behaviour<SyncCodec>,
    }

    #[derive(Debug)]
    pub enum OrchestrationBehaviourEvent {
        Gossipsub(gossipsub::Event),
        RequestResponse(request_response::Event<SyncRequest, SyncResponse>),
    }

    impl From<gossipsub::Event> for OrchestrationBehaviourEvent {
        fn from(event: gossipsub::Event) -> Self {
            OrchestrationBehaviourEvent::Gossipsub(event)
        }
    }

    impl From<request_response::Event<SyncRequest, SyncResponse>> for OrchestrationBehaviourEvent {
        fn from(event: request_response::Event<SyncRequest, SyncResponse>) -> Self {
            OrchestrationBehaviourEvent::RequestResponse(event)
        }
    }
}

use behaviour::{OrchestrationBehaviour, OrchestrationBehaviourEvent};

/// Commands sent *to* the swarm task.
#[derive(Debug)]
pub enum SwarmCommand {
    Listen(Multiaddr),
    Dial(Multiaddr),
    PublishBlock(Vec<u8>),
    SendStatusRequest(PeerId),
    SendBlocksRequest(PeerId, u64),
    SendStatusResponse(ResponseChannel<SyncResponse>, u64),
    SendBlocksResponse(ResponseChannel<SyncResponse>, Vec<Block<serde_bytes::ByteBuf>>),
    BroadcastViewChange(u64, u64, Vec<PeerId>),
    SendViewChangeAck(ResponseChannel<SyncResponse>),
    // MODIFICATION: Command to query all known peers.
    QueryAllPeers,
}

/// Events sent *from* the swarm task back to the event loop.
#[derive(Debug)]
enum SwarmEventOut {
    ConnectionEstablished(PeerId),
    ConnectionClosed(PeerId),
    GossipBlock(Vec<u8>, PeerId),
    StatusRequest(PeerId, ResponseChannel<SyncResponse>),
    BlocksRequest(PeerId, u64, ResponseChannel<SyncResponse>),
    StatusResponse(PeerId, u64),
    BlocksResponse(PeerId, Vec<Block<serde_bytes::ByteBuf>>),
    ViewChangeRequest(PeerId, u64, u64, ResponseChannel<SyncResponse>),
    ViewChangeAckReceived(PeerId),
}

/// Free function to check for quorum.
fn has_quorum(
    validator_set: &[Vec<u8>],
    known_peers: &HashSet<PeerId>,
    local_peer_id: &PeerId,
) -> bool {
    if validator_set.is_empty() {
        return true;
    }
    let mut connected_validators = 0;
    for peer_bytes in validator_set {
        if let Ok(peer_id) = PeerId::from_bytes(peer_bytes) {
            if &peer_id == local_peer_id || known_peers.contains(&peer_id) {
                connected_validators += 1;
            }
        }
    }
    let quorum_size = (validator_set.len() / 2) + 1;
    let has_quorum = connected_validators >= quorum_size;
    if !has_quorum {
        log::warn!(
            "Quorum check failed: see {}/{} of validator set (quorum is {}). Known peers: {}",
            connected_validators, validator_set.len(), quorum_size, known_peers.len()
        );
    } else {
        log::info!(
            "Quorum check passed: see {}/{} of validator set (quorum is {}).",
             connected_validators, validator_set.len(), quorum_size
        );
    }
    has_quorum
}

pub struct OrchestrationContainer<CS, TM, ST>
where
    CS: CommitmentScheme + Send + Sync + 'static,
    TM: TransactionModel<CommitmentScheme = CS> + Clone + Send + Sync + 'static,
    TM::Transaction: Clone + Debug + Send + Sync,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static + Debug,
{
    _config: OrchestrationConfig,
    chain: Arc<OnceCell<Arc<Mutex<dyn SovereignChain<CS, TM, ST> + Send + Sync>>>>,
    workload: Arc<OnceCell<Arc<WorkloadContainer<ST>>>>,
    swarm_command_sender: Mutex<Option<mpsc::Sender<SwarmCommand>>>,
    swarm_event_receiver: Arc<Mutex<Option<mpsc::Receiver<SwarmEventOut>>>>,
    shutdown_sender: Arc<watch::Sender<bool>>,
    task_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
    is_running: Arc<AtomicBool>,
    local_peer_id: PeerId,
    current_view: Arc<Mutex<(u64, u64)>>, // (height, view)
    view_change_votes: Arc<Mutex<HashMap<(u64, u64), HashSet<PeerId>>>>,
    // MODIFICATION: Add follower sub-state and a flag to track if we've been out-of-sync.
    follower_state: Arc<Mutex<FollowerSubState>>,
    has_higher_peer: Arc<AtomicBool>,
}

impl<CS, TM, ST> OrchestrationContainer<CS, TM, ST>
where
    CS: CommitmentScheme + Send + Sync + 'static,
    TM: TransactionModel<CommitmentScheme = CS> + Clone + Send + Sync + 'static,
    TM::Transaction: Clone + Debug + Send + Sync + for<'de> serde::Deserialize<'de> + serde::Serialize,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + StateTree<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send + Sync + 'static + Debug,
    CS::Commitment: Send + Sync + Debug,
{
    pub async fn new(config_path: &std::path::Path, state_file_path: &str) -> anyhow::Result<Self> {
        let _config: OrchestrationConfig = toml::from_str(&std::fs::read_to_string(config_path)?)?;
        let (shutdown_sender, _) = watch::channel(false);

        let key_path = Path::new(state_file_path).with_extension("json.identity.key");

        let local_key = if key_path.exists() {
            let mut bytes = Vec::new();
            fs::File::open(&key_path)?.read_to_end(&mut bytes)?;
            identity::Keypair::from_protobuf_encoding(&bytes)
                .map_err(|e| anyhow!("Failed to decode identity keypair from {:?}: {:?}", key_path, e))?
        } else {
            let keypair = identity::Keypair::generate_ed25519();
            fs::File::create(&key_path)?.write_all(&keypair.to_protobuf_encoding()?)?;
            log::info!("Generated and saved new identity key to {:?}", key_path);
            keypair
        };

        let local_peer_id = local_key.public().to_peer_id();

        let (swarm_command_sender, swarm_command_receiver) = mpsc::channel(100);
        let (swarm_event_sender, swarm_event_receiver) = mpsc::channel(100);

        let swarm_task_handle = tokio::spawn(Self::run_swarm_loop(
            local_key,
            swarm_command_receiver,
            swarm_event_sender,
        ));

        let container = Self {
            _config,
            chain: Arc::new(OnceCell::new()),
            workload: Arc::new(OnceCell::new()),
            swarm_command_sender: Mutex::new(Some(swarm_command_sender)),
            swarm_event_receiver: Arc::new(Mutex::new(Some(swarm_event_receiver))),
            shutdown_sender: Arc::new(shutdown_sender),
            task_handles: Arc::new(Mutex::new(vec![swarm_task_handle])),
            is_running: Arc::new(AtomicBool::new(false)),
            local_peer_id,
            current_view: Arc::new(Mutex::new((1, 0))),
            view_change_votes: Arc::new(Mutex::new(HashMap::new())),
            follower_state: Arc::new(Mutex::new(FollowerSubState::Listening)),
            has_higher_peer: Arc::new(AtomicBool::new(false)),
        };

        log::info!("Local Peer ID: {}", local_peer_id);
        Ok(container)
    }

    pub fn set_chain_and_workload_ref(
        &self,
        chain_ref: Arc<Mutex<dyn SovereignChain<CS, TM, ST> + Send + Sync>>,
        workload_ref: Arc<WorkloadContainer<ST>>,
    ) {
        self.chain.set(chain_ref).expect("Chain ref already set");
        self.workload.set(workload_ref).expect("Workload ref already set");
    }

    pub async fn dial(&self, addr: Multiaddr) {
        if let Some(sender) = self.swarm_command_sender.lock().await.as_ref() {
            sender.send(SwarmCommand::Dial(addr)).await.ok();
        }
    }

    async fn run_swarm_loop(
        local_key: identity::Keypair,
        mut command_receiver: mpsc::Receiver<SwarmCommand>,
        event_sender: mpsc::Sender<SwarmEventOut>,
    ) {
        let mut swarm = SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_other_transport(|key| {
                let noise_config = noise::Config::new(key).unwrap();
                let transport = tcp::tokio::Transport::new(tcp::Config::default())
                    .upgrade(Version::V1Lazy)
                    .authenticate(noise_config)
                    .multiplex(yamux::Config::default()).timeout(Duration::from_secs(20)).boxed();
                Ok(transport)
            }).unwrap()
            .with_behaviour(|key| {
                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub::Config::default(),
                ).unwrap();
                let request_response = request_response::Behaviour::new(
                    iter::once(("/depin/sync/1", ProtocolSupport::Full)),
                    request_response::Config::default(),
                );
                Ok(OrchestrationBehaviour { gossipsub, request_response })
            }).unwrap()
            .build();
        
        let topic = gossipsub::IdentTopic::new("blocks");
        swarm.behaviour_mut().gossipsub.subscribe(&topic).unwrap();

        loop {
            tokio::select! {
                event = swarm.select_next_some() => match event {
                    SwarmEvent::NewListenAddr { address, .. } => { log::info!("Swarm listening on {}", address); }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => { event_sender.send(SwarmEventOut::ConnectionEstablished(peer_id)).await.ok(); }
                    SwarmEvent::ConnectionClosed { peer_id, .. } => { event_sender.send(SwarmEventOut::ConnectionClosed(peer_id)).await.ok(); }
                    SwarmEvent::Behaviour(event) => match event {
                        OrchestrationBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. }) => {
                            if let Some(source) = message.source {
                                event_sender.send(SwarmEventOut::GossipBlock(message.data, source)).await.ok();
                            }
                        }
                        OrchestrationBehaviourEvent::RequestResponse(request_response::Event::Message { peer, message }) => {
                            match message {
                                request_response::Message::Request { request, channel, .. } => match request {
                                    SyncRequest::GetStatus => { event_sender.send(SwarmEventOut::StatusRequest(peer, channel)).await.ok(); }
                                    SyncRequest::GetBlocks(h) => { event_sender.send(SwarmEventOut::BlocksRequest(peer, h, channel)).await.ok(); }
                                    SyncRequest::ViewChangeProposal(h, v) => { event_sender.send(SwarmEventOut::ViewChangeRequest(peer, h, v, channel)).await.ok(); }
                                },
                                request_response::Message::Response { request_id: _, response } => match response {
                                    SyncResponse::Status(h) => { event_sender.send(SwarmEventOut::StatusResponse(peer, h)).await.ok(); }
                                    SyncResponse::Blocks(b) => { event_sender.send(SwarmEventOut::BlocksResponse(peer, b)).await.ok(); }
                                    SyncResponse::ViewChangeAck => { event_sender.send(SwarmEventOut::ViewChangeAckReceived(peer)).await.ok(); }
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
                                log::warn!("Failed to publish block: {:?}", e);
                            }
                        }
                        SwarmCommand::SendStatusRequest(p) => { swarm.behaviour_mut().request_response.send_request(&p, SyncRequest::GetStatus); }
                        SwarmCommand::SendBlocksRequest(p, h) => { swarm.behaviour_mut().request_response.send_request(&p, SyncRequest::GetBlocks(h)); }
                        SwarmCommand::SendStatusResponse(c, h) => { swarm.behaviour_mut().request_response.send_response(c, SyncResponse::Status(h)).ok(); }
                        SwarmCommand::SendBlocksResponse(c, b) => { swarm.behaviour_mut().request_response.send_response(c, SyncResponse::Blocks(b)).ok(); }
                        SwarmCommand::BroadcastViewChange(h, v, peers) => {
                            for peer in peers {
                                swarm.behaviour_mut().request_response.send_request(&peer, SyncRequest::ViewChangeProposal(h, v));
                            }
                        }
                        SwarmCommand::SendViewChangeAck(c) => { swarm.behaviour_mut().request_response.send_response(c, SyncResponse::ViewChangeAck).ok(); }
                        // MODIFICATION: Add logic to send status requests to all connected peers.
                        SwarmCommand::QueryAllPeers => {
                            let peers = swarm.connected_peers().cloned().collect::<Vec<_>>();
                             for peer in peers {
                                 swarm.behaviour_mut().request_response.send_request(&peer, SyncRequest::GetStatus);
                             }
                        }
                    },
                    None => {
                        log::info!("Swarm command channel closed. Shutting down swarm loop.");
                        return;
                    }
                }
            }
        }
    }

    async fn run_event_loop(
        swarm_commander: Option<mpsc::Sender<SwarmCommand>>,
        mut event_receiver: mpsc::Receiver<SwarmEventOut>,
        mut shutdown_receiver: watch::Receiver<bool>,
        chain_cell: Arc<OnceCell<Arc<Mutex<dyn SovereignChain<CS, TM, ST> + Send + Sync>>>>,
        workload_cell: Arc<OnceCell<Arc<WorkloadContainer<ST>>>>,
        known_peers: Arc<Mutex<HashSet<PeerId>>>,
        node_state: Arc<Mutex<NodeState>>,
        current_view: Arc<Mutex<(u64, u64)>>,
        view_change_votes: Arc<Mutex<HashMap<(u64, u64), HashSet<PeerId>>>>,
        // MODIFICATION: Add flag for sync check.
        has_higher_peer: Arc<AtomicBool>,
    ) {
        let chain_ref = chain_cell.get().unwrap().clone();
        let workload_ref = workload_cell.get().unwrap().clone();
        
        let initial_sync_timeout = tokio::time::sleep(Duration::from_secs(7));
        tokio::pin!(initial_sync_timeout);

        loop {
            let is_syncing = *node_state.lock().await == NodeState::Syncing;
            tokio::select! {
                _ = shutdown_receiver.changed() => if *shutdown_receiver.borrow() { break; },
                _ = &mut initial_sync_timeout, if is_syncing => {
                    if known_peers.lock().await.len() <= 1 {
                        log::info!("No peers found after timeout. Assuming genesis node. State -> Synced.");
                        *node_state.lock().await = NodeState::Synced;
                    }
                },
                Some(event) = event_receiver.recv() => if let Some(ref commander) = swarm_commander { match event {
                    SwarmEventOut::ConnectionEstablished(peer_id) => {
                        known_peers.lock().await.insert(peer_id);
                        commander.send(SwarmCommand::SendStatusRequest(peer_id)).await.ok();
                    }
                    SwarmEventOut::ConnectionClosed(peer_id) => {
                        known_peers.lock().await.remove(&peer_id);
                    }
                    SwarmEventOut::GossipBlock(data, source) => {
                        if let Ok(block_bytes) = serde_json::from_slice::<Block<serde_bytes::ByteBuf>>(&data) {
                            let transactions = block_bytes.transactions.into_iter().map(|b| serde_json::from_slice(&b).unwrap()).collect();
                            let block = Block { header: block_bytes.header, transactions };
                            log::info!("Received block #{} via gossip from peer {:?}.", block.header.height, source);
                            let mut chain = chain_ref.lock().await;
                            if let Err(e) = chain.process_block(block, &workload_ref).await {
                                log::warn!("Failed to process gossiped block from peer {:?}: {:?}", source, e);
                            } else {
                                let new_height = chain.status().height;
                                let mut cv = current_view.lock().await;
                                *cv = (new_height + 1, 0);
                                view_change_votes.lock().await.clear();
                                log::info!("Block processed. Resetting to target height {} view 0.", new_height + 1);
                            }
                        }
                    }
                    SwarmEventOut::StatusRequest(peer, channel) => {
                        let height = chain_ref.lock().await.status().height;
                        commander.send(SwarmCommand::SendStatusResponse(channel, height)).await.ok();
                        log::info!("Responded to GetStatus request from {} with height {}.", peer, height);
                    }
                    SwarmEventOut::BlocksRequest(peer, since, channel) => {
                        let blocks = chain_ref.lock().await.get_blocks_since(since);
                        let serializable = blocks.into_iter().map(|b| {
                            let txs = b.transactions.into_iter().map(|tx| serde_bytes::ByteBuf::from(serde_json::to_vec(&tx).unwrap())).collect();
                            Block { header: b.header, transactions: txs }
                        }).collect();
                        commander.send(SwarmCommand::SendBlocksResponse(channel, serializable)).await.ok();
                        log::info!("Responded to GetBlocks request from {} for blocks since {}.", peer, since);
                    }
                    SwarmEventOut::StatusResponse(peer, peer_height) => {
                        let our_height = chain_ref.lock().await.status().height;
                        if peer_height > our_height {
                            // MODIFICATION: Set the flag if we find a peer with a higher chain.
                            has_higher_peer.store(true, Ordering::SeqCst);
                            log::info!("Peer {} has longer chain ({} vs {}). Requesting blocks.", peer, peer_height, our_height);
                            commander.send(SwarmCommand::SendBlocksRequest(peer, our_height)).await.ok();
                        } else {
                             if *node_state.lock().await == NodeState::Syncing {
                                 *node_state.lock().await = NodeState::Synced;
                                 log::info!("Sync complete with {}. State -> Synced.", peer);
                             }
                        }
                    }
                    SwarmEventOut::BlocksResponse(peer, blocks) => {
                        log::info!("Received {} blocks from {} for syncing.", blocks.len(), peer);
                        let mut chain = chain_ref.lock().await;
                        for block_bytes in blocks {
                            let txs = block_bytes.transactions.into_iter().map(|b| serde_json::from_slice(&b).unwrap()).collect();
                            if let Err(e) = chain.process_block(Block { header: block_bytes.header, transactions: txs }, &workload_ref).await {
                                log::error!("Error syncing block from {}: {:?}", peer, e);
                                break;
                            }
                        }
                         if *node_state.lock().await == NodeState::Syncing {
                             *node_state.lock().await = NodeState::Synced;
                             log::info!("Finished applying blocks from {}. State -> Synced.", peer);
                         }
                    }
                    SwarmEventOut::ViewChangeRequest(peer, height, new_view, channel) => {
                        let (current_target_height, current_node_view) = *current_view.lock().await;

                        if height == current_target_height && new_view > current_node_view {
                            log::info!("Received valid ViewChangeProposal for height {} view {} from peer {}", height, new_view, peer);
                            let mut votes = view_change_votes.lock().await;
                            let entry = votes.entry((height, new_view)).or_default();
                            entry.insert(peer);

                            let validator_set = chain_ref.lock().await.get_validator_set(&workload_ref).await.unwrap_or_default();
                            let quorum = (validator_set.len() / 2) + 1;

                            if entry.len() >= quorum {
                                log::info!("Quorum met for view change to (h:{}, v:{}). Updating local view.", height, new_view);
                                let mut cv = current_view.lock().await;
                                *cv = (height, new_view);
                                votes.remove(&(height, new_view));
                            }
                        } else {
                            log::warn!("Ignoring stale or invalid ViewChangeProposal from {}: proposed (h:{}, v:{}), our state is (h:{}, v:{})", peer, height, new_view, current_target_height, current_node_view);
                        }
                        commander.send(SwarmCommand::SendViewChangeAck(channel)).await.ok();
                    }
                    SwarmEventOut::ViewChangeAckReceived(peer) => {
                        log::debug!("Received ViewChangeAck from {}", peer);
                    }
                }}
            }
        }
        log::info!("Orchestration event loop finished.");
    }

    async fn run_block_production(
        local_peer_id: PeerId,
        chain_ref: Arc<Mutex<dyn SovereignChain<CS, TM, ST> + Send + Sync>>,
        workload_ref: Arc<WorkloadContainer<ST>>,
        swarm_commander: Option<mpsc::Sender<SwarmCommand>>,
        is_running: Arc<AtomicBool>,
        known_peers_ref: Arc<Mutex<HashSet<PeerId>>>,
        node_state_ref: Arc<Mutex<NodeState>>,
        current_view_ref: Arc<Mutex<(u64, u64)>>,
        view_change_votes_ref: Arc<Mutex<HashMap<(u64, u64), HashSet<PeerId>>>>,
        follower_state_ref: Arc<Mutex<FollowerSubState>>,
        has_higher_peer_ref: Arc<AtomicBool>,
    ) {
        let mut interval = time::interval(Duration::from_secs(10));
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

        while is_running.load(Ordering::SeqCst) {
            interval.tick().await;

            if *node_state_ref.lock().await != NodeState::Synced {
                continue;
            }

            let chain_height = chain_ref.lock().await.status().height;
            let (mut target_height, mut current_view) = *current_view_ref.lock().await;

            if chain_height >= target_height {
                log::info!("Chain has advanced to height {}. Resetting to target {} view 0.", chain_height, chain_height + 1);
                target_height = chain_height + 1;
                current_view = 0;
                let mut cv_lock = current_view_ref.lock().await;
                *cv_lock = (target_height, current_view);
                view_change_votes_ref.lock().await.clear();
                // MODIFICATION: Reset follower state when chain advances.
                *follower_state_ref.lock().await = FollowerSubState::Listening;
            }

            let validator_set = match chain_ref.lock().await.get_validator_set(&workload_ref).await {
                Ok(vs) => vs,
                Err(e) => {
                    log::error!("Could not get validator set: {:?}", e);
                    continue;
                }
            };
            
            let is_me = if validator_set.is_empty() {
                chain_height == 0
            } else {
                let leader_index = ((target_height + current_view) % validator_set.len() as u64) as usize;
                let designated_leader_bytes = &validator_set[leader_index];
                designated_leader_bytes == &local_peer_id.to_bytes()
            };

            log::info!(
                "[LEADER CHECK] Target Height: {}, View: {}, Leader Index: {}, Me: {:?}, Is Me: {}",
                target_height, current_view,
                if validator_set.is_empty() { 0 } else { ((target_height + current_view) % validator_set.len() as u64) as usize },
                local_peer_id, is_me
            );

            let known_peers = known_peers_ref.lock().await;
            
            if is_me {
                // --- LEADER LOGIC ---
                *follower_state_ref.lock().await = FollowerSubState::Listening; // Reset follower state if we become leader.
                if !has_quorum(&validator_set, &known_peers, &local_peer_id) {
                    continue;
                }

                log::info!("We are the leader for (h:{}, v:{}), producing block...", target_height, current_view);
                
                let peers_bytes: Vec<Vec<u8>> = {
                    let mut peers = known_peers.clone();
                    peers.insert(local_peer_id);
                    peers.iter().map(|p| p.to_bytes()).collect()
                };

                let coinbase = match chain_ref.lock().await.transaction_model().clone().create_coinbase_transaction(target_height, &local_peer_id.to_bytes()) {
                    Ok(tx) => tx,
                    Err(e) => { log::error!("Failed to create coinbase: {:?}", e); continue; }
                };
                
                let new_block_template = chain_ref.lock().await.create_block(vec![coinbase], &workload_ref, &validator_set, &peers_bytes);
                
                let mut chain = chain_ref.lock().await;
                let final_block = match chain.process_block(new_block_template, &workload_ref).await {
                    Ok(b) => b,
                    Err(e) => { log::error!("Failed to process our own block: {:?}", e); continue; }
                };
                log::info!("Produced and processed new block #{}", final_block.header.height);

                if let Some(ref commander) = swarm_commander {
                    let message_data = serde_json::to_vec(&final_block).unwrap();
                    commander.send(SwarmCommand::PublishBlock(message_data)).await.ok();
                }

                let mut cv = current_view_ref.lock().await;
                *cv = (target_height + 1, 0);
                view_change_votes_ref.lock().await.clear();
                *follower_state_ref.lock().await = FollowerSubState::Listening;
            } else {
                // --- FOLLOWER LOGIC (TIMEOUT) ---
                let mut follower_state = follower_state_ref.lock().await;
                match *follower_state {
                    FollowerSubState::Listening => {
                        log::info!("Not the leader for (h:{}, v:{}). Entering query state before proposing view change.", target_height, current_view);
                        *follower_state = FollowerSubState::Querying;
                        has_higher_peer_ref.store(false, Ordering::SeqCst); // Reset flag
                        if let Some(ref commander) = swarm_commander {
                            commander.send(SwarmCommand::QueryAllPeers).await.ok();
                        }
                    }
                    FollowerSubState::Querying => {
                        // We have waited one tick (10s) in the Querying state. Now check the result.
                        if has_higher_peer_ref.load(Ordering::SeqCst) {
                            log::info!("A peer has a higher chain. Aborting view change and will sync.");
                            *follower_state = FollowerSubState::Listening; // Reset state
                        } else {
                            log::warn!("No peer has a higher chain after query. Proposing view change for (h:{}, v:{}).", target_height, current_view + 1);
                            let new_view = current_view + 1;
                            
                            let mut cv = current_view_ref.lock().await;
                            *cv = (target_height, new_view);
                            
                            let mut votes = view_change_votes_ref.lock().await;
                            votes.entry((target_height, new_view)).or_default().insert(local_peer_id);
                            
                            let remote_peers: Vec<_> = known_peers.iter().filter(|p| **p != local_peer_id).cloned().collect();
                            if let Some(ref commander) = swarm_commander {
                                commander.send(SwarmCommand::BroadcastViewChange(target_height, new_view, remote_peers)).await.ok();
                            }
                            *follower_state = FollowerSubState::Listening; // Go back to listening for the new view
                        }
                    }
                }
            }
        }
        log::info!("Orchestration block production loop finished.");
    }
}

#[async_trait]
impl<CS, TM, ST> Container for OrchestrationContainer<CS, TM, ST>
where
    CS: CommitmentScheme + Send + Sync + 'static,
    TM: TransactionModel<CommitmentScheme = CS> + Clone + Send + Sync + 'static,
    TM::Transaction: Clone + Debug + Send + Sync + for<'de> serde::Deserialize<'de> + serde::Serialize,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + StateTree<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static + Debug,
    CS::Commitment: Send + Sync + Debug,
{
    fn id(&self) -> &'static str { "orchestration_container" }
    fn is_running(&self) -> bool { self.is_running.load(Ordering::SeqCst) }

    async fn start(&self) -> Result<(), ValidatorError> {
        if self.is_running() { return Err(ValidatorError::AlreadyRunning(self.id().to_string())); }
        log::info!("OrchestrationContainer starting...");

        let command_sender = self.swarm_command_sender.lock().await.clone();
        if let Some(ref sender) = command_sender {
            let listen_addr: Multiaddr = "/ip4/0.0.0.0/tcp/0".parse().unwrap();
            sender.send(SwarmCommand::Listen(listen_addr)).await.ok();
        } else {
             return Err(ValidatorError::Other("Swarm command sender is gone before start".to_string()));
        }

        let chain = self.chain.get().ok_or_else(|| ValidatorError::Other("Chain ref not initialized before start".to_string()))?.clone();
        let workload = self.workload.get().ok_or_else(|| ValidatorError::Other("Workload ref not initialized before start".to_string()))?.clone();

        let known_peers = Arc::new(Mutex::new(HashSet::from([self.local_peer_id])));
        let node_state = Arc::new(Mutex::new(NodeState::Syncing));

        let mut handles = self.task_handles.lock().await;

        let swarm_event_receiver = self.swarm_event_receiver.lock().await.take()
            .ok_or_else(|| ValidatorError::Other("Event receiver already taken".to_string()))?;

        handles.push(tokio::spawn(Self::run_event_loop(
            command_sender.clone(),
            swarm_event_receiver,
            self.shutdown_sender.subscribe(),
            self.chain.clone(),
            self.workload.clone(),
            known_peers.clone(),
            node_state.clone(),
            self.current_view.clone(),
            self.view_change_votes.clone(),
            self.has_higher_peer.clone(),
        )));

        handles.push(tokio::spawn(Self::run_block_production(
            self.local_peer_id,
            chain,
            workload,
            command_sender,
            self.is_running.clone(),
            known_peers,
            node_state,
            self.current_view.clone(),
            self.view_change_votes.clone(),
            self.follower_state.clone(),
            self.has_higher_peer.clone(),
        )));

        self.is_running.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn stop(&self) -> Result<(), ValidatorError> {
        if !self.is_running() { return Ok(()); }
        log::info!("OrchestrationContainer stopping...");
        self.is_running.store(false, Ordering::SeqCst);
        self.shutdown_sender.send(true).ok();

        if let Some(sender) = self.swarm_command_sender.lock().await.take() {
            drop(sender);
        }

        let mut handles = self.task_handles.lock().await;
        for handle in handles.drain(..) {
            handle.await.map_err(|e| ValidatorError::Other(format!("Task panicked: {}", e)))?;
        }
        Ok(())
    }
}