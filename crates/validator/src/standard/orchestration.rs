// Path: crates/validator/src/standard/orchestration.rs

use crate::config::OrchestrationConfig;
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
use std::collections::HashSet;
use std::fmt::Debug;
use std::io;
use std::iter;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::{
    sync::{mpsc, watch, Mutex, OnceCell},
    task::JoinHandle,
    time::{self, Duration},
};

/// The internal state of the node, determining its participation in consensus.
#[derive(Debug, Clone, PartialEq, Eq)]
enum NodeState {
    Syncing,
    Synced,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncRequest {
    GetStatus,
    GetBlocks(u64),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncResponse {
    Status(u64),
    Blocks(Vec<Block<serde_bytes::ByteBuf>>),
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
    pub async fn new(config_path: &std::path::Path) -> anyhow::Result<Self> {
        let _config: OrchestrationConfig = toml::from_str(&std::fs::read_to_string(config_path)?)?;
        let (shutdown_sender, _) = watch::channel(false);
        let local_key = identity::Keypair::generate_ed25519();
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
                                },
                                request_response::Message::Response { request_id: _, response } => match response {
                                    SyncResponse::Status(h) => { event_sender.send(SwarmEventOut::StatusResponse(peer, h)).await.ok(); }
                                    SyncResponse::Blocks(b) => { event_sender.send(SwarmEventOut::BlocksResponse(peer, b)).await.ok(); }
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
    ) {
        let mut interval = time::interval(Duration::from_secs(10));
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    
        while is_running.load(Ordering::SeqCst) {
            interval.tick().await;
    
            // --- NEW: PERIODIC SYNC LOGIC ---
            // Periodically check status with a random peer to ensure we haven't fallen behind due to
            // missed gossip messages or transient network issues.
            if let Some(ref commander) = swarm_commander {
                let peer_to_ping = {
                    let peers = known_peers_ref.lock().await;
                    // Create a list of remote peers (excluding ourselves)
                    let remote_peers: Vec<_> = peers.iter().filter(|p| **p != local_peer_id).copied().collect();
                    // Select a peer inside this scope to ensure the non-Send ThreadRng is dropped.
                    remote_peers.choose(&mut rand::thread_rng()).copied()
                };

                if let Some(random_peer) = peer_to_ping {
                    log::info!("[SYNC CHECK] Performing periodic status check with peer {}.", random_peer);
                    commander.send(SwarmCommand::SendStatusRequest(random_peer)).await.ok();
                }
            }
            // --- END: PERIODIC SYNC LOGIC ---

            if *node_state_ref.lock().await != NodeState::Synced {
                continue;
            }

            // --- START INLINED LEADER ELECTION ---
            let (validator_set, current_height) = {
                let chain = chain_ref.lock().await;
                let height = chain.status().height;
                match chain.get_validator_set(&workload_ref).await {
                    Ok(vs) => (vs, height),
                    Err(e) => {
                        log::error!("Could not get validator set for leader check: {:?}", e);
                        continue; // Skip this tick if we can't get the validator set
                    }
                }
            };

            let next_height = current_height + 1;
            let is_me = if validator_set.is_empty() {
                if current_height == 0 {
                    log::info!("At genesis, assuming leadership.");
                    true
                } else {
                    log::warn!("Validator set from state is empty at height {}. Assuming leadership to recover.", current_height);
                    true
                }
            } else {
                let leader_index = (next_height % validator_set.len() as u64) as usize;
                // This check is important, although it should mathematically never fail if len > 0
                if leader_index >= validator_set.len() {
                    log::error!("BUG: Leader index {} is out of bounds for validator set of size {}.", leader_index, validator_set.len());
                    false
                } else {
                    let designated_leader_bytes = &validator_set[leader_index];
                    designated_leader_bytes == &local_peer_id.to_bytes()
                }
            };
            
            log::info!(
                "[LEADER CHECK] Height: {}, Next: {}, Validators: {}, Designated: {:?}, Me: {:?}, Is Me: {}",
                current_height,
                next_height,
                validator_set.len(),
                if validator_set.is_empty() { None } else { PeerId::from_bytes(&validator_set[(next_height % validator_set.len() as u64) as usize]).ok() },
                local_peer_id,
                is_me
            );
            
            if !is_me {
                continue;
            }
            
            let known_peers = known_peers_ref.lock().await;
            if !has_quorum(&validator_set, &known_peers, &local_peer_id) {
                continue;
            }
            // --- END INLINED LEADER ELECTION ---

            let height_after_check = chain_ref.lock().await.status().height;
            if height_after_check >= next_height {
                log::info!("Block #{} already processed by the time we acquired lock. Aborting production.", next_height);
                continue;
            }
            
            let tm = chain_ref.lock().await.transaction_model().clone();

            let peers_bytes: Vec<Vec<u8>> = {
                let mut peers = known_peers.clone();
                peers.insert(local_peer_id);
                peers.iter().map(|p| p.to_bytes()).collect()
            };
            
            log::info!("We are the leader, producing block #{}...", next_height);
            
            let coinbase = match tm.create_coinbase_transaction(next_height, &local_peer_id.to_bytes()) {
                Ok(tx) => tx,
                Err(e) => {
                    log::error!("Failed to create coinbase transaction: {:?}. Skipping block production.", e);
                    continue;
                }
            };

            let new_block_template = {
                let chain = chain_ref.lock().await;
                chain.create_block(vec![coinbase], &workload_ref, &validator_set, &peers_bytes)
            };

            // Take the lock on the chain state to process the new block.
            let mut chain = chain_ref.lock().await;

            // Process the block template. This will execute transactions, update state,
            // and return the finalized block with the correct state_root in its header.
            let final_block = match chain.process_block(new_block_template, &workload_ref).await {
                Ok(b) => b,
                Err(e) => {
                    log::error!("Failed to process our own new block: {:?}", e);
                    continue;
                }
            };
            log::info!("Produced and processed new block #{}", final_block.header.height);

            if let Some(ref commander) = swarm_commander {
                // Serialize and broadcast the FINALIZED block, not the old template.
                let message_data = serde_json::to_vec(&final_block).unwrap();
                commander.send(SwarmCommand::PublishBlock(message_data)).await.ok();
            }
        }
        log::info!("Orchestration block production loop finished.");
    }
}

// NOTE: The separate helper functions `check_leader_and_get_vs` and `is_our_turn_to_produce`
// have been removed, and their logic is now inlined into `run_block_production`.

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
        )));
        
        handles.push(tokio::spawn(Self::run_block_production(
            self.local_peer_id,
            chain,
            workload,
            command_sender,
            self.is_running.clone(),
            known_peers,
            node_state,
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