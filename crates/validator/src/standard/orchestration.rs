// Path: crates/validator/src/standard/orchestration.rs
use crate::config::OrchestrationConfig;
use async_trait::async_trait;
use depin_sdk_api::{
    chain::AppChain,
    commitment::CommitmentScheme,
    state::{StateCommitment, StateManager},
    transaction::TransactionModel,
    validator::{Container, WorkloadContainer},
};
use depin_sdk_consensus::{ConsensusDecision, ConsensusEngine};
use depin_sdk_crypto::algorithms::hash::sha256;
use depin_sdk_network::libp2p::{Libp2pSync, NetworkEvent, SwarmCommand};
use depin_sdk_network::traits::NodeState;
use depin_sdk_network::BlockSync;
use depin_sdk_transaction_models::unified::UnifiedTransactionModel;
use depin_sdk_types::{app::ChainTransaction, error::ValidatorError};
use libp2p::{identity, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Debug;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::{
    sync::{mpsc, watch, Mutex, OnceCell},
    task::JoinHandle,
    time::{self, Duration, Instant},
};

type ChainFor<CS, ST> = Arc<Mutex<dyn AppChain<CS, UnifiedTransactionModel<CS>, ST> + Send + Sync>>;

// NEW: State for tallying semantic consensus votes
#[derive(Debug)]
struct TallyState {
    votes: HashMap<Vec<u8>, Vec<PeerId>>, // Key: Vote Hash, Value: List of voters
    start_time: Instant,
}

pub struct OrchestrationContainer<CS, ST, CE>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
{
    config: OrchestrationConfig,
    chain: Arc<OnceCell<ChainFor<CS, ST>>>,
    workload: Arc<OnceCell<Arc<WorkloadContainer<ST>>>>,
    tx_pool: Arc<Mutex<VecDeque<ChainTransaction>>>,
    pub syncer: Arc<Libp2pSync>,
    swarm_command_sender: mpsc::Sender<SwarmCommand>,
    network_event_receiver: Mutex<Option<mpsc::Receiver<NetworkEvent>>>,
    consensus_engine: Arc<Mutex<CE>>,
    local_keypair: identity::Keypair,
    shutdown_sender: Arc<watch::Sender<bool>>,
    task_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
    is_running: Arc<AtomicBool>,
    is_quarantined: Arc<AtomicBool>,
    pending_consensus: Arc<Mutex<HashMap<String, TallyState>>>, // NEW
}

struct MainLoopContext<CS, ST, CE>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + StateCommitment<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug,
    CS::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
{
    chain_ref: Arc<Mutex<dyn AppChain<CS, UnifiedTransactionModel<CS>, ST> + Send + Sync>>,
    workload_ref: Arc<WorkloadContainer<ST>>,
    tx_pool_ref: Arc<Mutex<VecDeque<ChainTransaction>>>,
    network_event_receiver: mpsc::Receiver<NetworkEvent>,
    swarm_commander: mpsc::Sender<SwarmCommand>,
    shutdown_receiver: watch::Receiver<bool>,
    consensus_engine_ref: Arc<Mutex<CE>>,
    node_state: Arc<Mutex<NodeState>>,
    local_peer_id: PeerId,
    local_keypair: identity::Keypair,
    known_peers_ref: Arc<Mutex<HashSet<PeerId>>>,
    config: OrchestrationConfig,
    is_quarantined: Arc<AtomicBool>,
    pending_consensus: Arc<Mutex<HashMap<String, TallyState>>>, // NEW
}

impl<CS, ST, CE> OrchestrationContainer<CS, ST, CE>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + StateCommitment<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug,
    CS::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
{
    pub fn new(
        config_path: &std::path::Path,
        syncer: Arc<Libp2pSync>,
        network_event_receiver: mpsc::Receiver<NetworkEvent>,
        swarm_command_sender: mpsc::Sender<SwarmCommand>,
        consensus_engine: CE,
        local_keypair: identity::Keypair,
    ) -> anyhow::Result<Self> {
        let config: OrchestrationConfig = toml::from_str(&std::fs::read_to_string(config_path)?)?;
        let (shutdown_sender, _) = watch::channel(false);

        Ok(Self {
            config,
            chain: Arc::new(OnceCell::new()),
            workload: Arc::new(OnceCell::new()),
            tx_pool: Arc::new(Mutex::new(VecDeque::new())),
            syncer,
            swarm_command_sender,
            network_event_receiver: Mutex::new(Some(network_event_receiver)),
            consensus_engine: Arc::new(Mutex::new(consensus_engine)),
            local_keypair,
            shutdown_sender: Arc::new(shutdown_sender),
            task_handles: Arc::new(Mutex::new(Vec::new())),
            is_running: Arc::new(AtomicBool::new(false)),
            is_quarantined: Arc::new(AtomicBool::new(false)),
            pending_consensus: Arc::new(Mutex::new(HashMap::new())), // NEW
        })
    }

    pub fn set_chain_and_workload_ref(
        &self,
        chain_ref: Arc<Mutex<dyn AppChain<CS, UnifiedTransactionModel<CS>, ST> + Send + Sync>>,
        workload_ref: Arc<WorkloadContainer<ST>>,
    ) {
        self.chain.set(chain_ref).expect("Chain ref already set");
        self.workload
            .set(workload_ref)
            .expect("Workload ref already set");
    }

    pub async fn select_inference_committee(
        &self,
        height: u64,
        committee_size: usize,
    ) -> Result<Vec<PeerId>, String> {
        let chain = self.chain.get().unwrap().lock().await;
        let validator_set_bytes = chain
            .get_validator_set(self.workload.get().unwrap())
            .await
            .map_err(|e| e.to_string())?;

        if validator_set_bytes.is_empty() {
            return Err("Cannot select committee from empty validator set.".to_string());
        }

        let start_index = (height as usize) % validator_set_bytes.len();

        let committee_members = validator_set_bytes
            .iter()
            .cycle()
            .skip(start_index)
            .take(committee_size)
            .filter_map(|bytes| PeerId::from_bytes(bytes).ok())
            .collect();

        Ok(committee_members)
    }

    pub async fn execute_semantic_consensus(
        &self,
        prompt: String,
        committee: Vec<PeerId>,
    ) -> Result<Vec<u8>, String> {
        let prompt_hash_str = hex::encode(sha256(prompt.as_bytes()));

        // 1. Broadcast prompt to the committee
        self.swarm_command_sender
            .send(SwarmCommand::BroadcastToCommittee(
                committee.clone(),
                prompt,
            ))
            .await
            .map_err(|e| e.to_string())?;

        // 2. Initialize tally state
        let mut pending = self.pending_consensus.lock().await;
        pending.insert(
            prompt_hash_str.clone(),
            TallyState {
                votes: HashMap::new(),
                start_time: Instant::now(),
            },
        );
        drop(pending);

        // 3. Wait for consensus or timeout
        let consensus_timeout = Duration::from_secs(30);
        loop {
            // Check for timeout
            let pending = self.pending_consensus.lock().await;
            if let Some(tally) = pending.get(&prompt_hash_str) {
                if tally.start_time.elapsed() > consensus_timeout {
                    self.pending_consensus.lock().await.remove(&prompt_hash_str);
                    return Err("Semantic consensus timed out".to_string());
                }

                // Check for supermajority
                for (vote_hash, voters) in &tally.votes {
                    if voters.len() >= (committee.len() * 2 / 3) {
                        log::info!(
                            "Semantic consensus reached on hash: {}",
                            hex::encode(vote_hash)
                        );
                        self.pending_consensus.lock().await.remove(&prompt_hash_str);
                        return Ok(vote_hash.clone());
                    }
                }
            } else {
                // Tally state was removed, maybe by another thread that succeeded.
                return Err("Consensus process cancelled or already completed".to_string());
            }

            drop(pending);
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    async fn run_main_loop(mut context: MainLoopContext<CS, ST, CE>) {
        let mut block_production_interval = time::interval(Duration::from_secs(5));
        block_production_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

        let sync_timeout = time::sleep(Duration::from_secs(
            context.config.initial_sync_timeout_secs,
        ));
        tokio::pin!(sync_timeout);

        *context.node_state.lock().await = NodeState::Syncing;

        loop {
            if context.is_quarantined.load(Ordering::SeqCst) {
                log::warn!("Node is quarantined, skipping consensus participation.");
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }

            tokio::select! {
                biased;

                Some(event) = context.network_event_receiver.recv() => {
                    match event {
                        NetworkEvent::ConnectionEstablished(peer_id) => {
                            context.known_peers_ref.lock().await.insert(peer_id);
                            context.swarm_commander.send(SwarmCommand::SendStatusRequest(peer_id)).await.ok();
                        }
                        NetworkEvent::ConnectionClosed(peer_id) => {
                            context.known_peers_ref.lock().await.remove(&peer_id);
                        }
                        NetworkEvent::GossipBlock(block) => {
                            let mut chain = context.chain_ref.lock().await;
                            if let Err(e) = chain.process_block(block, &context.workload_ref).await {
                                log::warn!("[Orchestrator] Failed to process gossiped block: {e:?}");
                            }
                            if *context.node_state.lock().await == NodeState::Syncing {
                                *context.node_state.lock().await = NodeState::Synced;
                            }
                        },
                        NetworkEvent::GossipTransaction(tx) => {
                            let mut pool = context.tx_pool_ref.lock().await;
                            pool.push_back(tx);
                            log::info!("[Orchestrator] Received transaction via gossip. Pool size: {}", pool.len());
                        }
                        NetworkEvent::StatusRequest(_peer, channel) => {
                            let height = context.chain_ref.lock().await.status().height;
                            context.swarm_commander.send(SwarmCommand::SendStatusResponse(channel, height)).await.ok();
                        }
                        NetworkEvent::BlocksRequest(_, since, channel) => {
                            let blocks = context.chain_ref.lock().await.get_blocks_since(since);
                            context.swarm_commander.send(SwarmCommand::SendBlocksResponse(channel, blocks)).await.ok();
                        }
                        NetworkEvent::StatusResponse(peer, peer_height) => {
                            let our_height = context.chain_ref.lock().await.status().height;
                            if peer_height > our_height {
                                context.swarm_commander.send(SwarmCommand::SendBlocksRequest(peer, our_height)).await.ok();
                            } else if *context.node_state.lock().await == NodeState::Syncing {
                                *context.node_state.lock().await = NodeState::Synced;
                            }
                        }
                        NetworkEvent::BlocksResponse(_, blocks) => {
                            let mut chain = context.chain_ref.lock().await;
                            for block in blocks {
                                if chain.process_block(block, &context.workload_ref).await.is_err() {
                                    break;
                                }
                            }
                            if *context.node_state.lock().await == NodeState::Syncing {
                                *context.node_state.lock().await = NodeState::Synced;
                            }
                        }
                        NetworkEvent::SemanticPrompt { from, prompt } => {
                            log::info!("[Orchestrator] Received SemanticPrompt from peer {}: '{}'", from, prompt);
                        }
                        // FIX: Add the missing match arm
                        NetworkEvent::SemanticConsensusVote { from, prompt_hash, vote_hash } => {
                            let mut pending = context.pending_consensus.lock().await;
                            if let Some(tally) = pending.get_mut(&prompt_hash) {
                                log::info!("[Orchestrator] Tallying vote from {} for prompt hash {}", from, prompt_hash);
                                tally.votes.entry(vote_hash).or_default().push(from);
                            } else {
                                log::warn!("[Orchestrator] Received vote for unknown/expired consensus round: {}", prompt_hash);
                            }
                        }
                    }
                    continue;
                }

                _ = &mut sync_timeout, if *context.node_state.lock().await == NodeState::Syncing => {
                    if context.known_peers_ref.lock().await.is_empty() {
                         log::info!("[Orchestrator] No peers found after timeout. Assuming genesis node. State -> Synced.");
                        *context.node_state.lock().await = NodeState::Synced;
                    }
                },

                _ = block_production_interval.tick() => {
                    if *context.node_state.lock().await != NodeState::Synced {
                        continue;
                    }

                    let (decision, node_set_for_header) = {
                        let chain = context.chain_ref.lock().await;
                        let target_height = chain.status().height + 1;
                        let current_view = 0;

                        let (consensus_data, header_data) = if cfg!(feature = "consensus-pos") {
                            let stakers = chain.get_staked_validators(&context.workload_ref).await.unwrap_or_default();
                            let header_peer_ids = stakers.iter()
                                .filter(|(_, &stake)| stake > 0)
                                .filter_map(|(id_b58, _)| id_b58.parse::<PeerId>().ok())
                                .map(|id| id.to_bytes())
                                .collect();
                            let consensus_blob = vec![serde_json::to_vec(&stakers).unwrap_or_default()];
                            (consensus_blob, header_peer_ids)
                        } else if cfg!(feature = "consensus-poa") {
                            let authorities = chain.get_authority_set(&context.workload_ref).await.unwrap_or_else(|e| {
                                log::error!("Could not get authority set for consensus: {e:?}");
                                vec![]
                            });
                            (authorities.clone(), authorities)
                        } else {
                            let validators = chain.get_validator_set(&context.workload_ref).await.unwrap_or_else(|e| {
                                log::error!("Could not get validator set for consensus: {e:?}");
                                vec![]
                            });
                            (validators.clone(), validators)
                        };

                        let mut engine = context.consensus_engine_ref.lock().await;
                        let known_peers = context.known_peers_ref.lock().await;
                        let decision = engine.decide(&context.local_peer_id, target_height, current_view, &consensus_data, &known_peers).await;
                        (decision, header_data)
                    };

                    if let ConsensusDecision::ProduceBlock(_) = decision {
                        let target_height = context.chain_ref.lock().await.status().height + 1;
                        log::info!("Consensus decision: Produce block for height {target_height}.");

                        let mut transactions_to_include = context.tx_pool_ref.lock().await.drain(..).collect::<Vec<_>>();

                        let coinbase = context.chain_ref.lock().await.transaction_model().clone().create_coinbase_transaction(target_height, &context.local_peer_id.to_bytes()).unwrap();
                        transactions_to_include.insert(0, coinbase);

                        let known_peers = context.known_peers_ref.lock().await;
                        let mut peers_bytes: Vec<Vec<u8>> = known_peers.iter().map(|p| p.to_bytes()).collect();
                        peers_bytes.push(context.local_peer_id.to_bytes());
                        drop(known_peers);

                        let new_block_template = context.chain_ref.lock().await.create_block(
                            transactions_to_include,
                            &node_set_for_header,
                            &peers_bytes,
                            &context.local_keypair,
                        );

                        if let Ok((mut final_block, new_validator_set)) = context.chain_ref.lock().await.process_block(new_block_template, &context.workload_ref).await {
                            log::info!("Produced and processed new block #{}", final_block.header.height);

                             // Update the block header with the *new* validator set before signing
                            final_block.header.validator_set = new_validator_set;
                            let header_hash = final_block.header.hash();
                            final_block.header.signature = context.local_keypair.sign(&header_hash).unwrap();

                            let data = serde_json::to_vec(&final_block).unwrap();
                            context.swarm_commander.send(SwarmCommand::PublishBlock(data)).await.ok();
                            context.consensus_engine_ref.lock().await.reset(final_block.header.height);
                        }
                    }
                }

                _ = context.shutdown_receiver.changed() => {
                    if *context.shutdown_receiver.borrow() {
                        log::info!("Orchestration main loop received shutdown signal.");
                        break;
                    }
                }
            }
        }
        log::info!("Orchestration main loop finished.");
    }
}

#[async_trait]
impl<CS, ST, CE> Container for OrchestrationContainer<CS, ST, CE>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + StateCommitment<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug,
    CS::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
{
    fn id(&self) -> &'static str {
        "orchestration_container"
    }
    fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }

    async fn start(&self) -> Result<(), ValidatorError> {
        if self.is_running() {
            return Err(ValidatorError::AlreadyRunning(self.id().to_string()));
        }
        log::info!("OrchestrationContainer starting...");

        self.syncer
            .start()
            .await
            .map_err(|e| ValidatorError::Other(e.to_string()))?;

        let chain = self
            .chain
            .get()
            .ok_or_else(|| {
                ValidatorError::Other("Chain ref not initialized before start".to_string())
            })?
            .clone();
        let workload = self
            .workload
            .get()
            .ok_or_else(|| {
                ValidatorError::Other("Workload ref not initialized before start".to_string())
            })?
            .clone();

        let mut receiver_opt = self.network_event_receiver.lock().await;
        let receiver = receiver_opt.take().ok_or(ValidatorError::Other(
            "Network event receiver already taken".to_string(),
        ))?;

        let context = MainLoopContext::<CS, ST, CE> {
            chain_ref: chain,
            workload_ref: workload,
            tx_pool_ref: self.tx_pool.clone(),
            network_event_receiver: receiver,
            swarm_commander: self.swarm_command_sender.clone(),
            shutdown_receiver: self.shutdown_sender.subscribe(),
            consensus_engine_ref: self.consensus_engine.clone(),
            node_state: self.syncer.get_node_state(),
            local_peer_id: self.syncer.get_local_peer_id(),
            local_keypair: self.local_keypair.clone(),
            known_peers_ref: self.syncer.get_known_peers(),
            config: self.config.clone(),
            is_quarantined: self.is_quarantined.clone(),
            pending_consensus: self.pending_consensus.clone(), // NEW
        };

        let mut handles = self.task_handles.lock().await;
        handles.push(tokio::spawn(Self::run_main_loop(context)));

        self.is_running.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn stop(&self) -> Result<(), ValidatorError> {
        if !self.is_running() {
            return Ok(());
        }
        log::info!("OrchestrationContainer stopping...");
        self.shutdown_sender.send(true).ok();

        tokio::time::sleep(Duration::from_millis(100)).await;

        self.is_running.store(false, Ordering::SeqCst);

        self.syncer
            .stop()
            .await
            .map_err(|e| ValidatorError::Other(e.to_string()))?;

        let mut handles = self.task_handles.lock().await;
        for handle in handles.drain(..) {
            handle
                .await
                .map_err(|e| ValidatorError::Other(format!("Task panicked: {e}")))?;
        }
        Ok(())
    }
}
