// Path: crates/validator/src/standard/orchestration.rs
use crate::config::OrchestrationConfig;
use async_trait::async_trait;
use depin_sdk_api::{
    chain::AppChain,
    commitment::CommitmentScheme,
    state::{StateCommitment, StateManager},
    transaction::TransactionModel,
    validator::Container,
};
use depin_sdk_client::WorkloadClient;
use depin_sdk_commitment::primitives::hash::HashCommitmentScheme;
use depin_sdk_consensus::{ConsensusDecision, ConsensusEngine};
use depin_sdk_network::libp2p::{Libp2pSync, NetworkEvent, SwarmCommand};
use depin_sdk_network::traits::NodeState;
use depin_sdk_network::BlockSync;
use depin_sdk_transaction_models::unified::UnifiedTransactionModel;
use depin_sdk_types::{
    app::{Block, BlockHeader, ChainTransaction},
    error::ValidatorError,
};
use libp2p::{identity, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::fmt::Debug;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::{
    sync::{mpsc, watch, Mutex, OnceCell},
    task::JoinHandle,
    time::{self, Duration},
};

type ChainFor<CS, ST> = Arc<Mutex<dyn AppChain<CS, UnifiedTransactionModel<CS>, ST> + Send + Sync>>;

/// Main state for the Orchestration Container's event loop.
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
    chain_ref: ChainFor<CS, ST>,
    workload_client: Arc<WorkloadClient>,
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
    workload_client: Arc<OnceCell<Arc<WorkloadClient>>>,
    pub tx_pool: Arc<Mutex<VecDeque<ChainTransaction>>>,
    pub syncer: Arc<Libp2pSync>,
    swarm_command_sender: mpsc::Sender<SwarmCommand>,
    network_event_receiver: Mutex<Option<mpsc::Receiver<NetworkEvent>>>,
    consensus_engine: Arc<Mutex<CE>>,
    local_keypair: identity::Keypair,
    shutdown_sender: Arc<watch::Sender<bool>>,
    task_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
    is_running: Arc<AtomicBool>,
    is_quarantined: Arc<AtomicBool>,
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
        is_quarantined: Arc<AtomicBool>,
    ) -> anyhow::Result<Self> {
        let config: OrchestrationConfig = toml::from_str(&std::fs::read_to_string(config_path)?)?;
        let (shutdown_sender, _) = watch::channel(false);

        Ok(Self {
            config,
            chain: Arc::new(OnceCell::new()),
            workload_client: Arc::new(OnceCell::new()),
            tx_pool: Arc::new(Mutex::new(VecDeque::new())),
            syncer,
            swarm_command_sender,
            network_event_receiver: Mutex::new(Some(network_event_receiver)),
            consensus_engine: Arc::new(Mutex::new(consensus_engine)),
            local_keypair,
            shutdown_sender: Arc::new(shutdown_sender),
            task_handles: Arc::new(Mutex::new(Vec::new())),
            is_running: Arc::new(AtomicBool::new(false)),
            is_quarantined,
        })
    }

    pub fn set_chain_and_workload_client(
        &self,
        chain_ref: ChainFor<CS, ST>,
        workload_client_ref: Arc<WorkloadClient>,
    ) {
        self.chain.set(chain_ref).expect("Chain ref already set");
        self.workload_client
            .set(workload_client_ref)
            .expect("Workload client ref already set");
    }

    async fn run_main_loop(mut context: MainLoopContext<CS, ST, CE>) {
        let mut block_production_interval = time::interval(Duration::from_secs(5));
        block_production_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

        let sync_timeout = time::sleep(Duration::from_secs(
            context.config.initial_sync_timeout_secs,
        ));
        tokio::pin!(sync_timeout);

        *context.node_state.lock().await = NodeState::Syncing;
        log::info!("[Orchestrator] State -> Syncing.");

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
                            log::info!("[Orchestrator] Connection established with peer {}", peer_id);
                            context.known_peers_ref.lock().await.insert(peer_id);
                            context.swarm_commander.send(SwarmCommand::SendStatusRequest(peer_id)).await.ok();
                        }
                        NetworkEvent::ConnectionClosed(peer_id) => {
                            context.known_peers_ref.lock().await.remove(&peer_id);
                        }
                        NetworkEvent::GossipBlock(block) => {
                             let block_height = block.header.height;
                             log::info!("[Orchestrator] Received gossiped block #{}. Verifying...", block_height);

                             let mut engine = context.consensus_engine_ref.lock().await;
                             let mut chain = context.chain_ref.lock().await;

                             if let Err(e) = engine.handle_block_proposal(block.clone(), &mut *chain, &context.workload_client).await {
                                 log::warn!("[Orchestrator] Invalid gossiped block #{}: {}", block_height, e);
                                 continue;
                             }
                             drop(engine);
                             drop(chain);

                             log::info!("[Orchestrator] Block #{} is valid. Forwarding to workload...", block_height);
                             if let Err(e) = context.workload_client.process_block(block).await {
                                  log::error!("[Orchestrator] Workload failed to process gossiped block #{}: {}", block_height, e);
                             } else {
                                 log::info!("[Orchestrator] Workload processed block successfully.");
                                 if *context.node_state.lock().await == NodeState::Syncing {
                                     *context.node_state.lock().await = NodeState::Synced;
                                      log::info!("[Orchestrator] State -> Synced.");
                                 }
                             }
                        },
                        NetworkEvent::GossipTransaction(tx) => {
                            let mut pool = context.tx_pool_ref.lock().await;
                            pool.push_back(tx);
                            log::info!("[Orchestrator] Received transaction via gossip. Pool size: {}", pool.len());
                        }
                        NetworkEvent::StatusRequest(_peer, channel) => {
                            let height = context.workload_client.get_status().await.map_or(0, |s| s.height);
                            context.swarm_commander.send(SwarmCommand::SendStatusResponse(channel, height)).await.ok();
                        }
                        NetworkEvent::BlocksRequest(_, since, channel) => {
                            let blocks = context.chain_ref.lock().await.get_blocks_since(since);
                            context.swarm_commander.send(SwarmCommand::SendBlocksResponse(channel, blocks)).await.ok();
                        }
                        NetworkEvent::StatusResponse(peer, peer_height) => {
                            let our_height = context.workload_client.get_status().await.map_or(0, |s| s.height);
                            if peer_height > our_height {
                                context.swarm_commander.send(SwarmCommand::SendBlocksRequest(peer, our_height)).await.ok();
                            } else if *context.node_state.lock().await == NodeState::Syncing {
                                *context.node_state.lock().await = NodeState::Synced;
                                log::info!("[Orchestrator] Synced with peer {}. State -> Synced.", peer);
                            }
                        }
                        NetworkEvent::BlocksResponse(_, blocks) => {
                            for block in blocks {
                                if context.workload_client.process_block(block).await.is_err() {
                                    log::error!("[Orchestrator] Workload failed to process synced block.");
                                    break;
                                }
                            }
                            if *context.node_state.lock().await == NodeState::Syncing {
                                *context.node_state.lock().await = NodeState::Synced;
                                log::info!("[Orchestrator] Finished processing blocks. State -> Synced.");
                            }
                        }
                        _ => {}
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

                    let decision = {
                        let mut engine = context.consensus_engine_ref.lock().await;
                        let known_peers = context.known_peers_ref.lock().await;

                        let target_height = context.workload_client.get_status().await.map_or(0, |s| s.height) + 1;
                        let current_view = 0;

                        let consensus_data = match engine.get_validator_data(&context.workload_client).await {
                             Ok(data) => data,
                             Err(e) => { log::error!("[Orch] Could not get validator data for consensus: {e}"); continue; }
                        };

                        engine.decide(
                            &context.local_peer_id,
                            target_height,
                            current_view,
                            &consensus_data,
                            &known_peers,
                        ).await
                    };

                    if let ConsensusDecision::ProduceBlock(_) = decision {
                        let target_height = context.workload_client.get_status().await.map_or(0, |s| s.height) + 1;
                        log::info!("Consensus decision: Produce block for height {target_height}.");

                        let header_data = match context.workload_client.get_validator_set().await {
                            Ok(data) => data,
                            Err(e) => { log::error!("[Orch] Could not get validator set for block header: {e}"); continue; }
                        };

                        let mut transactions_to_include = context.tx_pool_ref.lock().await.drain(..).collect::<Vec<_>>();
                        let coinbase = UnifiedTransactionModel::new(HashCommitmentScheme::new()).create_coinbase_transaction(target_height, &context.local_peer_id.to_bytes()).unwrap();
                        transactions_to_include.insert(0, coinbase);

                        let prev_hash = context
                            .workload_client
                            .get_last_block_hash()
                            .await
                            .unwrap_or_else(|_| vec![0; 32]);

                        let new_block_template = Block {
                            header: BlockHeader {
                                height: target_height,
                                prev_hash,
                                state_root: vec![],
                                transactions_root: vec![0; 32],
                                timestamp: SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs(),
                                validator_set: header_data,
                                producer: context.local_keypair.public().encode_protobuf(),
                                signature: vec![],
                            },
                            transactions: transactions_to_include,
                        };

                        match context.workload_client.process_block(new_block_template).await {
                            Ok((mut final_block, _)) => {
                                log::info!("Produced and processed new block #{}", final_block.header.height);
                                let header_hash = final_block.header.hash();
                                final_block.header.signature = context.local_keypair.sign(&header_hash).unwrap();
                                let data = serde_json::to_vec(&final_block).unwrap();
                                context.swarm_commander.send(SwarmCommand::PublishBlock(data)).await.ok();
                                context.consensus_engine_ref.lock().await.reset(final_block.header.height);

                                if let Ok(outcomes) = context.workload_client.check_and_tally_proposals(final_block.header.height).await {
                                    for outcome in outcomes { log::info!("{}", outcome); }
                                }
                            },
                            Err(e) => log::error!("Workload failed to process new block: {}", e),
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
        let workload_client = self
            .workload_client
            .get()
            .ok_or_else(|| {
                ValidatorError::Other(
                    "Workload client ref not initialized before start".to_string(),
                )
            })?
            .clone();

        let mut receiver_opt = self.network_event_receiver.lock().await;
        let receiver = receiver_opt.take().ok_or(ValidatorError::Other(
            "Network event receiver already taken".to_string(),
        ))?;

        let context = MainLoopContext::<CS, ST, CE> {
            chain_ref: chain,
            workload_client,
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
