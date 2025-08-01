// Path: crates/validator/src/standard/orchestration.rs

use crate::config::OrchestrationConfig;
use async_trait::async_trait;
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use depin_sdk_consensus::{ConsensusDecision, ConsensusEngine};
use depin_sdk_core::app::{ApplicationTransaction, ProtocolTransaction, UTXOTransaction};
use depin_sdk_core::{
    chain::AppChain,
    commitment::CommitmentScheme,
    error::ValidatorError,
    state::{StateManager, StateTree},
    transaction::TransactionModel,
    validator::{Container, WorkloadContainer},
};
use depin_sdk_network::libp2p::{Libp2pSync, NetworkEvent, SwarmCommand};
use depin_sdk_network::traits::NodeState;
use depin_sdk_network::BlockSync;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::fmt::Debug;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::{
    sync::{mpsc, watch, Mutex, OnceCell},
    task::JoinHandle,
    time::{self, Duration},
};

#[derive(Deserialize, Debug)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    method: String,
    params: Vec<String>,
    id: u64,
}

#[derive(Serialize, Debug)]
struct JsonRpcResponse {
    jsonrpc: String,
    result: Option<String>,
    error: Option<String>,
    id: u64,
}

async fn rpc_handler(
    State(app_state): State<Arc<Mutex<VecDeque<ProtocolTransaction>>>>,
    Json(payload): Json<JsonRpcRequest>,
) -> (StatusCode, Json<JsonRpcResponse>) {
    let response = match payload.method.as_str() {
        "submit_tx" => {
            if let Some(tx_hex) = payload.params.first() {
                match hex::decode(tx_hex) {
                    Ok(tx_bytes) => {
                        match serde_json::from_slice::<ProtocolTransaction>(&tx_bytes) {
                            Ok(tx) => {
                                let mut pool = app_state.lock().await;
                                pool.push_back(tx);
                                log::info!(
                                    "Accepted transaction into pool. Pool size: {}",
                                    pool.len()
                                );
                                JsonRpcResponse {
                                    jsonrpc: "2.0".to_string(),
                                    result: Some("Transaction accepted".to_string()),
                                    error: None,
                                    id: payload.id,
                                }
                            }
                            Err(e) => JsonRpcResponse {
                                jsonrpc: "2.0".to_string(),
                                result: None,
                                error: Some(format!("Failed to deserialize transaction: {e}")),
                                id: payload.id,
                            },
                        }
                    }
                    Err(e) => JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        result: None,
                        error: Some(format!("Invalid hex in transaction: {e}")),
                        id: payload.id,
                    },
                }
            } else {
                JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some("Missing transaction parameter".to_string()),
                    id: payload.id,
                }
            }
        }
        _ => JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(format!("Method '{}' not found", payload.method)),
            id: payload.id,
        },
    };
    (StatusCode::OK, Json(response))
}

type ChainFor<CS, TM, ST> = Arc<Mutex<dyn AppChain<CS, TM, ST> + Send + Sync>>;

pub struct OrchestrationContainer<CS, TM, ST>
where
    CS: CommitmentScheme + Send + Sync + 'static,
    TM: TransactionModel<CommitmentScheme = CS> + Clone + Send + Sync + 'static,
    TM::Transaction: Clone + Debug + Send + Sync,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug,
{
    _config: OrchestrationConfig,
    chain: Arc<OnceCell<ChainFor<CS, TM, ST>>>,
    workload: Arc<OnceCell<Arc<WorkloadContainer<ST>>>>,
    tx_pool: Arc<Mutex<VecDeque<ProtocolTransaction>>>,
    syncer: Arc<Libp2pSync>,
    swarm_command_sender: mpsc::Sender<SwarmCommand>,
    network_event_receiver: Mutex<Option<mpsc::Receiver<NetworkEvent>>>,
    consensus_engine: Arc<Mutex<Box<dyn ConsensusEngine<ProtocolTransaction> + Send + Sync>>>,
    shutdown_sender: Arc<watch::Sender<bool>>,
    task_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
    is_running: Arc<AtomicBool>,
}

struct MainLoopContext<CS, TM, ST>
where
    CS: CommitmentScheme + Send + Sync + 'static,
    TM: TransactionModel<CommitmentScheme = CS, Transaction = UTXOTransaction>
        + Clone
        + Send
        + Sync
        + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + StateTree<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug,
    CS::Commitment: Send + Sync + Debug,
{
    chain_ref: Arc<Mutex<dyn AppChain<CS, TM, ST> + Send + Sync>>,
    workload_ref: Arc<WorkloadContainer<ST>>,
    tx_pool_ref: Arc<Mutex<VecDeque<ProtocolTransaction>>>,
    network_event_receiver: mpsc::Receiver<NetworkEvent>,
    swarm_commander: mpsc::Sender<SwarmCommand>,
    shutdown_receiver: watch::Receiver<bool>,
    consensus_engine_ref: Arc<Mutex<Box<dyn ConsensusEngine<ProtocolTransaction> + Send + Sync>>>,
    node_state: Arc<Mutex<NodeState>>,
    local_peer_id: PeerId,
    known_peers_ref: Arc<Mutex<HashSet<PeerId>>>,
}

impl<CS, TM, ST> OrchestrationContainer<CS, TM, ST>
where
    CS: CommitmentScheme + Send + Sync + 'static,
    TM: TransactionModel<CommitmentScheme = CS, Transaction = UTXOTransaction>
        + Clone
        + Send
        + Sync
        + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + StateTree<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug,
    CS::Commitment: Send + Sync + Debug,
{
    pub fn new(
        config_path: &std::path::Path,
        syncer: Arc<Libp2pSync>,
        network_event_receiver: mpsc::Receiver<NetworkEvent>,
        swarm_command_sender: mpsc::Sender<SwarmCommand>,
        consensus_engine: Arc<Mutex<Box<dyn ConsensusEngine<ProtocolTransaction> + Send + Sync>>>,
    ) -> anyhow::Result<Self> {
        let _config: OrchestrationConfig = toml::from_str(&std::fs::read_to_string(config_path)?)?;
        let (shutdown_sender, _) = watch::channel(false);

        Ok(Self {
            _config,
            chain: Arc::new(OnceCell::new()),
            workload: Arc::new(OnceCell::new()),
            tx_pool: Arc::new(Mutex::new(VecDeque::new())),
            syncer,
            swarm_command_sender,
            network_event_receiver: Mutex::new(Some(network_event_receiver)),
            consensus_engine,
            shutdown_sender: Arc::new(shutdown_sender),
            task_handles: Arc::new(Mutex::new(Vec::new())),
            is_running: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn set_chain_and_workload_ref(
        &self,
        chain_ref: Arc<Mutex<dyn AppChain<CS, TM, ST> + Send + Sync>>,
        workload_ref: Arc<WorkloadContainer<ST>>,
    ) {
        self.chain.set(chain_ref).expect("Chain ref already set");
        self.workload
            .set(workload_ref)
            .expect("Workload ref already set");
    }

    async fn run_main_loop(mut context: MainLoopContext<CS, TM, ST>) {
        let mut block_production_interval = time::interval(Duration::from_secs(5));
        block_production_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

        let sync_timeout = time::sleep(Duration::from_secs(5));
        tokio::pin!(sync_timeout);

        *context.node_state.lock().await = NodeState::Syncing;

        loop {
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
                        },
                        NetworkEvent::GossipTransaction(tx) => {
                            let mut pool = context.tx_pool_ref.lock().await;
                            // In a real implementation, we would validate the tx before adding it.
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

                    let (decision, node_set_for_block) = {
                        let chain = context.chain_ref.lock().await;
                        let target_height = chain.status().height + 1;
                        let current_view = 0;

                        // NEW: Conditionally fetch the correct validator set based on the compiled consensus engine.
                        let node_set_bytes = if cfg!(feature = "consensus-poa") {
                            // For PoA, the node set is the list of authority PeerIDs.
                            chain.get_authority_set(&context.workload_ref).await.unwrap_or_else(|e| {
                                log::error!("Could not get authority set for consensus: {e:?}");
                                vec![]
                            })
                        } else if cfg!(feature = "consensus-pos") {
                            // For PoS, we fetch the map of stakers and serialize it.
                            // The PoS engine expects this serialized map as its `validator_set`.
                            let stakers = chain.get_staked_validators(&context.workload_ref).await.unwrap_or_default();
                            // We wrap it in a Vec to match the function signature. A more robust solution
                            // would be a dedicated enum `NodeSetType`.
                            vec![serde_json::to_vec(&stakers).unwrap_or_default()]
                        } else {
                            // Fallback for other consensus types like RoundRobin
                            chain.get_validator_set(&context.workload_ref).await.unwrap_or_else(|e| {
                                log::error!("Could not get validator set for consensus: {e:?}");
                                vec![]
                            })
                        };

                        let mut engine = context.consensus_engine_ref.lock().await;
                        let known_peers = context.known_peers_ref.lock().await;
                        let decision = engine.decide(&context.local_peer_id, target_height, current_view, &node_set_bytes, &known_peers).await;
                        (decision, node_set_bytes)
                    };

                    // Use the fetched node set when creating the block.
                    if let ConsensusDecision::ProduceBlock(_) = decision {
                        let target_height = context.chain_ref.lock().await.status().height + 1;
                        log::info!("Consensus decision: Produce block for height {target_height}.");

                        let mut tx_pool = context.tx_pool_ref.lock().await;
                        let mut transactions_to_include = tx_pool.drain(..).collect::<Vec<_>>();
                        drop(tx_pool);

                        let coinbase = context.chain_ref.lock().await.transaction_model().clone().create_coinbase_transaction(target_height, &context.local_peer_id.to_bytes()).unwrap();
                        transactions_to_include.insert(0, ProtocolTransaction::Application(ApplicationTransaction::UTXO(coinbase)));

                        let known_peers = context.known_peers_ref.lock().await;
                        let mut peers_bytes: Vec<Vec<u8>> = known_peers.iter().map(|p| p.to_bytes()).collect();
                        peers_bytes.push(context.local_peer_id.to_bytes());
                        drop(known_peers);

                        // Pass the correct node set (authorities or serialized stakers) to `create_block`.
                        let new_block_template = context.chain_ref.lock().await.create_block(transactions_to_include, &context.workload_ref, &node_set_for_block, &peers_bytes);

                        if let Ok(final_block) = context.chain_ref.lock().await.process_block(new_block_template, &context.workload_ref).await {
                            log::info!("Produced and processed new block #{}", final_block.header.height);
                            let data = serde_json::to_vec(&final_block).unwrap();
                            context.swarm_commander.send(SwarmCommand::PublishBlock(data)).await.ok();
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
impl<CS, TM, ST> Container for OrchestrationContainer<CS, TM, ST>
where
    CS: CommitmentScheme + Send + Sync + 'static,
    TM: TransactionModel<CommitmentScheme = CS, Transaction = UTXOTransaction>
        + Clone
        + Send
        + Sync
        + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + StateTree<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug,
    CS::Commitment: Send + Sync + Debug,
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

        let tx_pool_for_rpc = self.tx_pool.clone();
        let app = Router::new()
            .route("/", post(rpc_handler))
            .with_state(tx_pool_for_rpc);

        let addr = self._config.rpc_listen_address.parse().unwrap();
        log::info!("RPC server listening on {}", addr);

        let mut shutdown_rx = self.shutdown_sender.subscribe();
        let rpc_server_handle = tokio::spawn(async move {
            axum::Server::bind(&addr)
                .serve(app.into_make_service())
                .with_graceful_shutdown(async {
                    shutdown_rx.changed().await.ok();
                    log::info!("RPC server shutting down.");
                })
                .await
                .unwrap();
        });

        let mut handles = self.task_handles.lock().await;
        handles.push(rpc_server_handle);

        let mut receiver_opt = self.network_event_receiver.lock().await;
        let receiver = receiver_opt.take().ok_or(ValidatorError::Other(
            "Network event receiver already taken".to_string(),
        ))?;

        let context = MainLoopContext::<CS, TM, ST> {
            chain_ref: chain,
            workload_ref: workload,
            tx_pool_ref: self.tx_pool.clone(),
            network_event_receiver: receiver,
            swarm_commander: self.swarm_command_sender.clone(),
            shutdown_receiver: self.shutdown_sender.subscribe(),
            consensus_engine_ref: self.consensus_engine.clone(),
            node_state: self.syncer.get_node_state(),
            local_peer_id: self.syncer.get_local_peer_id(),
            known_peers_ref: self.syncer.get_known_peers(),
        };

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
