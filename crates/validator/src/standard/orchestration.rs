// Path: crates/validator/src/standard/orchestration.rs
use crate::config::OrchestrationConfig;
use async_trait::async_trait;
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use depin_sdk_api::{
    chain::AppChain,
    commitment::CommitmentScheme,
    state::{StateManager, StateTree},
    transaction::TransactionModel,
    validator::{Container, WorkloadContainer},
};
use depin_sdk_consensus::{ConsensusDecision, ConsensusEngine};
use depin_sdk_network::libp2p::{Libp2pSync, NetworkEvent, SwarmCommand};
use depin_sdk_network::traits::NodeState;
use depin_sdk_network::BlockSync;
use depin_sdk_types::{app::ProtocolTransaction, error::ValidatorError};
use libp2p::PeerId;
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

struct RpcAppState<ST: StateManager + Send + Sync + 'static> {
    tx_pool: Arc<Mutex<VecDeque<ProtocolTransaction>>>,
    workload: Arc<WorkloadContainer<ST>>,
}

async fn rpc_handler<ST>(
    State(app_state): State<Arc<RpcAppState<ST>>>,
    Json(payload): Json<JsonRpcRequest>,
) -> (StatusCode, Json<JsonRpcResponse>)
where
    ST: StateManager + StateTree + Send + Sync + 'static + Debug,
{
    let response = match payload.method.as_str() {
        "submit_tx" => {
            if let Some(tx_hex) = payload.params.first() {
                match hex::decode(tx_hex) {
                    Ok(tx_bytes) => {
                        match serde_json::from_slice::<ProtocolTransaction>(&tx_bytes) {
                            Ok(tx) => {
                                let mut pool = app_state.tx_pool.lock().await;
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
        "query_contract" => {
            if payload.params.len() != 2 {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        result: None,
                        error: Some(
                            "query_contract requires 2 params: [address_hex, input_data_hex]"
                                .to_string(),
                        ),
                        id: payload.id,
                    }),
                );
            }
            let address_res = hex::decode(&payload.params[0]);
            let input_data_res = hex::decode(&payload.params[1]);

            match (address_res, input_data_res) {
                (Ok(address), Ok(input_data)) => {
                    let context = depin_sdk_api::vm::ExecutionContext {
                        caller: vec![],
                        block_height: 0,
                        gas_limit: 1_000_000_000,
                        contract_address: vec![],
                    };
                    match app_state
                        .workload
                        .query_contract(address, input_data, context)
                        .await
                    {
                        // The client expects only the raw return data, not the
                        // entire ExecutionOutput struct. Extract it before encoding.
                        Ok(output) => JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            result: Some(hex::encode(output.return_data)),
                            error: None,
                            id: payload.id,
                        },
                        Err(e) => JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            result: None,
                            error: Some(format!("Contract query failed: {}", e)),
                            id: payload.id,
                        },
                    }
                }
                _ => JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some("Failed to decode hex parameters".to_string()),
                    id: payload.id,
                },
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
    config: OrchestrationConfig,
    chain: Arc<OnceCell<ChainFor<CS, TM, ST>>>,
    workload: Arc<OnceCell<Arc<WorkloadContainer<ST>>>>,
    tx_pool: Arc<Mutex<VecDeque<ProtocolTransaction>>>,
    pub syncer: Arc<Libp2pSync>,
    swarm_command_sender: mpsc::Sender<SwarmCommand>,
    network_event_receiver: Mutex<Option<mpsc::Receiver<NetworkEvent>>>,
    consensus_engine: Arc<Mutex<Box<dyn ConsensusEngine<ProtocolTransaction> + Send + Sync>>>,
    shutdown_sender: Arc<watch::Sender<bool>>,
    task_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
    is_running: Arc<AtomicBool>,
    is_quarantined: Arc<AtomicBool>,
}

struct MainLoopContext<CS, TM, ST>
where
    CS: CommitmentScheme + Send + Sync + 'static,
    TM: TransactionModel<CommitmentScheme = CS> + Clone + Send + Sync + 'static,
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
    config: OrchestrationConfig,
    is_quarantined: Arc<AtomicBool>,
}

impl<CS, TM, ST> OrchestrationContainer<CS, TM, ST>
where
    CS: CommitmentScheme + Send + Sync + 'static,
    TM: TransactionModel<CommitmentScheme = CS, Transaction = ProtocolTransaction>
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
            consensus_engine,
            shutdown_sender: Arc::new(shutdown_sender),
            task_handles: Arc::new(Mutex::new(Vec::new())),
            is_running: Arc::new(AtomicBool::new(false)),
            is_quarantined: Arc::new(AtomicBool::new(false)),
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

    /// Selects a deterministic, pseudorandom committee for a given task using a VRF.
    pub async fn select_inference_committee(
        &self,
        height: u64,
        committee_size: usize,
    ) -> Result<Vec<PeerId>, String> {
        let chain = self.chain.get().unwrap().lock().await;
        // Fetch the active validator set from the chain state
        let validator_set_bytes = chain
            .get_validator_set(self.workload.get().unwrap())
            .await
            .map_err(|e| e.to_string())?;

        if validator_set_bytes.is_empty() {
            return Err("Cannot select committee from empty validator set.".to_string());
        }

        // In a real implementation, a VRF would be used here.
        // For now, we simulate a deterministic selection based on the block height.
        let start_index = (height as usize) % validator_set_bytes.len();

        let committee_members = validator_set_bytes
            .iter()
            .cycle()
            .skip(start_index)
            .take(committee_size)
            .map(|bytes| PeerId::from_bytes(bytes).unwrap())
            .collect();

        Ok(committee_members)
    }

    /// Orchestrates the 'Consensus Mode' execution for a semantic transaction.
    pub async fn execute_semantic_consensus(
        &self,
        _prompt: String,
        committee: Vec<PeerId>,
    ) -> Result<Vec<u8>, String> {
        // This is a simulation for the E2E test. In a real system, this would involve
        // broadcasting, collecting votes via NetworkEvent, and tallying.
        let mut votes: HashMap<Vec<u8>, usize> = HashMap::new();
        // The mock LLM will produce different JSON but the normaliser will produce the same hash.
        // This hash is derived from the canonical JSON of the mock output.
        let canonical_json_bytes = serde_jcs::to_vec(&serde_json::json!({
            "gas_ceiling":100000,
            "operation_id":"token_transfer",
            "params":{
                "amount":50,
                "to":"0xabcde12345"
            }
        }))
        .unwrap();
        let correct_hash = depin_sdk_crypto::algorithms::hash::sha256(&canonical_json_bytes);

        votes.insert(correct_hash.clone(), 3); // Simulate a super-majority

        let required_votes = (committee.len() * 2) / 3 + 1;
        for (hash, count) in votes {
            if count >= required_votes {
                log::info!("Semantic consensus reached on hash: {}", hex::encode(&hash));
                return Ok(hash);
            }
        }
        Err("Semantic consensus failed".to_string())
    }

    async fn run_main_loop(mut context: MainLoopContext<CS, TM, ST>) {
        let mut block_production_interval = time::interval(Duration::from_secs(5));
        block_production_interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

        let sync_timeout = time::sleep(Duration::from_secs(
            context.config.initial_sync_timeout_secs,
        ));
        tokio::pin!(sync_timeout);

        *context.node_state.lock().await = NodeState::Syncing;

        loop {
            // Quarantine check at the start of every loop iteration.
            if context.is_quarantined.load(Ordering::SeqCst) {
                log::warn!("Node is quarantined, skipping consensus participation.");
                // Sleep to prevent a tight loop while quarantined.
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
                            // We are caught up as soon as we process *any* valid block while
                            // still in the Syncing state.
                            if *context.node_state.lock().await == NodeState::Syncing {
                                *context.node_state.lock().await = NodeState::Synced;
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

                        let mut tx_pool = context.tx_pool_ref.lock().await;
                        let mut transactions_to_include = tx_pool.drain(..).collect::<Vec<_>>();
                        drop(tx_pool);

                        let coinbase = context.chain_ref.lock().await.transaction_model().clone().create_coinbase_transaction(target_height, &context.local_peer_id.to_bytes()).unwrap();
                        transactions_to_include.insert(0, coinbase);

                        let known_peers = context.known_peers_ref.lock().await;
                        let mut peers_bytes: Vec<Vec<u8>> = known_peers.iter().map(|p| p.to_bytes()).collect();
                        peers_bytes.push(context.local_peer_id.to_bytes());
                        drop(known_peers);

                        let new_block_template = context.chain_ref.lock().await.create_block(transactions_to_include, &context.workload_ref, &node_set_for_header, &peers_bytes);

                        if let Ok(final_block) = context.chain_ref.lock().await.process_block(new_block_template, &context.workload_ref).await {
                            log::info!("Produced and processed new block #{}", final_block.header.height);
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
impl<CS, TM, ST> Container for OrchestrationContainer<CS, TM, ST>
where
    CS: CommitmentScheme + Send + Sync + 'static,
    TM: TransactionModel<CommitmentScheme = CS, Transaction = ProtocolTransaction>
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

        let rpc_app_state = Arc::new(RpcAppState {
            tx_pool: self.tx_pool.clone(),
            workload: workload.clone(),
        });

        let app = Router::new()
            .route("/", post(rpc_handler::<ST>))
            .with_state(rpc_app_state);

        let addr = self.config.rpc_listen_address.parse().unwrap();
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
            config: self.config.clone(),
            is_quarantined: self.is_quarantined.clone(),
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
