// Path: crates/validator/src/standard/orchestration.rs
use crate::config::OrchestrationConfig;
use async_trait::async_trait;
use bs58;
use depin_sdk_api::{
    chain::AppChain,
    commitment::CommitmentScheme,
    state::{StateCommitment, StateManager},
    transaction::TransactionModel,
    validator::Container,
};
use depin_sdk_client::WorkloadClient;
use depin_sdk_consensus::{ConsensusDecision, ConsensusEngine};
use depin_sdk_network::libp2p::{Libp2pSync, NetworkEvent, SwarmCommand};
use depin_sdk_network::traits::NodeState;
use depin_sdk_network::BlockSync;
use depin_sdk_services::external_data::ExternalDataService;
use depin_sdk_transaction_models::unified::UnifiedTransactionModel;
use depin_sdk_types::{
    app::{
        Block, BlockHeader, ChainTransaction, OracleAttestation, OracleConsensusProof, StateEntry,
        SystemPayload, SystemTransaction,
    },
    error::ValidatorError,
    keys::ORACLE_PENDING_REQUEST_PREFIX,
};
use libp2p::identity::PublicKey as Libp2pPublicKey;
use libp2p::{identity, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
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
    external_data_service: ExternalDataService,
    pending_attestations: HashMap<u64, Vec<OracleAttestation>>,
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
    external_data_service: ExternalDataService,
}

impl<CS, ST, CE> OrchestrationContainer<CS, ST, CE>
where
    CS: CommitmentScheme + Clone + Default + Send + Sync + 'static,
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
            external_data_service: ExternalDataService::new(),
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
                             match context.workload_client.process_block(block).await {
                                Ok((processed_block, _)) => {
                                    log::info!("[Orchestrator] Workload processed block successfully.");

                                    let mut pool = context.tx_pool_ref.lock().await;

                                    let block_txs_canonical: HashSet<Vec<u8>> = processed_block
                                        .transactions
                                        .iter()
                                        .map(|tx| serde_jcs::to_vec(tx).unwrap())
                                        .collect();

                                    let finalized_oracle_ids: HashSet<u64> = processed_block.transactions.iter().filter_map(|tx| {
                                        if let ChainTransaction::System(SystemTransaction { payload: SystemPayload::SubmitOracleData { request_id, .. }, .. }) = tx {
                                            Some(*request_id)
                                        } else {
                                            None
                                        }
                                    }).collect();

                                    let original_size = pool.len();
                                    pool.retain(|tx_in_pool| {
                                        let tx_in_pool_canonical = serde_jcs::to_vec(tx_in_pool).unwrap();
                                        if block_txs_canonical.contains(&tx_in_pool_canonical) {
                                            return false;
                                        }

                                        if let ChainTransaction::System(SystemTransaction { payload: SystemPayload::SubmitOracleData { request_id, .. }, .. }) = tx_in_pool {
                                            if finalized_oracle_ids.contains(request_id) {
                                                return false;
                                            }
                                        }

                                        true
                                    });

                                    let new_size = pool.len();
                                    if new_size < original_size {
                                        log::info!("[Orchestrator] Pruned {} transaction(s) from mempool. New size: {}", original_size - new_size, new_size);
                                    }
                                    drop(pool);

                                    handle_newly_processed_block(&context, block_height, &context.external_data_service).await;
                                    if *context.node_state.lock().await == NodeState::Syncing {
                                        *context.node_state.lock().await = NodeState::Synced;
                                        log::info!("[Orchestrator] State -> Synced.");
                                    }
                                }
                                Err(e) => {
                                    log::error!("[Orchestrator] Workload failed to process gossiped block #{}: {}", block_height, e);
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
                        NetworkEvent::OracleAttestationReceived { from, attestation } => {
                            log::info!("Oracle: Received attestation for request_id {} from peer {}", attestation.request_id, from);
                             let validator_stakes = match context.workload_client.get_staked_validators().await {
                                Ok(vs) => vs,
                                Err(_) => continue,
                            };

                            let payload_to_verify = serde_json::to_vec(&(&attestation.request_id, &attestation.value, &attestation.timestamp)).unwrap();
                            let mut is_valid_signature = false;
                            for (pk_b58, _) in &validator_stakes {
                                if let Ok(pk_bytes) = bs58::decode(pk_b58).into_vec() {
                                    if let Ok(pubkey) = Libp2pPublicKey::try_decode_protobuf(&pk_bytes) {
                                         if pubkey.to_peer_id() == from && pubkey.verify(&payload_to_verify, &attestation.signature) {
                                             is_valid_signature = true;
                                             break;
                                         }
                                    }
                                }
                            }

                            if !is_valid_signature {
                                log::warn!("Oracle: Received attestation with invalid signature from {}", from);
                                continue;
                            }

                            let entry = context.pending_attestations.entry(attestation.request_id).or_default();
                            if !entry.iter().any(|a| a.signature == attestation.signature) {
                                entry.push(attestation.clone());
                            }

                            check_quorum_and_submit(&mut context, attestation.request_id).await;
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
                        let coinbase = UnifiedTransactionModel::new(CS::default()).create_coinbase_transaction(target_height, &context.local_peer_id.to_bytes()).unwrap();
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
                                let block_height = final_block.header.height;
                                log::info!("Produced and processed new block #{}", block_height);

                                handle_newly_processed_block(&context, block_height, &context.external_data_service).await;

                                let header_hash = final_block.header.hash();
                                final_block.header.signature = context.local_keypair.sign(&header_hash).unwrap();
                                let data = serde_json::to_vec(&final_block).unwrap();
                                context.swarm_commander.send(SwarmCommand::PublishBlock(data)).await.ok();
                                context.consensus_engine_ref.lock().await.reset(block_height);

                                if let Ok(outcomes) = context.workload_client.check_and_tally_proposals(block_height).await {
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

async fn handle_newly_processed_block<CS, ST, CE>(
    context: &MainLoopContext<CS, ST, CE>,
    _block_height: u64,
    external_data_service: &ExternalDataService,
) where
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
    let pending_requests = match context
        .workload_client
        .prefix_scan(ORACLE_PENDING_REQUEST_PREFIX)
        .await
    {
        Ok(kvs) => kvs,
        Err(e) => {
            log::error!("Oracle: Failed to scan for pending requests: {}", e);
            return;
        }
    };

    let validator_set = match context.workload_client.get_validator_set().await {
        Ok(vs) => vs,
        Err(e) => {
            log::error!("Oracle: Could not get validator set: {}", e);
            return;
        }
    };

    // --- FIX: Compare PeerId to PeerId, not PublicKey to PeerId ---
    let our_id_bytes = context.local_peer_id.to_bytes();
    if !validator_set.iter().any(|v| *v == our_id_bytes) {
        return; // We are not in the validator set, do nothing.
    }

    log::info!("Oracle: This node is in the validator set, checking for new tasks...");

    for (key, value_bytes) in pending_requests {
        if let Ok(entry) = serde_json::from_slice::<StateEntry>(&value_bytes) {
            let request_id_bytes: [u8; 8] = key[ORACLE_PENDING_REQUEST_PREFIX.len()..]
                .try_into()
                .unwrap_or_default();
            let request_id = u64::from_le_bytes(request_id_bytes);
            let url: String = serde_json::from_slice(&entry.value).unwrap_or_default();

            log::info!(
                "Oracle: Found new oracle task for request_id {} from URL: {}",
                request_id,
                url
            );

            match external_data_service.fetch(&url).await {
                Ok(value) => {
                    let mut attestation = OracleAttestation {
                        request_id,
                        value,
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        signature: vec![],
                    };

                    let payload_to_sign = serde_json::to_vec(&(
                        &attestation.request_id,
                        &attestation.value,
                        &attestation.timestamp,
                    ))
                    .unwrap();
                    attestation.signature = context.local_keypair.sign(&payload_to_sign).unwrap();

                    let attestation_bytes = serde_json::to_vec(&attestation).unwrap();
                    context
                        .swarm_commander
                        .send(SwarmCommand::GossipOracleAttestation(attestation_bytes))
                        .await
                        .ok();
                    log::info!("Oracle: Gossiped attestation for request_id {}", request_id);
                }
                Err(e) => log::error!(
                    "Oracle: Failed to fetch external data for request {}: {}",
                    request_id,
                    e
                ),
            }
        }
    }
}

async fn check_quorum_and_submit<CS, ST, CE>(
    context: &mut MainLoopContext<CS, ST, CE>,
    request_id: u64,
) where
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
    let attestations = match context.pending_attestations.get(&request_id) {
        Some(a) => a,
        None => return,
    };

    let validator_stakes = match context.workload_client.get_staked_validators().await {
        Ok(vs) => vs,
        Err(_) => return,
    };

    if validator_stakes.is_empty() {
        return;
    }

    let total_stake: u64 = validator_stakes.values().sum();
    let quorum_threshold = (total_stake * 2) / 3 + 1;

    let mut unique_signers = HashSet::new();
    let mut valid_attestations_for_quorum = Vec::new();

    for att in attestations {
        for (pk_b58, _) in &validator_stakes {
            if let Ok(pk_bytes) = bs58::decode(pk_b58).into_vec() {
                if let Ok(pubkey) = Libp2pPublicKey::try_decode_protobuf(&pk_bytes) {
                    let payload_to_verify =
                        serde_json::to_vec(&(&att.request_id, &att.value, &att.timestamp)).unwrap();
                    if pubkey.verify(&payload_to_verify, &att.signature)
                        && unique_signers.insert(pk_b58.clone())
                    {
                        valid_attestations_for_quorum.push((att.clone(), pk_b58));
                        break;
                    }
                }
            }
        }
    }
    valid_attestations_for_quorum.sort_by(|(_, pk_a), (_, pk_b)| pk_a.cmp(pk_b));

    let attested_stake: u64 = valid_attestations_for_quorum
        .iter()
        .filter_map(|(_, pk_b58)| validator_stakes.get(*pk_b58))
        .sum();

    if attested_stake >= quorum_threshold {
        log::info!(
            "Oracle: Quorum reached for request_id {} with {}/{} stake!",
            request_id,
            attested_stake,
            total_stake
        );

        let mut values: Vec<Vec<u8>> = valid_attestations_for_quorum
            .iter()
            .map(|(a, _)| a.value.clone())
            .collect();
        values.sort();
        let final_value = values[values.len() / 2].clone();

        let consensus_proof = OracleConsensusProof {
            attestations: valid_attestations_for_quorum
                .into_iter()
                .map(|(a, _)| a)
                .collect(),
        };

        let payload = SystemPayload::SubmitOracleData {
            request_id,
            final_value,
            consensus_proof,
        };

        let tx = ChainTransaction::System(SystemTransaction {
            payload,
            signature: vec![],
        });
        context.tx_pool_ref.lock().await.push_back(tx);
        log::info!(
            "Oracle: Submitted finalization transaction for request_id {} to local mempool.",
            request_id
        );

        context.pending_attestations.remove(&request_id);
    }
}

#[async_trait]
impl<CS, ST, CE> Container for OrchestrationContainer<CS, ST, CE>
where
    CS: CommitmentScheme + Clone + Default + Send + Sync + 'static,
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
            external_data_service: self.external_data_service.clone(),
            pending_attestations: HashMap::new(),
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
