// Path: crates/validator/src/standard/orchestration/mod.rs
use crate::config::OrchestrationConfig;
use async_trait::async_trait;
use depin_sdk_api::{
    chain::ChainView,
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    state::{StateCommitment, StateManager},
    validator::Container,
};
use depin_sdk_client::WorkloadClient;
use depin_sdk_network::libp2p::{Libp2pSync, NetworkEvent, SwarmCommand};
use depin_sdk_network::traits::NodeState;
use depin_sdk_network::BlockSync;
use depin_sdk_services::external_data::ExternalDataService;
use depin_sdk_types::app::ChainTransaction;
use depin_sdk_types::error::ValidatorError;
use libp2p::identity;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
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

// --- Submodule Declarations ---
mod consensus;
mod context;
mod gossip;
mod oracle;
mod peer_management;
mod remote_state_view;
mod sync;

// --- Use statements for handler functions ---
use consensus::handle_consensus_tick;
use context::{ChainFor, MainLoopContext};

pub struct OrchestrationContainer<CS, ST, CE>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug,
    CE: ConsensusEngine<ChainTransaction> + ChainView<CS, ST> + Send + Sync + 'static,
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
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + ChainView<CS, ST> + Send + Sync + 'static,
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
        let interval_secs = context.config.block_production_interval_secs;
        let mut block_production_interval = time::interval(Duration::from_secs(interval_secs));
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
                    handle_network_event(event, &mut context).await;
                }

                _ = &mut sync_timeout, if *context.node_state.lock().await == NodeState::Syncing => {
                    if context.known_peers_ref.lock().await.is_empty() {
                         log::info!("[Orchestrator] No peers found after timeout. Assuming genesis node. State -> Synced.");
                        *context.node_state.lock().await = NodeState::Synced;
                    }
                },

                _ = block_production_interval.tick() => {
                    handle_consensus_tick(&mut context).await;
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

/// Dispatches network events to their respective handlers.
async fn handle_network_event<CS, ST, CE>(
    event: NetworkEvent,
    context: &mut MainLoopContext<CS, ST, CE>,
) where
    CS: CommitmentScheme + Clone + Default + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + StateCommitment<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + ChainView<CS, ST> + Send + Sync + 'static,
{
    match event {
        NetworkEvent::ConnectionEstablished(peer_id) => {
            peer_management::handle_connection_established(context, peer_id).await
        }
        NetworkEvent::ConnectionClosed(peer_id) => {
            peer_management::handle_connection_closed(context, peer_id).await
        }
        NetworkEvent::GossipBlock(block) => gossip::handle_gossip_block(context, block).await,
        NetworkEvent::GossipTransaction(tx) => {
            gossip::handle_gossip_transaction(context, *tx).await
        }
        NetworkEvent::StatusRequest(peer, channel) => {
            sync::handle_status_request(context, peer, channel).await
        }
        NetworkEvent::BlocksRequest(peer, since, channel) => {
            sync::handle_blocks_request(context, peer, since, channel).await
        }
        NetworkEvent::StatusResponse(peer, height) => {
            sync::handle_status_response(context, peer, height).await
        }
        NetworkEvent::BlocksResponse(peer, blocks) => {
            sync::handle_blocks_response(context, peer, blocks).await
        }
        NetworkEvent::OracleAttestationReceived { from, attestation } => {
            oracle::handle_oracle_attestation_received(context, from, attestation).await
        }
        _ => {}
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
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + ChainView<CS, ST> + Send + Sync + 'static,
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

        // --- FIX START: Fetch the genesis root to initialize the context ---
        let genesis_root_vec = workload_client
            .get_state_root()
            .await
            .map_err(|e| ValidatorError::Other(format!("Failed to get genesis root: {}", e)))?;
        // --- FIX END ---

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
            pending_attestations: std::collections::HashMap::new(),
            // --- FIX START: Initialize the new fields ---
            genesis_root: genesis_root_vec,
            last_committed_block: None,
            // --- FIX END ---
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
