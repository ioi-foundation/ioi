// Path: crates/validator/src/standard/orchestration/mod.rs
use crate::config::OrchestrationConfig;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use depin_sdk_api::{
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    state::{StateCommitment, StateManager, Verifier},
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
use serde::Serialize;
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
pub mod verifier_select;

// --- Use statements for handler functions ---
use consensus::handle_consensus_tick;
use context::{ChainFor, MainLoopContext};

/// A struct to hold the numerous dependencies for the OrchestrationContainer,
/// improving constructor readability and maintainability.
pub struct OrchestrationDependencies<CE, V> {
    pub syncer: Arc<Libp2pSync>,
    pub network_event_receiver: mpsc::Receiver<NetworkEvent>,
    pub swarm_command_sender: mpsc::Sender<SwarmCommand>,
    pub consensus_engine: CE,
    pub local_keypair: identity::Keypair,
    pub is_quarantined: Arc<AtomicBool>,
    pub verifier: V,
}

pub struct OrchestrationContainer<CS, ST, CE, V>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
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
    verifier: V,
}

// Generic implementation for construction and setting dependencies.
impl<CS, ST, CE, V> OrchestrationContainer<CS, ST, CE, V>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    pub fn new(
        config_path: &std::path::Path,
        deps: OrchestrationDependencies<CE, V>,
    ) -> anyhow::Result<Self> {
        let config: OrchestrationConfig = toml::from_str(&std::fs::read_to_string(config_path)?)?;
        let (shutdown_sender, _) = watch::channel(false);

        Ok(Self {
            config,
            chain: Arc::new(OnceCell::new()),
            workload_client: Arc::new(OnceCell::new()),
            tx_pool: Arc::new(Mutex::new(VecDeque::new())),
            syncer: deps.syncer,
            swarm_command_sender: deps.swarm_command_sender,
            network_event_receiver: Mutex::new(Some(deps.network_event_receiver)),
            consensus_engine: Arc::new(Mutex::new(deps.consensus_engine)),
            local_keypair: deps.local_keypair,
            shutdown_sender: Arc::new(shutdown_sender),
            task_handles: Arc::new(Mutex::new(Vec::new())),
            is_running: Arc::new(AtomicBool::new(false)),
            is_quarantined: deps.is_quarantined,
            external_data_service: ExternalDataService::new(),
            verifier: deps.verifier,
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
}

// Feature-gated impl block for main loop logic. This is where most trait bounds are needed.
impl<CS, ST, CE, V> OrchestrationContainer<CS, ST, CE, V>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + StateCommitment<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    /// The simplified main loop, now focused on network events and shutdown.
    async fn run_main_loop(
        mut network_event_receiver: mpsc::Receiver<NetworkEvent>,
        mut shutdown_receiver: watch::Receiver<bool>,
        context_arc: Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    ) {
        let sync_timeout = {
            let context = context_arc.lock().await;
            time::sleep(Duration::from_secs(
                context.config.initial_sync_timeout_secs,
            ))
        };
        tokio::pin!(sync_timeout);

        {
            let context = context_arc.lock().await;
            *context.node_state.lock().await = NodeState::Syncing;
            log::info!("[Orchestrator] State -> Syncing.");
        }

        loop {
            tokio::select! {
                biased;

                Some(event) = network_event_receiver.recv() => {
                    let mut context = context_arc.lock().await;
                    handle_network_event(event, &mut context).await;
                }

                _ = &mut sync_timeout, if *context_arc.lock().await.node_state.lock().await == NodeState::Syncing => {
                    let context = context_arc.lock().await;
                    if context.known_peers_ref.lock().await.is_empty() {
                         log::info!("[Orchestrator] No peers found after timeout. Assuming genesis node. State -> Synced.");
                        *context.node_state.lock().await = NodeState::Synced;
                    }
                },

                _ = shutdown_receiver.changed() => {
                    if *shutdown_receiver.borrow() {
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
async fn handle_network_event<CS, ST, CE, V>(
    event: NetworkEvent,
    context: &mut MainLoopContext<CS, ST, CE, V>,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + StateCommitment<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
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
impl<CS, ST, CE, V> Container for OrchestrationContainer<CS, ST, CE, V>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + StateCommitment<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    fn id(&self) -> &'static str {
        "orchestration_container"
    }
    fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }

    async fn start(&self, _listen_addr: &str) -> Result<(), ValidatorError> {
        if self.is_running() {
            return Err(ValidatorError::AlreadyRunning(self.id().to_string()));
        }
        log::info!("OrchestrationContainer starting...");

        self.syncer
            .start()
            .await
            .map_err(|e| ValidatorError::Other(e.to_string()))?;

        let workload_client = self
            .workload_client
            .get()
            .ok_or_else(|| {
                ValidatorError::Other(
                    "Workload client ref not initialized before start".to_string(),
                )
            })?
            .clone();

        let guardian_addr = std::env::var("GUARDIAN_ADDR").unwrap_or_default();
        if !guardian_addr.is_empty() {
            log::info!("[Orchestrator] Performing agentic attestation with Guardian...");
            match self
                .perform_guardian_attestation(&guardian_addr, &workload_client)
                .await
            {
                Ok(()) => log::info!("[Orchestrator] Agentic attestation successful."),
                Err(e) => {
                    log::error!("[Orchestrator] CRITICAL: Agentic attestation failed: {}. Quarantining node.", e);
                    self.is_quarantined.store(true, Ordering::SeqCst);
                }
            }
        } else {
            log::warn!("GUARDIAN_ADDR not set, skipping Guardian attestation.");
        }

        let chain = self
            .chain
            .get()
            .ok_or_else(|| {
                ValidatorError::Other("Chain ref not initialized before start".to_string())
            })?
            .clone();

        let mut receiver_opt = self.network_event_receiver.lock().await;
        let receiver = receiver_opt.take().ok_or(ValidatorError::Other(
            "Network event receiver already taken".to_string(),
        ))?;

        let genesis_root = workload_client
            .get_state_root()
            .await
            .map_err(|e| ValidatorError::Other(format!("Failed to get genesis root: {}", e)))?;

        let context = MainLoopContext::<CS, ST, CE, V> {
            chain_ref: chain,
            workload_client,
            tx_pool_ref: self.tx_pool.clone(),
            network_event_receiver: Some(receiver),
            swarm_commander: self.swarm_command_sender.clone(),
            shutdown_receiver: self.shutdown_sender.subscribe(),
            consensus_engine_ref: self.consensus_engine.clone(),
            node_state: self.syncer.get_node_state(),
            local_keypair: self.local_keypair.clone(),
            known_peers_ref: self.syncer.get_known_peers(),
            config: self.config.clone(),
            is_quarantined: self.is_quarantined.clone(),
            external_data_service: self.external_data_service.clone(),
            pending_attestations: std::collections::HashMap::new(),
            genesis_root,
            last_committed_block: None,
            verifier: self.verifier.clone(),
        };

        let context_arc = Arc::new(Mutex::new(context));
        let mut handles = self.task_handles.lock().await;

        let ticker_context = Arc::clone(&context_arc);
        handles.push(tokio::spawn(async move {
            let (interval_secs, allow_when_quarantined) = {
                let ctx = ticker_context.lock().await;

                let interval = std::env::var("ORCH_BLOCK_INTERVAL_SECS")
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or_else(|| ctx.config.block_production_interval_secs.max(1));

                let allow = std::env::var("ORCH_ALLOW_CONSENSUS_WHEN_QUARANTINED")
                    .ok()
                    .map(|v| {
                        let v = v.to_ascii_lowercase();
                        v == "1" || v == "true" || v == "yes" || v == "on"
                    })
                    .unwrap_or(false); // Default to false for production safety

                log::info!(
                    "[Consensus] Effective block interval = {}s; allow_when_quarantined = {}",
                    interval,
                    allow
                );
                (interval, allow)
            };

            let mut ticker = time::interval(Duration::from_secs(interval_secs));
            ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

            loop {
                ticker.tick().await;
                let mut guard = ticker_context.lock().await;

                let quarantined = guard.is_quarantined.load(Ordering::SeqCst);
                if quarantined && !allow_when_quarantined {
                    log::info!("[Consensus] Skipping tick (node is quarantined).");
                    continue;
                }

                log::debug!("[Consensus] tick()");
                handle_consensus_tick(&mut guard).await;
            }
        }));

        let main_loop_context = Arc::clone(&context_arc);
        handles.push(tokio::spawn(async move {
            let (receiver, shutdown) = {
                let mut ctx = main_loop_context.lock().await;
                (
                    ctx.network_event_receiver.take().unwrap(),
                    ctx.shutdown_receiver.clone(),
                )
            };
            Self::run_main_loop(receiver, shutdown, main_loop_context).await;
        }));

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

impl<CS, ST, CE, V> OrchestrationContainer<CS, ST, CE, V>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    async fn perform_guardian_attestation(
        &self,
        guardian_addr: &str,
        workload_client: &WorkloadClient,
    ) -> Result<()> {
        let guardian_channel =
            depin_sdk_client::security::SecurityChannel::new("orchestration", "guardian");
        guardian_channel
            .establish_client(guardian_addr, "guardian")
            .await?;
        log::info!("[Orchestration] Attestation channel to Guardian established.");

        log::info!("[Orchestrator] Waiting for agentic attestation report from Guardian...");
        let report_bytes = guardian_channel.receive().await?;
        let report: Result<Vec<u8>, String> = serde_json::from_slice(&report_bytes)
            .map_err(|e| anyhow!("Failed to deserialize Guardian report: {}", e))?;

        let local_hash = report.map_err(|e| anyhow!("Guardian reported error: {}", e))?;
        log::info!(
            "[Orchestrator] Received local model hash from Guardian: {}",
            hex::encode(&local_hash)
        );

        let expected_hash = workload_client.get_expected_model_hash().await?;
        if local_hash == expected_hash {
            Ok(())
        } else {
            Err(anyhow!(
                "Model Integrity Failure! Local hash {} != on-chain hash {}",
                hex::encode(local_hash),
                hex::encode(expected_hash)
            ))
        }
    }
}
