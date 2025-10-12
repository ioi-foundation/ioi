// Path: crates/validator/src/standard/orchestration/mod.rs
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unimplemented,
        clippy::todo,
        clippy::indexing_slicing
    )
)]
//! The main logic for the Orchestration container, handling consensus and peer communication.
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use depin_sdk_api::crypto::SerializableKey;
use depin_sdk_api::{
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    crypto::SigningKeyPair,
    state::{StateCommitment, StateManager, Verifier},
    validator::Container,
};
use depin_sdk_client::WorkloadClient;
use depin_sdk_crypto::sign::dilithium::DilithiumKeyPair;
use depin_sdk_network::libp2p::{Libp2pSync, NetworkEvent, SwarmCommand};
use depin_sdk_network::traits::NodeState;
use depin_sdk_network::BlockSync;
use depin_sdk_services::external_data::ExternalDataService;
use depin_sdk_types::{
    app::{account_id_from_key_material, ChainTransaction, SignatureSuite},
    error::ValidatorError,
};
use libp2p::identity;
use lru::LruCache;
use rand::seq::SliceRandom;
use serde::Serialize;
use std::collections::VecDeque;
use std::fmt::Debug;
use std::panic::AssertUnwindSafe;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::{
    sync::{mpsc, watch, Mutex, OnceCell},
    task::JoinHandle,
    time::{self, Duration, MissedTickBehavior},
};

// --- Submodule Declarations ---
mod consensus;
mod context;
mod gossip;
mod oracle;
mod peer_management;
mod remote_state_view; // [+] ADDED: This module declaration was missing.
                       // Make sure the sync helpers are visible here.
mod sync;
pub mod verifier_select;
mod view_resolver;

// --- Use statements for handler functions ---
use crate::config::OrchestrationConfig;
use consensus::drive_consensus_tick;
use context::{ChainFor, MainLoopContext};
use futures::FutureExt;
// [+] Use `sync as sync_handlers` to avoid ambiguity with tokio::sync
use sync as sync_handlers;

/// A struct to hold the numerous dependencies for the OrchestrationContainer,
/// improving constructor readability and maintainability.
pub struct OrchestrationDependencies<CE, V> {
    /// The network synchronization engine.
    pub syncer: Arc<Libp2pSync>,
    /// The receiver for incoming network events.
    pub network_event_receiver: mpsc::Receiver<NetworkEvent>,
    /// The sender for commands to the network swarm.
    pub swarm_command_sender: mpsc::Sender<SwarmCommand>,
    /// The consensus engine instance.
    pub consensus_engine: CE,
    /// The node's primary cryptographic identity.
    pub local_keypair: identity::Keypair,
    /// An optional post-quantum keypair for signing.
    pub pqc_keypair: Option<DilithiumKeyPair>,
    /// A flag indicating if the node has been quarantined due to misbehavior.
    pub is_quarantined: Arc<AtomicBool>,
    /// The proof verifier matching the workload's state tree.
    pub verifier: V,
}

// Type aliases to simplify complex types used in the main struct.
type ProofCache = Arc<Mutex<LruCache<(Vec<u8>, Vec<u8>), Option<Vec<u8>>>>>;
type NetworkEventReceiver = Mutex<Option<mpsc::Receiver<NetworkEvent>>>;
type ConsensusKickReceiver = Mutex<Option<mpsc::UnboundedReceiver<()>>>;

/// The OrchestrationContainer is the central component of a validator node, responsible for
/// coordinating consensus, networking, and state transitions. It communicates with the
/// Workload container via IPC to process blocks and verify state, and with other nodes
/// via the libp2p network to participate in consensus and gossip blocks and transactions.
pub struct OrchestrationContainer<CS, ST, CE, V>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Clone
        + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
{
    config: OrchestrationConfig,
    chain: Arc<OnceCell<ChainFor<CS, ST>>>,
    workload_client: Arc<OnceCell<Arc<WorkloadClient>>>,
    /// The local mempool for pending transactions.
    pub tx_pool: Arc<Mutex<VecDeque<ChainTransaction>>>,
    syncer: Arc<Libp2pSync>,
    swarm_command_sender: mpsc::Sender<SwarmCommand>,
    network_event_receiver: NetworkEventReceiver,
    consensus_engine: Arc<Mutex<CE>>,
    local_keypair: identity::Keypair,
    pqc_signer: Option<DilithiumKeyPair>,
    shutdown_sender: Arc<watch::Sender<bool>>,
    task_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
    is_running: Arc<AtomicBool>,
    is_quarantined: Arc<AtomicBool>,
    external_data_service: ExternalDataService,
    proof_cache: ProofCache,
    verifier: V,
    main_loop_context: Arc<Mutex<Option<Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>>>>,
    // Robust consensus kick channel: keep both ends.
    consensus_kick_tx: mpsc::UnboundedSender<()>,
    consensus_kick_rx: ConsensusKickReceiver,
}

impl<CS, ST, CE, V> OrchestrationContainer<CS, ST, CE, V>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Clone
        + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
{
    /// Creates a new OrchestrationContainer from its configuration and dependencies.
    pub fn new(
        config_path: &std::path::Path,
        deps: OrchestrationDependencies<CE, V>,
    ) -> anyhow::Result<Self> {
        let config: OrchestrationConfig = toml::from_str(&std::fs::read_to_string(config_path)?)?;
        let (shutdown_sender, _) = watch::channel(false);

        // One kick channel pair for the whole container.
        let (consensus_kick_tx, consensus_kick_rx) = mpsc::unbounded_channel();

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
            pqc_signer: deps.pqc_keypair,
            shutdown_sender: Arc::new(shutdown_sender),
            task_handles: Arc::new(Mutex::new(Vec::new())),
            is_running: Arc::new(AtomicBool::new(false)),
            is_quarantined: deps.is_quarantined,
            external_data_service: ExternalDataService::new(),
            proof_cache: Arc::new(Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(1024).ok_or_else(|| anyhow!("Invalid LRU size"))?,
            ))),
            verifier: deps.verifier,
            main_loop_context: Arc::new(Mutex::new(None)),
            consensus_kick_tx,
            consensus_kick_rx: Mutex::new(Some(consensus_kick_rx)),
        })
    }

    /// Sets the `Chain` and `WorkloadClient` references, which are initialized
    /// after the container is created.
    pub fn set_chain_and_workload_client(
        &self,
        chain_ref: ChainFor<CS, ST>,
        workload_client_ref: Arc<WorkloadClient>,
    ) {
        if self.chain.set(chain_ref).is_err() {
            log::warn!("Attempted to set Chain ref on OrchestrationContainer more than once.");
        }
        if self.workload_client.set(workload_client_ref).is_err() {
            log::warn!(
                "Attempted to set WorkloadClient ref on OrchestrationContainer more than once."
            );
        }
    }
}

// ---------- ticker + main loop ----------
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
    async fn run_consensus_ticker(
        context_arc: Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
        mut kick_rx: mpsc::UnboundedReceiver<()>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) {
        let interval_secs = {
            let ctx = context_arc.lock().await;
            std::env::var("ORCH_BLOCK_INTERVAL_SECS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or_else(|| ctx.config.block_production_interval_secs.max(1))
        };
        log::info!("[Consensus] Ticker starting ({}s).", interval_secs);
        let mut ticker = time::interval(Duration::from_secs(interval_secs));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        // “Immediate” kick on startup (now wired to the actual receiver).
        let _ = {
            let ctx = context_arc.lock().await;
            ctx.consensus_kick_tx.send(())
        };

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let cause = "timer";
                    let is_quarantined = context_arc.lock().await.is_quarantined.load(Ordering::SeqCst);
                    if is_quarantined {
                        log::info!("[Consensus] Skipping tick (node is quarantined).");
                        continue;
                    }
                    // Use AssertUnwindSafe to prevent a panic in one tick from killing the entire loop.
                    let result = AssertUnwindSafe(drive_consensus_tick(&context_arc, cause)).catch_unwind().await;
                    if let Err(e) = result.map_err(|e| anyhow!("Consensus tick panicked: {:?}", e)).and_then(|res| res) {
                        log::error!("[Orch Tick] Consensus tick panicked: {:?}. Continuing loop.", e);
                    }
                }
                // Kicks from RPC/mempool/gossip.
                Some(()) = kick_rx.recv() => {
                    let cause = "kick";
                     let is_quarantined = context_arc.lock().await.is_quarantined.load(Ordering::SeqCst);
                    if is_quarantined {
                        log::info!("[Consensus] Skipping kicked tick (node is quarantined).");
                        continue;
                    }
                    let result = AssertUnwindSafe(drive_consensus_tick(&context_arc, cause)).catch_unwind().await;
                     if let Err(e) = result.map_err(|e| anyhow!("Kicked consensus tick panicked: {:?}", e)).and_then(|res| res) {
                        log::error!("[Orch Tick] Kicked consensus tick panicked: {:?}. Continuing loop.", e);
                    }
                }
                 _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        log::info!("Consensus ticker received shutdown signal.");
                        break;
                    }
                }
            }
        }
        log::info!("Consensus ticker finished.");
    }

    async fn run_sync_discoverer(
        context_arc: Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) {
        let mut interval = time::interval(Duration::from_secs(30));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let (known_peers, swarm_commander) = {
                        let ctx = context_arc.lock().await;
                        (ctx.known_peers_ref.clone(), ctx.swarm_commander.clone())
                    };

                    let random_peer_opt = {
                        let peers: Vec<_> = known_peers.lock().await.iter().cloned().collect();
                        peers.choose(&mut rand::thread_rng()).cloned()
                    };

                    if let Some(random_peer) = random_peer_opt {
                        log::debug!("Sending periodic status request to random peer: {}", random_peer);
                        if swarm_commander.send(SwarmCommand::SendStatusRequest(random_peer)).await.is_err() {
                            log::warn!("Failed to send periodic status request to swarm.");
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        log::info!("Sync discoverer received shutdown signal.");
                        break;
                    }
                }
            }
        }
        log::info!("Sync discoverer finished.");
    }

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
                    handle_network_event(event, &context_arc).await;
                }

                _ = &mut sync_timeout, if *context_arc.lock().await.node_state.lock().await == NodeState::Syncing => {
                    let context = context_arc.lock().await;
                    if context.known_peers_ref.lock().await.is_empty() {
                        tracing::warn!(target: "orchestration", "Initial sync timeout elapsed with no peers found. Will continue waiting for peers...");
                        // We no longer assume genesis here. The node will stay in Syncing state.
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
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
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
        // Wake consensus on new transactions.
        NetworkEvent::GossipTransaction(tx) => {
            let (tx_pool_ref, kick_tx) = {
                let ctx = context_arc.lock().await;
                (ctx.tx_pool_ref.clone(), ctx.consensus_kick_tx.clone())
            };
            {
                let mut pool = tx_pool_ref.lock().await;
                pool.push_back(*tx);
                log::debug!("[Orchestrator] Mempool size is now {}", pool.len());
                // Kick the consensus engine when a tx arrives.
                let _ = kick_tx.send(());
            }
        }

        // IMPORTANT: avoid deadlock by ignoring our own blocks (single-node).
        NetworkEvent::GossipBlock(block) => {
            let node_state = { context_arc.lock().await.node_state.lock().await.clone() };
            if node_state == NodeState::Syncing {
                tracing::debug!(
                    target: "gossip",
                    event = "block_ignored",
                    height = block.header.height,
                    reason = "Node is currently syncing"
                );
                return;
            }

            // Compute our Ed25519 account id.
            let (our_ed_id, our_pqc_id_opt, kick_tx) = {
                let ctx = context_arc.lock().await;

                let ed_pk = ctx.local_keypair.public().encode_protobuf();
                let ed_id = account_id_from_key_material(SignatureSuite::Ed25519, &ed_pk)
                    .unwrap_or_default();

                let pqc_id_opt = ctx.pqc_signer.as_ref().map(|kp| {
                    let pqc_pk = SigningKeyPair::public_key(kp).to_bytes();
                    account_id_from_key_material(SignatureSuite::Dilithium2, &pqc_pk)
                        .unwrap_or_default()
                });

                (ed_id, pqc_id_opt, ctx.consensus_kick_tx.clone())
            };

            let producer_id = block.header.producer_pubkey_hash;
            let is_ours = producer_id == our_ed_id
                || our_pqc_id_opt.map(|id| id == producer_id).unwrap_or(false);

            if is_ours {
                log::info!(
                    "[Orchestrator] Skipping verification of our own gossiped block #{}.",
                    block.header.height
                );
                // Still kick consensus in case peers sent txs with this block.
                let _ = kick_tx.send(());
                return;
            }

            // Otherwise, proceed as before (may verify with engine).
            let mut ctx = context_arc.lock().await;
            gossip::handle_gossip_block(&mut ctx, block).await
        }

        NetworkEvent::ConnectionEstablished(peer_id) => {
            let mut ctx = context_arc.lock().await;
            peer_management::handle_connection_established(&mut ctx, peer_id).await
        }
        NetworkEvent::ConnectionClosed(peer_id) => {
            let mut ctx = context_arc.lock().await;
            peer_management::handle_connection_closed(&mut ctx, peer_id).await
        }
        NetworkEvent::StatusRequest(peer, channel) => {
            let mut ctx = context_arc.lock().await;
            sync_handlers::handle_status_request(&mut ctx, peer, channel).await
        }
        NetworkEvent::BlocksRequest {
            peer,
            since,
            max_blocks,
            max_bytes,
            channel,
        } => {
            let mut ctx = context_arc.lock().await;
            sync_handlers::handle_blocks_request(
                &mut ctx, peer, since, max_blocks, max_bytes, channel,
            )
            .await
        }
        NetworkEvent::StatusResponse {
            peer,
            height,
            head_hash,
            chain_id,
            genesis_root,
        } => {
            let mut ctx = context_arc.lock().await;
            sync_handlers::handle_status_response(
                &mut ctx,
                peer,
                height,
                head_hash,
                chain_id,
                genesis_root,
            )
            .await
        }
        NetworkEvent::BlocksResponse(peer, blocks) => {
            let mut ctx = context_arc.lock().await;
            sync_handlers::handle_blocks_response(&mut ctx, peer, blocks).await
        }
        NetworkEvent::OracleAttestationReceived { from, attestation } => {
            let mut ctx = context_arc.lock().await;
            oracle::handle_oracle_attestation_received(&mut ctx, from, attestation).await
        }
        NetworkEvent::OutboundFailure(peer) => {
            let mut ctx = context_arc.lock().await;
            sync_handlers::handle_outbound_failure(&mut ctx, peer).await
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

        let rpc_handle = crate::rpc::run_rpc_server(
            &self.config.rpc_listen_address,
            self.tx_pool.clone(),
            self.workload_client
                .get()
                .ok_or_else(|| ValidatorError::Other("Workload client not set".to_string()))?
                .clone(),
            self.swarm_command_sender.clone(),
            // Pass the *real* kick sender used by the ticker.
            self.consensus_kick_tx.clone(),
            self.config.clone(),
        )
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

        let view_resolver = Arc::new(view_resolver::DefaultViewResolver::new(
            workload_client.clone(),
            self.verifier.clone(),
            self.proof_cache.clone(),
        ));

        // Build the run context (includes the *sender* for kicks).
        let context = MainLoopContext::<CS, ST, CE, V> {
            chain_ref: chain,
            tx_pool_ref: self.tx_pool.clone(),
            view_resolver,
            swarm_commander: self.swarm_command_sender.clone(),
            consensus_engine_ref: self.consensus_engine.clone(),
            node_state: self.syncer.get_node_state(),
            local_keypair: self.local_keypair.clone(),
            pqc_signer: self.pqc_signer.clone(),
            known_peers_ref: self.syncer.get_known_peers(),
            config: self.config.clone(),
            chain_id: self.config.chain_id,
            genesis_hash: [0; 32], // Placeholder, will be set properly in node binary
            is_quarantined: self.is_quarantined.clone(),
            external_data_service: self.external_data_service.clone(),
            pending_attestations: std::collections::HashMap::new(),
            last_committed_block: None,
            consensus_kick_tx: self.consensus_kick_tx.clone(),
            sync_progress: None,
        };

        let mut receiver_opt = self.network_event_receiver.lock().await;
        let receiver = receiver_opt.take().ok_or(ValidatorError::Other(
            "Network event receiver already taken".to_string(),
        ))?;

        let context_arc = Arc::new(Mutex::new(context));
        *self.main_loop_context.lock().await = Some(context_arc.clone());

        let mut handles = self.task_handles.lock().await;
        handles.push(rpc_handle);

        // Pass the *actual* receiver end to the ticker.
        let ticker_kick_rx = match self.consensus_kick_rx.lock().await.take() {
            Some(rx) => rx,
            None => {
                return Err(ValidatorError::Other(
                    "Consensus kick receiver already taken".into(),
                ))
            }
        };
        let ticker_context = context_arc.clone();
        let ticker_shutdown_rx = self.shutdown_sender.subscribe();

        handles.push(tokio::spawn(async move {
            Self::run_consensus_ticker(ticker_context, ticker_kick_rx, ticker_shutdown_rx).await;
        }));

        let discoverer_context = context_arc.clone();
        let discoverer_shutdown_rx = self.shutdown_sender.subscribe();
        handles.push(tokio::spawn(async move {
            Self::run_sync_discoverer(discoverer_context, discoverer_shutdown_rx).await;
        }));

        let shutdown_receiver_clone = self.shutdown_sender.subscribe();
        let main_loop_context_clone = context_arc.clone();
        handles.push(tokio::spawn(async move {
            Self::run_main_loop(receiver, shutdown_receiver_clone, main_loop_context_clone).await;
        }));

        self.is_running.store(true, Ordering::SeqCst);
        eprintln!("ORCHESTRATION_STARTUP_COMPLETE");
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
        + Debug
        + Clone,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
{
    async fn perform_guardian_attestation(
        &self,
        guardian_addr: &str,
        workload_client: &WorkloadClient,
    ) -> Result<()> {
        let guardian_channel =
            depin_sdk_client::security::SecurityChannel::new("orchestration", "guardian");
        let certs_dir = std::env::var("CERTS_DIR").map_err(|_| {
            ValidatorError::Config("CERTS_DIR environment variable must be set".to_string())
        })?;
        guardian_channel
            .establish_client(
                guardian_addr,
                "guardian",
                &format!("{}/ca.pem", certs_dir),
                &format!("{}/orchestration.pem", certs_dir),
                &format!("{}/orchestration.key", certs_dir),
            )
            .await?;
        log::info!("[Orchestration] Attestation channel to Guardian established.");

        log::info!("[Orchestrator] Waiting for agentic attestation report from Guardian...");
        let report_bytes = guardian_channel.receive().await?;
        let report: std::result::Result<Vec<u8>, String> = serde_json::from_slice(&report_bytes)
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
