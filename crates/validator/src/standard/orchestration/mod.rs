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
use ioi_api::crypto::BatchVerifier;
use ioi_api::crypto::SerializableKey;
use ioi_api::{
    chain::WorkloadClientApi,
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    crypto::SigningKeyPair,
    state::{StateManager, Verifier},
    validator::Container,
};
use ioi_client::WorkloadClient;
use ioi_crypto::sign::dilithium::DilithiumKeyPair;
use ioi_networking::libp2p::{Libp2pSync, NetworkEvent, SwarmCommand};
use ioi_networking::traits::NodeState;
use ioi_networking::BlockSync;
use ioi_tx::unified::UnifiedTransactionModel;
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ChainTransaction, GuardianReport, SignHeader,
        SignatureProof, SignatureSuite, SystemPayload, SystemTransaction,
    },
    codec,
    error::ValidatorError,
};
use libp2p::identity;
use lru::LruCache;
use rand::seq::SliceRandom;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::panic::AssertUnwindSafe;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::{
    io::AsyncReadExt,
    sync::{mpsc, watch, Mutex, OnceCell},
    task::JoinHandle,
    time::{self, Duration, MissedTickBehavior},
};

use crate::common::GuardianSigner;
use crate::standard::orchestration::grpc_public::PublicApiImpl;
use ioi_ipc::public::public_api_server::PublicApiServer;
use tonic::transport::Server;

// --- Submodule Declarations ---
mod consensus;
mod context;
mod gossip;
mod grpc_public;
// [NEW] Ingestion worker module
mod ingestion;
/// Transaction mempool logic.
pub mod mempool;
mod operator_tasks;
mod oracle;
mod peer_management;
mod remote_state_view;
mod sync;
pub mod verifier_select;
mod view_resolver;

use self::sync as sync_handlers;
use crate::config::OrchestrationConfig;
use consensus::drive_consensus_tick;
use context::{ChainFor, MainLoopContext};
use futures::FutureExt;
use ingestion::{run_ingestion_worker, ChainTipInfo, IngestionConfig};
use operator_tasks::run_oracle_operator_task;

/// A struct to hold the numerous dependencies for the Orchestrator,
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
    /// The SHA-256 hash of the canonical genesis file bytes.
    pub genesis_hash: [u8; 32],
    /// The proof verifier matching the workload's state tree.
    pub verifier: V,
    /// The signer for block headers (Local or Remote Oracle).
    pub signer: Arc<dyn GuardianSigner>,
    /// The batch verifier for parallel signature verification.
    pub batch_verifier: Arc<dyn BatchVerifier>,
}

// Type aliases to simplify complex types used in the main struct.
type ProofCache = Arc<Mutex<LruCache<(Vec<u8>, Vec<u8>), Option<Vec<u8>>>>>;
type NetworkEventReceiver = Mutex<Option<mpsc::Receiver<NetworkEvent>>>;
type ConsensusKickReceiver = Mutex<Option<mpsc::UnboundedReceiver<()>>>;

/// The Orchestrator is the central component of a validator node, responsible for
/// coordinating consensus, networking, and state transitions. It communicates with the
/// Workload container via IPC to process blocks and verify state, and with other nodes
/// via the libp2p network to participate in consensus and gossip blocks and transactions.
pub struct Orchestrator<CS, ST, CE, V>
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
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
{
    config: OrchestrationConfig,
    genesis_hash: [u8; 32],
    chain: Arc<OnceCell<ChainFor<CS, ST>>>,
    workload_client: Arc<OnceCell<Arc<WorkloadClient>>>,
    /// The local mempool for pending transactions.
    // [FIX] Changed from Arc<Mutex<Mempool>> to Arc<Mempool>
    pub tx_pool: Arc<crate::standard::orchestration::mempool::Mempool>,
    syncer: Arc<Libp2pSync>,
    swarm_command_sender: mpsc::Sender<SwarmCommand>,
    network_event_receiver: NetworkEventReceiver,
    consensus_engine: Arc<Mutex<CE>>,
    local_keypair: identity::Keypair,
    pqc_signer: Option<DilithiumKeyPair>,
    /// A channel sender to signal graceful shutdown to all background tasks.
    pub shutdown_sender: Arc<watch::Sender<bool>>,
    /// Handles to background tasks for graceful shutdown.
    pub task_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
    is_running: Arc<AtomicBool>,
    is_quarantined: Arc<AtomicBool>,
    proof_cache: ProofCache,
    verifier: V,
    main_loop_context: Arc<Mutex<Option<Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>>>>,
    consensus_kick_tx: mpsc::UnboundedSender<()>,
    consensus_kick_rx: ConsensusKickReceiver,
    /// A local, atomically-managed nonce for self-generated transactions.
    pub nonce_manager: Arc<Mutex<BTreeMap<AccountId, u64>>>,
    /// The signer for block headers (Local or Remote Oracle).
    pub signer: Arc<dyn GuardianSigner>,
    /// Thread pool for CPU-intensive ingress tasks (signature verification).
    #[allow(dead_code)] // Intended for future optimization
    _cpu_pool: Arc<rayon::ThreadPool>,
    /// The batch verifier for parallel signature verification.
    pub batch_verifier: Arc<dyn BatchVerifier>,
    /// The commitment scheme instance, stored for creating singletons like TxModel.
    scheme: CS,
}

impl<CS, ST, CE, V> Orchestrator<CS, ST, CE, V>
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
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
{
    /// Creates a new Orchestrator from its configuration and dependencies.
    pub fn new(
        config: &OrchestrationConfig,
        deps: OrchestrationDependencies<CE, V>,
        scheme: CS,
    ) -> anyhow::Result<Self> {
        let (shutdown_sender, _) = watch::channel(false);
        let (consensus_kick_tx, consensus_kick_rx) = mpsc::unbounded_channel();
        let cpu_pool = Arc::new(
            rayon::ThreadPoolBuilder::new()
                .num_threads(num_cpus::get())
                .build()
                .map_err(|e| anyhow::anyhow!("Failed to build CPU thread pool: {}", e))?,
        );

        Ok(Self {
            config: config.clone(),
            genesis_hash: deps.genesis_hash,
            chain: Arc::new(OnceCell::new()),
            workload_client: Arc::new(OnceCell::new()),
            // [FIX] Removed Mutex wrapping
            tx_pool: Arc::new(crate::standard::orchestration::mempool::Mempool::new()),
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
            proof_cache: Arc::new(Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(1024).ok_or_else(|| anyhow!("Invalid LRU size"))?,
            ))),
            verifier: deps.verifier,
            main_loop_context: Arc::new(Mutex::new(None)),
            consensus_kick_tx,
            consensus_kick_rx: Mutex::new(Some(consensus_kick_rx)),
            nonce_manager: Arc::new(Mutex::new(BTreeMap::new())),
            signer: deps.signer,
            _cpu_pool: cpu_pool,
            batch_verifier: deps.batch_verifier,
            scheme,
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
            log::warn!("Attempted to set Chain ref on Orchestrator more than once.");
        }
        if self.workload_client.set(workload_client_ref).is_err() {
            log::warn!("Attempted to set WorkloadClient ref on Orchestrator more than once.");
        }
    }

    async fn perform_guardian_attestation(
        &self,
        guardian_addr: &str,
        workload_client: &WorkloadClient,
    ) -> Result<()> {
        let guardian_channel =
            ioi_client::security::SecurityChannel::new("orchestration", "guardian");
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
        tracing::info!(target: "orchestration", "[Orchestration] Attestation channel to Guardian established.");

        tracing::info!(target: "orchestration", "[Orchestrator] Waiting for agentic attestation report from Guardian...");
        let mut stream = guardian_channel
            .take_stream()
            .await
            .ok_or_else(|| anyhow!("Failed to take stream from Guardian channel"))?;

        let len = stream.read_u32().await?;
        const MAX_REPORT_SIZE: u32 = 10 * 1024 * 1024; // 10 MiB limit
        if len > MAX_REPORT_SIZE {
            return Err(anyhow!(
                "Guardian attestation report too large: {} bytes (limit: {})",
                len,
                MAX_REPORT_SIZE
            ));
        }

        let mut report_bytes = vec![0u8; len as usize];
        stream.read_exact(&mut report_bytes).await?;

        let report: GuardianReport = serde_json::from_slice(&report_bytes)
            .map_err(|e| anyhow!("Failed to deserialize Guardian report: {}", e))?;

        tracing::info!(
            target: "orchestration",
            "[Orchestrator] Received local model hash from Guardian: {}",
            hex::encode(&report.agentic_hash)
        );

        let expected_hash = workload_client.get_expected_model_hash().await?;
        if report.agentic_hash != expected_hash {
            return Err(anyhow!(
                "Model Integrity Failure! Local hash {} != on-chain hash {}",
                hex::encode(&report.agentic_hash),
                hex::encode(expected_hash)
            ));
        }

        tracing::info!(target: "orchestration", "Submitting signed binary boot attestation to IdentityHub...");

        let payload_bytes =
            codec::to_bytes_canonical(&report.binary_attestation).map_err(|e| anyhow!(e))?;

        let sys_payload = SystemPayload::CallService {
            service_id: "identity_hub".to_string(),
            method: "register_attestation@v1".to_string(),
            params: payload_bytes,
        };

        let our_pk = self.local_keypair.public().encode_protobuf();
        let our_account_id = AccountId(
            account_id_from_key_material(SignatureSuite::Ed25519, &our_pk)
                .map_err(|e| anyhow!(e))?,
        );

        let nonce = {
            let mut nm = self.nonce_manager.lock().await;
            let n = nm.entry(our_account_id).or_insert(0);
            let cur = *n;
            *n += 1;
            cur
        };

        let mut sys_tx = SystemTransaction {
            header: SignHeader {
                account_id: our_account_id,
                nonce,
                chain_id: self.config.chain_id,
                tx_version: 1,
            },
            payload: sys_payload,
            signature_proof: SignatureProof::default(),
        };

        let sign_bytes = sys_tx.to_sign_bytes().map_err(|e| anyhow!(e))?;
        let signature = self.local_keypair.sign(&sign_bytes)?;

        sys_tx.signature_proof = SignatureProof {
            suite: SignatureSuite::Ed25519,
            public_key: our_pk,
            signature,
        };

        let tx = ChainTransaction::System(Box::new(sys_tx));
        let tx_hash = tx.hash()?;

        let committed_nonce = 0;
        // [FIX] No lock
        self.tx_pool
            .add(tx, tx_hash, Some((our_account_id, nonce)), committed_nonce);

        Ok(())
    }

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
        tracing::info!(
            target: "consensus",
            "Consensus ticker started ({}s interval).",
            interval_secs
        );
        let mut ticker = time::interval(Duration::from_secs(interval_secs));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        // [FIX] Throttling for block production
        let min_block_time = Duration::from_millis(50);
        let mut last_tick = tokio::time::Instant::now()
            .checked_sub(min_block_time)
            .unwrap();

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let cause = "timer";
                    let is_quarantined = context_arc.lock().await.is_quarantined.load(Ordering::SeqCst);
                    if is_quarantined {
                        tracing::info!(target: "consensus", "Skipping tick (node is quarantined).");
                        continue;
                    }

                    // Reset throttle
                    last_tick = tokio::time::Instant::now();

                    let result = AssertUnwindSafe(drive_consensus_tick(&context_arc, cause)).catch_unwind().await;
                    if let Err(e) = result.map_err(|e| anyhow!("Consensus tick panicked: {:?}", e)).and_then(|res| res) {
                        tracing::error!(target: "consensus", "[Orch Tick] Consensus tick panicked: {:?}. Continuing loop.", e);
                    }
                }
                Some(()) = kick_rx.recv() => {
                    let mut count = 1;
                    while let Ok(_) = kick_rx.try_recv() {
                        count += 1;
                    }
                    if count > 10 {
                        tracing::debug!(target: "consensus", "Coalesced {} kicks into one tick", count);
                    }
                    let cause = "kick";
                    let is_quarantined = context_arc.lock().await.is_quarantined.load(Ordering::SeqCst);
                    if is_quarantined {
                         continue;
                    }

                    // Throttle
                    if last_tick.elapsed() < min_block_time {
                        continue;
                    }
                    last_tick = tokio::time::Instant::now();

                    let result = AssertUnwindSafe(drive_consensus_tick(&context_arc, cause)).catch_unwind().await;
                     if let Err(e) = result.map_err(|e| anyhow!("Kicked consensus tick panicked: {:?}", e)).and_then(|res| res) {
                        tracing::error!(target: "consensus", "[Orch Tick] Kicked consensus tick panicked: {:?}. Continuing loop.", e);
                    }
                }
                 _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        tracing::info!(target: "consensus", "Consensus ticker received shutdown signal.");
                        break;
                    }
                }
            }
        }
        tracing::info!(target: "consensus", "Consensus ticker finished.");
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
                        tracing::info!(target: "orchestration", "Sync discoverer received shutdown signal.");
                        break;
                    }
                }
            }
        }
        tracing::info!(target: "orchestration", "Sync discoverer finished.");
    }

    async fn run_main_loop(
        mut network_event_receiver: mpsc::Receiver<NetworkEvent>,
        mut shutdown_receiver: watch::Receiver<bool>,
        context_arc: Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    ) {
        let mut sync_check_interval = time::interval(Duration::from_secs(
            context_arc.lock().await.config.initial_sync_timeout_secs,
        ));
        sync_check_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut operator_ticker = time::interval(Duration::from_secs(10));
        operator_ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        {
            let context = context_arc.lock().await;
            *context.node_state.lock().await = NodeState::Syncing;
            tracing::info!(target: "orchestration", "State -> Syncing.");
        }

        {
            let context = context_arc.lock().await;
            let is_bootstrap_consensus = matches!(
                context.config.consensus_type,
                ioi_types::config::ConsensusType::ProofOfAuthority
                    | ioi_types::config::ConsensusType::ProofOfStake
            );
            if is_bootstrap_consensus && context.known_peers_ref.lock().await.is_empty() {
                let mut node_state = context.node_state.lock().await;
                if *node_state == NodeState::Syncing {
                    *node_state = NodeState::Synced;
                    tracing::info!(
                        target: "orchestration",
                        event = "bootstrap_kick",
                        "Single-node startup detected. State -> Synced. Sending initial consensus kick."
                    );
                    let _ = context.consensus_kick_tx.send(());
                }
            }
        }

        loop {
            tokio::select! {
                biased;

                Some(event) = network_event_receiver.recv() => {
                    handle_network_event(event, &context_arc).await;
                }

                _ = operator_ticker.tick() => {
                    let ctx = context_arc.lock().await;
                    if let Err(e) = run_oracle_operator_task(&ctx).await {
                         tracing::error!(target: "operator_task", "Oracle operator task failed: {}", e);
                    }
                }

                _ = sync_check_interval.tick(), if *context_arc.lock().await.node_state.lock().await == NodeState::Syncing => {
                    let context = context_arc.lock().await;
                    if context.known_peers_ref.lock().await.is_empty() {
                        tracing::warn!(target: "orchestration", "Sync check: No peers found while in Syncing state. Assuming synced.");
                        let mut node_state = context.node_state.lock().await;
                        if *node_state == NodeState::Syncing {
                            *node_state = NodeState::Synced;
                            let _ = context.consensus_kick_tx.send(());
                            tracing::info!(target: "orchestration", "State -> Synced (by sync checker).");
                        }
                    }
                },

                _ = shutdown_receiver.changed() => {
                    if *shutdown_receiver.borrow() {
                        tracing::info!(target: "orchestration", "Orchestration main loop received shutdown signal.");
                        break;
                    }
                }
            }
        }
        tracing::info!(target: "orchestration", "Orchestration main loop finished.");
    }
}

// Implement Container for Orchestrator to hold start/stop/status methods
#[async_trait]
impl<CS, ST, CE, V> Container for Orchestrator<CS, ST, CE, V>
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
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
{
    fn id(&self) -> &'static str {
        "orchestration_container"
    }

    fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }

    async fn start(&self, _listen_addr: &str) -> Result<(), ValidatorError> {
        if self.is_running.load(Ordering::SeqCst) {
            return Err(ValidatorError::AlreadyRunning(self.id().to_string()));
        }
        tracing::info!(target: "orchestration", "Orchestrator starting...");

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

        let tx_model = Arc::new(UnifiedTransactionModel::new(self.scheme.clone()));

        // [NEW] Setup Ingestion Channels
        // 50k buffer allows bursting without backpressure on RPC
        let (tx_ingest_tx, tx_ingest_rx) = mpsc::channel(50_000);

        // [NEW] Setup Chain Tip Watcher
        let (tip_tx, tip_rx) = watch::channel(ChainTipInfo {
            height: 0,
            timestamp: 0,
            gas_used: 0,
            state_root: vec![],
            genesis_root: self.genesis_hash.to_vec(),
        });

        // [NEW] Setup Transaction Status Cache for Two-Phase Receipts
        // Kept outside MainLoopContext to be passed to worker
        let tx_status_cache = Arc::new(Mutex::new(LruCache::new(
            std::num::NonZeroUsize::new(100_000).unwrap(),
        )));

        // [NEW] Cache mapping Canonical Hash -> Receipt Hash (Hex String)
        let receipt_map = Arc::new(Mutex::new(LruCache::new(
            std::num::NonZeroUsize::new(100_000).unwrap(),
        )));

        // --- Public gRPC Server Start ---
        let public_service = PublicApiImpl {
            context_wrapper: self.main_loop_context.clone(),
            workload_client: workload_client.clone(),
            tx_pool: self.tx_pool.clone(),
            tx_ingest_tx, // [NEW] Pass channel sender
        };

        let rpc_addr =
            self.config.rpc_listen_address.parse().map_err(|e| {
                ValidatorError::Config(format!("Invalid RPC listen address: {}", e))
            })?;

        tracing::info!(target: "rpc", "Public gRPC API listening on {}", rpc_addr);
        eprintln!("ORCHESTRATION_RPC_LISTENING_ON_{}", rpc_addr);

        let rpc_handle = tokio::spawn(async move {
            if let Err(e) = Server::builder()
                .add_service(PublicApiServer::new(public_service))
                .serve(rpc_addr)
                .await
            {
                tracing::error!(target: "rpc", "Public API server failed: {}", e);
            }
        });

        let mut handles = self.task_handles.lock().await;
        handles.push(rpc_handle);

        // [NEW] Spawn Ingestion Worker
        // Clone dependencies for the worker task
        let ingestion_workload_client = workload_client.clone();
        let ingestion_tx_pool = self.tx_pool.clone();
        let ingestion_swarm = self.swarm_command_sender.clone();
        let ingestion_kick = self.consensus_kick_tx.clone();
        let ingestion_tx_model = tx_model.clone();
        let ingestion_cache = tx_status_cache.clone();
        let ingestion_receipt_map = receipt_map.clone(); // Pass clone

        let ingestion_handle = tokio::spawn(run_ingestion_worker(
            tx_ingest_rx,
            ingestion_workload_client,
            ingestion_tx_pool,
            ingestion_swarm,
            ingestion_kick,
            ingestion_tx_model,
            tip_rx,
            ingestion_cache,
            ingestion_receipt_map, // [NEW]
            IngestionConfig::default(),
        ));
        handles.push(ingestion_handle);

        let guardian_addr = std::env::var("GUARDIAN_ADDR").unwrap_or_default();
        if !guardian_addr.is_empty() {
            tracing::info!(target: "orchestration", "[Orchestration] Performing agentic attestation with Guardian...");
            match self
                .perform_guardian_attestation(&guardian_addr, &workload_client)
                .await
            {
                Ok(()) => {
                    tracing::info!(target: "orchestration", "[Orchestrator] Agentic attestation successful.")
                }
                Err(e) => {
                    tracing::error!(target: "orchestration", "[Orchestrator] CRITICAL: Agentic attestation failed: {}. Quarantining node.", e);
                    self.is_quarantined.store(true, Ordering::SeqCst);
                    return Err(ValidatorError::Attestation(e.to_string()));
                }
            }
        } else {
            tracing::warn!(target: "orchestration", "GUARDIAN_ADDR not set, skipping Guardian attestation.");
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

        let local_account_id = AccountId(
            account_id_from_key_material(
                SignatureSuite::Ed25519,
                &self.local_keypair.public().encode_protobuf(),
            )
            .map_err(|e| {
                ValidatorError::Config(format!("Failed to derive local account ID: {}", e))
            })?,
        );
        let nonce_key = [
            ioi_types::keys::ACCOUNT_NONCE_PREFIX,
            local_account_id.as_ref(),
        ]
        .concat();

        let initial_nonce = match workload_client.query_raw_state(&nonce_key).await {
            Ok(Some(bytes)) => {
                let arr: [u8; 8] = match bytes.try_into() {
                    Ok(a) => a,
                    Err(_) => [0; 8],
                };
                u64::from_le_bytes(arr)
            }
            _ => 0,
        };
        self.nonce_manager
            .lock()
            .await
            .insert(local_account_id, initial_nonce);
        tracing::info!(target: "orchestration", initial_nonce = initial_nonce, "Primed local nonce manager for self-generated transactions.");

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
            genesis_hash: self.genesis_hash,
            is_quarantined: self.is_quarantined.clone(),
            pending_attestations: std::collections::HashMap::new(),
            last_committed_block: None,
            consensus_kick_tx: self.consensus_kick_tx.clone(),
            sync_progress: None,
            nonce_manager: self.nonce_manager.clone(),
            signer: self.signer.clone(),
            batch_verifier: self.batch_verifier.clone(),
            // [NEW] Added fields
            tx_status_cache,
            tip_sender: tip_tx,
            receipt_map,
        };

        let mut receiver_opt = self.network_event_receiver.lock().await;
        let receiver = receiver_opt.take().ok_or(ValidatorError::Other(
            "Network event receiver already taken".to_string(),
        ))?;

        let context_arc = Arc::new(Mutex::new(context));
        *self.main_loop_context.lock().await = Some(context_arc.clone());

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
        if !self.is_running.load(Ordering::SeqCst) {
            return Ok(());
        }
        tracing::info!(target: "orchestration", "Orchestrator stopping...");
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

async fn handle_network_event<CS, ST, CE, V>(
    event: NetworkEvent,
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
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
        NetworkEvent::GossipTransaction(tx) => {
            let tx_hash = match tx.hash() {
                Ok(h) => h,
                Err(e) => {
                    tracing::warn!(target: "gossip", "Failed to hash gossiped transaction: {}", e);
                    return;
                }
            };

            let (tx_pool_ref, kick_tx) = {
                let ctx = context_arc.lock().await;
                (ctx.tx_pool_ref.clone(), ctx.consensus_kick_tx.clone())
            };

            let tx_info = match tx.as_ref() {
                ChainTransaction::System(s) => Some((s.header.account_id, s.header.nonce)),
                ChainTransaction::Application(a) => match a {
                    ioi_types::app::ApplicationTransaction::DeployContract { header, .. } => {
                        Some((header.account_id, header.nonce))
                    }
                    ioi_types::app::ApplicationTransaction::CallContract { header, .. } => {
                        Some((header.account_id, header.nonce))
                    }
                    _ => None,
                },
                _ => None,
            };

            {
                // [FIX] No lock needed, call add directly on Arc<Mempool>
                tx_pool_ref.add(*tx, tx_hash, tx_info, 0);

                log::debug!("[Orchestrator] Mempool size is now {}", tx_pool_ref.len());
                let _ = kick_tx.send(());
            }
        }
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
                tracing::info!(target: "orchestration",
                    "[Orchestrator] Skipping verification of our own gossiped block #{}.",
                    block.header.height
                );
                let _ = kick_tx.send(());
                return;
            }

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
