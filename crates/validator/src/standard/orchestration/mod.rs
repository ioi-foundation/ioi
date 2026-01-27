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
use ioi_api::{
    chain::WorkloadClientApi,
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    state::{StateManager, Verifier},
    validator::container::Container,
};
use ioi_client::WorkloadClient;
use ioi_crypto::sign::dilithium::MldsaKeyPair;
// [FIX] Removed unused Libp2pSync import
use ioi_networking::libp2p::{NetworkEvent, SwarmCommand};
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
use parity_scale_codec::{Decode, Encode};

use crate::common::GuardianSigner;
use crate::standard::orchestration::grpc_public::PublicApiImpl;
use ioi_ipc::public::public_api_server::PublicApiServer;
use tonic::transport::Server;

use ioi_api::vm::inference::{LocalSafetyModel, InferenceRuntime};
use ioi_api::vm::drivers::os::OsDriver; 
use ioi_scs::SovereignContextStore;
use crate::standard::orchestration::mempool::Mempool;

// --- Submodule Declarations ---
mod consensus;

/// Context structures for the orchestration main loop.
pub mod context;
mod gossip;
mod grpc_public;
mod ingestion;
/// Transaction mempool logic.
pub mod mempool;
/// Background tasks for operator logic (Oracle, Agents).
pub mod operator_tasks;
mod oracle;
mod peer_management;
mod remote_state_view;
mod sync;
/// Verifier selection logic.
pub mod verifier_select;
mod view_resolver;

mod events;
mod finalize;

use crate::config::OrchestrationConfig;
use consensus::drive_consensus_tick;
use context::{ChainFor, MainLoopContext};
use futures::FutureExt;
use ingestion::{run_ingestion_worker, ChainTipInfo, IngestionConfig};
use operator_tasks::run_oracle_operator_task;
use events::handle_network_event; 
use ioi_types::error::VmError;
use ioi_types::app::agentic::InferenceOptions;
use std::path::Path;

/// A struct to hold the numerous dependencies for the Orchestrator.
pub struct OrchestrationDependencies<CE, V> {
    /// The network synchronization engine.
    pub syncer: Arc<dyn BlockSync>, 
    /// The receiver for incoming network events.
    pub network_event_receiver: mpsc::Receiver<NetworkEvent>,
    /// The sender for commands to the network swarm.
    pub swarm_command_sender: mpsc::Sender<SwarmCommand>,
    /// The consensus engine instance.
    pub consensus_engine: CE,
    /// The node's primary cryptographic identity.
    pub local_keypair: identity::Keypair,
    /// An optional post-quantum keypair for signing.
    pub pqc_keypair: Option<MldsaKeyPair>,
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
    /// The local safety model for semantic firewall.
    pub safety_model: Arc<dyn LocalSafetyModel>,
    /// The primary inference runtime.
    pub inference_runtime: Arc<dyn InferenceRuntime>,
    /// The OS driver for context-aware policy enforcement.
    pub os_driver: Arc<dyn OsDriver>,
    /// The Sovereign Context Store handle (optional, for local nodes).
    pub scs: Option<Arc<std::sync::Mutex<SovereignContextStore>>>,
    /// Shared event broadcaster
    pub event_broadcaster: Option<tokio::sync::broadcast::Sender<ioi_types::app::KernelEvent>>,
}

type ProofCache = Arc<Mutex<LruCache<(Vec<u8>, Vec<u8>), Option<Vec<u8>>>>>;
type NetworkEventReceiver = Mutex<Option<mpsc::Receiver<NetworkEvent>>>;
type ConsensusKickReceiver = Mutex<Option<mpsc::UnboundedReceiver<()>>>;

// Wrapper for inference runtime to implement correct trait
struct RuntimeWrapper {
    inner: Arc<dyn InferenceRuntime>,
}

#[async_trait]
impl InferenceRuntime for RuntimeWrapper {
    async fn execute_inference(
        &self,
        model_hash: [u8; 32],
        input_context: &[u8],
        options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        self.inner
            .execute_inference(model_hash, input_context, options)
            .await
    }

    async fn execute_inference_streaming(
        &self,
        model_hash: [u8; 32],
        input_context: &[u8],
        options: InferenceOptions,
        token_stream: Option<tokio::sync::mpsc::Sender<String>>,
    ) -> Result<Vec<u8>, VmError> {
        self.inner
            .execute_inference_streaming(model_hash, input_context, options, token_stream)
            .await
    }

    async fn load_model(
        &self,
        model_hash: [u8; 32],
        path: &Path,
    ) -> Result<(), VmError> {
        self.inner.load_model(model_hash, path).await
    }

    async fn unload_model(
        &self,
        model_hash: [u8; 32],
    ) -> Result<(), VmError> {
        self.inner.unload_model(model_hash).await
    }
}

/// The Orchestrator is the central component of a validator node.
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
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug + Encode + Decode,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
{
    config: OrchestrationConfig,
    genesis_hash: [u8; 32],
    chain: Arc<OnceCell<ChainFor<CS, ST>>>,
    workload_client: Arc<OnceCell<Arc<WorkloadClient>>>,
    /// Local transaction pool.
    pub tx_pool: Arc<Mempool>,
    syncer: Arc<dyn BlockSync>, 
    swarm_command_sender: mpsc::Sender<SwarmCommand>,
    network_event_receiver: NetworkEventReceiver,
    consensus_engine: Arc<Mutex<CE>>,
    local_keypair: identity::Keypair,
    pqc_signer: Option<MldsaKeyPair>,
    /// Sender for shutdown signal.
    pub shutdown_sender: Arc<watch::Sender<bool>>,
    /// Handles for background tasks.
    pub task_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
    is_running: Arc<AtomicBool>,
    is_quarantined: Arc<AtomicBool>,
    proof_cache: ProofCache,
    verifier: V,
    /// Reference to the main loop context, accessible for external triggers.
    pub main_loop_context: Arc<Mutex<Option<Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>>>>,
    consensus_kick_tx: mpsc::UnboundedSender<()>,
    consensus_kick_rx: ConsensusKickReceiver,
    /// Manager for account nonces.
    pub nonce_manager: Arc<Mutex<BTreeMap<AccountId, u64>>>,
    /// Guardian signer for block headers.
    pub signer: Arc<dyn GuardianSigner>,
    _cpu_pool: Arc<rayon::ThreadPool>,
    /// Batch verifier for signatures.
    pub batch_verifier: Arc<dyn BatchVerifier>,
    scheme: CS,
    /// Safety model for semantic checks.
    pub safety_model: Arc<dyn LocalSafetyModel>,
    /// The primary inference runtime.
    pub inference_runtime: Arc<dyn InferenceRuntime>,
    /// The OS driver for context-aware policy enforcement.
    pub os_driver: Arc<dyn OsDriver>,
    /// The Sovereign Context Store handle.
    pub scs: Option<Arc<std::sync::Mutex<SovereignContextStore>>>,
    /// Shared event broadcaster.
    pub event_broadcaster: Option<tokio::sync::broadcast::Sender<ioi_types::app::KernelEvent>>,
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
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug + Encode + Decode,
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
            tx_pool: Arc::new(Mempool::new()),
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
            safety_model: deps.safety_model,
            inference_runtime: deps.inference_runtime,
            os_driver: deps.os_driver,
            scs: deps.scs, 
            event_broadcaster: deps.event_broadcaster,
        })
    }

    /// Sets the `Chain` and `WorkloadClient` references initialized after container creation.
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

        let mut stream = guardian_channel
            .take_stream()
            .await
            .ok_or_else(|| anyhow!("Failed to take stream from Guardian channel"))?;

        let len = stream.read_u32().await?;
        const MAX_REPORT_SIZE: u32 = 10 * 1024 * 1024;
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

        let expected_hash = workload_client.get_expected_model_hash().await?;
        if report.agentic_hash != expected_hash {
            return Err(anyhow!(
                "Model Integrity Failure! Local hash {} != on-chain hash {}",
                hex::encode(&report.agentic_hash),
                hex::encode(expected_hash)
            ));
        }

        let payload_bytes =
            codec::to_bytes_canonical(&report.binary_attestation).map_err(|e| anyhow!(e))?;

        let sys_payload = SystemPayload::CallService {
            service_id: "identity_hub".to_string(),
            method: "register_attestation@v1".to_string(),
            params: payload_bytes,
        };

        let our_pk = self.local_keypair.public().encode_protobuf();
        let our_account_id = AccountId(
            account_id_from_key_material(SignatureSuite::ED25519, &our_pk)
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
                session_auth: None,
            },
            payload: sys_payload,
            signature_proof: SignatureProof::default(),
        };

        let sign_bytes = sys_tx.to_sign_bytes().map_err(|e| anyhow!(e))?;
        let signature = self.local_keypair.sign(&sign_bytes)?;

        sys_tx.signature_proof = SignatureProof {
            suite: SignatureSuite::ED25519,
            public_key: our_pk,
            signature,
        };

        let tx = ChainTransaction::System(Box::new(sys_tx));
        let tx_hash = tx.hash()?;

        let committed_nonce = 0;
        self.tx_pool
            .add(tx, tx_hash, Some((our_account_id, nonce)), committed_nonce);

        Ok(())
    }

    async fn run_consensus_ticker(
        context_arc: Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
        mut kick_rx: mpsc::UnboundedReceiver<()>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) {
        // [INSTRUMENTATION] Log ticker start
        tracing::info!(target: "consensus", "Consensus ticker task started. Waiting for context lock...");
        let interval_secs = {
            let ctx = context_arc.lock().await;
            std::env::var("ORCH_BLOCK_INTERVAL_SECS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or_else(|| ctx.config.block_production_interval_secs)
        };
        tracing::info!(target: "consensus", "Consensus ticker acquired config. Interval: {}s", interval_secs);

        if interval_secs == 0 {
            tracing::info!(target: "consensus", "Consensus ticker disabled (interval=0).");
            let _ = shutdown_rx.changed().await;
            return;
        }

        let mut ticker = time::interval(Duration::from_secs(interval_secs));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

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
                        continue;
                    }
                    last_tick = tokio::time::Instant::now();
                    
                    // [INSTRUMENTATION] Log tick trigger
                    tracing::info!(target: "consensus", "Consensus timer tick triggered.");
                    
                    let result = AssertUnwindSafe(drive_consensus_tick(&context_arc, cause)).catch_unwind().await;
                    if let Err(e) = result.map_err(|e| anyhow!("Consensus tick panicked: {:?}", e)).and_then(|res| res) {
                        tracing::error!(target: "consensus", "[Orch Tick] Consensus tick failed: {:?}. Continuing loop.", e);
                    }
                }
                Some(()) = kick_rx.recv() => {
                    let mut _count = 1;
                    while let Ok(_) = kick_rx.try_recv() { _count += 1; }
                    let cause = "kick";
                    let is_quarantined = context_arc.lock().await.is_quarantined.load(Ordering::SeqCst);
                    if is_quarantined || last_tick.elapsed() < min_block_time {
                         continue;
                    }
                    last_tick = tokio::time::Instant::now();
                    
                    // [INSTRUMENTATION] Log kick trigger
                    tracing::debug!(target: "consensus", "Consensus kicked.");
                    
                    let result = AssertUnwindSafe(drive_consensus_tick(&context_arc, cause)).catch_unwind().await;
                     if let Err(e) = result.map_err(|e| anyhow!("Kicked consensus tick panicked: {:?}", e)).and_then(|res| res) {
                        tracing::error!(target: "consensus", "[Orch Tick] Kicked failed: {:?}.", e);
                    }
                }
                 _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() { break; }
                }
            }
        }
    }

    async fn run_sync_discoverer(
        context_arc: Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) {
        let interval_secs = {
            let ctx = context_arc.lock().await;
            ctx.config.initial_sync_timeout_secs
        };

        if interval_secs == 0 {
            tracing::info!(target: "orchestration", "Sync discoverer disabled (interval=0).");
            let _ = shutdown_rx.changed().await;
            return;
        }

        let mut interval = time::interval(Duration::from_secs(interval_secs));
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
                        if swarm_commander.send(SwarmCommand::SendStatusRequest(random_peer)).await.is_err() {
                            log::warn!("Failed to send periodic status request to swarm.");
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() { break; }
                }
            }
        }
    }

    async fn run_main_loop(
        mut network_event_receiver: mpsc::Receiver<NetworkEvent>,
        mut shutdown_receiver: watch::Receiver<bool>,
        context_arc: Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    ) {
        let sync_timeout = {
            let ctx = context_arc.lock().await;
            ctx.config.initial_sync_timeout_secs
        };

        if sync_timeout == 0 {
            let context = context_arc.lock().await;
            let mut ns = context.node_state.lock().await;
            if *ns == NodeState::Syncing || *ns == NodeState::Initializing {
                *ns = NodeState::Synced;
                let _ = context.consensus_kick_tx.send(());
                tracing::info!(target: "orchestration", "State -> Synced (direct/local mode).");
            }
        } else {
            let context = context_arc.lock().await;
            *context.node_state.lock().await = NodeState::Syncing;
            tracing::info!(target: "orchestration", "State -> Syncing.");
        }

        let mut sync_check_interval_opt = if sync_timeout > 0 {
            let mut i = time::interval(Duration::from_secs(sync_timeout));
            i.set_missed_tick_behavior(MissedTickBehavior::Delay);
            Some(i)
        } else {
            None
        };

        let mut operator_ticker = time::interval(Duration::from_secs(10));
        operator_ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                biased;

                Some(event) = network_event_receiver.recv() => {
                    handle_network_event(event, &context_arc).await;
                }

                _ = operator_ticker.tick() => {
                    let ctx = context_arc.lock().await;
                    if let Err(e) = run_oracle_operator_task(&ctx).await {
                         tracing::error!(target: "operator_task", "Oracle operator failed: {}", e);
                    }
                }

                _ = async {
                    if let Some(ref mut i) = sync_check_interval_opt {
                        i.tick().await
                    } else {
                        futures::future::pending().await
                    }
                }, if *context_arc.lock().await.node_state.lock().await == NodeState::Syncing => {
                    let context = context_arc.lock().await;
                    if context.known_peers_ref.lock().await.is_empty() {
                        let mut node_state = context.node_state.lock().await;
                        if *node_state == NodeState::Syncing {
                            *node_state = NodeState::Synced;
                            let _ = context.consensus_kick_tx.send(());
                            tracing::info!(target: "orchestration", "State -> Synced (no peers).");
                        }
                    }
                },

                _ = shutdown_receiver.changed() => {
                    if *shutdown_receiver.borrow() { break; }
                }
            }
        }
    }

    async fn start_internal(&self, _listen_addr: &str) -> Result<(), ValidatorError> {
        if self.is_running.load(Ordering::SeqCst) {
            return Err(ValidatorError::AlreadyRunning("orchestration".to_string()));
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

        // --- NEW: Hydrate Chain Tip from Store ---
        let mut initial_block = None;
        match workload_client.get_status().await {
            Ok(status) => {
                if status.height > 0 {
                    tracing::info!(target: "orchestration", "Recovering chain state from height {}", status.height);
                    match workload_client.get_block_by_height(status.height).await {
                        Ok(Some(block)) => {
                            initial_block = Some(block);
                            tracing::info!(target: "orchestration", "Hydrated last_committed_block (Height {})", status.height);
                        }
                        Ok(None) => {
                            tracing::warn!(target: "orchestration", "Status says height {}, but block not found in store!", status.height);
                        }
                        Err(e) => {
                            tracing::error!(target: "orchestration", "Failed to fetch head block: {}", e);
                            return Err(ValidatorError::Other(e.to_string()));
                        }
                    }
                }
            }
            Err(e) => {
                return Err(ValidatorError::Other(format!(
                    "Failed to get initial chain status: {}",
                    e
                )));
            }
        }
        // ------------------------------------------

        let tx_model = Arc::new(UnifiedTransactionModel::new(self.scheme.clone()));
        let (tx_ingest_tx, tx_ingest_rx) = mpsc::channel(50_000);
        
        let initial_tip = if let Some(b) = &initial_block {
             ChainTipInfo {
                height: b.header.height,
                timestamp: b.header.timestamp,
                gas_used: b.header.gas_used,
                state_root: b.header.state_root.0.clone(),
                genesis_root: self.genesis_hash.to_vec(),
             }
        } else {
             ChainTipInfo {
                height: 0,
                timestamp: 0, 
                gas_used: 0,
                state_root: vec![],
                genesis_root: self.genesis_hash.to_vec(),
             }
        };

        let (tip_tx, tip_rx) = watch::channel(initial_tip);
        let tx_status_cache = Arc::new(Mutex::new(LruCache::new(
            std::num::NonZeroUsize::new(100_000).unwrap(),
        )));
        let receipt_map = Arc::new(Mutex::new(LruCache::new(
            std::num::NonZeroUsize::new(100_000).unwrap(),
        )));
        let public_service = PublicApiImpl {
            context_wrapper: self.main_loop_context.clone(),
            workload_client: workload_client.clone(),
            tx_ingest_tx,
        };

        let rpc_addr = self
            .config
            .rpc_listen_address
            .parse()
            .map_err(|e| ValidatorError::Config(format!("Invalid RPC address: {}", e)))?;

        tracing::info!(target: "rpc", "Public gRPC API listening on {}", rpc_addr);
        eprintln!("ORCHESTRATION_RPC_LISTENING_ON_{}", rpc_addr);

        let mut shutdown_rx = self.shutdown_sender.subscribe();

        let rpc_handle = tokio::spawn(async move {
            if let Err(e) = Server::builder()
                .add_service(PublicApiServer::new(public_service))
                .serve_with_shutdown(rpc_addr, async move {
                    let _ = shutdown_rx.changed().await;
                })
                .await
            {
                tracing::error!(target: "rpc", "Public API server failed: {}", e);
            }
        });

        let mut handles = self.task_handles.lock().await;
        handles.push(rpc_handle);

        let (event_tx, _event_rx_guard) = if let Some(tx) = &self.event_broadcaster {
            (tx.clone(), None)
        } else {
            let (tx, rx) = tokio::sync::broadcast::channel(1000);
            (tx, Some(rx))
        };

        let ingestion_handle = tokio::spawn(run_ingestion_worker(
            tx_ingest_rx,
            workload_client.clone(),
            self.tx_pool.clone(),
            self.swarm_command_sender.clone(),
            self.consensus_kick_tx.clone(),
            tx_model.clone(),
            tip_rx,
            tx_status_cache.clone(),
            receipt_map.clone(),
            self.safety_model.clone(),
            self.os_driver.clone(),
            IngestionConfig::default(),
            event_tx.clone(),
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
                SignatureSuite::ED25519,
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
            last_committed_block: initial_block,
            consensus_kick_tx: self.consensus_kick_tx.clone(),
            sync_progress: None,
            nonce_manager: self.nonce_manager.clone(),
            signer: self.signer.clone(),
            batch_verifier: self.batch_verifier.clone(),
            tx_status_cache: tx_status_cache.clone(),
            tip_sender: tip_tx,
            receipt_map: receipt_map.clone(),
            safety_model: self.safety_model.clone(),
            inference_runtime: Arc::new(RuntimeWrapper {
                inner: self.inference_runtime.clone()
            }), // [FIX] Use wrapped runtime
            os_driver: self.os_driver.clone(),
            scs: self.scs.clone(),
            event_broadcaster: event_tx, 
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

        let shutdown_rx = self.shutdown_sender.subscribe();

        handles.push(tokio::spawn(Self::run_consensus_ticker(
            context_arc.clone(),
            ticker_kick_rx,
            shutdown_rx.clone(),
        )));
        handles.push(tokio::spawn(Self::run_sync_discoverer(
            context_arc.clone(),
            shutdown_rx.clone(),
        )));
        handles.push(tokio::spawn(Self::run_main_loop(
            receiver,
            shutdown_rx,
            context_arc,
        )));

        self.is_running.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn stop_internal(&self) -> Result<(), ValidatorError> {
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
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug + Encode + Decode,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
{
    async fn start(&self, listen_addr: &str) -> Result<(), ValidatorError> {
        self.start_internal(listen_addr).await
    }

    async fn stop(&self) -> Result<(), ValidatorError> {
        self.stop_internal().await
    }

    fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }

    fn id(&self) -> &'static str {
        "orchestration"
    }
}