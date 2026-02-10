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
    consensus::{ConsensusControl, ConsensusEngine}, // [FIX] Added ConsensusControl import
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
use parity_scale_codec::{Decode, Encode};
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

use crate::standard::orchestration::mempool::Mempool;
use ioi_api::vm::drivers::os::OsDriver;
use ioi_api::vm::inference::{InferenceRuntime, LocalSafetyModel};
use ioi_scs::SovereignContextStore;

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
mod lifecycle;

/// Transition logic
pub mod transition;

use crate::config::OrchestrationConfig;
use consensus::drive_consensus_tick;
use context::{ChainFor, MainLoopContext};
use events::handle_network_event;
use futures::FutureExt;
use ingestion::{run_ingestion_worker, ChainTipInfo, IngestionConfig};
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::error::VmError;
use operator_tasks::run_oracle_operator_task;
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

    async fn load_model(&self, model_hash: [u8; 32], path: &Path) -> Result<(), VmError> {
        self.inner.load_model(model_hash, path).await
    }

    async fn unload_model(&self, model_hash: [u8; 32]) -> Result<(), VmError> {
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
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
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
    CE: ConsensusEngine<ChainTransaction> + ConsensusControl + Send + Sync + 'static, // [FIX] Added ConsensusControl bound
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
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
    CE: ConsensusEngine<ChainTransaction> + ConsensusControl + Send + Sync + 'static, // [FIX] Added ConsensusControl bound
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
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
