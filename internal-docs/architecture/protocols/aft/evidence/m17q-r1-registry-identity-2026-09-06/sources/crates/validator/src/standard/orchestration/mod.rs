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
use ioi_networking::libp2p::{
    pq_channel::PqChannelLocalConfig, NetworkEvent, QuvNetworkEvent, SwarmCommand,
};
use ioi_networking::traits::NodeState;
use ioi_networking::BlockSync;
use ioi_tx::unified::UnifiedTransactionModel;
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ChainTransaction, GuardianReport, QuvCandidateV0,
        QuvPushQueryV0, SignHeader, SignatureProof, SignatureSuite, SystemPayload,
        SystemTransaction,
    },
    codec,
    error::ValidatorError,
};
use libp2p::identity;
use lru::LruCache;
use parity_scale_codec::{Decode, Encode};
use rand::{rngs::OsRng, seq::SliceRandom, RngCore};
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
use ioi_memory::MemoryRuntime;

// --- Submodule Declarations ---
pub(crate) mod aft_collapse;
mod consensus;

/// Context structures for the orchestration main loop.
pub mod context;
mod gossip;
mod grpc_public;
mod hash_async;
mod ingestion;
/// Transaction mempool logic.
pub mod mempool;
/// Background tasks for operator logic (Oracle, Agents).
pub mod operator_tasks;
mod oracle;
mod peer_management;
mod quv;
mod remote_state_view;
mod sync;
/// Verifier selection logic.
pub mod verifier_select;
mod view_resolver;

mod events;
mod finalize;
mod lifecycle;
pub(crate) mod runtime_finality;

/// Transition logic
pub mod transition;

pub(crate) fn consensus_kick_debounce_ms() -> u64 {
    std::env::var("IOI_INGESTION_CONSENSUS_KICK_DEBOUNCE_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
}

pub(crate) fn schedule_consensus_kick(
    sender: &mpsc::UnboundedSender<()>,
    scheduled: &Arc<AtomicBool>,
) {
    let debounce_ms = consensus_kick_debounce_ms();
    if debounce_ms == 0 {
        let _ = sender.send(());
        return;
    }

    if !scheduled.swap(true, Ordering::SeqCst) {
        let sender = sender.clone();
        let scheduled = Arc::clone(scheduled);
        tokio::spawn(async move {
            time::sleep(Duration::from_millis(debounce_ms)).await;
            let _ = sender.send(());
            scheduled.store(false, Ordering::SeqCst);
        });
    }
}

use crate::config::OrchestrationConfig;
use consensus::drive_consensus_tick;
use context::{ChainFor, MainLoopContext};
use events::handle_network_event;
use futures::FutureExt;
use ingestion::{run_ingestion_worker, ChainTipInfo, IngestionConfig};
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::error::VmError;
use std::path::{Path, PathBuf};

/// A struct to hold the numerous dependencies for the Orchestrator.
pub struct OrchestrationDependencies<CE, V> {
    /// The network synchronization engine.
    pub syncer: Arc<dyn BlockSync>,
    /// The receiver for incoming network events.
    pub network_event_receiver: mpsc::Receiver<NetworkEvent>,
    /// Isolated timing-critical QUV request/reply lane.
    pub quv_network_event_receiver: mpsc::Receiver<QuvNetworkEvent>,
    /// The sender for commands to the network swarm.
    pub swarm_command_sender: mpsc::Sender<SwarmCommand>,
    /// Isolated timing-critical QUV command lane.
    pub quv_swarm_command_sender: mpsc::Sender<SwarmCommand>,
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
    /// Optional runtime-backed memory store for transcript and artifact retrieval.
    pub memory_runtime: Option<Arc<MemoryRuntime>>,
    /// Shared event broadcaster
    pub event_broadcaster: Option<tokio::sync::broadcast::Sender<ioi_types::app::KernelEvent>>,
    /// Local durable root for the Agentgres finality spine and inert staging.
    pub runtime_finality_root: PathBuf,
}

type ProofCache = Arc<Mutex<LruCache<(Vec<u8>, Vec<u8>), Option<Vec<u8>>>>>;
type NetworkEventReceiver = Mutex<Option<mpsc::Receiver<NetworkEvent>>>;
type QuvNetworkEventReceiver = Mutex<Option<mpsc::Receiver<QuvNetworkEvent>>>;
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
    quv_swarm_command_sender: mpsc::Sender<SwarmCommand>,
    network_event_receiver: NetworkEventReceiver,
    quv_network_event_receiver: QuvNetworkEventReceiver,
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
    /// Optional runtime-backed memory store for transcript and artifact retrieval.
    pub memory_runtime: Option<Arc<MemoryRuntime>>,
    /// Shared event broadcaster.
    pub event_broadcaster: Option<tokio::sync::broadcast::Sender<ioi_types::app::KernelEvent>>,
    runtime_finality_root: PathBuf,
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
            quv_swarm_command_sender: deps.quv_swarm_command_sender,
            network_event_receiver: Mutex::new(Some(deps.network_event_receiver)),
            quv_network_event_receiver: Mutex::new(Some(deps.quv_network_event_receiver)),
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
            memory_runtime: deps.memory_runtime,
            event_broadcaster: deps.event_broadcaster,
            runtime_finality_root: deps.runtime_finality_root,
        })
    }

    /// Execute an online-QUV effect through the sole Agentgres mutation
    /// boundary. The candidate is checked against the durable effect manifest
    /// before it is written to members, and the process-local authorization is
    /// consumed immediately before Agentgres enters `Claimed`.
    ///
    /// A transcript or cached success indication cannot call this path: only
    /// the non-serializable token returned by this process's live operation is
    /// accepted by `ConsequenceStore`.
    /// Takes ownership of the store so neither fair queueing nor the online
    /// network wait holds its exclusive filesystem lock. Callers may reopen
    /// the same path after completion; every reopen revalidates durable state.
    pub async fn execute_query_unanimity_effect(
        &self,
        consequence_store: agentgres::consequence::ConsequenceStore,
        effect_id: &str,
        resource: &mut dyn agentgres::consequence::ExternalResourceV1,
        candidate: QuvCandidateV0,
    ) -> Result<agentgres::consequence::ConsequenceReceiptV1> {
        let consequence_root = consequence_store.path().to_path_buf();
        drop(consequence_store);
        let context = self
            .main_loop_context
            .lock()
            .await
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow!("orchestrator is not running"))?;
        let (runtime_finality, receipt_gate) = {
            let context = context.lock().await;
            (
                context.runtime_finality.clone(),
                context.aft_quv_admission.clone(),
            )
        };
        let mut admission = runtime_finality
            .lock()
            .await
            .committed_consequence_manifest(effect_id)?;
        let mut current_height;
        let receipt_domain = admission
            .manifest
            .conflict_domain_commitment()
            .map_err(anyhow::Error::new)?;
        let mut receipt_access = receipt_gate.receipt_access(receipt_domain).await?;
        let mut consequence_store =
            agentgres::consequence::ConsequenceStore::open(&consequence_root)
                .map_err(anyhow::Error::new)?;
        {
            let finality = runtime_finality.lock().await;
            admission = finality.committed_consequence_manifest(effect_id)?;
            current_height = finality
                .last_admitted_block()?
                .map(|block| block.header.height)
                .unwrap_or(admission.admitted_height);
            if admission
                .manifest
                .conflict_domain_commitment()
                .map_err(anyhow::Error::new)?
                != receipt_domain
            {
                return Err(anyhow!("queued receipt domain changed"));
            }
        }
        if resource.profile() != &admission.manifest.resource_profile {
            return Err(anyhow!(
                "executor resource differs from the Agentgres-admitted manifest"
            ));
        }
        let (authorization, achieved) = agentgres::consequence::AcceptedEffectAuthorizationV1::from_committed_with_resource_contract(
            &admission.committed,
            &admission.manifest,
        )
        .map_err(anyhow::Error::new)?;
        let needs_live = consequence_store
            .inspect_online_effect(
                admission.manifest.clone(),
                &achieved,
                &authorization,
                current_height,
                quv::effect_candidate_binding(&candidate),
            )
            .map_err(anyhow::Error::new)?;
        let reserved = if needs_live {
            let mut verifier_nonce = [0_u8; 32];
            OsRng.fill_bytes(&mut verifier_nonce);
            drop(consequence_store);
            drop(receipt_access);
            let reserved = quv::reserve_online_authorization(
                &context,
                QuvPushQueryV0 {
                    verifier_nonce,
                    candidate: candidate.clone(),
                },
            )
            .await?;
            receipt_access = receipt_gate.owned_receipt_access().await?;
            consequence_store = agentgres::consequence::ConsequenceStore::open(&consequence_root)
                .map_err(anyhow::Error::new)?;
            let finality = runtime_finality.lock().await;
            admission = finality.committed_consequence_manifest(effect_id)?;
            current_height = finality
                .last_admitted_block()?
                .map(|block| block.header.height)
                .unwrap_or(0);
            Some(reserved)
        } else {
            None
        };
        if resource.profile() != &admission.manifest.resource_profile {
            return Err(anyhow!(
                "executor resource differs from the Agentgres-admitted manifest"
            ));
        }
        let (authorization, achieved) = agentgres::consequence::AcceptedEffectAuthorizationV1::from_committed_with_resource_contract(
            &admission.committed, &admission.manifest,
        ).map_err(anyhow::Error::new)?;
        let needs_live = consequence_store
            .prepare_online_effect_checked(
                admission.manifest.clone(),
                &achieved,
                &authorization,
                current_height,
                quv::effect_candidate_binding(&candidate),
                async {
                    reserved
                        .as_ref()
                        .ok_or_else(|| {
                            agentgres::consequence::ConsequenceError::Invalid(
                                "executable receipt appeared without operation admission".into(),
                            )
                        })?
                        .check_service()
                        .map_err(|error| {
                            agentgres::consequence::ConsequenceError::Invalid(error.to_string())
                        })?;
                    quv::preflight_effect_candidate(&context, &candidate)
                        .await
                        .map_err(|error| {
                            agentgres::consequence::ConsequenceError::Invalid(error.to_string())
                        })
                },
            )
            .await
            .map_err(anyhow::Error::new)?;
        if needs_live {
            reserved
                .as_ref()
                .ok_or_else(|| anyhow!("missing operation admission"))?
                .check_service()?;
            resource
                .prepare(&admission.manifest)
                .map_err(anyhow::Error::new)?;
        }

        if let Some(receipt) = consequence_store
            .online_retry_result(effect_id, resource)
            .map_err(anyhow::Error::new)?
        {
            return Ok(receipt);
        }

        let reserved = reserved.ok_or_else(|| anyhow!("missing operation admission"))?;
        drop(consequence_store);
        drop(receipt_access);
        let receiver = quv::start_reserved_authorization(&context, reserved).await?;
        let authorization = receiver
            .await
            .map_err(|_| anyhow!("QUV online operation terminated without a decision"))??;
        let _receipt_access = receipt_gate.owned_receipt_access().await?;
        let mut consequence_store =
            agentgres::consequence::ConsequenceStore::open(&consequence_root)
                .map_err(anyhow::Error::new)?;
        // Re-derive from committed admission after the network wait, and keep
        // that admission/height stable through the synchronous claim/call.
        let finality = runtime_finality.lock().await;
        let admission = finality.committed_consequence_manifest(effect_id)?;
        let current_height = finality
            .last_admitted_block()?
            .map(|block| block.header.height)
            .unwrap_or(0);
        let (admitted_authorization, achieved) = agentgres::consequence::AcceptedEffectAuthorizationV1::from_committed_with_resource_contract(
            &admission.committed,
            &admission.manifest,
        )
        .map_err(anyhow::Error::new)?;
        consequence_store
            .prepare_online_effect(
                admission.manifest,
                &achieved,
                &admitted_authorization,
                current_height,
            )
            .map_err(anyhow::Error::new)?;
        let result = match consequence_store
            .online_retry_result(effect_id, resource)
            .map_err(anyhow::Error::new)?
        {
            Some(receipt) => Ok(receipt),
            None => authorization.with_continuation(|authorization| {
                consequence_store
                    .execute_with_online_authorization(
                        effect_id,
                        resource,
                        authorization,
                        current_height,
                    )
                    .map_err(anyhow::Error::new)
            }),
        };
        drop(finality);
        result
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
