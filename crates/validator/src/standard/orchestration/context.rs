// Path: crates/validator/src/standard/orchestration/context.rs

use crate::common::GuardianSigner;
use crate::config::OrchestrationConfig;
use crate::standard::orchestration::ingestion::ChainTipInfo;
use crate::standard::orchestration::mempool::Mempool;
use ioi_api::crypto::BatchVerifier;
use ioi_api::{
    chain::ChainStateMachine, commitment::CommitmentScheme, consensus::ConsensusEngine,
    state::StateManager,
};
use ioi_crypto::sign::dilithium::MldsaKeyPair;
use ioi_ipc::public::TxStatus;
// [NEW] Import ChainEvent - Note: The instruction mentions KernelEvent, but the plan used KernelEvent.
// The file previously imported ioi_ipc::public::ChainEvent.
// I will import KernelEvent from ioi_types based on step 1.1.
use ioi_types::app::KernelEvent;
use ioi_networking::libp2p::SwarmCommand;
use ioi_networking::traits::NodeState;
use ioi_types::app::{AccountId, Block, ChainTransaction, OracleAttestation, TxHash};
use libp2p::{identity, PeerId};
use lru::LruCache;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Debug;
use std::sync::{atomic::AtomicBool, Arc};
use tokio::sync::{mpsc, watch, Mutex};

// [FIX] Import LocalSafetyModel trait from API
use ioi_api::vm::inference::LocalSafetyModel;
// [NEW] Import SCS for Blob Retrieval
use ioi_scs::SovereignContextStore;

/// A type alias for the thread-safe, dynamically dispatched chain state machine.
pub type ChainFor<CS, ST> = Arc<
    Mutex<
        dyn ChainStateMachine<CS, ioi_tx::unified::UnifiedTransactionModel<CS>, ST> + Send + Sync,
    >,
>;

/// Tracks the state of a multi-block sync process with a target peer.
#[derive(Debug, Clone)]
pub struct SyncProgress {
    pub target: Option<PeerId>,
    pub tip: u64,
    pub next: u64, // The height of the last block we have successfully processed.
    pub inflight: bool,
    pub req_id: u64,
}

/// Stores the current lifecycle status of a transaction for client polling.
#[derive(Debug, Clone)]
pub struct TxStatusEntry {
    pub status: TxStatus,
    pub error: Option<String>,
    pub block_height: Option<u64>,
}

/// The central, shared state for the Orchestration container's main event loop.
///
/// This struct holds all the necessary components for coordinating consensus, networking,
/// and state transitions, wrapped in thread-safe containers (`Arc`, `Mutex`) to allow
/// concurrent access from multiple background tasks.
pub struct MainLoopContext<CS, ST, CE, V>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
{
    pub config: OrchestrationConfig,
    pub chain_id: ioi_types::app::ChainId,
    pub genesis_hash: [u8; 32],
    pub chain_ref: ChainFor<CS, ST>,
    pub view_resolver: Arc<dyn ioi_api::chain::ViewResolver<Verifier = V>>,

    /// The sharded, high-performance mempool. Wrapped in `Arc` for shared access.
    pub tx_pool_ref: Arc<Mempool>,

    pub swarm_commander: mpsc::Sender<SwarmCommand>,
    pub consensus_engine_ref: Arc<Mutex<CE>>,
    pub node_state: Arc<Mutex<NodeState>>,
    pub local_keypair: identity::Keypair,
    pub pqc_signer: Option<MldsaKeyPair>,
    pub known_peers_ref: Arc<Mutex<HashSet<PeerId>>>,
    pub is_quarantined: Arc<AtomicBool>,
    pub pending_attestations: HashMap<u64, Vec<OracleAttestation>>,
    pub last_committed_block: Option<Block<ChainTransaction>>,
    pub consensus_kick_tx: mpsc::UnboundedSender<()>,
    pub sync_progress: Option<SyncProgress>,
    pub nonce_manager: Arc<Mutex<BTreeMap<AccountId, u64>>>,
    pub signer: Arc<dyn GuardianSigner>,
    pub batch_verifier: Arc<dyn BatchVerifier>,

    // [NEW] Shared handle to the loaded safety model
    pub safety_model: Arc<dyn LocalSafetyModel>,

    // --- Ingestion & Async Status Tracking ---
    /// Cache for tracking transaction fate (PENDING -> MEMPOOL -> COMMITTED/REJECTED).
    /// Used by the Public gRPC API's `GetTransactionStatus` method.
    pub tx_status_cache: Arc<Mutex<LruCache<String, TxStatusEntry>>>,

    /// Reverse mapping used during block finalization to link canonical hashes back to
    /// the receipt hashes provided to the client.
    pub receipt_map: Arc<Mutex<LruCache<TxHash, String>>>,

    /// Broadcast channel to notify the Ingestion Worker of the latest chain tip,
    /// enabling correct nonce fetching and timestamp pre-checks.
    pub tip_sender: watch::Sender<ChainTipInfo>,

    // [NEW] Global event bus for the GUI (Capacity ~1000)
    // Used to stream live updates (Thought process, Firewall interceptions, Block commits)
    // to the Desktop Agent frontend.
    pub event_broadcaster: tokio::sync::broadcast::Sender<KernelEvent>,

    // [NEW] Handle to the Sovereign Context Substrate.
    // Allows the Orchestrator to serve raw blobs (screenshots) to the GUI.
    // Using std::sync::Mutex to match the SCS implementation.
    pub scs: Option<Arc<std::sync::Mutex<SovereignContextStore>>>,
}