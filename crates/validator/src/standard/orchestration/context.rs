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
use ioi_networking::libp2p::SwarmCommand;
use ioi_networking::traits::NodeState;
use ioi_types::app::KernelEvent; // [NEW]
use ioi_types::app::{AccountId, Block, ChainTransaction, OracleAttestation, TxHash};
use libp2p::{identity, PeerId};
use lru::LruCache;
use parity_scale_codec::{Decode, Encode};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Debug;
use std::sync::{atomic::AtomicBool, Arc};
use tokio::sync::{mpsc, watch, Mutex}; // [FIX] Added imports

use ioi_api::vm::inference::{InferenceRuntime, LocalSafetyModel}; // [FIX] Added InferenceRuntime
                                                                  // [NEW] Import OsDriver trait
use ioi_api::vm::drivers::os::OsDriver;
use ioi_scs::SovereignContextStore;
// [FIX] Removed unused Pacemaker import

/// Type alias for the thread-safe reference to the chain state machine.
pub type ChainFor<CS, ST> = Arc<
    Mutex<
        dyn ChainStateMachine<CS, ioi_tx::unified::UnifiedTransactionModel<CS>, ST> + Send + Sync,
    >,
>;

/// Tracks the progress of block synchronization from a specific peer.
#[derive(Debug, Clone)]
pub struct SyncProgress {
    /// The peer being synced from.
    pub target: Option<PeerId>,
    /// The target height (tip) we are trying to reach.
    pub tip: u64,
    /// The next height we need to request.
    pub next: u64,
    /// Whether a request is currently in flight.
    pub inflight: bool,
    /// Unique ID for the current request to match responses.
    pub req_id: u64,
}

/// Stores the current status of a transaction for RPC queries.
#[derive(Debug, Clone)]
pub struct TxStatusEntry {
    /// The current processing status (Pending, Committed, Rejected, etc.).
    pub status: TxStatus,
    /// Optional error message if the transaction failed.
    pub error: Option<String>,
    /// The block height where the transaction was committed, if applicable.
    pub block_height: Option<u64>,
}

/// The central context shared across the orchestrator's main event loop.
/// This struct holds references to all major components needed for consensus and networking.
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
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode, // [FIX] Added Encode + Decode
{
    /// Configuration for the orchestration node.
    pub config: OrchestrationConfig,
    /// The unique identifier for the chain.
    pub chain_id: ioi_types::app::ChainId,
    /// The hash of the genesis block.
    pub genesis_hash: [u8; 32],
    /// Reference to the chain state machine.
    pub chain_ref: ChainFor<CS, ST>,
    /// Resolver for creating state views.
    pub view_resolver: Arc<dyn ioi_api::chain::ViewResolver<Verifier = V>>,

    /// Reference to the transaction memory pool.
    pub tx_pool_ref: Arc<Mempool>,

    /// Channel for sending commands to the network swarm.
    pub swarm_commander: mpsc::Sender<SwarmCommand>,
    /// Reference to the consensus engine.
    pub consensus_engine_ref: Arc<Mutex<CE>>,
    /// Current high-level state of the node (Syncing, Synced, etc.).
    pub node_state: Arc<Mutex<NodeState>>,
    /// Local identity keypair for networking and signing.
    pub local_keypair: identity::Keypair,
    /// Optional post-quantum keypair for signing.
    pub pqc_signer: Option<MldsaKeyPair>,
    /// Set of currently connected and known peers.
    pub known_peers_ref: Arc<Mutex<HashSet<PeerId>>>,
    /// Flag indicating if the node is quarantined.
    pub is_quarantined: Arc<AtomicBool>,
    /// pending attestations for Oracle requests.
    pub pending_attestations: HashMap<u64, Vec<OracleAttestation>>,
    /// The last block committed to the local chain.
    pub last_committed_block: Option<Block<ChainTransaction>>,
    /// Channel to wake up the consensus loop.
    pub consensus_kick_tx: mpsc::UnboundedSender<()>,
    /// Current synchronization progress state.
    pub sync_progress: Option<SyncProgress>,
    /// Manager for tracking account nonces.
    pub nonce_manager: Arc<Mutex<BTreeMap<AccountId, u64>>>,
    /// The signer used for block headers (local or remote).
    pub signer: Arc<dyn GuardianSigner>,
    /// Verifier for batch signature verification.
    pub batch_verifier: Arc<dyn BatchVerifier>,
    /// Cache for transaction status queries.
    pub tx_status_cache: Arc<Mutex<LruCache<String, TxStatusEntry>>>,
    /// Watch channel for broadcasting chain tip updates.
    pub tip_sender: watch::Sender<ChainTipInfo>,
    /// Mapping of transaction hashes to their receipts.
    pub receipt_map: Arc<Mutex<LruCache<TxHash, String>>>,
    /// The local safety model for semantic analysis.
    pub safety_model: Arc<dyn LocalSafetyModel>,
    /// [NEW] The primary inference runtime (The "Brain") for intent resolution.
    pub inference_runtime: Arc<dyn InferenceRuntime>,
    /// [NEW] Added os_driver field
    /// Driver for OS-level interactions.
    pub os_driver: Arc<dyn OsDriver>,
    /// Handle to the Sovereign Context Store.
    pub scs: Option<Arc<std::sync::Mutex<SovereignContextStore>>>,
    /// [NEW] Event broadcaster for UI feedback
    /// Broadcaster for kernel events to UI subscribers.
    pub event_broadcaster: tokio::sync::broadcast::Sender<KernelEvent>,
}
