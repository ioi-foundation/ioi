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
use parity_scale_codec::{Decode, Encode}; // [FIX] Added imports

use ioi_api::vm::inference::LocalSafetyModel;
// [NEW] Import OsDriver trait
use ioi_api::vm::drivers::os::OsDriver;
use ioi_scs::SovereignContextStore;

pub type ChainFor<CS, ST> = Arc<
    Mutex<
        dyn ChainStateMachine<CS, ioi_tx::unified::UnifiedTransactionModel<CS>, ST> + Send + Sync,
    >,
>;

#[derive(Debug, Clone)]
pub struct SyncProgress {
    pub target: Option<PeerId>,
    pub tip: u64,
    pub next: u64,
    pub inflight: bool,
    pub req_id: u64,
}

#[derive(Debug, Clone)]
pub struct TxStatusEntry {
    pub status: TxStatus,
    pub error: Option<String>,
    pub block_height: Option<u64>,
}

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
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug + Encode + Decode, // [FIX] Added Encode + Decode
{
    pub config: OrchestrationConfig,
    pub chain_id: ioi_types::app::ChainId,
    pub genesis_hash: [u8; 32],
    pub chain_ref: ChainFor<CS, ST>,
    pub view_resolver: Arc<dyn ioi_api::chain::ViewResolver<Verifier = V>>,

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
    pub tx_status_cache: Arc<Mutex<LruCache<String, TxStatusEntry>>>,
    pub tip_sender: watch::Sender<ChainTipInfo>,
    pub receipt_map: Arc<Mutex<LruCache<TxHash, String>>>,
    pub safety_model: Arc<dyn LocalSafetyModel>,
    // [NEW] Added os_driver field
    pub os_driver: Arc<dyn OsDriver>,
    pub scs: Option<Arc<std::sync::Mutex<SovereignContextStore>>>,
    pub event_broadcaster: tokio::sync::broadcast::Sender<KernelEvent>,
}