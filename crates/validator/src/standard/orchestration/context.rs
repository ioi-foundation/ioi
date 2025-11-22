// Path: crates/validator/src/standard/orchestration/context.rs
use crate::config::OrchestrationConfig;
use ioi_api::{
    chain::ChainStateMachine, commitment::CommitmentScheme, consensus::ConsensusEngine,
    state::StateManager,
};
use ioi_crypto::sign::dilithium::DilithiumKeyPair;
use ioi_networking::libp2p::SwarmCommand;
use ioi_networking::traits::NodeState;
use ioi_types::app::{AccountId, Block, ChainTransaction, OracleAttestation, TxHash}; // Added TxHash
// REMOVED: use crate::standard::orchestration::tx_hash::TxHash;
use libp2p::{identity, PeerId};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt::Debug;
use std::sync::{atomic::AtomicBool, Arc};
use tokio::sync::{mpsc, Mutex};

pub type ChainFor<CS, ST> = Arc<
    Mutex<
        dyn ChainStateMachine<CS, ioi_tx::unified::UnifiedTransactionModel<CS>, ST> + Send + Sync,
    >,
>;

#[derive(Debug, Clone)]
pub struct SyncProgress {
    pub target: Option<PeerId>,
    pub tip: u64,
    pub next: u64, // We have blocks up to and including this height.
    pub inflight: bool,
    pub req_id: u64,
}

/// Main state for the Orchestration Container's event loop.
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
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
{
    pub config: OrchestrationConfig,
    pub chain_id: ioi_types::app::ChainId,
    pub genesis_hash: [u8; 32],
    pub chain_ref: ChainFor<CS, ST>,
    pub view_resolver: Arc<dyn ioi_api::chain::ViewResolver<Verifier = V>>,
    // MODIFIED: Mempool now stores transactions with their computed hashes.
    pub tx_pool_ref: Arc<Mutex<VecDeque<(ChainTransaction, TxHash)>>>,
    pub swarm_commander: mpsc::Sender<SwarmCommand>,
    pub consensus_engine_ref: Arc<Mutex<CE>>,
    pub node_state: Arc<Mutex<NodeState>>,
    pub local_keypair: identity::Keypair,
    pub pqc_signer: Option<DilithiumKeyPair>,
    pub known_peers_ref: Arc<Mutex<HashSet<PeerId>>>,
    pub is_quarantined: Arc<AtomicBool>,
    pub pending_attestations: HashMap<u64, Vec<OracleAttestation>>,
    pub last_committed_block: Option<Block<ChainTransaction>>,
    pub consensus_kick_tx: mpsc::UnboundedSender<()>,
    pub sync_progress: Option<SyncProgress>,
    /// A local, atomically-managed nonce for self-generated transactions.
    pub nonce_manager: Arc<Mutex<BTreeMap<AccountId, u64>>>,
}