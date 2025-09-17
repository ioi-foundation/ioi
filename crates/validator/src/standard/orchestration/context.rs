// Path: crates/validator/src/standard/orchestration/context.rs
use crate::config::OrchestrationConfig;
use depin_sdk_api::{
    chain::AppChain,
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    state::{StateManager, Verifier},
};
use depin_sdk_client::WorkloadClient;
use depin_sdk_crypto::sign::dilithium::DilithiumKeyPair;
use depin_sdk_network::libp2p::SwarmCommand;
use depin_sdk_network::traits::NodeState;
use depin_sdk_services::external_data::ExternalDataService;
use depin_sdk_types::app::{Block, ChainTransaction, OracleAttestation, StateRoot};
use libp2p::{identity, PeerId};
use lru::LruCache;
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Debug;
use std::sync::{atomic::AtomicBool, Arc};
use tokio::sync::{mpsc, Mutex};

pub type ChainFor<CS, ST> = Arc<
    Mutex<
        dyn AppChain<CS, depin_sdk_transaction_models::unified::UnifiedTransactionModel<CS>, ST>
            + Send
            + Sync,
    >,
>;

/// Main state for the Orchestration Container's event loop.
pub struct MainLoopContext<CS, ST, CE, V>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof> + Clone + Send + Sync + 'static,
{
    pub chain_ref: ChainFor<CS, ST>,
    pub workload_client: Arc<WorkloadClient>,
    pub tx_pool_ref: Arc<Mutex<VecDeque<ChainTransaction>>>,
    pub swarm_commander: mpsc::Sender<SwarmCommand>,
    pub consensus_engine_ref: Arc<Mutex<CE>>,
    pub node_state: Arc<Mutex<NodeState>>,
    pub local_keypair: identity::Keypair,
    pub pqc_signer: Option<DilithiumKeyPair>,
    pub known_peers_ref: Arc<Mutex<HashSet<PeerId>>>,
    pub config: OrchestrationConfig,
    pub is_quarantined: Arc<AtomicBool>,
    pub external_data_service: ExternalDataService,
    pub pending_attestations: HashMap<u64, Vec<OracleAttestation>>,
    /// The root of the initial (genesis) state.
    pub genesis_root: StateRoot,
    /// The most recent block that has been successfully processed and committed.
    pub last_committed_block: Option<Block<ChainTransaction>>,
    /// The stateless verifier for remote state proofs.
    pub verifier: V,
    /// A cache for verified remote state proofs to reduce redundant IPC/verification.
    pub proof_cache_ref: Arc<Mutex<LruCache<(Vec<u8>, Vec<u8>), Option<Vec<u8>>>>>,
    /// Kick the consensus ticker (RPC, gossip, etc. use this).
    pub consensus_kick_tx: mpsc::UnboundedSender<()>,
}
