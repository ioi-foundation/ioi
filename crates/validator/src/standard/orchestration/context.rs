// Path: crates/validator/src/standard/orchestration/context.rs
use crate::config::OrchestrationConfig;
use depin_sdk_api::{
    chain::AppChain, commitment::CommitmentScheme, consensus::ConsensusEngine, state::StateManager,
};
use depin_sdk_client::WorkloadClient;
use depin_sdk_network::{
    libp2p::{NetworkEvent, SwarmCommand},
    traits::NodeState,
};
use depin_sdk_services::external_data::ExternalDataService;
use depin_sdk_transaction_models::unified::UnifiedTransactionModel;
use depin_sdk_types::app::{ChainTransaction, OracleAttestation};
use libp2p::{identity, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Debug;
use std::sync::{atomic::AtomicBool, Arc};
use tokio::sync::{mpsc, watch, Mutex};

// --- FIX: Provide all 3 generic arguments to AppChain: CS, TM, and ST ---
pub type ChainFor<CS, ST> =
    Arc<Mutex<dyn AppChain<CS, UnifiedTransactionModel<CS>, ST> + Send + Sync>>;

/// Main state for the Orchestration Container's event loop.
pub struct MainLoopContext<CS, ST, CE>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
{
    pub chain_ref: ChainFor<CS, ST>,
    pub workload_client: Arc<WorkloadClient>,
    pub tx_pool_ref: Arc<Mutex<VecDeque<ChainTransaction>>>,
    pub network_event_receiver: mpsc::Receiver<NetworkEvent>,
    pub swarm_commander: mpsc::Sender<SwarmCommand>,
    pub shutdown_receiver: watch::Receiver<bool>,
    pub consensus_engine_ref: Arc<Mutex<CE>>,
    pub node_state: Arc<Mutex<NodeState>>,
    pub local_peer_id: PeerId,
    pub local_keypair: identity::Keypair,
    pub known_peers_ref: Arc<Mutex<HashSet<PeerId>>>,
    pub config: OrchestrationConfig,
    pub is_quarantined: Arc<AtomicBool>,
    pub external_data_service: ExternalDataService,
    pub pending_attestations: HashMap<u64, Vec<OracleAttestation>>,
}