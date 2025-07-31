// Path: crates/validator/src/standard/orchestration.rs

use crate::config::OrchestrationConfig;
use async_trait::async_trait;
use depin_sdk_core::app::{ApplicationTransaction, ProtocolTransaction, UTXOTransaction};
use depin_sdk_core::{
    chain::SovereignChain,
    commitment::CommitmentScheme,
    error::ValidatorError,
    state::{StateManager, StateTree},
    transaction::TransactionModel,
    validator::{Container, WorkloadContainer},
};
use depin_sdk_consensus::{ConsensusDecision, ConsensusEngine};
use depin_sdk_sync::traits::NodeState;
use depin_sdk_sync::BlockSync;
use libp2p::PeerId;
use std::collections::HashSet;
use std::fmt::Debug;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::{
    sync::{watch, Mutex, OnceCell},
    task::JoinHandle,
    time::{self, Duration},
};

pub struct OrchestrationContainer<CS, TM, ST>
where
    CS: CommitmentScheme + Send + Sync + 'static,
    TM: TransactionModel<CommitmentScheme = CS> + Clone + Send + Sync + 'static,
    TM::Transaction: Clone + Debug + Send + Sync,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static + Debug,
{
    _config: OrchestrationConfig,
    chain: Arc<OnceCell<Arc<Mutex<dyn SovereignChain<CS, TM, ST> + Send + Sync>>>>,
    workload: Arc<OnceCell<Arc<WorkloadContainer<ST>>>>,
    syncer: Arc<dyn BlockSync<CS, TM, ST>>,
    // FIX: The struct field must now hold the Box inside the Mutex.
    consensus_engine: Arc<Mutex<Box<dyn ConsensusEngine<ProtocolTransaction> + Send + Sync>>>,
    shutdown_sender: Arc<watch::Sender<bool>>,
    task_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
    is_running: Arc<AtomicBool>,
}

impl<CS, TM, ST> OrchestrationContainer<CS, TM, ST>
where
    CS: CommitmentScheme + Send + Sync + 'static,
    TM: TransactionModel<CommitmentScheme = CS, Transaction = UTXOTransaction> + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + StateTree<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send + Sync + 'static
        + Debug,
    CS::Commitment: Send + Sync + Debug,
{
    pub fn new(
        config_path: &std::path::Path,
        syncer: Arc<dyn BlockSync<CS, TM, ST>>,
        // FIX: The signature now accepts a Box<dyn Trait> instead of `impl Trait`.
        consensus_engine: Box<dyn ConsensusEngine<ProtocolTransaction> + Send + Sync>,
    ) -> anyhow::Result<Self> {
        let _config: OrchestrationConfig = toml::from_str(&std::fs::read_to_string(config_path)?)?;
        let (shutdown_sender, _) = watch::channel(false);

        Ok(Self {
            _config,
            chain: Arc::new(OnceCell::new()),
            workload: Arc::new(OnceCell::new()),
            syncer,
            // This now correctly wraps the Box in a Mutex and Arc.
            consensus_engine: Arc::new(Mutex::new(consensus_engine)),
            shutdown_sender: Arc::new(shutdown_sender),
            task_handles: Arc::new(Mutex::new(Vec::new())),
            is_running: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn set_chain_and_workload_ref(
        &self,
        chain_ref: Arc<Mutex<dyn SovereignChain<CS, TM, ST> + Send + Sync>>,
        workload_ref: Arc<WorkloadContainer<ST>>,
    ) {
        self.chain.set(chain_ref).expect("Chain ref already set");
        self.workload.set(workload_ref).expect("Workload ref already set");
    }

    async fn run_block_production(
        chain_ref: Arc<Mutex<dyn SovereignChain<CS, TM, ST> + Send + Sync>>,
        workload_ref: Arc<WorkloadContainer<ST>>,
        mut shutdown_receiver: watch::Receiver<bool>,
        // The type of this reference changes, but the usage below remains the same
        // due to Rust's deref coercion.
        consensus_engine_ref: Arc<Mutex<Box<dyn ConsensusEngine<ProtocolTransaction> + Send + Sync>>>,
        syncer: Arc<dyn BlockSync<CS, TM, ST>>,
        node_state: Arc<Mutex<NodeState>>,
        local_peer_id: PeerId,
        known_peers_ref: Arc<Mutex<HashSet<PeerId>>>,
    ) {
        let mut interval = time::interval(Duration::from_secs(10));
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = shutdown_receiver.changed() => {
                    if *shutdown_receiver.borrow() {
                        log::info!("Orchestration block production loop received shutdown signal.");
                        break;
                    }
                }
                _ = interval.tick() => {
                    if *node_state.lock().await != NodeState::Synced {
                        continue;
                    }

                    let chain_height = chain_ref.lock().await.status().height;
                    let target_height = chain_height + 1;
                    let current_view = 0; // Simplified for now

                    // Fetch the correct node set based on the compile-time feature.
                    let node_set_for_consensus = {
                        let chain = chain_ref.lock().await;

                        #[cfg(feature = "consensus-round-robin")]
                        { chain.get_validator_set(&workload_ref).await }

                        #[cfg(feature = "consensus-poa")]
                        { chain.get_authority_set(&workload_ref).await }

                        // If no feature is enabled, default to validator set for library testing.
                        #[cfg(not(any(feature = "consensus-round-robin", feature = "consensus-poa")))]
                        { chain.get_validator_set(&workload_ref).await }
                    };

                    let node_set = match node_set_for_consensus {
                        Ok(vs) => vs,
                        Err(e) => {
                            log::error!("Could not get node set for consensus: {:?}", e);
                            continue;
                        }
                    };

                    let known_peers = known_peers_ref.lock().await;
                    let decision = {
                        // This code works without changes because MutexGuard derefs to the Box,
                        // and the Box derefs to the underlying trait object.
                        let mut engine = consensus_engine_ref.lock().await;
                        engine.decide(&local_peer_id, target_height, current_view, &node_set, &known_peers).await
                    };
                    drop(known_peers);

                    if let ConsensusDecision::ProduceBlock(_txs) = decision {
                        log::info!("Consensus decision: Produce block for height {}.", target_height);

                        let known_peers = known_peers_ref.lock().await;
                        let mut peers_bytes: Vec<Vec<u8>> = known_peers.iter().map(|p| p.to_bytes()).collect();
                        peers_bytes.push(local_peer_id.to_bytes());
                        drop(known_peers);

                        // Retrieve the validator set again for block creation, as it might differ from the
                        // authority set used in PoA consensus.
                        let validator_set = match chain_ref.lock().await.get_validator_set(&workload_ref).await {
                            Ok(vs) => vs,
                            Err(e) => {
                                log::error!("Could not get validator set for block creation: {:?}", e);
                                continue;
                            }
                        };

                        let coinbase = match chain_ref.lock().await.transaction_model().clone().create_coinbase_transaction(target_height, &local_peer_id.to_bytes()) {
                            Ok(tx) => tx,
                            Err(e) => { log::error!("Failed to create coinbase: {:?}", e); continue; }
                        };

                        let full_coinbase_tx = ProtocolTransaction::Application(
                            ApplicationTransaction::UTXO(coinbase)
                        );

                        let new_block_template = chain_ref.lock().await.create_block(vec![full_coinbase_tx], &workload_ref, &validator_set, &peers_bytes);

                        let final_block = match chain_ref.lock().await.process_block(new_block_template, &workload_ref).await {
                            Ok(b) => b,
                            Err(e) => { log::error!("Failed to process our own block: {:?}", e); continue; }
                        };
                        log::info!("Produced and processed new block #{}", final_block.header.height);

                        if let Err(e) = syncer.publish_block(&final_block).await {
                            log::warn!("Failed to publish block via syncer: {:?}", e);
                        }
                    }
                }
            }
        }
        log::info!("Orchestration block production loop finished.");
    }
}

#[async_trait]
impl<CS, TM, ST> Container for OrchestrationContainer<CS, TM, ST>
where
    CS: CommitmentScheme + Send + Sync + 'static,
    TM: TransactionModel<CommitmentScheme = CS, Transaction = UTXOTransaction> + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + StateTree<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static + Debug,
    CS::Commitment: Send + Sync + Debug,
{
    fn id(&self) -> &'static str { "orchestration_container" }
    fn is_running(&self) -> bool { self.is_running.load(Ordering::SeqCst) }

    async fn start(&self) -> Result<(), ValidatorError> {
        if self.is_running() { return Err(ValidatorError::AlreadyRunning(self.id().to_string())); }
        log::info!("OrchestrationContainer starting...");

        self.syncer.start().await.map_err(|e| ValidatorError::Other(e.to_string()))?;

        let chain = self.chain.get().ok_or_else(|| ValidatorError::Other("Chain ref not initialized before start".to_string()))?.clone();
        let workload = self.workload.get().ok_or_else(|| ValidatorError::Other("Workload ref not initialized before start".to_string()))?.clone();
        
        let mut handles = self.task_handles.lock().await;
        handles.push(tokio::spawn(Self::run_block_production(
            chain,
            workload,
            self.shutdown_sender.subscribe(),
            self.consensus_engine.clone(),
            self.syncer.clone(),
            self.syncer.get_node_state(),
            self.syncer.get_local_peer_id(),
            self.syncer.get_known_peers(),
        )));

        self.is_running.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn stop(&self) -> Result<(), ValidatorError> {
        if !self.is_running() { return Ok(()); }
        log::info!("OrchestrationContainer stopping...");
        self.shutdown_sender.send(true).ok();
        
        // Give the block production loop a moment to receive the signal
        tokio::time::sleep(Duration::from_millis(100)).await;

        self.is_running.store(false, Ordering::SeqCst);

        self.syncer.stop().await.map_err(|e| ValidatorError::Other(e.to_string()))?;
        
        let mut handles = self.task_handles.lock().await;
        for handle in handles.drain(..) {
            handle.await.map_err(|e| ValidatorError::Other(format!("Task panicked: {}", e)))?;
        }
        Ok(())
    }
}