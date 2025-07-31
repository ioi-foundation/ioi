// Path: crates/validator/src/standard/orchestration.rs

use crate::config::OrchestrationConfig;
use async_trait::async_trait;
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
    consensus_engine: Arc<Mutex<dyn ConsensusEngine<TM::Transaction> + Send + Sync>>,
    shutdown_sender: Arc<watch::Sender<bool>>,
    task_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
    is_running: Arc<AtomicBool>,
}

impl<CS, TM, ST> OrchestrationContainer<CS, TM, ST>
where
    CS: CommitmentScheme + Send + Sync + 'static,
    TM: TransactionModel<CommitmentScheme = CS> + Clone + Send + Sync + 'static,
    TM::Transaction: Clone + Debug + Send + Sync + for<'de> serde::Deserialize<'de> + serde::Serialize,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + StateTree<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send + Sync + 'static + Debug,
    CS::Commitment: Send + Sync + Debug,
{
    pub fn new(
        config_path: &std::path::Path,
        syncer: Arc<dyn BlockSync<CS, TM, ST>>,
        consensus_engine: impl ConsensusEngine<TM::Transaction> + Send + Sync + 'static,
    ) -> anyhow::Result<Self> {
        let _config: OrchestrationConfig = toml::from_str(&std::fs::read_to_string(config_path)?)?;
        let (shutdown_sender, _) = watch::channel(false);

        Ok(Self {
            _config,
            chain: Arc::new(OnceCell::new()),
            workload: Arc::new(OnceCell::new()),
            syncer,
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
        consensus_engine_ref: Arc<Mutex<dyn ConsensusEngine<TM::Transaction> + Send + Sync>>,
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

                    let validator_set = match chain_ref.lock().await.get_validator_set(&workload_ref).await {
                        Ok(vs) => vs,
                        Err(e) => {
                            log::error!("Could not get validator set: {:?}", e);
                            continue;
                        }
                    };
                    
                    let known_peers = known_peers_ref.lock().await;
                    let decision = {
                        let mut engine = consensus_engine_ref.lock().await;
                        engine.decide(&local_peer_id, target_height, current_view, &validator_set, &known_peers).await
                    };
                    drop(known_peers);

                    if let ConsensusDecision::ProduceBlock(_txs) = decision {
                        log::info!("Consensus decision: Produce block for height {}.", target_height);
                        
                        let known_peers = known_peers_ref.lock().await;
                        let mut peers_bytes: Vec<Vec<u8>> = known_peers.iter().map(|p| p.to_bytes()).collect();
                        peers_bytes.push(local_peer_id.to_bytes());
                        drop(known_peers);

                        let coinbase = match chain_ref.lock().await.transaction_model().clone().create_coinbase_transaction(target_height, &local_peer_id.to_bytes()) {
                            Ok(tx) => tx,
                            Err(e) => { log::error!("Failed to create coinbase: {:?}", e); continue; }
                        };
                        
                        let new_block_template = chain_ref.lock().await.create_block(vec![coinbase], &workload_ref, &validator_set, &peers_bytes);
                        
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
    TM: TransactionModel<CommitmentScheme = CS> + Clone + Send + Sync + 'static,
    TM::Transaction: Clone + Debug + Send + Sync + for<'de> serde::Deserialize<'de> + serde::Serialize,
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