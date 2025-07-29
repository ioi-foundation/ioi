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
use futures::StreamExt;
// ADDED: Import Multiaddr for the listen_on call
use libp2p::{
    core::upgrade, gossipsub, identity, noise, swarm::SwarmEvent, tcp, yamux, Multiaddr, Swarm,
    SwarmBuilder, Transport,
};
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
    pub swarm: Arc<Mutex<Swarm<gossipsub::Behaviour>>>,
    shutdown_sender: Arc<watch::Sender<bool>>,
    task_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
    is_running: Arc<AtomicBool>,
}

impl<CS, TM, ST> OrchestrationContainer<CS, TM, ST>
where
    CS: CommitmentScheme + Send + Sync + 'static,
    TM: TransactionModel<CommitmentScheme = CS> + Clone + Send + Sync + 'static,
    TM::Transaction: Clone + Debug + Send + Sync,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + StateTree<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug,
    CS::Commitment: Send + Sync + Debug,
{
    pub async fn new(config_path: &std::path::Path) -> anyhow::Result<Self> {
        let _config: OrchestrationConfig =
            toml::from_str(&std::fs::read_to_string(config_path)?)?;

        let (shutdown_sender, _) = watch::channel(false);

        let local_key = identity::Keypair::generate_ed25519();

        let swarm = SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_other_transport(|key| {
                let noise_config = noise::Config::new(key)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                let transport = tcp::tokio::Transport::new(tcp::Config::default())
                    .upgrade(upgrade::Version::V1Lazy)
                    .authenticate(noise_config)
                    .multiplex(yamux::Config::default())
                    .timeout(std::time::Duration::from_secs(20))
                    .boxed();
                Ok(transport)
            })?
            .with_behaviour(|key| {
                let gossipsub_config = gossipsub::Config::default();
                gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )
                .expect("Valid gossipsub config")
            })?
            .build();

        Ok(Self {
            _config,
            chain: Arc::new(OnceCell::new()),
            workload: Arc::new(OnceCell::new()),
            swarm: Arc::new(Mutex::new(swarm)),
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
        self.workload
            .set(workload_ref)
            .expect("Workload ref already set");
    }

    async fn run_event_loop(
        swarm_ref: Arc<Mutex<Swarm<gossipsub::Behaviour>>>,
        mut shutdown_receiver: watch::Receiver<bool>,
    ) {
        loop {
            tokio::select! {
                biased;
                _ = shutdown_receiver.changed() => {
                    if *shutdown_receiver.borrow() {
                        log::info!("Orchestration event loop received shutdown signal.");
                        break;
                    }
                },
                event = async { swarm_ref.lock().await.select_next_some().await } => {
                     match event {
                        SwarmEvent::Behaviour(gossipsub::Event::Message { message, .. }) => {
                            log::info!(
                                "Received block gossip from peer {:?}: '{}'",
                                message.source,
                                String::from_utf8_lossy(&message.data)
                            );
                        }
                        SwarmEvent::NewListenAddr { address, .. } => {
                            log::info!("OrchestrationContainer now listening on {}", address);
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            log::info!("Connection established with peer: {:?}", peer_id);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    async fn run_block_production(
        chain_ref: Arc<Mutex<dyn SovereignChain<CS, TM, ST> + Send + Sync>>,
        workload_ref: Arc<WorkloadContainer<ST>>,
        swarm_ref: Arc<Mutex<Swarm<gossipsub::Behaviour>>>,
        is_running: Arc<AtomicBool>,
    ) {
        let mut interval = time::interval(Duration::from_secs(10));
        while is_running.load(Ordering::SeqCst) {
            interval.tick().await;

            let new_block;
            {
                let mut chain = chain_ref.lock().await;
                let tm = chain.transaction_model().clone();
                let coinbase_result = tm
                    .create_coinbase_transaction(chain.status().height + 1, &[]);
                
                let coinbase = match coinbase_result {
                    Ok(tx) => tx,
                    Err(e) => {
                        log::error!("Failed to create coinbase transaction: {:?}", e);
                        continue;
                    }
                };

                new_block = chain.create_block(vec![coinbase], &workload_ref);

                if let Err(e) = chain
                    .process_block(new_block.clone(), &workload_ref)
                    .await
                {
                    log::error!("Failed to process new block: {:?}", e);
                    continue;
                }
                log::info!("Produced and processed new block #{}", new_block.header.height);
            }
            
            let swarm_clone = swarm_ref.clone();
            tokio::spawn(async move {
                let mut swarm = swarm_clone.lock().await;
                let topic = gossipsub::IdentTopic::new("blocks");
                let message_data = serde_json::to_vec(&new_block.header).unwrap_or_default();

                if let Err(e) = swarm.behaviour_mut().publish(topic, message_data) {
                    log::warn!("Failed to publish block (likely no peers): {:?}", e);
                }
            });
        }
        log::info!("Orchestration block production loop finished.");
    }
}

#[async_trait]
impl<CS, TM, ST> Container for OrchestrationContainer<CS, TM, ST>
where
    CS: CommitmentScheme + Send + Sync + 'static,
    TM: TransactionModel<CommitmentScheme = CS> + Clone + Send + Sync + 'static,
    TM::Transaction: Clone + Debug + Send + Sync,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + StateTree<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug,
    CS::Commitment: Send + Sync + Debug,
{
    fn id(&self) -> &'static str {
        "orchestration_container"
    }

    fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }

    async fn start(&self) -> Result<(), ValidatorError> {
        if self.is_running() {
            return Err(ValidatorError::AlreadyRunning(self.id().to_string()));
        }
        log::info!("OrchestrationContainer starting...");

        // --- ADDED THIS BLOCK TO START LISTENING ---
        // Listen on all interfaces on a random OS-assigned TCP port.
        let listen_addr: Multiaddr = "/ip4/0.0.0.0/tcp/0"
            .parse()
            .expect("Invalid listen address format");
        self.swarm
            .lock()
            .await
            .listen_on(listen_addr)
            .map_err(|e| ValidatorError::Other(format!("Failed to listen on address: {}", e)))?;
        // --- END ADDED BLOCK ---

        self.is_running.store(true, Ordering::SeqCst);
        
        let mut handles = self.task_handles.lock().await;

        let event_loop_receiver = self.shutdown_sender.subscribe();
        let swarm_clone = self.swarm.clone();
        handles.push(tokio::spawn(async move {
            Self::run_event_loop(swarm_clone, event_loop_receiver).await;
        }));

        let chain_clone = self.chain.get().unwrap().clone();
        let workload_clone = self.workload.get().unwrap().clone();
        let swarm_clone_2 = self.swarm.clone();
        let is_running_clone = self.is_running.clone();

        handles.push(tokio::spawn(async move {
            Self::run_block_production(
                chain_clone,
                workload_clone,
                swarm_clone_2,
                is_running_clone,
            )
            .await;
        }));

        Ok(())
    }

    async fn stop(&self) -> Result<(), ValidatorError> {
        if !self.is_running() {
            return Ok(());
        }
        log::info!("OrchestrationContainer stopping...");
        self.is_running.store(false, Ordering::SeqCst);
        
        self.shutdown_sender.send(true).map_err(|e| {
            ValidatorError::Other(format!("Failed to send shutdown signal: {}", e))
        })?;

        let mut handles = self.task_handles.lock().await;
        for handle in handles.drain(..) {
            handle.await.map_err(|e| ValidatorError::Other(format!("Task panicked during shutdown: {}", e)))?;
        }

        Ok(())
    }
}