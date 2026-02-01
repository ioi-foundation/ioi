// Path: crates/node/src/bin/orchestration.rs
#![forbid(unsafe_code)]

use anyhow::{anyhow, Result};
use clap::Parser;
use ioi_api::services::access::ServiceDirectory;
use ioi_api::services::BlockchainService;
use ioi_api::services::UpgradableService;
use ioi_api::validator::container::Container;
use ioi_client::WorkloadClient;
use ioi_consensus::util::engine_from_config;
use ioi_crypto::sign::batch::CpuBatchVerifier;
use ioi_crypto::sign::dilithium::MldsaKeyPair;
use ioi_execution::ExecutionMachine;
use ioi_networking::libp2p::Libp2pSync;
use ioi_networking::metrics as network_metrics;
use ioi_services::governance::GovernanceModule;
// --- IBC Service Imports ---
use http_rpc_gateway;
use ibc_host::{DefaultIbcHost, TransactionPool};
#[cfg(feature = "ibc-deps")]
use ioi_services::ibc::{
    apps::channel::ChannelManager, core::registry::VerifierRegistry,
    light_clients::tendermint::TendermintVerifier,
};
use ioi_services::identity::IdentityHub;
use ioi_services::provider_registry::ProviderRegistryService; // Replaced OracleService
use ioi_storage::RedbEpochStore;
use ioi_tx::unified::UnifiedTransactionModel;
use ioi_types::config::{InitialServiceConfig, OrchestrationConfig, WorkloadConfig};
use ioi_validator::metrics as validator_metrics;
use ioi_validator::standard::orchestration::OrchestrationDependencies;
use ioi_validator::standard::{
    orchestration::verifier_select::{create_default_verifier, DefaultVerifier},
    Orchestrator,
};
use ioi_vm_wasm::WasmRuntime;
use libp2p::identity;
use libp2p::Multiaddr;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{atomic::AtomicBool, Arc};

// Imports for concrete types used in the factory
use ioi_api::{commitment::CommitmentScheme, crypto::SerializableKey, state::StateManager};
#[cfg(feature = "commitment-hash")]
use ioi_state::primitives::hash::HashCommitmentScheme;
#[cfg(feature = "commitment-kzg")]
use ioi_state::primitives::kzg::{KZGCommitmentScheme, KZGParams};
#[cfg(feature = "state-iavl")]
use ioi_state::tree::iavl::IAVLTree;
// [NEW] Import JMT
#[cfg(feature = "state-jellyfish")]
use ioi_state::tree::jellyfish::JellyfishMerkleTree;
#[cfg(feature = "state-sparse-merkle")]
use ioi_state::tree::sparse_merkle::SparseMerkleTree;
#[cfg(feature = "state-verkle")]
use ioi_state::tree::verkle::VerkleTree;
// [NEW] Import for ZK client config
#[cfg(all(feature = "ibc-deps", feature = "ethereum-zk"))]
use zk_driver_succinct::config::SuccinctDriverConfig;
// [NEW] Import for VK loading in native mode
#[cfg(feature = "ethereum-zk")]
use ioi_crypto::algorithms::hash::sha256;

// [NEW] Import GuardianSigner types
use async_trait::async_trait;
use ioi_types::app::ChainTransaction;
use ioi_validator::common::{GuardianContainer, GuardianSigner, LocalSigner, RemoteSigner};
use ioi_validator::standard::orchestration::mempool::Mempool;
use serde::Serialize;
use std::fmt::Debug;
use tokio::sync::Mutex;

// [FIX] Correctly import LocalSafetyModel, InferenceRuntime and OsDriver
use ioi_api::vm::inference::{InferenceRuntime, LocalSafetyModel, HttpInferenceRuntime};
use ioi_api::vm::drivers::os::OsDriver;
use ioi_drivers::os::NativeOsDriver;
use ioi_services::agentic::scrub_adapter::RuntimeAsSafetyModel;


#[derive(Parser, Debug)]
struct OrchestrationOpts {
    #[clap(long, help = "Path to the orchestration.toml configuration file.")]
    config: PathBuf,
    #[clap(long, help = "Path to the identity keypair file.")]
    identity_key_file: PathBuf,
    #[clap(
        long,
        env = "LISTEN_ADDRESS",
        help = "Address to listen for p2p connections"
    )]
    listen_address: Multiaddr,
    #[clap(
        long,
        env = "BOOTNODE",
        use_value_delimiter = true,
        help = "One or more bootnode addresses to connect to, comma-separated"
    )]
    bootnode: Vec<Multiaddr>,
    /// Optional path to a JSON file containing a Dilithium keypair:
    /// { "public": "<hex>", "private": "<hex>" }
    #[clap(long)]
    pqc_key_file: Option<PathBuf>,

    /// [NEW] URL of the remote ioi-signer Oracle. If set, the node will use
    /// the Oracle for signing block headers instead of the local key file.
    #[clap(long, env = "ORACLE_URL")]
    oracle_url: Option<String>,
}

/// Runtime check to ensure exactly one state tree feature is enabled.
fn check_features() {
    let mut enabled_features = Vec::new();
    if cfg!(feature = "state-iavl") {
        enabled_features.push("state-iavl");
    }
    if cfg!(feature = "state-sparse-merkle") {
        enabled_features.push("state-sparse-merkle");
    }
    if cfg!(feature = "state-verkle") {
        enabled_features.push("state-verkle");
    }
    if cfg!(feature = "state-jellyfish") {
        enabled_features.push("state-jellyfish");
    }

    if enabled_features.len() != 1 {
        panic!(
            "Error: Please enable exactly one 'tree-*' feature for the ioi-node crate. Found: {:?}",
            enabled_features
        );
    }
}

// Conditionally define a type alias for the optional KZG parameters.
// This allows the run_orchestration function to have a single signature
// that adapts based on compile-time features.
#[cfg(feature = "commitment-kzg")]
type OptionalKzgParams = Option<KZGParams>;
#[cfg(not(feature = "commitment-kzg"))]
#[allow(dead_code)]
type OptionalKzgParams = Option<()>;

/// Adapter to allow `Arc<Mempool>` to satisfy `TransactionPool`.
struct MempoolAdapter {
    inner: Arc<Mempool>,
}

#[async_trait]
impl TransactionPool for MempoolAdapter {
    async fn add(&self, tx: ChainTransaction) -> Result<()> {
        let tx_hash = tx.hash()?;

        let tx_info = match &tx {
            ChainTransaction::System(s) => Some((s.header.account_id, s.header.nonce)),
            ChainTransaction::Settlement(s) => Some((s.header.account_id, s.header.nonce)), // Add Settlement handling
            ChainTransaction::Application(a) => match a {
                ioi_types::app::ApplicationTransaction::DeployContract { header, .. }
                | ioi_types::app::ApplicationTransaction::CallContract { header, .. } => {
                    Some((header.account_id, header.nonce))
                }
            },
            // [FIX] Removed unreachable wildcard pattern since we cover all variants explicitly or don't care
            _ => None,
        };

        // Use 0 as committed_nonce fallback; Mempool will queue if needed.
        self.inner.add(tx, tx_hash, tx_info, 0);
        Ok(())
    }
}

/// Generic function containing all logic after component instantiation.
#[allow(dead_code)]
async fn run_orchestration<CS, ST>(
    opts: OrchestrationOpts,
    config: OrchestrationConfig,
    local_key: identity::Keypair,
    state_tree: ST,
    commitment_scheme: CS,
    workload_config: WorkloadConfig,
    kzg_params: OptionalKzgParams,
) -> Result<()>
where
    CS: CommitmentScheme<
            Commitment = <DefaultVerifier as ioi_api::state::Verifier>::Commitment,
            Proof = <DefaultVerifier as ioi_api::state::Verifier>::Proof,
        > + Clone
        + Send
        + Sync
        + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + std::fmt::Debug
        + Clone,
    CS::Commitment: std::fmt::Debug + Send + Sync,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Value: From<Vec<u8>> + AsRef<[u8]> + Send + Sync + std::fmt::Debug,
{
    // Read genesis file once to get the hash for identity checks and the oracle domain.
    let data_dir = opts.config.parent().unwrap_or_else(|| Path::new("."));
    let genesis_bytes = fs::read(&workload_config.genesis_file)?;
    let derived_genesis_hash: [u8; 32] = ioi_crypto::algorithms::hash::sha256(&genesis_bytes)?;

    let workload_client = {
        // --- Startup Identity Check ---
        let identity_path = data_dir.join("chain_identity.json");
        let configured_identity = (config.chain_id, derived_genesis_hash);

        if identity_path.exists() {
            let stored_bytes = fs::read(&identity_path)?;
            let stored_identity: (ioi_types::app::ChainId, [u8; 32]) =
                serde_json::from_slice(&stored_bytes)?;
            if stored_identity != configured_identity {
                panic!(
                    "FATAL: Chain identity mismatch! Config implies {:?}, but storage is initialized for {:?}. Aborting.",
                    configured_identity, stored_identity
                );
            }
        } else {
            // First boot: persist the identity
            fs::write(&identity_path, serde_json::to_vec(&configured_identity)?)?;
            tracing::info!(target: "orchestration", "Persisted new chain identity: {:?}", configured_identity);
        }

        let workload_ipc_addr =
            std::env::var("WORKLOAD_IPC_ADDR").unwrap_or_else(|_| "127.0.0.1:8555".to_string());
        let certs_dir =
            std::env::var("CERTS_DIR").expect("CERTS_DIR environment variable must be set");
        let ca_path = format!("{}/ca.pem", certs_dir);
        let cert_path = format!("{}/orchestration.pem", certs_dir);
        let key_path = format!("{}/orchestration.key", certs_dir);
        Arc::new(WorkloadClient::new(&workload_ipc_addr, &ca_path, &cert_path, &key_path).await?)
    };

    let workload_probe_deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
    loop {
        match workload_client.get_status().await {
            Ok(_) => {
                tracing::info!(target: "orchestration", "Workload IPC reachable.");
                break;
            }
            Err(e) => {
                if std::time::Instant::now() >= workload_probe_deadline {
                    eprintln!(
                        "ORCHESTRATION_FATAL: Workload IPC unreachable after retries: {}",
                        e
                    );
                    return Err(anyhow!("Workload IPC unreachable after retries: {}", e));
                }
                tracing::warn!(
                    target: "orchestration",
                    "Workload IPC not reachable yet: {} (retrying...)",
                    e
                );
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            }
        }
    }

    let (syncer, real_swarm_commander, network_event_receiver) =
        match Libp2pSync::new(local_key.clone(), opts.listen_address, Some(&opts.bootnode)) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("ORCHESTRATION_FATAL: Libp2p init failed: {e}");
                return Err(anyhow!("Libp2p init failed: {}", e));
            }
        };

    let pqc_keypair: Option<MldsaKeyPair> = if let Some(path) = opts.pqc_key_file.as_ref() {
        let content = fs::read_to_string(path)?;

        #[derive(serde::Deserialize)]
        struct PqcFile {
            public: String,
            private: String,
        }
        let PqcFile { public, private } = serde_json::from_str(&content).map_err(|e| {
            anyhow!("Invalid PQC key JSON (expected {{\"public\",\"private\"}}): {e}")
        })?;

        fn decode_hex(s: &str) -> Result<Vec<u8>, anyhow::Error> {
            let s = s.strip_prefix("0x").unwrap_or(s);
            Ok(hex::decode(s)?)
        }
        let pk_bytes =
            decode_hex(&public).map_err(|e| anyhow!("PQC public key hex decode failed: {e}"))?;
        let sk_bytes =
            decode_hex(&private).map_err(|e| anyhow!("PQC private key hex decode failed: {e}"))?;

        let kp = MldsaKeyPair::from_bytes(&pk_bytes, &sk_bytes)
            .map_err(|e| anyhow!("PQC key reconstruction failed: {e}"))?;

        tracing::info!(
            target: "orchestration",
            "Loaded Dilithium PQC key from {}",
            path.display()
        );
        Some(kp)
    } else {
        None
    };

    let consensus_engine = engine_from_config(&config)?;
    let verifier = create_default_verifier(kzg_params);
    let is_quarantined = Arc::new(AtomicBool::new(false));

    let signer: Arc<dyn GuardianSigner> = if let Some(oracle_url) = &opts.oracle_url {
        tracing::info!(target: "orchestration", "Using REMOTE Signing Oracle at {}", oracle_url);

        let pk_bytes = local_key.public().encode_protobuf();
        let ed_pk = libp2p::identity::PublicKey::try_decode_protobuf(&pk_bytes)?
            .try_into_ed25519()?
            .to_bytes()
            .to_vec();

        Arc::new(RemoteSigner::new(oracle_url.clone(), ed_pk))
    } else {
        tracing::info!(target: "orchestration", "Using LOCAL signing key (Dev Mode).");
        let sk_bytes = local_key.clone().try_into_ed25519()?.secret();
        let internal_sk =
            ioi_crypto::sign::eddsa::Ed25519PrivateKey::from_bytes(sk_bytes.as_ref())?;
        let internal_kp = ioi_crypto::sign::eddsa::Ed25519KeyPair::from_private_key(&internal_sk)?;

        Arc::new(LocalSigner::new(internal_kp))
    };

    let batch_verifier = Arc::new(CpuBatchVerifier::new());

    // [FIX] Initialize Safety Model and Inference Runtime properly
    let inference_runtime: Arc<dyn InferenceRuntime> = if let Some(key) = &workload_config.inference.api_key {
        let model_name = workload_config.inference.model_name.clone().unwrap_or("gpt-4o".to_string());
        let api_url = workload_config.inference.api_url.clone().unwrap_or("https://api.openai.com/v1/chat/completions".to_string());
        
        Arc::new(HttpInferenceRuntime::new(api_url, key.clone(), model_name))
    } else {
        Arc::new(ioi_api::vm::inference::mock::MockInferenceRuntime)
    };

    let safety_model: Arc<dyn LocalSafetyModel> = Arc::new(RuntimeAsSafetyModel::new(inference_runtime.clone()));

    // [FIX] Initialize OS Driver
    let os_driver = Arc::new(NativeOsDriver::new());

    let deps = OrchestrationDependencies {
        syncer,
        network_event_receiver,
        swarm_command_sender: real_swarm_commander.clone(),
        consensus_engine: consensus_engine.clone(),
        local_keypair: local_key.clone(),
        pqc_keypair,
        is_quarantined,
        genesis_hash: derived_genesis_hash,
        verifier: verifier.clone(),
        signer,
        batch_verifier,
        safety_model: safety_model.clone(),
        scs: None,
        event_broadcaster: None,
        inference_runtime: inference_runtime.clone(),
        // [FIX] Pass os_driver
        os_driver: os_driver.clone(),
    };

    let orchestration = Arc::new(Orchestrator::new(&config, deps, commitment_scheme.clone())?);

    // [FIX] Create ExecutionMachine with OS Driver
    let consensus_for_chain = consensus_engine.clone();
    let chain_ref = {
        let tm = UnifiedTransactionModel::new(commitment_scheme.clone());

        let mut initial_services = Vec::new();

        let penalty_engine: Arc<dyn ioi_consensus::PenaltyEngine> =
            Arc::new(consensus_engine.clone());
        let penalties_service = Arc::new(ioi_consensus::PenaltiesService::new(penalty_engine));
        initial_services.push(penalties_service as Arc<dyn UpgradableService>);

        let wasm_runtime = Arc::new(
            WasmRuntime::new(workload_config.fuel_costs.clone())
                .map_err(|e| anyhow!("Failed to init WasmRuntime: {}", e))?,
        );

        for service_config in &workload_config.initial_services {
            match service_config {
                InitialServiceConfig::IdentityHub(_migration_config) => {
                    tracing::info!(target: "orchestration", event = "service_init", name = "IdentityHub", impl="native", capabilities="identity_view, tx_decorator, on_end_block");
                    let _hub = IdentityHub::new(_migration_config.clone());
                    initial_services
                        .push(Arc::new(_hub) as Arc<dyn ioi_api::services::UpgradableService>);
                }
                InitialServiceConfig::Governance(_params) => {
                    tracing::info!(target: "orchestration", event = "service_init", name = "Governance", impl="native", capabilities="on_end_block");
                    let _gov = GovernanceModule::new(_params.clone());
                    initial_services
                        .push(Arc::new(_gov) as Arc<dyn ioi_api::services::UpgradableService>);
                }
                InitialServiceConfig::Oracle(_params) => {
                    tracing::info!(target: "orchestration", event = "service_init", name = "ProviderRegistry", impl="native", capabilities="");
                    let _registry = ProviderRegistryService::default();
                    initial_services
                        .push(Arc::new(_registry) as Arc<dyn ioi_api::services::UpgradableService>);
                }
                #[cfg(feature = "ibc-deps")]
                InitialServiceConfig::Ibc(ibc_config) => {
                    tracing::info!(target: "orchestration", event = "service_init", name = "IBC", impl="proxy", capabilities="ibc_handler");

                    #[cfg(feature = "vm-wasm")]
                    let mut verifier_registry = VerifierRegistry::new(wasm_runtime.clone());

                    #[cfg(not(feature = "vm-wasm"))]
                    let mut verifier_registry = {
                        panic!("vm-wasm feature is required for IBC setup");
                    };

                    for client_name in &ibc_config.enabled_clients {
                        if client_name.starts_with("tendermint") {
                            let tm_verifier = TendermintVerifier::new(
                                "cosmos-hub-test".to_string(),
                                "07-tendermint-0".to_string(),
                                Arc::new(state_tree.clone()),
                            );
                            verifier_registry.register(Arc::new(tm_verifier));
                        }
                    }

                    #[cfg(feature = "ethereum-zk")]
                    {
                        use ioi_api::ibc::LightClient;
                        use ioi_services::ibc::light_clients::ethereum_zk::EthereumZkLightClient;

                        let zk_cfg = &workload_config.zk_config;
                        let load_vk = |path: &Option<String>,
                                       expected_hash: &str,
                                       label: &str|
                         -> Result<Vec<u8>> {
                            if let Some(p) = path {
                                let bytes = fs::read(p).map_err(|e| {
                                    anyhow!("Failed to read {} VK from {}: {}", label, p, e)
                                })?;
                                let hash = hex::encode(sha256(&bytes)?);
                                if hash != expected_hash {
                                    tracing::warn!(
                                        "Configured {} VK hash {} does not match file {}",
                                        label,
                                        expected_hash,
                                        hash
                                    );
                                }
                                Ok(bytes)
                            } else {
                                Ok(vec![])
                            }
                        };
                        let beacon_bytes = load_vk(
                            &zk_cfg.beacon_vk_path,
                            &zk_cfg.ethereum_beacon_vkey,
                            "Beacon",
                        )?;
                        let state_bytes =
                            load_vk(&zk_cfg.state_vk_path, &zk_cfg.state_inclusion_vkey, "State")?;
                        let driver_config = SuccinctDriverConfig {
                            beacon_vkey_hash: zk_cfg.ethereum_beacon_vkey.clone(),
                            beacon_vkey_bytes: beacon_bytes,
                            state_inclusion_vkey_hash: zk_cfg.state_inclusion_vkey.clone(),
                            state_inclusion_vkey_bytes: state_bytes,
                        };
                        let eth_verifier =
                            EthereumZkLightClient::new("eth-mainnet".to_string(), driver_config);
                        verifier_registry.register(Arc::new(eth_verifier) as Arc<dyn LightClient>);
                        tracing::info!("Registered Ethereum ZK Light Client for 'eth-mainnet'");
                    }

                    initial_services
                        .push(Arc::new(verifier_registry) as Arc<dyn UpgradableService>);
                    initial_services
                        .push(Arc::new(ChannelManager::new()) as Arc<dyn UpgradableService>);
                }
                #[cfg(not(feature = "ibc-deps"))]
                InitialServiceConfig::Ibc(_) => {
                    return Err(anyhow!(
                        "Workload configured for IBC, but not compiled with 'ibc-deps' feature."
                    ));
                }
            }
        }
        let services_for_dir: Vec<Arc<dyn BlockchainService>> = initial_services
            .iter()
            .map(|s| s.clone() as Arc<dyn BlockchainService>)
            .collect();
        let service_directory = ServiceDirectory::new(services_for_dir);

        let dummy_workload_config = WorkloadConfig {
            runtimes: vec![],
            state_tree: workload_config.state_tree.clone(),
            commitment_scheme: workload_config.commitment_scheme.clone(),
            consensus_type: config.consensus_type,
            genesis_file: "".to_string(),
            state_file: "".to_string(),
            srs_file_path: workload_config.srs_file_path.clone(),
            fuel_costs: Default::default(),
            initial_services: vec![],
            service_policies: ioi_types::config::default_service_policies(),
            min_finality_depth: workload_config.min_finality_depth,
            keep_recent_heights: workload_config.keep_recent_heights,
            epoch_size: workload_config.epoch_size,
            gc_interval_secs: workload_config.gc_interval_secs,
            zk_config: Default::default(),
            // [FIX] Initialize missing fields with defaults
            inference: Default::default(),
            fast_inference: None,
            reasoning_inference: None,
            connectors: Default::default(),
            mcp_servers: Default::default(), // [FIX] Initialize mcp_servers
        };

        let data_dir = opts.config.parent().unwrap_or_else(|| Path::new("."));
        let dummy_store_path = data_dir.join("orchestrator_dummy_store.db");
        let dummy_store = Arc::new(RedbEpochStore::open(&dummy_store_path, 50_000)?);

        let workload_container = Arc::new(ioi_api::validator::WorkloadContainer::new(
            dummy_workload_config,
            state_tree,
            Box::new(ioi_vm_wasm::WasmRuntime::new(Default::default())?), // Dummy VM
            None,
            service_directory, // <-- Pass the populated directory here
            dummy_store,
        )?);
        
        let mut machine = ExecutionMachine::new(
            commitment_scheme.clone(),
            tm,
            config.chain_id,
            initial_services,    
            consensus_for_chain, 
            workload_container,
            workload_config.service_policies.clone(), 
            os_driver.clone(), // [FIX] Pass os_driver
        )
        .map_err(|e| anyhow!("Failed to initialize ExecutionMachine: {}", e))?;

        for runtime_id in &workload_config.runtimes {
            let id = runtime_id.to_ascii_lowercase();
            if id == "wasm" {
                tracing::info!(target: "orchestration", "Registering WasmRuntime for tx pre-checks.");
                #[cfg(feature = "vm-wasm")]
                {
                    // We reuse the runtime created earlier for the registry to ensure resource sharing
                    machine
                        .service_manager
                        .register_runtime("wasm", wasm_runtime.clone());
                }
            }
        }
        Arc::new(tokio::sync::Mutex::new(machine))
    };

    orchestration.set_chain_and_workload_client(chain_ref, workload_client.clone());

    std::env::set_var("GATEWAY_CHAIN_ID", config.chain_id.to_string());

    if let Some(gateway_addr) = config.ibc_gateway_listen_address.clone() {
        tracing::info!(target: "orchestration", "Enabling IBC HTTP Gateway.");

        let mempool_adapter = Arc::new(MempoolAdapter {
            inner: orchestration.tx_pool.clone(),
        });

        let ibc_host = Arc::new(DefaultIbcHost::new(
            workload_client.clone(),
            verifier.clone(),
            mempool_adapter,
            real_swarm_commander.clone(),
            local_key.clone(),
            orchestration.nonce_manager.clone(),
            config.chain_id,
        ));
        let gateway_config = http_rpc_gateway::GatewayConfig {
            listen_addr: gateway_addr,
            rps: 20,
            burst: 50,
            body_limit_kb: 512,
            trusted_proxies: vec![],
        };
        let shutdown_rx_for_gateway = orchestration.shutdown_sender.subscribe();
        let chain_id_for_gateway = config.chain_id.to_string();
        let gateway_handle = tokio::spawn(async move {
            if let Err(e) = http_rpc_gateway::run_server(
                gateway_config,
                ibc_host,
                shutdown_rx_for_gateway,
                chain_id_for_gateway,
            )
            .await
            {
                tracing::error!(target: "http-gateway", "IBC HTTP Gateway failed: {}", e);
            }
        });
        orchestration.task_handles.lock().await.push(gateway_handle);
    }

    orchestration.start(&config.rpc_listen_address).await?;
    
    // [FIX] Explicitly log startup complete here to stderr
    eprintln!("ORCHESTRATION_STARTUP_COMPLETE");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!(target: "orchestration", event = "shutdown", reason = "ctrl-c");
        }
    }

    tracing::info!(target: "orchestration", "Shutdown signal received.");

    Container::stop(&*orchestration).await?;

    let data_dir = opts.config.parent().unwrap_or_else(|| Path::new("."));
    let _ = fs::remove_file(data_dir.join("orchestrator_dummy_store.db"));
    tracing::info!(target: "orchestration", event = "shutdown", reason = "complete");
    Ok(())
}

#[tokio::main]
#[allow(unused_variables)]
async fn main() -> Result<()> {
    // [FIX] Install default crypto provider for rustls 0.23+
    let _ = rustls::crypto::ring::default_provider().install_default();

    ioi_telemetry::init::init_tracing()?;
    let metrics_sink = ioi_telemetry::prometheus::install()?;
    ioi_storage::metrics::SINK
        .set(metrics_sink)
        .expect("SINK must be set only once");
    network_metrics::SINK
        .set(metrics_sink)
        .expect("SINK must be set only once");
    validator_metrics::CONSENSUS_SINK
        .set(metrics_sink)
        .expect("SINK must be set only once");
    validator_metrics::RPC_SINK
        .set(metrics_sink)
        .expect("SINK must be set only once");

    let telemetry_addr_str =
        std::env::var("TELEMETRY_ADDR").unwrap_or_else(|_| "127.0.0.1:9615".to_string());
    let telemetry_addr = telemetry_addr_str.parse()?;
    tokio::spawn(ioi_telemetry::http::run_server(telemetry_addr));

    check_features();
    std::panic::set_hook(Box::new(|info| {
        eprintln!("ORCHESTRATION_PANIC: {}", info);
    }));

    let opts = OrchestrationOpts::parse();
    tracing::info!(
        target: "orchestration",
        event = "startup",
        config = ?opts.config
    );

    let config_path = opts.config.clone();
    let config: OrchestrationConfig = toml::from_str(&fs::read_to_string(&config_path)?)?;
    config.validate().map_err(|e| anyhow!(e))?;

    let local_key = {
        let key_path = &opts.identity_key_file;
        if key_path.exists() {
            let raw = GuardianContainer::load_encrypted_file(key_path)?;
            identity::Keypair::from_protobuf_encoding(&raw)?
        } else {
            let keypair = identity::Keypair::generate_ed25519();
            if let Some(parent) = key_path.parent() {
                fs::create_dir_all(parent)?;
            }
            GuardianContainer::save_encrypted_file(key_path, &keypair.to_protobuf_encoding()?)?;
            keypair
        }
    };

    let workload_config_path = opts.config.parent().unwrap().join("workload.toml");
    let workload_config_str = fs::read_to_string(&workload_config_path)?;
    let workload_config: WorkloadConfig = toml::from_str(&workload_config_str)?;
    workload_config.validate().map_err(|e| anyhow!(e))?;

    match (
        workload_config.state_tree.clone(),
        workload_config.commitment_scheme.clone(),
    ) {
        #[cfg(all(feature = "state-iavl", feature = "commitment-hash"))]
        (ioi_types::config::StateTreeType::IAVL, ioi_types::config::CommitmentSchemeType::Hash) => {
            let scheme = HashCommitmentScheme::new();
            let tree = IAVLTree::new(scheme.clone());
            run_orchestration(opts, config, local_key, tree, scheme, workload_config, None).await
        }
        #[cfg(all(feature = "state-sparse-merkle", feature = "commitment-hash"))]
        (
            ioi_types::config::StateTreeType::SparseMerkle,
            ioi_types::config::CommitmentSchemeType::Hash,
        ) => {
            let scheme = HashCommitmentScheme::new();
            let tree = SparseMerkleTree::new(scheme.clone());
            run_orchestration(opts, config, local_key, tree, scheme, workload_config, None).await
        }
        #[cfg(all(feature = "state-verkle", feature = "commitment-kzg"))]
        (
            ioi_types::config::StateTreeType::Verkle,
            ioi_types::config::CommitmentSchemeType::KZG,
        ) => {
            let params = if let Some(srs_path) = &workload_config.srs_file_path {
                KZGParams::load_from_file(srs_path.as_ref()).map_err(|e| anyhow!(e))?
            } else {
                return Err(anyhow!(
                    "Verkle tree requires an SRS file path in workload.toml"
                ));
            };
            let scheme = KZGCommitmentScheme::new(params.clone());
            let tree = VerkleTree::new(scheme.clone(), 256).map_err(|e| anyhow!(e))?;
            run_orchestration(
                opts,
                config,
                local_key,
                tree,
                scheme,
                workload_config,
                Some(params),
            )
            .await
        }
        #[cfg(all(feature = "state-jellyfish", feature = "commitment-hash"))]
        (
            ioi_types::config::StateTreeType::Jellyfish,
            ioi_types::config::CommitmentSchemeType::Hash,
        ) => {
            let scheme = HashCommitmentScheme::new();
            let tree = JellyfishMerkleTree::new(scheme.clone());
            run_orchestration(opts, config, local_key, tree, scheme, workload_config, None).await
        }

        _ => {
            let err_msg = format!("Unsupported or disabled state configuration: StateTree={:?}, CommitmentScheme={:?}. Please check your config and compile-time features.", workload_config.state_tree, workload_config.commitment_scheme);
            Err(anyhow!(err_msg))
        }
    }
}