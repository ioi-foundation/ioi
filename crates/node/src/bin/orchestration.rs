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
use ioi_crypto::sign::dilithium::DilithiumKeyPair;
use ioi_execution::ExecutionMachine;
use ioi_networking::libp2p::Libp2pSync;
use ioi_networking::metrics as network_metrics;
use ioi_services::governance::GovernanceModule;
// --- IBC Service Imports ---
use http_rpc_gateway;
use ibc_host::DefaultIbcHost;
#[cfg(feature = "ibc-deps")]
use ioi_services::ibc::{
    // Updated paths
    apps::channel::ChannelManager,
    core::registry::VerifierRegistry,
    light_clients::tendermint::TendermintVerifier,
};
use ioi_services::identity::IdentityHub;
use ioi_services::oracle::OracleService;
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
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{atomic::AtomicBool, Arc};

// Imports for concrete types used in the factory
// [FIX] Import SerializableKey for from_bytes
use ioi_api::{commitment::CommitmentScheme, crypto::SerializableKey, state::StateManager};
#[cfg(feature = "commitment-hash")]
use ioi_state::primitives::hash::HashCommitmentScheme;
#[cfg(feature = "commitment-kzg")]
use ioi_state::primitives::kzg::{KZGCommitmentScheme, KZGParams};
#[cfg(feature = "state-iavl")]
use ioi_state::tree::iavl::IAVLTree;
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
use ioi_validator::common::{GuardianSigner, LocalSigner, RemoteSigner};

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
        serde::Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
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

    let workload_probe_deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
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

    // Load optional Dilithium PQC keypair from the specified file.
    let pqc_keypair: Option<DilithiumKeyPair> = if let Some(path) = opts.pqc_key_file.as_ref() {
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

        let kp = DilithiumKeyPair::from_bytes(&pk_bytes, &sk_bytes)
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

    // [NEW] Determine Signing Strategy based on CLI arguments.
    // If an Oracle URL is provided, we use the RemoteSigner which connects to the
    // cryptographically isolated Signing Oracle.
    // If not, we fall back to the LocalSigner which signs using the key file directly.
    let signer: Arc<dyn GuardianSigner> = if let Some(oracle_url) = &opts.oracle_url {
        tracing::info!(target: "orchestration", "Using REMOTE Signing Oracle at {}", oracle_url);

        // Extract the raw ed25519 public key bytes for the RemoteSigner constructor
        let pk_bytes = local_key.public().encode_protobuf();
        let ed_pk = libp2p::identity::PublicKey::try_decode_protobuf(&pk_bytes)?
            .try_into_ed25519()?
            .to_bytes()
            .to_vec();

        Arc::new(RemoteSigner::new(oracle_url.clone(), ed_pk))
    } else {
        tracing::info!(target: "orchestration", "Using LOCAL signing key (Dev Mode).");
        // Convert the libp2p keypair to the internal crypto type used by LocalSigner
        // This requires exporting the secret key bytes and re-importing.
        // [FIX] Clone local_key before moving it into try_into_ed25519
        let sk_bytes = local_key.clone().try_into_ed25519()?.secret();
        let internal_sk =
            ioi_crypto::sign::eddsa::Ed25519PrivateKey::from_bytes(sk_bytes.as_ref())?;
        let internal_kp = ioi_crypto::sign::eddsa::Ed25519KeyPair::from_private_key(&internal_sk)?;

        Arc::new(LocalSigner::new(internal_kp))
    };

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
        signer, // [NEW] Inject the configured signer
    };

    let orchestration = Arc::new(Orchestrator::new(&opts.config, deps)?);

    // Share the same consensus engine instance between Orchestrator and ExecutionMachine.
    let consensus_for_chain = consensus_engine.clone();
    let chain_ref = {
        let tm = UnifiedTransactionModel::new(commitment_scheme.clone());

        // This is necessary for the transaction pre-check simulation to find required services.
        let mut initial_services = Vec::new();

        // --- WIRE PENALTIES SERVICE ---
        let penalty_engine: Arc<dyn ioi_consensus::PenaltyEngine> =
            Arc::new(consensus_engine.clone());
        let penalties_service = Arc::new(ioi_consensus::PenaltiesService::new(penalty_engine));
        // Cast to UpgradableService (we added the impl in consensus/service.rs)
        initial_services.push(penalties_service as Arc<dyn UpgradableService>);

        for service_config in &workload_config.initial_services {
            match service_config {
                InitialServiceConfig::IdentityHub(migration_config) => {
                    let hub = IdentityHub::new(migration_config.clone());
                    initial_services.push(Arc::new(hub) as Arc<dyn UpgradableService>);
                }
                InitialServiceConfig::Governance(params) => {
                    let gov = GovernanceModule::new(params.clone());
                    initial_services.push(Arc::new(gov) as Arc<dyn UpgradableService>);
                }
                InitialServiceConfig::Oracle(_params) => {
                    tracing::info!(target: "orchestration", event = "service_init", name = "Oracle", impl="proxy", capabilities="");
                    let oracle = OracleService::new();
                    initial_services.push(Arc::new(oracle) as Arc<dyn UpgradableService>);
                }
                #[cfg(feature = "ibc-deps")]
                InitialServiceConfig::Ibc(ibc_config) => {
                    // Orchestration needs to know about the IBC handler for tx pre-checks,
                    // even if the full logic lives in the workload.
                    // The verifier here uses a dummy state accessor since it's only for type resolution.
                    tracing::info!(target: "orchestration", event = "service_init", name = "IBC", impl="proxy", capabilities="ibc_handler");
                    let mut verifier_registry = VerifierRegistry::new();
                    for client_name_str in &ibc_config.enabled_clients {
                        if client_name_str.starts_with("tendermint") {
                            let tm_verifier = TendermintVerifier::new(
                                "cosmos-hub-test".to_string(), // Mock value, consistent with test
                                "07-tendermint-0".to_string(),
                                Arc::new(state_tree.clone()), // Use the orchestrator's dummy state tree
                            );
                            verifier_registry.register(Arc::new(tm_verifier));
                        }
                    }

                    #[cfg(feature = "ethereum-zk")]
                    {
                        use ioi_api::ibc::LightClient;
                        use ioi_services::ibc::light_clients::ethereum_zk::EthereumZkLightClient;

                        // Convert WorkloadConfig ZK settings to SuccinctDriverConfig
                        // NOTE: In the orchestrator, we don't enforce the VK hash match strictly
                        // during pre-checks unless we also load the keys here.
                        // For simplicity in this plumbing phase, we load if paths are present,
                        // or default to empty. The Workload container is the primary enforcer.

                        let zk_cfg = &workload_config.zk_config;
                        let load_vk = |path: &Option<String>,
                                       expected_hash: &str,
                                       label: &str|
                         -> Result<Vec<u8>> {
                            if let Some(p) = path {
                                let bytes = fs::read(p)
                                    .map_err(|e| anyhow!("Failed to read {} VK: {}", label, e))?;
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

                        // We use unwrap_or_default on the result of load_vk because the orchestrator
                        // doesn't strictly need to verify the proofs, just route them.
                        // However, constructing the verifier requires the config.
                        let beacon_bytes = load_vk(
                            &zk_cfg.beacon_vk_path,
                            &zk_cfg.ethereum_beacon_vkey,
                            "Beacon",
                        )
                        .unwrap_or_default();
                        let state_bytes =
                            load_vk(&zk_cfg.state_vk_path, &zk_cfg.state_inclusion_vkey, "State")
                                .unwrap_or_default();

                        let driver_config = SuccinctDriverConfig {
                            beacon_vkey_hash: zk_cfg.ethereum_beacon_vkey.clone(),
                            beacon_vkey_bytes: beacon_bytes,
                            state_inclusion_vkey_hash: zk_cfg.state_inclusion_vkey.clone(),
                            state_inclusion_vkey_bytes: state_bytes,
                        };

                        // Initialize with real config
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
                    // IBC feature not compiled in, but config asks for it. Do nothing.
                    // The transaction model will correctly reject the tx as unsupported.
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
            // [FIX] Use default_service_policies() for consistent dummy config
            service_policies: ioi_types::config::default_service_policies(),
            min_finality_depth: workload_config.min_finality_depth,
            keep_recent_heights: workload_config.keep_recent_heights,
            epoch_size: workload_config.epoch_size,
            // [FIX] Initialize gc_interval_secs
            gc_interval_secs: workload_config.gc_interval_secs,
            // [FIX] Add default ZK config
            zk_config: Default::default(),
        };

        let data_dir = opts.config.parent().unwrap_or_else(|| Path::new("."));
        let dummy_store_path = data_dir.join("orchestrator_dummy_store.db");
        let dummy_store = Arc::new(RedbEpochStore::open(&dummy_store_path, 50_000)?);

        let workload_container = Arc::new(ioi_api::validator::WorkloadContainer::new(
            dummy_workload_config,
            state_tree,
            Box::new(ioi_vm_wasm::WasmRuntime::new(Default::default())?), // Dummy VM
            service_directory, // <-- Pass the populated directory here
            dummy_store,
        )?);
        let mut machine = ExecutionMachine::new(
            commitment_scheme,
            tm,
            config.chain_id,
            initial_services,    // <-- And pass the instantiated services here
            consensus_for_chain, // Use the cloned engine
            workload_container,
            workload_config.service_policies.clone(), // [NEW] Pass policies
        )
        .map_err(|e| anyhow!("Failed to initialize ExecutionMachine: {}", e))?;

        for runtime_id in &workload_config.runtimes {
            let id = runtime_id.to_ascii_lowercase();
            if id == "wasm" {
                tracing::info!(
                    target: "orchestration",
                    "Registering WasmRuntime for tx pre-checks."
                );
                let wasm_runtime = WasmRuntime::new(Default::default())?;
                machine
                    .service_manager
                    .register_runtime("wasm", Arc::new(wasm_runtime));
            }
        }
        Arc::new(tokio::sync::Mutex::new(machine))
    };

    orchestration.set_chain_and_workload_client(chain_ref, workload_client.clone());

    // Set the chain_id env var so the gateway can label metrics correctly.
    std::env::set_var("GATEWAY_CHAIN_ID", config.chain_id.to_string());

    // --- NEW: IBC Host & Gateway Setup ---
    if let Some(gateway_addr) = config.ibc_gateway_listen_address.clone() {
        tracing::info!(target: "orchestration", "Enabling IBC HTTP Gateway.");
        let ibc_host = Arc::new(DefaultIbcHost::new(
            workload_client.clone(),
            verifier.clone(),
            orchestration.tx_pool.clone(),
            real_swarm_commander.clone(),
            local_key.clone(),
            orchestration.nonce_manager.clone(),
            config.chain_id,
        ));
        let gateway_config = http_rpc_gateway::GatewayConfig {
            listen_addr: gateway_addr,
            // These should come from config eventually
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

    orchestration.start("").await?;
    eprintln!("ORCHESTRATION_STARTUP_COMPLETE");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!(target: "orchestration", event = "shutdown", reason = "ctrl-c");
        }
    }

    tracing::info!(target: "orchestration", "Shutdown signal received.");
    orchestration.stop().await?;
    let data_dir = opts.config.parent().unwrap_or_else(|| Path::new("."));
    let _ = fs::remove_file(data_dir.join("orchestrator_dummy_store.db"));
    tracing::info!(target: "orchestration", event = "shutdown", reason = "complete");
    Ok(())
}

#[tokio::main]
#[allow(unused_variables)]
async fn main() -> Result<()> {
    // 1. Initialize tracing FIRST
    ioi_telemetry::init::init_tracing()?;

    // 2. Install the Prometheus sink
    let metrics_sink = ioi_telemetry::prometheus::install()?;

    // 3. Set all static sinks
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

    // 4. Spawn the telemetry server
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
            let mut bytes = Vec::new();
            fs::File::open(key_path)?.read_to_end(&mut bytes)?;
            identity::Keypair::from_protobuf_encoding(&bytes)?
        } else {
            let keypair = identity::Keypair::generate_ed25519();
            if let Some(parent) = key_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::File::create(key_path)?.write_all(&keypair.to_protobuf_encoding()?)?;
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
        _ => {
            let err_msg = format!("Unsupported or disabled state configuration: StateTree={:?}, CommitmentScheme={:?}. Please check your config and compile-time features.", workload_config.state_tree, workload_config.commitment_scheme);
            Err(anyhow!(err_msg))
        }
    }
}
