// Path: crates/node/src/bin/orchestration.rs
#![forbid(unsafe_code)]

use anyhow::{anyhow, Result};
use clap::Parser;
use depin_sdk_api::services::access::ServiceDirectory;
use depin_sdk_api::services::BlockchainService;
use depin_sdk_api::services::UpgradableService;
use depin_sdk_api::validator::container::Container;
use depin_sdk_chain::Chain;
use depin_sdk_client::WorkloadClient;
use depin_sdk_consensus::util::engine_from_config;
use depin_sdk_crypto::sign::dilithium::DilithiumKeyPair;
use depin_sdk_network::libp2p::Libp2pSync;
use depin_sdk_network::metrics as network_metrics;
use depin_sdk_services::governance::GovernanceModule;
// --- IBC Service Imports ---
#[cfg(feature = "ibc-deps")]
use depin_sdk_services::ibc::{
    channel::ChannelManager, light_client::tendermint::TendermintVerifier,
    registry::VerifierRegistry,
};
use depin_sdk_services::identity::IdentityHub;
use depin_sdk_services::oracle::OracleService;
use depin_sdk_storage::RedbEpochStore;
use depin_sdk_transaction_models::unified::UnifiedTransactionModel;
use depin_sdk_types::config::{InitialServiceConfig, OrchestrationConfig, WorkloadConfig};
use depin_sdk_validator::metrics as validator_metrics;
use depin_sdk_validator::standard::orchestration::OrchestrationDependencies;
use depin_sdk_validator::standard::{
    orchestration::verifier_select::{create_default_verifier, DefaultVerifier},
    OrchestrationContainer,
};
use depin_sdk_vm_wasm::WasmRuntime;
use http_rpc_gateway;
use ibc_host::DefaultIbcHost;
use libp2p::identity;
use libp2p::Multiaddr;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{atomic::AtomicBool, Arc};

// Imports for concrete types used in the factory
use depin_sdk_api::{commitment::CommitmentScheme, state::StateManager};
#[cfg(feature = "primitive-hash")]
use depin_sdk_commitment::primitives::hash::HashCommitmentScheme;
#[cfg(feature = "primitive-kzg")]
use depin_sdk_commitment::primitives::kzg::{KZGCommitmentScheme, KZGParams};
#[cfg(feature = "tree-iavl")]
use depin_sdk_commitment::tree::iavl::IAVLTree;
#[cfg(feature = "tree-sparse-merkle")]
use depin_sdk_commitment::tree::sparse_merkle::SparseMerkleTree;
#[cfg(feature = "tree-verkle")]
use depin_sdk_commitment::tree::verkle::VerkleTree;

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
}

/// Runtime check to ensure exactly one state tree feature is enabled.
fn check_features() {
    let mut enabled_features = Vec::new();
    if cfg!(feature = "tree-iavl") {
        enabled_features.push("tree-iavl");
    }
    if cfg!(feature = "tree-sparse-merkle") {
        enabled_features.push("tree-sparse-merkle");
    }
    if cfg!(feature = "tree-verkle") {
        enabled_features.push("tree-verkle");
    }

    if enabled_features.len() != 1 {
        panic!(
            "Error: Please enable exactly one 'tree-*' feature for the depin-sdk-node crate. Found: {:?}",
            enabled_features
        );
    }
}

// Conditionally define a type alias for the optional KZG parameters.
// This allows the run_orchestration function to have a single signature
// that adapts based on compile-time features.
#[cfg(feature = "primitive-kzg")]
type OptionalKzgParams = Option<KZGParams>;
#[cfg(not(feature = "primitive-kzg"))]
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
            Commitment = <DefaultVerifier as depin_sdk_api::state::Verifier>::Commitment,
            Proof = <DefaultVerifier as depin_sdk_api::state::Verifier>::Proof,
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
    let derived_genesis_hash: [u8; 32] =
        depin_sdk_crypto::algorithms::hash::sha256(&genesis_bytes)?;

    let workload_client = {
        // --- Startup Identity Check ---
        let identity_path = data_dir.join("chain_identity.json");
        let configured_identity = (config.chain_id, derived_genesis_hash);

        if identity_path.exists() {
            let stored_bytes = fs::read(&identity_path)?;
            let stored_identity: (depin_sdk_types::app::ChainId, [u8; 32]) =
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

    let deps = OrchestrationDependencies {
        syncer,
        network_event_receiver,
        swarm_command_sender: real_swarm_commander.clone(),
        consensus_engine: consensus_engine.clone(), // Pass a clone to the container
        local_keypair: local_key.clone(),
        pqc_keypair,
        is_quarantined,
        genesis_hash: derived_genesis_hash,
        verifier: verifier.clone(),
    };

    let orchestration = Arc::new(OrchestrationContainer::new(&opts.config, deps)?);

    // Share the same consensus engine instance between Orchestrator and Chain.
    let consensus_for_chain = consensus_engine.clone();
    let chain_ref = {
        let tm = UnifiedTransactionModel::new(commitment_scheme.clone());

        // This is necessary for the transaction pre-check simulation to find required services.
        let mut initial_services = Vec::new();
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
            min_finality_depth: workload_config.min_finality_depth,
            keep_recent_heights: workload_config.keep_recent_heights,
            epoch_size: workload_config.epoch_size,
        };

        let data_dir = opts.config.parent().unwrap_or_else(|| Path::new("."));
        let dummy_store_path = data_dir.join("orchestrator_dummy_store.db");
        let dummy_store = Arc::new(RedbEpochStore::open(&dummy_store_path, 50_000)?);

        let workload_container = Arc::new(depin_sdk_api::validator::WorkloadContainer::new(
            dummy_workload_config,
            state_tree,
            Box::new(depin_sdk_vm_wasm::WasmRuntime::new(Default::default())?), // Dummy VM
            service_directory, // <-- Pass the populated directory here
            dummy_store,
        )?);
        let mut chain = Chain::new(
            commitment_scheme,
            tm,
            config.chain_id,
            initial_services,    // <-- And pass the instantiated services here
            consensus_for_chain, // Use the cloned engine
            workload_container,
        );

        for runtime_id in &workload_config.runtimes {
            let id = runtime_id.to_ascii_lowercase();
            if id == "wasm" {
                tracing::info!(
                    target: "orchestration",
                    "Registering WasmRuntime for tx pre-checks."
                );
                let wasm_runtime = WasmRuntime::new(Default::default())?;
                chain
                    .service_manager
                    .register_runtime("wasm", Arc::new(wasm_runtime));
            }
        }
        Arc::new(tokio::sync::Mutex::new(chain))
    };

    orchestration.set_chain_and_workload_client(chain_ref, workload_client.clone());

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
        let gateway_handle = tokio::spawn(async move {
            if let Err(e) =
                http_rpc_gateway::run_server(gateway_config, ibc_host, shutdown_rx_for_gateway)
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
    depin_sdk_telemetry::init::init_tracing()?;

    // 2. Install the Prometheus sink
    let metrics_sink = depin_sdk_telemetry::prometheus::install()?;

    // 3. Set all static sinks
    depin_sdk_storage::metrics::SINK
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
    tokio::spawn(depin_sdk_telemetry::http::run_server(telemetry_addr));

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

    match (
        workload_config.state_tree.clone(),
        workload_config.commitment_scheme.clone(),
    ) {
        #[cfg(all(feature = "tree-iavl", feature = "primitive-hash"))]
        (
            depin_sdk_types::config::StateTreeType::IAVL,
            depin_sdk_types::config::CommitmentSchemeType::Hash,
        ) => {
            let scheme = HashCommitmentScheme::new();
            let tree = IAVLTree::new(scheme.clone());
            run_orchestration(opts, config, local_key, tree, scheme, workload_config, None).await
        }
        #[cfg(all(feature = "tree-sparse-merkle", feature = "primitive-hash"))]
        (
            depin_sdk_types::config::StateTreeType::SparseMerkle,
            depin_sdk_types::config::CommitmentSchemeType::Hash,
        ) => {
            let scheme = HashCommitmentScheme::new();
            let tree = SparseMerkleTree::new(scheme.clone());
            run_orchestration(opts, config, local_key, tree, scheme, workload_config, None).await
        }
        #[cfg(all(feature = "tree-verkle", feature = "primitive-kzg"))]
        (
            depin_sdk_types::config::StateTreeType::Verkle,
            depin_sdk_types::config::CommitmentSchemeType::KZG,
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
