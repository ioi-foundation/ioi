// Path: crates/node/src/bin/ioi-provider.rs
#![forbid(unsafe_code)]

//! The IOI Compute Provider Node (Type B).
//!
//! Responsible for executing heavy AI inference tasks and generating ZK proofs.
//! Operates as a Light Client to the consensus chain, listening for Job Tickets.

use anyhow::{anyhow, Result};
use clap::Parser;
use ioi_api::crypto::SerializableKey;
use ioi_api::state::{StateAccess, StateManager};
use ioi_api::validator::container::Container;
use ioi_consensus::util::engine_from_config;
use ioi_crypto::sign::eddsa::Ed25519PrivateKey;
use ioi_state::primitives::hash::HashCommitmentScheme;
// Use IAVL for light client verification
#[cfg(feature = "state-iavl")]
use ioi_state::tree::iavl::IAVLTree;

use ioi_types::app::{account_id_from_key_material, AccountId, SignatureSuite};
use ioi_types::config::{
    ConsensusType, InferenceConfig, InitialServiceConfig, OrchestrationConfig, ValidatorRole,
    WorkloadConfig,
};
use ioi_validator::common::{GuardianContainer, LocalSigner};
use ioi_validator::standard::orchestration::verifier_select::{
    create_default_verifier, DefaultVerifier,
};
use ioi_validator::standard::orchestration::OrchestrationDependencies;
use ioi_validator::standard::workload::setup::setup_workload;
use ioi_validator::standard::Orchestrator;
use libp2p::{identity, Multiaddr};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{atomic::AtomicBool, Arc, Mutex};
use tokio::time::Duration;

use ioi_api::vm::inference::{HttpInferenceRuntime, InferenceRuntime, LocalSafetyModel};
use ioi_drivers::os::NativeOsDriver;
use ioi_networking::libp2p::Libp2pSync;
use ioi_services::agentic::pii_adapter::RuntimeAsPiiModel;

// [FIX] Compute Specific Drivers
use ioi_validator::standard::workload::drivers::cpu::CpuDriver;
use ioi_validator::standard::workload::hydration::ModelHydrator;
use ioi_validator::standard::workload::runtime::StandardInferenceRuntime;

// [NEW] Provider API
use ioi_validator::standard::provider::{server::run_provider_server, ProviderController};
use std::net::SocketAddr;

#[derive(Parser, Debug)]
#[clap(name = "ioi-provider", about = "IOI Compute Provider (Type B)")]
struct ProviderOpts {
    #[clap(long, default_value = "./ioi-provider-data")]
    data_dir: PathBuf,

    #[clap(long, help = "Path to the model storage directory")]
    model_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    ioi_telemetry::init::init_tracing()?;
    let opts = ProviderOpts::parse();
    fs::create_dir_all(&opts.data_dir)?;
    let model_dir = opts.model_dir.unwrap_or(opts.data_dir.join("models"));
    fs::create_dir_all(&model_dir)?;

    // 1. Identity
    let key_path = opts.data_dir.join("identity.key");
    let local_key = if key_path.exists() {
        let raw = GuardianContainer::load_encrypted_file(&key_path)?;
        identity::Keypair::from_protobuf_encoding(&raw)?
    } else {
        println!("Initializing new Provider Identity...");
        let kp = identity::Keypair::generate_ed25519();
        if std::env::var("IOI_GUARDIAN_KEY_PASS").is_err() {
            println!("WARNING: IOI_GUARDIAN_KEY_PASS not set.");
        }
        GuardianContainer::save_encrypted_file(&key_path, &kp.to_protobuf_encoding()?)?;
        kp
    };

    // 2. Config - Optimized for Compute
    let config = OrchestrationConfig {
        chain_id: ioi_types::app::ChainId(1),
        config_schema_version: 1,
        validator_role: ValidatorRole::Compute {
            accelerator_type: "cpu-candle".to_string(), // Detect hardware in real implementation
            vram_capacity: 0,
        },
        consensus_type: ConsensusType::Admft, // Follows chain consensus
        rpc_listen_address: "0.0.0.0:8545".to_string(),
        rpc_hardening: Default::default(),
        initial_sync_timeout_secs: 5,
        block_production_interval_secs: 2,
        round_robin_view_timeout_secs: 20,
        default_query_gas_limit: 10_000_000,
        ibc_gateway_listen_address: None, // No IBC gateway needed
        safety_model_path: None,
        tokenizer_path: None,
    };

    // 3. Setup Heavy Inference Runtime
    let cpu_driver = Arc::new(CpuDriver::new());
    let hydrator = Arc::new(ModelHydrator::new(model_dir.clone(), cpu_driver.clone()));

    // The "Standard" runtime supports hydration and hardware offload
    let inference_runtime = Arc::new(StandardInferenceRuntime::new(hydrator, cpu_driver));

    let safety_model = Arc::new(RuntimeAsPiiModel::new(inference_runtime.clone()));

    // 4. Workload Config
    let workload_config = WorkloadConfig {
        runtimes: vec!["wasm".to_string()],
        state_tree: ioi_types::config::StateTreeType::IAVL,
        commitment_scheme: ioi_types::config::CommitmentSchemeType::Hash,
        consensus_type: ConsensusType::Admft,
        genesis_file: opts
            .data_dir
            .join("genesis.json")
            .to_string_lossy()
            .to_string(),
        state_file: opts.data_dir.join("state.db").to_string_lossy().to_string(),
        srs_file_path: None,
        fuel_costs: Default::default(),
        initial_services: vec![], // Minimal services for a provider
        service_policies: ioi_types::config::default_service_policies(),
        min_finality_depth: 100,
        keep_recent_heights: 1000,
        epoch_size: 50_000,
        gc_interval_secs: 3600,
        zk_config: Default::default(),
        inference: Default::default(), // Using custom runtime construction above
        fast_inference: None,
        reasoning_inference: None,
        connectors: Default::default(),
        mcp_servers: Default::default(),
    };

    // 5. Setup Stack
    #[cfg(feature = "state-iavl")]
    let scheme = HashCommitmentScheme::new();
    #[cfg(feature = "state-iavl")]
    let tree = IAVLTree::new(scheme.clone());

    let os_driver = Arc::new(NativeOsDriver::new());

    let (workload_container, machine) = setup_workload(
        tree,
        scheme.clone(),
        workload_config.clone(),
        None,
        None,
        None,
        None,
        Some(os_driver.clone()),
    )
    .await?;

    // 6. Start Runtime
    let workload_ipc_addr = "127.0.0.1:8555";
    std::env::set_var("IPC_SERVER_ADDR", workload_ipc_addr);

    let server_workload = workload_container.clone();
    let server_machine = machine.clone();
    let server_addr = workload_ipc_addr.to_string();

    let mut workload_server_handle = tokio::spawn(async move {
        let server = ioi_validator::standard::workload::ipc::WorkloadIpcServer::new(
            server_addr,
            server_workload,
            server_machine,
        )
        .await
        .map_err(|e| anyhow!(e))?;
        server.run().await.map_err(|e| anyhow!(e))
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    // 7. Connect Orchestrator
    // (Standard logic...)
    let ca_path = opts.data_dir.join("ca.pem");
    let cert_path = opts.data_dir.join("orchestration.pem");
    let key_path = opts.data_dir.join("orchestration.key");

    let workload_client = Arc::new(
        ioi_client::WorkloadClient::new(
            workload_ipc_addr,
            &ca_path.to_string_lossy(),
            &cert_path.to_string_lossy(),
            &key_path.to_string_lossy(),
        )
        .await?,
    );

    // Full P2P for Provider (to receive Job Tickets)
    let (syncer, swarm_commander, network_events) = Libp2pSync::new(
        local_key.clone(),
        "/ip4/0.0.0.0/tcp/9000".parse()?, // Listen for jobs
        None,
    )?;

    let consensus_engine = engine_from_config(&config)?;
    let verifier = create_default_verifier(None);

    let sk_bytes = local_key.clone().try_into_ed25519()?.secret();
    let internal_sk = Ed25519PrivateKey::from_bytes(sk_bytes.as_ref())?;
    let internal_kp = ioi_crypto::sign::eddsa::Ed25519KeyPair::from_private_key(&internal_sk)?;

    // Using Arc<LocalSigner> concrete type for ProviderController constructor
    let local_signer_struct = LocalSigner::new(internal_kp);
    let local_signer_arc = Arc::new(local_signer_struct);

    // Cast to trait object for Orchestrator dependencies
    let signer: Arc<dyn ioi_validator::common::GuardianSigner> = local_signer_arc.clone();

    // --- NEW: Start Provider API Server ---
    let public_endpoint = format!("http://{}:9090", "127.0.0.1"); // Default local
    let controller = Arc::new(ProviderController::new(local_signer_arc, public_endpoint));

    let api_addr: SocketAddr = "0.0.0.0:9090".parse()?;

    // Spawn server in background
    tokio::spawn(async move {
        run_provider_server(controller, api_addr).await;
    });

    println!("   - Provider API: Active on port 9090");

    let deps = OrchestrationDependencies {
        syncer,
        network_event_receiver: network_events,
        swarm_command_sender: swarm_commander,
        consensus_engine,
        local_keypair: local_key.clone(),
        pqc_keypair: None,
        is_quarantined: Arc::new(AtomicBool::new(false)),
        genesis_hash: [0; 32],
        verifier,
        signer,
        batch_verifier: Arc::new(ioi_crypto::sign::batch::CpuBatchVerifier::new()),
        safety_model,
        inference_runtime,
        os_driver,
        scs: None,
        event_broadcaster: None,
    };

    let orchestrator = Arc::new(Orchestrator::new(&config, deps, scheme)?);
    orchestrator.set_chain_and_workload_client(machine.clone(), workload_client);

    println!("\n✅ IOI Compute Provider (Type B) Started.");
    println!("   - Capability: {}", "CPU-Candle");
    println!("   - Models Dir: {}", model_dir.display());

    Container::start(&*orchestrator, &config.rpc_listen_address).await?;

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = workload_server_handle => {}
    }

    Container::stop(&*orchestrator).await?;
    Ok(())
}
