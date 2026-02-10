// Path: crates/node/src/bin/ioi-validator.rs
#![forbid(unsafe_code)]

//! The IOI Validator Node (Type A).
//!
//! Responsible for block ordering, ledger security, and signature verification via A-DMFT.
//! This node joins the P2P mesh and maintains the global state.

use anyhow::{anyhow, Result};
use clap::Parser;
use ioi_api::crypto::SerializableKey;
use ioi_api::state::{StateAccess, StateManager};
use ioi_api::validator::container::Container;
use ioi_client::WorkloadClient;
use ioi_consensus::util::engine_from_config;
use ioi_crypto::sign::eddsa::Ed25519PrivateKey;
use ioi_execution::ExecutionMachine;
use ioi_networking::libp2p::Libp2pSync;
use ioi_storage::RedbEpochStore;
use ioi_tx::unified::UnifiedTransactionModel;
use ioi_types::app::{account_id_from_key_material, AccountId, ChainTransaction, SignatureSuite};
use ioi_types::config::{
    ConsensusType, InitialServiceConfig, OrchestrationConfig, ValidatorRole, WorkloadConfig,
};
use ioi_types::service_configs::MigrationConfig;
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
use tokio::sync::Mutex as TokioMutex;
use tokio::time::Duration;

// State Trees
#[cfg(feature = "commitment-hash")]
use ioi_state::primitives::hash::HashCommitmentScheme;
#[cfg(feature = "state-iavl")]
use ioi_state::tree::iavl::IAVLTree;

use ioi_api::vm::inference::{InferenceRuntime, LocalSafetyModel};
use ioi_drivers::os::NativeOsDriver;
use ioi_services::agentic::scrub_adapter::RuntimeAsSafetyModel;

#[derive(Parser, Debug)]
#[clap(name = "ioi-validator", about = "IOI Consensus Validator (Type A)")]
struct ValidatorOpts {
    #[clap(long, default_value = "./ioi-data")]
    data_dir: PathBuf,

    #[clap(
        long,
        env = "LISTEN_ADDRESS",
        default_value = "/ip4/0.0.0.0/tcp/9000",
        help = "Address to listen for p2p connections"
    )]
    listen_address: Multiaddr,

    #[clap(
        long,
        env = "BOOTNODE",
        use_value_delimiter = true,
        help = "One or more bootnode addresses to connect to"
    )]
    bootnode: Vec<Multiaddr>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    ioi_telemetry::init::init_tracing()?;

    let opts = ValidatorOpts::parse();
    fs::create_dir_all(&opts.data_dir)?;

    // 1. Identity
    let key_path = opts.data_dir.join("identity.key");
    let local_key = if key_path.exists() {
        let raw = GuardianContainer::load_encrypted_file(&key_path)?;
        identity::Keypair::from_protobuf_encoding(&raw)?
    } else {
        println!("Initializing new Validator Identity...");
        let kp = identity::Keypair::generate_ed25519();
        if std::env::var("IOI_GUARDIAN_KEY_PASS").is_err() {
            println!(
                "WARNING: IOI_GUARDIAN_KEY_PASS not set. Key will be encrypted interactively."
            );
        }
        GuardianContainer::save_encrypted_file(&key_path, &kp.to_protobuf_encoding()?)?;
        kp
    };
    let local_account_id = AccountId(account_id_from_key_material(
        SignatureSuite::ED25519,
        &local_key.public().encode_protobuf(),
    )?);

    println!("Validator ID: 0x{}", hex::encode(local_account_id.as_ref()));

    // 2. Configuration (Hardcoded for Mainnet/Testnet defaults)
    let config = OrchestrationConfig {
        chain_id: ioi_types::app::ChainId(1), // Mainnet ID
        config_schema_version: 1,
        validator_role: ValidatorRole::Consensus,
        consensus_type: ConsensusType::Admft,
        rpc_listen_address: "0.0.0.0:8545".to_string(), // Public RPC
        rpc_hardening: Default::default(),
        initial_sync_timeout_secs: 5,
        block_production_interval_secs: 2,
        round_robin_view_timeout_secs: 20,
        default_query_gas_limit: 10_000_000,
        ibc_gateway_listen_address: Some("0.0.0.0:9876".to_string()),
        safety_model_path: None,
        tokenizer_path: None,
    };

    // Default Services for a Validator
    let initial_services = vec![
        InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 100,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::ED25519, SignatureSuite::ML_DSA_44],
            allow_downgrade: false,
        }),
        InitialServiceConfig::Governance(Default::default()),
        InitialServiceConfig::Oracle(Default::default()),
        // Add IBC config if needed
    ];

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
        initial_services,
        service_policies: ioi_types::config::default_service_policies(),
        min_finality_depth: 1000,
        keep_recent_heights: 100_000,
        epoch_size: 50_000,
        gc_interval_secs: 3600,
        zk_config: Default::default(),
        inference: Default::default(), // No AI needed for consensus
        fast_inference: None,
        reasoning_inference: None,
        connectors: Default::default(),
        mcp_servers: Default::default(),
    };

    // 3. State Setup (Merkle Tree)
    #[cfg(feature = "state-iavl")]
    let scheme = HashCommitmentScheme::new();
    #[cfg(feature = "state-iavl")]
    let tree = IAVLTree::new(scheme.clone());

    // 4. Drivers (Minimal)
    let os_driver = Arc::new(NativeOsDriver::new());
    // Mock inference for safety checks (Validator doesn't need heavy models)
    let inference_runtime = Arc::new(ioi_api::vm::inference::mock::MockInferenceRuntime);
    let safety_model = Arc::new(RuntimeAsSafetyModel::new(inference_runtime.clone()));

    // 5. Setup Workload
    let (workload_container, machine) = setup_workload(
        tree,
        scheme.clone(),
        workload_config.clone(),
        None, // No GUI
        None, // No Browser
        None, // No SCS
        None, // No Event Sender
        Some(os_driver.clone()),
    )
    .await?;

    // 6. Start Workload Server
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

    // 7. Orchestrator Setup
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

    // Full P2P Sync
    let (syncer, swarm_commander, network_events) =
        Libp2pSync::new(local_key.clone(), opts.listen_address, Some(&opts.bootnode))?;

    // A-DMFT Consensus
    let consensus_engine = engine_from_config(&config)?;
    let verifier = create_default_verifier(None);

    let sk_bytes = local_key.clone().try_into_ed25519()?.secret();
    let internal_sk = Ed25519PrivateKey::from_bytes(sk_bytes.as_ref())?;
    let internal_kp = ioi_crypto::sign::eddsa::Ed25519KeyPair::from_private_key(&internal_sk)?;
    let signer = Arc::new(LocalSigner::new(internal_kp));

    let deps = OrchestrationDependencies {
        syncer,
        network_event_receiver: network_events,
        swarm_command_sender: swarm_commander,
        consensus_engine,
        local_keypair: local_key.clone(),
        pqc_keypair: None,
        is_quarantined: Arc::new(AtomicBool::new(false)),
        genesis_hash: [0; 32], // Todo: Compute from genesis file
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

    println!("\n✅ IOI Validator Node (Type A) Started.");
    println!("   - Consensus: A-DMFT (Active)");
    println!("   - P2P: Listening on {}", config.rpc_listen_address);

    Container::start(&*orchestrator, &config.rpc_listen_address).await?;

    // Wait for shutdown
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("Shutdown signal received.");
        }
        _ = workload_server_handle => {
            println!("Workload server crashed.");
        }
    }

    Container::stop(&*orchestrator).await?;
    Ok(())
}
