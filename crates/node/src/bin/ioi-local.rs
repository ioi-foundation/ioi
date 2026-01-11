// Path: crates/node/src/bin/ioi-local.rs
#![forbid(unsafe_code)]

use anyhow::{anyhow, Result};
use clap::Parser;
use ioi_api::crypto::SerializableKey;
use ioi_api::state::service_namespace_prefix;
use ioi_api::validator::container::Container;
use ioi_consensus::util::engine_from_config;
use ioi_consensus::Consensus;
use ioi_crypto::sign::eddsa::Ed25519PrivateKey;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::gui::IoiGuiDriver;
use ioi_scs::{SovereignContextStore, StoreConfig}; // [NEW] Import SCS
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::{
    account_id_from_key_material, AccountId, ActiveKeyRecord, ChainTransaction, SignatureSuite,
    ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
};
use ioi_types::config::{
    ConsensusType, InitialServiceConfig, OrchestrationConfig, ValidatorRole, WorkloadConfig,
};
use ioi_types::service_configs::MigrationConfig;
use ioi_validator::common::{GuardianContainer, LocalSigner};
use ioi_validator::firewall::inference::MockBitNet;
use ioi_validator::standard::orchestration::verifier_select::DefaultVerifier;
use ioi_validator::standard::orchestration::OrchestrationDependencies;
use ioi_validator::standard::workload::setup::setup_workload;
use ioi_validator::standard::Orchestrator;
use libp2p::identity;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{atomic::AtomicBool, Arc, Mutex}; // [FIX] Reverted to std Mutex for SCS
use tokio::time::Duration;

#[derive(Parser, Debug)]
#[clap(name = "ioi-local", about = "IOI User Node (Mode 0)")]
struct LocalOpts {
    #[clap(long, default_value = "./ioi-data")]
    data_dir: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    ioi_telemetry::init::init_tracing()?;

    let opts = LocalOpts::parse();
    fs::create_dir_all(&opts.data_dir)?;

    let key_path = opts.data_dir.join("identity.key");
    let local_key = if key_path.exists() {
        let raw = GuardianContainer::load_encrypted_file(&key_path)?;
        identity::Keypair::from_protobuf_encoding(&raw)?
    } else {
        println!("Initializing new User Node Identity...");
        let kp = identity::Keypair::generate_ed25519();
        if std::env::var("IOI_GUARDIAN_KEY_PASS").is_err() {
            std::env::set_var("IOI_GUARDIAN_KEY_PASS", "local-mode");
        }
        GuardianContainer::save_encrypted_file(&key_path, &kp.to_protobuf_encoding()?)?;
        kp
    };
    let local_account_id = AccountId(account_id_from_key_material(
        SignatureSuite::ED25519,
        &local_key.public().encode_protobuf(),
    )?);

    // [NEW] Initialize the Sovereign Context Store (SCS)
    let scs_path = opts.data_dir.join("context.scs");
    let scs_config = StoreConfig {
        chain_id: 0,
        owner_id: local_account_id.0,
    };

    let scs = if scs_path.exists() {
        println!(
            "Opening existing Sovereign Context Substrate at {:?}",
            scs_path
        );
        SovereignContextStore::open(&scs_path)?
    } else {
        println!("Creating new Sovereign Context Substrate at {:?}", scs_path);
        SovereignContextStore::create(&scs_path, scs_config)?
    };
    // Wrap in Arc<Mutex> for shared access using STD MUTEX
    let scs_arc: Arc<Mutex<SovereignContextStore>> = Arc::new(Mutex::new(scs));

    let rpc_addr = std::env::var("ORCHESTRATION_RPC_LISTEN_ADDRESS")
        .unwrap_or_else(|_| "0.0.0.0:9000".to_string());

    let config = OrchestrationConfig {
        chain_id: ioi_types::app::ChainId(0),
        config_schema_version: 1,
        validator_role: ValidatorRole::Consensus,
        consensus_type: ConsensusType::Admft,
        rpc_listen_address: rpc_addr.clone(),
        rpc_hardening: Default::default(),
        initial_sync_timeout_secs: 0,
        block_production_interval_secs: 1,
        round_robin_view_timeout_secs: 10,
        default_query_gas_limit: u64::MAX,
        ibc_gateway_listen_address: None,
        safety_model_path: None,
        tokenizer_path: None,
    };

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
        initial_services: vec![
            InitialServiceConfig::IdentityHub(MigrationConfig {
                chain_id: 0,
                grace_period_blocks: 100,
                accept_staged_during_grace: true,
                allowed_target_suites: vec![SignatureSuite::ED25519, SignatureSuite::ML_DSA_44],
                allow_downgrade: false,
            }),
            InitialServiceConfig::Governance(Default::default()),
            InitialServiceConfig::Oracle(Default::default()),
        ],
        service_policies: ioi_types::config::default_service_policies(),
        min_finality_depth: 0,
        keep_recent_heights: 1000,
        epoch_size: 1000,
        gc_interval_secs: 3600,
        zk_config: Default::default(),
        inference: Default::default(),
        fast_inference: None,
        reasoning_inference: None,
        connectors: Default::default(),
    };

    if !Path::new(&workload_config.genesis_file).exists() {
        println!("Generating new genesis file for local mode...");
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use ioi_types::codec::to_bytes_canonical;
        use ioi_types::keys::*;
        use ioi_types::service_configs::{GovernancePolicy, GovernanceSigner};
        let mut genesis_state = serde_json::Map::new();
        let mut insert_raw = |key: &[u8], encoded_val: Vec<u8>| {
            let key_str = format!("b64:{}", BASE64.encode(key));
            let val_str = format!("b64:{}", BASE64.encode(encoded_val));
            genesis_state.insert(key_str, serde_json::Value::String(val_str));
        };
        let cred = ioi_types::app::Credential {
            suite: SignatureSuite::ED25519,
            public_key_hash: local_account_id.0,
            activation_height: 0,
            l2_location: None,
            weight: 1,
        };
        let creds_key = [
            service_namespace_prefix("identity_hub").as_slice(),
            IDENTITY_CREDENTIALS_PREFIX,
            local_account_id.as_ref(),
        ]
        .concat();
        insert_raw(&creds_key, to_bytes_canonical(&[Some(cred), None]).unwrap());
        insert_raw(
            &[ACCOUNT_ID_TO_PUBKEY_PREFIX, local_account_id.as_ref()].concat(),
            to_bytes_canonical(&local_key.public().encode_protobuf()).unwrap(),
        );
        let vs = ValidatorSetsV1 {
            current: ValidatorSetV1 {
                effective_from_height: 1,
                total_weight: 1,
                validators: vec![ValidatorV1 {
                    account_id: local_account_id,
                    weight: 1,
                    consensus_key: ActiveKeyRecord {
                        suite: SignatureSuite::ED25519,
                        public_key_hash: local_account_id.0,
                        since_height: 0,
                    },
                }],
            },
            next: None,
        };
        insert_raw(VALIDATOR_SET_KEY, to_bytes_canonical(&vs).unwrap());
        insert_raw(
            GOVERNANCE_KEY,
            to_bytes_canonical(&GovernancePolicy {
                signer: GovernanceSigner::Single(local_account_id),
            })
            .unwrap(),
        );
        let json = serde_json::json!({ "genesis_state": genesis_state });
        fs::write(
            &workload_config.genesis_file,
            serde_json::to_string_pretty(&json)?,
        )?;
    }

    // [NEW] Initialize the Native GUI Driver (The "Eyes & Hands")
    let gui_driver = Arc::new(IoiGuiDriver::new());
    println!("   - Native GUI Driver: Initialized (enigo/xcap/accesskit)");

    // [NEW] Initialize Browser Driver
    let browser_driver = Arc::new(BrowserDriver::new());
    println!("   - Browser Driver: Initialized (chromiumoxide)");

    // Pass driver and SCS to workload setup
    let scheme = HashCommitmentScheme::new();
    let tree = IAVLTree::new(scheme.clone());
    let (workload_container, machine) = setup_workload(
        tree,
        scheme.clone(),
        workload_config.clone(),
        Some(gui_driver),
        Some(browser_driver),
        Some(scs_arc.clone()), // [NEW] Pass SCS
    )
    .await?;

    let workload_ipc_addr = "127.0.0.1:8555";
    std::env::set_var("IPC_SERVER_ADDR", workload_ipc_addr);

    let server_workload = workload_container.clone();
    let server_machine = machine.clone();
    let server_addr = workload_ipc_addr.to_string();

    let workload_server_handle = tokio::spawn(async move {
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

    let (syncer, swarm_commander, network_events) = ioi_networking::libp2p::Libp2pSync::new(
        local_key.clone(),
        "/ip4/127.0.0.1/tcp/0".parse()?,
        None,
    )?;

    let consensus_engine = engine_from_config(&config)?;
    let sk_bytes = local_key.clone().try_into_ed25519()?.secret();
    let internal_sk = Ed25519PrivateKey::from_bytes(sk_bytes.as_ref())?;
    let internal_kp = ioi_crypto::sign::eddsa::Ed25519KeyPair::from_private_key(&internal_sk)?;
    let signer = Arc::new(LocalSigner::new(internal_kp));

    let safety_model = Arc::new(MockBitNet);

    let deps = OrchestrationDependencies {
        syncer,
        network_event_receiver: network_events,
        swarm_command_sender: swarm_commander,
        consensus_engine,
        local_keypair: local_key.clone(),
        pqc_keypair: None,
        is_quarantined: Arc::new(AtomicBool::new(false)),
        genesis_hash: [0; 32],
        verifier: DefaultVerifier::default(),
        signer,
        batch_verifier: Arc::new(ioi_crypto::sign::batch::CpuBatchVerifier::new()),
        safety_model: safety_model,
    };

    let orchestrator = Arc::new(Orchestrator::new(&config, deps, scheme)?);
    orchestrator.set_chain_and_workload_client(machine, workload_client);

    println!("\n✅ IOI User Node (Mode 0) configuration is valid.");
    println!("   - Agency Firewall: Active");
    println!("   - The Substrate: Mounted at {}", opts.data_dir.display());
    println!("   - SCS Storage: Active (.scs)"); // [NEW]
    println!("   - GUI Automation: Enabled");
    println!("   - Browser Automation: Enabled");
    println!(
        "   - RPC will listen on http://{}",
        config.rpc_listen_address
    );
    println!("Starting main components (press Ctrl+C to exit)...");

    orchestrator
        .start(&config.rpc_listen_address)
        .await
        .map_err(|e| anyhow!("Failed to start: {}", e))?;

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("\nShutdown signal received.");
        }
        res = workload_server_handle => {
            match res {
                Ok(Err(e)) => return Err(anyhow!("Workload IPC Server crashed: {}", e)),
                Ok(Ok(_)) => return Err(anyhow!("Workload IPC Server exited unexpectedly.")),
                Err(e) => return Err(anyhow!("Workload IPC Server task panicked: {}", e)),
            }
        }
    }

    println!("\nShutting down...");
    orchestrator.stop().await?;
    println!("Bye!");

    Ok(())
}
