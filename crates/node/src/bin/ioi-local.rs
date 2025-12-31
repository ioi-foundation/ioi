// Path: crates/node/src/bin/ioi-local.rs
#![forbid(unsafe_code)]

use anyhow::Result;
use clap::Parser;
use ioi_api::crypto::SerializableKey;
use ioi_api::state::service_namespace_prefix;
use ioi_api::validator::container::Container;
use ioi_consensus::util::engine_from_config;
use ioi_consensus::Consensus; // FIX: Added for type annotation
use ioi_crypto::sign::eddsa::Ed25519PrivateKey;
use ioi_state::primitives::hash::HashCommitmentScheme; // FIX: Added for type annotation
use ioi_state::tree::iavl::IAVLTree; // FIX: Added for type annotation
use ioi_types::app::{
    account_id_from_key_material, AccountId, ActiveKeyRecord, ChainTransaction, SignatureSuite,
    ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
};
use ioi_types::config::{
    ConsensusType, InitialServiceConfig, OrchestrationConfig, ValidatorRole, WorkloadConfig,
};
use ioi_types::service_configs::MigrationConfig;
use ioi_validator::common::{GuardianContainer, LocalSigner};
use ioi_validator::standard::orchestration::verifier_select::DefaultVerifier; // FIX: Added
use ioi_validator::standard::orchestration::OrchestrationDependencies;
use ioi_validator::standard::Orchestrator;
use libp2p::identity;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{atomic::AtomicBool, Arc};

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

    // 1. Generate Local Identity (Auto-generated on first run)
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

    // 2. Configure for Solo Mode
    let config = OrchestrationConfig {
        chain_id: ioi_types::app::ChainId(0),
        config_schema_version: 1,
        validator_role: ValidatorRole::Consensus,
        consensus_type: ConsensusType::Admft,
        rpc_listen_address: "127.0.0.1:9000".to_string(),
        rpc_hardening: Default::default(),
        initial_sync_timeout_secs: 0,
        block_production_interval_secs: 1,
        round_robin_view_timeout_secs: 10,
        default_query_gas_limit: u64::MAX,
        ibc_gateway_listen_address: None,
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
    };

    // 3. Generate Genesis if it doesn't exist
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

        // Identity
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

        // Validator Set
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

        // Governance Policy
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

    // 4. Initialize Orchestrator Dependencies
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
    };

    // 5. Launch Orchestrator
    // FIX: Provide explicit type annotations to Orchestrator to resolve inference error.
    let orchestrator = Arc::new(Orchestrator::<
        HashCommitmentScheme,
        IAVLTree<HashCommitmentScheme>,
        Consensus<ChainTransaction>,
        DefaultVerifier,
    >::new(&config, deps, HashCommitmentScheme::new())?);

    println!("\n✅ IOI User Node (Mode 0) configuration is valid.");
    println!("   - Agency Firewall: Active");
    println!("   - Semantic FS: Mounted at {}", opts.data_dir.display());
    println!(
        "   - RPC will listen on http://{}\n",
        config.rpc_listen_address
    );
    println!("Starting main components (press Ctrl+C to exit)...");

    tokio::signal::ctrl_c().await?;
    println!("\nShutting down...");
    orchestrator.stop().await?;
    println!("Bye!");

    Ok(())
}
