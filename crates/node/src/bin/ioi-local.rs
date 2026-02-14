// Path: crates/node/src/bin/ioi-local.rs
#![forbid(unsafe_code)]

use anyhow::{anyhow, Result};
use clap::Parser;
use ioi_api::crypto::SerializableKey;
use ioi_api::state::service_namespace_prefix;
use ioi_api::state::{StateAccess, StateManager};
use ioi_api::validator::container::Container;
use ioi_consensus::solo::SoloEngine;

use ioi_crypto::sign::eddsa::Ed25519PrivateKey;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::gui::IoiGuiDriver;
use ioi_scs::{SovereignContextStore, StoreConfig};
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::flat::verifier::FlatVerifier;
use ioi_state::tree::flat::RedbFlatStore;

use ioi_types::app::{
    account_id_from_key_material, AccountId, ActiveKeyRecord, ChainTransaction, SignatureSuite,
    ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
};
use ioi_types::config::{
    ConsensusType, InitialServiceConfig, OrchestrationConfig, ValidatorRole, WorkloadConfig,
};
use ioi_types::service_configs::MigrationConfig;
use ioi_validator::common::{GuardianContainer, LocalSigner};
use ioi_validator::standard::orchestration::OrchestrationDependencies;
use ioi_validator::standard::workload::setup::setup_workload;
use ioi_validator::standard::Orchestrator;
use libp2p::identity;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{atomic::AtomicBool, Arc, Mutex};
use tokio::sync::Mutex as TokioMutex;
use tokio::time::Duration;

use ioi_types::service_configs::{ActiveServiceMeta, Capabilities, MethodPermission};

use ioi_consensus::Consensus;
use ioi_validator::standard::orchestration::context::MainLoopContext;
use ioi_validator::standard::orchestration::operator_tasks::{
    run_agent_driver_task, run_oracle_operator_task,
};

use ioi_api::vm::inference::{HttpInferenceRuntime, InferenceRuntime, LocalSafetyModel};
use ioi_drivers::os::NativeOsDriver;
use ioi_services::agentic::desktop::DesktopAgentService;
use ioi_services::agentic::rules::{ActionRules, DefaultPolicy, Rule, Verdict};
use ioi_services::agentic::scrub_adapter::RuntimeAsSafetyModel;
use ioi_types::codec;

// [UPDATED] Import Market Service types
use ioi_services::market::MarketService;
// [FIX] Import OptimizerService
use ioi_services::agentic::optimizer::OptimizerService;

// [NEW] Import for SwarmCommand
use ioi_networking::libp2p::SwarmCommand;
use ioi_networking::noop::NoOpBlockSync;

// [NEW] Import for Skill Injection
// [FIX] Used in commented out blocks or future extensions, keeping to avoid churn if needed
// use ioi_types::app::agentic::{AgentMacro, LlmToolDefinition};

#[derive(Parser, Debug)]
#[clap(name = "ioi-local", about = "IOI User Node (Mode 0)")]
struct LocalOpts {
    #[clap(long, default_value = "./ioi-data")]
    data_dir: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install default crypto provider for rustls 0.23+
    let _ = rustls::crypto::ring::default_provider().install_default();
    ioi_telemetry::init::init_tracing()?;

    let opts = LocalOpts::parse();
    fs::create_dir_all(&opts.data_dir)?;

    let abs_data_dir = fs::canonicalize(&opts.data_dir)?;
    let abs_data_dir_str = abs_data_dir.to_string_lossy().to_string();

    // 1. Identity Setup
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

    // 2. SCS Setup
    let scs_path = opts.data_dir.join("context.scs");

    // [FIX] Derive identity key from the local node key for SCS encryption
    let ed_kp = local_key
        .clone()
        .try_into_ed25519()
        .map_err(|_| anyhow!("SCS requires Ed25519 key in local mode"))?;
    let mut identity_key = [0u8; 32];
    identity_key.copy_from_slice(ed_kp.secret().as_ref());

    let scs_config = StoreConfig {
        chain_id: 0,
        owner_id: local_account_id.0,
        identity_key, // [FIX] Field added
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
    let scs_arc: Arc<Mutex<SovereignContextStore>> = Arc::new(Mutex::new(scs));

    // Agent Meta
    let mut agent_methods = std::collections::BTreeMap::new();
    agent_methods.insert("start@v1".to_string(), MethodPermission::User);
    agent_methods.insert("step@v1".to_string(), MethodPermission::User);
    agent_methods.insert("resume@v1".to_string(), MethodPermission::User);

    let agent_meta = ActiveServiceMeta {
        id: "desktop_agent".to_string(),
        abi_version: 1,
        state_schema: "v1".to_string(),
        caps: Capabilities::empty(),
        artifact_hash: [0u8; 32],
        activated_at: 0,
        methods: agent_methods,
        allowed_system_prefixes: vec![],
        generation_id: 0,
        parent_hash: None,
        author: Some(local_account_id), // [FIX] User owns their agent
        context_filter: None,           // [FIX] Initialize context_filter
    };

    let session_id = [0u8; 32];
    let local_policy = ActionRules {
        policy_id: "interactive-mode".to_string(),
        defaults: DefaultPolicy::RequireApproval,
        ontology_policy: Default::default(),
        rules: vec![
            Rule {
                rule_id: Some("allow-ui-read".into()),
                target: "gui::screenshot".into(),
                conditions: Default::default(),
                action: Verdict::Allow,
            },
            Rule {
                rule_id: Some("allow-lifecycle".into()),
                target: "start@v1".into(),
                conditions: Default::default(),
                action: Verdict::Allow,
            },
            Rule {
                rule_id: Some("allow-step".into()),
                target: "step@v1".into(),
                conditions: Default::default(),
                action: Verdict::Allow,
            },
            Rule {
                rule_id: Some("allow-resume".into()),
                target: "resume@v1".into(),
                conditions: Default::default(),
                action: Verdict::Allow,
            },
            Rule {
                rule_id: Some("allow-complete".into()),
                target: "agent__complete".into(),
                conditions: Default::default(),
                action: Verdict::Allow,
            },
            Rule {
                rule_id: Some("allow-pause".into()),
                target: "agent__pause".into(),
                conditions: Default::default(),
                action: Verdict::Allow,
            },
            Rule {
                rule_id: Some("allow-await".into()),
                target: "agent__await_result".into(),
                conditions: Default::default(),
                action: Verdict::Allow,
            },
            Rule {
                rule_id: Some("allow-chat".into()),
                target: "chat__reply".into(),
                conditions: Default::default(),
                action: Verdict::Allow,
            },
            // Allow echo for the test macro
            Rule {
                rule_id: Some("allow-sys-exec-echo".into()),
                target: "sys::exec".into(),
                conditions: Default::default(),
                action: Verdict::Allow,
            },
            // [NEW] Allow Computer Use for UI-TARS
            Rule {
                rule_id: Some("allow-computer".into()),
                target: "gui::click".into(), // Maps to computer.left_click AND ui__click_component
                conditions: Default::default(),
                action: Verdict::Allow,
            },
            Rule {
                rule_id: Some("allow-computer-type".into()),
                target: "gui::type".into(), // Maps to computer.type
                conditions: Default::default(),
                action: Verdict::Allow,
            },
            Rule {
                rule_id: Some("allow-computer-mouse".into()),
                target: "gui::mouse_move".into(), // Maps to computer.mouse_move
                conditions: Default::default(),
                action: Verdict::Allow,
            },
        ],
    };

    // 3. Configuration Setup
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

    let mut service_policies = ioi_types::config::default_service_policies();
    service_policies.insert(
        "desktop_agent".to_string(),
        ioi_types::config::ServicePolicy {
            methods: agent_meta.methods.clone(),
            allowed_system_prefixes: vec![],
        },
    );

    let mut market_methods = std::collections::BTreeMap::new();
    market_methods.insert("request_compute@v1".to_string(), MethodPermission::User);
    market_methods.insert("settle_compute@v1".to_string(), MethodPermission::User);
    market_methods.insert("publish_asset@v1".to_string(), MethodPermission::User);
    market_methods.insert("purchase_license@v1".to_string(), MethodPermission::User);

    service_policies.insert(
        "market".to_string(),
        ioi_types::config::ServicePolicy {
            methods: market_methods.clone(),
            allowed_system_prefixes: vec![],
        },
    );

    let mut optimizer_methods = std::collections::BTreeMap::new();
    optimizer_methods.insert("optimize_agent@v1".to_string(), MethodPermission::User);
    optimizer_methods.insert("crystallize_skill@v1".to_string(), MethodPermission::User);
    optimizer_methods.insert("deploy_skill@v1".to_string(), MethodPermission::User);
    // [NEW] Allow import_skill via CLI
    optimizer_methods.insert("import_skill@v1".to_string(), MethodPermission::User);

    service_policies.insert(
        "optimizer".to_string(),
        ioi_types::config::ServicePolicy {
            methods: optimizer_methods,
            allowed_system_prefixes: vec![
                "agent::trace::".to_string(),
                "upgrade::active::".to_string(),
            ],
        },
    );

    // Inference Config
    let openai_key = std::env::var("OPENAI_API_KEY").ok();
    let local_url = std::env::var("LOCAL_LLM_URL").ok();
    let (provider, api_url, api_key, model_name) = if let Some(key) = openai_key {
        let model = std::env::var("OPENAI_MODEL").unwrap_or("gpt-4o".to_string());
        println!("🤖 OpenAI API Key detected.");
        (
            "openai",
            "https://api.openai.com/v1/chat/completions".to_string(),
            Some(key),
            model,
        )
    } else if let Some(url) = local_url {
        println!("🤖 LOCAL_LLM_URL detected.");
        ("local", url, None, "llama3".to_string())
    } else {
        println!("⚠️ No API Key found. Fallback to Mock.");
        ("mock", "".to_string(), None, "mock-model".to_string())
    };

    let user_home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    // [FIX] Mount a specific workspace instead of full home to prevent timeouts on large dirs
    let workspace_path = std::path::Path::new(&user_home).join("ioi-workspace");
    std::fs::create_dir_all(&workspace_path)?;
    let workspace_str = workspace_path.to_string_lossy().to_string();

    println!("📂 Mounting User Space (Gated): {}", workspace_str);

    let mut mcp_servers = std::collections::HashMap::new();
    mcp_servers.insert(
        "filesystem".to_string(),
        ioi_types::config::McpConfigEntry {
            command: "npx".to_string(),
            args: vec![
                "-y".to_string(),
                "@modelcontextprotocol/server-filesystem".to_string(),
                abs_data_dir_str.clone(),
                workspace_str,
            ],
            env: std::collections::HashMap::new(),
        },
    );

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
        service_policies,
        min_finality_depth: 0,
        keep_recent_heights: 1000,
        epoch_size: 1000,
        gc_interval_secs: 3600,
        zk_config: Default::default(),
        inference: ioi_types::config::InferenceConfig {
            provider: provider.to_string(),
            api_url: Some(api_url.clone()),
            api_key: api_key.clone(),
            model_name: Some(model_name.clone()),
            connector_ref: None,
        },
        fast_inference: None,
        reasoning_inference: None,
        connectors: Default::default(),
        mcp_servers,
    };

    // 4. Genesis Generation
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

        // Identity & Validator Set
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

        let agent_key = ioi_types::keys::active_service_key("desktop_agent");
        insert_raw(&agent_key, to_bytes_canonical(&agent_meta).unwrap());

        let policy_key = [b"agent::policy::", session_id.as_slice()].concat();
        insert_raw(&policy_key, to_bytes_canonical(&local_policy).unwrap());

        let market_meta = ActiveServiceMeta {
            id: "market".to_string(),
            abi_version: 1,
            state_schema: "v1".to_string(),
            caps: Capabilities::empty(),
            artifact_hash: [0u8; 32],
            activated_at: 0,
            methods: market_methods,
            allowed_system_prefixes: vec![],
            generation_id: 0,
            parent_hash: None,
            author: None,         // [FIX] System service has no specific owner
            context_filter: None, // [FIX] Initialize context_filter
        };
        let market_key = ioi_types::keys::active_service_key("market");
        insert_raw(&market_key, to_bytes_canonical(&market_meta).unwrap());

        let json = serde_json::json!({ "genesis_state": genesis_state });
        fs::write(
            &workload_config.genesis_file,
            serde_json::to_string_pretty(&json)?,
        )?;
    }

    // 5. Driver Instantiation
    let (event_tx, _event_rx) = tokio::sync::broadcast::channel(1000);
    let os_driver = Arc::new(NativeOsDriver::new());

    // [MODIFIED] Create GUI driver mutably to register lenses
    let mut gui_driver = IoiGuiDriver::new()
        .with_event_sender(event_tx.clone())
        .with_scs(scs_arc.clone())
        .with_som(true); // [FIX] Explicitly enable SoM Visual Grounding

    // [NEW] Register Auto-Lens as the fallback for "LiDAR"
    // This allows the agent to semantically target ANY native app, not just Calculator.
    // e.g. a button labeled "Play" becomes ID="btn_play".
    gui_driver.register_lens(Box::new(ioi_drivers::gui::lenses::auto::AutoLens));

    // [OPTIONAL] You can still register specific lenses (like ReactLens) first for higher fidelity.
    // ReactLens is already registered by default in IoiGuiDriver::new(), so we are good.

    // Wrap GUI driver in Arc for shared use
    let gui_driver_arc = Arc::new(gui_driver);
    let browser_driver = Arc::new(BrowserDriver::new());

    println!("   - State: Redb Flat Store (Zero Hashing)");
    let scheme = HashCommitmentScheme::new();
    let flat_db_path = opts.data_dir.join("state_flat.redb");
    let tree = RedbFlatStore::new(&flat_db_path, scheme.clone())
        .map_err(|e| anyhow!("Failed to open flat store: {}", e))?;

    let (workload_container, machine) = setup_workload(
        tree,
        scheme.clone(),
        workload_config.clone(),
        Some(gui_driver_arc.clone()),
        Some(browser_driver.clone()),
        Some(scs_arc.clone()),
        Some(event_tx.clone()),
        Some(os_driver.clone()),
    )
    .await?;

    // Hot-Patch Policy & Meta
    {
        println!("Applying active security policy to state...");
        let state_tree: Arc<tokio::sync::RwLock<RedbFlatStore<HashCommitmentScheme>>> =
            workload_container.state_tree();
        let mut state = state_tree.write().await;

        let policy_key = [b"agent::policy::", session_id.as_slice()].concat();
        let policy_bytes = codec::to_bytes_canonical(&local_policy).map_err(|e| anyhow!(e))?;
        state
            .insert(&policy_key, &policy_bytes)
            .map_err(|e| anyhow!(e.to_string()))?;

        let agent_key = ioi_types::keys::active_service_key("desktop_agent");
        let meta_bytes = codec::to_bytes_canonical(&agent_meta).map_err(|e| anyhow!(e))?;
        state
            .insert(&agent_key, &meta_bytes)
            .map_err(|e| anyhow!(e.to_string()))?;

        let _ = state
            .commit_version(0)
            .map_err(|e| anyhow!(e.to_string()))?;
    }

    // 6. Runtime Execution
    let workload_ipc_addr = "127.0.0.1:8555";
    std::env::set_var("IPC_SERVER_ADDR", workload_ipc_addr);

    let server_workload: Arc<
        ioi_api::validator::WorkloadContainer<RedbFlatStore<HashCommitmentScheme>>,
    > = workload_container.clone();
    let server_machine = machine.clone();
    let server_addr = workload_ipc_addr.to_string();

    let mut workload_server_handle = tokio::spawn(async move {
        let server = ioi_validator::standard::workload::ipc::WorkloadIpcServer::<
            RedbFlatStore<HashCommitmentScheme>,
            HashCommitmentScheme,
        >::new(server_addr, server_workload, server_machine)
        .await
        .map_err(|e| anyhow!(e))?;
        server.run().await.map_err(|e: anyhow::Error| anyhow!(e))
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

    let syncer = Arc::new(NoOpBlockSync::new());

    let (swarm_commander, mut swarm_rx) = tokio::sync::mpsc::channel::<SwarmCommand>(100);
    tokio::spawn(async move { while let Some(_) = swarm_rx.recv().await {} });

    let (_dummy_tx, network_events) = tokio::sync::mpsc::channel(100);

    println!("   - Consensus: Solo (Lite Mode)");
    let consensus_engine = ioi_consensus::Consensus::Solo(SoloEngine::new());

    let sk_bytes = local_key.clone().try_into_ed25519()?.secret();
    let internal_sk = Ed25519PrivateKey::from_bytes(sk_bytes.as_ref())?;
    let internal_kp = ioi_crypto::sign::eddsa::Ed25519KeyPair::from_private_key(&internal_sk)?;
    let signer = Arc::new(LocalSigner::new(internal_kp));

    let inference_runtime: Arc<dyn InferenceRuntime> =
        if let Some(key) = &workload_config.inference.api_key {
            let model_name = workload_config
                .inference
                .model_name
                .clone()
                .unwrap_or("gpt-4o".to_string());
            let api_url = workload_config
                .inference
                .api_url
                .clone()
                .unwrap_or("https://api.openai.com/v1/chat/completions".to_string());
            Arc::new(HttpInferenceRuntime::new(api_url, key.clone(), model_name))
        } else if workload_config.inference.provider == "mock" {
            Arc::new(ioi_api::vm::inference::mock::MockInferenceRuntime)
        } else {
            let model_name = workload_config
                .inference
                .model_name
                .clone()
                .unwrap_or("llama3".to_string());
            let api_url = workload_config
                .inference
                .api_url
                .clone()
                .unwrap_or("http://localhost:11434/v1/chat/completions".to_string());
            Arc::new(HttpInferenceRuntime::new(
                api_url,
                "".to_string(),
                model_name,
            ))
        };

    let safety_model: Arc<dyn LocalSafetyModel> =
        Arc::new(RuntimeAsSafetyModel::new(inference_runtime.clone()));

    let verifier = FlatVerifier::default();

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
        safety_model: safety_model,
        inference_runtime: inference_runtime.clone(),
        os_driver: os_driver.clone(),
        scs: Some(scs_arc.clone()),
        event_broadcaster: Some(event_tx.clone()),
    };

    let orchestrator = Arc::new(Orchestrator::<
        HashCommitmentScheme,
        RedbFlatStore<HashCommitmentScheme>,
        Consensus<ChainTransaction>,
        FlatVerifier,
    >::new(&config, deps, scheme)?);

    orchestrator.set_chain_and_workload_client(machine.clone(), workload_client);

    println!("\n✅ IOI User Node (Mode 0) configuration is valid.");
    println!("   - Agency Firewall: User-in-the-Loop Mode (Interactive Gates)");
    println!("   - The Substrate: Mounted at {}", opts.data_dir.display());
    println!("   - SCS Storage: Active (.scs)");
    println!("   - GUI Automation: Enabled (Visual Grounding Active + LiDAR)");
    println!("   - Browser Automation: Enabled");
    println!("   - MCP: Enabled (Filesystem)");
    println!("   - Market: Active (Universal Asset Ledger)");
    println!(
        "   - RPC will listen on http://{}",
        config.rpc_listen_address
    );
    println!("Starting main components (press Ctrl+C to exit)...");

    Container::start(&*orchestrator, &config.rpc_listen_address)
        .await
        .map_err(|e| anyhow!("Failed to start: {}", e))?;

    let agent = DesktopAgentService::new_hybrid(
        gui_driver_arc,
        Arc::new(ioi_drivers::terminal::TerminalDriver::new()),
        browser_driver,
        inference_runtime.clone(),
        inference_runtime.clone(),
    )
    .with_mcp_manager(Arc::new(ioi_drivers::mcp::McpManager::new()))
    .with_workspace_path(abs_data_dir_str.clone())
    .with_scs(scs_arc.clone())
    .with_event_sender(event_tx.clone())
    .with_os_driver(os_driver.clone())
    .with_som(true); // Enable SoM in Agent

    // Configure Optimizer with SCS access
    let safety_adapter: Arc<dyn LocalSafetyModel> =
        Arc::new(RuntimeAsSafetyModel::new(inference_runtime.clone()));
    let optimizer_service =
        OptimizerService::new(inference_runtime.clone(), safety_adapter.clone())
            .with_scs(scs_arc.clone());
    let optimizer_arc = Arc::new(optimizer_service);

    // Inject Optimizer into Agent Service for RSI
    let agent = agent.with_optimizer(optimizer_arc.clone());

    {
        let mut machine_guard = machine.lock().await;
        let service_arc = Arc::new(agent);
        if let Err(e) = machine_guard.service_manager.register_service(service_arc) {
            eprintln!("Failed to register enhanced DesktopAgentService: {}", e);
        } else {
            println!("✅ Enhanced DesktopAgentService (MCP+Path) registered via Hot Swap.");
        }

        let market_service = Arc::new(MarketService::default());
        if let Err(e) = machine_guard
            .service_manager
            .register_service(market_service)
        {
            eprintln!("Failed to register MarketService: {}", e);
        } else {
            println!("✅ MarketService active (Skills, Agents, Compute).");
        }

        // Register Optimizer
        if let Err(e) = machine_guard
            .service_manager
            .register_service(optimizer_arc)
        {
            eprintln!("Failed to register OptimizerService: {}", e);
        } else {
            println!("✅ OptimizerService active (Skill Injection Enabled).");
        }
    }

    let mut operator_ticker = tokio::time::interval(Duration::from_millis(500));
    operator_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("\nShutdown signal received.");
                break;
            }
            res = &mut workload_server_handle => {
                match res {
                    Ok(Err(e)) => return Err(anyhow!("Workload IPC Server crashed: {}", e)),
                    Ok(Ok(_)) => return Err(anyhow!("Workload IPC Server exited unexpectedly.")),
                    Err(e) => return Err(anyhow!("Workload IPC Server task panicked: {}", e)),
                }
            }
            _ = operator_ticker.tick() => {
                let ctx_opt_guard = orchestrator.main_loop_context.lock().await;
                let ctx_opt: &Option<Arc<TokioMutex<MainLoopContext<
                    HashCommitmentScheme,
                    RedbFlatStore<HashCommitmentScheme>,
                    Consensus<ChainTransaction>,
                    FlatVerifier
                >>>> = &*ctx_opt_guard;

                if let Some(ctx) = ctx_opt {
                    let ctx_guard = ctx.lock().await;

                    if let Err(e) = run_oracle_operator_task::<
                        HashCommitmentScheme,
                        RedbFlatStore<HashCommitmentScheme>,
                        Consensus<ChainTransaction>,
                        FlatVerifier
                    >(&*ctx_guard).await {
                         tracing::error!(target: "operator_task", "Oracle operator failed: {}", e);
                    }

                    match run_agent_driver_task::<
                        HashCommitmentScheme,
                        RedbFlatStore<HashCommitmentScheme>,
                        Consensus<ChainTransaction>,
                        FlatVerifier
                    >(&*ctx_guard).await {
                        Ok(true) => {
                             // [FIX] Removed aggressive reset to prevent runaway execution loops (e.g. opening 100 windows).
                             // operator_ticker.reset();
                        },
                        Ok(false) => {
                        },
                        Err(e) => {
                             tracing::error!(target: "operator_task", "Agent driver failed: {}", e);
                        }
                    }
                }
            }
        }
    }

    println!("\nShutting down...");
    workload_server_handle.abort();
    Container::stop(&*orchestrator).await?;
    println!("Bye!");
    Ok(())
}
