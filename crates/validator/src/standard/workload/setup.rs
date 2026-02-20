// Path: crates/validator/src/standard/workload/setup.rs
#![allow(unreachable_code)] // Allow unreachable code for vm-wasm compile guard panic

use anyhow::{anyhow, Result};
use ioi_api::vm::drivers::gui::GuiDriver;
use ioi_api::{
    commitment::CommitmentScheme,
    services::{access::ServiceDirectory, BlockchainService, UpgradableService},
    state::{ProofProvider, StateManager},
    storage::NodeStore,
    validator::WorkloadContainer,
    vm::inference::InferenceRuntime,
};
use ioi_consensus::util::engine_from_config;
use ioi_drivers::browser::BrowserDriver;
use ioi_execution::{util::load_state_from_genesis_file, ExecutionMachine};
use ioi_scs::SovereignContextStore;
use ioi_services::{
    agentic::desktop::DesktopAgentService,
    agentic::optimizer::OptimizerService, // Import Optimizer
    governance::GovernanceModule,
    identity::IdentityHub,
    provider_registry::ProviderRegistryService,
    wallet_network::WalletNetworkService,
};
use ioi_storage::RedbEpochStore;
use ioi_tx::unified::UnifiedTransactionModel;
use ioi_types::{
    app::agentic::InferenceOptions,
    app::{to_root_hash, Membership},
    config::{
        InferenceConfig, InitialServiceConfig, OrchestrationConfig, ValidatorRole, WorkloadConfig,
    },
    keys::{STATUS_KEY, VALIDATOR_SET_KEY},
};
#[cfg(feature = "vm-wasm")]
use ioi_vm_wasm::WasmRuntime;
use rand::{thread_rng, Rng};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::{sync::Mutex, time::interval};

use crate::standard::workload::drivers::cpu::CpuDriver;
use crate::standard::workload::hydration::ModelHydrator;
use crate::standard::workload::runtime::StandardInferenceRuntime;

use ioi_api::vm::inference::LocalSafetyModel;
use ioi_api::vm::inference::{mock::MockInferenceRuntime, HttpInferenceRuntime};

use crate::standard::workload::drivers::verified_http::VerifiedHttpRuntime;
use ioi_services::agentic::pii_adapter::RuntimeAsPiiModel;

use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

#[cfg(feature = "ibc-deps")]
use ioi_plugin_ibc_service::{
    apps::channel::ChannelManager, core::registry::VerifierRegistry,
    light_clients::tendermint::TendermintVerifier,
};

#[cfg(all(feature = "ibc-deps", feature = "ethereum-zk"))]
use {
    ioi_api::ibc::LightClient, ioi_crypto::algorithms::hash::sha256,
    ioi_plugin_ibc_service::light_clients::ethereum_zk::EthereumZkLightClient, std::fs,
    zk_driver_succinct::config::SuccinctDriverConfig,
};

use ioi_api::vm::drivers::os::OsDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_types::app::KernelEvent;

use ioi_drivers::mcp::{McpManager, McpServerConfig};
use std::collections::HashMap;

async fn create_guardian_channel(certs_dir: &str) -> Result<Channel> {
    let ca_pem = std::fs::read(format!("{}/ca.pem", certs_dir))?;
    let client_pem = std::fs::read(format!("{}/workload.pem", certs_dir))?;
    let client_key = std::fs::read(format!("{}/workload.key", certs_dir))?;

    let ca = Certificate::from_pem(ca_pem);
    let identity = Identity::from_pem(client_pem, client_key);

    let tls = ClientTlsConfig::new()
        .domain_name("guardian")
        .ca_certificate(ca)
        .identity(identity);

    let guardian_addr =
        std::env::var("GUARDIAN_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8443".to_string());

    let endpoint = std::env::var("GUARDIAN_GRPC_ADDR").unwrap_or(guardian_addr);

    let channel = Channel::from_shared(endpoint)?
        .tls_config(tls)?
        .connect()
        .await?;

    Ok(channel)
}

async fn build_runtime_from_config(
    cfg: &InferenceConfig,
    hydrator: Arc<ModelHydrator>,
    driver: Arc<dyn ioi_api::vm::inference::HardwareDriver>,
    workload_config: &WorkloadConfig,
) -> Result<Arc<dyn InferenceRuntime>> {
    if let Some(key_ref) = &cfg.connector_ref {
        if let Some(conn_cfg) = workload_config.connectors.get(key_ref) {
            if !conn_cfg.enabled {
                return Err(anyhow!("Connector '{}' is disabled", key_ref));
            }
            let secret_id = &conn_cfg.key_ref;

            tracing::info!(
                target: "workload",
                "Initializing Verified HTTP Runtime (Provider: {}, Secret: {})",
                cfg.provider, secret_id
            );

            let certs_dir = std::env::var("CERTS_DIR").map_err(|_| anyhow!("CERTS_DIR not set"))?;
            let channel = create_guardian_channel(&certs_dir).await?;

            return Ok(Arc::new(VerifiedHttpRuntime::new(
                channel,
                cfg.provider.clone(),
                secret_id.clone(),
                cfg.model_name.clone().unwrap_or_default(),
            )) as Arc<dyn InferenceRuntime>);
        } else {
            return Err(anyhow!(
                "Connector '{}' not found in configuration",
                key_ref
            ));
        }
    }

    match cfg.provider.as_str() {
        "openai" | "local" => {
            let api_url = cfg.api_url.clone().ok_or_else(|| {
                anyhow!("API URL required for 'openai' or 'local' inference provider")
            })?;
            let api_key = cfg.api_key.clone().unwrap_or_default();
            let model_name = cfg
                .model_name
                .clone()
                .unwrap_or_else(|| "gpt-3.5-turbo".to_string());

            tracing::info!(
                target: "workload",
                "Initializing HTTP Inference Runtime (Provider: {}, URL: {}, Model: {})",
                cfg.provider, api_url, model_name
            );

            Ok(
                Arc::new(HttpInferenceRuntime::new(api_url, api_key, model_name))
                    as Arc<dyn InferenceRuntime>,
            )
        }
        "mock" => {
            tracing::info!(target: "workload", "Initializing Mock Inference Runtime");
            Ok(Arc::new(MockInferenceRuntime) as Arc<dyn InferenceRuntime>)
        }
        other => {
            if other == "standard" {
                tracing::info!(target: "workload", "Initializing Standard Inference Runtime (Local Hardware)");
                Ok(Arc::new(StandardInferenceRuntime::new(hydrator, driver))
                    as Arc<dyn InferenceRuntime>)
            } else {
                Err(anyhow!("Unknown inference provider: {}", other))
            }
        }
    }
}

/// Sets up the Workload components including State, VM, Services, ExecutionMachine, and background tasks.
pub async fn setup_workload<CS, ST>(
    mut state_tree: ST,
    commitment_scheme: CS,
    config: WorkloadConfig,
    _gui_driver: Option<Arc<dyn GuiDriver>>,
    _browser_driver: Option<Arc<BrowserDriver>>,
    _scs: Option<Arc<std::sync::Mutex<SovereignContextStore>>>,
    _event_sender: Option<tokio::sync::broadcast::Sender<KernelEvent>>,
    _os_driver: Option<Arc<dyn OsDriver>>,
) -> Result<(
    Arc<WorkloadContainer<ST>>,
    Arc<Mutex<ExecutionMachine<CS, ST>>>,
)>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + ProofProvider
        + Send
        + Sync
        + 'static
        + Clone
        + std::fmt::Debug,
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + Send + Sync + std::fmt::Debug,
    CS::Proof: serde::Serialize
        + for<'de> serde::Deserialize<'de>
        + AsRef<[u8]>
        + std::fmt::Debug
        + Clone
        + Send
        + Sync
        + 'static,
    CS::Commitment: std::fmt::Debug + From<Vec<u8>>,
{
    let _ = &commitment_scheme;
    let db_path = Path::new(&config.state_file).with_extension("db");
    let db_preexisted = db_path.exists();

    let store = Arc::new(RedbEpochStore::open(&db_path, config.epoch_size)?);
    state_tree.attach_store(store.clone());

    if !db_preexisted {
        tracing::info!(
            target: "workload",
            event = "state_init",
            path = %db_path.display(),
            "No existing state DB found. Initializing from genesis {}.",
            config.genesis_file
        );
        load_state_from_genesis_file(&mut state_tree, &config.genesis_file)?;
    } else {
        tracing::info!(
            target: "workload",
            event = "state_init",
            path = %db_path.display(),
            "Existing state DB found. Attempting recovery from stored state.",
        );
        if let Ok((head_height, _)) = store.head() {
            if head_height > 0 {
                if let Ok(Some(head_block)) = store.get_block_by_height(head_height) {
                    let recovered_root = &head_block.header.state_root.0;
                    state_tree.adopt_known_root(recovered_root, head_height)?;
                    tracing::warn!(target: "workload", event = "state_recovered", height = head_height, "Recovered and adopted durable head into state backend.");

                    let anchor = to_root_hash(recovered_root)?;
                    if let Ok((Membership::Present(status_bytes), _)) =
                        state_tree.get_with_proof_at_anchor(&anchor, STATUS_KEY)
                    {
                        state_tree.insert(STATUS_KEY, &status_bytes)?;
                        tracing::info!(target: "workload", "Re-hydrated STATUS_KEY into current state.");
                    }
                    if let Ok((Membership::Present(vs_bytes), _)) =
                        state_tree.get_with_proof_at_anchor(&anchor, VALIDATOR_SET_KEY)
                    {
                        state_tree.insert(VALIDATOR_SET_KEY, &vs_bytes)?;
                        tracing::info!(target: "workload", "Re-hydrated VALIDATOR_SET_KEY into current state.");
                    }
                }
            }
        }
    }

    let driver = Arc::new(CpuDriver::new());
    let models_dir = Path::new("models");
    std::fs::create_dir_all(models_dir).ok();
    let hydrator = Arc::new(ModelHydrator::new(models_dir.to_path_buf(), driver.clone()));

    let inference_runtime =
        build_runtime_from_config(&config.inference, hydrator.clone(), driver.clone(), &config)
            .await?;

    let fast_runtime = if let Some(cfg) = &config.fast_inference {
        build_runtime_from_config(cfg, hydrator.clone(), driver.clone(), &config).await?
    } else {
        inference_runtime.clone()
    };
    let _ = &fast_runtime;

    let reasoning_runtime = if let Some(cfg) = &config.reasoning_inference {
        build_runtime_from_config(cfg, hydrator.clone(), driver.clone(), &config).await?
    } else {
        inference_runtime.clone()
    };
    let _ = &reasoning_runtime;

    #[cfg(feature = "vm-wasm")]
    struct VmWrapper(Arc<WasmRuntime>);

    #[cfg(feature = "vm-wasm")]
    #[async_trait::async_trait]
    impl ioi_api::vm::VirtualMachine for VmWrapper {
        async fn execute(
            &self,
            code: &[u8],
            method: &str,
            input: &[u8],
            state: &dyn ioi_api::state::VmStateAccessor,
            ctx: ioi_api::vm::ExecutionContext,
        ) -> Result<ioi_api::vm::ExecutionOutput, ioi_types::error::VmError> {
            self.0.execute(code, method, input, state, ctx).await
        }
    }

    #[cfg(feature = "vm-wasm")]
    let (wasm_runtime_arc, vm): (Arc<WasmRuntime>, Box<dyn ioi_api::vm::VirtualMachine>) = {
        let runtime = WasmRuntime::new(config.fuel_costs.clone())?;
        runtime.link_inference(inference_runtime.clone());

        if let Some(driver) = &_gui_driver {
            runtime.link_gui_driver(driver.clone());
            tracing::info!(target: "workload", "GUI Driver linked to WasmRuntime (Eyes & Hands Active)");
        }

        if let Some(driver) = &_browser_driver {
            runtime.link_browser_driver(Arc::clone(driver));
            tracing::info!(target: "workload", "Browser Driver linked to WasmRuntime");
        }

        let arc = Arc::new(runtime);
        (arc.clone(), Box::new(VmWrapper(arc)))
    };

    #[cfg(not(feature = "vm-wasm"))]
    #[allow(unused_variables)]
    let vm: Box<dyn ioi_api::vm::VirtualMachine> = {
        panic!("vm-wasm feature is required for Workload setup");
    };

    let _temp_orch_config = OrchestrationConfig {
        chain_id: 1.into(),
        config_schema_version: 0,
        consensus_type: config.consensus_type,
        rpc_listen_address: String::new(),
        rpc_hardening: Default::default(),
        initial_sync_timeout_secs: 0,
        block_production_interval_secs: 0,
        round_robin_view_timeout_secs: 0,
        default_query_gas_limit: 0,
        ibc_gateway_listen_address: None,
        validator_role: ValidatorRole::Consensus,
        safety_model_path: None,
        tokenizer_path: None,
    };
    let _consensus_engine = engine_from_config(&_temp_orch_config)?;

    let mut initial_services = Vec::new();
    let _penalty_engine: Arc<dyn ioi_consensus::PenaltyEngine> =
        Arc::new(_consensus_engine.clone());
    let _penalties_service = Arc::new(ioi_consensus::PenaltiesService::new(_penalty_engine));
    initial_services.push(_penalties_service as Arc<dyn UpgradableService>);

    tracing::info!(target: "workload", event = "service_init", name = "WalletNetwork", impl="native", capabilities="policy_sessions_audit");
    initial_services.push(Arc::new(WalletNetworkService) as Arc<dyn UpgradableService>);

    for _service_config in &config.initial_services {
        match _service_config {
            InitialServiceConfig::IdentityHub(_migration_config) => {
                tracing::info!(target: "workload", event = "service_init", name = "IdentityHub", impl="native", capabilities="identity_view, tx_decorator, on_end_block");
                let _hub = IdentityHub::new(_migration_config.clone());
                initial_services
                    .push(Arc::new(_hub) as Arc<dyn ioi_api::services::UpgradableService>);
            }
            InitialServiceConfig::Governance(_params) => {
                tracing::info!(target: "workload", event = "service_init", name = "Governance", impl="native", capabilities="on_end_block");
                let _gov = GovernanceModule::new(_params.clone());
                initial_services
                    .push(Arc::new(_gov) as Arc<dyn ioi_api::services::UpgradableService>);
            }
            InitialServiceConfig::Oracle(_params) => {
                tracing::info!(target: "workload", event = "service_init", name = "ProviderRegistry", impl="native", capabilities="");
                let _registry = ProviderRegistryService::default();
                initial_services
                    .push(Arc::new(_registry) as Arc<dyn ioi_api::services::UpgradableService>);
            }
            #[cfg(feature = "ibc-deps")]
            InitialServiceConfig::Ibc(ibc_config) => {
                tracing::info!(target: "workload", event = "service_init", name = "IBC", impl="native", capabilities="");

                #[cfg(feature = "vm-wasm")]
                let mut verifier_registry = VerifierRegistry::new(wasm_runtime_arc.clone());

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
                    tracing::info!(target: "workload", "Initializing Ethereum ZK Light Client for 'eth-mainnet'");
                    let zk_cfg = &config.zk_config;
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
                                return Err(anyhow!("SECURITY CRITICAL: {} VK hash mismatch! Config expects: {}, File has: {}", label, expected_hash, hash));
                            }
                            tracing::info!(target: "workload", "Loaded {} VK from {} (hash match)", label, p);
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
                }

                initial_services.push(Arc::new(verifier_registry) as Arc<dyn UpgradableService>);
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

    // [NEW] Instantiate Optimizer Service
    let safety_adapter: Arc<dyn LocalSafetyModel> =
        Arc::new(RuntimeAsPiiModel::new(fast_runtime.clone()));

    let mut optimizer_service =
        OptimizerService::new(reasoning_runtime.clone(), safety_adapter.clone());

    // [FIX] Inject SCS if available
    if let Some(store) = &_scs {
        optimizer_service = optimizer_service.with_scs(store.clone());
        tracing::info!(target: "workload", "SCS injected into OptimizerService.");
    }

    // Register Optimizer
    initial_services.push(Arc::new(optimizer_service) as Arc<dyn UpgradableService>);
    tracing::info!(target: "workload", event = "service_init", name = "Optimizer", impl="native", capabilities="RSI_Engine");

    if let Some(gui) = _gui_driver {
        tracing::info!(target: "workload", event = "service_init", name = "DesktopAgent", impl="native");

        let terminal_driver = Arc::new(TerminalDriver::new());
        tracing::info!(target: "workload", "Terminal Driver initialized");

        let browser = _browser_driver
            .clone()
            .unwrap_or_else(|| Arc::new(BrowserDriver::new()));
        tracing::info!(target: "workload", "Browser Driver injected into DesktopAgent");

        // [NEW] Initialize MCP Manager and spawn servers
        let mcp_manager = Arc::new(McpManager::new());

        for (name, server_cfg) in &config.mcp_servers {
            let manager_clone = mcp_manager.clone();
            let name_clone = name.clone();

            let mut resolved_env = HashMap::new();
            for (k, v) in &server_cfg.env {
                if let Some(secret_ref) = v.strip_prefix("env:") {
                    let secret = std::env::var(secret_ref).unwrap_or_default();
                    resolved_env.insert(k.clone(), secret);
                } else {
                    resolved_env.insert(k.clone(), v.clone());
                }
            }

            let mcp_cfg = McpServerConfig {
                command: server_cfg.command.clone(),
                args: server_cfg.args.clone(),
                env: resolved_env,
            };

            tokio::spawn(async move {
                if let Err(e) = manager_clone.start_server(&name_clone, mcp_cfg).await {
                    tracing::error!(target: "mcp", "Failed to start MCP server '{}': {}", name_clone, e);
                } else {
                    tracing::info!(target: "mcp", "MCP server '{}' started successfully", name_clone);
                }
            });
        }

        // [MODIFIED] Pass MCP Manager to DesktopAgentService
        let mut agent = DesktopAgentService::new_hybrid(
            gui,
            terminal_driver,
            browser,
            fast_runtime,
            reasoning_runtime,
        )
        .with_mcp_manager(mcp_manager);

        if let Some(store) = &_scs {
            agent = agent.with_scs(store.clone());
            tracing::info!(target: "workload", "SCS injected into DesktopAgent.");
        }

        if let Some(sender) = _event_sender {
            agent = agent.with_event_sender(sender.clone());
            tracing::info!(target: "workload", "Event Bus connected to DesktopAgent.");
        }

        if let Some(os) = &_os_driver {
            agent = agent.with_os_driver(os.clone());
            tracing::info!(target: "workload", "OS Driver injected into DesktopAgent.");
        } else {
            tracing::warn!(target: "workload", "OS Driver missing! DesktopAgent will fail policy checks.");
        }

        initial_services.push(Arc::new(agent) as Arc<dyn UpgradableService>);
    }

    let _services_for_dir: Vec<Arc<dyn BlockchainService>> = initial_services
        .iter()
        .map(|s| s.clone() as Arc<dyn BlockchainService>)
        .collect();
    let _service_directory = ServiceDirectory::new(_services_for_dir);

    struct RuntimeWrapper {
        inner: Arc<dyn InferenceRuntime>,
    }

    #[async_trait::async_trait]
    impl InferenceRuntime for RuntimeWrapper {
        async fn execute_inference(
            &self,
            model_hash: [u8; 32],
            input_context: &[u8],
            options: InferenceOptions,
        ) -> Result<Vec<u8>, ioi_types::error::VmError> {
            self.inner
                .execute_inference(model_hash, input_context, options)
                .await
        }

        async fn load_model(
            &self,
            model_hash: [u8; 32],
            path: &Path,
        ) -> Result<(), ioi_types::error::VmError> {
            self.inner.load_model(model_hash, path).await
        }

        async fn unload_model(
            &self,
            model_hash: [u8; 32],
        ) -> Result<(), ioi_types::error::VmError> {
            self.inner.unload_model(model_hash).await
        }
    }

    let _workload_container = Arc::new(WorkloadContainer::new(
        config.clone(),
        state_tree,
        vm,
        Some(Box::new(RuntimeWrapper {
            inner: inference_runtime,
        })),
        _service_directory,
        store,
    )?);

    let machine_os_driver = if let Some(os) = &_os_driver {
        os.clone()
    } else {
        Arc::new(ioi_drivers::os::NativeOsDriver::new())
    };

    let mut _machine = ExecutionMachine::new(
        commitment_scheme.clone(),
        UnifiedTransactionModel::new(commitment_scheme),
        1.into(),
        initial_services,
        _consensus_engine,
        _workload_container.clone(),
        config.service_policies.clone(),
        machine_os_driver,
    )?;

    for _runtime_id in &config.runtimes {
        let _id = _runtime_id.to_ascii_lowercase();
        if _id == "wasm" {
            tracing::info!(target: "workload", "Registering WasmRuntime for service upgrades.");
            #[cfg(feature = "vm-wasm")]
            {
                _machine
                    .service_manager
                    .register_runtime("wasm", wasm_runtime_arc.clone());
            }
        }
    }

    _machine
        .load_or_initialize_status(&_workload_container)
        .await?;
    let _machine_arc = Arc::new(Mutex::new(_machine));

    let _machine_for_gc = _machine_arc.clone();
    let _workload_for_gc = _workload_container.clone();

    tokio::spawn(async move {
        let gc_interval_secs = _workload_for_gc.config().gc_interval_secs.max(1);
        let mut ticker = interval(Duration::from_secs(gc_interval_secs));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;
            if gc_interval_secs > 10 {
                let jitter_factor = thread_rng().gen_range(-0.10..=0.10);
                let jitter_millis =
                    ((gc_interval_secs as f64 * jitter_factor).abs() * 1000.0) as u64;
                if jitter_millis > 0 {
                    tokio::time::sleep(Duration::from_millis(jitter_millis)).await;
                }
            }
            let current_height = {
                let guard = _machine_for_gc.lock().await;
                use ioi_api::chain::ChainStateMachine;
                guard.status().height
            };
            if let Err(e) = _workload_for_gc.run_gc_pass(current_height).await {
                log::error!("[GC] Background pass failed: {}", e);
            }
        }
    });

    Ok((_workload_container, _machine_arc))
}
