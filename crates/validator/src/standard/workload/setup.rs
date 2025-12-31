// Path: crates/validator/src/standard/workload/setup.rs

use anyhow::{anyhow, Result};
use ioi_api::{
    commitment::CommitmentScheme,
    services::{access::ServiceDirectory, BlockchainService, UpgradableService},
    state::{ProofProvider, StateManager},
    storage::NodeStore,
    validator::WorkloadContainer,
    vm::inference::mock::MockInferenceRuntime,
};
use ioi_consensus::util::engine_from_config;
use ioi_execution::{util::load_state_from_genesis_file, ExecutionMachine};
// [FIX] Updated import
use ioi_services::{governance::GovernanceModule, identity::IdentityHub, provider_registry::ProviderRegistryService};
use ioi_storage::RedbEpochStore;
use ioi_tx::unified::UnifiedTransactionModel;
use ioi_types::{
    app::{to_root_hash, Membership},
    config::{InitialServiceConfig, OrchestrationConfig, ValidatorRole, WorkloadConfig},
    keys::{STATUS_KEY, VALIDATOR_SET_KEY},
};
#[cfg(feature = "vm-wasm")]
use ioi_vm_wasm::WasmRuntime;
use rand::{thread_rng, Rng};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::{sync::Mutex, time::interval};

#[cfg(feature = "ibc-deps")]
use ioi_services::ibc::{
    apps::channel::ChannelManager, core::registry::VerifierRegistry,
    light_clients::tendermint::TendermintVerifier,
};

#[cfg(all(feature = "ibc-deps", feature = "ethereum-zk"))]
use {
    ioi_api::ibc::LightClient, ioi_crypto::algorithms::hash::sha256,
    ioi_services::ibc::light_clients::ethereum_zk::EthereumZkLightClient, std::fs,
    zk_driver_succinct::config::SuccinctDriverConfig,
};

/// Sets up the Workload components: State, VM, Services, ExecutionMachine, and background tasks.
pub async fn setup_workload<CS, ST>(
    mut state_tree: ST,
    commitment_scheme: CS,
    config: WorkloadConfig,
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

    // --- VM Setup ---

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
        let arc = Arc::new(runtime);
        // Correctly wrap the Arc in the adapter struct
        (arc.clone(), Box::new(VmWrapper(arc)))
    };

    // Fallback if VM-WASM is not enabled
    #[cfg(not(feature = "vm-wasm"))]
    let vm: Box<dyn ioi_api::vm::VirtualMachine> = {
        panic!("vm-wasm feature is required for Workload setup");
    };

    // [NEW] Instantiate the Mock Inference Runtime
    let _inference: Box<dyn ioi_api::vm::inference::InferenceRuntime> =
        Box::new(MockInferenceRuntime::default());
    tracing::info!(target: "workload", "Initialized Mock Inference Runtime for agentic tasks.");

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
    };
    let _consensus_engine = engine_from_config(&_temp_orch_config)?;

    let mut initial_services = Vec::new();
    let _penalty_engine: Arc<dyn ioi_consensus::PenaltyEngine> =
        Arc::new(_consensus_engine.clone());
    let _penalties_service = Arc::new(ioi_consensus::PenaltiesService::new(_penalty_engine));
    initial_services.push(_penalties_service as Arc<dyn UpgradableService>);

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
                // [FIX] Use ProviderRegistryService
                let _registry = ProviderRegistryService::default();
                initial_services
                    .push(Arc::new(_registry) as Arc<dyn ioi_api::services::UpgradableService>);
            }
            #[cfg(feature = "ibc-deps")]
            InitialServiceConfig::Ibc(ibc_config) => {
                tracing::info!(target: "workload", event = "service_init", name = "IBC", impl="native", capabilities="");

                // [FIX] Pass the WasmRuntime Arc to the registry constructor
                #[cfg(feature = "vm-wasm")]
                let mut verifier_registry = VerifierRegistry::new(wasm_runtime_arc.clone());

                // [FIX] Fallback if vm-wasm is disabled (though setup panics earlier)
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

    let _services_for_dir: Vec<Arc<dyn BlockchainService>> = initial_services
        .iter()
        .map(|s| s.clone() as Arc<dyn BlockchainService>)
        .collect();
    let _service_directory = ServiceDirectory::new(_services_for_dir);

    // [FIX] Pass Some(inference) to WorkloadContainer
    let _workload_container = Arc::new(WorkloadContainer::new(
        config.clone(),
        state_tree,
        vm,
        Some(_inference), // [CHANGED]
        _service_directory,
        store,
    )?);

    let mut _machine = ExecutionMachine::new(
        commitment_scheme.clone(),
        UnifiedTransactionModel::new(commitment_scheme),
        1.into(),
        initial_services,
        _consensus_engine,
        _workload_container.clone(),
        config.service_policies.clone(),
    )?;

    for _runtime_id in &config.runtimes {
        let _id = _runtime_id.to_ascii_lowercase();
        if _id == "wasm" {
            tracing::info!(target: "workload", "Registering WasmRuntime for service upgrades.");
            #[cfg(feature = "vm-wasm")]
            {
                // We reuse the runtime created earlier for the registry to ensure resource sharing
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