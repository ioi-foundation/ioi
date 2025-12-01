// Path: crates/validator/src/standard/workload/setup.rs

use anyhow::{anyhow, Result};
use ioi_api::{
    commitment::CommitmentScheme,
    services::{access::ServiceDirectory, BlockchainService, UpgradableService},
    state::{ProofProvider, StateManager},
    storage::NodeStore,
    validator::WorkloadContainer,
};
use ioi_consensus::util::engine_from_config;
use ioi_execution::{util::load_state_from_genesis_file, ExecutionMachine};
use ioi_services::{
    governance::GovernanceModule, identity::IdentityHub, oracle::OracleService,
};
// [FIX] Correct crate import
use ioi_storage::RedbEpochStore;
use ioi_tx::unified::UnifiedTransactionModel;
use ioi_types::{
    app::{to_root_hash, Membership},
    config::{InitialServiceConfig, OrchestrationConfig, WorkloadConfig},
    keys::{STATUS_KEY, VALIDATOR_SET_KEY},
};
use ioi_vm_wasm::WasmRuntime;
use rand::{thread_rng, Rng};
// [FIX] Added Duration import
use std::{path::Path, sync::Arc, time::Duration};
use tokio::{sync::Mutex, time::interval};

#[cfg(feature = "ibc-deps")]
use ioi_services::ibc::{
    apps::channel::ChannelManager, core::registry::VerifierRegistry,
    light_clients::tendermint::TendermintVerifier,
};

#[cfg(all(feature = "ibc-deps", feature = "ethereum-zk"))]
use {
    ioi_api::ibc::LightClient,
    ioi_crypto::algorithms::hash::sha256,
    ioi_services::ibc::light_clients::ethereum_zk::EthereumZkLightClient,
    std::fs,
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

    let wasm_vm = Box::new(WasmRuntime::new(config.fuel_costs.clone())?);

    let temp_orch_config = OrchestrationConfig {
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
    };
    let consensus_engine = engine_from_config(&temp_orch_config)?;

    let mut initial_services = Vec::new();
    let penalty_engine: Arc<dyn ioi_consensus::PenaltyEngine> = Arc::new(consensus_engine.clone());
    let penalties_service = Arc::new(ioi_consensus::PenaltiesService::new(penalty_engine));
    initial_services.push(penalties_service as Arc<dyn UpgradableService>);

    for service_config in &config.initial_services {
        match service_config {
            InitialServiceConfig::IdentityHub(migration_config) => {
                tracing::info!(target: "workload", event = "service_init", name = "IdentityHub", impl="native", capabilities="identity_view, tx_decorator, on_end_block");
                let hub = IdentityHub::new(migration_config.clone());
                initial_services
                    .push(Arc::new(hub) as Arc<dyn ioi_api::services::UpgradableService>);
            }
            InitialServiceConfig::Governance(params) => {
                tracing::info!(target: "workload", event = "service_init", name = "Governance", impl="native", capabilities="on_end_block");
                let gov = GovernanceModule::new(params.clone());
                initial_services
                    .push(Arc::new(gov) as Arc<dyn ioi_api::services::UpgradableService>);
            }
            InitialServiceConfig::Oracle(_params) => {
                tracing::info!(target: "workload", event = "service_init", name = "Oracle", impl="native", capabilities="");
                let oracle = OracleService::new();
                initial_services
                    .push(Arc::new(oracle) as Arc<dyn ioi_api::services::UpgradableService>);
            }
            #[cfg(feature = "ibc-deps")]
            InitialServiceConfig::Ibc(ibc_config) => {
                tracing::info!(target: "workload", event = "service_init", name = "IBC", impl="native", capabilities="");
                let mut verifier_registry = VerifierRegistry::new();
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
                initial_services.push(Arc::new(ChannelManager::new()) as Arc<dyn UpgradableService>);
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

    let workload_container = Arc::new(WorkloadContainer::new(
        config.clone(),
        state_tree,
        wasm_vm,
        service_directory,
        store,
    )?);

    let mut machine = ExecutionMachine::new(
        commitment_scheme.clone(),
        UnifiedTransactionModel::new(commitment_scheme),
        1.into(),
        initial_services,
        consensus_engine,
        workload_container.clone(),
        config.service_policies.clone(),
    )?;

    for runtime_id in &config.runtimes {
        let id = runtime_id.to_ascii_lowercase();
        if id == "wasm" {
            tracing::info!(target: "workload", "Registering WasmRuntime for service upgrades.");
            let wasm_runtime = WasmRuntime::new(config.fuel_costs.clone())?;
            machine
                .service_manager
                .register_runtime("wasm", Arc::new(wasm_runtime));
        }
    }

    machine
        .load_or_initialize_status(&workload_container)
        .await?;
    let machine_arc = Arc::new(Mutex::new(machine));

    let machine_for_gc = machine_arc.clone();
    let workload_for_gc = workload_container.clone();

    tokio::spawn(async move {
        let gc_interval_secs = workload_for_gc.config().gc_interval_secs.max(1);
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
                let guard = machine_for_gc.lock().await;
                use ioi_api::chain::ChainStateMachine;
                guard.status().height
            };
            if let Err(e) = workload_for_gc.run_gc_pass(current_height).await {
                log::error!("[GC] Background pass failed: {}", e);
            }
        }
    });

    Ok((workload_container, machine_arc))
}