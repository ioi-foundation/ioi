// Path: crates/node/src/bin/workload.rs

//! The main binary for the Workload container.
//!
//! The Workload container is the primary component responsible for all deterministic,
//! state-related operations in a validator node. Its responsibilities include:
//!
//! - Managing the state tree (e.g., IAVL, Verkle).
//! - Executing smart contracts within a virtual machine (e.g., Wasmtime).
//! - Processing blocks by applying transactions and updating the state.
//! - Generating cryptographic proofs of state for queries.
//! - Communicating with the Orchestration container via a secure IPC channel to
//!   receive blocks for processing and respond to state queries.
//!
//! This binary is configured via a `workload.toml` file and is launched by the
//! `ioi-node` process or a similar orchestration mechanism.

use anyhow::{anyhow, Result};
use clap::Parser;
use ioi_api::services::access::ServiceDirectory;
use ioi_api::services::BlockchainService;
use ioi_api::{commitment::CommitmentScheme, state::StateManager, validator::WorkloadContainer};
use ioi_consensus::util::engine_from_config;
use ioi_execution::util::load_state_from_genesis_file;
use ioi_execution::Chain;
use ioi_services::governance::GovernanceModule;
// --- IBC Service Imports ---
#[cfg(feature = "ibc-deps")]
use ioi_services::ibc::{
    // Updated paths
    apps::channel::ChannelManager,
    core::registry::VerifierRegistry,
    light_clients::tendermint::TendermintVerifier,
};
use ioi_services::identity::IdentityHub;
use ioi_services::oracle::OracleService;
use ioi_storage::metrics as storage_metrics;
use ioi_storage::RedbEpochStore;
use ioi_tx::unified::UnifiedTransactionModel;
use ioi_types::config::{InitialServiceConfig, OrchestrationConfig, WorkloadConfig};
use ioi_validator::standard::WorkloadIpcServer;
use ioi_vm_wasm::WasmRuntime;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

// Imports for concrete types used in the factory
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

#[derive(Parser, Debug)]
struct WorkloadOpts {
    #[clap(long, help = "Path to the workload.toml configuration file.")]
    config: PathBuf,
}

/// Generic function containing all logic after component instantiation.
#[allow(dead_code)]
async fn run_workload<CS, ST>(
    mut state_tree: ST,
    commitment_scheme: CS,
    config: WorkloadConfig,
) -> Result<()>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Clone,
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + Send + Sync + std::fmt::Debug,
    CS::Proof:
        AsRef<[u8]> + serde::Serialize + for<'de> serde::Deserialize<'de> + std::fmt::Debug,
    CS::Commitment: std::fmt::Debug + From<Vec<u8>>,
{
    if !Path::new(&config.state_file).exists() {
        load_state_from_genesis_file(&mut state_tree, &config.genesis_file)?;
    } else {
        tracing::info!(
            target: "workload",
            event = "state_init",
            path = %config.state_file,
            "Found existing state file, skipping genesis init."
        );
    }

    let wasm_vm = Box::new(WasmRuntime::new(config.fuel_costs.clone())?);

    let mut initial_services = Vec::new();
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
            // --- IBC Service Instantiation ---
            #[cfg(feature = "ibc-deps")]
            InitialServiceConfig::Ibc(ibc_config) => {
                tracing::info!(target: "workload", event = "service_init", name = "IBC", impl="native", capabilities="");
                // A real implementation would load client configurations from a file or config.
                let mut verifier_registry = VerifierRegistry::new();
                for client_name in &ibc_config.enabled_clients {
                    if client_name.starts_with("tendermint") {
                        // For Milestone A, we instantiate the Tendermint verifier for a mock Cosmos chain.
                        let tm_verifier = TendermintVerifier::new(
                            "cosmos-hub-test".to_string(),
                            "07-tendermint-0".to_string(),
                            Arc::new(state_tree.clone()), // The verifier needs access to the state.
                        );
                        verifier_registry.register(Arc::new(tm_verifier));
                    }
                }
                initial_services
                    .push(Arc::new(verifier_registry)
                        as Arc<dyn ioi_api::services::UpgradableService>);
                // The ChannelManager is also a required part of the IBC service suite.
                initial_services.push(Arc::new(ChannelManager::new())
                    as Arc<dyn ioi_api::services::UpgradableService>);
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

    let store_path = Path::new(&config.state_file).with_extension("db");
    let store = Arc::new(RedbEpochStore::open(store_path, config.epoch_size)?);
    state_tree.attach_store(store.clone());

    let workload_container = Arc::new(WorkloadContainer::new(
        config.clone(),
        state_tree,
        wasm_vm,
        service_directory,
        store.clone(),
    )?);

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

    let mut chain = Chain::new(
        commitment_scheme.clone(),
        UnifiedTransactionModel::new(commitment_scheme),
        1.into(),
        initial_services,
        consensus_engine,
        workload_container.clone(),
    );

    for runtime_id in &config.runtimes {
        let id = runtime_id.to_ascii_lowercase();
        if id == "wasm" {
            tracing::info!(target: "workload", "Registering WasmRuntime for service upgrades.");
            let wasm_runtime = WasmRuntime::new(config.fuel_costs.clone())?;
            chain
                .service_manager
                .register_runtime("wasm", Arc::new(wasm_runtime));
        }
    }

    chain.load_or_initialize_status(&workload_container).await?;
    let chain_arc = Arc::new(Mutex::new(chain));

    let ipc_server_addr =
        std::env::var("IPC_SERVER_ADDR").unwrap_or_else(|_| "0.0.0.0:8555".to_string());

    let ipc_server = WorkloadIpcServer::new(ipc_server_addr, workload_container, chain_arc).await?;

    tracing::info!(target: "workload", "State, VM, and Chain initialized. Running IPC server.");
    ipc_server.run().await?;
    Ok(())
}

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

#[tokio::main]
async fn main() -> Result<()> {
    ioi_telemetry::init::init_tracing()?;
    let metrics_sink = ioi_telemetry::prometheus::install()?;
    storage_metrics::SINK
        .set(metrics_sink)
        .expect("SINK must only be set once");

    let telemetry_addr_str =
        std::env::var("TELEMETRY_ADDR").unwrap_or_else(|_| "127.0.0.1:9616".to_string());
    let telemetry_addr = telemetry_addr_str.parse()?;
    tokio::spawn(ioi_telemetry::http::run_server(telemetry_addr));

    check_features();

    let opts = WorkloadOpts::parse();
    tracing::info!(
        target: "workload",
        event = "startup",
        config = ?opts.config
    );

    let config_str = fs::read_to_string(&opts.config)?;
    let config: WorkloadConfig = toml::from_str(&config_str)?;

    match (config.state_tree.clone(), config.commitment_scheme.clone()) {
        #[cfg(all(feature = "state-iavl", feature = "commitment-hash"))]
        (ioi_types::config::StateTreeType::IAVL, ioi_types::config::CommitmentSchemeType::Hash) => {
            tracing::info!(target: "workload", "Instantiating state backend: IAVLTree<HashCommitmentScheme>");
            let commitment_scheme = HashCommitmentScheme::new();
            let state_tree = IAVLTree::new(commitment_scheme.clone());
            run_workload(state_tree, commitment_scheme, config).await
        }

        #[cfg(all(feature = "state-sparse-merkle", feature = "commitment-hash"))]
        (
            ioi_types::config::StateTreeType::SparseMerkle,
            ioi_types::config::CommitmentSchemeType::Hash,
        ) => {
            tracing::info!(target: "workload", "Instantiating state backend: SparseMerkleTree<HashCommitmentScheme>");
            let commitment_scheme = HashCommitmentScheme::new();
            let state_tree = SparseMerkleTree::new(commitment_scheme.clone());
            run_workload(state_tree, commitment_scheme, config).await
        }

        #[cfg(all(feature = "state-verkle", feature = "commitment-kzg"))]
        (
            ioi_types::config::StateTreeType::Verkle,
            ioi_types::config::CommitmentSchemeType::KZG,
        ) => {
            tracing::info!(target: "workload", "Instantiating state backend: VerkleTree<KZGCommitmentScheme>");
            let params = if let Some(srs_path) = &config.srs_file_path {
                tracing::info!(target: "workload", "Loading KZG SRS from file: {}", srs_path);
                KZGParams::load_from_file(Path::new(srs_path)).map_err(|e| anyhow!(e))?
            } else {
                tracing::warn!(target: "workload", "Generating insecure KZG parameters for testing. This is slow. DO NOT USE IN PRODUCTION.");
                KZGParams::new_insecure_for_testing(12345, 255)
            };
            let commitment_scheme = KZGCommitmentScheme::new(params);
            let state_tree =
                VerkleTree::new(commitment_scheme.clone(), 256).map_err(|e| anyhow!(e))?;
            run_workload(state_tree, commitment_scheme, config).await
        }

        _ => {
            let err_msg = format!(
                "Unsupported or disabled state configuration: StateTree={:?}, CommitmentScheme={:?}. Please check your config and compile-time features.",
                config.state_tree, config.commitment_scheme
            );
            tracing::error!(target: "workload", "{}", err_msg);
            Err(anyhow!(err_msg))
        }
    }
}