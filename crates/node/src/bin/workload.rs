// Path: crates/node/src/bin/workload.rs
#![forbid(unsafe_code)]

//! The main binary for the Workload container.

use anyhow::{anyhow, Result};
use clap::Parser;
use ioi_api::services::UpgradableService; // Import UpgradableService trait
use ioi_api::services::{access::ServiceDirectory, BlockchainService};
use ioi_api::{
    commitment::CommitmentScheme,
    ibc::LightClient, // Added import
    state::{ProofProvider, StateManager},
    storage::NodeStore,
    validator::WorkloadContainer,
};
use ioi_consensus::util::engine_from_config;
use ioi_crypto::transport::hybrid_kem_tls::{
    derive_application_key, server_post_handshake, AeadWrappedStream,
};
use ioi_execution::util::load_state_from_genesis_file;
use ioi_execution::ExecutionMachine;
use ioi_ipc::jsonrpc::{JsonRpcError, JsonRpcId, JsonRpcRequest, JsonRpcResponse};
use ioi_services::governance::GovernanceModule;
#[cfg(feature = "ibc-deps")]
use ioi_services::ibc::{
    apps::channel::ChannelManager, core::registry::VerifierRegistry,
    light_clients::tendermint::TendermintVerifier,
};
// [NEW] Import for ZK client and driver
#[cfg(all(feature = "ibc-deps", feature = "ethereum-zk"))]
use ioi_services::ibc::light_clients::ethereum_zk::EthereumZkLightClient;
#[cfg(all(feature = "ibc-deps", feature = "ethereum-zk"))]
use zk_driver_succinct::config::SuccinctDriverConfig;

use ioi_services::identity::IdentityHub;
use ioi_services::oracle::OracleService;
use ioi_state::primitives::hash::HashCommitmentScheme;
#[cfg(feature = "commitment-kzg")]
use ioi_state::primitives::kzg::{KZGCommitmentScheme, KZGParams};
use ioi_state::tree::iavl::IAVLTree;
#[cfg(feature = "state-sparse-merkle")]
use ioi_state::tree::sparse_merkle::SparseMerkleTree;
#[cfg(feature = "state-verkle")]
use ioi_state::tree::verkle::VerkleTree;
use ioi_storage::metrics as storage_metrics;
use ioi_storage::RedbEpochStore;
use ioi_tx::unified::UnifiedTransactionModel;
use ioi_types::app::{to_root_hash, Membership};
use ioi_types::codec;
use ioi_types::config::{InitialServiceConfig, OrchestrationConfig, WorkloadConfig};
use ioi_types::keys::{STATUS_KEY, VALIDATOR_SET_KEY};
use ioi_validator::standard::workload_ipc_server::WorkloadIpcServer;
use ioi_vm_wasm::WasmRuntime;
use serde::Serialize;
use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

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
        + ProofProvider // This bound is required by ChainStateMachine
        + Send
        + Sync
        + 'static
        + Clone
        + Debug,
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + Send + Sync + Debug,
    CS::Proof: AsRef<[u8]> + Serialize + for<'de> serde::Deserialize<'de> + Debug,
    CS::Commitment: Debug + From<Vec<u8>>,
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
        // RECOVERY LOGIC: Re-hydrate live state from the last committed version in the store.
        if let Ok((head_height, _)) = store.head() {
            if head_height > 0 {
                if let Ok(Some(head_block)) = store.get_block_by_height(head_height) {
                    let recovered_root = &head_block.header.state_root.0;
                    state_tree.adopt_known_root(recovered_root, head_height)?;
                    tracing::warn!(target: "workload", event = "state_recovered", height = head_height, "Recovered and adopted durable head into state backend.");

                    let anchor = to_root_hash(recovered_root)?;

                    // Re-hydrate critical keys into the live state to make it usable.
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

    // --- START: Initialize Services ---
    // We need to set up the consensus engine first to create the PenaltiesService,
    // mirroring the Orchestrator setup.
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

    // 1. Wire Penalties Service (Kernel Space)
    let penalty_engine: Arc<dyn ioi_consensus::PenaltyEngine> = Arc::new(consensus_engine.clone());
    let penalties_service = Arc::new(ioi_consensus::PenaltiesService::new(penalty_engine));
    initial_services.push(penalties_service as Arc<dyn UpgradableService>);

    // 2. Wire User Space Services
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

                // [NEW] Register Ethereum ZK Client if enabled
                #[cfg(feature = "ethereum-zk")]
                {
                    tracing::info!(target: "workload", "Initializing Ethereum ZK Light Client for 'eth-mainnet'");

                    // Convert WorkloadConfig ZK settings to SuccinctDriverConfig
                    let driver_config = SuccinctDriverConfig {
                        beacon_vkey_hash: config.zk_config.ethereum_beacon_vkey.clone(),
                        state_inclusion_vkey_hash: config.zk_config.state_inclusion_vkey.clone(),
                    };

                    // Initialize with the driver config (which sets the verification keys for native mode)
                    let eth_verifier =
                        EthereumZkLightClient::new("eth-mainnet".to_string(), driver_config);
                    verifier_registry.register(Arc::new(eth_verifier) as Arc<dyn LightClient>);
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
    // --- END: Initialize Services ---

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
        store.clone(),
    )?);

    let mut machine = ExecutionMachine::new(
        commitment_scheme.clone(),
        UnifiedTransactionModel::new(commitment_scheme),
        1.into(),
        initial_services,
        consensus_engine,
        workload_container.clone(),
        config.service_policies.clone(), // Pass service policies
    );

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

    let ipc_server_addr =
        std::env::var("IPC_SERVER_ADDR").unwrap_or_else(|_| "0.0.0.0:8555".to_string());

    let ipc_server: WorkloadIpcServer<ST, CS> =
        WorkloadIpcServer::new(ipc_server_addr, workload_container, machine_arc).await?;

    tracing::info!(target: "workload", "State, VM, and ExecutionMachine initialized. Running IPC server.");
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
            let commitment_scheme = ioi_state::primitives::hash::HashCommitmentScheme::new();
            let state_tree =
                ioi_state::tree::sparse_merkle::SparseMerkleTree::new(commitment_scheme.clone());
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
                ioi_state::primitives::kzg::KZGParams::load_from_file(Path::new(srs_path))
                    .map_err(|e| anyhow!(e))?
            } else {
                tracing::warn!(target: "workload", "Generating insecure KZG parameters for testing. This is slow. DO NOT USE IN PRODUCTION.");
                ioi_state::primitives::kzg::KZGParams::new_insecure_for_testing(12345, 255)
            };
            let commitment_scheme = ioi_state::primitives::kzg::KZGCommitmentScheme::new(params);
            let state_tree =
                ioi_state::tree::verkle::VerkleTree::new(commitment_scheme.clone(), 256)
                    .map_err(|e| anyhow!(e))?;
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
