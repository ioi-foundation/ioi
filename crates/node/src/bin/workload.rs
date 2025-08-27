// Path: crates/node/src/bin/workload.rs

#![forbid(unsafe_code)]

use anyhow::{anyhow, Result};
use clap::Parser;
use depin_sdk_api::services::access::{Service, ServiceDirectory};
use depin_sdk_api::{
    commitment::CommitmentScheme, state::StateManager, validator::WorkloadContainer,
};
use depin_sdk_chain::util::load_state_from_genesis_file;
use depin_sdk_chain::wasm_loader::load_service_from_wasm;
use depin_sdk_chain::Chain;
use depin_sdk_services::identity::IdentityHub;
use depin_sdk_transaction_models::unified::UnifiedTransactionModel;
use depin_sdk_types::config::{
    CommitmentSchemeType, InitialServiceConfig, StateTreeType, WorkloadConfig,
};
use depin_sdk_validator::standard::WorkloadIpcServer;
use depin_sdk_vm_wasm::WasmVm;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

// Imports for concrete types used in the factory
#[cfg(feature = "primitive-hash")]
use depin_sdk_commitment::primitives::hash::HashCommitmentScheme;
#[cfg(feature = "primitive-kzg")]
use depin_sdk_commitment::primitives::kzg::{KZGCommitmentScheme, KZGParams};
#[cfg(feature = "tree-file")]
use depin_sdk_commitment::tree::file::FileStateTree;
#[cfg(feature = "tree-hashmap")]
use depin_sdk_commitment::tree::hashmap::HashMapStateTree;
#[cfg(feature = "tree-iavl")]
use depin_sdk_commitment::tree::iavl::IAVLTree;
#[cfg(feature = "tree-sparse-merkle")]
use depin_sdk_commitment::tree::sparse_merkle::SparseMerkleTree;
#[cfg(feature = "tree-verkle")]
use depin_sdk_commitment::tree::verkle::VerkleTree;

#[derive(Parser, Debug)]
struct WorkloadOpts {
    #[clap(long, help = "Path to the workload.toml configuration file.")]
    config: PathBuf,
}

type BoxedStateManager<CS> = Box<
    dyn StateManager<
            Commitment = <CS as CommitmentScheme>::Commitment,
            Proof = <CS as CommitmentScheme>::Proof,
        > + Send
        + Sync,
>;

/// Generic function containing all logic after component instantiation.
async fn run_workload<CS>(
    mut state_tree: BoxedStateManager<CS>,
    commitment_scheme: CS,
    config: WorkloadConfig,
) -> Result<()>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + Send + Sync + std::fmt::Debug,
    CS::Proof: AsRef<[u8]> + serde::Serialize + for<'de> serde::Deserialize<'de>,
    CS::Commitment: std::fmt::Debug,
{
    if !Path::new(&config.state_file).exists() {
        load_state_from_genesis_file(&mut *state_tree, &config.genesis_file)?;
    } else {
        log::info!(
            "Found existing state file at '{}'. Skipping genesis initialization.",
            &config.state_file
        );
    }

    let wasm_vm = Box::new(WasmVm::new(config.fuel_costs.clone()));

    let mut initial_services = Vec::new();
    for service_config in &config.initial_services {
        match service_config {
            InitialServiceConfig::IdentityHub(migration_config) => {
                log::info!("[Workload] Instantiating initial service: IdentityHub");
                let hub = IdentityHub::new(migration_config.clone());
                initial_services
                    .push(Arc::new(hub) as Arc<dyn depin_sdk_api::services::UpgradableService>);
            }
        }
    }

    let services_for_dir: Vec<Arc<dyn Service>> = initial_services
        .iter()
        .map(|s| s.clone() as Arc<dyn Service>)
        .collect();
    let service_directory = ServiceDirectory::new(services_for_dir);

    let workload_container = Arc::new(WorkloadContainer::new(
        config.clone(),
        state_tree,
        wasm_vm,
        service_directory,
    ));

    let mut chain = Chain::new(
        commitment_scheme.clone(),
        UnifiedTransactionModel::new(commitment_scheme),
        "depin-chain-1",
        initial_services,
        Box::new(load_service_from_wasm),
        config.consensus_type.clone(),
    );
    chain.load_or_initialize_status(&workload_container).await?;
    let chain_arc = Arc::new(Mutex::new(chain));

    let ipc_server_addr =
        std::env::var("IPC_SERVER_ADDR").unwrap_or_else(|_| "0.0.0.0:8555".to_string());

    let ipc_server = WorkloadIpcServer::new(ipc_server_addr, workload_container, chain_arc).await?;

    log::info!("Workload: State, VM, and Chain initialized. Running IPC server.");
    ipc_server.run().await?;
    Ok(())
}

fn check_features() {
    let mut enabled_features = Vec::new();
    if cfg!(feature = "tree-file") {
        enabled_features.push("tree-file");
    }
    if cfg!(feature = "tree-hashmap") {
        enabled_features.push("tree-hashmap");
    }
    if cfg!(feature = "tree-iavl") {
        enabled_features.push("tree-iavl");
    }
    if cfg!(feature = "tree-sparse-merkle") {
        enabled_features.push("tree-sparse-merkle");
    }
    if cfg!(feature = "tree-verkle") {
        enabled_features.push("tree-verkle");
    }

    if enabled_features.len() > 1 {
        panic!("Error: Please enable exactly one 'tree-*' feature for the depin-sdk-node crate. Found: {:?}", enabled_features);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // --- FIX START: Move build-time check to runtime ---
    check_features();
    // --- FIX END ---

    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();
    let opts = WorkloadOpts::parse();
    log::info!(
        "Workload container starting up with config: {:?}",
        opts.config
    );

    let config_str = fs::read_to_string(&opts.config)?;
    let config: WorkloadConfig = toml::from_str(&config_str)?;

    match (config.state_tree.clone(), config.commitment_scheme.clone()) {
        #[cfg(all(feature = "tree-file", feature = "primitive-hash"))]
        (StateTreeType::File, CommitmentSchemeType::Hash) => {
            log::info!("Instantiating state backend: FileStateTree<HashCommitmentScheme>");
            let commitment_scheme = HashCommitmentScheme::new();
            let state_tree = Box::new(FileStateTree::new(
                &config.state_file,
                commitment_scheme.clone(),
            ));
            run_workload(state_tree, commitment_scheme, config).await
        }

        #[cfg(all(feature = "tree-hashmap", feature = "primitive-hash"))]
        (StateTreeType::HashMap, CommitmentSchemeType::Hash) => {
            log::info!("Instantiating state backend: HashMapStateTree<HashCommitmentScheme>");
            let commitment_scheme = HashCommitmentScheme::new();
            let state_tree = Box::new(HashMapStateTree::new(commitment_scheme.clone()));
            run_workload(state_tree, commitment_scheme, config).await
        }

        #[cfg(all(feature = "tree-iavl", feature = "primitive-hash"))]
        (StateTreeType::IAVL, CommitmentSchemeType::Hash) => {
            log::info!("Instantiating state backend: IAVLTree<HashCommitmentScheme>");
            let commitment_scheme = HashCommitmentScheme::new();
            let state_tree = Box::new(IAVLTree::new(commitment_scheme.clone()));
            run_workload(state_tree, commitment_scheme, config).await
        }

        #[cfg(all(feature = "tree-sparse-merkle", feature = "primitive-hash"))]
        (StateTreeType::SparseMerkle, CommitmentSchemeType::Hash) => {
            log::info!("Instantiating state backend: SparseMerkleTree<HashCommitmentScheme>");
            let commitment_scheme = HashCommitmentScheme::new();
            let state_tree = Box::new(SparseMerkleTree::new(commitment_scheme.clone()));
            run_workload(state_tree, commitment_scheme, config).await
        }

        #[cfg(all(feature = "tree-verkle", feature = "primitive-kzg"))]
        (StateTreeType::Verkle, CommitmentSchemeType::KZG) => {
            log::info!("Instantiating state backend: VerkleTree<KZGCommitmentScheme>");
            let params = KZGParams::new_insecure_for_testing(12345, 256);
            let commitment_scheme = KZGCommitmentScheme::new(params);
            let state_tree = Box::new(VerkleTree::new(commitment_scheme.clone(), 256));
            run_workload(state_tree, commitment_scheme, config).await
        }

        _ => {
            let err_msg = format!(
                "Unsupported or disabled state configuration: StateTree={:?}, CommitmentScheme={:?}. Please check your config and compile-time features.",
                config.state_tree, config.commitment_scheme
            );
            log::error!("{}", err_msg);
            Err(anyhow!(err_msg))
        }
    }
}
