// Path: crates/node/src/bin/workload.rs

#![forbid(unsafe_code)]

use anyhow::{anyhow, Result};
use clap::Parser;
// --- FIX START: Correct the typo from CommitScheme to CommitmentScheme ---
use depin_sdk_api::{
    commitment::CommitmentScheme, state::StateManager, validator::WorkloadContainer,
};
// --- FIX END ---
use depin_sdk_chain::util::load_state_from_genesis_file;
use depin_sdk_chain::wasm_loader::load_service_from_wasm;
use depin_sdk_chain::Chain;
use depin_sdk_transaction_models::unified::UnifiedTransactionModel;
use depin_sdk_types::config::{CommitmentSchemeType, StateTreeType, WorkloadConfig};
use depin_sdk_validator::standard::WorkloadIpcServer;
use depin_sdk_vm_wasm::WasmVm;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

// Imports for concrete types used in the factory
#[cfg(feature = "primitive-hash")]
use depin_sdk_commitment::primitives::hash::HashCommitmentScheme;
#[cfg(feature = "tree-file")]
use depin_sdk_commitment::tree::file::FileStateTree;
#[cfg(feature = "tree-hashmap")]
use depin_sdk_commitment::tree::hashmap::HashMapStateTree;

#[derive(Parser, Debug)]
struct WorkloadOpts {
    #[clap(long, help = "Path to the workload.toml configuration file.")]
    config: PathBuf,
}

/// Generic function containing all logic after component instantiation.
async fn run_workload<ST, CS>(
    mut state_tree: ST,
    commitment_scheme: CS,
    config: WorkloadConfig,
) -> Result<()>
where
    CS: CommitmentScheme + Clone + Default + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + std::fmt::Debug,
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + Send + Sync,
    CS::Proof: AsRef<[u8]> + serde::Serialize + for<'de> serde::Deserialize<'de>,
    CS::Commitment: std::fmt::Debug,
{
    // Initialize state from genesis if the state file doesn't exist.
    if !Path::new(&config.state_file).exists() {
        load_state_from_genesis_file(&mut state_tree, &config.genesis_file)?;
    } else {
        log::info!(
            "Found existing state file at '{}'. Skipping genesis initialization.",
            &config.state_file
        );
    }

    // This logic is now generic and works with any StateManager/CommitmentScheme combination.
    let wasm_vm = Box::new(WasmVm::new());
    let workload_container = Arc::new(WorkloadContainer::new(config, state_tree, wasm_vm));

    let mut chain = Chain::new(
        commitment_scheme.clone(),
        UnifiedTransactionModel::new(commitment_scheme),
        "depin-chain-1",
        vec![],
        Box::new(load_service_from_wasm),
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

#[tokio::main]
async fn main() -> Result<()> {
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
            let state_tree = FileStateTree::new(&config.state_file, commitment_scheme.clone());
            run_workload(state_tree, commitment_scheme, config).await
        }

        #[cfg(all(feature = "tree-hashmap", feature = "primitive-hash"))]
        (StateTreeType::HashMap, CommitmentSchemeType::Hash) => {
            log::info!("Instantiating state backend: HashMapStateTree<HashCommitmentScheme>");
            let commitment_scheme = HashCommitmentScheme::new();
            let state_tree = HashMapStateTree::new(commitment_scheme.clone());
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
