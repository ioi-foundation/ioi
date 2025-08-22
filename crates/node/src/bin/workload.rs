// crates/node/src/bin/workload.rs
#![forbid(unsafe_code)]

use anyhow::Result;
use clap::Parser;
use depin_sdk_api::validator::WorkloadContainer;
use depin_sdk_chain::util::load_state_from_genesis_file;
use depin_sdk_chain::wasm_loader::load_service_from_wasm;
use depin_sdk_chain::Chain;
use depin_sdk_commitment::primitives::hash::HashCommitmentScheme;
use depin_sdk_commitment::tree::file::FileStateTree;
use depin_sdk_transaction_models::unified::UnifiedTransactionModel;
use depin_sdk_types::config::WorkloadConfig;
use depin_sdk_validator::standard::WorkloadIpcServer;
use depin_sdk_vm_wasm::WasmVm;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Parser, Debug)]
struct WorkloadOpts {
    #[clap(long)]
    genesis_file: String,
    #[clap(long, default_value = "workload_state.json")]
    state_file: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();
    let opts = WorkloadOpts::parse();
    log::info!("Workload container starting up...");

    let commitment_scheme = HashCommitmentScheme::new();
    let mut state_tree = FileStateTree::new(&opts.state_file, commitment_scheme.clone());

    if !Path::new(&opts.state_file).exists() {
        load_state_from_genesis_file(&mut state_tree, &opts.genesis_file)?;
    } else {
        log::info!(
            "Found existing state file at '{}'. Skipping genesis initialization.",
            &opts.state_file
        );
    }

    let workload_config = WorkloadConfig {
        enabled_vms: vec!["WASM".to_string()],
    };
    let wasm_vm = Box::new(WasmVm::new());
    let workload_container = Arc::new(WorkloadContainer::new(workload_config, state_tree, wasm_vm));

    let mut chain = Chain::new(
        HashCommitmentScheme::new(),
        UnifiedTransactionModel::new(HashCommitmentScheme::new()),
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
