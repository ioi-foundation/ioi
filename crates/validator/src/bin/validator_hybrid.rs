// Path: crates/validator/src/bin/validator_hybrid.rs

use anyhow::anyhow;
use clap::Parser;
use depin_sdk_commitment_schemes::hash::HashCommitmentScheme;
use depin_sdk_core::config::WorkloadConfig;
use depin_sdk_core::validator::{Container, WorkloadContainer};
use depin_sdk_state_trees::file::FileStateTree;
use depin_sdk_transaction_models::utxo::UTXOModel;
use depin_sdk_validator::{
    common::GuardianContainer,
    hybrid::{ApiContainer, InterfaceContainer},
    standard::OrchestrationContainer,
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;


#[derive(Parser, Debug)]
#[clap(name = "validator_hybrid", about = "A hybrid DePIN SDK validator node with public APIs.")]
struct Opts {
    // MODIFICATION: Add state_file argument.
    #[clap(long, default_value = "state_hybrid.json")]
    state_file: String,

    #[clap(long, default_value = "./config")]
    config_dir: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::builder().filter_level(log::LevelFilter::Info).init();
    let opts = Opts::parse();
    let path = PathBuf::from(opts.config_dir);

    log::info!("Initializing Hybrid Validator...");

    let guardian = GuardianContainer::new(&path.join("guardian.toml"))?;

    // MODIFICATION: Use the same setup as mvsc.rs for consistency.
    let commitment_scheme = HashCommitmentScheme::new();
    let state_tree = FileStateTree::new(&opts.state_file, commitment_scheme.clone());
    let workload_config = WorkloadConfig {
        enabled_vms: vec!["WASM".to_string()],
    };
    let workload = Arc::new(WorkloadContainer::new(workload_config, state_tree));

    // MODIFICATION: Update constructor call with state_file path and correct generic arguments.
    let orchestration = Arc::new(
        OrchestrationContainer::<
            HashCommitmentScheme,
            UTXOModel<HashCommitmentScheme>,
            FileStateTree<HashCommitmentScheme>,
        >::new(&path.join("orchestration.toml"), &opts.state_file)
        .await?,
    );
    
    // NOTE: The dummy chain logic from mvsc.rs should eventually be moved here too,
    // but for now we'll just set dummy refs to get it compiling.
    orchestration.set_chain_and_workload_ref(
        Arc::new(Mutex::new(())), // This should be a real ChainLogic instance
        workload.clone()
    );

    let interface = InterfaceContainer::new(&path.join("interface.toml"))?;
    let api = ApiContainer::new(&path.join("api.toml"))?;


    log::info!("Starting services...");
    guardian.start().await?;
    orchestration.start().await?;
    workload.start().await?;
    interface.start().await?;
    api.start().await?;

    tokio::signal::ctrl_c().await?;
    log::info!("Shutdown signal received.");

    api.stop().await?;
    interface.stop().await?;
    workload.stop().await?;
    orchestration.stop().await?;
    guardian.stop().await?;
    log::info!("Validator stopped gracefully.");
    
    Ok(())
}