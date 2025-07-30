// Path: crates/validator/src/bin/validator.rs

use anyhow::anyhow;
use clap::Parser;
use depin_sdk_commitment_schemes::hash::HashCommitmentScheme;
use depin_sdk_core::validator::{Container, WorkloadContainer};
use depin_sdk_core::WorkloadConfig;
use depin_sdk_state_trees::file::FileStateTree;
use depin_sdk_transaction_models::utxo::UTXOModel; // Import UTXOModel
use depin_sdk_validator::{common::GuardianContainer, standard::OrchestrationContainer};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Parser, Debug)]
#[clap(name = "validator", about = "A standard DePIN SDK validator node.")]
struct Opts {
    // MODIFICATION: Add state_file argument.
    #[clap(long, default_value = "state_standard.json")]
    state_file: String,

    #[clap(long, default_value = "./config")]
    config_dir: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::builder().filter_level(log::LevelFilter::Info).init();
    let opts = Opts::parse();
    let path = PathBuf::from(opts.config_dir);

    log::info!("Initializing Standard Validator...");

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
            UTXOModel<HashCommitmentScheme>, // Use the actual model
            FileStateTree<HashCommitmentScheme>,
        >::new(&path.join("orchestration.toml"), &opts.state_file)
        .await?,
    );

    // NOTE: This should also be wired up to a real ChainLogic instance like in mvsc.rs
    // For now, setting dummy refs to compile.
    orchestration.set_chain_and_workload_ref(
        Arc::new(Mutex::new(())), 
        workload.clone()
    );

    log::info!("Starting services...");
    guardian.start().await?;
    orchestration.start().await?;
    workload.start().await?;

    tokio::signal::ctrl_c().await?;
    log::info!("Shutdown signal received.");

    workload.stop().await?;
    orchestration.stop().await?;
    guardian.stop().await?;
    log::info!("Validator stopped gracefully.");

    Ok(())
}