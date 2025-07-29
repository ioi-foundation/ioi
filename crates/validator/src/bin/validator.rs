// Path: crates/validator/src/bin/validator.rs

use anyhow::anyhow;
use clap::Parser;
use depin_sdk_commitment_schemes::hash::HashCommitmentScheme;
// FIX: core::Container is now async
use depin_sdk_core::validator::{Container, WorkloadContainer};
use depin_sdk_core::WorkloadConfig;
use depin_sdk_state_trees::file::FileStateTree;
use depin_sdk_validator::{common::GuardianContainer, standard::OrchestrationContainer};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Parser, Debug)]
#[clap(name = "validator", about = "A standard DePIN SDK validator node.")]
struct Opts {
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

    let state_tree = FileStateTree::new("state.json", HashCommitmentScheme::new());

    let workload_config = WorkloadConfig {
        enabled_vms: vec!["WASM".to_string()],
    };

    let workload = Arc::new(WorkloadContainer::new(workload_config, state_tree));

    // FIX: OrchestrationContainer::new is now async and must be awaited.
    let orchestration = Arc::new(
        OrchestrationContainer::<
            HashCommitmentScheme,
            (), // Placeholder for TM
            FileStateTree<HashCommitmentScheme>,
        >::new(&path.join("orchestration.toml"))
        .await?,
    );

    // Wire up a dummy chain for now. In a real scenario, this would be part of the composition root.
    // orchestration.set_chain_and_workload_ref(Arc::new(Mutex::new(())), workload);

    log::info!("Starting services...");
    orchestration.start().await?;
    guardian.start().await?;

    tokio::signal::ctrl_c().await?;
    log::info!("Shutdown signal received.");

    orchestration.stop().await?;
    guardian.stop().await?;
    log::info!("Validator stopped gracefully.");

    Ok(())
}