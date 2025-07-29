// Path: crates/validator/src/bin/validator_hybrid.rs

use anyhow::anyhow;
use clap::Parser;
// FIX: Import WorkloadContainer from its new, correct location in `core`.
use depin_sdk_core::validator::WorkloadContainer;
use depin_sdk_core::{config::WorkloadConfig, Container};
use depin_sdk_state_trees::file::FileStateTree;
// FIX: Add necessary imports.
use depin_sdk_commitment_schemes::hash::HashCommitmentScheme;
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
    #[clap(long, default_value = "./config")]
    config_dir: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::builder().filter_level(log::LevelFilter::Info).init();
    let opts = Opts::parse();
    let path = PathBuf::from(opts.config_dir);

    log::info!("Initializing Hybrid Validator...");

    // FIX: Pass borrowed paths (`&`) to the `new` constructors.
    let guardian = GuardianContainer::new(&path.join("guardian.toml"))?;

    let state_tree = FileStateTree::new("state.json", HashCommitmentScheme::new());

    let workload = Arc::new(WorkloadContainer::new(
        WorkloadConfig::default(),
        state_tree,
    ));

    let orchestration = Arc::new(OrchestrationContainer::new(
        &path.join("orchestration.toml"),
    )?);
    
    // Wire up a dummy chain for now.
    orchestration.set_chain_and_workload_ref(Arc::new(Mutex::new(())), workload);

    let interface = InterfaceContainer::new(&path.join("interface.toml"))?;
    let api = ApiContainer::new(&path.join("api.toml"))?;


    log::info!("Starting services...");
    guardian.start()?;
    // FIX: The start method is async and must be awaited.
    orchestration.start().await?;
    interface.start()?;
    api.start()?;

    tokio::signal::ctrl_c().await?;
    log::info!("Shutdown signal received.");

    api.stop()?;
    interface.stop()?;
    orchestration.stop().await?;
    guardian.stop()?;
    log::info!("Validator stopped gracefully.");
    
    Ok(())
}