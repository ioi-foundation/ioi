// Path: crates/chain/src/bin/mvsc.rs

//! # Minimum Viable Single-Node Chain (MVSC)
//!
//! This binary acts as the composition root for the validator node. It initializes
//! all core components (chain logic, state, containers) and wires them together.

use anyhow::anyhow;
use clap::Parser;
use depin_sdk_chain::ChainLogic;
use depin_sdk_commitment_schemes::hash::HashCommitmentScheme;
use depin_sdk_core::config::WorkloadConfig;
use depin_sdk_core::validator::WorkloadContainer;
use depin_sdk_core::Container;
use libp2p::Multiaddr;
use depin_sdk_state_trees::file::FileStateTree;
use depin_sdk_transaction_models::utxo::UTXOModel;
use depin_sdk_validator::common::GuardianContainer;
use depin_sdk_validator::standard::OrchestrationContainer;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Parser, Debug)]
#[clap(name = "mvsc", about = "A minimum viable sovereign chain node.")]
struct Opts {
    #[clap(long, default_value = "state.json")]
    state_file: String,
    #[clap(long, default_value = "./config")]
    config_dir: String,
    #[clap(long)]
    peer: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::builder().filter_level(log::LevelFilter::Info).init();
    let opts = Opts::parse();
    log::info!("Initializing DePIN SDK Node...");
    log::info!("Using state file: {}", &opts.state_file);

    let commitment_scheme = HashCommitmentScheme::new();
    let transaction_model = UTXOModel::new(commitment_scheme.clone());
    let state_tree = FileStateTree::new(&opts.state_file, commitment_scheme.clone());
    let workload_config = WorkloadConfig {
        enabled_vms: vec!["WASM".to_string()],
    };

    let workload_container = Arc::new(WorkloadContainer::new(workload_config, state_tree));

    let config_path = PathBuf::from(&opts.config_dir);
    // MODIFICATION: Pass the state_file path to the constructor.
    let orchestration_container = Arc::new(
        OrchestrationContainer::<
            HashCommitmentScheme,
            UTXOModel<HashCommitmentScheme>,
            FileStateTree<HashCommitmentScheme>,
        >::new(&config_path.join("orchestration.toml"), &opts.state_file)
        .await?,
    );
    let guardian_container = GuardianContainer::new(&config_path.join("guardian.toml"))?;

    let mut chain_logic = ChainLogic::new(
        commitment_scheme.clone(),
        transaction_model,
        "mvsc-chain-1",
        vec![],
    );
    chain_logic
        .load_or_initialize_status(&workload_container)
        .await
        .map_err(|e| anyhow!("Failed to load or initialize chain status: {:?}", e))?;
    let chain_ref: Arc<Mutex<ChainLogic<HashCommitmentScheme, UTXOModel<HashCommitmentScheme>>>> =
        Arc::new(Mutex::new(chain_logic));

    orchestration_container.set_chain_and_workload_ref(
        chain_ref.clone(),
        workload_container.clone(),
    );

    guardian_container.start().await.map_err(|e| anyhow!(e))?;
    orchestration_container.start().await.map_err(|e| anyhow!(e))?;
    workload_container.start().await.map_err(|e| anyhow!(e))?;

    if let Some(peer_addr_str) = opts.peer {
        let peer_addr: Multiaddr = peer_addr_str.parse()?;
        log::info!("Attempting to dial peer: {}", peer_addr_str);
        
        // Use the new public method to send a command, instead of locking the swarm.
        orchestration_container.dial(peer_addr).await;
    }

    log::info!("Node successfully started. Running indefinitely...");

    tokio::signal::ctrl_c().await?;

    log::info!("Shutdown signal received. Stopping node...");
    orchestration_container.stop().await.map_err(|e| anyhow!(e))?;
    workload_container.stop().await.map_err(|e| anyhow!(e))?;
    guardian_container.stop().await.map_err(|e| anyhow!(e))?;
    log::info!("Node stopped gracefully.");

    Ok(())
}