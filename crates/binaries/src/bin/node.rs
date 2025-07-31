// Path: crates/binaries/src/bin/node.rs

//! # DePIN SDK Node
//!
//! This binary acts as the composition root for the validator node. It initializes
//! all core components (chain logic, state, containers) and wires them together.

use anyhow::anyhow;
use clap::Parser;
use depin_sdk_chain::ChainLogic;
use depin_sdk_commitment_schemes::hash::HashCommitmentScheme;
use depin_sdk_consensus::round_robin::RoundRobinBftEngine;
use depin_sdk_core::config::WorkloadConfig;
use depin_sdk_core::validator::WorkloadContainer;
use depin_sdk_core::Container;
use depin_sdk_state_trees::file::FileStateTree;
use depin_sdk_sync::libp2p::Libp2pSync;
use depin_sdk_transaction_models::utxo::UTXOModel;
use depin_sdk_validator::common::GuardianContainer;
use depin_sdk_validator::standard::OrchestrationContainer;
use libp2p::{identity, Multiaddr};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Parser, Debug)]
#[clap(name = "node", about = "A minimum viable sovereign chain node.")]
struct Opts {
    #[clap(long, default_value = "state.json")]
    state_file: String,
    #[clap(long, default_value = "./config")]
    config_dir: String,
    #[clap(long)]
    peer: Option<Multiaddr>,
    #[clap(long, default_value = "/ip4/0.0.0.0/tcp/0")]
    listen_address: Multiaddr,
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
    let chain_ref = Arc::new(Mutex::new(chain_logic));

    let consensus_engine = RoundRobinBftEngine::new();

    // Setup libp2p identity
    let key_path = Path::new(&opts.state_file).with_extension("json.identity.key");
    let local_key = if key_path.exists() {
        let mut bytes = Vec::new();
        fs::File::open(&key_path)?.read_to_end(&mut bytes)?;
        identity::Keypair::from_protobuf_encoding(&bytes)?
    } else {
        let keypair = identity::Keypair::generate_ed25519();
        fs::File::create(&key_path)?.write_all(&keypair.to_protobuf_encoding()?)?;
        log::info!("Generated and saved new identity key to {:?}", key_path);
        keypair
    };

    // Instantiate the new Libp2pSync
    let syncer = Arc::new(Libp2pSync::new(
        chain_ref.clone(),
        workload_container.clone(),
        local_key,
        opts.listen_address,
        opts.peer,
    )?);

    let config_path = PathBuf::from(&opts.config_dir);
    let orchestration_container = Arc::new(
        OrchestrationContainer::<
            HashCommitmentScheme,
            UTXOModel<HashCommitmentScheme>,
            FileStateTree<HashCommitmentScheme>,
        >::new(
            &config_path.join("orchestration.toml"),
            syncer,
            consensus_engine,
        )?,
    );
    let guardian_container = GuardianContainer::new(&config_path.join("guardian.toml"))?;

    orchestration_container.set_chain_and_workload_ref(
        chain_ref.clone(),
        workload_container.clone(),
    );

    guardian_container.start().await.map_err(|e| anyhow!(e))?;
    orchestration_container.start().await.map_err(|e| anyhow!(e))?;
    workload_container.start().await.map_err(|e| anyhow!(e))?;

    log::info!("Node successfully started. Running indefinitely...");

    tokio::signal::ctrl_c().await?;

    log::info!("Shutdown signal received. Stopping node...");
    orchestration_container.stop().await.map_err(|e| anyhow!(e))?;
    workload_container.stop().await.map_err(|e| anyhow!(e))?;
    guardian_container.stop().await.map_err(|e| anyhow!(e))?;
    log::info!("Node stopped gracefully.");

    Ok(())
}