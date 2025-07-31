// Path: crates/validator/src/bin/validator_hybrid.rs

use anyhow::anyhow;
use clap::Parser;
use depin_sdk_chain::Chain;
use depin_sdk_commitment_schemes::hash::HashCommitmentScheme;
use depin_sdk_consensus::round_robin::RoundRobinBftEngine;
use depin_sdk_core::config::WorkloadConfig;
use depin_sdk_core::validator::{Container, WorkloadContainer};
use depin_sdk_state_trees::file::FileStateTree;
use depin_sdk_sync::libp2p::Libp2pSync;
use depin_sdk_transaction_models::utxo::UTXOModel;
use depin_sdk_validator::{
    common::GuardianContainer,
    hybrid::{ApiContainer, InterfaceContainer},
    standard::OrchestrationContainer,
};
use libp2p::{identity, Multiaddr};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Parser, Debug)]
#[clap(
    name = "validator_hybrid",
    about = "A hybrid DePIN SDK validator node with public APIs."
)]
struct Opts {
    #[clap(long, default_value = "state_hybrid.json")]
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
    let path = PathBuf::from(opts.config_dir);

    log::info!("Initializing Hybrid Validator...");

    let commitment_scheme = HashCommitmentScheme::new();
    let transaction_model = UTXOModel::new(commitment_scheme.clone());
    let state_tree = FileStateTree::new(&opts.state_file, commitment_scheme.clone());
    let workload_config = WorkloadConfig {
        enabled_vms: vec!["WASM".to_string()],
    };
    let workload = Arc::new(WorkloadContainer::new(workload_config, state_tree));

    let mut chain = Chain::new(commitment_scheme.clone(), transaction_model, "hybrid-chain-1", vec![]);
    chain.load_or_initialize_status(&workload).await?;
    let chain_ref = Arc::new(Mutex::new(chain));

    let consensus_engine = RoundRobinBftEngine::new();

    let key_path = Path::new(&opts.state_file).with_extension("json.identity.key");
    let local_key = if key_path.exists() {
        let mut bytes = Vec::new();
        fs::File::open(&key_path)?.read_to_end(&mut bytes)?;
        identity::Keypair::from_protobuf_encoding(&bytes)?
    } else {
        let keypair = identity::Keypair::generate_ed25519();
        fs::File::create(&key_path)?.write_all(&keypair.to_protobuf_encoding()?)?;
        keypair
    };

    let syncer = Arc::new(Libp2pSync::new(
        chain_ref.clone(),
        workload.clone(),
        local_key,
        opts.listen_address,
        opts.peer,
    )?);

    let orchestration = Arc::new(
        OrchestrationContainer::<
            HashCommitmentScheme,
            UTXOModel<HashCommitmentScheme>,
            FileStateTree<HashCommitmentScheme>,
        >::new(
            &path.join("orchestration.toml"),
            syncer,
            consensus_engine,
        )?,
    );

    orchestration.set_chain_and_workload_ref(chain_ref.clone(), workload.clone());

    let guardian = GuardianContainer::new(&path.join("guardian.toml"))?;
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