// Path: crates/binaries/src/bin/node.rs

//! # DePIN SDK Node
//!
//! This binary acts as the composition root for the validator node. It initializes
//! all core components (chain logic, state, containers) and wires them together.

use anyhow::anyhow;
use cfg_if::cfg_if;
use clap::Parser;
use depin_sdk_chain::Chain;
use depin_sdk_commitment_schemes::hash::HashCommitmentScheme;
use depin_sdk_core::app::ProtocolTransaction;
use depin_sdk_core::config::WorkloadConfig;
use depin_sdk_core::state::StateTree;
use depin_sdk_core::validator::WorkloadContainer;
use depin_sdk_core::Container;
use depin_sdk_state_trees::file::FileStateTree;
use depin_sdk_sync::libp2p::Libp2pSync;
use depin_sdk_transaction_models::utxo::UTXOModel;
use depin_sdk_validator::common::GuardianContainer;
use depin_sdk_validator::standard::OrchestrationContainer;
use depin_sdk_vm_wasm::WasmVm;
use libp2p::{identity, Multiaddr};
use serde_json::Value;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

// Only import the top-level trait here. Specific engines will be imported inside cfg_if.
use depin_sdk_consensus::ConsensusEngine;

#[derive(Parser, Debug)]
#[clap(name = "node", about = "A minimum viable sovereign chain node.")]
struct Opts {
    #[clap(long, default_value = "state.json")]
    state_file: String,
    #[clap(long, default_value = "genesis.json")]
    genesis_file: String,
    #[clap(long, default_value = "./config")]
    config_dir: String,
    #[clap(long)]
    peer: Option<Multiaddr>,
    #[clap(long, default_value = "/ip4/0.0.0.0/tcp/0")]
    listen_address: Multiaddr,
}

/// Populates the state from a genesis file.
fn populate_state_from_genesis(
    state_tree: &mut FileStateTree<HashCommitmentScheme>,
    genesis_path: &Path,
) -> anyhow::Result<()> {
    log::info!("Populating state from genesis file: {:?}", genesis_path);
    let genesis_content = fs::read_to_string(genesis_path)?;
    let genesis_json: Value = serde_json::from_str(&genesis_content)?;

    let state = genesis_json["genesis_state"]
        .as_object()
        .ok_or_else(|| anyhow!("genesis_state is not a JSON object"))?;

    for (key, value) in state {
        log::info!("  - Loading state for key: {}", key);
        // All values in genesis are serialized to JSON bytes, including the stakes map.
        let value_bytes = serde_json::to_vec(value)?;
        state_tree.insert(key.as_bytes(), &value_bytes)?;
    }
    Ok(())
}

// --- Compile-Time Consensus Engine Selection ---

/// Builds the consensus engine based on compile-time features.
fn build_consensus_engine() -> Box<dyn ConsensusEngine<ProtocolTransaction> + Send + Sync> {
    cfg_if! {
        if #[cfg(feature = "consensus-poa")] {
            use depin_sdk_consensus::proof_of_authority::ProofOfAuthorityEngine;
            log::info!("Building with ProofOfAuthorityEngine.");
            Box::new(ProofOfAuthorityEngine::new())
        } else if #[cfg(feature = "consensus-pos")] {
            use depin_sdk_consensus::proof_of_stake::ProofOfStakeEngine;
            log::info!("Building with ProofOfStakeEngine.");
            Box::new(ProofOfStakeEngine::new())
        } else if #[cfg(feature = "consensus-round-robin")] {
            use depin_sdk_consensus::round_robin::RoundRobinBftEngine;
            log::info!("Building with RoundRobinBftEngine.");
            Box::new(RoundRobinBftEngine::new())
        } else {
            compile_error!("A consensus engine feature must be enabled via --features flag. Use --features consensus-poa, --features consensus-pos, or --features consensus-round-robin");
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();
    let opts = Opts::parse();
    log::info!("Initializing DePIN SDK Node...");
    log::info!("Using state file: {}", &opts.state_file);

    let commitment_scheme = HashCommitmentScheme::new();
    let transaction_model = UTXOModel::new(commitment_scheme.clone());

    let state_path = PathBuf::from(&opts.state_file);
    let genesis_path = PathBuf::from(&opts.genesis_file);
    let is_new_state = !state_path.exists();

    let mut state_tree = FileStateTree::new(&state_path, commitment_scheme.clone());

    if is_new_state && genesis_path.exists() {
        populate_state_from_genesis(&mut state_tree, &genesis_path)
            .map_err(|e| anyhow!("Failed to load genesis state: {}", e))?;
    } else if is_new_state {
        log::warn!("Starting with a fresh state, but no genesis file was found at {:?}. Node may not function correctly.", genesis_path);
    }

    let workload_config = WorkloadConfig {
        enabled_vms: vec!["WASM".to_string()],
    };

    let wasm_vm = Box::new(WasmVm::new());
    let workload_container = Arc::new(WorkloadContainer::new(
        workload_config,
        state_tree,
        wasm_vm,
    ));

    let mut chain = Chain::new(
        commitment_scheme.clone(),
        transaction_model,
        "mvsc-chain-1",
        vec![],
    );
    chain
        .load_or_initialize_status(&workload_container)
        .await
        .map_err(|e| anyhow!("Failed to load or initialize chain status: {:?}", e))?;
    let chain_ref = Arc::new(Mutex::new(chain));

    let consensus_engine = Arc::new(Mutex::new(build_consensus_engine()));

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

    let (syncer, swarm_commander, network_event_receiver) =
        Libp2pSync::new(local_key, opts.listen_address, opts.peer)?;

    let config_path = PathBuf::from(&opts.config_dir);
    let orchestration_container = Arc::new(
        OrchestrationContainer::<
            HashCommitmentScheme,
            UTXOModel<HashCommitmentScheme>,
            FileStateTree<HashCommitmentScheme>,
        >::new(
            &config_path.join("orchestration.toml"),
            syncer,
            network_event_receiver,
            swarm_commander,
            consensus_engine,
        )?,
    );
    let guardian_container = GuardianContainer::new(&config_path.join("guardian.toml"))?;

    orchestration_container.set_chain_and_workload_ref(
        chain_ref.clone(),
        workload_container.clone(),
    );

    guardian_container.start().await.map_err(|e| anyhow!(e))?;
    orchestration_container
        .start()
        .await
        .map_err(|e| anyhow!(e))?;
    workload_container.start().await.map_err(|e| anyhow!(e))?;

    log::info!("Node successfully started. Running indefinitely...");

    tokio::signal::ctrl_c().await?;

    log::info!("Shutdown signal received. Stopping node...");
    orchestration_container
        .stop()
        .await
        .map_err(|e| anyhow!(e))?;
    workload_container.stop().await.map_err(|e| anyhow!(e))?;
    guardian_container.stop().await.map_err(|e| anyhow!(e))?;
    log::info!("Node stopped gracefully.");

    Ok(())
}