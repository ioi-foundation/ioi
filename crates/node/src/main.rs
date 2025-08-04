// Path: crates/node/src/main.rs
// Change: Added missing imports for Duration and attest_to_guardian.

#![forbid(unsafe_code)]

use anyhow::anyhow;
use cfg_if::cfg_if;
use clap::{Parser, Subcommand};
use depin_sdk_api::services::{BlockchainService, ServiceType, UpgradableService};
use depin_sdk_api::state::StateTree;
use depin_sdk_api::validator::{Container, WorkloadContainer};
use depin_sdk_api::vm::VirtualMachine;
use depin_sdk_chain::Chain;
use depin_sdk_commitment::hash::HashCommitmentScheme;
use depin_sdk_consensus::ConsensusEngine;
use depin_sdk_network::libp2p::Libp2pSync;
use depin_sdk_state_tree::file::FileStateTree;
use depin_sdk_transaction_models::protocol::ProtocolModel;
use depin_sdk_types::app::ProtocolTransaction;
use depin_sdk_types::config::WorkloadConfig;
use depin_sdk_types::error::{CoreError, UpgradeError};
use depin_sdk_validator::common::attestation::attest_to_guardian; // FIX: Import the attestation helper function.
use depin_sdk_validator::common::GuardianContainer;
use depin_sdk_validator::standard::OrchestrationContainer;
use libp2p::{identity, Multiaddr};
use serde_json::Value;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration; // FIX: Import the Duration type.
use tokio::sync::Mutex;

// --- Test Service Definitions for Forkless Upgrade E2E Test ---
#[derive(Debug)]
struct FeeCalculatorV1;
impl BlockchainService for FeeCalculatorV1 {
    fn service_type(&self) -> ServiceType {
        ServiceType::Custom("fee".to_string())
    }
}
impl UpgradableService for FeeCalculatorV1 {
    fn prepare_upgrade(&self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        Ok(Vec::new())
    }
    fn complete_upgrade(&mut self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}
#[derive(Debug)]
struct FeeCalculatorV2;
impl BlockchainService for FeeCalculatorV2 {
    fn service_type(&self) -> ServiceType {
        ServiceType::Custom("fee".to_string())
    }
}
impl UpgradableService for FeeCalculatorV2 {
    fn prepare_upgrade(&self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        Ok(Vec::new())
    }
    fn complete_upgrade(&mut self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}
fn service_factory(wasm_blob: &[u8]) -> Result<Arc<dyn UpgradableService>, CoreError> {
    let marker = std::str::from_utf8(wasm_blob)
        .map_err(|_| CoreError::UpgradeError("Invalid marker".to_string()))?;
    match marker {
        "FEE_CALCULATOR_V1" => Ok(Arc::new(FeeCalculatorV1)),
        "FEE_CALCULATOR_V2" => Ok(Arc::new(FeeCalculatorV2)),
        _ => Err(CoreError::UpgradeError(format!(
            "Unknown service: {}",
            marker
        ))),
    }
}

#[derive(Parser, Debug)]
#[clap(name = "depin-sdk-node", about = "A sovereign chain node.")]
struct Cli {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Runs the full, single-process validator node.
    Node(NodeOpts),
    /// Runs only the Guardian container logic.
    Guardian(ContainerOpts),
    /// Runs only the Orchestration container logic.
    Orchestration(ContainerOpts),
    /// Runs only the Workload container logic.
    Workload(ContainerOpts),
}

#[derive(Parser, Debug)]
struct NodeOpts {
    #[clap(long, default_value = "state.json")]
    state_file: String,
    #[clap(long, default_value = "genesis.json")]
    genesis_file: String,
    #[clap(long, default_value = "./config")]
    config_dir: String,
    #[clap(long)]
    bootnode: Option<Multiaddr>,
    #[clap(long, default_value = "/ip4/0.0.0.0/tcp/0")]
    listen_address: Multiaddr,
}

#[derive(Parser, Debug)]
struct ContainerOpts {}

fn populate_state_from_genesis(
    state_tree: &mut FileStateTree<HashCommitmentScheme>,
    genesis_path: &Path,
) -> anyhow::Result<()> {
    let genesis_content = fs::read_to_string(genesis_path)?;
    let genesis_json: Value = serde_json::from_str(&genesis_content)?;
    let state = genesis_json["genesis_state"]
        .as_object()
        .ok_or_else(|| anyhow!("genesis_state missing"))?;
    for (key, value) in state {
        state_tree.insert(key.as_bytes(), &serde_json::to_vec(value)?)?;
    }
    Ok(())
}

fn build_consensus_engine() -> Box<dyn ConsensusEngine<ProtocolTransaction> + Send + Sync> {
    cfg_if! {
        if #[cfg(feature = "consensus-poa")] {
            Box::new(depin_sdk_consensus::proof_of_authority::ProofOfAuthorityEngine::new())
        } else if #[cfg(feature = "consensus-pos")] {
            Box::new(depin_sdk_consensus::proof_of_stake::ProofOfStakeEngine::new())
        } else if #[cfg(feature = "consensus-round-robin")] {
            Box::new(depin_sdk_consensus::round_robin::RoundRobinBftEngine::new())
        } else {
            compile_error!("A consensus engine feature must be enabled.");
        }
    }
}

fn build_virtual_machine() -> Box<dyn VirtualMachine + Send + Sync> {
    cfg_if! {
        if #[cfg(feature = "vm-wasm")] {
            Box::new(depin_sdk_vm_wasm::WasmVm::new())
        } else {
            compile_error!("A VM feature must be enabled.");
        }
    }
}

async fn run_full_node(opts: NodeOpts) -> anyhow::Result<()> {
    log::info!("Initializing DePIN SDK Node (Full Mode)...");
    let commitment_scheme = HashCommitmentScheme::new();
    let transaction_model = ProtocolModel::new(commitment_scheme.clone());
    let state_path = PathBuf::from(&opts.state_file);
    let genesis_path = PathBuf::from(&opts.genesis_file);
    let mut state_tree = FileStateTree::new(&state_path, commitment_scheme.clone());
    if !state_path.exists() && genesis_path.exists() {
        populate_state_from_genesis(&mut state_tree, &genesis_path)?;
    }
    let workload_container = Arc::new(WorkloadContainer::new(
        WorkloadConfig {
            enabled_vms: vec![],
        },
        state_tree,
        build_virtual_machine(),
    ));
    let mut chain = Chain::new(
        commitment_scheme.clone(),
        transaction_model,
        "mvsc-chain-1",
        vec![Arc::new(FeeCalculatorV1)],
        Box::new(service_factory),
    );
    chain.load_or_initialize_status(&workload_container).await?;
    let chain_ref = Arc::new(Mutex::new(chain));
    let consensus_engine = Arc::new(Mutex::new(build_consensus_engine()));
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
    let (syncer, swarm_commander, network_event_receiver) =
        Libp2pSync::new(local_key, opts.listen_address, opts.bootnode)?;
    let config_path = PathBuf::from(&opts.config_dir);
    let orchestration_container = Arc::new(OrchestrationContainer::new(
        &config_path.join("orchestration.toml"),
        syncer,
        network_event_receiver,
        swarm_commander,
        consensus_engine,
    )?);
    let guardian_container = GuardianContainer::new(&config_path.join("guardian.toml"))?;
    orchestration_container
        .set_chain_and_workload_ref(chain_ref.clone(), workload_container.clone());
    guardian_container.start().await?;
    orchestration_container.start().await?;
    workload_container.start().await?;
    log::info!("Node successfully started. Running indefinitely...");
    tokio::signal::ctrl_c().await?;
    orchestration_container.stop().await?;
    workload_container.stop().await?;
    guardian_container.stop().await?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();
    let cli = Cli::parse();
    match cli.command {
        Command::Node(opts) => run_full_node(opts).await?,
        Command::Guardian(_) => {
            let guardian = GuardianContainer::new(&PathBuf::from("./config/guardian.toml"))?;
            guardian.start().await?;
            log::info!("Guardian container running...");
            tokio::signal::ctrl_c().await?;
            guardian.stop().await?;
        }
        Command::Orchestration(_) | Command::Workload(_) => {
            log::info!("Container starting up to attest...");
            tokio::time::sleep(Duration::from_secs(5)).await;
            if let Ok(guardian_addr) = std::env::var("GUARDIAN_ADDR") {
                attest_to_guardian(&guardian_addr).await?;
            } else {
                log::error!("GUARDIAN_ADDR environment variable not set. Cannot attest.");
            }
            log::info!("Attestation complete. Container will now idle.");
            tokio::signal::ctrl_c().await?;
        }
    }
    log::info!("Shutdown complete.");
    Ok(())
}
