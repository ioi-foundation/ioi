// Path: crates/node/src/bin/orchestration.rs

#![forbid(unsafe_code)]

use anyhow::{anyhow, Result};
use clap::Parser;
use depin_sdk_api::state::Verifier;
use depin_sdk_api::validator::container::Container;
use depin_sdk_chain::Chain;
use depin_sdk_client::{security::SecurityChannel, WorkloadClient};
use depin_sdk_consensus::util::engine_from_config;
use depin_sdk_network::libp2p::Libp2pSync;
use depin_sdk_transaction_models::unified::UnifiedTransactionModel;
use depin_sdk_types::config::OrchestrationConfig;
use depin_sdk_validator::{
    rpc::run_rpc_server,
    standard::{
        orchestration::verifier_select::{create_default_verifier, DefaultVerifier},
        OrchestrationContainer,
    },
};
use libp2p::{identity, Multiaddr};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::Mutex;
use tokio::time::Duration;

// Imports for concrete types used in the factory
use depin_sdk_api::{commitment::CommitmentScheme, state::StateManager};
#[cfg(feature = "primitive-hash")]
use depin_sdk_commitment::primitives::hash::HashCommitmentScheme;
#[cfg(feature = "primitive-kzg")]
use depin_sdk_commitment::primitives::kzg::{KZGCommitmentScheme, KZGParams};
#[cfg(feature = "tree-file")]
use depin_sdk_commitment::tree::file::FileStateTree;
#[cfg(feature = "tree-hashmap")]
use depin_sdk_commitment::tree::hashmap::HashMapStateTree;
#[cfg(feature = "tree-iavl")]
use depin_sdk_commitment::tree::iavl::IAVLTree;
#[cfg(feature = "tree-sparse-merkle")]
use depin_sdk_commitment::tree::sparse_merkle::SparseMerkleTree;
#[cfg(feature = "tree-verkle")]
use depin_sdk_commitment::tree::verkle::VerkleTree;
use depin_sdk_types::config::WorkloadConfig;

#[derive(Parser, Debug)]
struct OrchestrationOpts {
    #[clap(long, help = "Path to the orchestration.toml configuration file.")]
    config: PathBuf,
    #[clap(long, help = "Path to the identity keypair file.")]
    identity_key_file: PathBuf,
    #[clap(long, env = "LISTEN_ADDRESS")]
    listen_address: Multiaddr,
    #[clap(long, env = "BOOTNODE")]
    bootnode: Option<Multiaddr>,
}

/// Runtime check to ensure exactly one state tree feature is enabled.
fn check_features() {
    let mut enabled_features = Vec::new();
    if cfg!(feature = "tree-file") {
        enabled_features.push("tree-file");
    }
    if cfg!(feature = "tree-hashmap") {
        enabled_features.push("tree-hashmap");
    }
    if cfg!(feature = "tree-iavl") {
        enabled_features.push("tree-iavl");
    }
    if cfg!(feature = "tree-sparse-merkle") {
        enabled_features.push("tree-sparse-merkle");
    }
    if cfg!(feature = "tree-verkle") {
        enabled_features.push("tree-verkle");
    }

    if enabled_features.len() != 1 {
        panic!(
            "Error: Please enable exactly one 'tree-*' feature for the depin-sdk-node crate. Found: {:?}",
            enabled_features
        );
    }
}

// Conditionally define a type alias for the optional KZG parameters.
// This allows the run_orchestration function to have a single signature
// that adapts based on compile-time features.
#[cfg(feature = "primitive-kzg")]
type OptionalKzgParams = Option<KZGParams>;
#[cfg(not(feature = "primitive-kzg"))]
type OptionalKzgParams = Option<()>;

/// Generic function containing all logic after component instantiation.
async fn run_orchestration<CS, ST>(
    opts: OrchestrationOpts,
    config: OrchestrationConfig,
    local_key: identity::Keypair,
    state_tree: ST,
    commitment_scheme: CS,
    workload_config: WorkloadConfig,
    kzg_params: OptionalKzgParams,
) -> Result<()>
where
    CS: CommitmentScheme<
            Commitment = <DefaultVerifier as Verifier>::Commitment,
            Proof = <DefaultVerifier as Verifier>::Proof,
        > + Clone
        + Send
        + Sync
        + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + std::fmt::Debug
        + Clone,
    CS::Commitment: std::fmt::Debug + Send + Sync,
    <CS as CommitmentScheme>::Proof:
        serde::Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
{
    let (syncer, swarm_commander, network_event_receiver) =
        Libp2pSync::new(local_key.clone(), opts.listen_address, opts.bootnode)?;

    let consensus_engine = engine_from_config(&config)?;
    let verifier = create_default_verifier(kzg_params);

    let is_quarantined = Arc::new(AtomicBool::new(false));

    let orchestration = Arc::new(OrchestrationContainer::new(
        &opts.config,
        syncer,
        network_event_receiver,
        swarm_commander.clone(),
        consensus_engine,
        local_key,
        is_quarantined.clone(),
        verifier,
    )?);

    let workload_client = {
        let workload_ipc_addr =
            std::env::var("WORKLOAD_IPC_ADDR").unwrap_or_else(|_| "127.0.0.1:8555".to_string());
        Arc::new(WorkloadClient::new(&workload_ipc_addr).await?)
    };

    let guardian_addr = std::env::var("GUARDIAN_ADDR").unwrap_or_default();
    if !guardian_addr.is_empty() {
        let is_quarantined_clone = is_quarantined.clone();
        let workload_client_clone = workload_client.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let guardian_channel = SecurityChannel::new("orchestration", "guardian");
            if let Err(e) = guardian_channel
                .establish_client(&guardian_addr, "guardian")
                .await
            {
                log::error!(
                    "[Orchestration] Failed to connect to Guardian: {}. Quarantining.",
                    e
                );
                is_quarantined_clone.store(true, Ordering::SeqCst);
                return;
            }
            log::info!("[Orchestration] Attestation channel to Guardian established.");

            log::info!("[Orchestrator] Waiting for agentic attestation report from Guardian...");
            match guardian_channel.receive().await {
                Ok(report_bytes) => {
                    let report: Result<Vec<u8>, String> =
                        serde_json::from_slice(&report_bytes).unwrap();
                    match report {
                        Ok(local_hash) => {
                            log::info!(
                                "[Orchestrator] Received local model hash from Guardian: {}",
                                hex::encode(&local_hash)
                            );
                            match workload_client_clone.get_expected_model_hash().await {
                                Ok(expected_hash) => {
                                    if local_hash == expected_hash {
                                        log::info!("[Orchestrator] agentic model hash matches on-chain state. Node is healthy.");
                                    } else {
                                        log::error!("[Orchestrator] Model Integrity Failure! Local hash {} != on-chain hash {}. Quarantining node.", hex::encode(local_hash), hex::encode(expected_hash));
                                        is_quarantined_clone.store(true, Ordering::SeqCst);
                                    }
                                }
                                Err(e) => {
                                    log::error!("[Orchestrator] Failed to get expected model hash from Workload: {}. Quarantining node.", e);
                                    is_quarantined_clone.store(true, Ordering::SeqCst);
                                }
                            }
                        }
                        Err(e) => {
                            log::error!("[Orchestrator] Guardian reported an error during local hashing: {}. Quarantining node.", e);
                            is_quarantined_clone.store(true, Ordering::SeqCst);
                        }
                    }
                }
                Err(e) => {
                    log::error!("[Orchestrator] Failed to receive agentic report from Guardian: {}. Quarantining node.", e);
                    is_quarantined_clone.store(true, Ordering::SeqCst);
                }
            }
        });
    } else {
        log::warn!("GUARDIAN_ADDR not set, skipping Guardian attestation.");
    }

    let chain_ref = {
        let tm = UnifiedTransactionModel::new(commitment_scheme.clone());
        let dummy_workload_config = WorkloadConfig {
            enabled_vms: vec![],
            state_tree: workload_config.state_tree.clone(),
            commitment_scheme: workload_config.commitment_scheme.clone(),
            consensus_type: config.consensus_type,
            genesis_file: "".to_string(),
            state_file: "".to_string(),
            srs_file_path: workload_config.srs_file_path.clone(),
            fuel_costs: Default::default(),
            initial_services: vec![],
        };
        let workload_container = Arc::new(depin_sdk_api::validator::WorkloadContainer::new(
            dummy_workload_config,
            state_tree,
            Box::new(depin_sdk_vm_wasm::WasmVm::new(Default::default())), // dummy VM
            Default::default(),
        ));
        let consensus = engine_from_config(&config)?;
        let chain = Chain::new(
            commitment_scheme,
            tm,
            "dummy-chain",
            vec![],
            Box::new(|_| unimplemented!()),
            consensus,
            workload_container,
        );
        Arc::new(Mutex::new(chain))
    };

    orchestration.set_chain_and_workload_client(chain_ref, workload_client.clone());

    let rpc_handle = run_rpc_server(
        &config.rpc_listen_address,
        orchestration.tx_pool.clone(),
        workload_client,
        swarm_commander,
        config.clone(),
    )
    .await?;

    orchestration.start().await?;

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            log::info!("Ctrl-C received, initiating shutdown.");
        }
    }

    log::info!("Shutdown signal received.");
    orchestration.stop().await?;
    rpc_handle.abort();
    log::info!("Orchestration container stopped gracefully.");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    check_features();
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();
    let opts = OrchestrationOpts::parse();
    log::info!(
        "Orchestration container starting up with config: {:?}",
        opts.config
    );

    let config_path = opts.config.clone();
    let config: OrchestrationConfig = toml::from_str(&fs::read_to_string(&config_path)?)?;
    let local_key = {
        let key_path = &opts.identity_key_file;
        if key_path.exists() {
            let mut bytes = Vec::new();
            fs::File::open(key_path)?.read_to_end(&mut bytes)?;
            identity::Keypair::from_protobuf_encoding(&bytes)?
        } else {
            let keypair = identity::Keypair::generate_ed25519();
            if let Some(parent) = key_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::File::create(key_path)?.write_all(&keypair.to_protobuf_encoding()?)?;
            keypair
        }
    };

    let workload_config_path = opts.config.parent().unwrap().join("workload.toml");
    let workload_config_str = fs::read_to_string(&workload_config_path)?;
    let workload_config: WorkloadConfig = toml::from_str(&workload_config_str)?;

    match (
        workload_config.state_tree.clone(),
        workload_config.commitment_scheme.clone(),
    ) {
        #[cfg(all(feature = "tree-file", feature = "primitive-hash"))]
        (
            depin_sdk_types::config::StateTreeType::File,
            depin_sdk_types::config::CommitmentSchemeType::Hash,
        ) => {
            let state_path = opts
                .config
                .parent()
                .unwrap()
                .join("orchestrator_state.json");
            let scheme = HashCommitmentScheme::new();
            let tree = FileStateTree::new(state_path, scheme.clone());
            run_orchestration(opts, config, local_key, tree, scheme, workload_config, None).await
        }
        #[cfg(all(feature = "tree-hashmap", feature = "primitive-hash"))]
        (
            depin_sdk_types::config::StateTreeType::HashMap,
            depin_sdk_types::config::CommitmentSchemeType::Hash,
        ) => {
            let scheme = HashCommitmentScheme::new();
            let tree = HashMapStateTree::new(scheme.clone());
            run_orchestration(opts, config, local_key, tree, scheme, workload_config, None).await
        }
        #[cfg(all(feature = "tree-iavl", feature = "primitive-hash"))]
        (
            depin_sdk_types::config::StateTreeType::IAVL,
            depin_sdk_types::config::CommitmentSchemeType::Hash,
        ) => {
            let scheme = HashCommitmentScheme::new();
            let tree = IAVLTree::new(scheme.clone());
            run_orchestration(opts, config, local_key, tree, scheme, workload_config, None).await
        }
        #[cfg(all(feature = "tree-sparse-merkle", feature = "primitive-hash"))]
        (
            depin_sdk_types::config::StateTreeType::SparseMerkle,
            depin_sdk_types::config::CommitmentSchemeType::Hash,
        ) => {
            let scheme = HashCommitmentScheme::new();
            let tree = SparseMerkleTree::new(scheme.clone());
            run_orchestration(opts, config, local_key, tree, scheme, workload_config, None).await
        }
        #[cfg(all(feature = "tree-verkle", feature = "primitive-kzg"))]
        (
            depin_sdk_types::config::StateTreeType::Verkle,
            depin_sdk_types::config::CommitmentSchemeType::KZG,
        ) => {
            let params = if let Some(srs_path) = &workload_config.srs_file_path {
                KZGParams::load_from_file(srs_path.as_ref()).map_err(|e| anyhow!(e))?
            } else {
                return Err(anyhow!(
                    "Verkle tree requires an SRS file path in workload.toml"
                ));
            };
            let scheme = KZGCommitmentScheme::new(params.clone());
            let tree = VerkleTree::new(scheme.clone(), 256);
            run_orchestration(
                opts,
                config,
                local_key,
                tree,
                scheme,
                workload_config,
                Some(params),
            )
            .await
        }
        _ => {
            let err_msg = format!("Unsupported or disabled state configuration: StateTree={:?}, CommitmentScheme={:?}.", workload_config.state_tree, workload_config.commitment_scheme);
            Err(anyhow!(err_msg))
        }
    }
}
