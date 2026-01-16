// Path: crates/node/src/bin/workload.rs
#![forbid(unsafe_code)]

//! The main binary for the Workload container.

use anyhow::{anyhow, Result};
use clap::Parser;
use ioi_api::{
    commitment::CommitmentScheme,
    state::{ProofProvider, StateManager},
};
use ioi_state::primitives::hash::HashCommitmentScheme;
#[cfg(feature = "commitment-kzg")]
use ioi_state::primitives::kzg::{KZGCommitmentScheme, KZGParams};
#[cfg(feature = "state-sparse-merkle")]
use ioi_state::tree::sparse_merkle::SparseMerkleTree;
#[cfg(feature = "state-verkle")]
use ioi_state::tree::verkle::VerkleTree;
// [NEW] Import JMT
#[cfg(feature = "state-jellyfish")]
use ioi_state::tree::jellyfish::JellyfishMerkleTree;
use ioi_storage::metrics as storage_metrics;
use ioi_types::config::WorkloadConfig;
// Import the shared components from the validator library
use ioi_validator::standard::workload::{ipc::WorkloadIpcServer, setup::setup_workload};
use std::fmt::Debug;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser, Debug)]
struct WorkloadOpts {
    #[clap(long, help = "Path to the workload.toml configuration file.")]
    config: PathBuf,
}

/// Thin wrapper to invoke shared setup and run the standard IPC server.
async fn run_standard_workload<CS, ST>(
    state_tree: ST,
    commitment_scheme: CS,
    config: WorkloadConfig,
) -> Result<()>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + ProofProvider
        + Send
        + Sync
        + 'static
        + Clone
        + Debug,
    CS::Value: From<Vec<u8>> + AsRef<[u8]> + Send + Sync + Debug,
    CS::Proof: serde::Serialize + for<'de> serde::Deserialize<'de> + AsRef<[u8]> + Debug + Clone,
    CS::Commitment: Debug + From<Vec<u8>>,
{
    // 1. Run Shared Initialization
    // [FIX] Pass None for GUI, Browser drivers, SCS, event_sender, AND os_driver.
    // The standalone workload binary does not support local UI event streaming or OS policy enforcement.
    let (workload_container, machine_arc) =
        setup_workload(
            state_tree, 
            commitment_scheme, 
            config, 
            None, 
            None, 
            None, 
            None,
            None // [FIX] Passed None for os_driver
        ).await?;

    // 2. Start the Standard IPC Server
    // The IPC server now internally handles both Legacy JSON-RPC and the new gRPC Data Plane
    let ipc_server_addr =
        std::env::var("IPC_SERVER_ADDR").unwrap_or_else(|_| "0.0.0.0:8555".to_string());

    let ipc_server: WorkloadIpcServer<ST, CS> =
        WorkloadIpcServer::new(ipc_server_addr, workload_container, machine_arc).await?;

    tracing::info!(target: "workload", "Standard Workload initialized. Running Hybrid IPC server.");
    ipc_server.run().await?;
    Ok(())
}

fn check_features() {
    let mut enabled_features = Vec::new();
    if cfg!(feature = "state-iavl") {
        enabled_features.push("state-iavl");
    }
    if cfg!(feature = "state-sparse-merkle") {
        enabled_features.push("state-sparse-merkle");
    }
    if cfg!(feature = "state-verkle") {
        enabled_features.push("state-verkle");
    }
    if cfg!(feature = "state-jellyfish") {
        enabled_features.push("state-jellyfish");
    }

    if enabled_features.len() != 1 {
        panic!(
            "Error: Please enable exactly one 'tree-*' feature for the ioi-node crate. Found: {:?}",
            enabled_features
        );
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // [FIX] Install default crypto provider for rustls 0.23+
    let _ = rustls::crypto::ring::default_provider().install_default();

    ioi_telemetry::init::init_tracing()?;
    let metrics_sink = ioi_telemetry::prometheus::install()?;
    storage_metrics::SINK
        .set(metrics_sink)
        .expect("SINK must only be set once");

    let telemetry_addr_str =
        std::env::var("TELEMETRY_ADDR").unwrap_or_else(|_| "127.0.0.1:9616".to_string());
    let telemetry_addr = telemetry_addr_str.parse()?;
    tokio::spawn(ioi_telemetry::http::run_server(telemetry_addr));

    check_features();

    let opts = WorkloadOpts::parse();
    tracing::info!(
        target: "workload",
        event = "startup",
        config = ?opts.config
    );

    let config_str = fs::read_to_string(&opts.config)?;
    let config: WorkloadConfig = toml::from_str(&config_str)?;
    config.validate().map_err(|e| anyhow!(e))?;

    match (config.state_tree.clone(), config.commitment_scheme.clone()) {
        #[cfg(all(feature = "state-iavl", feature = "commitment-hash"))]
        (ioi_types::config::StateTreeType::IAVL, ioi_types::config::CommitmentSchemeType::Hash) => {
            tracing::info!(target: "workload", "Instantiating state backend: IAVLTree<HashCommitmentScheme>");
            use ioi_state::tree::iavl::IAVLTree;
            let commitment_scheme = HashCommitmentScheme::new();
            let state_tree = IAVLTree::new(commitment_scheme.clone());
            run_standard_workload(state_tree, commitment_scheme, config).await
        }

        #[cfg(all(feature = "state-sparse-merkle", feature = "commitment-hash"))]
        (
            ioi_types::config::StateTreeType::SparseMerkle,
            ioi_types::config::CommitmentSchemeType::Hash,
        ) => {
            tracing::info!(target: "workload", "Instantiating state backend: SparseMerkleTree<HashCommitmentScheme>");
            let commitment_scheme = ioi_state::primitives::hash::HashCommitmentScheme::new();
            let state_tree =
                ioi_state::tree::sparse_merkle::SparseMerkleTree::new(commitment_scheme.clone());
            run_standard_workload(state_tree, commitment_scheme, config).await
        }

        #[cfg(all(feature = "state-verkle", feature = "commitment-kzg"))]
        (
            ioi_types::config::StateTreeType::Verkle,
            ioi_types::config::CommitmentSchemeType::KZG,
        ) => {
            tracing::info!(target: "workload", "Instantiating state backend: VerkleTree<KZGCommitmentScheme>");

            // The config.validate() call ensures srs_file_path is Some.
            let srs_path = config
                .srs_file_path
                .as_ref()
                .expect("SRS file path validated");

            tracing::info!(target: "workload", "Loading KZG SRS from file: {}", srs_path);
            let params = ioi_state::primitives::kzg::KZGParams::load_from_file(
                std::path::Path::new(srs_path),
            )
            .map_err(|e| anyhow!(e))?;

            let commitment_scheme = ioi_state::primitives::kzg::KZGCommitmentScheme::new(params);
            let state_tree =
                ioi_state::tree::verkle::VerkleTree::new(commitment_scheme.clone(), 256)
                    .map_err(|e| anyhow!(e))?;
            run_standard_workload(state_tree, commitment_scheme, config).await
        }

        #[cfg(all(feature = "state-jellyfish", feature = "commitment-hash"))]
        (
            ioi_types::config::StateTreeType::Jellyfish,
            ioi_types::config::CommitmentSchemeType::Hash,
        ) => {
            tracing::info!(target: "workload", "Instantiating state backend: JellyfishMerkleTree<HashCommitmentScheme>");
            let commitment_scheme = HashCommitmentScheme::new();
            let state_tree = JellyfishMerkleTree::new(commitment_scheme.clone());
            run_standard_workload(state_tree, commitment_scheme, config).await
        }

        _ => {
            let err_msg = format!(
                "Unsupported or disabled state configuration: StateTree={:?}, CommitmentScheme={:?}. Please check your config and compile-time features.",
                config.state_tree, config.commitment_scheme
            );
            tracing::error!(target: "workload", "{}", err_msg);
            Err(anyhow!(err_msg))
        }
    }
}