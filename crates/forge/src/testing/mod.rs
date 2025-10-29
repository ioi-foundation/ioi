// Path: crates/forge/src/testing/mod.rs

//! Contains helper functions for building and running end-to-end tests.
//! These functions are exposed as a public library to allow users of the
//! SDK to write their own integration tests with the same tooling.

pub mod backend;
pub mod poll;
pub mod rpc;
pub use rpc::submit_transaction;

use crate::testing::poll::{wait_for, wait_for_height};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use backend::{DockerBackend, DockerBackendConfig, LogStream, ProcessBackend, TestBackend};
use bollard::{query_parameters::BuildImageOptionsBuilder, Docker};
use bytes::Bytes;
use depin_sdk_api::crypto::{SerializableKey, SigningKeyPair};
use depin_sdk_client::WorkloadClient;
use depin_sdk_commitment::primitives::kzg::KZGParams;
use depin_sdk_crypto::sign::dilithium::{DilithiumKeyPair, DilithiumScheme};
use depin_sdk_types::config::{
    CommitmentSchemeType, ConsensusType, InitialServiceConfig, OrchestrationConfig, StateTreeType,
    VmFuelCosts, WorkloadConfig,
};
use depin_sdk_validator::common::generate_certificates_if_needed;
use futures_util::{stream::FuturesUnordered, StreamExt};
use http_body_util::{Either, Full};
use libp2p::{identity, Multiaddr, PeerId};
use serde_json::Value;
use std::any::Any;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Once};
use std::time::{Duration, Instant};
use tar::Builder;
use tempfile::TempDir;
use tokio::process::Command as TokioCommand;
use tokio::sync::{broadcast, Mutex, OnceCell};
use tokio::time::timeout;

// --- Test Configuration ---
const DOCKER_IMAGE_TAG: &str = "depin-sdk-node:e2e";
const LOG_ASSERT_TIMEOUT: Duration = Duration::from_secs(45);
const WORKLOAD_READY_TIMEOUT: Duration = Duration::from_secs(30);
const LOG_CHANNEL_CAPACITY: usize = 8192;

// --- One-Time Build ---
static BUILD: Once = Once::new();
static DOCKER_BUILD_CHECK: OnceCell<()> = OnceCell::const_new();

/// Builds test artifacts that are NOT configuration-dependent (like contracts).
pub fn build_test_artifacts() {
    BUILD.call_once(|| {
        println!("--- Building Test Artifacts (one-time setup) ---");

        // Construct the path to the contract relative to the forge crate's manifest directory.
        // This is robust and works regardless of where `cargo test` is invoked from.
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let counter_manifest_path = manifest_dir.join("tests/contracts/counter/Cargo.toml");

        let status_contract = Command::new("cargo")
            .args([
                "build",
                "--manifest-path", // Use --manifest-path instead of -p
                counter_manifest_path
                    .to_str()
                    .expect("Path to counter contract manifest is not valid UTF-8"),
                "--release",
                "--target",
                "wasm32-unknown-unknown",
            ])
            .status()
            .expect("Failed to execute cargo build for counter-contract");

        if !status_contract.success() {
            panic!("Counter contract build failed");
        }

        // The build for `test-service-v2` is removed. It was replaced by `fee-calculator-service`,
        // which is now built just-in-time within the `module_upgrade_e2e.rs` test,
        // making this build step obsolete.

        println!("--- Test Artifacts built successfully ---");
    });
}

/// Infer a correct feature string for `depin-sdk-node` if the caller did not
/// supply one with an explicit `tree-*` feature.
#[allow(dead_code)] // This is a library function for test consumers
fn resolve_node_features(user_supplied: &str) -> String {
    fn has_tree_feature(s: &str) -> bool {
        s.split(',')
            .map(|f| f.trim())
            .any(|f| matches!(f, "tree-iavl" | "tree-sparse-merkle" | "tree-verkle"))
    }

    if !user_supplied.trim().is_empty() && has_tree_feature(user_supplied) {
        return user_supplied.to_string();
    }

    let mut feats: Vec<&'static str> = Vec::new();

    // --- State tree (must be exactly one) ---
    let mut tree_count = 0usize;
    if cfg!(feature = "tree-iavl") {
        feats.push("tree-iavl");
        tree_count += 1;
    }
    if cfg!(feature = "tree-sparse-merkle") {
        feats.push("tree-sparse-merkle");
        tree_count += 1;
    }
    if cfg!(feature = "tree-verkle") {
        feats.push("tree-verkle");
        tree_count += 1;
    }
    if tree_count == 0 {
        panic!("No 'tree-*' feature was provided and none are enabled on depin-sdk-forge. Enable exactly one of: tree-iavl, tree-sparse-merkle, tree-verkle.");
    }
    if tree_count > 1 {
        panic!("Multiple 'tree-*' features are enabled on depin-sdk-forge. Enable exactly one.");
    }

    // --- Commitment primitives ---
    if cfg!(feature = "primitive-hash") {
        feats.push("primitive-hash");
    }
    if cfg!(feature = "primitive-kzg") {
        feats.push("primitive-kzg");
    }

    // --- Consensus engines ---
    if cfg!(feature = "consensus-poa") {
        feats.push("consensus-poa");
    }
    if cfg!(feature = "consensus-pos") {
        feats.push("consensus-pos");
    }
    if cfg!(feature = "consensus-round-robin") {
        feats.push("consensus-round-robin");
    }

    // --- VMs / extras ---
    if cfg!(feature = "vm-wasm") {
        feats.push("vm-wasm");
    }
    if cfg!(feature = "malicious-bin") {
        feats.push("malicious-bin");
    }

    feats.join(",")
}

/// Checks if the test Docker image exists and builds it if it doesn't.
async fn ensure_docker_image_exists() -> Result<()> {
    let docker = Docker::connect_with_local_defaults()?;
    match docker.inspect_image(DOCKER_IMAGE_TAG).await {
        Ok(_) => {
            println!(
                "--- Docker image '{}' found locally. Skipping build. ---",
                DOCKER_IMAGE_TAG
            );
            return Ok(());
        }
        Err(bollard::errors::Error::DockerResponseServerError {
            status_code: 404, ..
        }) => {
            println!(
                "--- Docker image '{}' not found. Building... ---",
                DOCKER_IMAGE_TAG
            );
        }
        Err(e) => return Err(e.into()),
    };

    let context_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let tar_bytes = {
        let mut bytes = Vec::new();
        {
            let mut ar = Builder::new(&mut bytes);
            ar.append_dir_all(".", context_dir)?;
            ar.finish()?;
        }
        bytes
    };
    // bollard expects Into<Either<Full<Bytes>, StreamBody<...>>>.
    // Use a single Full body from the in-memory tar.
    let image_body = Either::Left(Full::new(Bytes::from(tar_bytes)));

    let options = BuildImageOptionsBuilder::default()
        .dockerfile("crates/node/Dockerfile")
        .t(DOCKER_IMAGE_TAG)
        .rm(true)
        .build();

    let mut build_stream = docker.build_image(options, None, Some(image_body));
    while let Some(chunk) = build_stream.next().await {
        match chunk {
            Ok(info) => {
                if let Some(stream_content) = info.stream {
                    print!("{}", stream_content);
                }
                if let Some(err) = info.error {
                    return Err(anyhow!("Image build error: {}", err));
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    println!("--- Docker image built successfully. ---");
    Ok(())
}

// --- Helper Structs & Functions ---

pub async fn assert_log_contains(
    label: &str,
    log_stream: &mut broadcast::Receiver<String>,
    pattern: &str,
) -> Result<()> {
    let start = Instant::now();
    let mut received_lines = Vec::new();

    loop {
        // Manually check overall timeout
        if start.elapsed() > LOG_ASSERT_TIMEOUT {
            let combined_logs = received_lines.join("\n");
            return Err(anyhow!(
                "[{}] Timeout waiting for pattern '{}'.\n--- Received Logs ---\n{}\n--- End Logs ---",
                label,
                pattern,
                combined_logs
            ));
        }

        // Use a short timeout on recv to prevent blocking forever if no new logs arrive
        match timeout(Duration::from_millis(500), log_stream.recv()).await {
            Ok(Ok(line)) => {
                println!("[LOGS-{}] {}", label, line); // Live logging
                received_lines.push(line.clone());
                if line.contains(pattern) {
                    return Ok(());
                }
            }
            Ok(Err(broadcast::error::RecvError::Lagged(count))) => {
                let msg = format!(
                    "[WARN] Log assertion for '{}' may have missed {} lines.",
                    label, count
                );
                println!("{}", &msg);
                received_lines.push(msg);
            }
            Ok(Err(broadcast::error::RecvError::Closed)) => {
                let combined_logs = received_lines.join("\n");
                return Err(anyhow!(
                    "Log stream for '{}' ended before pattern '{}' was found.\n--- Received Logs ---\n{}\n--- End Logs ---",
                    label,
                    pattern,
                    combined_logs
                ));
            }
            Err(_) => {
                // recv timed out, continue outer loop to check overall timeout
                continue;
            }
        }
    }
}

pub async fn assert_log_contains_and_return_line(
    label: &str,
    log_stream: &mut broadcast::Receiver<String>,
    pattern: &str,
) -> Result<String> {
    let start = Instant::now();
    let mut received_lines = Vec::new();

    loop {
        // Manually check overall timeout
        if start.elapsed() > LOG_ASSERT_TIMEOUT {
            let combined_logs = received_lines.join("\n");
            return Err(anyhow!(
                "[{}] Timeout waiting for pattern '{}'.\n--- Received Logs ---\n{}\n--- End Logs ---",
                label,
                pattern,
                combined_logs
            ));
        }

        // Use a short timeout on recv to prevent blocking forever if no new logs arrive
        match timeout(Duration::from_millis(500), log_stream.recv()).await {
            Ok(Ok(line)) => {
                println!("[LOGS-{}] {}", label, line);
                let line_clone = line.clone();
                received_lines.push(line);
                if line_clone.contains(pattern) {
                    return Ok(line_clone);
                }
            }
            Ok(Err(broadcast::error::RecvError::Lagged(count))) => {
                let msg = format!(
                    "[WARN] Log assertion for '{}' may have missed {} lines.",
                    label, count
                );
                println!("{}", &msg);
                received_lines.push(msg);
            }
            Ok(Err(broadcast::error::RecvError::Closed)) => {
                let combined_logs = received_lines.join("\n");
                return Err(anyhow!(
                    "Log stream for '{}' ended before pattern '{}' was found.\n--- Received Logs ---\n{}\n--- End Logs ---",
                    label,
                    pattern,
                    combined_logs
                ));
            }
            Err(_) => {
                // recv timed out, continue outer loop to check overall timeout
                continue;
            }
        }
    }
}

/// Represents a complete, logical validator node, abstracting over its execution backend.
pub struct TestValidator {
    pub keypair: identity::Keypair,
    pub pqc_keypair: Option<DilithiumKeyPair>,
    pub peer_id: PeerId,
    pub rpc_addr: String,
    pub workload_ipc_addr: String,
    pub orchestration_telemetry_addr: String,
    pub workload_telemetry_addr: String,
    pub p2p_addr: Multiaddr,
    pub certs_dir_path: PathBuf,
    _temp_dir: Arc<TempDir>,
    pub backend: Box<dyn TestBackend>,
    orch_log_tx: broadcast::Sender<String>,
    workload_log_tx: broadcast::Sender<String>,
    guardian_log_tx: Option<broadcast::Sender<String>>,
    log_drain_handles: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

struct NullBackend;
#[async_trait]
impl TestBackend for NullBackend {
    async fn launch(&mut self) -> Result<()> {
        Ok(())
    }
    fn get_addresses(&self) -> (String, Multiaddr) {
        ("".into(), "/ip4/127.0.0.1/tcp/0".parse().unwrap())
    }
    fn get_log_streams(&mut self) -> Result<(LogStream, LogStream, Option<LogStream>)> {
        Err(anyhow!("null backend"))
    }
    async fn cleanup(&mut self) -> Result<()> {
        Ok(())
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

impl Drop for TestValidator {
    fn drop(&mut self) {
        // Take ownership of the backend to ensure it's cleaned up.
        let mut backend = std::mem::replace(&mut self.backend, Box::new(NullBackend));
        let handles = self.log_drain_handles.clone();

        let cleanup_future = async move {
            // Abort log draining tasks first to prevent them from interfering.
            for handle in handles.lock().await.iter() {
                handle.abort();
            }
            // Now, cleanup the backend which kills the processes/containers.
            if let Err(e) = backend.cleanup().await {
                // Use eprintln! because logging might not be available during panic unwinding.
                eprintln!("[WARN] Failed to cleanup test validator backend: {}", e);
            }
        };

        // If we are in an async context, spawn the task without blocking.
        // This is the common case when a test finishes without panicking.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(cleanup_future);
        } else {
            // If `try_current()` fails, we are likely in a drop during a panic
            // where the test runtime is being torn down.
            // Create a new, simple runtime just for our cleanup task and BLOCK on it.
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .expect("Failed to create temporary runtime for cleanup");
            rt.block_on(cleanup_future);
        }
    }
}

impl TestValidator {
    /// Subscribes to the non-blocking log streams for this validator's containers.
    ///
    /// This method should be called once at the beginning of a test. The returned
    /// receivers will receive log lines from the moment of subscription. Slow consumption
    /// of these receivers will cause logs to be dropped, but will not block the
    /// underlying validator process.
    pub fn subscribe_logs(
        &self,
    ) -> (
        broadcast::Receiver<String>,
        broadcast::Receiver<String>,
        Option<broadcast::Receiver<String>>,
    ) {
        (
            self.orch_log_tx.subscribe(),
            self.workload_log_tx.subscribe(),
            self.guardian_log_tx.as_ref().map(|tx| tx.subscribe()),
        )
    }

    /// Explicitly shuts down the validator and all its associated resources.
    /// This is the preferred way to tear down a validator in a controlled test,
    /// as it avoids the unpredictable timing of `Drop`.
    pub async fn shutdown(&mut self) -> Result<()> {
        // Abort this validator's log drainers first.
        // This prevents them from holding any resources or panicking during backend cleanup.
        let handles = self.log_drain_handles.lock().await;
        for handle in handles.iter() {
            handle.abort();
        }
        drop(handles); // Release lock

        // Now, trigger the backend cleanup for just this node.
        self.backend.cleanup().await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn launch(
        keypair: identity::Keypair,
        genesis_content: String,
        base_port: u16,
        chain_id: depin_sdk_types::app::ChainId,
        bootnode_addrs: Option<&[Multiaddr]>,
        consensus_type: &str,
        state_tree_type: &str,
        commitment_scheme_type: &str,
        ibc_gateway_addr: Option<&str>,
        agentic_model_path: Option<&str>,
        use_docker: bool,
        initial_services: Vec<InitialServiceConfig>,
        use_malicious_workload: bool,
        light_readiness_check: bool,
        // [+] MODIFIED: Use a generic slice of strings for features
        extra_features: &[String],
    ) -> Result<Self> {
        // --- NEW: Per-validator build step with corrected feature names ---
        let consensus_feature = match consensus_type {
            "ProofOfAuthority" => "consensus-poa",
            "ProofOfStake" => "consensus-pos",
            _ => {
                return Err(anyhow!(
                    "Unsupported test consensus type: {}",
                    consensus_type
                ))
            }
        };
        let tree_feature = match state_tree_type {
            "IAVL" => "tree-iavl",
            "SparseMerkle" => "tree-sparse-merkle",
            "Verkle" => "tree-verkle",
            _ => return Err(anyhow!("Unsupported test state tree: {}", state_tree_type)),
        };
        let primitive_feature = match commitment_scheme_type {
            "Hash" => "primitive-hash",
            "Pedersen" => "primitive-pedersen",
            "KZG" => "primitive-kzg",
            "Lattice" => "primitive-lattice",
            _ => {
                return Err(anyhow!(
                    "Unsupported commitment scheme: {}",
                    commitment_scheme_type
                ))
            }
        };

        // [+] MODIFIED: Dynamically construct the features string.
        let mut features = format!(
            "validator-bins,{},{},{},vm-wasm{}",
            consensus_feature,
            tree_feature,
            primitive_feature,
            if use_malicious_workload {
                ",malicious-bin"
            } else {
                ""
            }
        );

        if !extra_features.is_empty() {
            features.push(',');
            features.push_str(&extra_features.join(","));
        }

        println!("--- Building node binaries with features: {} ---", features);
        let status_node = Command::new("cargo")
            .args([
                "build",
                "-p",
                "depin-sdk-node",
                "--release",
                "--no-default-features",
                "--features",
                &features,
            ])
            .status()
            .expect("Failed to execute cargo build for node");
        if !status_node.success() {
            panic!("Node binary build failed for features: {}", features);
        }
        // --- END MODIFIED BUILD STEP ---

        let peer_id = keypair.public().to_peer_id();
        let temp_dir = Arc::new(tempfile::tempdir()?);
        let certs_dir_path = temp_dir.path().join("certs");
        std::fs::create_dir_all(&certs_dir_path)?;

        let pqc_keypair = Some(
            DilithiumScheme::new(depin_sdk_crypto::security::SecurityLevel::Level2)
                .generate_keypair(),
        )
        .transpose()?; // This handles the Result correctly.

        let p2p_port = portpicker::pick_unused_port().unwrap_or(base_port);
        let rpc_port = portpicker::pick_unused_port().unwrap_or(base_port + 1);
        let p2p_addr_str = format!("/ip4/127.0.0.1/tcp/{}", p2p_port);
        let p2p_addr: Multiaddr = p2p_addr_str.parse()?;
        let rpc_addr = format!("127.0.0.1:{}", rpc_port);

        let keypair_path = temp_dir.path().join("identity.key");
        std::fs::write(&keypair_path, keypair.to_protobuf_encoding()?)?;

        let genesis_path = temp_dir.path().join("genesis.json");
        std::fs::write(&genesis_path, genesis_content)?;

        let config_dir_path = temp_dir.path().to_path_buf();

        // Persist PQC keypair for the orchestrator binary to load.
        let pqc_key_path = config_dir_path.join("pqc_key.json");
        if let Some(kp) = pqc_keypair.as_ref() {
            let pub_hex = hex::encode(SigningKeyPair::public_key(kp).to_bytes());
            let priv_hex = hex::encode(SigningKeyPair::private_key(kp).to_bytes());
            let body = serde_json::json!({ "public": pub_hex, "private": priv_hex }).to_string();
            #[cfg(unix)]
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .mode(0o600)
                    .open(&pqc_key_path)?;
                f.write_all(body.as_bytes())?;
            }
            #[cfg(not(unix))]
            {
                std::fs::write(&pqc_key_path, body)?;
            }
        }

        let consensus_enum = match consensus_type {
            "ProofOfAuthority" => ConsensusType::ProofOfAuthority,
            "ProofOfStake" => ConsensusType::ProofOfStake,
            _ => return Err(anyhow!("Unsupported consensus type: {}", consensus_type)),
        };

        let state_tree_enum = match state_tree_type {
            "IAVL" => StateTreeType::IAVL,
            "SparseMerkle" => StateTreeType::SparseMerkle,
            "Verkle" => StateTreeType::Verkle,
            _ => return Err(anyhow!("Unsupported state tree type: {}", state_tree_type)),
        };

        let commitment_scheme_enum = match commitment_scheme_type {
            "Hash" => CommitmentSchemeType::Hash,
            "Pedersen" => CommitmentSchemeType::Pedersen,
            "KZG" => CommitmentSchemeType::KZG,
            "Lattice" => CommitmentSchemeType::Lattice,
            _ => {
                return Err(anyhow!(
                    "Unsupported commitment scheme: {}",
                    commitment_scheme_type
                ))
            }
        };

        let orch_config_path = config_dir_path.join("orchestration.toml");
        let orchestration_config = OrchestrationConfig {
            chain_id,
            config_schema_version: 0,
            consensus_type: consensus_enum,
            rpc_listen_address: if use_docker {
                "0.0.0.0:9999".to_string()
            } else {
                rpc_addr.clone()
            },
            rpc_hardening: Default::default(),
            initial_sync_timeout_secs: 180, // avoid premature “no peers” timeouts in CI
            block_production_interval_secs: 5,
            round_robin_view_timeout_secs: 20,
            default_query_gas_limit: 1_000_000_000,
            ibc_gateway_listen_address: ibc_gateway_addr.map(String::from),
        };
        std::fs::write(&orch_config_path, toml::to_string(&orchestration_config)?)?;

        let workload_config_path = config_dir_path.join("workload.toml");
        let workload_state_file = temp_dir.path().join("workload_state.json");
        let mut workload_config = WorkloadConfig {
            runtimes: vec!["WASM".to_string()],
            state_tree: state_tree_enum,
            commitment_scheme: commitment_scheme_enum,
            consensus_type: consensus_enum,
            genesis_file: if use_docker {
                "/tmp/test-data/genesis.json".to_string()
            } else {
                genesis_path.to_string_lossy().replace('\\', "/")
            },
            state_file: if use_docker {
                "/tmp/test-data/workload_state.json".to_string()
            } else {
                workload_state_file.to_string_lossy().replace('\\', "/")
            },
            srs_file_path: None,
            fuel_costs: VmFuelCosts::default(),
            initial_services,
            min_finality_depth: 1000,
            keep_recent_heights: 100_000,
            epoch_size: 50_000,
        };

        if state_tree_type == "Verkle" {
            let srs_path = temp_dir.path().join("srs.bin");
            println!("Generating Verkle SRS, this may take a moment...");
            let params = KZGParams::new_insecure_for_testing(12345, 255);
            params.save_to_file(&srs_path).map_err(|e| anyhow!(e))?;
            println!("SRS generation complete.");
            workload_config.srs_file_path = Some(if use_docker {
                "/tmp/test-data/srs.bin".to_string()
            } else {
                srs_path.to_string_lossy().to_string()
            });
        }

        std::fs::write(&workload_config_path, toml::to_string(&workload_config)?)?;

        let guardian_config = r#"signature_policy = "FollowChain""#.to_string();
        std::fs::write(config_dir_path.join("guardian.toml"), guardian_config)?;

        let (orch_log_tx, _) = broadcast::channel(LOG_CHANNEL_CAPACITY);
        let (workload_log_tx, _) = broadcast::channel(LOG_CHANNEL_CAPACITY);
        let (guardian_log_tx, mut guardian_sub) = {
            let (tx, rx) = broadcast::channel(LOG_CHANNEL_CAPACITY);
            (Some(tx), Some(rx))
        };

        let mut log_drain_handles = Vec::new();

        let workload_ipc_addr;
        let orchestration_telemetry_addr;
        let workload_telemetry_addr;

        let mut backend: Box<dyn TestBackend> = if use_docker {
            let docker_config = DockerBackendConfig {
                rpc_addr: rpc_addr.clone(),
                p2p_addr: p2p_addr.clone(),
                agentic_model_path: agentic_model_path.map(PathBuf::from),
                temp_dir: temp_dir.clone(),
                config_dir_path: config_dir_path.clone(),
                certs_dir_path: certs_dir_path.clone(),
            };
            let mut docker_backend = DockerBackend::new(docker_config).await?;
            docker_backend.launch().await?; // Just starts containers
            workload_ipc_addr = "127.0.0.1:8555".to_string();
            orchestration_telemetry_addr = format!("127.0.0.1:{}", rpc_port + 100); // Placeholder
            workload_telemetry_addr = format!("127.0.0.1:{}", rpc_port + 200); // Placeholder
            Box::new(docker_backend)
        } else {
            generate_certificates_if_needed(&certs_dir_path)?;

            let ipc_port_workload = portpicker::pick_unused_port().unwrap_or(base_port + 2);
            let guardian_addr = format!(
                "127.0.0.1:{}",
                portpicker::pick_unused_port().unwrap_or(base_port + 3)
            );
            workload_ipc_addr = format!("127.0.0.1:{}", ipc_port_workload);
            workload_telemetry_addr = format!(
                "127.0.0.1:{}",
                portpicker::pick_unused_port().unwrap_or(base_port + 4)
            );
            orchestration_telemetry_addr = format!(
                "127.0.0.1:{}",
                portpicker::pick_unused_port().unwrap_or(base_port + 5)
            );

            let node_binary_path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("target/release/");

            let mut pb = ProcessBackend::new(
                rpc_addr.clone(),
                p2p_addr.clone(),
                node_binary_path.clone(),
                workload_config_path.clone(),
                workload_ipc_addr.clone(),
                certs_dir_path.clone(),
            );
            pb.orchestration_telemetry_addr = Some(orchestration_telemetry_addr.clone());
            pb.workload_telemetry_addr = Some(workload_telemetry_addr.clone());

            // --- Spawn Guardian ---
            if let Some(model_path) = agentic_model_path {
                let telemetry_addr_guard = format!(
                    "127.0.0.1:{}",
                    portpicker::pick_unused_port().unwrap_or(base_port + 6)
                );
                let process = TokioCommand::new(node_binary_path.join("guardian"))
                    .args([
                        "--config-dir",
                        &config_dir_path.to_string_lossy(),
                        "--agentic-model-path",
                        model_path,
                    ])
                    .env("TELEMETRY_ADDR", &telemetry_addr_guard)
                    .env("GUARDIAN_LISTEN_ADDR", &guardian_addr)
                    .env("CERTS_DIR", certs_dir_path.to_string_lossy().as_ref())
                    .stderr(Stdio::piped())
                    .kill_on_drop(true)
                    .spawn()?;
                pb.guardian_process = Some(process);
            }

            // --- Spawn Workload ---
            let workload_binary_name = if use_malicious_workload {
                "malicious-workload"
            } else {
                "workload"
            };
            let mut workload_cmd = TokioCommand::new(node_binary_path.join(workload_binary_name));
            workload_cmd
                .args(["--config", &workload_config_path.to_string_lossy()])
                .env("TELEMETRY_ADDR", &workload_telemetry_addr)
                .env("IPC_SERVER_ADDR", &workload_ipc_addr)
                .env("CERTS_DIR", certs_dir_path.to_string_lossy().as_ref())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            if agentic_model_path.is_some() {
                workload_cmd.env("GUARDIAN_ADDR", &guardian_addr);
            }
            pb.workload_process = Some(workload_cmd.spawn()?);

            // --- Spawn Orchestration ---
            let mut orch_args = vec![
                "--config".to_string(),
                orch_config_path.to_string_lossy().to_string(),
                "--identity-key-file".to_string(),
                keypair_path.to_string_lossy().to_string(),
                "--listen-address".to_string(),
                p2p_addr_str.clone(),
            ];
            if let Some(addrs) = bootnode_addrs {
                for addr in addrs {
                    orch_args.push("--bootnode".to_string());
                    orch_args.push(addr.to_string());
                }
            }
            if pqc_keypair.is_some() {
                orch_args.push("--pqc-key-file".to_string());
                orch_args.push(pqc_key_path.to_string_lossy().to_string());
            }
            let mut orch_cmd = TokioCommand::new(node_binary_path.join("orchestration"));
            orch_cmd
                .args(&orch_args)
                .env("RUST_BACKTRACE", "1") // Add backtrace for debugging
                .env("TELEMETRY_ADDR", &orchestration_telemetry_addr)
                .env("WORKLOAD_IPC_ADDR", &workload_ipc_addr)
                .env("CERTS_DIR", certs_dir_path.to_string_lossy().as_ref())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            if agentic_model_path.is_some() {
                orch_cmd.env("GUARDIAN_ADDR", &guardian_addr);
            }
            pb.orchestration_process = Some(orch_cmd.spawn()?);

            Box::new(pb)
        };

        // --- START LOG DRAINING AND READINESS CHECKS ---
        let (mut orch_logs, mut workload_logs, guardian_logs_opt) = backend.get_log_streams()?;

        let orch_tx_clone = orch_log_tx.clone();
        log_drain_handles.push(tokio::spawn(async move {
            while let Some(Ok(line)) = orch_logs.next().await {
                let _ = orch_tx_clone.send(line);
            }
        }));

        let work_tx_clone = workload_log_tx.clone();
        log_drain_handles.push(tokio::spawn(async move {
            while let Some(Ok(line)) = workload_logs.next().await {
                let _ = work_tx_clone.send(line);
            }
        }));

        if let (Some(mut guardian_logs), Some(tx)) = (guardian_logs_opt, guardian_log_tx.as_ref()) {
            let tx_clone = tx.clone();
            log_drain_handles.push(tokio::spawn(async move {
                while let Some(Ok(line)) = guardian_logs.next().await {
                    let _ = tx_clone.send(line);
                }
            }));
        }

        let mut orch_sub = orch_log_tx.subscribe();
        let mut workload_sub = workload_log_tx.subscribe();

        if agentic_model_path.is_some() {
            assert_log_contains(
                "Guardian",
                guardian_sub.as_mut().unwrap(),
                &format!("GUARDIAN_IPC_LISTENING_ON_"),
            )
            .await?;
        }

        assert_log_contains(
            "Workload",
            &mut workload_sub,
            &format!("WORKLOAD_IPC_LISTENING_ON_{}", workload_ipc_addr),
        )
        .await?;

        if !use_docker {
            // Only probe genesis for process backend; docker backend has network delays
            let temp_workload_client = WorkloadClient::new(
                &workload_ipc_addr,
                &certs_dir_path.join("ca.pem").to_string_lossy(),
                &certs_dir_path.join("orchestration.pem").to_string_lossy(),
                &certs_dir_path.join("orchestration.key").to_string_lossy(),
            )
            .await?;
            wait_for(
                "workload genesis to be ready",
                Duration::from_millis(250),
                WORKLOAD_READY_TIMEOUT,
                || async {
                    match temp_workload_client.get_genesis_status().await {
                        Ok(status) if status.ready => Ok(Some(())),
                        _ => Ok(None),
                    }
                },
            )
            .await?;
        }

        assert_log_contains(
            "Orchestration",
            &mut orch_sub,
            &format!("ORCHESTRATION_RPC_LISTENING_ON_{}", rpc_addr),
        )
        .await?;

        if !light_readiness_check {
            assert_log_contains(
                "Orchestration",
                &mut orch_sub,
                "ORCHESTRATION_STARTUP_COMPLETE",
            )
            .await?;
        } else {
            log::info!("[Forge] Light readiness check complete. Bypassing wait for startup-complete signal.");
        }

        // --- END READINESS CHECKS ---

        Ok(TestValidator {
            keypair,
            pqc_keypair,
            peer_id,
            rpc_addr,
            workload_ipc_addr,
            orchestration_telemetry_addr,
            workload_telemetry_addr,
            p2p_addr,
            certs_dir_path,
            _temp_dir: temp_dir,
            backend,
            orch_log_tx,
            workload_log_tx,
            guardian_log_tx,
            log_drain_handles: Arc::new(Mutex::new(log_drain_handles)),
        })
    }
}

/// A type alias for a closure that modifies the genesis state.
type GenesisModifier = Box<dyn FnOnce(&mut Value, &Vec<identity::Keypair>) + Send>;

pub struct TestCluster {
    pub validators: Vec<TestValidator>,
    pub genesis_content: String,
}

impl TestCluster {
    pub fn builder() -> TestClusterBuilder {
        TestClusterBuilder::new()
    }
}

pub struct TestClusterBuilder {
    num_validators: usize,
    keypairs: Option<Vec<identity::Keypair>>,
    chain_id: depin_sdk_types::app::ChainId,
    genesis_modifiers: Vec<GenesisModifier>,
    consensus_type: String,
    agentic_model_path: Option<String>,
    use_docker: bool,
    state_tree: String,
    commitment_scheme: String,
    ibc_gateway_addr: Option<String>,
    initial_services: Vec<InitialServiceConfig>,
    use_malicious_workload: bool,
    // [+] MODIFIED: a generic list for extra features
    extra_features: Vec<String>,
}

impl Default for TestClusterBuilder {
    fn default() -> Self {
        Self {
            num_validators: 1,
            keypairs: None,
            chain_id: depin_sdk_types::app::ChainId(1),
            genesis_modifiers: Vec::new(),
            consensus_type: "ProofOfAuthority".to_string(),
            agentic_model_path: None,
            use_docker: false,
            state_tree: "IAVL".to_string(),
            commitment_scheme: "Hash".to_string(),
            ibc_gateway_addr: None,
            initial_services: Vec::new(),
            use_malicious_workload: false,
            // [+] MODIFIED: Initialize the new field
            extra_features: Vec::new(),
        }
    }
}

impl TestClusterBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_validators(mut self, count: usize) -> Self {
        self.num_validators = count;
        self
    }

    pub fn with_keypairs(mut self, keypairs: Vec<identity::Keypair>) -> Self {
        self.num_validators = keypairs.len();
        self.keypairs = Some(keypairs);
        self
    }

    pub fn with_chain_id(mut self, id: u32) -> Self {
        self.chain_id = id.into();
        self
    }

    pub fn with_random_chain_id(mut self) -> Self {
        use rand::Rng;
        self.chain_id = (rand::thread_rng().gen::<u32>() | 1).into(); // Avoid 0
        self
    }

    pub fn use_docker_backend(mut self, use_docker: bool) -> Self {
        self.use_docker = use_docker;
        self
    }

    pub fn with_consensus_type(mut self, consensus: &str) -> Self {
        self.consensus_type = consensus.to_string();
        self
    }

    pub fn with_state_tree(mut self, state: &str) -> Self {
        self.state_tree = state.to_string();
        self
    }

    pub fn with_commitment_scheme(mut self, scheme: &str) -> Self {
        self.commitment_scheme = scheme.to_string();
        self
    }

    pub fn with_agentic_model_path(mut self, path: &str) -> Self {
        self.agentic_model_path = Some(path.to_string());
        self
    }

    pub fn with_ibc_gateway(mut self, addr: &str) -> Self {
        self.ibc_gateway_addr = Some(addr.to_string());
        self
    }

    pub fn with_initial_service(mut self, service_config: InitialServiceConfig) -> Self {
        // [+] MODIFIED: Automatically detect required features.
        if let InitialServiceConfig::Ibc(_) = &service_config {
            if !self.extra_features.contains(&"ibc-deps".to_string()) {
                self.extra_features.push("ibc-deps".to_string());
            }
        }
        self.initial_services.push(service_config);
        self
    }

    pub fn with_malicious_workload(mut self, use_malicious: bool) -> Self {
        self.use_malicious_workload = use_malicious;
        self
    }

    pub fn with_genesis_modifier<F>(mut self, modifier: F) -> Self
    where
        F: FnOnce(&mut Value, &Vec<identity::Keypair>) + Send + 'static,
    {
        self.genesis_modifiers.push(Box::new(modifier));
        self
    }

    pub async fn build(mut self) -> Result<TestCluster> {
        let validator_keys = self.keypairs.take().unwrap_or_else(|| {
            (0..self.num_validators)
                .map(|_| identity::Keypair::generate_ed25519())
                .collect()
        });

        let mut genesis = serde_json::json!({ "genesis_state": {} });
        for modifier in self.genesis_modifiers.drain(..) {
            modifier(&mut genesis, &validator_keys);
        }
        let genesis_content = genesis.to_string();
        let mut validators = Vec::new();

        let mut bootnode_addrs: Vec<Multiaddr> = Vec::new();

        if let Some(boot_key) = validator_keys.first() {
            let bootnode = TestValidator::launch(
                boot_key.clone(),
                genesis_content.clone(),
                5000,
                self.chain_id,
                None, // No bootnode for the bootnode itself
                &self.consensus_type,
                &self.state_tree,
                &self.commitment_scheme,
                self.ibc_gateway_addr.as_deref(),
                self.agentic_model_path.as_deref(),
                self.use_docker,
                self.initial_services.clone(),
                self.use_malicious_workload,
                false, // Full readiness check for the bootnode
                &self.extra_features,
            )
            .await?;

            bootnode_addrs.push(bootnode.p2p_addr.clone());
            validators.push(bootnode);
        }

        if validator_keys.len() > 1 {
            let mut launch_futures = FuturesUnordered::new();
            for (i, key) in validator_keys.iter().enumerate().skip(1) {
                let base_port = 5000 + (i * 100) as u16;
                let captured_bootnodes = bootnode_addrs.clone();
                let captured_chain_id = self.chain_id;
                let captured_genesis = genesis_content.clone();
                let captured_consensus = self.consensus_type.clone();
                let captured_state_tree = self.state_tree.clone();
                let captured_commitment = self.commitment_scheme.clone();
                let captured_agentic_path = self.agentic_model_path.clone();
                let captured_ibc_gateway = self.ibc_gateway_addr.clone();
                let captured_use_docker = self.use_docker;
                let captured_services = self.initial_services.clone();
                let captured_malicious = self.use_malicious_workload;
                let captured_extra_features = self.extra_features.clone();
                let key_clone = key.clone();

                let fut = async move {
                    TestValidator::launch(
                        key_clone,
                        captured_genesis,
                        base_port,
                        captured_chain_id,
                        Some(&captured_bootnodes),
                        &captured_consensus,
                        &captured_state_tree,
                        &captured_commitment,
                        captured_ibc_gateway.as_deref(),
                        captured_agentic_path.as_deref(),
                        captured_use_docker,
                        captured_services,
                        captured_malicious,
                        false, // Full readiness check for subsequent nodes
                        &captured_extra_features,
                    )
                    .await
                };
                launch_futures.push(fut);
            }

            while let Some(result) = launch_futures.next().await {
                validators.push(result?);
            }
        }
        validators.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));

        // Wait for all nodes in the cluster to reach a common height.
        if validators.len() > 1 {
            println!("--- Waiting for cluster to sync to height 2 ---");
            // Wait for each node to see at least height 1, then height 2 overall.
            // This is more robust than just waiting for height 2 on all, as it ensures
            // the genesis block was processed by all before expecting further progress.
            for v in &validators {
                wait_for_height(&v.rpc_addr, 1, Duration::from_secs(30)).await?;
            }
            for v in &validators {
                wait_for_height(&v.rpc_addr, 2, Duration::from_secs(30)).await?;
            }
            println!("--- All nodes synced. Cluster is ready. ---");
        }

        Ok(TestCluster {
            validators,
            genesis_content,
        })
    }
}
