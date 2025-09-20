// Path: crates/forge/src/testing/mod.rs

//! Contains helper functions for building and running end-to-end tests.
//! These functions are exposed as a public library to allow users of the
//! SDK to write their own integration tests with the same tooling.

pub mod backend;
pub mod poll;
pub mod rpc;

use crate::testing::poll::{wait_for, wait_for_height};
use anyhow::{anyhow, Result};
use backend::{DockerBackend, DockerBackendConfig, LogStream, ProcessBackend, TestBackend};
use bollard::image::BuildImageOptions;
use bollard::Docker;
use depin_sdk_api::crypto::{SerializableKey, SigningKeyPair};
use depin_sdk_client::WorkloadClient;
use depin_sdk_commitment::primitives::kzg::KZGParams;
use depin_sdk_crypto::sign::dilithium::{DilithiumKeyPair, DilithiumScheme};
use depin_sdk_types::app::ChainTransaction;
use depin_sdk_types::config::{
    CommitmentSchemeType, ConsensusType, InitialServiceConfig, StateTreeType, VmFuelCosts,
    WorkloadConfig,
};
// [+] FIX: Import the certificate generation utility.
use depin_sdk_validator::common::generate_certificates_if_needed;
use depin_sdk_validator::config::OrchestrationConfig;
use futures_util::{stream::FuturesUnordered, StreamExt};
use hyper::Body;
use libp2p::{identity, Multiaddr, PeerId};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Once};
use std::time::Duration;
use tar::Builder;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command as TokioCommand;
// --- FIX START (Analysis 2): Add broadcast for non-blocking logs ---
use tokio::sync::{broadcast, Mutex, OnceCell};
// --- FIX END ---
use tokio::time::timeout;

// --- Test Configuration ---
const DOCKER_IMAGE_TAG: &str = "depin-sdk-node:e2e";
const LOG_ASSERT_TIMEOUT: Duration = Duration::from_secs(45);
const WORKLOAD_READY_TIMEOUT: Duration = Duration::from_secs(30);
const ORCHESTRATION_READY_TIMEOUT: Duration = Duration::from_secs(30);
const GUARDIAN_READY_TIMEOUT: Duration = Duration::from_secs(10);
// --- FIX START (Analysis 2): Define channel capacity for logs ---
const LOG_CHANNEL_CAPACITY: usize = 8192;
// --- FIX END ---

// --- One-Time Build ---
static BUILD: Once = Once::new();
static DOCKER_BUILD_CHECK: OnceCell<()> = OnceCell::const_new();

/// Builds all required binaries for testing (node, contracts) exactly once.
pub fn build_test_artifacts(node_features: &str) {
    BUILD.call_once(|| {
        println!("--- Building Test Artifacts (one-time setup) ---");
        // Build the node with an explicit, deterministic feature set.
        let resolved_features = resolve_node_features(node_features);
        println!(
            "--- Building node binaries with features: {} ---",
            resolved_features
        );

        let status_node = Command::new("cargo")
            .args([
                "build",
                "-p",
                "depin-sdk-node",
                "--release",
                "--no-default-features",
                "--features",
                &format!("validator-bins,{}", resolved_features),
            ])
            .status()
            .expect("Failed to execute cargo build for node");
        if !status_node.success() {
            panic!("Node binary build failed");
        }

        let status_contract = Command::new("cargo")
            .args([
                "build",
                "-p",
                "counter-contract",
                "--release",
                "--target",
                "wasm32-unknown-unknown",
            ])
            .status()
            .expect("Failed to execute cargo build for counter-contract");
        if !status_contract.success() {
            panic!("Counter contract build failed");
        }

        let status_service = Command::new("cargo")
            .args([
                "build",
                "-p",
                "test-service-v2",
                "--release",
                "--target",
                "wasm32-unknown-unknown",
            ])
            .status()
            .expect("Failed to execute cargo build for test-service-v2");
        if !status_service.success() {
            panic!("Test service contract build failed");
        }

        println!("--- Test Artifacts built successfully ---");
    });
}

/// Infer a correct feature string for `depin-sdk-node` if the caller did not
/// supply one with an explicit `tree-*` feature.
fn resolve_node_features(user_supplied: &str) -> String {
    fn has_tree_feature(s: &str) -> bool {
        s.split(',').map(|f| f.trim()).any(|f| {
            matches!(
                f,
                "tree-file" | "tree-hashmap" | "tree-iavl" | "tree-sparse-merkle" | "tree-verkle"
            )
        })
    }

    if !user_supplied.trim().is_empty() && has_tree_feature(user_supplied) {
        return user_supplied.to_string();
    }

    let mut feats: Vec<&'static str> = Vec::new();

    // --- State tree (must be exactly one) ---
    let mut tree_count = 0usize;
    if cfg!(feature = "tree-file") {
        feats.push("tree-file");
        tree_count += 1;
    }
    if cfg!(feature = "tree-hashmap") {
        feats.push("tree-hashmap");
        tree_count += 1;
    }
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
        panic!("No 'tree-*' feature was provided and none are enabled on depin-sdk-forge. Enable exactly one of: tree-file, tree-hashmap, tree-iavl, tree-sparse-merkle, tree-verkle.");
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
    let image_body = Body::from(tar_bytes);

    let options = BuildImageOptions {
        dockerfile: "crates/node/Dockerfile",
        t: DOCKER_IMAGE_TAG,
        rm: true,
        ..Default::default()
    };

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

pub async fn submit_transaction(rpc_addr: &str, tx: &ChainTransaction) -> Result<()> {
    let tx_hex = hex::encode(serde_json::to_vec(tx)?);
    let url = format!("http://{}/rpc", rpc_addr);
    let client = reqwest::Client::new();

    // candidates: method names & param shapes
    let candidates = [
        ("submit_tx", serde_json::json!([tx_hex.clone()])),
        ("tx.submit.v1", serde_json::json!([tx_hex.clone()])),
        ("transaction.submit.v1", serde_json::json!([tx_hex.clone()])),
        ("tx.submit.v1", serde_json::json!({ "tx": tx_hex.clone() })),
        ("transaction.submit.v1", serde_json::json!({ "tx": tx_hex })),
    ];

    for (method, params) in candidates {
        let req =
            serde_json::json!({ "jsonrpc":"2.0", "method": method, "params": params, "id": 1 });
        let resp = client.post(&url).json(&req).send().await?;
        let text = resp.text().await?;
        // Parse but also keep the raw for diagnostics
        let v: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);

        // explicit JSON-RPC error -> fail fast with context
        if v.get("error").is_some() && !v["error"].is_null() {
            return Err(anyhow!("RPC {} error: {}", method, v["error"]));
        }

        // success heuristics
        let ok = match &v["result"] {
            serde_json::Value::String(s) => {
                s.eq_ignore_ascii_case("ok")
                    || s.eq_ignore_ascii_case("submitted")
                    || s.eq_ignore_ascii_case("transaction accepted")
            }
            serde_json::Value::Bool(b) => *b,
            serde_json::Value::Object(m) => {
                m.get("accepted").and_then(|v| v.as_bool()).unwrap_or(false)
            }
            _ => false,
        };

        if ok {
            println!("submit_transaction: {} accepted -> {}", method, text);
            return Ok(());
        } else {
            println!("submit_transaction: {} returned non-OK -> {}", method, text);
        }
    }

    Err(anyhow!(
        "No RPC submit variant accepted the tx; see logs above for raw responses"
    ))
}

// --- FIX START (Analysis 2): Update assert helpers to use non-blocking broadcast receiver ---
pub async fn assert_log_contains(
    label: &str,
    log_stream: &mut broadcast::Receiver<String>,
    pattern: &str,
) -> Result<()> {
    timeout(LOG_ASSERT_TIMEOUT, async {
        loop {
            match log_stream.recv().await {
                Ok(line) => {
                    println!("[LOGS-{}] {}", label, line);
                    if line.contains(pattern) {
                        return Ok(());
                    }
                }
                Err(broadcast::error::RecvError::Lagged(count)) => {
                    log::warn!(
                        "[{}] Log assertion may have missed {} lines due to backpressure.",
                        label,
                        count
                    );
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => {
                    return Err(anyhow!("Log stream ended before pattern was found"));
                }
            }
        }
    })
    .await?
    .map_err(|e| {
        anyhow!(
            "[{}] Log assertion failed for pattern '{}': {}",
            label,
            pattern,
            e
        )
    })
}

pub async fn assert_log_contains_and_return_line(
    label: &str,
    log_stream: &mut broadcast::Receiver<String>,
    pattern: &str,
) -> Result<String> {
    timeout(LOG_ASSERT_TIMEOUT, async {
        loop {
            match log_stream.recv().await {
                Ok(line) => {
                    println!("[LOGS-{}] {}", label, line);
                    if line.contains(pattern) {
                        return Ok(line);
                    }
                }
                Err(broadcast::error::RecvError::Lagged(count)) => {
                    log::warn!(
                        "[{}] Log assertion may have missed {} lines due to backpressure.",
                        label,
                        count
                    );
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => {
                    return Err(anyhow!("Log stream ended before pattern was found"));
                }
            }
        }
    })
    .await?
    .map_err(|e| {
        anyhow!(
            "[{}] Log assertion failed for pattern '{}': {}",
            label,
            pattern,
            e
        )
    })
}
// --- FIX END ---

/// Represents a complete, logical validator node, abstracting over its execution backend.
pub struct TestValidator {
    pub keypair: identity::Keypair,
    pub pqc_keypair: Option<DilithiumKeyPair>,
    pub peer_id: PeerId,
    pub rpc_addr: String,
    pub workload_ipc_addr: String,
    pub p2p_addr: Multiaddr,
    pub certs_dir_path: PathBuf,
    _temp_dir: Arc<TempDir>,
    backend: Box<dyn TestBackend>,
    // --- FIX START (Analysis 2): Store Senders, not streams, and add a join handle for drainers ---
    orch_log_tx: broadcast::Sender<String>,
    workload_log_tx: broadcast::Sender<String>,
    guardian_log_tx: Option<broadcast::Sender<String>>,
    log_drain_handles: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    // --- FIX END ---
}

impl Drop for TestValidator {
    fn drop(&mut self) {
        let mut backend = std::mem::replace(&mut self.backend, Box::new(NullBackend));
        // --- FIX START (Analysis 2): Abort log drainers on drop ---
        let handles = self.log_drain_handles.clone();
        tokio::spawn(async move {
            for handle in handles.lock().await.iter() {
                handle.abort();
            }
            if let Err(e) = backend.cleanup().await {
                log::error!("Failed to cleanup test validator backend: {}", e);
            }
        });
        // --- FIX END ---
    }
}

struct NullBackend;
#[async_trait::async_trait]
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
}

impl TestValidator {
    // --- FIX START (Analysis 2): Add method to get log receivers ---
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
    // --- FIX END ---

    #[allow(clippy::too_many_arguments)]
    pub async fn launch(
        keypair: identity::Keypair,
        genesis_content: String,
        base_port: u16,
        bootnode_addr: Option<&Multiaddr>,
        consensus_type: &str,
        state_tree_type: &str,
        commitment_scheme_type: &str,
        agentic_model_path: Option<&str>,
        use_docker: bool,
        initial_services: Vec<InitialServiceConfig>,
        use_malicious_workload: bool,
    ) -> Result<Self> {
        let peer_id = keypair.public().to_peer_id();
        let temp_dir = Arc::new(tempfile::tempdir()?);
        // [+] FIX: Create a dedicated subdir for certs to keep the temp dir clean.
        let certs_dir_path = temp_dir.path().join("certs");
        std::fs::create_dir_all(&certs_dir_path)?;

        let pqc_keypair = Some(
            DilithiumScheme::new(depin_sdk_crypto::security::SecurityLevel::Level2)
                .generate_keypair(),
        );

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
            "File" => StateTreeType::File,
            "HashMap" => StateTreeType::HashMap,
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
            consensus_type: consensus_enum,
            rpc_listen_address: if use_docker {
                "0.0.0.0:9999".to_string()
            } else {
                rpc_addr.clone()
            },
            initial_sync_timeout_secs: 2,
            block_production_interval_secs: 5,
            round_robin_view_timeout_secs: 20,
            default_query_gas_limit: 1_000_000_000,
        };
        std::fs::write(&orch_config_path, toml::to_string(&orchestration_config)?)?;

        let workload_config_path = config_dir_path.join("workload.toml");
        let workload_state_file = temp_dir.path().join("workload_state.json");
        let mut workload_config = WorkloadConfig {
            enabled_vms: vec!["WASM".to_string()],
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

        let workload_ipc_addr;
        let mut backend: Box<dyn TestBackend> = if use_docker {
            let docker_config = DockerBackendConfig {
                rpc_addr: rpc_addr.clone(),
                p2p_addr: p2p_addr.clone(),
                agentic_model_path: agentic_model_path.map(PathBuf::from),
                temp_dir: temp_dir.clone(),
                config_dir_path: config_dir_path.clone(),
                certs_dir_path: certs_dir_path.clone(),
            };
            let docker_backend = DockerBackend::new(docker_config).await?;
            workload_ipc_addr = "127.0.0.1:8555".to_string(); // Placeholder for Docker
            Box::new(docker_backend)
        } else {
            // [+] FIX: Generate certificates for process-based backend.
            generate_certificates_if_needed(&certs_dir_path)?;

            let ipc_port_workload = portpicker::pick_unused_port().unwrap_or(base_port + 2);
            let guardian_addr = format!(
                "127.0.0.1:{}",
                portpicker::pick_unused_port().unwrap_or(base_port + 3)
            );
            workload_ipc_addr = format!("127.0.0.1:{}", ipc_port_workload);
            let node_binary_path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("target/release/");

            let (guardian_process, mut guardian_reader) =
                if let Some(model_path) = agentic_model_path {
                    let mut process = TokioCommand::new(node_binary_path.join("guardian"))
                        .args([
                            "--config-dir",
                            &config_dir_path.to_string_lossy(),
                            "--agentic-model-path",
                            model_path,
                        ])
                        .env("GUARDIAN_LISTEN_ADDR", &guardian_addr)
                        // [+] FIX: Provide certs dir to Guardian.
                        .env("CERTS_DIR", certs_dir_path.to_string_lossy().as_ref())
                        .stderr(Stdio::piped())
                        .kill_on_drop(true)
                        .spawn()?;
                    let mut reader = BufReader::new(process.stderr.take().unwrap()).lines();

                    let ready_signal = format!("GUARDIAN_IPC_LISTENING_ON_{}", guardian_addr);
                    timeout(GUARDIAN_READY_TIMEOUT, async {
                        while let Some(line) = reader.next_line().await? {
                            println!("[GUARDIAN-BOOT] {}", line); // Debug print
                            if line.contains(&ready_signal) {
                                return Ok(());
                            }
                        }
                        Err(anyhow!("Guardian stream ended before ready signal"))
                    })
                    .await??;
                    (Some(process), Some(reader))
                } else {
                    (None, None)
                };

            let workload_binary_name = if use_malicious_workload {
                "malicious-workload"
            } else {
                "workload"
            };

            let mut workload_cmd = TokioCommand::new(node_binary_path.join(workload_binary_name));
            workload_cmd
                .args(["--config", &workload_config_path.to_string_lossy()])
                .env("IPC_SERVER_ADDR", &workload_ipc_addr)
                // [+] FIX: Provide certs dir to Workload.
                .env("CERTS_DIR", certs_dir_path.to_string_lossy().as_ref())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            if agentic_model_path.is_some() {
                workload_cmd.env("GUARDIAN_ADDR", &guardian_addr);
            }

            let mut workload_process = workload_cmd.spawn()?;
            let mut workload_reader =
                BufReader::new(workload_process.stderr.take().unwrap()).lines();

            // STEP 1: Wait for the IPC server to come online.
            timeout(WORKLOAD_READY_TIMEOUT, async {
                let ready_signal = format!("WORKLOAD_IPC_LISTENING_ON_{}", workload_ipc_addr);
                while let Some(line) = workload_reader.next_line().await? {
                    println!("[WORKLOAD-BOOT] {}", line);
                    if line.contains(&ready_signal) {
                        return Ok(());
                    }
                }
                Err(anyhow!(
                    "Workload stderr stream ended before IPC ready signal."
                ))
            })
            .await??;

            // STEP 2: Create a client and poll for genesis readiness via RPC.
            // [+] FIX: Provide certificate paths to the client constructor.
            let temp_workload_client = WorkloadClient::new(
                &workload_ipc_addr,
                &certs_dir_path.join("ca.pem").to_string_lossy(),
                &certs_dir_path.join("orchestration.pem").to_string_lossy(),
                &certs_dir_path.join("orchestration.key").to_string_lossy(),
            )
            .await?;
            let genesis_status = wait_for(
                "workload genesis to be ready",
                Duration::from_millis(250),
                WORKLOAD_READY_TIMEOUT,
                || async {
                    match temp_workload_client.get_genesis_status().await {
                        Ok(status) if status.ready => Ok(Some(status)),
                        _ => Ok(None),
                    }
                },
            )
            .await?;
            let _captured_root = genesis_status.root;

            // STEP 3: Now that Workload is fully ready, launch Orchestration.
            let mut orch_args = vec![
                "--config".to_string(),
                orch_config_path.to_string_lossy().to_string(),
                "--identity-key-file".to_string(),
                keypair_path.to_string_lossy().to_string(),
                "--listen-address".to_string(),
                p2p_addr_str.clone(),
            ];
            if let Some(addr) = bootnode_addr {
                orch_args.push("--bootnode".to_string());
                orch_args.push(addr.to_string());
            }
            // Add the PQC key file argument if a PQC key exists.
            if pqc_keypair.is_some() {
                orch_args.push("--pqc-key-file".to_string());
                orch_args.push(pqc_key_path.to_string_lossy().to_string());
            }
            let mut orch_cmd = TokioCommand::new(node_binary_path.join("orchestration"));
            orch_cmd
                .args(&orch_args)
                .env("RUST_BACKTRACE", "1") // Add backtrace for debugging
                .env("WORKLOAD_IPC_ADDR", &workload_ipc_addr)
                // [+] FIX: Provide certs dir to Orchestration.
                .env("CERTS_DIR", certs_dir_path.to_string_lossy().as_ref())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            if agentic_model_path.is_some() {
                orch_cmd.env("GUARDIAN_ADDR", &guardian_addr);
            }

            let mut orchestration_process = orch_cmd.spawn()?;
            let mut orch_reader =
                BufReader::new(orchestration_process.stderr.take().unwrap()).lines();
            let rpc_signal = format!("ORCHESTRATION_RPC_LISTENING_ON_{}", rpc_addr);

            // STAGE 1: Wait for RPC to be ready or process to exit.
            let ready_result = tokio::select! {
                res = timeout(ORCHESTRATION_READY_TIMEOUT, async {
                    while let Some(line) = orch_reader.next_line().await? {
                        println!("[ORCH-BOOT] {}", line); // Live log
                        if line.contains(&rpc_signal) { return Ok::<_, anyhow::Error>(()); }
                    }
                    Err(anyhow!("Orchestration stderr ended before ready signal"))
                }) => res,
                status = orchestration_process.wait() => {
                    let st = status?;
                    Err(anyhow!("Orchestration process exited early with status: {}", st))?
                }
            };

            // Fallback probe if we timed out on logs but process is alive
            if let Err(e) = ready_result {
                log::warn!(
                    "Orchestration readiness log not found (reason: {}), attempting RPC probe.",
                    e
                );
                let probe_url = format!("http://{}/rpc", rpc_addr);
                let client = reqwest::Client::new();
                let probe_ok = client
                    .post(&probe_url)
                    .json(&serde_json::json!({"jsonrpc":"2.0","method":"unknown","id":1}))
                    .send()
                    .await
                    .map(|r| r.status().is_success())
                    .unwrap_or(false);

                if !probe_ok {
                    return Err(anyhow!(
                        "Orchestration readiness timed out and RPC probe failed at {}",
                        rpc_addr
                    ));
                }
                log::warn!("Orchestration readiness log not found, but RPC probe succeeded.");
            }

            // STAGE 2: Wait for full startup complete signal or process exit.
            let started_signal = "ORCHESTRATION_STARTUP_COMPLETE";
            let started_result = tokio::select! {
                res = timeout(Duration::from_secs(20), async {
                    while let Some(line) = orch_reader.next_line().await? {
                        println!("[ORCH-BOOT] {}", line); // Live log
                        if line.contains(started_signal) { return Ok::<_, anyhow::Error>(()); }
                    }
                    Err(anyhow!("Orchestration stderr ended before startup-complete signal"))
                }) => res,
                status = orchestration_process.wait() => {
                    let st = status?;
                    Err(anyhow!("Orchestration process exited early with status: {}", st))?
                }
            };
            if let Err(e) = started_result {
                return Err(anyhow!(
                    "Orchestration failed to reach startup-complete: {}",
                    e
                ));
            }

            let mut pb = ProcessBackend::new(rpc_addr.clone(), p2p_addr.clone());
            pb.orchestration_process = Some(orchestration_process);
            pb.workload_process = Some(workload_process);
            pb.guardian_process = guardian_process;
            pb.orchestration_process.as_mut().unwrap().stderr =
                Some(orch_reader.into_inner().into_inner());
            pb.workload_process.as_mut().unwrap().stderr =
                Some(workload_reader.into_inner().into_inner());
            if let (Some(g), Some(gr)) = (pb.guardian_process.as_mut(), guardian_reader.take()) {
                g.stderr = Some(gr.into_inner().into_inner());
            }
            Box::new(pb)
        };

        backend.launch().await?;
        let (rpc_addr, p2p_addr) = backend.get_addresses();
        let (mut orch_logs, mut workload_logs, guardian_logs_opt) = backend.get_log_streams()?;

        // --- FIX START (Analysis 2): Spawn non-blocking log drainers ---
        let mut log_drain_handles = Vec::new();
        let (orch_log_tx, _) = broadcast::channel(LOG_CHANNEL_CAPACITY);
        let (workload_log_tx, _) = broadcast::channel(LOG_CHANNEL_CAPACITY);

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

        let guardian_log_tx = if let Some(mut guardian_logs) = guardian_logs_opt {
            let (tx, _) = broadcast::channel(LOG_CHANNEL_CAPACITY);
            let tx_clone = tx.clone();
            log_drain_handles.push(tokio::spawn(async move {
                while let Some(Ok(line)) = guardian_logs.next().await {
                    let _ = tx_clone.send(line);
                }
            }));
            Some(tx)
        } else {
            None
        };
        // --- FIX END ---

        Ok(TestValidator {
            keypair,
            pqc_keypair,
            peer_id,
            rpc_addr,
            workload_ipc_addr,
            p2p_addr,
            certs_dir_path,
            _temp_dir: temp_dir,
            backend,
            // --- FIX START (Analysis 2): Store senders and handles ---
            orch_log_tx,
            workload_log_tx,
            guardian_log_tx,
            log_drain_handles: Arc::new(Mutex::new(log_drain_handles)),
            // --- FIX END ---
        })
    }
}

pub struct TestCluster {
    pub validators: Vec<TestValidator>,
    pub genesis_content: String,
}

impl TestCluster {
    pub fn builder() -> TestClusterBuilder {
        TestClusterBuilder::new()
    }
}

/// A type alias for a closure that modifies the genesis state.
type GenesisModifier = Box<dyn FnOnce(&mut Value, &Vec<identity::Keypair>) + Send>;

pub struct TestClusterBuilder {
    num_validators: usize,
    keypairs: Option<Vec<identity::Keypair>>,
    genesis_modifiers: Vec<GenesisModifier>,
    consensus_type: String,
    agentic_model_path: Option<String>,
    use_docker: bool,
    state_tree: String,
    commitment_scheme: String,
    initial_services: Vec<InitialServiceConfig>,
    use_malicious_workload: bool,
}

impl Default for TestClusterBuilder {
    fn default() -> Self {
        Self {
            num_validators: 1,
            keypairs: None,
            genesis_modifiers: Vec::new(),
            consensus_type: "ProofOfAuthority".to_string(),
            agentic_model_path: None,
            use_docker: false,
            state_tree: "IAVL".to_string(),
            commitment_scheme: "Hash".to_string(),
            initial_services: Vec::new(),
            use_malicious_workload: false,
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

    pub fn with_initial_service(mut self, service_config: InitialServiceConfig) -> Self {
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

        let mut bootnode_addr: Option<Multiaddr> = None;

        if let Some(boot_key) = validator_keys.first() {
            let bootnode = TestValidator::launch(
                boot_key.clone(),
                genesis_content.clone(),
                5000,
                None, // No bootnode for the bootnode itself
                &self.consensus_type,
                &self.state_tree,
                &self.commitment_scheme,
                self.agentic_model_path.as_deref(),
                self.use_docker,
                self.initial_services.clone(),
                self.use_malicious_workload,
            )
            .await?;
            bootnode_addr = Some(bootnode.p2p_addr.clone());
            validators.push(bootnode);
        }

        if validator_keys.len() > 1 {
            let mut launch_futures = FuturesUnordered::new();
            for (i, key) in validator_keys.iter().enumerate().skip(1) {
                let base_port = 5000 + (i * 20) as u16;
                let captured_bootnode = bootnode_addr.clone();
                let captured_genesis = genesis_content.clone();
                let captured_consensus = self.consensus_type.clone();
                let captured_state_tree = self.state_tree.clone();
                let captured_commitment = self.commitment_scheme.clone();
                let captured_agentic_path = self.agentic_model_path.clone();
                let captured_use_docker = self.use_docker;
                let captured_services = self.initial_services.clone();
                let captured_malicious = self.use_malicious_workload;
                let key_clone = key.clone();

                let fut = async move {
                    TestValidator::launch(
                        key_clone,
                        captured_genesis,
                        base_port,
                        captured_bootnode.as_ref(),
                        &captured_consensus,
                        &captured_state_tree,
                        &captured_commitment,
                        captured_agentic_path.as_deref(),
                        captured_use_docker,
                        captured_services,
                        captured_malicious,
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

        if validators.len() > 1 {
            println!("--- Waiting for cluster-wide sync (all nodes at height >= 1) ---");
            let mut height_futs = FuturesUnordered::new();
            for v in &validators {
                let rpc_addr = v.rpc_addr.clone();
                height_futs.push(async move {
                    wait_for_height(&rpc_addr, 1, Duration::from_secs(45)).await
                });
            }
            while let Some(result) = height_futs.next().await {
                result?; // Propagate any timeout errors
            }
            println!("--- Cluster is synced and ready. ---");
        }

        Ok(TestCluster {
            validators,
            genesis_content,
        })
    }
}
