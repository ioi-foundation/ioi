// Path: crates/forge/src/testing/mod.rs

//! Contains helper functions for building and running end-to-end tests.
//! These functions are exposed as a public library to allow users of the
//! SDK to write their own integration tests with the same tooling.

pub mod backend;
pub mod poll; // Add new module
pub mod rpc; // Add new module

use anyhow::{anyhow, Result};
use backend::{DockerBackend, LogStream, ProcessBackend, TestBackend};
use bollard::image::BuildImageOptions;
use bollard::Docker;
use depin_sdk_commitment::primitives::kzg::KZGParams;
use depin_sdk_types::app::ChainTransaction;
use depin_sdk_types::config::{
    CommitmentSchemeType, ConsensusType, InitialServiceConfig, StateTreeType, VmFuelCosts,
    WorkloadConfig,
};
use depin_sdk_validator::config::OrchestrationConfig;
use futures_util::StreamExt;
use hyper::Body;
use libp2p::{identity, Multiaddr, PeerId};
use reqwest::Client;
use serde_json::Value;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Once};
use std::time::Duration;
use tar::Builder;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command as TokioCommand;
use tokio::sync::{Mutex, OnceCell};
use tokio::time::timeout;

// --- Test Configuration ---
const DOCKER_IMAGE_TAG: &str = "depin-sdk-node:e2e";
const LOG_ASSERT_TIMEOUT: Duration = Duration::from_secs(45);
const WORKLOAD_READY_TIMEOUT: Duration = Duration::from_secs(20);
const ORCHESTRATION_READY_TIMEOUT: Duration = Duration::from_secs(20);
const GUARDIAN_READY_TIMEOUT: Duration = Duration::from_secs(10);

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
    let tx_bytes = serde_json::to_vec(tx)?;
    let tx_hex = hex::encode(tx_bytes);
    let client = Client::new();
    let request_body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "submit_tx",
        "params": [tx_hex],
        "id": 1
    });
    let rpc_url = format!("http://{}/rpc", rpc_addr);
    let response = client
        .post(&rpc_url)
        .json(&request_body)
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;
    if let Some(error) = response.get("error") {
        if !error.is_null() {
            return Err(anyhow!("RPC error: {}", error));
        }
    }
    Ok(())
}

pub async fn assert_log_contains(
    label: &str,
    log_stream: &mut LogStream,
    pattern: &str,
) -> Result<()> {
    timeout(LOG_ASSERT_TIMEOUT, async {
        while let Some(line_result) = log_stream.next().await {
            match line_result {
                Ok(line) => {
                    println!("[LOGS-{}] {}", label, line);
                    if line.contains(pattern) {
                        return Ok(());
                    }
                }
                Err(e) => return Err(anyhow!("Error reading log line: {}", e)),
            }
        }
        Err(anyhow!("Log stream ended before pattern was found"))
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
    log_stream: &mut LogStream,
    pattern: &str,
) -> Result<String> {
    timeout(LOG_ASSERT_TIMEOUT, async {
        while let Some(line_result) = log_stream.next().await {
            match line_result {
                Ok(line) => {
                    println!("[LOGS-{}] {}", label, line);
                    if line.contains(pattern) {
                        return Ok(line);
                    }
                }
                Err(e) => return Err(anyhow!("Error reading log line: {}", e)),
            }
        }
        Err(anyhow!("Log stream ended before pattern was found"))
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

/// Represents a complete, logical validator node, abstracting over its execution backend.
pub struct TestValidator {
    pub keypair: identity::Keypair,
    pub peer_id: PeerId,
    pub rpc_addr: String,
    pub p2p_addr: Multiaddr,
    _temp_dir: Arc<TempDir>,
    backend: Box<dyn TestBackend>,
    pub orch_log_stream: Mutex<Option<LogStream>>,
    pub workload_log_stream: Mutex<Option<LogStream>>,
    pub guardian_log_stream: Mutex<Option<LogStream>>,
}

impl Drop for TestValidator {
    fn drop(&mut self) {
        let mut backend = std::mem::replace(&mut self.backend, Box::new(NullBackend));
        tokio::spawn(async move {
            if let Err(e) = backend.cleanup().await {
                log::error!("Failed to cleanup test validator backend: {}", e);
            }
        });
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
    ) -> Result<Self> {
        let peer_id = keypair.public().to_peer_id();
        let temp_dir = Arc::new(tempfile::tempdir()?);

        let p2p_port = portpicker::pick_unused_port().unwrap_or(base_port);
        let rpc_port = portpicker::pick_unused_port().unwrap_or(base_port + 1);
        let p2p_addr_str = format!("/ip4/127.0.0.1/tcp/{}", p2p_port);
        let rpc_addr = format!("127.0.0.1:{}", rpc_port);

        let keypair_path = temp_dir.path().join("identity.key");
        std::fs::write(&keypair_path, keypair.to_protobuf_encoding()?)?;

        let genesis_path = temp_dir.path().join("genesis.json");
        std::fs::write(&genesis_path, genesis_content)?;

        let config_dir_path = temp_dir.path().to_path_buf();

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

        let mut backend: Box<dyn TestBackend> = if use_docker {
            Box::new(
                DockerBackend::new(
                    rpc_addr.clone(),
                    p2p_addr_str.parse()?,
                    agentic_model_path.map(std::path::PathBuf::from),
                    temp_dir.clone(),
                    keypair_path.clone(),
                    genesis_path.clone(),
                    config_dir_path.clone(),
                )
                .await?,
            )
        } else {
            let ipc_port_workload = portpicker::pick_unused_port().unwrap_or(base_port + 2);
            let guardian_port = portpicker::pick_unused_port().unwrap_or(base_port + 3);
            let guardian_addr = format!("127.0.0.1:{}", guardian_port);
            let ipc_addr_workload = format!("127.0.0.1:{}", ipc_port_workload);
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
                        .stderr(Stdio::piped())
                        .kill_on_drop(true)
                        .spawn()?;
                    let mut reader = BufReader::new(process.stderr.take().unwrap()).lines();
                    timeout(GUARDIAN_READY_TIMEOUT, async {
                        while let Some(line) = reader.next_line().await? {
                            if line.contains("Guardian container started") {
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

            let mut workload_cmd = TokioCommand::new(node_binary_path.join("workload"));
            workload_cmd
                .args(["--config", &workload_config_path.to_string_lossy()])
                .env("IPC_SERVER_ADDR", &ipc_addr_workload)
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            if agentic_model_path.is_some() {
                workload_cmd.env("GUARDIAN_ADDR", &guardian_addr);
            }

            let mut workload_process = workload_cmd.spawn()?;
            let mut workload_reader =
                BufReader::new(workload_process.stderr.take().unwrap()).lines();
            timeout(WORKLOAD_READY_TIMEOUT, async {
                let ready_signal = format!("WORKLOAD_IPC_LISTENING_ON_{}", ipc_addr_workload);
                while let Some(line) = workload_reader.next_line().await? {
                    if line.contains(&ready_signal) {
                        return Ok(());
                    }
                }
                Err(anyhow!("Workload stderr stream ended before ready signal."))
            })
            .await??;

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
            let mut orch_cmd = TokioCommand::new(node_binary_path.join("orchestration"));
            orch_cmd
                .args(&orch_args)
                .env("WORKLOAD_IPC_ADDR", &ipc_addr_workload)
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            if agentic_model_path.is_some() {
                orch_cmd.env("GUARDIAN_ADDR", &guardian_addr);
            }

            let mut orchestration_process = orch_cmd.spawn()?;
            let mut orch_reader =
                BufReader::new(orchestration_process.stderr.take().unwrap()).lines();
            timeout(ORCHESTRATION_READY_TIMEOUT, async {
                let rpc_signal = format!("ORCHESTRATION_RPC_LISTENING_ON_{}", rpc_addr);
                while let Some(line) = orch_reader.next_line().await? {
                    if line.contains(&rpc_signal) {
                        return Ok(());
                    }
                }
                Err(anyhow!(
                    "Orchestration stderr stream ended before ready signal."
                ))
            })
            .await??;

            let mut pb = ProcessBackend::new(rpc_addr.clone(), p2p_addr_str.parse()?);
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
        let (orch_logs, workload_logs, guardian_logs) = backend.get_log_streams()?;

        Ok(TestValidator {
            keypair,
            peer_id,
            rpc_addr,
            p2p_addr,
            _temp_dir: temp_dir,
            backend,
            orch_log_stream: Mutex::new(Some(orch_logs)),
            workload_log_stream: Mutex::new(Some(workload_logs)),
            guardian_log_stream: Mutex::new(guardian_logs),
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
    genesis_modifiers: Vec<GenesisModifier>,
    consensus_type: String,
    agentic_model_path: Option<String>,
    use_docker: bool,
    state_tree: String,
    commitment_scheme: String,
    initial_services: Vec<InitialServiceConfig>,
}

impl Default for TestClusterBuilder {
    fn default() -> Self {
        Self {
            num_validators: 1,
            genesis_modifiers: Vec::new(),
            consensus_type: "ProofOfAuthority".to_string(),
            agentic_model_path: None,
            use_docker: false,
            state_tree: "File".to_string(),
            commitment_scheme: "Hash".to_string(),
            initial_services: Vec::new(),
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

    pub fn with_genesis_modifier<F>(mut self, modifier: F) -> Self
    where
        F: FnOnce(&mut Value, &Vec<identity::Keypair>) + Send + 'static,
    {
        self.genesis_modifiers.push(Box::new(modifier));
        self
    }

    pub async fn build(mut self) -> Result<TestCluster> {
        let validator_keys: Vec<identity::Keypair> = (0..self.num_validators)
            .map(|_| identity::Keypair::generate_ed25519())
            .collect();
        let mut genesis = serde_json::json!({ "genesis_state": {} });
        for modifier in self.genesis_modifiers.drain(..) {
            modifier(&mut genesis, &validator_keys);
        }
        let genesis_content = genesis.to_string();
        let mut validators = Vec::new();
        let mut bootnode_addr = None;

        for (i, key) in validator_keys.iter().enumerate() {
            let base_port = 5000 + (i * 20) as u16;
            let validator = TestValidator::launch(
                key.clone(),
                genesis_content.clone(),
                base_port,
                bootnode_addr.as_ref(),
                &self.consensus_type,
                &self.state_tree,
                &self.commitment_scheme,
                self.agentic_model_path.as_deref(),
                self.use_docker,
                self.initial_services.clone(),
            )
            .await?;
            if i == 0 {
                bootnode_addr = Some(validator.p2p_addr.clone());
            }
            validators.push(validator);
        }

        Ok(TestCluster {
            validators,
            genesis_content,
        })
    }
}
