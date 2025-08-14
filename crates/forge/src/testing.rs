// Path: crates/forge/src/testing.rs
//! Contains helper functions for building and running end-to-end tests.
//! These functions are exposed as a public library to allow users of the
//! SDK to write their own integration tests with the same tooling.

use anyhow::{anyhow, Result};
use depin_sdk_types::app::ChainTransaction;
use libp2p::{identity, Multiaddr, PeerId};
use reqwest::Client;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Once;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::{Child, Command as TokioCommand};
use tokio::time::timeout;

// --- Test Configuration ---
const NODE_BINARY_REL_PATH: &str = "../../target/release/depin-sdk-node";
const LOG_ASSERT_TIMEOUT: Duration = Duration::from_secs(45);
const WORKLOAD_READY_TIMEOUT: Duration = Duration::from_secs(10);

// --- One-Time Build ---
static BUILD: Once = Once::new();

/// Builds all required binaries for testing (node, contracts) exactly once.
/// This function is idempotent and thread-safe.
pub fn build_test_artifacts(node_features: &str) {
    BUILD.call_once(|| {
        println!("--- Building Test Artifacts (one-time setup) ---");

        // 1. Build the node binary with specified consensus features.
        println!("Building Node Binary (Features: {})", node_features);
        let status_node = Command::new("cargo")
            .args([
                "build",
                "-p",
                "depin-sdk-node",
                "--release",
                "--no-default-features",
                "--features",
                node_features,
            ])
            .status()
            .expect("Failed to execute cargo build for node");
        if !status_node.success() {
            panic!("Node binary build failed");
        }

        // 2. Build the test WASM contract.
        println!("Building 'counter-contract' (WASM)");
        let status_contract = Command::new("cargo")
            .args([
                "build",
                "--release",
                "--target",
                "wasm32-unknown-unknown",
                "-p",
                "counter-contract",
            ])
            .status()
            .expect("Failed to build counter contract");
        if !status_contract.success() {
            panic!("Counter contract build failed");
        }

        println!("--- Test Artifacts built successfully ---");
    });
}

// --- Helper Structs & Functions ---

/// Submits a transaction to a node's RPC endpoint.
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

    let rpc_url = format!("http://{}", rpc_addr);
    println!("Submitting tx to {}", rpc_url);

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

/// Checks a node's log stream for a line containing a specific pattern within a timeout.
pub async fn assert_log_contains<R: AsyncRead + Unpin>(
    label: &str,
    log_stream: &mut tokio::io::Lines<BufReader<R>>,
    pattern: &str,
) -> Result<()> {
    timeout(LOG_ASSERT_TIMEOUT, async {
        while let Some(line_result) = log_stream.next_line().await.transpose() {
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

/// Checks a node's log stream for a line containing a specific pattern and returns it.
pub async fn assert_log_contains_and_return_line<R: AsyncRead + Unpin>(
    label: &str,
    log_stream: &mut tokio::io::Lines<BufReader<R>>,
    pattern: &str,
) -> Result<String> {
    timeout(LOG_ASSERT_TIMEOUT, async {
        while let Some(line_result) = log_stream.next_line().await.transpose() {
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

// --- New Test Harness Implementation ---

/// Represents a complete, logical validator node, including all its container processes.
pub struct TestValidator {
    pub keypair: identity::Keypair,
    pub peer_id: PeerId,
    pub orchestration_process: Child,
    pub workload_process: Child,
    pub rpc_addr: String,
    pub p2p_addr: Multiaddr,
    _temp_dir: TempDir,
}

impl Drop for TestValidator {
    fn drop(&mut self) {
        let _ = self.orchestration_process.kill();
        let _ = self.workload_process.kill();
    }
}

impl TestValidator {
    pub async fn launch(
        keypair: identity::Keypair,
        genesis_content: String,
        base_port: u16,
        bootnode_addr: Option<&Multiaddr>,
    ) -> Result<Self> {
        let peer_id = keypair.public().to_peer_id();
        let temp_dir = tempfile::tempdir()?;
        let state_file_path = temp_dir.path().join("state.json");

        let p2p_port = portpicker::pick_unused_port().unwrap_or(base_port);
        let rpc_port = portpicker::pick_unused_port().unwrap_or(base_port + 1);
        let ipc_port = portpicker::pick_unused_port().unwrap_or(base_port + 2);

        let p2p_addr_str = format!("/ip4/127.0.0.1/tcp/{}", p2p_port);
        let rpc_addr = format!("127.0.0.1:{}", rpc_port);
        let ipc_addr = format!("127.0.0.1:{}", ipc_port);

        fs::write(temp_dir.path().join("genesis.json"), genesis_content)?;

        let identity_key_path = Path::new(&state_file_path).with_extension("json.identity.key");
        fs::write(identity_key_path, keypair.to_protobuf_encoding()?)?;

        let config_dir = temp_dir.path().join("config");
        fs::create_dir_all(&config_dir)?;

        let orchestration_config = format!(
            r#"
consensus_type = "ProofOfStake"
rpc_listen_address = "127.0.0.1:9999"
"#
        );
        fs::write(config_dir.join("orchestration.toml"), orchestration_config)?;
        fs::write(config_dir.join("guardian.toml"), "")?;

        let workload_state_file = temp_dir.path().join("workload_state.json");
        let mut workload_process = TokioCommand::new(NODE_BINARY_REL_PATH)
            .args([
                "workload",
                "--genesis-file",
                &temp_dir.path().join("genesis.json").to_string_lossy(),
                "--state-file",
                &workload_state_file.to_string_lossy(),
            ])
            .env("IPC_SERVER_ADDR", &ipc_addr)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        let workload_stderr = workload_process.stderr.take().unwrap();
        let mut reader = BufReader::new(workload_stderr).lines();

        let readiness_probe = async {
            let ready_signal = format!("WORKLOAD_IPC_LISTENING_ON_{}", ipc_addr);
            while let Some(line) = reader.next_line().await? {
                if line.contains(&ready_signal) {
                    return Ok(());
                }
            }
            Err(anyhow!("Workload stderr stream ended before ready signal."))
        };

        timeout(WORKLOAD_READY_TIMEOUT, readiness_probe).await??;

        let mut orch_args = vec![
            "orchestration".to_string(),
            "--state-file".to_string(),
            state_file_path.to_string_lossy().to_string(),
            "--genesis-file".to_string(),
            temp_dir
                .path()
                .join("genesis.json")
                .to_string_lossy()
                .to_string(),
            "--config-dir".to_string(),
            config_dir.to_string_lossy().to_string(),
            "--listen-address".to_string(),
            p2p_addr_str.clone(),
            "--rpc-listen-address".to_string(),
            rpc_addr.clone(),
        ];

        if let Some(addr) = bootnode_addr {
            orch_args.push("--bootnode".to_string());
            orch_args.push(addr.to_string());
        }

        let orchestration_process = TokioCommand::new(NODE_BINARY_REL_PATH)
            .args(&orch_args)
            .env("WORKLOAD_IPC_ADDR", &ipc_addr)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        Ok(TestValidator {
            keypair,
            peer_id,
            orchestration_process,
            workload_process,
            rpc_addr,
            p2p_addr: p2p_addr_str.parse()?,
            _temp_dir: temp_dir,
        })
    }
}

pub struct TestCluster {
    pub validators: Vec<TestValidator>,
    pub genesis_content: String,
}

impl TestCluster {
    pub fn new() -> TestClusterBuilder {
        TestClusterBuilder::new()
    }
}

pub struct TestClusterBuilder {
    num_validators: usize,
    genesis_modifiers: Vec<Box<dyn FnOnce(&mut Value, &Vec<identity::Keypair>)>>,
}

impl TestClusterBuilder {
    pub fn new() -> Self {
        Self {
            num_validators: 1,
            genesis_modifiers: Vec::new(),
        }
    }

    pub fn with_validators(mut self, count: usize) -> Self {
        self.num_validators = count;
        self
    }

    pub fn with_genesis_modifier<F>(mut self, modifier: F) -> Self
    where
        F: FnOnce(&mut Value, &Vec<identity::Keypair>) + 'static,
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
            let base_port = 5000 + (i * 10);
            let validator = TestValidator::launch(
                key.clone(),
                genesis_content.clone(),
                base_port as u16,
                bootnode_addr.as_ref(),
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
