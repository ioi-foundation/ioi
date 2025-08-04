// Path: crates/forge/src/testing.rs
//! Contains helper functions for building and running end-to-end tests.
//! These functions are exposed as a public library to allow users of the
//! SDK to write their own integration tests with the same tooling.

use anyhow::{anyhow, Result};
use depin_sdk_types::app::ProtocolTransaction;
use libp2p::identity;
use reqwest::Client;
use std::process::{Command, Stdio};
use std::sync::Once;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncRead, BufReader};
use tokio::process::Child;
use tokio::time::timeout;

// --- Test Configuration ---
const NODE_BINARY_REL_PATH: &str = "../../target/release/depin-sdk-node";
const LOG_ASSERT_TIMEOUT: Duration = Duration::from_secs(45);
const STARTUP_DELAY: Duration = Duration::from_secs(5);

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
        assert!(status_node.success(), "Node binary build failed");

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
        assert!(status_contract.success(), "Counter contract build failed");

        println!("--- Test Artifacts built successfully ---");
    });
}

// --- Helper Structs & Functions ---

/// Represents a running node process in a test environment.
/// Held for automatic cleanup when it goes out of scope.
pub struct TestNode {
    pub process: Child,
    _dir: TempDir,
}

/// Submits a transaction to a node's RPC endpoint.
pub async fn submit_transaction(rpc_addr: &str, tx: &ProtocolTransaction) -> Result<()> {
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

/// Spawns a node process in a temporary directory with specified configurations.
pub async fn spawn_node(
    key: &identity::Keypair,
    dir: TempDir,
    genesis_content: &str,
    args: &[&str],
    rpc_addr: &str,
    consensus_type: &str,
) -> Result<TestNode> {
    std::fs::write(dir.path().join("genesis.json"), genesis_content)?;
    std::fs::write(
        dir.path().join("state.json.identity.key"),
        key.to_protobuf_encoding()?,
    )?;

    let config_dir = dir.path().join("config");
    std::fs::create_dir_all(&config_dir)?;

    let orchestration_config = format!(
        r#"
consensus_type = "{}"
rpc_listen_address = "{}"
initial_sync_timeout_secs = 15
"#,
        consensus_type, rpc_addr
    );
    std::fs::write(config_dir.join("orchestration.toml"), orchestration_config)?;

    // Create a unique guardian port for each test to avoid conflicts.
    let guardian_port = portpicker::pick_unused_port().unwrap_or(8443);
    let guardian_config = format!(r#"listen_addr = "0.0.0.0:{}""#, guardian_port);
    std::fs::write(config_dir.join("guardian.toml"), guardian_config)?;

    let state_file_arg = dir.path().join("state.json").to_string_lossy().to_string();
    let genesis_file_arg = dir
        .path()
        .join("genesis.json")
        .to_string_lossy()
        .to_string();
    let config_dir_arg = config_dir.to_string_lossy().to_string();

    // FIX: Add the "node" subcommand as the first argument to match the CLI definition.
    let mut cmd_args = vec![
        "node",
        "--state-file",
        &state_file_arg,
        "--genesis-file",
        &genesis_file_arg,
        "--config-dir",
        &config_dir_arg,
    ];

    let args_owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    cmd_args.extend(args_owned.iter().map(|s| s.as_str()));

    let process = tokio::process::Command::new(NODE_BINARY_REL_PATH)
        .args(&cmd_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    tokio::time::sleep(STARTUP_DELAY).await;

    Ok(TestNode { process, _dir: dir })
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
