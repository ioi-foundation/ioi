//! End-to-End Test: Proof of Stake and Dynamic Staking
//!
//! This test simulates a live network to verify the entire lifecycle of
//! the Proof of Stake consensus engine, including a change in the staker set
//! triggered by `Stake` and `Unstake` system transactions.
//!
//! Test Plan:
//! A. Setup a 3-node cluster. Genesis state gives Node 1 100% of the stake.
//! B. Verify that only Node 1 produces blocks.
//! C. Submit an `Unstake` transaction from Node 1 and a `Stake` transaction from Node 2.
//! D. Verify that after the state change, Node 2 produces blocks and Node 1 does not.
//! E. Cleanup all processes and temporary state.

use anyhow::{anyhow, Result};
use depin_sdk_core::app::{ProtocolTransaction, SystemPayload, SystemTransaction};
use libp2p::identity;
use reqwest::Client;
use std::process::{Command, Stdio};
use std::sync::Once;
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::Child;
use tokio::time::timeout;

// --- Test Configuration ---
const NODE_BINARY_REL_PATH: &str = "../../target/release/node";
const LOG_ASSERT_TIMEOUT: Duration = Duration::from_secs(45);
const STARTUP_DELAY: Duration = Duration::from_secs(5);

// --- One-Time Build ---
static BUILD: Once = Once::new();

/// Builds the node binary with PoS consensus features. This is run only once.
fn build_pos_node_binary() {
    BUILD.call_once(|| {
        println!("--- Building PoS Node Binary for E2E Test ---");
        let status = Command::new("cargo")
            .args([
                "build",
                "-p",
                "depin-sdk-binaries",
                "--release",
                "--no-default-features",
                "--features",
                "consensus-pos,vm-wasm", // <-- FIX: Add vm-wasm feature
            ])
            .status()
            .expect("Failed to execute cargo build command");
        assert!(status.success(), "Node binary build failed");
    });
}

// --- Helper Structs & Functions ---
struct TestNode {
    process: Child,
    _dir: TempDir, // Held for automatic cleanup
}

async fn submit_transaction(rpc_addr: &str, tx: &ProtocolTransaction) -> Result<()> {
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

    println!("RPC response: {:?}", response);
    Ok(())
}

/// Spawns a node process, assuming its temporary directory and configs are already created.
async fn spawn_node(
    key: &identity::Keypair,
    dir: TempDir,
    args: &[&str],
    rpc_addr: &str,
) -> Result<TestNode> {
    std::fs::write(
        dir.path().join("state.json.identity.key"),
        key.to_protobuf_encoding()?,
    )?;

    let config_dir = dir.path().join("config");
    std::fs::create_dir_all(&config_dir)?;

    let orchestration_config = format!(
        r#"
consensus_type = "ProofOfStake"
rpc_listen_address = "{}"
"#,
        rpc_addr
    );
    std::fs::write(config_dir.join("orchestration.toml"), orchestration_config)?;
    std::fs::write(
        config_dir.join("guardian.toml"),
        r#"signature_policy = "FollowChain""#,
    )?;

    let state_file_arg = dir.path().join("state.json").to_string_lossy().to_string();
    let genesis_file_arg = dir
        .path()
        .join("genesis.json")
        .to_string_lossy()
        .to_string();
    let config_dir_arg = config_dir.to_string_lossy().to_string();
    let mut cmd_args = vec![
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

    Ok(TestNode { process, _dir: dir })
}

/// Checks a node's log stream for a line containing a specific pattern within a timeout.
async fn assert_log_contains<R: AsyncRead + Unpin>(
    label: &str,
    log_stream: &mut tokio::io::Lines<BufReader<R>>,
    pattern: &str,
) -> Result<()> {
    timeout(LOG_ASSERT_TIMEOUT, async {
        while let Some(line_result) = log_stream.next_line().await.transpose() {
            match line_result {
                Ok(line) => {
                    println!("[LOGS-{}] {}", label, line); // Print logs for debugging
                    if line.contains(pattern) {
                        return Ok(());
                    }
                }
                Err(e) => return Err(anyhow!("Error reading log line: {}", e)),
            }
        }
        Err(anyhow!("Log stream ended before pattern was found"))
    })
    .await? // Handles timeout error
    .map_err(|e| {
        anyhow!(
            "[{}] Log assertion failed for pattern '{}': {}",
            label,
            pattern,
            e
        )
    })
}

// --- The Main E2E Test ---
#[tokio::test]
#[ignore] // This test is long-running and should be run explicitly via `cargo test -- --ignored`
async fn test_staking_lifecycle() -> Result<()> {
    // --- A. Setup ---
    println!("--- Building Node Binary ---");
    build_pos_node_binary();

    // 1. Prepare identities
    let key_node1 = identity::Keypair::generate_ed25519();
    let peer_id_node1 = key_node1.public().to_peer_id();
    let key_node2 = identity::Keypair::generate_ed25519();
    let _peer_id_node2 = key_node2.public().to_peer_id();
    let key_node3 = identity::Keypair::generate_ed25519();
    let _peer_id_node3 = key_node3.public().to_peer_id();

    // 2. Prepare genesis content first
    let genesis_content = serde_json::json!({
      "genesis_state": {
        "system::stakes": {
          peer_id_node1.to_base58(): 100000
        }
      }
    });
    let genesis_string = genesis_content.to_string();

    // 3. Prepare directories and genesis files *before* spawning nodes.
    println!("--- Launching 3-Node Cluster ---");
    let dir1 = tempdir()?;
    std::fs::write(dir1.path().join("genesis.json"), &genesis_string)?;
    let mut node1 = spawn_node(
        &key_node1,
        dir1,
        &["--listen-address", "/ip4/127.0.0.1/tcp/4001"],
        "127.0.0.1:9944",
    )
    .await?;

    tokio::time::sleep(STARTUP_DELAY).await; // Give listener time to bind
    let bootnode_addr = "/ip4/127.0.0.1/tcp/4001";

    let dir2 = tempdir()?;
    std::fs::write(dir2.path().join("genesis.json"), &genesis_string)?;
    let mut node2 = spawn_node(
        &key_node2,
        dir2,
        &[
            "--listen-address",
            "/ip4/127.0.0.1/tcp/4002",
            "--peer",
            bootnode_addr,
        ],
        "127.0.0.1:9945",
    )
    .await?;

    let dir3 = tempdir()?;
    std::fs::write(dir3.path().join("genesis.json"), &genesis_string)?;
    let mut _node3 = spawn_node(
        &key_node3,
        dir3,
        &[
            "--listen-address",
            "/ip4/127.0.0.1/tcp/4003",
            "--peer",
            bootnode_addr,
        ],
        "127.0.0.1:9946",
    )
    .await?;

    let mut logs1 = BufReader::new(node1.process.stderr.take().unwrap()).lines();
    let mut logs2 = BufReader::new(node2.process.stderr.take().unwrap()).lines();
    let mut _logs3 = BufReader::new(_node3.process.stderr.take().unwrap()).lines();

    // --- B. Phase 1: Verify Initial State (Pre-Staking Change) ---
    println!("--- Phase 1: Verifying Initial State ---");
    assert_log_contains("Node1", &mut logs1, "Consensus decision: Produce block").await?;
    println!("--- Initial state verified: Node 1 is the sole staker. ---");

    // --- C. Phase 2: Submit Staking Transactions ---
    println!("--- Phase 2: Submitting Staking Transactions ---");
    // Tx 1: Node 1 unstakes everything
    let unstake_payload = SystemPayload::Unstake { amount: 100000 };
    let unstake_payload_bytes = serde_json::to_vec(&unstake_payload)?;
    let pubkey1_bytes = key_node1
        .public()
        .try_into_ed25519()
        .expect("test key is ed25519")
        .to_bytes()
        .to_vec();
    let signature1 = key_node1.sign(&unstake_payload_bytes)?;
    let combined_sig1 = [pubkey1_bytes, signature1].concat();
    let unstake_tx = ProtocolTransaction::System(SystemTransaction {
        payload: unstake_payload,
        signature: combined_sig1,
    });
    submit_transaction("127.0.0.1:9944", &unstake_tx).await?;

    // Tx 2: Node 2 stakes
    let stake_payload = SystemPayload::Stake { amount: 100000 };
    let stake_payload_bytes = serde_json::to_vec(&stake_payload)?;
    let pubkey2_bytes = key_node2
        .public()
        .try_into_ed25519()
        .expect("test key is ed25519")
        .to_bytes()
        .to_vec();
    let signature2 = key_node2.sign(&stake_payload_bytes)?;
    let combined_sig2 = [pubkey2_bytes, signature2].concat();
    let stake_tx = ProtocolTransaction::System(SystemTransaction {
        payload: stake_payload,
        signature: combined_sig2,
    });
    submit_transaction("127.0.0.1:9944", &stake_tx).await?;
    println!("--- Staking transactions submitted successfully. ---");

    // --- D. Phase 3: Verify New State (Post-Staking Change) ---
    println!("--- Phase 3: Verifying New State ---");
    // Wait for Node 1 (the current leader) to process both transactions in a block.
    assert_log_contains(
        "Node1",
        &mut logs1,
        "Processed unstake of 100000 for validator.",
    )
    .await?;
    assert_log_contains(
        "Node1",
        &mut logs1,
        "Processed stake of 100000 for validator.",
    )
    .await?;

    // Wait for Node 2 to process the block, confirming the state has propagated.
    assert_log_contains(
        "Node2",
        &mut logs2,
        "Processed stake of 100000 for validator.",
    )
    .await?;
    println!("--- State change confirmed by nodes. Now verifying new leader. ---");

    // Check that Node 2 is now producing blocks
    assert_log_contains("Node2", &mut logs2, "Consensus decision: Produce block").await?;

    // Check that Node 1 is no longer producing blocks (expect timeout)
    let node1_inactive_check = timeout(
        Duration::from_secs(20),
        assert_log_contains("Node1", &mut logs1, "Consensus decision: Produce block"),
    )
    .await;
    match node1_inactive_check {
        Ok(_) => {
            return Err(anyhow!(
                "Node 1 unexpectedly produced a block after unstaking."
            ))
        }
        Err(_) => {
            println!("--- Inactivity verified: Node 1 correctly stopped producing blocks. ---")
        }
    }

    println!("--- New state verified: Node 2 is now the sole staker. ---");

    // --- E. Cleanup ---
    println!("--- Test finished. Cleaning up. ---");
    Ok(())
}
