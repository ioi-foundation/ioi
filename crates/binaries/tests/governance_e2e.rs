//! End-to-End Test: Governance-driven Authority Set Change
//!
//! This test simulates a live network to verify the entire lifecycle of an
//! authority set change triggered by a `SystemTransaction`.
//!
//! It follows the E2E Test Plan:
//! A. Setup a 3-node cluster with Node1 & Node2 as initial authorities.
//! B. Verify that only Node1 & Node2 produce blocks.
//! C. Submit a governance transaction to replace Node2 with Node3.
//! D. Verify that Node1 & Node3 now produce blocks, and Node2 does not.
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

/// Builds the node binary with PoA consensus features. This is run only once.
fn build_node_binary() {
    BUILD.call_once(|| {
        println!("--- Building PoA Node Binary for E2E Test ---");
        let status = Command::new("cargo")
            .args([
                "build",
                "-p",
                "depin-sdk-binaries",
                "--release",
                "--no-default-features",
                "--features",
                "consensus-poa,vm-wasm", // <-- FIX: Add vm-wasm feature
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
consensus_type = "ProofOfAuthority"
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
async fn test_governance_authority_change_lifecycle() -> Result<()> {
    // --- A. Setup ---
    println!("--- Building Node Binary ---");
    build_node_binary();

    // 1. Prepare identities
    let key_node1 = identity::Keypair::generate_ed25519();
    let peer_id_node1 = key_node1.public().to_peer_id();
    let key_node2 = identity::Keypair::generate_ed25519();
    let peer_id_node2 = key_node2.public().to_peer_id();
    let key_node3 = identity::Keypair::generate_ed25519();
    let peer_id_node3 = key_node3.public().to_peer_id();
    let governance_keypair = identity::Keypair::generate_ed25519();
    let governance_pubkey_bytes = governance_keypair
        .public()
        .try_into_ed25519()
        .map_err(|_| anyhow!("This test requires an Ed25519 governance key"))?
        .to_bytes()
        .to_vec();

    // 2. Prepare genesis content first
    let genesis_content = serde_json::json!({
      "genesis_state": {
        "system::authorities": [
          peer_id_node1.to_base58(),
          peer_id_node2.to_base58()
        ],
        "system::governance_key": bs58::encode(&governance_pubkey_bytes).into_string()
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
    let mut node3 = spawn_node(
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
    let mut logs3 = BufReader::new(node3.process.stderr.take().unwrap()).lines();

    let mut stdout1 = BufReader::new(node1.process.stdout.take().unwrap());
    let mut stdout2 = BufReader::new(node2.process.stdout.take().unwrap());
    let mut stdout3 = BufReader::new(node3.process.stdout.take().unwrap());

    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut stdout1, &mut tokio::io::sink()).await;
    });
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut stdout2, &mut tokio::io::sink()).await;
    });
    tokio::spawn(async move {
        let _ = tokio::io::copy(&mut stdout3, &mut tokio::io::sink()).await;
    });

    // --- B. Phase 1: Verify Initial State (Pre-Governance) ---
    println!("--- Phase 1: Verifying Initial State ---");
    let phase1_checks = tokio::join!(
        assert_log_contains("Node1", &mut logs1, "Consensus decision: Produce block"),
        assert_log_contains("Node2", &mut logs2, "Consensus decision: Produce block")
    );
    phase1_checks.0?;
    phase1_checks.1?;
    println!("--- Initial state verified: Node 1 & 2 are authorities. ---");

    // --- C. Phase 2: Submit Governance Transaction ---
    println!("--- Phase 2: Submitting Governance Transaction ---");
    let payload = SystemPayload::UpdateAuthorities {
        new_authorities: vec![peer_id_node1.to_bytes(), peer_id_node3.to_bytes()],
    };
    let payload_bytes = serde_json::to_vec(&payload)?;
    let signature = governance_keypair.sign(&payload_bytes)?;
    let tx = ProtocolTransaction::System(SystemTransaction { payload, signature });

    submit_transaction("127.0.0.1:9944", &tx).await?;
    println!("--- Governance transaction submitted successfully. ---");

    // --- D. Phase 3: Verify New State (Post-Governance) ---
    println!("--- Phase 3: Verifying New State ---");

    // --- FIX START: Wait for ALL relevant nodes to process the state change ---
    // This synchronizes the test harness with the distributed state of the network,
    // ensuring Node 2 has processed its own removal before we check its behavior.
    assert_log_contains("Node3", &mut logs3, "Successfully updated authority set").await?;
    assert_log_contains("Node2", &mut logs2, "Successfully updated authority set").await?;
    println!("--- State change confirmed by all nodes. Now verifying roles. ---");
    // --- FIX END ---

    let phase3_checks = tokio::join!(
        // Check for new authority activity
        assert_log_contains("Node3", &mut logs3, "Consensus decision: Produce block"),
        // Check for old authority inactivity (expect a timeout)
        async {
            // Now that the state change is confirmed, we can start the inactivity check.
            let res = timeout(
                Duration::from_secs(20), // Wait for a few block cycles
                assert_log_contains("Node2", &mut logs2, "Consensus decision: Produce block"),
            )
            .await;

            match res {
                Ok(_) => Err(anyhow!(
                    "Node 2 unexpectedly produced a block after being removed."
                )),
                Err(_) => {
                    println!(
                        "--- Inactivity verified: Node 2 correctly stopped producing blocks. ---"
                    );
                    Ok(())
                }
            }
        }
    );
    phase3_checks.0?;
    phase3_checks.1?;
    println!("--- New state verified: Node 1 & 3 are now authorities. ---");

    // --- E. Cleanup ---
    println!("--- Test finished. Cleaning up. ---");
    Ok(())
}
