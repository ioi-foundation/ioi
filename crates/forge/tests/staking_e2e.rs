// Path: crates/forge/tests/staking_e2e.rs

//! End-to-End Test: Proof of Stake and Dynamic Staking

use anyhow::{anyhow, Result};
use depin_sdk_core::app::{ProtocolTransaction, SystemPayload, SystemTransaction};
use depin_sdk_forge::testing::{
    assert_log_contains, build_node_binary, spawn_node, submit_transaction,
};
use libp2p::identity;
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::time::timeout;

#[tokio::test]
#[ignore] // This test is long-running and should be run explicitly
async fn test_staking_lifecycle() -> Result<()> {
    // A. Setup
    println!("--- Building Node Binary for Staking Test ---");
    build_node_binary("consensus-pos,vm-wasm");

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

    // 3. Spawn nodes using the forge helper
    println!("--- Launching 3-Node Cluster ---");
    let mut node1 = spawn_node(
        &key_node1,
        tempdir()?,
        &genesis_string,
        &["--listen-address", "/ip4/127.0.0.1/tcp/4011"],
        "127.0.0.1:9954",
        "ProofOfStake",
    )
    .await?;

    // FIX: Use the format! macro for robust string construction.
    let bootnode_addr = format!("/ip4/127.0.0.1/tcp/4011/p2p/{}", peer_id_node1);

    let mut node2 = spawn_node(
        &key_node2,
        tempdir()?,
        &genesis_string,
        &[
            "--listen-address",
            "/ip4/127.0.0.1/tcp/4012",
            "--peer",
            &bootnode_addr,
        ],
        "127.0.0.1:9955",
        "ProofOfStake",
    )
    .await?;

    let mut _node3 = spawn_node(
        &key_node3,
        tempdir()?,
        &genesis_string,
        &[
            "--listen-address",
            "/ip4/127.0.0.1/tcp/4013",
            "--peer",
            &bootnode_addr,
        ],
        "127.0.0.1:9956",
        "ProofOfStake",
    )
    .await?;

    // Setup log streams
    let mut logs1 = BufReader::new(node1.process.stderr.take().unwrap()).lines();
    let mut logs2 = BufReader::new(node2.process.stderr.take().unwrap()).lines();

    // B. Phase 1: Verify Initial State
    println!("--- Phase 1: Verifying Initial State ---");
    assert_log_contains("Node1", &mut logs1, "Consensus decision: Produce block").await?;
    println!("--- Initial state verified: Node 1 is the sole staker. ---");

    // C. Phase 2: Submit Staking Transactions
    println!("--- Phase 2: Submitting Staking Transactions ---");
    // Tx 1: Node 1 unstakes everything
    let unstake_payload = SystemPayload::Unstake { amount: 100000 };
    let unstake_payload_bytes = serde_json::to_vec(&unstake_payload)?;
    let pubkey1_bytes = key_node1.public().try_into_ed25519()?.to_bytes().to_vec();
    let signature1 = key_node1.sign(&unstake_payload_bytes)?;
    let combined_sig1 = [pubkey1_bytes, signature1].concat();
    let unstake_tx = ProtocolTransaction::System(SystemTransaction {
        payload: unstake_payload,
        signature: combined_sig1,
    });
    submit_transaction("127.0.0.1:9954", &unstake_tx).await?;

    // Tx 2: Node 2 stakes
    let stake_payload = SystemPayload::Stake { amount: 100000 };
    let stake_payload_bytes = serde_json::to_vec(&stake_payload)?;
    let pubkey2_bytes = key_node2.public().try_into_ed25519()?.to_bytes().to_vec();
    let signature2 = key_node2.sign(&stake_payload_bytes)?;
    let combined_sig2 = [pubkey2_bytes, signature2].concat();
    let stake_tx = ProtocolTransaction::System(SystemTransaction {
        payload: stake_payload,
        signature: combined_sig2,
    });
    submit_transaction("127.0.0.1:9954", &stake_tx).await?;
    println!("--- Staking transactions submitted successfully. ---");

    // D. Phase 3: Verify New State
    println!("--- Phase 3: Verifying New State ---");
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
    if node1_inactive_check.is_ok() {
        return Err(anyhow!(
            "Node 1 unexpectedly produced a block after unstaking."
        ));
    }
    println!("--- Inactivity verified: Node 1 correctly stopped producing blocks. ---");
    println!("--- New state verified: Node 2 is now the sole staker. ---");

    // E. Cleanup
    println!("--- Test finished. Cleaning up. ---");
    Ok(())
}
