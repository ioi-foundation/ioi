// Path: crates/forge/tests/staking_e2e.rs

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use depin_sdk_forge::testing::{
    assert_log_contains, build_test_artifacts, submit_transaction, TestCluster,
};
use depin_sdk_types::app::{ChainTransaction, SystemPayload, SystemTransaction};
use depin_sdk_types::keys::{STAKES_KEY_CURRENT, STAKES_KEY_NEXT};
use serde_json::json;

#[tokio::test]
async fn test_staking_lifecycle() -> Result<()> {
    // A. Setup
    build_test_artifacts("consensus-pos,vm-wasm");

    // B. Launch Cluster with Node 0 as the initial staker.
    let mut cluster = TestCluster::new()
        .with_validators(3)
        .with_consensus_type("ProofOfStake")
        .with_genesis_modifier(|genesis, keys| {
            let initial_staker_peer_id = keys[0].public().to_peer_id();
            let stakes = json!({
                initial_staker_peer_id.to_base58(): 100000
            });
            let stakes_bytes = serde_json::to_vec(&stakes).unwrap();
            let stakes_b64 = format!("b64:{}", BASE64_STANDARD.encode(stakes_bytes));

            // Set both current and next to the same initial state
            genesis["genesis_state"][std::str::from_utf8(STAKES_KEY_CURRENT).unwrap()] =
                json!(stakes_b64.clone());
            genesis["genesis_state"][std::str::from_utf8(STAKES_KEY_NEXT).unwrap()] =
                json!(stakes_b64);
        })
        .build()
        .await?;

    // C. Get handles to nodes and logs.
    let (node0, node1, node2) = {
        let mut iter = cluster.validators.iter_mut();
        (
            iter.next().unwrap(),
            iter.next().unwrap(),
            iter.next().unwrap(),
        )
    };

    let mut logs0 = node0.orch_log_stream.lock().await.take().unwrap();
    let mut logs1 = node1.orch_log_stream.lock().await.take().unwrap();
    let mut logs2 = node2.orch_log_stream.lock().await.take().unwrap();
    let bootnode_peer_id = node0.peer_id;

    // --- WAIT FOR NETWORK CONNECTIONS ---
    println!("--- Waiting for network to connect ---");
    assert_log_contains(
        "Node1",
        &mut logs1,
        &format!("Connection established with peer {}", bootnode_peer_id),
    )
    .await?;
    assert_log_contains(
        "Node2",
        &mut logs2,
        &format!("Connection established with peer {}", bootnode_peer_id),
    )
    .await?;
    println!("--- Network connected ---");

    // D. Execute transactions: Node 0 unstakes, Node 1 stakes.
    println!("--- Submitting Unstake transaction for Node 0 ---");
    let unstake_payload = SystemPayload::Unstake { amount: 100000 };
    let unstake_payload_bytes = serde_json::to_vec(&unstake_payload)?;
    let unstake_signature = node0.keypair.sign(&unstake_payload_bytes)?;
    let unstake_tx = ChainTransaction::System(SystemTransaction {
        payload: unstake_payload,
        signature: [
            node0
                .keypair
                .public()
                .try_into_ed25519()?
                .to_bytes()
                .as_ref(),
            &unstake_signature,
        ]
        .concat(),
    });
    submit_transaction(&node0.rpc_addr, &unstake_tx).await?;

    println!("--- Submitting Stake transaction for Node 1 ---");
    let stake_payload = SystemPayload::Stake { amount: 50000 };
    let stake_payload_bytes = serde_json::to_vec(&stake_payload)?;
    let stake_signature = node1.keypair.sign(&stake_payload_bytes)?;
    let stake_tx = ChainTransaction::System(SystemTransaction {
        payload: stake_payload,
        signature: [
            node1
                .keypair
                .public()
                .try_into_ed25519()?
                .to_bytes()
                .as_ref(),
            &stake_signature,
        ]
        .concat(),
    });
    submit_transaction(&node0.rpc_addr, &stake_tx).await?;

    // --- CORRECTED WAIT LOGIC FOR 2-BLOCK LATENCY ---
    // Block 1: Leader is Node 0 (based on genesis state), but transactions might not make it in time.
    println!("--- Waiting for Node 0 to produce block #1 ---");
    assert_log_contains("Node0", &mut logs0, "Produced and processed new block #1").await?;

    // Block 2: Leader is still Node 0. The stake/unstake transactions are included here.
    println!("--- Verifying Node 0 produces block #2 with stake changes ---");
    assert_log_contains(
        "Node0",
        &mut logs0,
        "Accepted transaction into pool. Pool size: 1",
    )
    .await?;
    assert_log_contains(
        "Node0",
        &mut logs0,
        "Accepted transaction into pool. Pool size: 2",
    )
    .await?;
    assert_log_contains("Node0", &mut logs0, "Produced and processed new block #2").await?;

    // --- Wait for Node 1 to process block #2 to ensure its state is updated ---
    assert_log_contains(
        "Node1",
        &mut logs1,
        "Received gossiped block #2. Forwarding to workload...",
    )
    .await?;
    assert_log_contains(
        "Node1",
        &mut logs1,
        "Workload processed block successfully.",
    )
    .await?;

    // Block 3: Leader is still Node 0. The `next` stake set from block 2 is promoted to `current` at the start of this block's processing.
    // The leader for block 3 was already decided based on the state at the end of block 2.
    println!("--- Verifying state transition: Node 0 remains leader for block #3 ---");
    assert_log_contains(
        "Node0",
        &mut logs0,
        "Consensus decision: Produce block for height 3",
    )
    .await?;
    assert_log_contains("Node0", &mut logs0, "Produced and processed new block #3").await?;

    // --- Wait for Node 1 to process block #3. This ensures the newly promoted `current` stake set is active on Node 1. ---
    assert_log_contains(
        "Node1",
        &mut logs1,
        "Received gossiped block #3. Forwarding to workload...",
    )
    .await?;
    assert_log_contains(
        "Node1",
        &mut logs1,
        "Workload processed block successfully.",
    )
    .await?;

    // E. Assert the outcomes
    // Block 4: Leader is now Node 1, based on the `current` stake set established in block 3.
    println!("--- Verifying state transition: Node 1 becomes the new leader for block #4 ---");
    assert_log_contains(
        "Node1",
        &mut logs1,
        "Consensus decision: Produce block for height 4",
    )
    .await?;

    Ok(())
}
