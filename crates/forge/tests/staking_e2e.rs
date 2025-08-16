// Path: crates/forge/tests/staking_e2e.rs

use anyhow::Result;
use depin_sdk_forge::testing::{
    assert_log_contains, build_test_artifacts, submit_transaction, TestCluster,
};
use depin_sdk_types::app::{ChainTransaction, SystemPayload, SystemTransaction};
use serde_json::json;

#[tokio::test]
async fn test_staking_lifecycle() -> Result<()> {
    // A. Setup
    build_test_artifacts("consensus-pos,vm-wasm");

    // B. Launch Cluster
    let mut cluster = TestCluster::new()
        .with_validators(3)
        .with_consensus_type("ProofOfStake")
        .with_genesis_modifier(|genesis, keys| {
            let initial_staker_peer_id = keys[0].public().to_peer_id();
            genesis["genesis_state"]["system::stakes"] = json!({
                initial_staker_peer_id.to_base58(): 100000
            });
        })
        .build()
        .await?;

    // C. Get handles to nodes and logs
    // --- START FIX: Use split_at_mut for safe multiple mutable borrows ---
    let (node0_slice, rest) = cluster.validators.split_at_mut(1);
    let (node1_slice, node2_slice) = rest.split_at_mut(1);
    let node0 = &mut node0_slice[0];
    let node1 = &mut node1_slice[0];
    let node2 = &mut node2_slice[0];
    // --- END FIX ---

    let mut logs1 = node1.orch_log_stream.lock().await.take().unwrap();
    let mut logs2 = node2.orch_log_stream.lock().await.take().unwrap();
    let bootnode_peer_id = node0.peer_id;

    // --- WAIT FOR NETWORK CONNECTIONS ---
    println!("--- Waiting for network to connect ---");
    // Wait for Node 1 and Node 2 to connect to the bootnode (Node 0)
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

    // D. Execute the test logic
    println!("--- Submitting Unstake transaction for Node 1 ---");
    let unstake_payload = SystemPayload::Unstake { amount: 100000 };
    let unstake_payload_bytes = serde_json::to_vec(&unstake_payload)?;
    let unstake_signature = node0.keypair.sign(&unstake_payload_bytes)?; // Node 0 is the initial staker
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
    // Submit to any node, it will be gossiped. Submitting to the initial leader is realistic.
    submit_transaction(&node0.rpc_addr, &unstake_tx).await?;

    println!("--- Submitting Stake transaction for Node 2 ---");
    let stake_payload = SystemPayload::Stake { amount: 50000 };
    let stake_payload_bytes = serde_json::to_vec(&stake_payload)?;
    let stake_signature = node1.keypair.sign(&stake_payload_bytes)?; // Node 1 will be the new staker
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

    // E. Assert the outcomes
    println!("--- Verifying state transition: Node 2 becomes the new leader ---");
    // Now that Node 1 has staked, it should become the leader for a future block.
    assert_log_contains("Node1", &mut logs1, "Consensus decision: Produce block").await?;

    Ok(())
}
