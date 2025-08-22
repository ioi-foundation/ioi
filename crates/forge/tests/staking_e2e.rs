// crates/forge/tests/staking_e2e.rs

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
    // 1. SETUP: Build artifacts.
    build_test_artifacts("consensus-pos,vm-wasm");

    // 2. LAUNCH CLUSTER: 3-node PoS cluster with Node0 as the sole initial staker.
    let mut cluster = TestCluster::builder()
        .with_validators(3)
        .with_consensus_type("ProofOfStake")
        .with_genesis_modifier(|genesis, keys| {
            let initial_staker_peer_id = keys[0].public().to_peer_id();
            let stakes = json!({ initial_staker_peer_id.to_base58(): 100_000u64 });
            let stakes_b64 = format!(
                "b64:{}",
                BASE64_STANDARD.encode(serde_json::to_vec(&stakes).unwrap())
            );
            genesis["genesis_state"][std::str::from_utf8(STAKES_KEY_CURRENT).unwrap()] =
                json!(stakes_b64.clone());
            genesis["genesis_state"][std::str::from_utf8(STAKES_KEY_NEXT).unwrap()] =
                json!(stakes_b64);
        })
        .build()
        .await?;

    // 3. GET HANDLES: Get mutable references to the nodes and their log streams.
    let (node0, node1, node2) = {
        let mut it = cluster.validators.iter_mut();
        (it.next().unwrap(), it.next().unwrap(), it.next().unwrap())
    };
    let rpc_addr = node0.rpc_addr.clone();
    let node1_peer_id_b58 = node1.peer_id.to_base58();
    let mut logs1 = node1.orch_log_stream.lock().await.take().unwrap();
    let mut logs2 = node2.orch_log_stream.lock().await.take().unwrap();

    // 4. PRE-CONDITION: Wait for the network to be active by seeing the first block gossiped.
    assert_log_contains("Node2", &mut logs2, "Received gossiped block #1").await?;

    // 5. ACTION: Submit staking transactions via Node0's RPC.
    // Transaction 1: Node0 (the current leader) unstakes all its funds.
    let unstake_payload = SystemPayload::Unstake { amount: 100_000 };
    let unstake_sig = node0.keypair.sign(&serde_json::to_vec(&unstake_payload)?)?;
    let unstake_tx = ChainTransaction::System(SystemTransaction {
        payload: unstake_payload,
        signature: [
            node0
                .keypair
                .public()
                .try_into_ed25519()?
                .to_bytes()
                .as_ref(),
            &unstake_sig,
        ]
        .concat(),
    });
    submit_transaction(&rpc_addr, &unstake_tx).await?;

    // Transaction 2: Node1 stakes some funds to become the new (and only) validator.
    let stake_payload = SystemPayload::Stake { amount: 50_000 };
    let stake_sig = node1.keypair.sign(&serde_json::to_vec(&stake_payload)?)?;
    let stake_tx = ChainTransaction::System(SystemTransaction {
        payload: stake_payload,
        signature: [
            node1
                .keypair
                .public()
                .try_into_ed25519()?
                .to_bytes()
                .as_ref(),
            &stake_sig,
        ]
        .concat(),
    });
    submit_transaction(&rpc_addr, &stake_tx).await?;

    // 6. VERIFICATION: This is the critical part of the robust test.
    // Instead of asserting intermediate steps (like gossip), we wait for the
    // ultimate desired outcome: Node1 is elected as the leader for a future block.
    //
    // The staking transactions will likely be included in block #2. The state change
    // (Node0 unstaked, Node1 staked) will be committed with block #2. Therefore,
    // the leader election for block #3 will see Node1 as the sole staker.
    // We confirm this by looking for the leader election log message on any node.
    let expected_leader_log = format!("[PoS] leader@3 = {}", node1_peer_id_b58);

    assert_log_contains(
        "Node1", // We can check any node's log, as they all run the same consensus.
        &mut logs1,
        &expected_leader_log,
    )
    .await?;

    println!("--- Staking Lifecycle E2E Test Passed ---");
    Ok(())
}
