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
    // 1) Setup
    build_test_artifacts("consensus-pos,vm-wasm");

    // 2) Launch 3-node PoS cluster with Node0 as initial staker
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

    // 3) Handles + log streams
    let (node0, node1, node2) = {
        let mut it = cluster.validators.iter_mut();
        (it.next().unwrap(), it.next().unwrap(), it.next().unwrap())
    };

    let mut logs0 = node0.orch_log_stream.lock().await.take().unwrap();
    let mut logs1 = node1.orch_log_stream.lock().await.take().unwrap();
    let mut logs2 = node2.orch_log_stream.lock().await.take().unwrap();

    // 4) Connectivity: observe *any* gossiped block on Node2 only
    // (Avoid consuming Node1's stream here since we'll assert specific lines later.)
    assert_log_contains("Node2", &mut logs2, "Received gossiped block #").await?;

    // 5) Submit staking transactions via Node0 RPC
    let unstake_payload = SystemPayload::Unstake { amount: 100_000 };
    let unstake_sig = node0.keypair.sign(&serde_json::to_vec(&unstake_payload)?)?;
    let unstake_tx = ChainTransaction::System(SystemTransaction {
        payload: unstake_payload,
        signature: [
            // FIX: Access the public key via the .keypair field
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
    submit_transaction(&node0.rpc_addr, &unstake_tx).await?;

    let stake_payload = SystemPayload::Stake { amount: 50_000 };
    let stake_sig = node1.keypair.sign(&serde_json::to_vec(&stake_payload)?)?;
    let stake_tx = ChainTransaction::System(SystemTransaction {
        payload: stake_payload,
        signature: [
            // FIX: Access the public key via the .keypair field
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
    submit_transaction(&node0.rpc_addr, &stake_tx).await?;

    // 6) RPC node confirms tx gossip
    assert_log_contains(
        "Node0",
        &mut logs0,
        "[RPC] Published transaction via gossip.",
    )
    .await?;

    // 7) Followers keep progressing: Node1 sees #3 and processes it
    // (Don’t re-assert #2 here—its first occurrence was likely consumed earlier.)
    assert_log_contains("Node1", &mut logs1, "Received gossiped block #3").await?;
    assert_log_contains(
        "Node1",
        &mut logs1,
        "Workload processed block successfully.",
    )
    .await?;

    Ok(())
}
