// In crates/forge/tests/staking_e2e.rs

use anyhow::Result;
use depin_sdk_forge::testing::{
    assert_log_contains, build_test_artifacts, submit_transaction, TestCluster,
};
use depin_sdk_types::app::{ChainTransaction, SystemPayload, SystemTransaction};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, BufReader};

#[tokio::test]
async fn test_staking_lifecycle() -> Result<()> {
    // A. Setup
    build_test_artifacts("consensus-pos,vm-wasm");

    // B. Launch Cluster using the new builder
    let mut cluster = TestCluster::new()
        .with_validators(3)
        .with_genesis_modifier(|genesis, keys| {
            let initial_staker_peer_id = keys[0].public().to_peer_id();
            genesis["genesis_state"]["system::stakes"] = json!({
                initial_staker_peer_id.to_base58(): 100000
            });
        })
        .build()
        .await?;

    // C. Get handles to nodes and logs
    let (node1_slice, rest) = cluster.validators.split_at_mut(1);
    let node1 = &mut node1_slice[0];
    let node2 = &mut rest[0];

    // FIX: Get the log streams from the new field in TestValidator.
    // Also, fix the unused variable warning for logs1, as it's not needed.
    let _logs1 = node1.orch_log_stream.lock().await.take().unwrap();
    let mut logs2 = node2.orch_log_stream.lock().await.take().unwrap();

    // D. Execute the test logic
    println!("--- Submitting Unstake transaction for Node 1 ---");
    let unstake_payload = SystemPayload::Unstake { amount: 100000 };
    let unstake_payload_bytes = serde_json::to_vec(&unstake_payload)?;
    let unstake_signature = node1.keypair.sign(&unstake_payload_bytes)?;
    let unstake_tx = ChainTransaction::System(SystemTransaction {
        payload: unstake_payload,
        signature: [
            node1
                .keypair
                .public()
                .try_into_ed25519()?
                .to_bytes()
                .as_ref(),
            &unstake_signature,
        ]
        .concat(),
    });
    submit_transaction(&node1.rpc_addr, &unstake_tx).await?;

    println!("--- Submitting Stake transaction for Node 2 ---");
    let stake_payload = SystemPayload::Stake { amount: 50000 };
    let stake_payload_bytes = serde_json::to_vec(&stake_payload)?;
    let stake_signature = node2.keypair.sign(&stake_payload_bytes)?;
    let stake_tx = ChainTransaction::System(SystemTransaction {
        payload: stake_payload,
        signature: [
            node2
                .keypair
                .public()
                .try_into_ed25519()?
                .to_bytes()
                .as_ref(),
            &stake_signature,
        ]
        .concat(),
    });
    submit_transaction(&node1.rpc_addr, &stake_tx).await?;

    // E. Assert the outcomes
    println!("--- Verifying state transition: Node 2 becomes the new leader ---");
    assert_log_contains("Node2", &mut logs2, "Consensus decision: Produce block").await?;

    Ok(())
}
