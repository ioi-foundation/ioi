// Path: crates/forge/tests/oracle_e2e.rs

#![cfg(all(
    feature = "consensus-pos",
    feature = "vm-wasm",
    feature = "tree-file",
    feature = "primitive-hash"
))]

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use depin_sdk_forge::testing::{
    assert_log_contains, build_test_artifacts, submit_transaction, TestCluster,
};
use depin_sdk_types::app::{ChainTransaction, SystemPayload, SystemTransaction};
use depin_sdk_types::keys::{STAKES_KEY_CURRENT, STAKES_KEY_NEXT};
use serde_json::json;

#[tokio::test]
async fn test_validator_native_oracle_e2e() -> Result<()> {
    // 1. SETUP: Build artifacts and launch a 4-node PoS cluster.
    build_test_artifacts("consensus-pos,vm-wasm,tree-file,primitive-hash");

    let cluster = TestCluster::builder()
        .with_validators(4)
        .with_consensus_type("ProofOfStake")
        .with_genesis_modifier(|genesis, keys| {
            let stakes: serde_json::Value = keys
                .iter()
                .map(|k| (k.public().to_peer_id().to_base58(), json!(100_000)))
                .collect();
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

    let node0_rpc = &cluster.validators[0].rpc_addr;
    let mut logs1 = cluster.validators[1]
        .orch_log_stream
        .lock()
        .await
        .take()
        .unwrap();
    let mut logs2 = cluster.validators[2]
        .orch_log_stream
        .lock()
        .await
        .take()
        .unwrap();
    let mut orch_logs3 = cluster.validators[3]
        .orch_log_stream
        .lock()
        .await
        .take()
        .unwrap();
    let mut workload_logs3 = cluster.validators[3]
        .workload_log_stream
        .lock()
        .await
        .take()
        .unwrap();

    // Wait for network to stabilize
    assert_log_contains("Node 3", &mut orch_logs3, "Received gossiped block #1").await?;

    // 2. SUBMIT ORACLE REQUEST TRANSACTION
    let request_id = 101;
    let payload = SystemPayload::RequestOracleData {
        url: "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd"
            .to_string(),
        request_id,
    };
    let payload_bytes = serde_json::to_vec(&payload)?;
    let signature_bytes = cluster.validators[0].keypair.sign(&payload_bytes)?;
    let pubkey_bytes = cluster.validators[0]
        .keypair
        .public()
        .try_into_ed25519()?
        .to_bytes()
        .to_vec();

    let request_tx = ChainTransaction::System(SystemTransaction {
        payload,
        signature: [pubkey_bytes, signature_bytes].concat(),
    });
    submit_transaction(node0_rpc, &request_tx).await?;

    // 3. ASSERT ATTESTATION GOSSIP
    assert_log_contains(
        "Node 1",
        &mut logs1,
        &format!("Oracle: Received attestation for request_id {}", request_id),
    )
    .await?;
    assert_log_contains(
        "Node 2",
        &mut logs2,
        &format!("Oracle: Received attestation for request_id {}", request_id),
    )
    .await?;

    // 4. ASSERT QUORUM AND SUBMISSION
    assert_log_contains(
        "Node 1",
        &mut logs1,
        &format!(
            "Oracle: Submitted finalization transaction for request_id {} to local mempool.",
            request_id
        ),
    )
    .await?;

    // 5. ASSERT ON-CHAIN FINALIZATION
    assert_log_contains(
        "Workload 3",
        &mut workload_logs3,
        &format!("Applied and verified oracle data for id: {}", request_id),
    )
    .await?;

    println!("--- Validator-Native Oracle E2E Test Passed ---");
    Ok(())
}
