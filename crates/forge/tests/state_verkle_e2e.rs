// Path: crates/forge/tests/state_verkle_e2e.rs
#![cfg(all(
    feature = "consensus-poa",
    feature = "vm-wasm",
    feature = "tree-verkle"
))]

use anyhow::Result;
use depin_sdk_forge::testing::{assert_log_contains, build_test_artifacts, TestCluster};
use serde_json::json;

#[tokio::test]
async fn test_verkle_tree_e2e() -> Result<()> {
    // 1. Build binaries with the specific Verkle feature enabled
    // Note: 'tree-verkle' implies 'primitive-kzg'
    build_test_artifacts("consensus-poa,vm-wasm,tree-verkle");

    // 2. Launch a cluster configured to use the VerkleTree
    let mut cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("ProofOfAuthority")
        .with_state_tree("Verkle")
        .with_commitment_scheme("KZG")
        .with_genesis_modifier(|genesis, keys| {
            let authority = keys[0].public().to_peer_id().to_bytes();
            genesis["genesis_state"]["system::authorities"] = json!([authority]);
        })
        .build()
        .await?;

    // 3. Assert that the node can produce a block
    let node = &mut cluster.validators[0];
    let mut orch_logs = node.orch_log_stream.lock().await.take().unwrap();
    assert_log_contains(
        "Orchestration-Verkle",
        &mut orch_logs,
        "Produced and processed new block #1",
    )
    .await?;

    println!("--- Verkle Tree E2E Test Passed ---");
    Ok(())
}
