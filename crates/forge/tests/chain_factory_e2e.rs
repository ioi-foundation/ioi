// Path: crates/forge/tests/chain_factory_e2e.rs

#![cfg(all(
    feature = "consensus-poa",
    feature = "consensus-pos",
    feature = "vm-wasm",
    feature = "tree-file",
    feature = "tree-hashmap",
    feature = "primitive-hash"
))]

use anyhow::Result;
use depin_sdk_forge::testing::{assert_log_contains, build_test_artifacts, TestCluster};
use serde_json::json;

#[tokio::test]
async fn test_concurrent_polymorphic_chains() -> Result<()> {
    // Build binaries with all necessary features enabled for both clusters.
    build_test_artifacts(
        "consensus-poa,consensus-pos,vm-wasm,tree-file,tree-hashmap,primitive-hash",
    );

    // --- Define Cluster A: Proof of Authority with FileStateTree ---
    let cluster_a_handle = tokio::spawn(async {
        let mut cluster = TestCluster::builder()
            .with_validators(1)
            .with_consensus_type("ProofOfAuthority")
            .with_state_tree("File")
            .with_commitment_scheme("Hash")
            .with_genesis_modifier(|genesis, keys| {
                let authority = keys[0].public().to_peer_id().to_bytes();
                genesis["genesis_state"]["system::authorities"] = json!([authority]);
            })
            .build()
            .await
            .expect("Failed to build Cluster A");

        let node = &mut cluster.validators[0];
        let mut logs = node.orch_log_stream.lock().await.take().unwrap();
        assert_log_contains(
            "Cluster A",
            &mut logs,
            "Produced and processed new block #1",
        )
        .await
    });

    // --- Define Cluster B: Proof of Stake with HashMapStateTree ---
    let cluster_b_handle = tokio::spawn(async {
        let mut cluster = TestCluster::builder()
            .with_validators(1)
            .with_consensus_type("ProofOfStake")
            .with_state_tree("HashMap")
            .with_commitment_scheme("Hash")
            .with_genesis_modifier(|genesis, keys| {
                let staker_id = keys[0].public().to_peer_id().to_base58();
                let stakes = json!({ staker_id: 100_000 });
                // The genesis loader will serialize this JSON object into bytes correctly.
                genesis["genesis_state"]["system::stakes::current"] = stakes.clone();
                genesis["genesis_state"]["system::stakes::next"] = stakes;
            })
            .build()
            .await
            .expect("Failed to build Cluster B");

        let node = &mut cluster.validators[0];
        let mut logs = node.orch_log_stream.lock().await.take().unwrap();
        assert_log_contains(
            "Cluster B",
            &mut logs,
            "Produced and processed new block #1",
        )
        .await
    });

    // Launch both concurrently and await results.
    let (res_a, res_b) = tokio::join!(cluster_a_handle, cluster_b_handle);

    res_a??; // Propagate any errors from cluster A's Tokio task and its Result
    res_b??; // Propagate any errors from cluster B's Tokio task and its Result

    println!("--- Comprehensive Polymorphism E2E Test Passed ---");

    Ok(())
}
