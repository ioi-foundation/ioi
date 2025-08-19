// Path: crates/forge/tests/semantic_consensus_e2e.rs

use anyhow::Result;
use depin_sdk_crypto::algorithms::hash::sha256;
use depin_sdk_forge::testing::{
    assert_log_contains, build_test_artifacts, TestCluster, TestValidator,
};
use libp2p::identity;
use serde_json::json;
use std::fs;
use tempfile::tempdir;

#[tokio::test]
async fn test_secure_semantic_consensus_e2e() -> Result<()> {
    build_test_artifacts("consensus-poa,vm-wasm"); // Ensure all binaries are ready

    // Setup: Create model file and calculate its hash
    let temp_dir_models = tempdir()?;
    let good_model_path = temp_dir_models.path().join("good_model.bin");
    fs::write(&good_model_path, "correct_model_data")?;
    let correct_model_hash = hex::encode(sha256(b"correct_model_data"));

    // Launch a 3-node cluster to meet the committee size requirement
    let mut cluster = TestCluster::new()
        .with_validators(3)
        .with_consensus_type("ProofOfAuthority")
        .with_genesis_modifier(move |genesis, keys| {
            // Set authorities for PoA consensus
            let authorities: Vec<Vec<u8>> = keys
                .iter()
                .map(|k| k.public().to_peer_id().to_bytes())
                .collect();
            genesis["genesis_state"]["system::authorities"] = json!(authorities.clone());
            // FIX: Also set the validator set, which the test's mock logic uses to find the committee.
            genesis["genesis_state"]["system::validators"] = json!(authorities);
            // Set the correct model hash in the genesis state
            genesis["genesis_state"][std::str::from_utf8(
                depin_sdk_types::keys::STATE_KEY_SEMANTIC_MODEL_HASH,
            )
            .unwrap()] = json!(correct_model_hash);
        })
        .with_semantic_model_path(good_model_path.to_str().unwrap())
        .build()
        .await?;

    // Get handles for one of the nodes to check logs
    let node0 = &mut cluster.validators[0];
    let mut orch_logs = node0.orch_log_stream.lock().await.take().unwrap();

    // Assertions: Check the Orchestrator's log to verify the semantic attestation passed.
    assert_log_contains(
        "Orchestration",
        &mut orch_logs,
        "Semantic model hash matches on-chain state. Node is healthy.",
    )
    .await?;

    // This assertion can remain as a placeholder for the next phase of semantic consensus implementation.
    assert_log_contains(
        "Orchestration",
        &mut orch_logs,
        "Semantic consensus reached on hash:",
    )
    .await?;

    Ok(())
}

#[tokio::test]
async fn test_mismatched_model_quarantine() -> Result<()> {
    build_test_artifacts("consensus-poa,vm-wasm");

    // Setup: Create two different model files
    let temp_dir_models = tempdir()?;
    let good_model_path = temp_dir_models.path().join("good_model.bin");
    let bad_model_path = temp_dir_models.path().join("bad_model.bin");
    fs::write(&good_model_path, "correct_model_data")?;
    fs::write(&bad_model_path, "incorrect_model_data")?;
    let correct_model_hash = hex::encode(sha256(b"correct_model_data"));

    // Launch a 2-node cluster. Genesis is correct. Node 0 is correct. Node 1 is bad.
    let keys = (0..2)
        .map(|_| identity::Keypair::generate_ed25519())
        .collect::<Vec<_>>();
    let genesis_content = json!({
        "genesis_state": {
            "system::authorities": json!(keys.iter().map(|k| k.public().to_peer_id().to_bytes()).collect::<Vec<_>>()),
            std::str::from_utf8(depin_sdk_types::keys::STATE_KEY_SEMANTIC_MODEL_HASH).unwrap(): json!(correct_model_hash),
        }
    })
    .to_string();

    let node0 = TestValidator::launch(
        keys[0].clone(),
        genesis_content.clone(),
        5000,
        None,
        "ProofOfAuthority",
        Some(good_model_path.to_str().unwrap()),
    )
    .await?;

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let bad_node = TestValidator::launch(
        keys[1].clone(),
        genesis_content.clone(),
        5010,
        Some(&node0.p2p_addr),
        "ProofOfAuthority",
        Some(bad_model_path.to_str().unwrap()),
    )
    .await?;

    let mut node0_logs = node0.orch_log_stream.lock().await.take().unwrap();
    let mut bad_node_logs = bad_node.orch_log_stream.lock().await.take().unwrap();

    // Assert that the bad node connects to the good node
    assert_log_contains(
        "BadNode",
        &mut bad_node_logs,
        &format!("Connection established with peer {}", node0.peer_id),
    )
    .await?;

    // Assert that the good node sees the connection from the bad node
    assert_log_contains(
        "Node0",
        &mut node0_logs,
        &format!("Connection established with peer {}", bad_node.peer_id),
    )
    .await?;

    // Assertions: Check the logs of the "bad" node's Orchestrator for the failure and quarantine messages.
    assert_log_contains(
        "Orchestration",
        &mut bad_node_logs,
        "Model Integrity Failure!",
    )
    .await?;
    assert_log_contains(
        "Orchestration",
        &mut bad_node_logs,
        "Node is quarantined, skipping consensus participation.",
    )
    .await?;

    Ok(())
}
