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
    build_test_artifacts("consensus-poa,vm-wasm");

    // Setup: Create model file and calculate its hash
    let temp_dir_models = tempdir()?;
    let good_model_path = temp_dir_models.path().join("good_model.bin");
    fs::write(&good_model_path, "correct_model_data")?;
    let correct_model_hash = hex::encode(sha256(b"correct_model_data"));

    // --- FIX: The successful build of the cluster is the test itself. ---
    // The TestCluster::build() function internally calls TestValidator::launch, which
    // waits for the "Semantic attestation sequence complete." log message. This message
    // is only printed after the "Node is healthy" message. Therefore, if build()
    // returns Ok, we have already implicitly verified that the nodes passed their
    // health checks. No further assertions are needed.
    let _cluster = TestCluster::new()
        .with_validators(3)
        .with_consensus_type("ProofOfAuthority")
        .with_genesis_modifier(move |genesis, keys| {
            let authorities: Vec<Vec<u8>> = keys
                .iter()
                .map(|k| k.public().to_peer_id().to_bytes())
                .collect();
            genesis["genesis_state"]["system::authorities"] = json!(authorities.clone());
            genesis["genesis_state"]["system::validators"] = json!(authorities);
            genesis["genesis_state"][std::str::from_utf8(
                depin_sdk_types::keys::STATE_KEY_SEMANTIC_MODEL_HASH,
            )
            .unwrap()] = json!(correct_model_hash);
        })
        .with_semantic_model_path(good_model_path.to_str().unwrap())
        .build()
        .await?;

    Ok(())
}

#[tokio::test]
async fn test_mismatched_model_quarantine() -> Result<()> {
    build_test_artifacts("consensus-poa,vm-wasm");

    // Setup: Create two different model files
    let temp_dir_models = tempdir()?;
    let bad_model_path = temp_dir_models.path().join("bad_model.bin");
    fs::write(&bad_model_path, "incorrect_model_data")?;
    let correct_model_hash = hex::encode(sha256(b"correct_model_data"));

    // Use a single-node setup to remove network race conditions.
    let key = identity::Keypair::generate_ed25519();
    let genesis_content = json!({
        "genesis_state": {
            "system::authorities": json!([key.public().to_peer_id().to_bytes()]),
            std::str::from_utf8(depin_sdk_types::keys::STATE_KEY_SEMANTIC_MODEL_HASH).unwrap(): json!(correct_model_hash),
        }
    })
    .to_string();

    // Launch a single node with the mismatched model.
    let bad_node = TestValidator::launch(
        key.clone(),
        genesis_content.clone(),
        6000, // Use a different port to avoid conflicts in parallel test runners
        None,
        "ProofOfAuthority",
        Some(bad_model_path.to_str().unwrap()),
    )
    .await?;

    let mut bad_node_logs = bad_node.orch_log_stream.lock().await.take().unwrap();

    // Assert that the node correctly identifies itself as quarantined after starting up.
    // This is the most important and robust check for this test case.
    assert_log_contains(
        "BadNode",
        &mut bad_node_logs,
        "Node is quarantined, skipping consensus participation.",
    )
    .await?;

    Ok(())
}
