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

    // Launch a 1-node cluster, configured with the correct model and genesis state
    let mut cluster = TestCluster::new()
        .with_validators(1)
        .with_consensus_type("ProofOfAuthority")
        .with_genesis_modifier(move |genesis, keys| {
            // Set authorities for PoA consensus
            let authorities: Vec<Vec<u8>> = keys
                .iter()
                .map(|k| k.public().to_peer_id().to_bytes())
                .collect();
            genesis["genesis_state"]["system::authorities"] = json!(authorities);
            // Set the correct model hash in the genesis state
            genesis["genesis_state"][std::str::from_utf8(
                depin_sdk_types::keys::STATE_KEY_SEMANTIC_MODEL_HASH,
            )
            .unwrap()] = json!(correct_model_hash);
        })
        .with_semantic_model_path(good_model_path.to_str().unwrap()) // NEW: Pass model path to builder
        .build()
        .await?;

    // Get handles for one of the nodes to check logs
    let node0 = &mut cluster.validators[0];
    let mut _workload_logs = node0.workload_log_stream.lock().await.take().unwrap();
    let mut guardian_logs = node0.guardian_log_stream.lock().await.take().unwrap();
    let mut orch_logs = node0.orch_log_stream.lock().await.take().unwrap();

    // Action: Submit a semantic transaction (this part needs a new RPC endpoint or test hook)
    // For now, the test just verifies the startup attestation and mock consensus.

    // Assertions: Check logs in order to verify the entire pipeline
    assert_log_contains(
        "Guardian",
        &mut guardian_logs,
        "Guardian::attest_weights() check passed.",
    )
    .await?;
    assert_log_contains(
        "Orchestration",
        &mut orch_logs,
        "Semantic consensus reached on hash:",
    )
    .await?;
    // The following logs would be asserted after a real semantic transaction is submitted
    // assert_log_contains("Workload", &mut workload_logs, "GasEscrowHandler::bond() called").await?;
    // assert_log_contains("Workload", &mut workload_logs, "Executed semantic operation: token_transfer").await?;
    // assert_log_contains("Workload", &mut workload_logs, "GasEscrowHandler::settle() called").await?;

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
    let mut bad_node = TestValidator::launch(
        keys[1].clone(),
        genesis_content.clone(),
        5010,
        Some(&node0.p2p_addr),
        "ProofOfAuthority",
        Some(bad_model_path.to_str().unwrap()),
    )
    .await?;

    // Action: No action needed. The failure happens on startup.

    // Assertions: Check the logs of the "bad" node for the failure and quarantine messages.
    let mut bad_guardian_logs = bad_node.guardian_log_stream.lock().await.take().unwrap();
    let mut bad_orch_logs = bad_node.orch_log_stream.lock().await.take().unwrap();

    assert_log_contains(
        "Guardian",
        &mut bad_guardian_logs,
        "Model Integrity Failure!",
    )
    .await?;
    assert_log_contains(
        "Orchestration",
        &mut bad_orch_logs,
        "Node is quarantined, skipping consensus participation.",
    )
    .await?;

    Ok(())
}
