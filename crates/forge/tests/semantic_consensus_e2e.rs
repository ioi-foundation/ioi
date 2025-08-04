// crates/forge/tests/semantic_consensus_e2e.rs
use anyhow::Result;
use depin_sdk_crypto::algorithms::hash::sha256;
use depin_sdk_forge::testing::{
    build_test_artifacts,
    spawn_node, // submit_transaction,
};
use depin_sdk_types::keys::STATE_KEY_SEMANTIC_MODEL_HASH;
use libp2p::identity::Keypair;
use std::fs;
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::time::timeout;

#[tokio::test]
async fn test_secure_semantic_consensus_e2e() -> Result<()> {
    build_test_artifacts("consensus-poa,vm-wasm");

    let key = Keypair::generate_ed25519();
    let peer_id = key.public().to_peer_id();
    let temp_dir_models = tempdir()?;
    let good_model_path = temp_dir_models.path().join("good_model.bin");
    fs::write(&good_model_path, "correct_model_data")?;
    let correct_model_hash = sha256(b"correct_model_data");

    let genesis_content = serde_json::json!({
      "genesis_state": {
          "system::authorities": [peer_id.to_bytes()],
          std::str::from_utf8(STATE_KEY_SEMANTIC_MODEL_HASH).unwrap(): hex::encode(&correct_model_hash)
      }
    })
    .to_string();

    let mut node = spawn_node(
        &key,
        tempdir()?,
        &genesis_content,
        &["--semantic-model-path", good_model_path.to_str().unwrap()],
        "127.0.0.1:9977",
        "ProofOfAuthority",
    )
    .await?;
    let mut logs = BufReader::new(node.process.stderr.take().unwrap()).lines();

    // **REVISED TEST LOGIC**
    // Capture all logs until the final "settle" log appears, or timeout.
    // This is more robust against async ordering issues.
    let mut log_buffer = String::new();
    let final_log_pattern = "GasEscrowHandler::settle() called";

    timeout(Duration::from_secs(45), async {
        while let Ok(Some(line)) = logs.next_line().await {
            println!("[LOGS-Node] {}", line);
            log_buffer.push_str(&line);
            log_buffer.push('\n');
            if line.contains(final_log_pattern) {
                return;
            }
        }
    })
    .await?;

    // Now, assert that all required patterns exist in the captured buffer.
    assert!(log_buffer.contains("GasEscrowHandler::bond() called"));
    assert!(log_buffer.contains("PromptWrapper created canonical prompt"));
    assert!(log_buffer.contains("Guardian::attest_weights() check passed."));
    assert!(log_buffer.contains("OutputNormaliser produced identical hash:"));
    assert!(log_buffer.contains("Semantic consensus reached on hash:"));
    assert!(log_buffer.contains("Executed semantic operation: token_transfer"));
    assert!(log_buffer.contains(final_log_pattern));

    Ok(())
}

#[tokio::test]
async fn test_mismatched_model_quarantine() -> Result<()> {
    build_test_artifacts("consensus-poa,vm-wasm");
    let key = Keypair::generate_ed25519();
    let peer_id = key.public().to_peer_id();

    let temp_dir_models = tempdir()?;
    let bad_model_path = temp_dir_models.path().join("bad_model.bin");
    fs::write(&bad_model_path, "incorrect_model_data")?;
    let correct_hash = sha256(b"correct_model_data");

    let genesis_content = serde_json::json!({
      "genesis_state": {
          "system::authorities": [peer_id.to_bytes()],
          std::str::from_utf8(STATE_KEY_SEMANTIC_MODEL_HASH).unwrap(): hex::encode(&correct_hash)
      }
    })
    .to_string();

    let mut bad_node = spawn_node(
        &key,
        tempdir()?,
        &genesis_content,
        &["--semantic-model-path", bad_model_path.to_str().unwrap()],
        "127.0.0.1:9978",
        "ProofOfAuthority",
    )
    .await?;
    let mut logs = BufReader::new(bad_node.process.stderr.take().unwrap()).lines();

    // Use the same robust log capturing strategy for this test.
    let mut log_buffer = String::new();
    let final_log_pattern = "Node is quarantined, skipping consensus participation.";

    timeout(Duration::from_secs(45), async {
        while let Ok(Some(line)) = logs.next_line().await {
            println!("[LOGS-Node] {}", line);
            log_buffer.push_str(&line);
            log_buffer.push('\n');
            if line.contains(final_log_pattern) {
                return;
            }
        }
    })
    .await?;

    assert!(log_buffer.contains("Model Integrity Failure!"));
    assert!(log_buffer.contains(final_log_pattern));

    Ok(())
}
