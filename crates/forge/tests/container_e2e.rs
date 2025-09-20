// Path: crates/forge/tests/container_e2e.rs

// Gate the test to only compile when the necessary features are enabled for the forge crate.
#![cfg(all(feature = "consensus-poa", feature = "vm-wasm"))]

use anyhow::Result;
use depin_sdk_crypto::algorithms::hash::sha256;
use depin_sdk_forge::testing::{build_test_artifacts, TestCluster};
use serde_json::json;
use tempfile::tempdir;

#[tokio::test]
async fn test_secure_channel_and_attestation_flow_docker() -> Result<()> {
    // 1. SETUP: Build the node binaries with all features required by the test.
    // The TestClusterBuilder defaults to a IAVLTree + HashCommitmentScheme backend,
    // so we must include the `tree-iavl` and `primitive-hash` features.
    build_test_artifacts("consensus-poa,vm-wasm,tree-iavl,primitive-hash");
    let temp_dir = tempdir()?;
    let model_path = temp_dir.path().join("model.bin");
    std::fs::write(&model_path, "dummy_model_data_for_docker_test")?;
    let correct_model_hash = hex::encode(sha256(b"dummy_model_data_for_docker_test"));

    // 2. LAUNCH CLUSTER
    // The .build().await? call will not return until the test harness's internal
    // readiness checks have passed. This implicitly verifies that all containers
    // (guardian, workload, orchestration) have started, connected, and that the
    // orchestration container has passed its agentic attestation check.
    // The successful completion of this line is the entire test.
    let _cluster = TestCluster::builder()
        .with_validators(1)
        .use_docker_backend(true)
        .with_state_tree("IAVL") // Use a valid, production-grade tree
        .with_agentic_model_path(model_path.to_str().unwrap())
        .with_genesis_modifier(move |genesis, _keys| {
            genesis["genesis_state"][std::str::from_utf8(
                depin_sdk_types::keys::STATE_KEY_SEMANTIC_MODEL_HASH,
            )
            .unwrap()] = json!(correct_model_hash);
        })
        .build()
        .await?;

    // 3. CLEANUP & FINISH
    // If we reach this point without `build()` returning a timeout error, the test has passed.

    println!("--- Secure Channel and Attestation E2E Test Passed ---");
    Ok(())
}
