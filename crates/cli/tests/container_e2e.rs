// Path: crates/cli/tests/container_e2e.rs

// Gate the test to only compile when the necessary features are enabled for the cli crate.
#![cfg(all(feature = "consensus-poa", feature = "vm-wasm"))]

use anyhow::Result;
use ioi_cli::testing::{build_test_artifacts, TestCluster};
use ioi_crypto::algorithms::hash::sha256;
use serde_json::json;
use tempfile::tempdir;

#[tokio::test]
async fn test_secure_channel_and_attestation_flow_docker() -> Result<()> {
    // 1. SETUP: Build the test-only artifacts like contracts.
    // The node binaries will be built just-in-time by the test harness.
    build_test_artifacts();
    let temp_dir = tempdir()?;
    let model_path = temp_dir.path().join("model.bin");
    std::fs::write(&model_path, "dummy_model_data_for_docker_test")?;
    let correct_model_hash = hex::encode(sha256(b"dummy_model_data_for_docker_test").unwrap());

    // 2. LAUNCH CLUSTER
    // The .build().await? call will not return until the test harness's internal
    // readiness checks have passed. This implicitly verifies that all containers
    // (guardian, workload, orchestration) have started, connected, and that the
    // orchestration container has passed its agentic attestation check.
    // The successful completion of this line is the entire test.
    let cluster = TestCluster::builder()
        .with_validators(1)
        .use_docker_backend(true)
        .with_state_tree("IAVL") // Use a valid, production-grade tree
        .with_agentic_model_path(model_path.to_str().unwrap())
        .with_genesis_modifier(move |genesis, _keys| {
            genesis["genesis_state"]
                [std::str::from_utf8(ioi_types::keys::STATE_KEY_SEMANTIC_MODEL_HASH).unwrap()] =
                json!(correct_model_hash);
        })
        .build()
        .await?;

    // 3. CLEANUP & FINISH
    // If we reach this point without `build()` returning a timeout error, the test has passed.
    // Explicitly shut down all validators to satisfy the ValidatorGuard requirement.
    for guard in cluster.validators {
        guard.shutdown().await?;
    }

    println!("--- Secure Channel and Attestation E2E Test Passed ---");
    Ok(())
}
