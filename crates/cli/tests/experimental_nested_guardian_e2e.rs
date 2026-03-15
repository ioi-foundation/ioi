#![cfg(all(
    feature = "consensus-convergent",
    feature = "vm-wasm",
    feature = "state-iavl"
))]

use anyhow::Result;
use ioi_cli::testing::{build_test_artifacts, rpc, wait_for_height, TestCluster};
use ioi_types::config::ConvergentSafetyMode;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_experimental_nested_guardian_live_cluster_emits_witness_certificates() -> Result<()> {
    build_test_artifacts();

    let cluster = TestCluster::builder()
        .with_validators(3)
        .with_consensus_type("Convergent")
        .with_state_tree("IAVL")
        .with_chain_id(17)
        .with_convergent_safety_mode(ConvergentSafetyMode::ExperimentalNestedGuardian)
        .build()
        .await?;

    let rpc_addr = cluster.validators[0].validator().rpc_addr.clone();

    let test_logic = async {
        let target_height = 5;
        wait_for_height(&rpc_addr, target_height, Duration::from_secs(60)).await?;

        for height in 2..=target_height {
            let block = rpc::get_block_by_height_resilient(&rpc_addr, height)
                .await?
                .ok_or_else(|| anyhow::anyhow!("missing block at height {height}"))?;
            let certificate = block.header.guardian_certificate.as_ref().ok_or_else(|| {
                anyhow::anyhow!("missing guardian certificate at height {height}")
            })?;
            let witness_certificate = certificate
                .experimental_witness_certificate
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing witness certificate at height {height}"))?;
            assert_ne!(witness_certificate.manifest_hash, [0u8; 32]);
            assert!(
                !witness_certificate.aggregated_signature.is_empty(),
                "empty witness aggregated signature at height {}",
                height
            );
        }

        Ok(())
    };

    let result = test_logic.await;
    if let Err(error) = cluster.shutdown().await {
        eprintln!("Error shutting down cluster: {}", error);
    }
    result
}
