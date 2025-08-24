// Path: crates/forge/tests/module_upgrade_e2e.rs

#![cfg(all(feature = "consensus-poa", feature = "vm-wasm"))]

use anyhow::Result;
use depin_sdk_forge::testing::{
    assert_log_contains, build_test_artifacts, submit_transaction, TestCluster,
};
use depin_sdk_types::app::{ChainTransaction, SystemPayload, SystemTransaction};
use serde_json::json;

#[tokio::test]
async fn test_forkless_module_upgrade() -> Result<()> {
    // 1. SETUP & BUILD
    build_test_artifacts("consensus-poa,vm-wasm,tree-file,primitive-hash");
    let service_v2_wasm =
        std::fs::read("../../target/wasm32-unknown-unknown/release/test_service_v2.wasm")?;

    // 2. LAUNCH CLUSTER
    let mut cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("ProofOfAuthority")
        .with_genesis_modifier(|genesis, keys| {
            let authority_peer_id = keys[0].public().to_peer_id();
            genesis["genesis_state"]["system::authorities"] = json!([authority_peer_id.to_bytes()]);
        })
        .build()
        .await?;

    // 3. GET HANDLES
    let node = &mut cluster.validators[0];
    let rpc_addr = &node.rpc_addr;
    let keypair = &node.keypair;
    let mut workload_logs = node.workload_log_stream.lock().await.take().unwrap();

    // 4. SUBMIT UPGRADE TRANSACTION
    let activation_height = 5;
    let payload = SystemPayload::SwapModule {
        service_type: "fee_calculator_v2".to_string(),
        module_wasm: service_v2_wasm,
        activation_height,
    };

    let payload_bytes = serde_json::to_vec(&payload)?;
    let signature_bytes = keypair.sign(&payload_bytes)?;
    let pubkey_bytes = keypair.public().try_into_ed25519()?.to_bytes().to_vec();

    let tx = ChainTransaction::System(SystemTransaction {
        payload,
        signature: [pubkey_bytes, signature_bytes].concat(),
    });

    submit_transaction(rpc_addr, &tx).await?;

    // 5. WAIT & ASSERT
    // The test will wait for the node to produce blocks until it reaches the activation height.
    // We assert that the log message confirming the upgrade application is present in the Workload container's output.
    assert_log_contains(
        "Workload",
        &mut workload_logs,
        &format!(
            "Applied 1 module upgrade(s) at height {}",
            activation_height
        ),
    )
    .await?;

    println!("--- Forkless Module Upgrade E2E Test Successful ---");

    Ok(())
}
