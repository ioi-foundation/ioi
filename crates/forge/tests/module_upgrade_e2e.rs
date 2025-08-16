// Path: crates/forge/tests/module_upgrade_e2e.rs

use anyhow::Result;
use depin_sdk_forge::testing::{
    assert_log_contains, build_test_artifacts, submit_transaction, TestCluster,
};
use depin_sdk_types::app::{ChainTransaction, SystemPayload, SystemTransaction};
// FIX: Remove unused import
// use libp2p::identity::Keypair;
use serde_json::json;

#[tokio::test]
async fn test_forkless_module_upgrade() -> Result<()> {
    // 1. SETUP & BUILD
    // Ensure the node and our test WASM service are built.
    build_test_artifacts("consensus-poa,vm-wasm");
    let service_v2_wasm =
        std::fs::read("../../target/wasm32-unknown-unknown/release/test_service_v2.wasm")?;

    // 2. LAUNCH CLUSTER
    // Start a single-node cluster. The genesis state makes the node its own authority.
    let mut cluster = TestCluster::new()
        .with_validators(1)
        .with_consensus_type("ProofOfAuthority")
        .with_genesis_modifier(|genesis, keys| {
            let authority_peer_id = keys[0].public().to_peer_id();
            genesis["genesis_state"]["system::authorities"] = json!([authority_peer_id.to_bytes()]);
        })
        .build()
        .await?;

    // 3. GET HANDLES
    // Get a mutable handle to the node, its RPC address, keypair, and log stream.
    let node = &mut cluster.validators[0];
    let rpc_addr = &node.rpc_addr;
    let keypair = &node.keypair;
    // FIX: The upgrade logs are emitted by the Workload container, not the Orchestration one.
    let mut workload_logs = node.workload_log_stream.lock().await.take().unwrap();

    // The node starts with no services registered. The upgrade will be the first one.

    // 4. SUBMIT UPGRADE TRANSACTION
    // The upgrade is scheduled to activate at block height 5.
    let activation_height = 5;
    let payload = SystemPayload::SwapModule {
        service_type: "fee_calculator_v2".to_string(), // This MUST match the string returned by the WASM's `service_type` function
        module_wasm: service_v2_wasm,
        activation_height,
    };

    let payload_bytes = serde_json::to_vec(&payload)?;
    // In a real network, this tx must be signed by the governance authority.
    // In our test setup, the validator is the authority, so its signature is valid.
    let signature = keypair.sign(&payload_bytes)?;
    let tx = ChainTransaction::System(SystemTransaction { payload, signature });

    submit_transaction(rpc_addr, &tx).await?;

    // Assert that the transaction was accepted and the upgrade was scheduled.
    // FIX: Listen to the Workload logs for the scheduling message.
    assert_log_contains(
        "Workload",
        &mut workload_logs,
        &format!(
            "Scheduling module upgrade for Custom(\"fee_calculator_v2\") at height {}",
            activation_height
        ),
    )
    .await?;

    // 5. WAIT & ASSERT
    // The test will now wait for the node to produce blocks until it reaches the activation height.
    // The `assert_log_contains` has a generous timeout to allow for this.
    // We expect to see a log message confirming the upgrade was successfully applied.
    // FIX: Listen to the Workload logs for the apply message.
    assert_log_contains(
        "Workload",
        &mut workload_logs,
        &format!(
            "Successfully applied 1 module upgrade(s) at height {}",
            activation_height
        ),
    )
    .await?;

    println!("--- Forkless Module Upgrade E2E Test Successful ---");

    Ok(())
}
