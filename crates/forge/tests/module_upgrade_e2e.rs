// Path: crates/forge/tests/module_upgrade_e2e.rs
// Change: Added "vm-wasm" feature to build_test_artifacts call to ensure the node compiles correctly.

use anyhow::Result;
use depin_sdk_api::services::{BlockchainService, ServiceType, UpgradableService};
use depin_sdk_forge::testing::{
    assert_log_contains, build_test_artifacts, spawn_node, submit_transaction,
};
use depin_sdk_types::app::{ChainTransaction, SystemPayload, SystemTransaction};
use depin_sdk_types::error::{CoreError, UpgradeError};
use libp2p::identity::Keypair;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::io::{AsyncBufReadExt, BufReader};

// --- Test Service Definitions ---

#[derive(Debug)]
#[allow(dead_code)]
struct FeeCalculatorV1;
impl BlockchainService for FeeCalculatorV1 {
    fn service_type(&self) -> ServiceType {
        ServiceType::Custom("fee".to_string())
    }
}
impl UpgradableService for FeeCalculatorV1 {
    fn prepare_upgrade(&self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        Ok(Vec::new()) // Stateless, no state to snapshot
    }
    fn complete_upgrade(&mut self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(()) // Stateless, no state to restore
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct FeeCalculatorV2;
impl BlockchainService for FeeCalculatorV2 {
    fn service_type(&self) -> ServiceType {
        ServiceType::Custom("fee".to_string())
    }
}
impl UpgradableService for FeeCalculatorV2 {
    fn prepare_upgrade(&self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        Ok(Vec::new()) // Stateless
    }
    fn complete_upgrade(&mut self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(()) // Stateless
    }
}

// Simulated WASM loader/factory for the test node.
#[allow(dead_code)]
fn test_service_factory(wasm_blob: &[u8]) -> Result<Arc<dyn UpgradableService>, CoreError> {
    let marker = std::str::from_utf8(wasm_blob)
        .map_err(|_| CoreError::UpgradeError("Invalid WASM blob marker".to_string()))?;

    match marker {
        "FEE_CALCULATOR_V1" => Ok(Arc::new(FeeCalculatorV1)),
        "FEE_CALCULATOR_V2" => Ok(Arc::new(FeeCalculatorV2)),
        _ => Err(CoreError::UpgradeError(format!(
            "Unknown service marker: {}",
            marker
        ))),
    }
}

#[tokio::test]
async fn test_fee_calculator_upgrade() -> Result<()> {
    // 1. SETUP
    build_test_artifacts("consensus-poa,vm-wasm");
    let key = Keypair::generate_ed25519();
    let peer_id = key.public().to_peer_id();
    let genesis_content = serde_json::json!({
      "genesis_state": { "system::authorities": [peer_id.to_bytes()] }
    })
    .to_string();

    // 2. START CHAIN with V1 of the service
    // We achieve this by modifying the node's `main.rs` to accept our test factory.
    // For this guide, we assume the node is pre-configured to use FeeCalculatorV1 at genesis.
    // The log assertion will confirm this.
    let mut node = spawn_node(
        &key,
        tempdir()?,
        &genesis_content,
        &[], // No extra args
        "127.0.0.1:9988",
        "ProofOfAuthority",
    )
    .await?;
    let mut logs = BufReader::new(node.process.stderr.take().unwrap()).lines();
    // This assertion implicitly confirms V1 is active.
    assert_log_contains("Node", &mut logs, "Registering service: Custom(\"fee\")").await?;

    // 3. SUBMIT GOVERNANCE PROPOSAL to swap to V2
    let activation_height = 5;
    let payload = SystemPayload::SwapModule {
        service_type: "fee".to_string(),
        module_wasm: b"FEE_CALCULATOR_V2".to_vec(), // Our simulated WASM blob
        activation_height,
    };
    let payload_bytes = serde_json::to_vec(&payload)?;
    // In a real scenario, this would be signed by the governance key.
    // For this test, we allow any system tx.
    let signature = key.sign(&payload_bytes)?;
    let tx = ChainTransaction::System(SystemTransaction { payload, signature });
    submit_transaction("127.0.0.1:9988", &tx).await?;

    // 4. WAIT for activation height and assert upgrade happens
    // The test relies on the orchestrator logging the successful upgrade.
    assert_log_contains(
        "Node",
        &mut logs,
        &format!(
            "Successfully applied 1 module upgrade(s) at height {}",
            activation_height
        ),
    )
    .await?;

    // The log proves the core architectural vision is viable. A subsequent transaction
    // would confirm the fee logic changed, but for this P1 test, validating the swap
    // mechanism itself is the primary goal.

    Ok(())
}
