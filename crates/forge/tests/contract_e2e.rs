// Path: crates/forge/tests/contract_e2e.rs

//! End-to-End Test: Smart Contract Execution Lifecycle

use anyhow::Result;
use depin_sdk_core::app::{ApplicationTransaction, ProtocolTransaction};
use depin_sdk_forge::testing::{
    assert_log_contains, build_node_binary, spawn_node, submit_transaction,
};
use libp2p::identity;
use tempfile::tempdir;
use tokio::io::{AsyncBufReadExt, BufReader};

// A helper to query contract state would be added to `forge::testing` in the future.
// For now, this is a placeholder.
// async fn query_contract_state(rpc_addr: &str, contract_address: &[u8], input_data: &[u8]) -> Result<Vec<u8>> {
//     // ... implementation for an RPC `query` method ...
//     Ok(vec![1]) // Placeholder
// }

#[tokio::test]
#[ignore] // This test is long-running and requires a build script and RPC query support.
async fn test_contract_deployment_and_execution_lifecycle() -> Result<()> {
    // 1. COMPILE CONTRACT
    // In a real scenario, a build.rs script in `forge` or a `forge build`
    // command would compile the contract WASM.
    // For this test, we'll assume a dummy wasm binary.
    let contract_wasm = b"\0asm\x01\0\0\0".to_vec(); // Dummy WASM header

    // 2. SETUP NETWORK
    println!("--- Building Node Binary for Contract Test ---");
    build_node_binary("consensus-poa,vm-wasm");

    let key = identity::Keypair::generate_ed25519();
    let peer_id = key.public().to_peer_id();

    let genesis_content = serde_json::json!({
      "genesis_state": {
        "system::authorities": [peer_id.to_base58()]
      }
    });
    let genesis_string = genesis_content.to_string();

    let mut node = spawn_node(
        &key,
        tempdir()?,
        &genesis_string,
        &["--listen-address", "/ip4/127.0.0.1/tcp/4021"],
        "127.0.0.1:9964",
        "ProofOfAuthority",
    )
    .await?;
    let mut logs = BufReader::new(node.process.stderr.take().unwrap()).lines();

    // 3. DEPLOY CONTRACT
    let deploy_tx = ProtocolTransaction::Application(ApplicationTransaction::DeployContract {
        code: contract_wasm,
    });
    submit_transaction("127.0.0.1:9964", &deploy_tx).await?;

    // 4. VERIFY DEPLOYMENT
    // We would need a way to get the contract address, e.g., from RPC or logs.
    assert_log_contains("Node", &mut logs, "Deployed contract at address:").await?;
    // In a real test, we would parse the address from the log line.
    // let contract_address = ...;

    // 5. CALL INCREMENT (Placeholder)
    // let increment_input = vec![...]; // The ABI-encoded call to increment()
    // let call_tx_1 = ProtocolTransaction::Application(
    //     ApplicationTransaction::CallContract {
    //         address: contract_address.clone(),
    //         input_data: increment_input
    //     }
    // );
    // submit_transaction("127.0.0.1:9964", &call_tx_1).await?;
    // assert_log_contains(&mut logs, "Contract call successful").await?;

    // 6. CALL GET AND VERIFY (Placeholder)
    // let get_input = vec![...]; // The ABI-encoded call to get()
    // let counter_value = query_contract_state("127.0.0.1:9964", &contract_address, &get_input).await?;
    // assert_eq!(counter_value, vec![1]);

    println!("--- E2E Contract Test Placeholder ---");
    Ok(())
}
