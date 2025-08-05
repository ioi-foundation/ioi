// Path: crates/forge/tests/contract_e2e.rs
//! End-to-End Test: Smart Contract Execution Lifecycle

use anyhow::{anyhow, Result};
use depin_sdk_forge::testing::{
    assert_log_contains, assert_log_contains_and_return_line, build_test_artifacts, spawn_node,
    submit_transaction,
};
use depin_sdk_types::app::{ApplicationTransaction, ChainTransaction};
use libp2p::identity::Keypair;
use reqwest::Client;
use tempfile::tempdir;
use tokio::io::{AsyncBufReadExt, BufReader};

// Helper function to create a signed transaction
fn create_signed_tx(keypair: &Keypair, tx: ApplicationTransaction) -> ChainTransaction {
    let payload = tx.to_signature_payload();
    let signature = keypair.sign(&payload).unwrap();
    let signer_pubkey = keypair.public().encode_protobuf();

    let signed_tx = match tx {
        ApplicationTransaction::DeployContract { code, .. } => {
            ApplicationTransaction::DeployContract {
                code,
                signer_pubkey,
                signature,
            }
        }
        ApplicationTransaction::CallContract {
            address,
            input_data,
            gas_limit,
            ..
        } => ApplicationTransaction::CallContract {
            address,
            input_data,
            gas_limit,
            signer_pubkey,
            signature,
        },
        _ => panic!("Unsupported tx type for signing"),
    };
    ChainTransaction::Application(signed_tx)
}

// Helper for query_contract RPC
async fn query_contract(rpc_addr: &str, address_hex: &str, input: &[u8]) -> Result<Vec<u8>> {
    let client = Client::new();
    let request_body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "query_contract",
        "params": [address_hex, hex::encode(input)],
        "id": 1
    });

    let rpc_url = format!("http://{}", rpc_addr);
    let response: serde_json::Value = client
        .post(&rpc_url)
        .json(&request_body)
        .send()
        .await?
        .json()
        .await?;

    if let Some(error) = response.get("error") {
        if !error.is_null() {
            return Err(anyhow!("RPC error: {}", error));
        }
    }

    let result_hex = response["result"]
        .as_str()
        .ok_or_else(|| anyhow!("Missing result field in RPC response"))?;
    let result_bytes = hex::decode(result_hex)?;
    Ok(result_bytes)
}

#[tokio::test]
async fn test_contract_deployment_and_execution_lifecycle() -> Result<()> {
    // 1. SETUP & BUILD
    build_test_artifacts("consensus-poa,vm-wasm");
    let counter_wasm =
        std::fs::read("../../target/wasm32-unknown-unknown/release/counter_contract.wasm")?;

    // 2. SETUP NETWORK
    let key = Keypair::generate_ed25519();
    let peer_id = key.public().to_peer_id();

    // FIX: Use the byte representation of the Peer ID, not the Base58 string.
    // This ensures the genesis state matches what the chain expects to
    // deserialize (`Vec<Vec<u8>>`) for the PoA authority set.
    let genesis_content = serde_json::json!({
      "genesis_state": {
        "system::authorities": [peer_id.to_bytes()]
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
    let deploy_tx_unsigned = ApplicationTransaction::DeployContract {
        code: counter_wasm,
        signer_pubkey: vec![],
        signature: vec![],
    };
    let deploy_tx = create_signed_tx(&key, deploy_tx_unsigned);
    submit_transaction("127.0.0.1:9964", &deploy_tx).await?;

    // 4. PARSE LOGS TO GET CONTRACT ADDRESS
    // The node now logs the *application* of a contract immediately after
    // block import. We must match that new format to find the address.
    let log_line = assert_log_contains_and_return_line(
        "Node",
        &mut logs,
        "Applied contract deployment at address:",
    )
    .await?;
    let address_hex = log_line.split("address: ").last().unwrap().trim();

    // 5. QUERY INITIAL STATE
    let get_input = vec![0]; // ABI for get()
    let initial_value_bytes = query_contract("127.0.0.1:9964", address_hex, &get_input).await?;
    assert_eq!(initial_value_bytes, vec![0], "Initial count should be 0");

    // 6. CALL INCREMENT
    let increment_input = vec![1]; // ABI for increment()
    let call_tx_unsigned = ApplicationTransaction::CallContract {
        address: hex::decode(address_hex)?,
        input_data: increment_input,
        gas_limit: 1_000_000,
        signer_pubkey: vec![],
        signature: vec![],
    };
    let call_tx = create_signed_tx(&key, call_tx_unsigned);
    submit_transaction("127.0.0.1:9964", &call_tx).await?;
    assert_log_contains("Node", &mut logs, "Contract call successful").await?;

    // 7. VERIFY FINAL STATE
    let final_value_bytes = query_contract("127.0.0.1:9964", address_hex, &get_input).await?;
    assert_eq!(final_value_bytes, vec![1], "Final count should be 1");

    println!("--- E2E Contract Test Successful ---");
    Ok(())
}
