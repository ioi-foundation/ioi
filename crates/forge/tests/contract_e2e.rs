// Path: crates/forge/tests/contract_e2e.rs
//! End-to-End Test: Smart Contract Execution Lifecycle

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use depin_sdk_forge::testing::{
    assert_log_contains, assert_log_contains_and_return_line, build_test_artifacts,
    submit_transaction, TestCluster,
};
use depin_sdk_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, ApplicationTransaction,
        ChainTransaction, Credential, SignHeader, SignatureProof, SignatureSuite,
    },
    codec,
    config::InitialServiceConfig,
    keys::{ACCOUNT_ID_TO_PUBKEY_PREFIX, AUTHORITY_SET_KEY, IDENTITY_CREDENTIALS_PREFIX},
    service_configs::MigrationConfig,
};
use libp2p::identity::Keypair;
use reqwest::Client;
use serde_json::json;

// Helper function to create a signed transaction with proper nonce and account_id
fn create_signed_app_tx(
    keypair: &Keypair,
    mut tx: ApplicationTransaction,
    nonce: u64,
) -> ChainTransaction {
    let public_key = keypair.public().encode_protobuf();

    // Use the canonical function to derive the account ID
    let account_id_hash =
        account_id_from_key_material(SignatureSuite::Ed25519, &public_key).unwrap();
    let account_id = depin_sdk_types::app::AccountId(account_id_hash);

    let header = SignHeader {
        account_id,
        nonce,
        chain_id: 1, // Must match the chain's config
        tx_version: 1,
    };

    // Set header before creating sign bytes
    match &mut tx {
        ApplicationTransaction::DeployContract { header: h, .. } => *h = header,
        ApplicationTransaction::CallContract { header: h, .. } => *h = header,
        _ => panic!("Unsupported tx type"),
    }

    let payload_bytes = tx.to_sign_bytes().unwrap();
    let signature = keypair.sign(&payload_bytes).unwrap();

    let proof = SignatureProof {
        suite: SignatureSuite::Ed25519,
        public_key,
        signature,
    };

    // Set signature proof after signing
    match &mut tx {
        ApplicationTransaction::DeployContract {
            signature_proof, ..
        } => *signature_proof = proof,
        ApplicationTransaction::CallContract {
            signature_proof, ..
        } => *signature_proof = proof,
        _ => panic!("Unsupported tx type"),
    }

    ChainTransaction::Application(tx)
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

    let rpc_url = format!("http://{}/rpc", rpc_addr);
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
    build_test_artifacts("consensus-poa,vm-wasm,tree-file,primitive-hash");
    let counter_wasm =
        std::fs::read("../../target/wasm32-unknown-unknown/release/counter_contract.wasm")?;
    let mut nonce = 0;

    // 2. SETUP NETWORK
    let mut cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("ProofOfAuthority")
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
            chain_id: 1,
        }))
        // --- FIX START: Correctly set up genesis state for PoA with AccountId ---
        .with_genesis_modifier(|genesis, keys| {
            let keypair = &keys[0];
            let suite = SignatureSuite::Ed25519;
            let public_key_bytes = keypair.public().encode_protobuf();
            let account_id_hash = account_id_from_key_material(suite, &public_key_bytes).unwrap();
            let account_id = AccountId(account_id_hash);

            // A. Set the authority set using canonical encoding of Vec<AccountId>
            let authorities = vec![account_id];
            let authorities_bytes = codec::to_bytes_canonical(&authorities);
            let auth_key_str = std::str::from_utf8(AUTHORITY_SET_KEY).unwrap();
            genesis["genesis_state"][auth_key_str] =
                json!(format!("b64:{}", BASE64_STANDARD.encode(authorities_bytes)));

            // B. Set the initial IdentityHub credentials
            let initial_cred = Credential {
                suite,
                public_key_hash: account_id_hash,
                activation_height: 0,
                l2_location: None,
            };
            let creds_array: [Option<Credential>; 2] = [Some(initial_cred), None];
            let creds_bytes = serde_json::to_vec(&creds_array).unwrap();
            let creds_key = [IDENTITY_CREDENTIALS_PREFIX, account_id.as_ref()].concat();
            let creds_key_b64 = format!("b64:{}", BASE64_STANDARD.encode(&creds_key));
            genesis["genesis_state"][creds_key_b64] =
                json!(format!("b64:{}", BASE64_STANDARD.encode(&creds_bytes)));

            // C. Set the ActiveKeyRecord for consensus verification
            let record = ActiveKeyRecord {
                suite,
                pubkey_hash: account_id_hash,
                since_height: 0,
            };
            let record_key = [b"identity::key_record::", account_id.as_ref()].concat();
            let record_bytes = codec::to_bytes_canonical(&record);
            genesis["genesis_state"][format!("b64:{}", BASE64_STANDARD.encode(&record_key))] =
                json!(format!("b64:{}", BASE64_STANDARD.encode(&record_bytes)));

            // D. Set the AccountId -> PublicKey mapping for consensus verification
            let pubkey_map_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, account_id.as_ref()].concat();
            genesis["genesis_state"][format!("b64:{}", BASE64_STANDARD.encode(&pubkey_map_key))] =
                json!(format!("b64:{}", BASE64_STANDARD.encode(&public_key_bytes)));
        })
        // --- FIX END ---
        .build()
        .await?;

    let node = &mut cluster.validators[0];
    let rpc_addr = &node.rpc_addr;
    let keypair = &node.keypair;
    let mut workload_logs = node.workload_log_stream.lock().await.take().unwrap();
    let _orch_logs = node.orch_log_stream.lock().await.take().unwrap();

    // 3. DEPLOY CONTRACT
    let deploy_tx_unsigned = ApplicationTransaction::DeployContract {
        header: Default::default(),
        code: counter_wasm,
        signature_proof: Default::default(),
    };
    let deploy_tx = create_signed_app_tx(keypair, deploy_tx_unsigned, nonce);
    nonce += 1;
    submit_transaction(rpc_addr, &deploy_tx).await?;

    // 4. PARSE LOGS TO GET CONTRACT ADDRESS
    let log_line = assert_log_contains_and_return_line(
        "Workload",
        &mut workload_logs,
        "Applied contract deployment at address:",
    )
    .await?;
    let address_hex = log_line.split("address: ").last().unwrap().trim();

    // 5. QUERY INITIAL STATE
    let get_input = vec![0]; // ABI for get()
    let initial_value_bytes = query_contract(rpc_addr, address_hex, &get_input).await?;
    assert_eq!(initial_value_bytes, vec![0], "Initial count should be 0");

    // 6. CALL INCREMENT
    let increment_input = vec![1]; // ABI for increment()
    let call_tx_unsigned = ApplicationTransaction::CallContract {
        header: Default::default(),
        address: hex::decode(address_hex)?,
        input_data: increment_input,
        gas_limit: 1_000_000,
        signature_proof: Default::default(),
    };
    let call_tx = create_signed_app_tx(keypair, call_tx_unsigned, nonce);
    submit_transaction(rpc_addr, &call_tx).await?;
    assert_log_contains("Workload", &mut workload_logs, "Contract call successful").await?;

    // 7. VERIFY FINAL STATE
    tokio::time::sleep(std::time::Duration::from_secs(6)).await;
    let final_value_bytes = query_contract(rpc_addr, address_hex, &get_input).await?;
    assert_eq!(final_value_bytes, vec![1], "Final count should be 1");

    println!("--- E2E Contract Test Successful ---");
    Ok(())
}
