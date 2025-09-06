// Path: crates/forge/tests/module_upgrade_e2e.rs

#![cfg(all(feature = "consensus-poa", feature = "vm-wasm"))]

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _}; // Add this import
use depin_sdk_forge::testing::{
    assert_log_contains, build_test_artifacts, submit_transaction, TestCluster,
};
use depin_sdk_types::app::{
    // Add these imports
    account_id_from_key_material,
    AccountId,
    ActiveKeyRecord,
    ChainTransaction,
    Credential,
    SignHeader,
    SignatureProof,
    SignatureSuite,
    SystemPayload,
    SystemTransaction,
};
use depin_sdk_types::codec; // Add this import
use depin_sdk_types::config::InitialServiceConfig; // Add this import
use depin_sdk_types::keys::{
    // Add these imports
    ACCOUNT_ID_TO_PUBKEY_PREFIX,
    AUTHORITY_SET_KEY,
    GOVERNANCE_KEY,
    IDENTITY_CREDENTIALS_PREFIX,
};
use depin_sdk_types::service_configs::MigrationConfig; // Add this import
use libp2p::identity::{self, Keypair};
use serde_json::json;

// Helper function to create a signed system transaction
fn create_system_tx(
    keypair: &Keypair,
    payload: SystemPayload,
    nonce: u64,
) -> Result<ChainTransaction> {
    let public_key_bytes = keypair.public().encode_protobuf();
    let account_id_hash = account_id_from_key_material(SignatureSuite::Ed25519, &public_key_bytes)?;
    let account_id = AccountId(account_id_hash);

    let header = SignHeader {
        account_id,
        nonce,
        chain_id: 1, // Default chain_id for tests
        tx_version: 1,
    };

    let mut tx_to_sign = SystemTransaction {
        header,
        payload,
        signature_proof: SignatureProof::default(),
    };
    let sign_bytes = tx_to_sign.to_sign_bytes()?;
    let signature = keypair.sign(&sign_bytes)?;

    tx_to_sign.signature_proof = SignatureProof {
        suite: SignatureSuite::Ed25519,
        public_key: public_key_bytes,
        signature,
    };
    Ok(ChainTransaction::System(Box::new(tx_to_sign)))
}

#[tokio::test]
async fn test_forkless_module_upgrade() -> Result<()> {
    // 1. SETUP & BUILD
    build_test_artifacts("consensus-poa,vm-wasm,tree-file,primitive-hash");
    let service_v2_wasm =
        std::fs::read("../../target/wasm32-unknown-unknown/release/test_service_v2.wasm")?;
    let governance_key = identity::Keypair::generate_ed25519();
    let governance_pubkey_b58 =
        bs58::encode(governance_key.public().try_into_ed25519()?.to_bytes()).into_string();

    // --- FIX: Clone the keypair before moving it into the closure ---
    let governance_key_clone = governance_key.clone();

    // 2. LAUNCH CLUSTER
    let mut cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("ProofOfAuthority")
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
        }))
        .with_genesis_modifier(move |genesis, keys| {
            // Setup validator identity
            let validator_key = &keys[0];
            let suite = SignatureSuite::Ed25519;
            let validator_pk_bytes = validator_key.public().encode_protobuf();
            let validator_account_id =
                AccountId(account_id_from_key_material(suite, &validator_pk_bytes).unwrap());
            let authorities = vec![validator_account_id];
            genesis["genesis_state"][std::str::from_utf8(AUTHORITY_SET_KEY).unwrap()] =
                json!(format!(
                    "b64:{}",
                    BASE64_STANDARD.encode(codec::to_bytes_canonical(&authorities))
                ));

            // Setup governance identity
            genesis["genesis_state"][std::str::from_utf8(GOVERNANCE_KEY).unwrap()] =
                json!(governance_pubkey_b58);
            let gov_pk_bytes = governance_key_clone.public().encode_protobuf(); // Use the cloned key
            let gov_account_id =
                AccountId(account_id_from_key_material(suite, &gov_pk_bytes).unwrap());

            // Add credentials for both validator and governance key
            for (key, acct_id) in [
                (validator_key, validator_account_id),
                (&governance_key_clone, gov_account_id),
            ] {
                let pk_bytes = key.public().encode_protobuf();
                let cred = Credential {
                    suite,
                    public_key_hash: acct_id.0,
                    activation_height: 0,
                    l2_location: None,
                };
                let creds_array: [Option<Credential>; 2] = [Some(cred), None];
                let creds_bytes = serde_json::to_vec(&creds_array).unwrap();
                let creds_key = [IDENTITY_CREDENTIALS_PREFIX, acct_id.as_ref()].concat();
                genesis["genesis_state"][format!("b64:{}", BASE64_STANDARD.encode(&creds_key))] =
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&creds_bytes)));

                let record = ActiveKeyRecord {
                    suite,
                    pubkey_hash: acct_id.0,
                    since_height: 0,
                };
                let record_key = [b"identity::key_record::", acct_id.as_ref()].concat();
                genesis["genesis_state"][format!("b64:{}", BASE64_STANDARD.encode(&record_key))] =
                    json!(format!(
                        "b64:{}",
                        BASE64_STANDARD.encode(codec::to_bytes_canonical(&record))
                    ));

                let pubkey_map_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, acct_id.as_ref()].concat();
                genesis["genesis_state"]
                    [format!("b64:{}", BASE64_STANDARD.encode(&pubkey_map_key))] =
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&pk_bytes)));
            }
        })
        .build()
        .await?;

    // 3. GET HANDLES
    let node = &mut cluster.validators[0];
    let rpc_addr = &node.rpc_addr;
    let mut workload_logs = node.workload_log_stream.lock().await.take().unwrap();
    let mut orch_logs = node.orch_log_stream.lock().await.take().unwrap();

    // 4. SUBMIT UPGRADE TRANSACTION
    let activation_height = 5;
    let payload = SystemPayload::SwapModule {
        service_type: "fee_calculator_v2".to_string(),
        module_wasm: service_v2_wasm,
        activation_height,
    };

    let tx = create_system_tx(&governance_key, payload, 0)?; // Nonce is 0 for first tx

    submit_transaction(rpc_addr, &tx).await?;

    // Assert that the transaction was accepted into the mempool
    assert_log_contains(
        "Orchestration",
        &mut orch_logs,
        "[RPC] Published transaction via gossip.",
    )
    .await?;

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