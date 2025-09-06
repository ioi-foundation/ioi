// crates/forge/tests/oracle_e2e.rs
#![cfg(all(
    feature = "consensus-pos",
    feature = "vm-wasm",
    feature = "tree-file",
    feature = "primitive-hash"
))]

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use depin_sdk_forge::testing::{
    assert_log_contains, build_test_artifacts, submit_transaction, TestCluster,
};
use depin_sdk_types::app::{
    account_id_from_key_material, AccountId, ActiveKeyRecord, ChainTransaction, Credential,
    SignHeader, SignatureProof, SignatureSuite, SystemPayload, SystemTransaction,
};
use depin_sdk_types::codec;
use depin_sdk_types::config::InitialServiceConfig;
use depin_sdk_types::keys::{
    ACCOUNT_ID_TO_PUBKEY_PREFIX, IDENTITY_CREDENTIALS_PREFIX, STAKES_KEY_CURRENT, STAKES_KEY_NEXT,
};
use depin_sdk_types::service_configs::MigrationConfig;
use libp2p::identity::Keypair;
use serde_json::json;
use std::collections::BTreeMap;

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
        chain_id: 1, // Matches chain default
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
async fn test_validator_native_oracle_e2e() -> Result<()> {
    // 1. SETUP: Build artifacts and launch a 4-node PoS cluster.
    build_test_artifacts("consensus-pos,vm-wasm,tree-file,primitive-hash");

    let cluster = TestCluster::builder()
        .with_validators(4)
        .with_consensus_type("ProofOfStake")
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
        }))
        .with_genesis_modifier(|genesis, keys| {
            // Setup initial stakes using the correct AccountId key and canonical codec
            let stakes: BTreeMap<_, _> = keys
                .iter()
                .map(|k| {
                    let pk_bytes = k.public().encode_protobuf();
                    let account_hash =
                        account_id_from_key_material(SignatureSuite::Ed25519, &pk_bytes).unwrap();
                    (AccountId(account_hash), 100_000u64)
                })
                .collect();
            let stakes_bytes = codec::to_bytes_canonical(&stakes);
            let stakes_b64 = format!("b64:{}", BASE64_STANDARD.encode(&stakes_bytes));
            genesis["genesis_state"][std::str::from_utf8(STAKES_KEY_CURRENT).unwrap()] =
                json!(&stakes_b64);
            genesis["genesis_state"][std::str::from_utf8(STAKES_KEY_NEXT).unwrap()] =
                json!(&stakes_b64);

            // Populate identity records for all validators
            for keypair in keys {
                let suite = SignatureSuite::Ed25519;
                let pk_bytes = keypair.public().encode_protobuf();
                let account_id_hash = account_id_from_key_material(suite, &pk_bytes).unwrap();
                let account_id = AccountId(account_id_hash);

                // Add IdentityHub credentials
                let cred = Credential {
                    suite,
                    public_key_hash: account_id.0,
                    activation_height: 0,
                    l2_location: None,
                };
                let creds_array: [Option<Credential>; 2] = [Some(cred), None];
                let creds_bytes = serde_json::to_vec(&creds_array).unwrap();
                let creds_key = [IDENTITY_CREDENTIALS_PREFIX, account_id.as_ref()].concat();
                genesis["genesis_state"][format!("b64:{}", BASE64_STANDARD.encode(&creds_key))] =
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&creds_bytes)));

                // Add AccountId -> PublicKey mapping
                let pubkey_map_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, account_id.as_ref()].concat();
                genesis["genesis_state"]
                    [format!("b64:{}", BASE64_STANDARD.encode(&pubkey_map_key))] =
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&pk_bytes)));

                // Add ActiveKeyRecord for consensus
                let record = ActiveKeyRecord {
                    suite,
                    pubkey_hash: account_id_hash,
                    since_height: 0,
                };
                let record_key = [b"identity::key_record::", account_id.as_ref()].concat();
                let record_bytes = codec::to_bytes_canonical(&record);
                genesis["genesis_state"][format!("b64:{}", BASE64_STANDARD.encode(&record_key))] =
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&record_bytes)));
            }
        })
        .build()
        .await?;

    let node0_rpc = &cluster.validators[0].rpc_addr;
    let mut logs1 = cluster.validators[1]
        .orch_log_stream
        .lock()
        .await
        .take()
        .unwrap();
    let mut logs2 = cluster.validators[2]
        .orch_log_stream
        .lock()
        .await
        .take()
        .unwrap();
    let mut orch_logs3 = cluster.validators[3]
        .orch_log_stream
        .lock()
        .await
        .take()
        .unwrap();
    let mut workload_logs3 = cluster.validators[3]
        .workload_log_stream
        .lock()
        .await
        .take()
        .unwrap();

    // Wait for network to stabilize
    assert_log_contains(
        "Node 3",
        &mut orch_logs3,
        "Oracle: This node is in the validator set, checking for new tasks...",
    )
    .await?;

    // 2. SUBMIT ORACLE REQUEST TRANSACTION
    let request_id = 101;
    let payload = SystemPayload::RequestOracleData {
        url: "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd"
            .to_string(),
        request_id,
    };

    let signer_keypair = &cluster.validators[0].keypair;
    let request_tx = create_system_tx(signer_keypair, payload, 0)?;
    submit_transaction(node0_rpc, &request_tx).await?;

    // 3. ASSERT ATTESTATION GOSSIP
    assert_log_contains(
        "Node 1",
        &mut logs1,
        &format!("Oracle: Received attestation for request_id {}", request_id),
    )
    .await?;
    assert_log_contains(
        "Node 2",
        &mut logs2,
        &format!("Oracle: Received attestation for request_id {}", request_id),
    )
    .await?;

    // 4. ASSERT QUORUM AND SUBMISSION
    assert_log_contains(
        "Node 1",
        &mut logs1,
        &format!(
            "Oracle: Submitted finalization transaction for request_id {} to local mempool.",
            request_id
        ),
    )
    .await?;

    // 5. ASSERT ON-CHAIN FINALIZATION
    assert_log_contains(
        "Workload 3",
        &mut workload_logs3,
        &format!("Applied and verified oracle data for id: {}", request_id),
    )
    .await?;

    println!("--- Validator-Native Oracle E2E Test Passed ---");
    Ok(())
}
