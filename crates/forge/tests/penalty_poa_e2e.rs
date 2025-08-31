// Path: crates/forge/tests/penalty_poa_e2e.rs

#![cfg(all(feature = "consensus-poa", feature = "vm-wasm"))]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use depin_sdk_forge::testing::{
    assert_log_contains, build_test_artifacts, submit_transaction, TestCluster,
};
use depin_sdk_types::{
    app::{
        account_id_from_key_material, AccountId, ChainTransaction, Credential, FailureReport,
        OffenseFacts, OffenseType, SignHeader, SignatureProof, SignatureSuite, SystemPayload,
        SystemTransaction,
    },
    codec,
    config::InitialServiceConfig,
    keys::{ACCOUNT_ID_TO_PUBKEY_PREFIX, IDENTITY_CREDENTIALS_PREFIX, QUARANTINED_VALIDATORS_KEY},
    service_configs::MigrationConfig,
};
use libp2p::identity::Keypair;
use reqwest::Client;
use serde_json::json;
use std::collections::BTreeSet;
use std::time::Duration;
use tokio::time;

async fn query_state_key(rpc_addr: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
    let client = Client::new();
    let request_body = json!({
        "jsonrpc": "2.0", "method": "query_state", "params": [hex::encode(key)], "id": 1
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
    match response["result"].as_str() {
        Some(hex_val) if !hex_val.is_empty() => Ok(Some(hex::decode(hex_val)?)),
        _ => Ok(None),
    }
}

fn create_report_tx(
    reporter_key: &Keypair,
    offender_id: AccountId,
    nonce: u64,
) -> Result<ChainTransaction> {
    let report = FailureReport {
        offender: offender_id,
        offense_type: OffenseType::FailedCalibrationProbe,
        facts: OffenseFacts::FailedCalibrationProbe { probe_id: [1; 32] },
        proof: b"mock_proof_data".to_vec(),
    };
    let public_key_bytes = reporter_key.public().encode_protobuf();
    let account_id_hash = account_id_from_key_material(SignatureSuite::Ed25519, &public_key_bytes)?;
    let account_id = AccountId(account_id_hash);

    let header = SignHeader {
        account_id,
        nonce,
        chain_id: 1,
        tx_version: 1,
    };
    let mut tx_to_sign = SystemTransaction {
        header,
        payload: SystemPayload::ReportMisbehavior { report },
        signature_proof: SignatureProof::default(),
    };
    let sign_bytes = tx_to_sign.to_sign_bytes().unwrap();
    let signature = reporter_key.sign(&sign_bytes).unwrap();
    tx_to_sign.signature_proof = SignatureProof {
        suite: SignatureSuite::Ed25519,
        public_key: public_key_bytes,
        signature,
    };
    Ok(ChainTransaction::System(tx_to_sign))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_poa_quarantine_and_liveness_guard() -> Result<()> {
    println!("\n--- Running PoA Non-Economic Quarantine and Liveness Guard Test ---");
    build_test_artifacts("consensus-poa,vm-wasm,tree-file,primitive-hash");

    let mut cluster = TestCluster::builder()
        .with_validators(4) // Start with 4 to allow one quarantine while meeting liveness (min 3 live)
        .with_consensus_type("ProofOfAuthority")
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
        }))
        .with_genesis_modifier(|genesis, keys| {
            let authorities: Vec<_> = keys
                .iter()
                .map(|k| k.public().to_peer_id().to_bytes())
                .collect();
            genesis["genesis_state"]["system::authorities"] = json!(authorities);

            for keypair in keys {
                let pk_bytes = keypair.public().encode_protobuf();
                let account_id_hash =
                    account_id_from_key_material(SignatureSuite::Ed25519, &pk_bytes).unwrap();
                let account_id = AccountId(account_id_hash);

                let cred = Credential {
                    suite: SignatureSuite::Ed25519,
                    public_key_hash: account_id.0,
                    activation_height: 0,
                    l2_location: None,
                };
                let creds_array: [Option<Credential>; 2] = [Some(cred), None];
                let creds_bytes = serde_json::to_vec(&creds_array).unwrap();
                let creds_key = [IDENTITY_CREDENTIALS_PREFIX, account_id.as_ref()].concat();
                genesis["genesis_state"][format!("b64:{}", BASE64_STANDARD.encode(&creds_key))] =
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&creds_bytes)));

                let pubkey_map_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, account_id.as_ref()].concat();
                genesis["genesis_state"]
                    [format!("b64:{}", BASE64_STANDARD.encode(&pubkey_map_key))] =
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&pk_bytes)));
            }
        })
        .build()
        .await?;

    let (reporter_slice, offenders_slice) = cluster.validators.split_at_mut(1);
    let reporter = &mut reporter_slice[0];
    let (offender1_slice, offender2_slice) = offenders_slice.split_at_mut(1);
    let offender1 = &offender1_slice[0];
    let offender2 = &offender2_slice[0];

    let rpc_addr = &reporter.rpc_addr;
    let mut orch_logs = reporter.orch_log_stream.lock().await.take().unwrap();

    tokio::time::sleep(Duration::from_secs(10)).await;

    // Action 1: Quarantine the first offender. This should succeed.
    let offender1_pk_bytes = offender1.keypair.public().encode_protobuf();
    let offender1_id_hash =
        account_id_from_key_material(SignatureSuite::Ed25519, &offender1_pk_bytes)?;
    let offender1_id = AccountId(offender1_id_hash);
    let tx1 = create_report_tx(&reporter.keypair, offender1_id, 0)?;
    submit_transaction(rpc_addr, &tx1).await?;

    // Assert 1: Poll state until the offender is quarantined.
    println!("Waiting for offender to be quarantined...");
    let mut quarantine_bytes = None;
    for _ in 0..15 {
        time::sleep(Duration::from_secs(2)).await;
        if let Some(bytes) = query_state_key(rpc_addr, QUARANTINED_VALIDATORS_KEY).await? {
            quarantine_bytes = Some(bytes);
            break;
        }
    }
    let final_quarantine_bytes =
        quarantine_bytes.ok_or_else(|| anyhow!("Quarantine key was never created in state"))?;

    let quarantine_list: BTreeSet<AccountId> =
        codec::from_bytes_canonical(&final_quarantine_bytes).map_err(|e| anyhow!(e))?;

    assert!(
        quarantine_list.contains(&offender1_id),
        "Offender was not quarantined"
    );
    assert_eq!(quarantine_list.len(), 1);
    println!("SUCCESS: First offender was correctly quarantined.");

    // Action 2: Try to quarantine the second offender. This should fail the liveness check.
    let offender2_pk_bytes = offender2.keypair.public().encode_protobuf();
    let offender2_id_hash =
        account_id_from_key_material(SignatureSuite::Ed25519, &offender2_pk_bytes)?;
    let offender2_id = AccountId(offender2_id_hash);
    let tx2 = create_report_tx(&reporter.keypair, offender2_id, 1)?; // increment nonce
    submit_transaction(rpc_addr, &tx2).await?;

    // Assert 2: Liveness guard rejected the transaction.
    assert_log_contains("Orchestration", &mut orch_logs, "Transaction processing error: Invalid transaction: Quarantine would jeopardize network liveness").await?;
    println!("SUCCESS: Liveness guard correctly rejected second quarantine.");

    Ok(())
}
