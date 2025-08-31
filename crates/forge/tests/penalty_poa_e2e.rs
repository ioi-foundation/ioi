// Path: crates/forge/tests/penalty_poa_e2e.rs

#![cfg(all(feature = "consensus-poa", feature = "vm-wasm"))]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use depin_sdk_forge::testing::{build_test_artifacts, submit_transaction, TestCluster};
use depin_sdk_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, ChainTransaction, Credential,
        FailureReport, OffenseFacts, OffenseType, SignHeader, SignatureProof, SignatureSuite,
        SystemPayload, SystemTransaction,
    },
    codec,
    config::InitialServiceConfig,
    keys::{
        ACCOUNT_ID_TO_PUBKEY_PREFIX, AUTHORITY_SET_KEY, IDENTITY_CREDENTIALS_PREFIX,
        QUARANTINED_VALIDATORS_KEY,
    },
    service_configs::MigrationConfig,
};
use libp2p::identity::Keypair;
use reqwest::Client;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};
use tokio::time;

async fn query_state_key(rpc_addr: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
    let client = Client::new();
    let request_body = json!({
        "jsonrpc": "2.0", "method": "query_state", "params": [hex::encode(key)], "id": 1
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
        .with_validators(3) // Start with 3 to test the liveness boundary of MIN_LIVE_AUTHORITIES=2
        .with_consensus_type("ProofOfAuthority")
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
        }))
        .with_genesis_modifier(|genesis, keys| {
            // 1. Derive AccountIds and sort them for canonical representation.
            let mut authorities: Vec<AccountId> = keys
                .iter()
                .map(|k| {
                    let pk_bytes = k.public().encode_protobuf();
                    let hash =
                        account_id_from_key_material(SignatureSuite::Ed25519, &pk_bytes).unwrap();
                    AccountId(hash)
                })
                .collect();
            authorities.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));

            // 2. Store the authority set using the canonical codec.
            let auth_bytes = depin_sdk_types::codec::to_bytes_canonical(&authorities);
            genesis["genesis_state"][std::str::from_utf8(AUTHORITY_SET_KEY).unwrap()] =
                json!(format!("b64:{}", BASE64_STANDARD.encode(&auth_bytes)));

            // 3. Build a stable map AccountId -> public key bytes.
            let suite = SignatureSuite::Ed25519;
            let id_to_pk: BTreeMap<AccountId, Vec<u8>> = keys
                .iter()
                .map(|k| {
                    let pk = k.public().encode_protobuf();
                    let id = AccountId(
                        account_id_from_key_material(suite, &pk).expect("derive account id"),
                    );
                    (id, pk)
                })
                .collect();

            // 4. Populate ActiveKeyRecord, IdentityHub creds, and pk map per authority using that mapping.
            for acct_id in &authorities {
                let pk_bytes = id_to_pk.get(acct_id).expect("missing pubkey for authority");

                // Create the core consensus key record.
                let record = ActiveKeyRecord {
                    suite,
                    // This equals *acct_id* by construction; using the derived value keeps it explicit.
                    pubkey_hash: account_id_from_key_material(suite, pk_bytes).unwrap(),
                    since_height: 0, // Active from genesis
                };
                let record_key = [b"identity::key_record::", acct_id.as_ref()].concat();
                let record_bytes = depin_sdk_types::codec::to_bytes_canonical(&record);
                genesis["genesis_state"][format!("b64:{}", BASE64_STANDARD.encode(&record_key))] =
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&record_bytes)));

                // IdentityHub credentials for this authority
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

                // AccountId -> PublicKey mapping
                let pubkey_map_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, acct_id.as_ref()].concat();
                genesis["genesis_state"]
                    [format!("b64:{}", BASE64_STANDARD.encode(&pubkey_map_key))] =
                    json!(format!("b64:{}", BASE64_STANDARD.encode(pk_bytes)));
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
    let _orch_logs = reporter.orch_log_stream.lock().await.take().unwrap();

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

    // Assert 2: Liveness guard rejected the transaction by asserting state hasn't changed.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        time::sleep(Duration::from_secs(2)).await;

        let bytes_opt = query_state_key(rpc_addr, QUARANTINED_VALIDATORS_KEY).await?;
        let set: BTreeSet<AccountId> = bytes_opt
            .map(|b| codec::from_bytes_canonical(&b))
            .transpose()
            .map_err(|e| anyhow!("Failed to decode quarantine set from state: {}", e))?
            .unwrap_or_default();

        if set.len() == 1 && set.contains(&offender1_id) {
            break; // Success: second quarantine was correctly rejected and state is unchanged.
        }
        if Instant::now() > deadline {
            anyhow::bail!(
                "Expected liveness guard to prevent second quarantine; set = {:?}",
                set
            );
        }
    }
    println!("SUCCESS: Liveness guard kept quarantine set at size 1.");

    Ok(())
}
