// Path: forge/tests/penalty_pos_e2e.rs

#![cfg(all(feature = "consensus-pos", feature = "vm-wasm"))]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use depin_sdk_forge::testing::{
    assert_log_contains, build_test_artifacts, submit_transaction, TestCluster,
};
use depin_sdk_types::{
    app::{
        account_id_from_pubkey, evidence_id, AccountId, ChainTransaction, Credential,
        FailureReport, OffenseFacts, OffenseType, SignHeader, SignatureProof, SignatureSuite,
        SystemPayload, SystemTransaction,
    },
    codec,
    config::InitialServiceConfig,
    keys::{
        ACCOUNT_ID_TO_PUBKEY_PREFIX, EVIDENCE_REGISTRY_KEY, IDENTITY_CREDENTIALS_PREFIX,
        STAKES_KEY_CURRENT, STAKES_KEY_NEXT,
    },
    service_configs::MigrationConfig,
};
use libp2p::identity::Keypair;
use reqwest::Client;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

/// Helper function to query a raw key from the workload state via RPC.
async fn query_state_key(rpc_addr: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
    let client = Client::new();
    let request_body = json!({
        "jsonrpc": "2.0",
        "method": "query_state",
        "params": [hex::encode(key)],
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

    match response["result"].as_str() {
        Some(hex_val) if !hex_val.is_empty() => Ok(Some(hex::decode(hex_val)?)),
        _ => Ok(None),
    }
}

/// Helper to create a signed ReportMisbehavior transaction and return the report for assertions.
fn create_report_tx(
    reporter_key: &Keypair,
    offender_id: AccountId,
    nonce: u64,
) -> (ChainTransaction, FailureReport) {
    let report = FailureReport {
        offender: offender_id,
        offense_type: OffenseType::FailedCalibrationProbe,
        facts: OffenseFacts::FailedCalibrationProbe { probe_id: [1; 32] },
        proof: b"mock_proof_data".to_vec(),
    };

    let header = SignHeader {
        account_id: account_id_from_pubkey(&reporter_key.public()),
        nonce,
        chain_id: 1, // Must match chain's config
        tx_version: 1,
    };

    let mut tx_to_sign = SystemTransaction {
        header,
        payload: SystemPayload::ReportMisbehavior {
            report: report.clone(),
        },
        signature_proof: SignatureProof::default(),
    };

    let sign_bytes = tx_to_sign.to_sign_bytes().unwrap();
    let signature = reporter_key.sign(&sign_bytes).unwrap();

    tx_to_sign.signature_proof = SignatureProof {
        suite: SignatureSuite::Ed25519,
        public_key: reporter_key.public().encode_protobuf(),
        signature,
    };

    (ChainTransaction::System(tx_to_sign), report)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_pos_slashing_and_replay_protection() -> Result<()> {
    println!("\n--- Running PoS Economic Slashing and Replay Protection Test ---");
    build_test_artifacts("consensus-pos,vm-wasm,tree-file,primitive-hash");
    let initial_stake = 100_000u64;
    let expected_stake_after_slash = 90_000u64; // Based on 10% hardcoded penalty

    let mut cluster = TestCluster::builder()
        .with_validators(2)
        .with_consensus_type("ProofOfStake")
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
        }))
        .with_genesis_modifier(move |genesis, keys| {
            // Setup initial stakes using canonical AccountId and SCALE codec
            let stakes: BTreeMap<AccountId, u64> = keys
                .iter()
                .map(|k| (account_id_from_pubkey(&k.public()), initial_stake))
                .collect();
            let stakes_bytes = codec::to_bytes_canonical(&stakes);
            let stakes_b64 = format!("b64:{}", BASE64_STANDARD.encode(&stakes_bytes));
            genesis["genesis_state"][std::str::from_utf8(STAKES_KEY_CURRENT).unwrap()] =
                json!(&stakes_b64);
            genesis["genesis_state"][std::str::from_utf8(STAKES_KEY_NEXT).unwrap()] =
                json!(&stakes_b64);

            // Setup initial credentials and the new pubkey lookup map
            for keypair in keys {
                let account_id = account_id_from_pubkey(&keypair.public());
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

                // Populate the AccountId -> PubKey map in genesis
                let pubkey_map_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, account_id.as_ref()].concat();
                let pubkey_bytes = keypair.public().encode_protobuf();
                genesis["genesis_state"]
                    [format!("b64:{}", BASE64_STANDARD.encode(&pubkey_map_key))] =
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&pubkey_bytes)));
            }
        })
        .build()
        .await?;

    let (reporter_slice, offender_slice) = cluster.validators.split_at_mut(1);
    let reporter = &mut reporter_slice[0];
    let offender = &mut offender_slice[0];

    let rpc_addr = &reporter.rpc_addr;
    let mut orch_logs = reporter.orch_log_stream.lock().await.take().unwrap();

    // Wait for the first block to establish baseline state
    assert_log_contains(
        "Orchestration",
        &mut orch_logs,
        "Received gossiped block #1",
    )
    .await?;

    // ACTION: Report the offender
    let offender_account_id = account_id_from_pubkey(&offender.keypair.public());
    let (tx, report) = create_report_tx(&reporter.keypair, offender_account_id, 0); // Nonce 0
    submit_transaction(rpc_addr, &tx).await?;

    // Wait for the next block to process the report transaction
    assert_log_contains(
        "Orchestration",
        &mut orch_logs,
        "Received gossiped block #2",
    )
    .await?;

    // --- VERIFICATION ---

    // Assert 1: Stake was correctly slashed in the *next* stakes map.
    let stakes_bytes = query_state_key(rpc_addr, STAKES_KEY_NEXT)
        .await?
        .expect("STAKES_KEY_NEXT should exist in state");
    let stakes: BTreeMap<AccountId, u64> =
        codec::from_bytes_canonical(&stakes_bytes).map_err(|e| anyhow!(e))?;
    let offender_stake = stakes.get(&offender_account_id).unwrap();
    assert_eq!(
        *offender_stake, expected_stake_after_slash,
        "Stake was not slashed correctly"
    );
    println!(
        "SUCCESS: Offender's stake was correctly slashed to {}.",
        offender_stake
    );

    // Assert 2: Evidence ID was recorded for replay protection.
    let evidence_bytes = query_state_key(rpc_addr, EVIDENCE_REGISTRY_KEY)
        .await?
        .expect("EVIDENCE_REGISTRY_KEY should exist in state");
    let evidence_list: BTreeSet<[u8; 32]> =
        codec::from_bytes_canonical(&evidence_bytes).map_err(|e| anyhow!(e))?;
    let id = evidence_id(&report);
    assert!(evidence_list.contains(&id), "Evidence ID was not recorded");
    println!("SUCCESS: Evidence ID was correctly recorded in the registry.");

    // Assert 3: An identical report (with a new nonce) is rejected as a replay.
    let (replay_tx, _) = create_report_tx(&reporter.keypair, offender_account_id, 1); // Incremented nonce
    submit_transaction(rpc_addr, &replay_tx).await?;

    // The node will accept the tx into the mempool, but it will fail during block processing.
    assert_log_contains(
        "Orchestration",
        &mut orch_logs,
        "Transaction processing error: Invalid transaction: Duplicate evidence: this offense has already been penalized.",
    ).await?;
    println!("SUCCESS: Replay transaction was correctly rejected by the state machine.");

    Ok(())
}
