// Path: crates/forge/tests/penalty_pos_e2e.rs

#![cfg(all(feature = "consensus-pos", feature = "vm-wasm"))]

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use depin_sdk_client::WorkloadClient;
use depin_sdk_forge::testing::{
    build_test_artifacts,
    poll::{wait_for_evidence, wait_for_height, wait_for_stake_to_be},
    submit_transaction, TestCluster,
};
use depin_sdk_types::{
    app::{
        account_id_from_key_material, evidence_id, AccountId, ActiveKeyRecord, ChainTransaction,
        Credential, FailureReport, OffenseFacts, OffenseType, SignHeader, SignatureProof,
        SignatureSuite, SystemPayload, SystemTransaction, ValidatorSetBlob, ValidatorSetV1,
        ValidatorSetsV1, ValidatorV1,
    },
    codec,
    config::InitialServiceConfig,
    keys::{ACCOUNT_ID_TO_PUBKEY_PREFIX, IDENTITY_CREDENTIALS_PREFIX, VALIDATOR_SET_KEY},
    service_configs::MigrationConfig,
};
use libp2p::identity::Keypair;
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;

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

    let reporter_pk_bytes = reporter_key.public().encode_protobuf();
    let reporter_account_hash =
        account_id_from_key_material(SignatureSuite::Ed25519, &reporter_pk_bytes).unwrap();
    let reporter_account_id = AccountId(reporter_account_hash);

    let header = SignHeader {
        account_id: reporter_account_id,
        nonce,
        chain_id: 1,
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
        public_key: reporter_pk_bytes,
        signature,
    };

    (ChainTransaction::System(Box::new(tx_to_sign)), report)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_pos_slashing_and_replay_protection() -> Result<()> {
    println!("\n--- Running PoS Economic Slashing and Replay Protection Test ---");
    build_test_artifacts("consensus-pos,vm-wasm,tree-iavl,primitive-hash");
    let initial_stake = 100_000u64;
    let expected_stake_after_slash = 90_000u64;

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
            let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();
            let validators: Vec<ValidatorV1> = keys
                .iter()
                .map(|k| {
                    let pk_bytes = k.public().encode_protobuf();
                    let account_hash =
                        account_id_from_key_material(SignatureSuite::Ed25519, &pk_bytes).unwrap();
                    ValidatorV1 {
                        account_id: AccountId(account_hash),
                        weight: initial_stake as u128,
                        consensus_key: ActiveKeyRecord {
                            suite: SignatureSuite::Ed25519,
                            pubkey_hash: account_hash,
                            since_height: 0,
                        },
                    }
                })
                .collect();
            let total_weight = validators.iter().map(|v| v.weight).sum();
            let vs_blob = ValidatorSetBlob {
                schema_version: 2,
                payload: ValidatorSetsV1 {
                    current: ValidatorSetV1 {
                        effective_from_height: 1,
                        total_weight,
                        validators,
                    },
                    next: None,
                },
            };
            let vs_bytes = depin_sdk_types::app::write_validator_sets(&vs_blob.payload);
            genesis_state.insert(
                std::str::from_utf8(VALIDATOR_SET_KEY).unwrap().to_string(),
                json!(format!("b64:{}", BASE64_STANDARD.encode(&vs_bytes))),
            );

            // Populate identity records for all validators
            for keypair in keys {
                let suite = SignatureSuite::Ed25519;
                let pk_bytes = keypair.public().encode_protobuf();
                let account_id_hash = account_id_from_key_material(suite, &pk_bytes).unwrap();
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
                genesis_state.insert(
                    format!("b64:{}", BASE64_STANDARD.encode(&creds_key)),
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&creds_bytes))),
                );

                let pubkey_map_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, account_id.as_ref()].concat();
                genesis_state.insert(
                    format!("b64:{}", BASE64_STANDARD.encode(&pubkey_map_key)),
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&pk_bytes))),
                );

                let record = ActiveKeyRecord {
                    suite,
                    pubkey_hash: account_id_hash,
                    since_height: 0,
                };
                let record_key = [b"identity::key_record::", account_id.as_ref()].concat();
                let record_bytes = codec::to_bytes_canonical(&record);
                genesis_state.insert(
                    format!("b64:{}", BASE64_STANDARD.encode(&record_key)),
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&record_bytes))),
                );
            }
        })
        .build()
        .await?;

    let (reporter_slice, offender_slice) = cluster.validators.split_at_mut(1);
    let reporter = &mut reporter_slice[0];
    let offender = &mut offender_slice[0];
    let rpc_addr_reporter = &reporter.rpc_addr;
    let rpc_addr_offender = &offender.rpc_addr;

    let certs_path = &reporter.certs_dir_path;
    let reporter_client = WorkloadClient::new(
        &reporter.workload_ipc_addr,
        &certs_path.join("ca.pem").to_string_lossy(),
        &certs_path.join("orchestration.pem").to_string_lossy(),
        &certs_path.join("orchestration.key").to_string_lossy(),
    )
    .await?;

    wait_for_height(rpc_addr_reporter, 1, Duration::from_secs(20)).await?;

    let offender_pk_bytes = offender.keypair.public().encode_protobuf();
    let offender_account_id_hash =
        account_id_from_key_material(SignatureSuite::Ed25519, &offender_pk_bytes)?;
    let offender_account_id = AccountId(offender_account_id_hash);

    // ACTION 1: Report the offender. Submit to BOTH nodes to ensure the leader gets it.
    let (tx1, report1) = create_report_tx(&reporter.keypair, offender_account_id, 0);
    submit_transaction(rpc_addr_reporter, &tx1).await?;
    submit_transaction(rpc_addr_offender, &tx1).await?;

    // VERIFY 1: Poll state until stake is slashed
    println!("Waiting for stake to be slashed...");
    wait_for_stake_to_be(
        &reporter_client,
        &offender_account_id,
        expected_stake_after_slash,
        Duration::from_secs(20),
    )
    .await?;
    println!(
        "SUCCESS: Offender's stake was correctly slashed to {}.",
        expected_stake_after_slash
    );

    // VERIFY 2: Evidence ID was recorded
    let id1 = evidence_id(&report1);
    wait_for_evidence(rpc_addr_reporter, &id1, Duration::from_secs(10)).await?;
    println!("SUCCESS: Evidence ID was correctly recorded in the registry.");

    // ACTION 2: Submit an identical report (with a new nonce) to test replay protection.
    let (replay_tx, _) = create_report_tx(&reporter.keypair, offender_account_id, 1);
    submit_transaction(rpc_addr_reporter, &replay_tx).await?;
    submit_transaction(rpc_addr_offender, &replay_tx).await?;

    // VERIFY 3: Wait for a new block to be produced after submitting the invalid tx.
    // If the chain halts because of the invalid tx, this will fail.
    println!("Waiting to confirm no double-slashing occurs and chain remains live...");
    wait_for_height(rpc_addr_reporter, 3, Duration::from_secs(30)).await?;

    let final_offender_stake = reporter_client
        .get_staked_validators()
        .await
        .map_err(|e| anyhow::anyhow!(e))?
        .get(&offender_account_id)
        .copied()
        .unwrap_or(0);

    assert_eq!(
        final_offender_stake, expected_stake_after_slash,
        "Stake was slashed a second time, replay protection failed"
    );
    println!("SUCCESS: Replay transaction was correctly rejected by the state machine and the chain did not halt.");

    Ok(())
}
