// Path: crates/forge/tests/penalty_pos_e2e.rs
#![cfg(all(feature = "consensus-pos", feature = "vm-wasm"))]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ioi_client::WorkloadClient;
use ioi_forge::testing::{
    build_test_artifacts,
    rpc::{get_chain_timestamp, query_state_key},
    submit_transaction, wait_for_evidence, wait_for_height, wait_for_stake_to_be, TestCluster,
};
use ioi_system::keys::VALIDATOR_SET_KEY_STR; // Use the public string constant
use ioi_types::{
    app::{
        account_id_from_key_material, evidence_id, AccountId, ActiveKeyRecord, BlockTimingParams,
        BlockTimingRuntime, ChainId, ChainTransaction, Credential, FailureReport, OffenseFacts,
        OffenseType, ReportMisbehaviorParams, SignHeader, SignatureProof, SignatureSuite,
        SystemPayload, SystemTransaction, ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    codec,
    config::InitialServiceConfig,
    keys::{
        ACCOUNT_ID_TO_PUBKEY_PREFIX, ACCOUNT_NONCE_PREFIX, BLOCK_TIMING_PARAMS_KEY,
        BLOCK_TIMING_RUNTIME_KEY, IDENTITY_CREDENTIALS_PREFIX,
    },
    service_configs::{GovernanceParams, MigrationConfig},
};
use libp2p::identity::Keypair;
use serde_json::json;
use std::time::Duration;

// Helper function to create a signed system transaction
fn create_report_tx(
    reporter_key: &Keypair,
    offender_id: AccountId,
    nonce: u64,
    chain_id: ChainId,
    target_url: &str,
    probe_timestamp: u64,
) -> Result<(ChainTransaction, FailureReport)> {
    let report = FailureReport {
        offender: offender_id,
        offense_type: OffenseType::FailedCalibrationProbe,
        facts: OffenseFacts::FailedCalibrationProbe {
            target_url: target_url.trim().to_ascii_lowercase(),
            probe_timestamp,
        },
        proof: b"mock_proof_data".to_vec(),
    };

    let params = ReportMisbehaviorParams {
        report: report.clone(),
    };
    let params_bytes = codec::to_bytes_canonical(&params).map_err(|e| anyhow!(e))?;

    let payload = SystemPayload::CallService {
        service_id: "penalties".to_string(), // NEW: Use the new penalties service ID
        method: "report_misbehavior@v1".to_string(),
        params: params_bytes,
    };

    let reporter_pk_bytes = reporter_key.public().encode_protobuf();
    let reporter_account_hash =
        account_id_from_key_material(SignatureSuite::Ed25519, &reporter_pk_bytes)?;
    let reporter_account_id = AccountId(reporter_account_hash);

    let header = SignHeader {
        account_id: reporter_account_id,
        nonce,
        chain_id,
        tx_version: 1,
    };

    let mut tx_to_sign = SystemTransaction {
        header,
        payload, // Use the new payload
        signature_proof: SignatureProof::default(),
    };

    let sign_bytes = tx_to_sign.to_sign_bytes().map_err(|e| anyhow!(e))?;
    let signature = reporter_key.sign(&sign_bytes)?;

    tx_to_sign.signature_proof = SignatureProof {
        suite: SignatureSuite::Ed25519,
        public_key: reporter_pk_bytes,
        signature,
    };

    Ok((ChainTransaction::System(Box::new(tx_to_sign)), report))
}

/// Helper: fetch current on-chain next_nonce for an account (defaults to 0 if missing).
async fn fetch_next_nonce(rpc_addr: &str, acct: &AccountId) -> u64 {
    let key = [ACCOUNT_NONCE_PREFIX, acct.as_ref()].concat();
    match query_state_key(rpc_addr, &key).await {
        Ok(Some(bytes)) => codec::from_bytes_canonical::<u64>(&bytes).unwrap_or(0),
        _ => 0,
    }
}

/// Returns true if an error looks like a nonce mismatch from RPC/ante.
fn is_nonce_mismatch(err: &anyhow::Error) -> bool {
    let s = err.to_string();
    s.contains("Nonce mismatch")
        || s.contains("nonce") && s.contains("mismatch")
        || s.contains("InvalidNonce")
}

/// Submit the report from a *validator account* with a small retry
/// in case a self-generated tx raced the nonce.
async fn submit_report_with_retry(
    rpc_reporter: &str,
    rpc_other: &str,
    reporter_key: &Keypair,
    reporter_account_id: &AccountId,
    offender_account_id: AccountId,
    chain_id: ChainId,
    target_url: &str,
    probe_timestamp: u64,
) -> Result<FailureReport> {
    const MAX_ATTEMPTS: usize = 3;

    let mut last_err: Option<anyhow::Error> = None;

    for _attempt in 0..MAX_ATTEMPTS {
        let n = fetch_next_nonce(rpc_reporter, reporter_account_id).await;
        let (tx, report) = create_report_tx(
            reporter_key,
            offender_account_id,
            n,
            chain_id,
            target_url,
            probe_timestamp,
        )?;

        // Try local node first.
        let r1 = submit_transaction(rpc_reporter, &tx).await;
        // And propagate to the other validator as well (ok if this one rejects as dup).
        let r2 = submit_transaction(rpc_other, &tx).await;

        match (r1, r2) {
            // Success if either node accepted it.
            (Ok(_), _) | (_, Ok(_)) => return Ok(report),
            // Both failed.
            (Err(e1), Err(e2)) => {
                // If either was a nonce mismatch, retry.
                if is_nonce_mismatch(&e1) || is_nonce_mismatch(&e2) {
                    last_err = Some(anyhow!(
                        "Nonce race detected on submit; will retry with fresh nonce."
                    ));
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    continue;
                }
                // Otherwise, it's a hard failure.
                return Err(anyhow!(
                    "Report submit failed on both nodes: [{}] | [{}]",
                    e1,
                    e2
                ));
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow!("Report submit failed after retries")))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_pos_slashing_and_replay_protection() -> Result<()> {
    println!("\n--- Running PoS Economic Slashing and Replay Protection Test ---");
    build_test_artifacts();
    let expected_stake_after_slash = 90_000u64;

    let mut cluster = TestCluster::builder()
        .with_validators(2)
        .with_consensus_type("ProofOfStake")
        .with_chain_id(1)
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
        }))
        .with_initial_service(InitialServiceConfig::Governance(GovernanceParams::default()))
        .with_genesis_modifier(move |genesis, keys| {
            let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();
            let initial_stake = 100_000u128;

            let mut validators: Vec<ValidatorV1> = keys
                .iter()
                .map(|keypair| {
                    let pk_bytes = keypair.public().encode_protobuf();
                    let account_id_hash =
                        account_id_from_key_material(SignatureSuite::Ed25519, &pk_bytes).unwrap();
                    let account_id = AccountId(account_id_hash);

                    ValidatorV1 {
                        account_id,
                        weight: initial_stake,
                        consensus_key: ActiveKeyRecord {
                            suite: SignatureSuite::Ed25519,
                            public_key_hash: account_id_hash,
                            since_height: 0,
                        },
                    }
                })
                .collect();
            validators.sort_by(|a, b| a.account_id.cmp(&b.account_id));

            let total_weight = validators.iter().map(|v| v.weight).sum();

            let validator_sets = ValidatorSetsV1 {
                current: ValidatorSetV1 {
                    effective_from_height: 1,
                    total_weight,
                    validators,
                },
                next: None,
            };

            let vs_bytes = ioi_types::app::write_validator_sets(&validator_sets).unwrap();
            // Use the public string constant from ioi-system
            genesis_state.insert(
                VALIDATOR_SET_KEY_STR.to_string(),
                json!(format!("b64:{}", BASE64_STANDARD.encode(&vs_bytes))),
            );

            let timing_params = BlockTimingParams {
                base_interval_secs: 5,
                retarget_every_blocks: 0,
                ..Default::default()
            };
            let timing_runtime = BlockTimingRuntime {
                effective_interval_secs: timing_params.base_interval_secs,
                ..Default::default()
            };

            genesis_state.insert(
                std::str::from_utf8(BLOCK_TIMING_PARAMS_KEY)
                    .unwrap()
                    .to_string(),
                json!(format!(
                    "b64:{}",
                    BASE64_STANDARD.encode(codec::to_bytes_canonical(&timing_params).unwrap())
                )),
            );
            genesis_state.insert(
                std::str::from_utf8(BLOCK_TIMING_RUNTIME_KEY)
                    .unwrap()
                    .to_string(),
                json!(format!(
                    "b64:{}",
                    BASE64_STANDARD.encode(codec::to_bytes_canonical(&timing_runtime).unwrap())
                )),
            );

            for keypair in keys {
                let pk_bytes = keypair.public().encode_protobuf();
                let suite = SignatureSuite::Ed25519;
                let account_id_hash = account_id_from_key_material(suite, &pk_bytes).unwrap();
                let account_id = AccountId(account_id_hash);
                let pubkey_hash = account_id_from_key_material(suite, &pk_bytes).unwrap();

                let pubkey_map_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, account_id.as_ref()].concat();
                genesis_state.insert(
                    format!("b64:{}", BASE64_STANDARD.encode(&pubkey_map_key)),
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&pk_bytes))),
                );

                let record = ActiveKeyRecord {
                    suite,
                    public_key_hash: pubkey_hash,
                    since_height: 0,
                };
                let record_key = [b"identity::key_record::", account_id.as_ref()].concat();
                let record_bytes = codec::to_bytes_canonical(&record).unwrap();
                genesis_state.insert(
                    format!("b64:{}", BASE64_STANDARD.encode(&record_key)),
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&record_bytes))),
                );

                let cred = Credential {
                    suite,
                    public_key_hash: account_id.0,
                    activation_height: 0,
                    l2_location: None,
                };
                let creds_array: [Option<Credential>; 2] = [Some(cred), None];
                let creds_bytes = codec::to_bytes_canonical(&creds_array).unwrap();
                let creds_key = [IDENTITY_CREDENTIALS_PREFIX, account_id.as_ref()].concat();
                genesis_state.insert(
                    format!("b64:{}", BASE64_STANDARD.encode(&creds_key)),
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&creds_bytes))),
                );
            }

            for keypair in keys {
                let pk_bytes = keypair.public().encode_protobuf();
                let account_id_hash =
                    account_id_from_key_material(SignatureSuite::Ed25519, &pk_bytes).unwrap();
                let account_id = AccountId(account_id_hash);
                let nonce_key = [ACCOUNT_NONCE_PREFIX, account_id.as_ref()].concat();
                let nonce_bytes = codec::to_bytes_canonical(&0u64).unwrap();
                genesis_state.insert(
                    format!("b64:{}", BASE64_STANDARD.encode(&nonce_key)),
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&nonce_bytes))),
                );
            }
        })
        .build()
        .await?;

    let test_result: anyhow::Result<()> = async {
        let (reporter_slice, offender_slice) = cluster.validators.split_at_mut(1);
        let reporter = &mut reporter_slice[0];
        let offender = &mut offender_slice[0];

        let rpc_addr_reporter = &reporter.validator().rpc_addr;
        let rpc_addr_offender = &offender.validator().rpc_addr;

        let certs_path = &reporter.validator().certs_dir_path;
        let reporter_client = WorkloadClient::new(
            &reporter.validator().workload_ipc_addr,
            &certs_path.join("ca.pem").to_string_lossy(),
            &certs_path.join("orchestration.pem").to_string_lossy(),
            &certs_path.join("orchestration.key").to_string_lossy(),
        )
        .await?;

        wait_for_height(rpc_addr_reporter, 1, Duration::from_secs(30)).await?;
        wait_for_height(rpc_addr_offender, 1, Duration::from_secs(30)).await?;

        let offender_pk_bytes = offender.validator().keypair.public().encode_protobuf();
        let offender_account_id_hash =
            account_id_from_key_material(SignatureSuite::Ed25519, &offender_pk_bytes)?;
        let offender_account_id = AccountId(offender_account_id_hash);

        let reporter_pk_bytes = reporter.validator().keypair.public().encode_protobuf();
        let reporter_account_hash =
            account_id_from_key_material(SignatureSuite::Ed25519, &reporter_pk_bytes)?;
        let reporter_account_id = AccountId(reporter_account_hash);

        let probe_ts = get_chain_timestamp(rpc_addr_reporter).await?;
        let target_url = "https://calibration.ioi/heartbeat@v1";

        let report1 = submit_report_with_retry(
            rpc_addr_reporter,
            rpc_addr_offender,
            &reporter.validator().keypair,
            &reporter_account_id,
            offender_account_id,
            1u32.into(),
            target_url,
            probe_ts,
        )
        .await?;

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

        let id1 = evidence_id(&report1)?;
        wait_for_evidence(rpc_addr_reporter, &id1, Duration::from_secs(10)).await?;
        println!("SUCCESS: Evidence ID was correctly recorded in the registry.");

        let n1 = fetch_next_nonce(rpc_addr_reporter, &reporter_account_id).await;
        let (replay_tx, _) = create_report_tx(
            &reporter.validator().keypair,
            offender_account_id,
            n1,
            1u32.into(),
            target_url,
            probe_ts,
        )?;

        let _ = submit_transaction(rpc_addr_reporter, &replay_tx).await;
        let _ = submit_transaction(rpc_addr_offender, &replay_tx).await;

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
    .await;

    for guard in cluster.validators {
        if let Err(e) = guard.shutdown().await {
            eprintln!("Error during validator shutdown: {}", e);
        }
    }

    test_result?;

    Ok(())
}