// Path: crates/forge/tests/penalty_poa_e2e.rs

#![cfg(all(feature = "consensus-poa", feature = "vm-wasm"))]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ioi_api::state::service_namespace_prefix;
use ioi_forge::testing::{
    add_genesis_identity, // [+] Import
    build_test_artifacts,
    rpc::{self, get_chain_timestamp, get_quarantined_set},
    wait_for_height,
    wait_for_quarantine_status,
    TestValidator, 
};
use ioi_system::keys::VALIDATOR_SET_KEY_STR;
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, BlockTimingParams,
        BlockTimingRuntime, ChainId, ChainTransaction, Credential, FailureReport, OffenseFacts,
        OffenseType, ReportMisbehaviorParams, SignHeader, SignatureProof, SignatureSuite,
        SystemPayload, SystemTransaction, ValidatorSetBlob, ValidatorSetV1, ValidatorSetsV1,
        ValidatorV1,
    },
    codec,
    config::InitialServiceConfig,
    keys::{
        BLOCK_TIMING_PARAMS_KEY, BLOCK_TIMING_RUNTIME_KEY,
    },
    service_configs::{GovernanceParams, MigrationConfig},
};
use libp2p::identity::{self, Keypair};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::time;

// ... [create_report_tx remains unchanged] ...
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
        service_id: "penalties".to_string(),
        method: "report_misbehavior@v1".to_string(),
        params: params_bytes,
    };

    let public_key_bytes = reporter_key.public().encode_protobuf();
    let account_id_hash = account_id_from_key_material(SignatureSuite::Ed25519, &public_key_bytes)?;
    let account_id = AccountId(account_id_hash);

    let header = SignHeader {
        account_id,
        nonce,
        chain_id,
        tx_version: 1,
    };
    let mut tx_to_sign = SystemTransaction {
        header,
        payload,
        signature_proof: SignatureProof::default(),
    };
    let sign_bytes = tx_to_sign.to_sign_bytes().unwrap();
    let signature = reporter_key.sign(&sign_bytes).unwrap();
    tx_to_sign.signature_proof = SignatureProof {
        suite: SignatureSuite::Ed25519,
        public_key: public_key_bytes,
        signature,
    };
    Ok((ChainTransaction::System(Box::new(tx_to_sign)), report))
}

// [-] REMOVED: add_poa_identity_to_genesis local helper

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_poa_quarantine_and_liveness_guard() -> Result<()> {
    println!("\n--- Running PoA Non-Economic Quarantine and Liveness Guard Test ---");
    build_test_artifacts();

    // --- SETUP: Deterministic Leader-First Launch ---
    let k0 = identity::Keypair::generate_ed25519();
    let k1 = identity::Keypair::generate_ed25519();
    let k2 = identity::Keypair::generate_ed25519();
    let all_keys = vec![k0.clone(), k1.clone(), k2.clone()];

    let suite = SignatureSuite::Ed25519;
    let mut account_ids_with_keys = all_keys
        .iter()
        .map(|k| {
            let id = AccountId(
                account_id_from_key_material(suite, &k.public().encode_protobuf()).unwrap(),
            );
            (id, k.clone())
        })
        .collect::<Vec<_>>();
    account_ids_with_keys.sort_by(|a, b| a.0.cmp(&b.0));

    let leader_key = account_ids_with_keys[0].1.clone();
    let follower_keys: Vec<_> = account_ids_with_keys
        .iter()
        .skip(1)
        .map(|(_, k)| k.clone())
        .collect();

    let genesis_content = {
        let mut genesis = json!({ "genesis_state": {} });
        let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();
        
        // [+] Use shared helper for all keys
        // This handles dual-write (Global + Namespaced) so consensus and IdentityHub work.
        for k in &all_keys {
            add_genesis_identity(genesis_state, k);
        }

        let mut authorities: Vec<AccountId> = account_ids_with_keys
            .iter()
            .map(|(id, _)| *id)
            .collect();
        // No need to sort again, already sorted above for leader selection

        let validators: Vec<ValidatorV1> = authorities
            .iter()
            .map(|acct_id| {
                let pk_hash = acct_id.0;
                ValidatorV1 {
                    account_id: *acct_id,
                    weight: 1, // PoA
                    consensus_key: ActiveKeyRecord {
                        suite: SignatureSuite::Ed25519,
                        public_key_hash: pk_hash,
                        since_height: 0,
                    },
                }
            })
            .collect();

        let vs_blob = ValidatorSetBlob {
            schema_version: 2,
            payload: ValidatorSetsV1 {
                current: ValidatorSetV1 {
                    effective_from_height: 1,
                    total_weight: validators.len() as u128,
                    validators,
                },
                next: None,
            },
        };
        let vs_bytes = ioi_types::app::write_validator_sets(&vs_blob.payload).unwrap();
        genesis_state.insert(
            VALIDATOR_SET_KEY_STR.to_string(),
            json!(format!("b64:{}", BASE64_STANDARD.encode(vs_bytes))),
        );

        // [+] Use valid timing parameters
        let timing_params = BlockTimingParams {
            base_interval_secs: 5,
            min_interval_secs: 1,  // [+]
            max_interval_secs: 60, // [+]
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

        genesis.to_string()
    };

    // ... [Rest of test logic remains unchanged] ...
    let leader_node = TestValidator::launch(
        leader_key,
        genesis_content.clone(),
        5000,
        1.into(),
        None,
        "ProofOfAuthority",
        "IAVL",
        "Hash",
        None,
        None,
        false,
        vec![
            InitialServiceConfig::IdentityHub(MigrationConfig {
                chain_id: 1,
                grace_period_blocks: 5,
                accept_staged_during_grace: true,
                allowed_target_suites: vec![SignatureSuite::Ed25519],
                allow_downgrade: false,
            }),
            InitialServiceConfig::Governance(GovernanceParams::default()),
        ],
        false,
        false,
        &[],
    )
    .await?;
    wait_for_height(
        &leader_node.validator().rpc_addr,
        1,
        Duration::from_secs(20),
    )
    .await?;

    let bootnode_addrs = vec![leader_node.validator().p2p_addr.clone()];

    let follower1 = TestValidator::launch(
        follower_keys[0].clone(),
        genesis_content.clone(),
        6000,
        1.into(),
        Some(&bootnode_addrs),
        "ProofOfAuthority",
        "IAVL",
        "Hash",
        None,
        None,
        false,
        vec![
            InitialServiceConfig::IdentityHub(MigrationConfig {
                chain_id: 1,
                grace_period_blocks: 5,
                accept_staged_during_grace: true,
                allowed_target_suites: vec![SignatureSuite::Ed25519],
                allow_downgrade: false,
            }),
            InitialServiceConfig::Governance(GovernanceParams::default()),
        ],
        false,
        false,
        &[],
    )
    .await?;
    let follower2 = TestValidator::launch(
        follower_keys[1].clone(),
        genesis_content,
        7000,
        1.into(),
        Some(&bootnode_addrs),
        "ProofOfAuthority",
        "IAVL",
        "Hash",
        None,
        None,
        false,
        vec![
            InitialServiceConfig::IdentityHub(MigrationConfig {
                chain_id: 1,
                grace_period_blocks: 5,
                accept_staged_during_grace: true,
                allowed_target_suites: vec![SignatureSuite::Ed25519],
                allow_downgrade: false,
            }),
            InitialServiceConfig::Governance(GovernanceParams::default()),
        ],
        false,
        false,
        &[],
    )
    .await?;

    let mut validators = vec![leader_node, follower1, follower2];

    let test_result = async {
        validators.sort_by(|a, b| a.validator().peer_id.cmp(&b.validator().peer_id));

        let reporter = &validators[0];
        let offender1 = &validators[1];
        let offender2 = &validators[2];
        let rpc_addr = &reporter.validator().rpc_addr;

        wait_for_height(rpc_addr, 2, Duration::from_secs(30)).await?;
        wait_for_height(&offender1.validator().rpc_addr, 2, Duration::from_secs(30)).await?;
        wait_for_height(&offender2.validator().rpc_addr, 2, Duration::from_secs(30)).await?;
        println!("--- All nodes synced. Cluster is ready. ---");

        let target_url = "https://calibration.ioi/heartbeat@v1";
        let probe_ts = get_chain_timestamp(rpc_addr).await?;

        let offender1_pk_bytes = offender1.validator().keypair.public().encode_protobuf();
        let offender1_id_hash =
            account_id_from_key_material(SignatureSuite::Ed25519, &offender1_pk_bytes)?;
        let offender1_id = AccountId(offender1_id_hash);
        let (tx1, _) = create_report_tx(
            &reporter.validator().keypair,
            offender1_id,
            0,
            1.into(),
            target_url,
            probe_ts,
        )?;
        rpc::submit_transaction(rpc_addr, &tx1).await?;

        println!("Waiting for offender to be quarantined...");
        wait_for_quarantine_status(rpc_addr, &offender1_id, true, Duration::from_secs(20)).await?;

        let quarantine_list = get_quarantined_set(rpc_addr).await?;
        assert_eq!(
            quarantine_list.len(),
            1,
            "Quarantine list should have one member"
        );
        println!("SUCCESS: First offender was correctly quarantined.");

        let height_before_halt = rpc::get_chain_height(rpc_addr).await?;

        let offender2_pk_bytes = offender2.validator().keypair.public().encode_protobuf();
        let offender2_id_hash =
            account_id_from_key_material(SignatureSuite::Ed25519, &offender2_pk_bytes)?;
        let offender2_id = AccountId(offender2_id_hash);
        let (tx2, _) = create_report_tx(
            &reporter.validator().keypair,
            offender2_id,
            1,
            1.into(),
            target_url,
            probe_ts,
        )?; 

        for v in &validators {
            let _ = rpc::submit_transaction_no_wait(&v.validator().rpc_addr, &tx2).await;
        }

        println!("Waiting to confirm chain has halted due to invalid transaction...");
        time::sleep(Duration::from_secs(10)).await; 
        let height_after_halt = rpc::get_chain_height(rpc_addr).await?;
        assert_eq!(
            height_after_halt, height_before_halt,
            "Chain should have halted at height {} but advanced to {}",
            height_before_halt, height_after_halt
        );
        println!("SUCCESS: Chain correctly halted after receiving a transaction that would violate liveness.");

        let final_quarantine_list = get_quarantined_set(rpc_addr).await?;
        if final_quarantine_list.contains(&offender2_id) {
            return Err(anyhow!(
                "Liveness guard failed: second offender was quarantined."
            ));
        }
        assert_eq!(
            final_quarantine_list.len(),
            1,
            "Quarantine list size should remain 1"
        );

        println!("SUCCESS: Liveness guard correctly prevented the invalid state transition.");
        Ok(())
    }
    .await;

    for v in validators {
        if let Err(e) = v.shutdown().await {
            eprintln!("Error during validator shutdown: {}", e);
        }
    }

    test_result?;

    Ok(())
}