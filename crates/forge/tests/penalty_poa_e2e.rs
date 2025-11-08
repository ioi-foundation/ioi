// Path: crates/forge/tests/penalty_poa_e2e.rs

#![cfg(all(feature = "consensus-poa", feature = "vm-wasm"))]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ioi_forge::testing::{
    build_test_artifacts,
    wait_for_height, wait_for_quarantine_status,
    rpc,
    rpc::get_quarantined_set,
    TestValidator, // Use the validator struct directly instead of the cluster builder
};
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, BlockTimingParams,
        BlockTimingRuntime, ChainId, ChainTransaction, Credential, FailureReport, OffenseFacts,
        OffenseType, SignHeader, SignatureProof, SignatureSuite, SystemPayload, SystemTransaction,
        ValidatorSetBlob, ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    codec,
    config::InitialServiceConfig,
    keys::{
        ACCOUNT_ID_TO_PUBKEY_PREFIX, BLOCK_TIMING_PARAMS_KEY, BLOCK_TIMING_RUNTIME_KEY,
        IDENTITY_CREDENTIALS_PREFIX, VALIDATOR_SET_KEY,
    },
    service_configs::MigrationConfig,
};
use libp2p::identity::{self, Keypair};
use libp2p::Multiaddr; // Added for bootnode address
use serde_json::json; // FIX: Removed unused 'Value' import
use std::collections::BTreeMap;
use std::mem::ManuallyDrop;
use std::time::Duration;
use tokio::time;

fn create_report_tx(
    reporter_key: &Keypair,
    offender_id: AccountId,
    nonce: u64,
    chain_id: ChainId,
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
        chain_id,
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
    Ok(ChainTransaction::System(Box::new(tx_to_sign)))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_poa_quarantine_and_liveness_guard() -> Result<()> {
    println!("\n--- Running PoA Non-Economic Quarantine and Liveness Guard Test ---");
    build_test_artifacts();

    // --- SETUP: Deterministic Leader-First Launch ---

    // 1. Manually create keys for all nodes.
    let k0 = identity::Keypair::generate_ed25519();
    let k1 = identity::Keypair::generate_ed25519();
    let k2 = identity::Keypair::generate_ed25519();
    let all_keys = vec![k0.clone(), k1.clone(), k2.clone()];

    // 2. Derive AccountIds and sort the keys to find the canonical leader for H=1.
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
    // Sort by AccountId to find the leader (index 0).
    account_ids_with_keys.sort_by(|a, b| a.0.cmp(&b.0));

    // The first key in the sorted list is the leader for block 1.
    let leader_key = account_ids_with_keys[0].1.clone();
    let follower_keys: Vec<_> = account_ids_with_keys
        .iter()
        .skip(1)
        .map(|(_, k)| k.clone())
        .collect();

    // 3. Create a single genesis string to be shared by all nodes.
    let genesis_content = {
        let mut genesis = json!({ "genesis_state": {} });
        let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();
        // 1. Derive AccountIds and sort them for canonical representation.
        let mut authorities: Vec<AccountId> = all_keys
            .iter()
            .map(|k| {
                let pk_bytes = k.public().encode_protobuf();
                let hash =
                    account_id_from_key_material(SignatureSuite::Ed25519, &pk_bytes).unwrap();
                AccountId(hash)
            })
            .collect();
        authorities.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));

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
            std::str::from_utf8(VALIDATOR_SET_KEY).unwrap().to_string(),
            json!(format!("b64:{}", BASE64_STANDARD.encode(vs_bytes))),
        );

        let timing_params = BlockTimingParams {
            base_interval_secs: 5,
            retarget_every_blocks: 0, // Disable adaptive timing for simplicity.
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
        let id_to_pk: BTreeMap<AccountId, Vec<u8>> = all_keys
            .iter()
            .map(|k| {
                let pk = k.public().encode_protobuf();
                let id =
                    AccountId(account_id_from_key_material(suite, &pk).expect("derive account id"));
                (id, pk)
            })
            .collect();

        for acct_id in &authorities {
            let pk_bytes = id_to_pk.get(acct_id).expect("missing pubkey for authority");
            let record = ActiveKeyRecord {
                suite,
                public_key_hash: account_id_from_key_material(suite, pk_bytes).unwrap(),
                since_height: 0,
            };
            let record_key = [b"identity::key_record::", acct_id.as_ref()].concat();
            let record_bytes = ioi_types::codec::to_bytes_canonical(&record).unwrap();
            genesis_state.insert(
                format!("b64:{}", BASE64_STANDARD.encode(&record_key)),
                json!(format!("b64:{}", BASE64_STANDARD.encode(&record_bytes))),
            );
            let cred = Credential {
                suite,
                public_key_hash: acct_id.0,
                activation_height: 0,
                l2_location: None,
            };
            let creds_array: [Option<Credential>; 2] = [Some(cred), None];
            let creds_bytes = codec::to_bytes_canonical(&creds_array).unwrap();
            let creds_key = [IDENTITY_CREDENTIALS_PREFIX, acct_id.as_ref()].concat();
            genesis_state.insert(
                format!("b64:{}", BASE64_STANDARD.encode(&creds_key)),
                json!(format!("b64:{}", BASE64_STANDARD.encode(&creds_bytes))),
            );
            let pubkey_map_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, acct_id.as_ref()].concat();
            genesis_state.insert(
                format!("b64:{}", BASE64_STANDARD.encode(&pubkey_map_key)),
                json!(format!("b64:{}", BASE64_STANDARD.encode(pk_bytes))),
            );
        }
        genesis.to_string()
    };

    // 4. Launch leader node, wait for block 1, then launch followers.
    let leader_node = ManuallyDrop::new(
        TestValidator::launch(
            leader_key,
            genesis_content.clone(),
            5000,
            1.into(),
            None,
            "ProofOfAuthority",
            "IAVL",
            "Hash",
            None,
            None, // [+] FIX: Added missing agentic_model_path argument
            false,
            vec![InitialServiceConfig::IdentityHub(MigrationConfig {
                chain_id: 1,
                grace_period_blocks: 5,
                accept_staged_during_grace: true,
                allowed_target_suites: vec![SignatureSuite::Ed25519],
                allow_downgrade: false,
            })],
            false,
            false,
            &[],
        )
        .await?,
    );
    wait_for_height(&leader_node.rpc_addr, 1, Duration::from_secs(20)).await?;

    let bootnode_addrs: Vec<Multiaddr> = vec![leader_node.p2p_addr.clone()];

    let follower1 = ManuallyDrop::new(
        TestValidator::launch(
            follower_keys[0].clone(),
            genesis_content.clone(),
            6000,
            1.into(),
            Some(&bootnode_addrs),
            "ProofOfAuthority",
            "IAVL",
            "Hash",
            None,
            None, // [+] FIX: Added missing agentic_model_path argument
            false,
            vec![InitialServiceConfig::IdentityHub(MigrationConfig {
                chain_id: 1,
                grace_period_blocks: 5,
                accept_staged_during_grace: true,
                allowed_target_suites: vec![SignatureSuite::Ed25519],
                allow_downgrade: false,
            })],
            false,
            false,
            &[],
        )
        .await?,
    );
    let follower2 = ManuallyDrop::new(
        TestValidator::launch(
            follower_keys[1].clone(),
            genesis_content.clone(),
            7000,
            1.into(),
            Some(&bootnode_addrs),
            "ProofOfAuthority",
            "IAVL",
            "Hash",
            None,
            None, // [+] FIX: Added missing agentic_model_path argument
            false,
            vec![InitialServiceConfig::IdentityHub(MigrationConfig {
                chain_id: 1,
                grace_period_blocks: 5,
                accept_staged_during_grace: true,
                allowed_target_suites: vec![SignatureSuite::Ed25519],
                allow_downgrade: false,
            })],
            false,
            false,
            &[],
        )
        .await?,
    );

    // Re-assemble validators and sort by PeerId for a stable test order
    let mut validators = vec![
        ManuallyDrop::into_inner(leader_node),
        ManuallyDrop::into_inner(follower1),
        ManuallyDrop::into_inner(follower2),
    ];
    validators.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));

    // The rest of the test logic proceeds from here...
    let reporter = &validators[0];
    let offender1 = &validators[1];
    let offender2 = &validators[2];
    let rpc_addr = &reporter.rpc_addr;

    // Wait for network to be ready and synced
    wait_for_height(rpc_addr, 2, Duration::from_secs(30)).await?;
    wait_for_height(&offender1.rpc_addr, 2, Duration::from_secs(30)).await?;
    wait_for_height(&offender2.rpc_addr, 2, Duration::from_secs(30)).await?;
    println!("--- All nodes synced. Cluster is ready. ---");

    // Action 1: Quarantine the first offender. This should succeed.
    let offender1_pk_bytes = offender1.keypair.public().encode_protobuf();
    let offender1_id_hash =
        account_id_from_key_material(SignatureSuite::Ed25519, &offender1_pk_bytes)?;
    let offender1_id = AccountId(offender1_id_hash);
    let tx1 = create_report_tx(&reporter.keypair, offender1_id, 0, 1.into())?;
    rpc::submit_transaction(rpc_addr, &tx1).await?;

    // Assert 1: Poll state until the offender is quarantined.
    println!("Waiting for offender to be quarantined...");
    wait_for_quarantine_status(rpc_addr, &offender1_id, true, Duration::from_secs(20)).await?;

    let quarantine_list = get_quarantined_set(rpc_addr).await?;
    assert_eq!(
        quarantine_list.len(),
        1,
        "Quarantine list should have one member"
    );
    println!("SUCCESS: First offender was correctly quarantined.");

    // Get current height before submitting the problematic transaction.
    let height_before_halt = rpc::get_chain_height(rpc_addr).await?;

    // Action 2: Try to quarantine the second offender. This should be accepted by mempool but cause a chain halt.
    let offender2_pk_bytes = offender2.keypair.public().encode_protobuf();
    let offender2_id_hash =
        account_id_from_key_material(SignatureSuite::Ed25519, &offender2_pk_bytes)?;
    let offender2_id = AccountId(offender2_id_hash);
    let tx2 = create_report_tx(&reporter.keypair, offender2_id, 1, 1.into())?; // increment nonce

    let submission_result = rpc::submit_transaction_no_wait(rpc_addr, &tx2).await?;
    assert!(
        submission_result.get("error").is_none() || submission_result["error"].is_null(),
        "Submission of liveness-violating tx should be accepted by mempool, but was rejected with: {}",
        submission_result
    );

    // Assert 2: Chain should halt. Wait for a duration longer than block time and assert height hasn't changed.
    println!("Waiting to confirm chain has halted due to invalid transaction...");
    time::sleep(Duration::from_secs(10)).await; // Wait longer than a block time.
    let height_after_halt = rpc::get_chain_height(rpc_addr).await?;
    assert_eq!(
        height_after_halt, height_before_halt,
        "Chain should have halted at height {} but advanced to {}",
        height_before_halt, height_after_halt
    );
    println!("SUCCESS: Chain correctly halted after receiving a transaction that would violate liveness.");

    // Assert 3: The liveness guard prevented the state change. The quarantine list should still have only one member.
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