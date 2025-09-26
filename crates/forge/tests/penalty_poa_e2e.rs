// Path: crates/forge/tests/penalty_poa_e2e.rs

#![cfg(all(feature = "consensus-poa", feature = "vm-wasm"))]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use depin_sdk_forge::testing::{
    build_test_artifacts,
    poll::{wait_for_height, wait_for_quarantine_status},
    rpc::get_quarantined_set,
    submit_transaction, TestCluster,
};
use depin_sdk_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, ChainId, ChainTransaction,
        Credential, FailureReport, OffenseFacts, OffenseType, SignHeader, SignatureProof,
        SignatureSuite, SystemPayload, SystemTransaction, ValidatorSetBlob, ValidatorSetV1,
        ValidatorSetsV1, ValidatorV1,
    },
    // [+] FIX: Import the canonical codec
    codec,
    config::InitialServiceConfig,
    keys::{ACCOUNT_ID_TO_PUBKEY_PREFIX, IDENTITY_CREDENTIALS_PREFIX, VALIDATOR_SET_KEY},
    service_configs::MigrationConfig,
};
use libp2p::identity::Keypair;
use serde_json::json;
use std::collections::BTreeMap;
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

    let mut cluster = TestCluster::builder()
        .with_validators(3) // Start with 3 to test the liveness boundary of MIN_LIVE_AUTHORITIES=2
        .with_consensus_type("ProofOfAuthority")
        .with_chain_id(1)
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
        }))
        .with_genesis_modifier(|genesis, keys| {
            let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();
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

            let validators: Vec<ValidatorV1> = authorities
                .iter()
                .map(|acct_id| {
                    let pk_hash = acct_id.0;
                    ValidatorV1 {
                        account_id: *acct_id,
                        weight: 1, // PoA
                        consensus_key: ActiveKeyRecord {
                            suite: SignatureSuite::Ed25519,
                            pubkey_hash: pk_hash,
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
            let vs_bytes = depin_sdk_types::app::write_validator_sets(&vs_blob.payload);
            genesis_state.insert(
                std::str::from_utf8(VALIDATOR_SET_KEY).unwrap().to_string(),
                json!(format!("b64:{}", BASE64_STANDARD.encode(&vs_bytes))),
            );

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
                genesis_state.insert(
                    format!("b64:{}", BASE64_STANDARD.encode(&record_key)),
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&record_bytes))),
                );

                // IdentityHub credentials for this authority
                let cred = Credential {
                    suite,
                    public_key_hash: acct_id.0,
                    activation_height: 0,
                    l2_location: None,
                };
                let creds_array: [Option<Credential>; 2] = [Some(cred), None];
                // [+] FIX: Use the canonical SCALE codec instead of serde_json for credentials.
                let creds_bytes = codec::to_bytes_canonical(&creds_array);
                let creds_key = [IDENTITY_CREDENTIALS_PREFIX, acct_id.as_ref()].concat();
                genesis_state.insert(
                    format!("b64:{}", BASE64_STANDARD.encode(&creds_key)),
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&creds_bytes))),
                );

                // AccountId -> PublicKey mapping
                let pubkey_map_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, acct_id.as_ref()].concat();
                genesis_state.insert(
                    format!("b64:{}", BASE64_STANDARD.encode(&pubkey_map_key)),
                    json!(format!("b64:{}", BASE64_STANDARD.encode(pk_bytes))),
                );
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

    // Wait for network to be ready
    wait_for_height(rpc_addr, 1, Duration::from_secs(20)).await?;

    // Action 1: Quarantine the first offender. This should succeed.
    let offender1_pk_bytes = offender1.keypair.public().encode_protobuf();
    let offender1_id_hash =
        account_id_from_key_material(SignatureSuite::Ed25519, &offender1_pk_bytes)?;
    let offender1_id = AccountId(offender1_id_hash);
    let tx1 = create_report_tx(&reporter.keypair, offender1_id, 0, 1.into())?;
    submit_transaction(rpc_addr, &tx1).await?;

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

    // Action 2: Try to quarantine the second offender. This should be accepted by mempool but rejected by state machine.
    let offender2_pk_bytes = offender2.keypair.public().encode_protobuf();
    let offender2_id_hash =
        account_id_from_key_material(SignatureSuite::Ed25519, &offender2_pk_bytes)?;
    let offender2_id = AccountId(offender2_id_hash);
    let tx2 = create_report_tx(&reporter.keypair, offender2_id, 1, 1.into())?; // increment nonce
    submit_transaction(rpc_addr, &tx2).await?;

    // Assert 2: Liveness guard rejected the transaction by asserting state hasn't changed after a delay.
    time::sleep(Duration::from_secs(10)).await;
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

    println!("SUCCESS: Liveness guard kept quarantine set at size 1.");
    Ok(())
}
