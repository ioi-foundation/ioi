// Path: crates/forge/tests/proof_verification_e2e.rs

#![cfg(all(
    feature = "consensus-poa",
    feature = "vm-wasm",
    feature = "tree-iavl",
    feature = "primitive-hash",
    feature = "malicious-bin"
))]

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use depin_sdk_forge::testing::{assert_log_contains, build_test_artifacts, TestValidator};
use depin_sdk_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, SignatureSuite, ValidatorSetBlob,
        ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    codec,
    keys::{ACCOUNT_ID_TO_PUBKEY_PREFIX, VALIDATOR_SET_KEY},
};
use libp2p::identity;
use serde_json::json;

#[tokio::test]
async fn test_orchestration_rejects_tampered_proof() -> Result<()> {
    // 1. Build test-only artifacts (contracts).
    build_test_artifacts();

    // 2. Manually launch a single node with the malicious workload.
    // We bypass TestCluster::build() to avoid its readiness checks (which expect block 1 to be produced).
    let keypair = identity::Keypair::generate_ed25519();
    let genesis_content = {
        let mut genesis = json!({ "genesis_state": {} });
        let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();
        let suite = SignatureSuite::Ed25519;
        let pk = keypair.public().encode_protobuf();
        let acct_hash = account_id_from_key_material(suite, &pk).unwrap();
        let acct = AccountId(acct_hash);

        let vs_blob = ValidatorSetBlob {
            schema_version: 2,
            payload: ValidatorSetsV1 {
                current: ValidatorSetV1 {
                    effective_from_height: 1,
                    total_weight: 1,
                    validators: vec![ValidatorV1 {
                        account_id: acct,
                        weight: 1,
                        consensus_key: ActiveKeyRecord {
                            suite: SignatureSuite::Ed25519,
                            pubkey_hash: acct_hash,
                            since_height: 0,
                        },
                    }],
                },
                next: None,
            },
        };
        let vs_bytes = codec::to_bytes_canonical(&vs_blob);
        genesis_state.insert(
            std::str::from_utf8(VALIDATOR_SET_KEY).unwrap().to_string(),
            json!(format!("b64:{}", BASE64_STANDARD.encode(&vs_bytes))),
        );
        let record = ActiveKeyRecord {
            suite,
            pubkey_hash: acct.0,
            since_height: 0,
        };
        let record_key = [b"identity::key_record::", acct.as_ref()].concat();
        let record_bytes = codec::to_bytes_canonical(&record);
        genesis_state.insert(
            format!("b64:{}", BASE64_STANDARD.encode(&record_key)),
            json!(format!("b64:{}", BASE64_STANDARD.encode(&record_bytes))),
        );
        let map_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, acct.as_ref()].concat();
        genesis_state.insert(
            format!("b64:{}", BASE64_STANDARD.encode(&map_key)),
            json!(format!("b64:{}", BASE64_STANDARD.encode(&pk))),
        );
        genesis.to_string()
    };

    // --- Launch with the `light_readiness_check` parameter set to true ---
    let node = TestValidator::launch(
        keypair,
        genesis_content,
        7000, // Use a unique port base to avoid conflicts
        1.into(),
        None,
        "ProofOfAuthority",
        "IAVL",
        "Hash",
        None,
        false, // use_docker
        vec![],
        true,  // use_malicious_workload
        true,  // light_readiness_check
    )
    .await?;

    // 3. Get the log stream and start asserting immediately.
    let (mut orch_logs, _, _) = node.subscribe_logs();

    // 4. Assert that Orchestration logs the critical failure message.
    // The consensus ticker will start, attempt to produce block 1, query the malicious
    // workload for the validator set, receive a bad proof, and log the error.
    assert_log_contains(
        "Orchestration",
        &mut orch_logs,
        "CRITICAL: Proof verification failed for remote state read",
    )
    .await?;

    println!("--- Negative E2E Test Passed: Orchestration correctly rejected a tampered proof ---");
    Ok(())
}