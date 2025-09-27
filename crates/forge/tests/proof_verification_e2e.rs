// Path: crates/forge/tests/proof_verification_e2e.rs

#![cfg(all(
    feature = "consensus-poa",
    feature = "vm-wasm",
    feature = "tree-iavl",
    feature = "primitive-hash",
    feature = "malicious-bin"
))]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use depin_sdk_forge::testing::{build_test_artifacts, poll::wait_for_height, TestValidator};
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
use std::time::Duration;

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
        true, // use_malicious_workload
        // A light readiness check is sufficient here, as we are not relying on log timing.
        true,
    )
    .await?;

    // 3. ASSERT CORRECT BEHAVIOR
    // The node, connected to a malicious workload, should fail its internal proof
    // verification and stall consensus. It should NEVER produce block 1.
    // We assert this by waiting for height 1 and expecting the wait to time out.
    // A timeout here is the sign of a successful test.
    let wait_result = wait_for_height(&node.rpc_addr, 1, Duration::from_secs(15)).await;

    assert!(
        wait_result.is_err(),
        "Node should have stalled due to invalid proofs, but it successfully produced a block."
    );

    println!("--- Negative E2E Test Passed: Orchestration correctly stalled after receiving tampered proof ---");
    Ok(())
}
