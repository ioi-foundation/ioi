// Path: forge/tests/proof_verification_e2e.rs

#![cfg(all(
    feature = "consensus-poa",
    feature = "vm-wasm",
    feature = "tree-iavl",
    feature = "primitive-hash",
    feature = "malicious-bin"
))]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use depin_sdk_forge::testing::{assert_log_contains, build_test_artifacts, TestCluster};
use depin_sdk_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, SignatureSuite, ValidatorSetBlob,
        ValidatorSetV1, ValidatorV1,
    },
    codec,
    keys::{
        ACCOUNT_ID_TO_PUBKEY_PREFIX, IDENTITY_CREDENTIALS_PREFIX, VALIDATOR_SET_KEY,
    },
};
use serde_json::json;

#[tokio::test]
async fn test_orchestration_rejects_tampered_proof() -> Result<()> {
    // 1. Build binaries with the malicious feature enabled
    // This ensures the `malicious-workload` binary is available.
    build_test_artifacts("consensus-poa,vm-wasm,tree-iavl,primitive-hash,malicious-bin");

    // 2. Launch a cluster configured to use the malicious workload.
    // The builder needs to be modified to support selecting the workload binary.
    // For this implementation, we'll assume a new builder method `with_malicious_workload`.
    let mut cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("ProofOfAuthority")
        .with_state_tree("IAVL") // Use IAVL as it has robust proof logic
        .with_commitment_scheme("Hash")
        .with_malicious_workload(true) // A hypothetical new builder method
        .with_genesis_modifier(|genesis, keys| {
            // Setup a basic PoA genesis state
            let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();
            let suite = SignatureSuite::Ed25519;
            let pk = keys[0].public().encode_protobuf();
            let acct_hash = account_id_from_key_material(suite, &pk).unwrap();
            let acct = AccountId(acct_hash);

            let vs_blob = ValidatorSetBlob {
                schema_version: 1,
                payload: ValidatorSetV1 {
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

            // Add the "poison_pill" key to the genesis state so the Orchestrator will read it.
            // A consensus engine might read a special key like this for configuration.
            genesis["genesis_state"]["poison_pill"] = json!("initial_value");
        })
        .build()
        .await?;

    let node = &mut cluster.validators[0];
    let (mut orch_logs, _, _) = node.subscribe_logs();
    let rpc_addr = &node.rpc_addr;

    // 3. Trigger a state read for the "poisoned" key.
    // A simple way to do this is to make an RPC call that forces the Orchestrator's
    // RemoteStateView to query the key. We'll simulate a consensus action that reads this key.
    // In a real scenario, the consensus `decide` loop would trigger this naturally.
    // For this test, we can use a placeholder for a specific action that reads the key.
    // We expect the read to fail internally, so we don't need to check the RPC result itself.
    let client = reqwest::Client::new();
    let request_body = serde_json::json!({
        "jsonrpc":"2.0",
        "method":"query_state_proof_test", // A hypothetical RPC method to trigger the read
        "params":[hex::encode(b"poison_pill")],
        "id":1
    });
    // The actual call might fail because the Orchestrator will error out, which is what we want.
    let _ = client
        .post(format!("http://{}/rpc", rpc_addr))
        .json(&request_body)
        .send()
        .await;

    // 4. Assert that Orchestration logs the critical failure message.
    // This proves that the verifier in RemoteStateView caught the tampered proof
    // and the error was propagated correctly.
    assert_log_contains(
        "Orchestration",
        &mut orch_logs,
        "CRITICAL: Proof verification failed for remote state read",
    )
    .await?;

    println!("--- Negative E2E Test Passed: Orchestration correctly rejected a tampered proof ---");
    Ok(())
}