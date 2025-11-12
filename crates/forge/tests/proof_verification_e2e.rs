// Path: crates/forge/tests/proof_verification_e2e.rs

#![cfg(all(
    feature = "consensus-poa",
    feature = "vm-wasm",
    feature = "state-iavl",
    feature = "commitment-hash",
    feature = "malicious-bin"
))]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ioi_forge::testing::{
    assert_log_contains, build_test_artifacts, wait_for_height, TestValidator,
};
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, BlockTimingParams,
        BlockTimingRuntime, Credential, SignatureSuite, ValidatorSetV1, ValidatorSetsV1,
        ValidatorV1,
    },
    codec,
    config::InitialServiceConfig,
    keys::{
        ACCOUNT_ID_TO_PUBKEY_PREFIX, BLOCK_TIMING_PARAMS_KEY, BLOCK_TIMING_RUNTIME_KEY,
        IDENTITY_CREDENTIALS_PREFIX, VALIDATOR_SET_KEY,
    },
    service_configs::MigrationConfig,
};
use libp2p::identity;
use serde_json::json;
use std::time::Duration;

#[tokio::test]
async fn test_orchestration_rejects_tampered_proof() -> Result<()> {
    // 1. Build test-only artifacts (contracts).
    build_test_artifacts();

    // 2. Programmatically generate a minimal but valid genesis for a single PoA node.
    let keypair = identity::Keypair::generate_ed25519();
    let genesis_content = {
        let mut genesis = json!({ "genesis_state": {} });
        let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();
        let suite = SignatureSuite::Ed25519;
        let pk = keypair.public().encode_protobuf();
        let acct_hash = account_id_from_key_material(suite, &pk).unwrap();
        let acct = AccountId(acct_hash);

        // Define the validator set
        let vs = ValidatorSetV1 {
            effective_from_height: 1,
            total_weight: 1,
            validators: vec![ValidatorV1 {
                account_id: acct,
                weight: 1,
                consensus_key: ActiveKeyRecord {
                    suite: SignatureSuite::Ed25519,
                    public_key_hash: acct_hash,
                    since_height: 0,
                },
            }],
        };
        let vs_bytes = ioi_types::app::write_validator_sets(&ValidatorSetsV1 {
            current: vs,
            next: None,
        })
        .unwrap();
        genesis_state.insert(
            std::str::from_utf8(VALIDATOR_SET_KEY).unwrap().to_string(),
            json!(format!("b64:{}", BASE64_STANDARD.encode(vs_bytes))),
        );

        // Add identity records required for startup and signing
        let record = ActiveKeyRecord {
            suite,
            public_key_hash: acct.0,
            since_height: 0,
        };
        let record_key = [b"identity::key_record::", acct.as_ref()].concat();
        let record_bytes = codec::to_bytes_canonical(&record).unwrap();
        genesis_state.insert(
            format!("b64:{}", BASE64_STANDARD.encode(&record_key)),
            json!(format!("b64:{}", BASE64_STANDARD.encode(&record_bytes))),
        );
        let map_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, acct.as_ref()].concat();
        genesis_state.insert(
            format!("b64:{}", BASE64_STANDARD.encode(&map_key)),
            json!(format!("b64:{}", BASE64_STANDARD.encode(&pk))),
        );
        let initial_cred = Credential {
            suite,
            public_key_hash: acct_hash,
            activation_height: 0,
            l2_location: None,
        };
        let creds_array: [Option<Credential>; 2] = [Some(initial_cred), None];
        let creds_bytes = codec::to_bytes_canonical(&creds_array).unwrap();
        let creds_key = [IDENTITY_CREDENTIALS_PREFIX, acct.as_ref()].concat();
        genesis_state.insert(
            format!("b64:{}", BASE64_STANDARD.encode(&creds_key)),
            json!(format!("b64:{}", BASE64_STANDARD.encode(&creds_bytes))),
        );

        // Add required block timing params
        let timing_params = BlockTimingParams {
            base_interval_secs: 5,
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

    // 3. Launch a single node with the malicious workload.
    // Use a light readiness check because we EXPECT consensus to stall, so the full
    // startup complete signal will never be emitted.
    let node_guard = TestValidator::launch(
        keypair,
        genesis_content,
        7000,
        1.into(),
        None,
        "ProofOfAuthority",
        "IAVL",
        "Hash",
        None, // ibc_gateway_addr
        None, // agentic_model_path
        false,
        vec![InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
        })],
        true, // use_malicious_workload
        true, // light_readiness_check
        &[],  // extra_features
    )
    .await?;

    // 4. Wrap the test logic in an async block to ensure cleanup happens on failure.
    let test_result: anyhow::Result<()> = async {
        let node = node_guard.validator();
        let (mut orch_logs, _, _) = node.subscribe_logs();

        // The node, connected to a malicious workload, should fail its internal proof
        // verification and stall consensus. It should NEVER produce block 1.
        // We assert this by waiting for height 1 and expecting the wait to time out.
        // A timeout here is the sign of a successful test.
        let wait_result = wait_for_height(&node.rpc_addr, 1, Duration::from_secs(15)).await;

        assert!(
            wait_result.is_err(),
            "Node should have stalled due to invalid proofs, but it successfully produced a block."
        );

        // Additionally, check the orchestrator logs for the "CRITICAL" proof verification failure message.
        assert_log_contains(
            "Orchestration",
            &mut orch_logs,
            "CRITICAL: Proof verification failed for remote state read",
        )
        .await?;

        Ok(())
    }
    .await;

    // 5. Guaranteed cleanup.
    node_guard.shutdown().await?;

    // 6. Propagate the test result.
    test_result?;

    println!("--- Negative E2E Test Passed: Orchestration correctly stalled after receiving tampered proof ---");
    Ok(())
}
