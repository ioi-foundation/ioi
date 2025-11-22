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
    add_genesis_identity, // [+] Import
    assert_log_contains,
    build_test_artifacts,
    wait_for_height,
    TestValidator,
};
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, BlockTimingParams,
        BlockTimingRuntime, Credential, SignatureSuite, ValidatorSetV1, ValidatorSetsV1,
        ValidatorV1,
    },
    codec,
    config::InitialServiceConfig,
    keys::{BLOCK_TIMING_PARAMS_KEY, BLOCK_TIMING_RUNTIME_KEY, VALIDATOR_SET_KEY},
    service_configs::MigrationConfig,
};
use libp2p::identity;
use serde_json::json;
use std::time::Duration;

#[tokio::test]
async fn test_orchestration_rejects_tampered_proof() -> Result<()> {
    build_test_artifacts();

    let keypair = identity::Keypair::generate_ed25519();
    let genesis_content = {
        let mut genesis = json!({ "genesis_state": {} });
        let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();

        // [+] Use shared helper
        let account_id = add_genesis_identity(genesis_state, &keypair);
        let acct_hash = account_id.0;

        // Define the validator set
        let vs = ValidatorSetV1 {
            effective_from_height: 1,
            total_weight: 1,
            validators: vec![ValidatorV1 {
                account_id,
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

        // [-] REMOVED: Manual Identity Records insertion

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

    let node_guard = TestValidator::launch(
        keypair,
        genesis_content,
        7000,
        1.into(),
        None,
        "ProofOfAuthority",
        "IAVL",
        "Hash",
        None,
        None,
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
        &[],
    )
    .await?;

    let test_result: anyhow::Result<()> = async {
        let node = node_guard.validator();
        let (mut orch_logs, _, _) = node.subscribe_logs();

        // The node should stall.
        let wait_result = wait_for_height(&node.rpc_addr, 1, Duration::from_secs(15)).await;

        assert!(
            wait_result.is_err(),
            "Node should have stalled due to invalid proofs."
        );

        assert_log_contains(
            "Orchestration",
            &mut orch_logs,
            "CRITICAL: Proof verification failed for remote state read",
        )
        .await?;

        Ok(())
    }
    .await;

    node_guard.shutdown().await?;
    test_result?;

    println!("--- Negative E2E Test Passed ---");
    Ok(())
}
