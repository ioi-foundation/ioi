// Path: crates/forge/tests/state_verkle_e2e.rs
#![cfg(all(
    feature = "consensus-poa",
    feature = "vm-wasm",
    feature = "state-verkle",
    feature = "commitment-kzg"
))]

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ioi_forge::testing::{
    add_genesis_identity, build_test_artifacts, wait_for_height, TestCluster,
}; // [+] Import
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, SignatureSuite, ValidatorSetBlob,
        ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    codec,
    config::InitialServiceConfig,
    keys::VALIDATOR_SET_KEY, // Removed other keys as helper handles them
    service_configs::MigrationConfig,
};
use serde_json::json;
use std::time::Duration;

#[tokio::test]
async fn test_verkle_tree_e2e() -> Result<()> {
    build_test_artifacts();

    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("ProofOfAuthority")
        .with_state_tree("Verkle")
        .with_commitment_scheme("KZG")
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
            chain_id: 1,
        }))
        .with_genesis_modifier(|genesis, keys| {
            let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();

            // [+] Use shared helper
            let key = &keys[0];
            let account_id = add_genesis_identity(genesis_state, key);
            let acct_hash = account_id.0;

            let validator_set = ValidatorSetV1 {
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

            let vs_blob = ValidatorSetBlob {
                schema_version: 2,
                payload: ValidatorSetsV1 {
                    current: validator_set,
                    next: None,
                },
            };
            let vs_bytes = ioi_types::app::write_validator_sets(&vs_blob.payload).unwrap();
            genesis_state.insert(
                std::str::from_utf8(VALIDATOR_SET_KEY).unwrap().to_string(),
                json!(format!("b64:{}", BASE64_STANDARD.encode(vs_bytes))),
            );

            // [-] REMOVED: Manual identity record insertion
        })
        .build()
        .await?;

    let node_guard = &cluster.validators[0];
    let rpc_addr = &node_guard.validator().rpc_addr;

    println!("--- Verkle Node Launched ---");

    wait_for_height(rpc_addr, 1, Duration::from_secs(20)).await?;
    println!("--- Bootstrap Block #1 Processed ---");

    println!("--- Verkle Tree E2E Test Passed ---");

    for guard in cluster.validators {
        guard.shutdown().await?;
    }

    Ok(())
}
