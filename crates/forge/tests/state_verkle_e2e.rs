// Path: crates/forge/tests/state_verkle_e2e.rs
#![cfg(all(
    feature = "consensus-poa",
    feature = "vm-wasm",
    feature = "tree-verkle",
    feature = "primitive-kzg"
))]

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use depin_sdk_forge::testing::{build_test_artifacts, poll::wait_for_height, TestCluster};
use depin_sdk_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, SignatureSuite, ValidatorSetBlob,
        ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    codec,
    config::InitialServiceConfig,
    keys::{ACCOUNT_ID_TO_PUBKEY_PREFIX, IDENTITY_CREDENTIALS_PREFIX, VALIDATOR_SET_KEY},
    service_configs::MigrationConfig,
};
use serde_json::json;
use std::time::Duration;

#[tokio::test]
async fn test_verkle_tree_e2e() -> Result<()> {
    // 1. Build binaries with the specific Verkle feature enabled
    build_test_artifacts();

    // 2. Launch a cluster configured to use the VerkleTree
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
            let suite = SignatureSuite::Ed25519;
            let pk = keys[0].public().encode_protobuf();
            let acct_hash = account_id_from_key_material(suite, &pk).unwrap();
            let acct = AccountId(acct_hash);

            let validator_set = ValidatorSetV1 {
                effective_from_height: 1,
                total_weight: 1,
                validators: vec![ValidatorV1 {
                    account_id: acct,
                    weight: 1, // PoA uses weight 1
                    consensus_key: ActiveKeyRecord {
                        suite: SignatureSuite::Ed25519,
                        pubkey_hash: acct_hash,
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
            let vs_bytes = depin_sdk_types::app::write_validator_sets(&vs_blob.payload).unwrap();
            genesis_state.insert(
                std::str::from_utf8(VALIDATOR_SET_KEY).unwrap().to_string(),
                json!(format!("b64:{}", BASE64_STANDARD.encode(vs_bytes))),
            );

            // ActiveKeyRecord for consensus verification
            let record = ActiveKeyRecord {
                suite,
                pubkey_hash: acct.0,
                since_height: 0,
            };
            let record_key = [b"identity::key_record::", acct.as_ref()].concat();
            let record_bytes = codec::to_bytes_canonical(&record).unwrap();
            genesis_state.insert(
                format!("b64:{}", BASE64_STANDARD.encode(&record_key)),
                json!(format!("b64:{}", BASE64_STANDARD.encode(&record_bytes))),
            );

            // AccountId -> PubKey map for consensus verification
            let map_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, acct.as_ref()].concat();
            genesis_state.insert(
                format!("b64:{}", BASE64_STANDARD.encode(&map_key)),
                json!(format!("b64:{}", BASE64_STANDARD.encode(&pk))),
            );

            // Initial credentials for the IdentityHub
            let initial_cred = depin_sdk_types::app::Credential {
                suite,
                public_key_hash: acct_hash,
                activation_height: 0,
                l2_location: None,
            };
            let creds_array: [Option<depin_sdk_types::app::Credential>; 2] =
                [Some(initial_cred), None];
            let creds_bytes = serde_json::to_vec(&creds_array).unwrap();
            let creds_key = [IDENTITY_CREDENTIALS_PREFIX, acct.as_ref()].concat();
            genesis_state.insert(
                format!("b64:{}", BASE64_STANDARD.encode(&creds_key)),
                json!(format!("b64:{}", BASE64_STANDARD.encode(&creds_bytes))),
            );
        })
        .build()
        .await?;

    // 3. Get handles and wait for node to be ready
    let node = &cluster.validators[0];
    let rpc_addr = &node.rpc_addr;

    println!("--- Verkle Node Launched ---");

    // Assert that the node can produce a block by polling its state via RPC.
    wait_for_height(rpc_addr, 1, Duration::from_secs(20)).await?;
    println!("--- Bootstrap Block #1 Processed ---");

    println!("--- Verkle Tree E2E Test Passed ---");
    Ok(())
}
