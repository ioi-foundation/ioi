// Path: crates/forge/tests/agentic_consensus_e2e.rs

#![cfg(all(feature = "consensus-poa", feature = "vm-wasm"))]

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use depin_sdk_crypto::algorithms::hash::sha256;
use depin_sdk_forge::testing::{
    assert_log_contains, build_test_artifacts, TestCluster, TestValidator,
};
use depin_sdk_types::{
    app::{account_id_from_key_material, AccountId, ActiveKeyRecord, Credential, SignatureSuite},
    codec,
    config::InitialServiceConfig,
    keys::{
        ACCOUNT_ID_TO_PUBKEY_PREFIX, AUTHORITY_SET_KEY, IDENTITY_CREDENTIALS_PREFIX,
        STATE_KEY_SEMANTIC_MODEL_HASH,
    },
    service_configs::MigrationConfig,
};
use libp2p::identity;
use serde_json::{json, Value};
use std::fs;
use tempfile::tempdir;

/// Helper function to add a full identity record for a PoA authority to the genesis state.
fn add_poa_identity_to_genesis(
    genesis_state: &mut serde_json::Map<String, Value>,
    keypair: &identity::Keypair,
) -> AccountId {
    let suite = SignatureSuite::Ed25519;
    let public_key_bytes = keypair.public().encode_protobuf();
    let account_id_hash = account_id_from_key_material(suite, &public_key_bytes).unwrap();
    let account_id = AccountId(account_id_hash);

    // B. Set the initial IdentityHub credentials
    let initial_cred = Credential {
        suite,
        public_key_hash: account_id_hash,
        activation_height: 0,
        l2_location: None,
    };
    let creds_array: [Option<Credential>; 2] = [Some(initial_cred), None];
    let creds_bytes = serde_json::to_vec(&creds_array).unwrap();
    let creds_key = [IDENTITY_CREDENTIALS_PREFIX, account_id.as_ref()].concat();
    let creds_key_b64 = format!("b64:{}", BASE64_STANDARD.encode(&creds_key));
    genesis_state.insert(
        creds_key_b64,
        json!(format!("b64:{}", BASE64_STANDARD.encode(&creds_bytes))),
    );

    // C. Set the ActiveKeyRecord for consensus verification
    let record = ActiveKeyRecord {
        suite,
        pubkey_hash: account_id_hash,
        since_height: 0,
    };
    let record_key = [b"identity::key_record::", account_id.as_ref()].concat();
    let record_bytes = codec::to_bytes_canonical(&record);
    genesis_state.insert(
        format!("b64:{}", BASE64_STANDARD.encode(&record_key)),
        json!(format!("b64:{}", BASE64_STANDARD.encode(&record_bytes))),
    );

    // D. Set the AccountId -> PublicKey mapping for consensus verification
    let pubkey_map_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, account_id.as_ref()].concat();
    genesis_state.insert(
        format!("b64:{}", BASE64_STANDARD.encode(&pubkey_map_key)),
        json!(format!("b64:{}", BASE64_STANDARD.encode(&public_key_bytes))),
    );

    account_id
}

#[tokio::test]
async fn test_secure_agentic_consensus_e2e() -> Result<()> {
    build_test_artifacts("consensus-poa,vm-wasm,tree-file,primitive-hash");

    // Setup: Create model file and calculate its hash
    let temp_dir_models = tempdir()?;
    let good_model_path = temp_dir_models.path().join("good_model.bin");
    fs::write(&good_model_path, "correct_model_data")?;
    let correct_model_hash = hex::encode(sha256(b"correct_model_data"));

    let _cluster = TestCluster::builder()
        .with_validators(3)
        .with_consensus_type("ProofOfAuthority")
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
        }))
        .with_genesis_modifier(move |genesis, keys| {
            let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();
            let authorities: Vec<AccountId> = keys
                .iter()
                .map(|k| add_poa_identity_to_genesis(genesis_state, k))
                .collect();

            let authorities_bytes = codec::to_bytes_canonical(&authorities);
            genesis_state.insert(
                std::str::from_utf8(AUTHORITY_SET_KEY).unwrap().to_string(),
                json!(format!("b64:{}", BASE64_STANDARD.encode(authorities_bytes))),
            );
            genesis_state.insert(
                std::str::from_utf8(STATE_KEY_SEMANTIC_MODEL_HASH)
                    .unwrap()
                    .to_string(),
                json!(correct_model_hash),
            );
        })
        .with_agentic_model_path(good_model_path.to_str().unwrap())
        .build()
        .await?;

    Ok(())
}

#[tokio::test]
async fn test_mismatched_model_quarantine() -> Result<()> {
    build_test_artifacts("consensus-poa,vm-wasm,tree-file,primitive-hash");

    // Setup: Create two different model files
    let temp_dir_models = tempdir()?;
    let bad_model_path = temp_dir_models.path().join("bad_model.bin");
    fs::write(&bad_model_path, "incorrect_model_data")?;
    let correct_model_hash = hex::encode(sha256(b"correct_model_data"));

    // Use a single-node setup to remove network race conditions.
    let key = identity::Keypair::generate_ed25519();
    let genesis_content = {
        let mut genesis = json!({ "genesis_state": {} });
        let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();

        let authority_id = add_poa_identity_to_genesis(genesis_state, &key);
        let authorities_bytes = codec::to_bytes_canonical(&vec![authority_id]);
        genesis_state.insert(
            std::str::from_utf8(AUTHORITY_SET_KEY).unwrap().to_string(),
            json!(format!("b64:{}", BASE64_STANDARD.encode(authorities_bytes))),
        );
        genesis_state.insert(
            std::str::from_utf8(STATE_KEY_SEMANTIC_MODEL_HASH)
                .unwrap()
                .to_string(),
            json!(correct_model_hash),
        );
        genesis.to_string()
    };

    // Launch a single node with the mismatched model.
    let bad_node = TestValidator::launch(
        key.clone(),
        genesis_content.clone(),
        6000,
        None,
        "ProofOfAuthority",
        "File",
        "Hash",
        Some(bad_model_path.to_str().unwrap()),
        false,
        vec![InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
        })],
    )
    .await?;

    let mut bad_node_logs = bad_node.orch_log_stream.lock().await.take().unwrap();

    // Assert that the node correctly identifies the model mismatch and quarantines itself.
    assert_log_contains("BadNode", &mut bad_node_logs, "Model Integrity Failure!").await?;

    Ok(())
}
