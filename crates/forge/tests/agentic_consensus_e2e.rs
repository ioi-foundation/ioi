// Path: crates/forge/tests/agentic_consensus_e2e.rs

#![cfg(all(feature = "consensus-poa", feature = "vm-wasm"))]

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ioi_crypto::algorithms::hash::sha256;
use ioi_forge::testing::{build_test_artifacts, TestCluster};
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, Credential, SignatureSuite,
        ValidatorSetBlob, ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    codec,
    config::InitialServiceConfig,
    keys::{
        ACCOUNT_ID_TO_PUBKEY_PREFIX, IDENTITY_CREDENTIALS_PREFIX, STATE_KEY_SEMANTIC_MODEL_HASH,
        VALIDATOR_SET_KEY,
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
    let creds_bytes = codec::to_bytes_canonical(&creds_array).unwrap();
    let creds_key = [IDENTITY_CREDENTIALS_PREFIX, account_id.as_ref()].concat();
    let creds_key_b64 = format!("b64:{}", BASE64_STANDARD.encode(&creds_key));
    genesis_state.insert(
        creds_key_b64,
        json!(format!("b64:{}", BASE64_STANDARD.encode(&creds_bytes))),
    );

    // C. Set the ActiveKeyRecord for consensus verification
    let record = ActiveKeyRecord {
        suite,
        public_key_hash: account_id_hash,
        since_height: 0,
    };
    let record_key = [b"identity::key_record::", account_id.as_ref()].concat();
    let record_bytes = codec::to_bytes_canonical(&record).unwrap();
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
    build_test_artifacts();

    // Setup: Create model file and calculate its hash
    let temp_dir_models = tempdir()?;
    let good_model_path = temp_dir_models.path().join("good_model.bin");
    fs::write(&good_model_path, "correct_model_data")?;
    let correct_model_hash = hex::encode(sha256(b"correct_model_data").unwrap());

    let k0 = identity::Keypair::generate_ed25519();
    let k1 = identity::Keypair::generate_ed25519();
    let k2 = identity::Keypair::generate_ed25519();
    let all_keys = vec![k0, k1, k2];

    let services = vec![InitialServiceConfig::IdentityHub(MigrationConfig {
        chain_id: 1,
        grace_period_blocks: 5,
        accept_staged_during_grace: true,
        allowed_target_suites: vec![SignatureSuite::Ed25519],
        allow_downgrade: false,
    })];

    let cluster = TestCluster::builder()
        .with_validators(3)
        .with_keypairs(all_keys)
        .with_consensus_type("ProofOfAuthority")
        .with_state_tree("IAVL")
        .with_commitment_scheme("Hash")
        .with_agentic_model_path(good_model_path.to_str().unwrap())
        .with_initial_service(services[0].clone())
        .with_genesis_modifier(move |genesis, keys| {
            let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();

            let mut auths = vec![
                add_poa_identity_to_genesis(genesis_state, &keys[0]),
                add_poa_identity_to_genesis(genesis_state, &keys[1]),
                add_poa_identity_to_genesis(genesis_state, &keys[2]),
            ];
            auths.sort();

            let validators: Vec<ValidatorV1> = auths
                .into_iter()
                .map(|account_id| ValidatorV1 {
                    account_id,
                    weight: 1,
                    consensus_key: ActiveKeyRecord {
                        suite: SignatureSuite::Ed25519,
                        public_key_hash: account_id.0,
                        since_height: 0,
                    },
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
            genesis_state.insert(
                std::str::from_utf8(STATE_KEY_SEMANTIC_MODEL_HASH)
                    .unwrap()
                    .to_string(),
                json!(correct_model_hash),
            );
        })
        .build()
        .await?;

    // The test logic is now implicitly handled by `build()`.
    // It waits for all nodes to start, connect, and sync.
    // The test passes if `build()` completes without error.

    // Explicitly shut down all validators before the function returns.
    for guard in cluster.validators {
        guard.shutdown().await?;
    }

    Ok(())
}

#[tokio::test]
async fn test_mismatched_model_quarantine() -> Result<()> {
    build_test_artifacts();

    // Setup: Create two different model files
    let temp_dir_models = tempdir()?;
    let bad_model_path = temp_dir_models.path().join("bad_model.bin");
    fs::write(&bad_model_path, "incorrect_model_data")?;
    let correct_model_hash = hex::encode(sha256(b"correct_model_data").unwrap());

    // Use a single-node setup to remove network race conditions.
    let key = identity::Keypair::generate_ed25519();

    let services = vec![InitialServiceConfig::IdentityHub(MigrationConfig {
        chain_id: 1,
        grace_period_blocks: 5,
        accept_staged_during_grace: true,
        allowed_target_suites: vec![SignatureSuite::Ed25519],
        allow_downgrade: false,
    })];

    // Use a closure to capture the result of the async block
    let cluster_result = async {
        TestCluster::builder()
            .with_validators(1)
            .with_keypairs(vec![key.clone()])
            .with_consensus_type("ProofOfAuthority")
            .with_state_tree("IAVL")
            .with_commitment_scheme("Hash")
            .with_agentic_model_path(bad_model_path.to_str().unwrap())
            .with_initial_service(services[0].clone())
            .with_genesis_modifier(move |genesis, keys| {
                let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();
                let authority_id = add_poa_identity_to_genesis(genesis_state, &keys[0]);
                let vs_blob = ValidatorSetBlob {
                    schema_version: 2,
                    payload: ValidatorSetsV1 {
                        current: ValidatorSetV1 {
                            effective_from_height: 1,
                            total_weight: 1,
                            validators: vec![ValidatorV1 {
                                account_id: authority_id,
                                weight: 1,
                                consensus_key: ActiveKeyRecord {
                                    suite: SignatureSuite::Ed25519,
                                    public_key_hash: authority_id.0,
                                    since_height: 0,
                                },
                            }],
                        },
                        next: None,
                    },
                };
                let vs_bytes = ioi_types::app::write_validator_sets(&vs_blob.payload).unwrap();
                genesis_state.insert(
                    std::str::from_utf8(VALIDATOR_SET_KEY).unwrap().to_string(),
                    json!(format!("b64:{}", BASE64_STANDARD.encode(vs_bytes))),
                );
                genesis_state.insert(
                    std::str::from_utf8(STATE_KEY_SEMANTIC_MODEL_HASH)
                        .unwrap()
                        .to_string(),
                    json!(correct_model_hash),
                );
            })
            .build()
            .await
    }
    .await;

    // A node that fails attestation will never become "ready" and the builder will time out.
    // Assert that the builder returned an error.
    assert!(
        cluster_result.is_err(),
        "Cluster build should have failed due to attestation failure, but it succeeded."
    );

    if let Err(e) = cluster_result {
        assert!(
            e.to_string().contains("Agentic attestation failed"),
            "Expected an attestation failure, but got: {}",
            e
        );
    }

    Ok(())
}
