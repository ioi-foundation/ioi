// Path: crates/forge/tests/agentic_consensus_e2e.rs

#![cfg(all(feature = "consensus-poa", feature = "vm-wasm"))]

use anyhow::Result;
use ioi_crypto::algorithms::hash::sha256;
use ioi_forge::testing::{build_test_artifacts, genesis::GenesisBuilder, TestCluster};
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, SignatureSuite, ValidatorSetV1,
        ValidatorSetsV1, ValidatorV1,
    },
    config::InitialServiceConfig,
    keys::STATE_KEY_SEMANTIC_MODEL_HASH,
    service_configs::MigrationConfig,
};
use libp2p::identity;
use serde_json::json;
use std::fs;
use tempfile::tempdir;

// ... helper ...
fn add_poa_identity_to_genesis(
    builder: &mut GenesisBuilder,
    keypair: &identity::Keypair,
) -> AccountId {
    let suite = SignatureSuite::Ed25519;
    let pk_bytes = keypair.public().encode_protobuf();
    builder.add_identity_custom(suite, &pk_bytes)
}

#[tokio::test]
async fn test_secure_agentic_consensus_e2e() -> Result<()> {
    build_test_artifacts();

    let temp_dir_models = tempdir()?;
    let good_model_path = temp_dir_models.path().join("good_model.bin");
    fs::write(&good_model_path, "correct_model_data")?;
    let correct_model_hash = hex::encode(sha256(b"correct_model_data").unwrap());

    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("ProofOfAuthority")
        .with_state_tree("IAVL")
        .with_commitment_scheme("Hash")
        .with_agentic_model_path(good_model_path.to_str().unwrap())
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
        }))
        .with_genesis_modifier(move |builder, keys| {
            let mut validators = Vec::new();
            for key in keys {
                let account_id = add_poa_identity_to_genesis(builder, key);
                validators.push(ValidatorV1 {
                    account_id,
                    weight: 1,
                    consensus_key: ActiveKeyRecord {
                        suite: SignatureSuite::Ed25519,
                        public_key_hash: account_id.0,
                        since_height: 0,
                    },
                });
            }

            validators.sort_by(|a, b| a.account_id.cmp(&b.account_id));

            let vs = ValidatorSetsV1 {
                current: ValidatorSetV1 {
                    effective_from_height: 1,
                    total_weight: validators.len() as u128,
                    validators,
                },
                next: None,
            };

            builder.set_validators(&vs);

            let hash_json_bytes = serde_json::to_vec(&correct_model_hash).unwrap();
            builder.insert_raw(STATE_KEY_SEMANTIC_MODEL_HASH, hash_json_bytes);
        })
        .build()
        .await?;

    // --- ENABLE LOGGING ---
    let node = &cluster.validators[0];
    let (mut orch_logs, mut work_logs, _) = node.validator().subscribe_logs();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                Ok(line) = orch_logs.recv() => println!("[ORCH] {}", line),
                Ok(line) = work_logs.recv() => println!("[WORK] {}", line),
            }
        }
    });

    let rpc_addr = &node.validator().rpc_addr;
    println!("Waiting for height 2...");
    let res =
        ioi_forge::testing::wait_for_height(rpc_addr, 2, std::time::Duration::from_secs(60)).await;

    if res.is_err() {
        let metrics_url = format!(
            "http://{}/metrics",
            node.validator().orchestration_telemetry_addr
        );
        if let Ok(m) = reqwest::get(&metrics_url).await {
            if let Ok(text) = m.text().await {
                println!("--- METRICS DUMP ---\n{}", text);
            }
        }
    }

    for guard in cluster.validators {
        guard.shutdown().await?;
    }

    res?;
    Ok(())
}

#[tokio::test]
async fn test_mismatched_model_quarantine() -> Result<()> {
    // ... same as before ...
    build_test_artifacts();
    let temp_dir_models = tempdir()?;
    let bad_model_path = temp_dir_models.path().join("bad_model.bin");
    fs::write(&bad_model_path, "incorrect_model_data")?;
    let correct_model_hash = hex::encode(sha256(b"correct_model_data").unwrap());
    let key = identity::Keypair::generate_ed25519();
    let services = vec![InitialServiceConfig::IdentityHub(MigrationConfig {
        chain_id: 1,
        grace_period_blocks: 5,
        accept_staged_during_grace: true,
        allowed_target_suites: vec![SignatureSuite::Ed25519],
        allow_downgrade: false,
    })];

    let cluster_result = async {
        TestCluster::builder()
            .with_validators(1)
            .with_keypairs(vec![key.clone()])
            .with_consensus_type("ProofOfAuthority")
            .with_state_tree("IAVL")
            .with_commitment_scheme("Hash")
            .with_agentic_model_path(bad_model_path.to_str().unwrap())
            .with_initial_service(services[0].clone())
            .with_genesis_modifier(move |builder, keys| {
                let authority_id = add_poa_identity_to_genesis(builder, &keys[0]);
                let vs = ValidatorSetsV1 {
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
                };
                builder.set_validators(&vs);
                let hash_json_bytes = serde_json::to_vec(&correct_model_hash).unwrap();
                builder.insert_raw(STATE_KEY_SEMANTIC_MODEL_HASH, hash_json_bytes);
            })
            .build()
            .await
    }
    .await;

    assert!(cluster_result.is_err());
    if let Err(e) = cluster_result {
        let msg = e.to_string();
        assert!(msg.contains("Agentic attestation failed") || msg.contains("Quarantining node"));
    }
    Ok(())
}
