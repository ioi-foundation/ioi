// Path: crates/forge/tests/chain_factory_e2e.rs

#![cfg(all(
    feature = "consensus-poa",
    feature = "consensus-pos",
    feature = "vm-wasm",
    feature = "tree-file",
    feature = "tree-hashmap",
    feature = "primitive-hash"
))]

use anyhow::Result;
use depin_sdk_forge::testing::{assert_log_contains, build_test_artifacts, TestCluster};
use depin_sdk_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, SignatureSuite, ValidatorSetBlob,
        ValidatorSetV1, ValidatorV1,
    },
    codec,
};
use serde_json::json;

#[tokio::test]
async fn test_concurrent_polymorphic_chains() -> Result<()> {
    // Build binaries with all necessary features enabled for both clusters.
    build_test_artifacts(
        "consensus-poa,consensus-pos,vm-wasm,tree-file,tree-hashmap,primitive-hash",
    );

    // --- Define Cluster A: Proof of Authority with FileStateTree ---
    let cluster_a_handle = tokio::spawn(async {
        let cluster = TestCluster::builder()
            .with_validators(1)
            .with_consensus_type("ProofOfAuthority")
            .with_state_tree("File")
            .with_commitment_scheme("Hash")
            .with_genesis_modifier(|genesis, keys| {
                let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();
                let authority_pk_bytes = keys[0].public().encode_protobuf();
                let account_id_hash =
                    account_id_from_key_material(SignatureSuite::Ed25519, &authority_pk_bytes)
                        .unwrap();
                let authority_id = AccountId(account_id_hash);

                let vs_blob = ValidatorSetBlob {
                    schema_version: 1,
                    payload: ValidatorSetV1 {
                        effective_from_height: 1,
                        total_weight: 1,
                        validators: vec![ValidatorV1 {
                            account_id: authority_id,
                            weight: 1,
                            consensus_key: ActiveKeyRecord {
                                suite: SignatureSuite::Ed25519,
                                pubkey_hash: account_id_hash,
                                since_height: 0,
                            },
                        }],
                    },
                };
                let vs_bytes = codec::to_bytes_canonical(&vs_blob);
                genesis_state.insert(
                    std::str::from_utf8(depin_sdk_types::keys::VALIDATOR_SET_KEY)
                        .unwrap()
                        .to_string(),
                    json!(format!(
                        "b64:{}",
                        base64::prelude::BASE64_STANDARD.encode(vs_bytes)
                    )),
                );
            })
            .build()
            .await
            .expect("Failed to build Cluster A");

        let node = &cluster.validators[0];
        let (mut logs, _, _) = node.subscribe_logs();
        assert_log_contains(
            "Cluster A",
            &mut logs,
            "Produced and processed new block #1",
        )
        .await
    });

    // --- Define Cluster B: Proof of Stake with HashMapStateTree ---
    let cluster_b_handle = tokio::spawn(async {
        let cluster = TestCluster::builder()
            .with_validators(1)
            .with_consensus_type("ProofOfStake")
            .with_state_tree("HashMap")
            .with_commitment_scheme("Hash")
            .with_genesis_modifier(|genesis, keys| {
                let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();
                let staker_pk_bytes = keys[0].public().encode_protobuf();
                let account_id_hash =
                    account_id_from_key_material(SignatureSuite::Ed25519, &staker_pk_bytes)
                        .unwrap();
                let staker_id = AccountId(account_id_hash);

                let vs_blob = ValidatorSetBlob {
                    schema_version: 1,
                    payload: ValidatorSetV1 {
                        effective_from_height: 1,
                        total_weight: 100_000,
                        validators: vec![ValidatorV1 {
                            account_id: staker_id,
                            weight: 100_000,
                            consensus_key: ActiveKeyRecord {
                                suite: SignatureSuite::Ed25519,
                                pubkey_hash: account_id_hash,
                                since_height: 0,
                            },
                        }],
                    },
                };
                let vs_bytes = codec::to_bytes_canonical(&vs_blob);
                genesis_state.insert(
                    std::str::from_utf8(depin_sdk_types::keys::VALIDATOR_SET_KEY)
                        .unwrap()
                        .to_string(),
                    json!(format!(
                        "b64:{}",
                        base64::prelude::BASE64_STANDARD.encode(vs_bytes)
                    )),
                );
            })
            .build()
            .await
            .expect("Failed to build Cluster B");

        let node = &cluster.validators[0];
        let (mut logs, _, _) = node.subscribe_logs();
        assert_log_contains(
            "Cluster B",
            &mut logs,
            "Produced and processed new block #1",
        )
        .await
    });

    // Launch both concurrently and await results.
    let (res_a, res_b) = tokio::join!(cluster_a_handle, cluster_b_handle);

    res_a??; // Propagate any errors from cluster A's Tokio task and its Result
    res_b??; // Propagate any errors from cluster B's Tokio task and its Result

    println!("--- Comprehensive Polymorphism E2E Test Passed ---");

    Ok(())
}
