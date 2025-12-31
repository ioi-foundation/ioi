// Path: crates/cli/tests/state_verkle_e2e.rs
#![cfg(all(
    feature = "consensus-poa",
    feature = "vm-wasm",
    feature = "state-verkle",
    feature = "commitment-kzg"
))]

use anyhow::Result;
use ioi_cli::testing::{build_test_artifacts, wait_for_height, TestCluster};
use ioi_types::{
    app::{ActiveKeyRecord, SignatureSuite, ValidatorSetV1, ValidatorSetsV1, ValidatorV1},
    config::InitialServiceConfig,
    service_configs::MigrationConfig,
};
use std::time::Duration;

#[tokio::test]
async fn test_verkle_tree_e2e() -> Result<()> {
    build_test_artifacts();

    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("Admft")
        .with_state_tree("Verkle")
        .with_commitment_scheme("KZG")
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            // FIX: Use ED25519 constant
            allowed_target_suites: vec![SignatureSuite::ED25519],
            allow_downgrade: false,
            chain_id: 1,
        }))
        // --- UPDATED: Using GenesisBuilder API ---
        .with_genesis_modifier(|builder, keys| {
            let key = &keys[0];

            // 1. Register Identity
            let account_id = builder.add_identity(key);
            let acct_hash = account_id.0;

            // 2. Validator Set
            let validator_set = ValidatorSetV1 {
                effective_from_height: 1,
                total_weight: 1,
                validators: vec![ValidatorV1 {
                    account_id,
                    weight: 1,
                    consensus_key: ActiveKeyRecord {
                        // FIX: Use ED25519 constant
                        suite: SignatureSuite::ED25519,
                        public_key_hash: acct_hash,
                        since_height: 0,
                    },
                }],
            };

            let vs = ValidatorSetsV1 {
                current: validator_set,
                next: None,
            };
            builder.set_validators(&vs);
        })
        .build()
        .await?;

    let node_guard = &cluster.validators[0];
    let rpc_addr = &node_guard.validator().rpc_addr;

    println!("--- Verkle Node Launched ---");

    // INCREASED TIMEOUT: Verkle block production is slow on test runners due to KZG overhead.
    wait_for_height(rpc_addr, 1, Duration::from_secs(120)).await?;
    println!("--- Bootstrap Block #1 Processed ---");

    println!("--- Verkle Tree E2E Test Passed ---");

    for guard in cluster.validators {
        guard.shutdown().await?;
    }

    Ok(())
}
