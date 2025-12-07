// Path: crates/forge/tests/topology_e2e.rs
#![cfg(all(feature = "consensus-poa", feature = "vm-wasm", feature = "state-iavl"))]

use anyhow::Result;
use ioi_forge::testing::{build_test_artifacts, genesis::GenesisBuilder, TestCluster};
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, BlockTimingParams,
        BlockTimingRuntime, SignatureSuite, ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    config::{InitialServiceConfig, ValidatorRole},
    service_configs::MigrationConfig,
};
use std::time::Duration;
use tokio::fs;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_mixed_validator_topology() -> Result<()> {
    println!("--- Running Mixed Validator Topology E2E Test ---");
    build_test_artifacts();

    // 1. Define Roles
    // Node 0: Consensus (Standard)
    // Node 1: Compute (GPU)
    let compute_role = ValidatorRole::Compute {
        accelerator_type: "nvidia-test-gpu".to_string(),
        vram_capacity: 32 * 1024 * 1024 * 1024,
    };

    // 2. Build Cluster
    let cluster = TestCluster::builder()
        .with_validators(2)
        .with_consensus_type("ProofOfAuthority")
        .with_state_tree("IAVL")
        .with_chain_id(1)
        .with_role(0, ValidatorRole::Consensus)
        .with_role(1, compute_role.clone())
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
        }))
        .with_genesis_modifier(move |builder: &mut GenesisBuilder, keys| {
            let mut validators = Vec::new();
            for key in keys {
                let account_id = builder.add_identity(key);
                let pk = key.public().encode_protobuf();
                let hash = account_id_from_key_material(SignatureSuite::Ed25519, &pk).unwrap();

                validators.push(ValidatorV1 {
                    account_id,
                    weight: 1,
                    consensus_key: ActiveKeyRecord {
                        suite: SignatureSuite::Ed25519,
                        public_key_hash: hash,
                        since_height: 0,
                    },
                });
            }
            // Sort for deterministic consensus
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

            // Block Timing
            let timing_params = BlockTimingParams {
                base_interval_secs: 2,
                ..Default::default()
            };
            let timing_runtime = BlockTimingRuntime {
                effective_interval_secs: timing_params.base_interval_secs,
                ..Default::default()
            };
            builder.set_block_timing(&timing_params, &timing_runtime);
        })
        .build()
        .await?;

    let test_result: Result<()> = async {
        let node0 = &cluster.validators[0];
        let node1 = &cluster.validators[1];

        // 3. Verify Liveness (Basic check that mixed roles don't break consensus)
        println!("Waiting for chain to produce blocks...");
        ioi_forge::testing::wait_for_height(
            &node0.validator().rpc_addr,
            3,
            Duration::from_secs(30),
        )
        .await?;

        // 4. Verify Configuration Integrity
        // Since we don't have an RPC endpoint for "getRole" yet (that's Phase 2/3),
        // we verify that the `orchestration.toml` on disk was written correctly.
        // This confirms the Config struct -> TOML serialization path works in a live environment.

        // Node 0 Config Path: stored in the temp dir of the validator
        let node0_config_path = node0
            .validator()
            .certs_dir_path
            .parent()
            .unwrap()
            .join("orchestration.toml");
        let node0_toml = fs::read_to_string(&node0_config_path).await?;

        // Assert Node 0 is Consensus
        assert!(
            node0_toml.contains("type = \"Consensus\""),
            "Node 0 config mismatch: {}",
            node0_toml
        );
        println!("Node 0 configuration verified: Consensus Role.");

        // Node 1 Config Path
        let node1_config_path = node1
            .validator()
            .certs_dir_path
            .parent()
            .unwrap()
            .join("orchestration.toml");
        let node1_toml = fs::read_to_string(&node1_config_path).await?;

        // Assert Node 1 is Compute with correct params
        assert!(
            node1_toml.contains("type = \"Compute\""),
            "Node 1 config mismatch: {}",
            node1_toml
        );
        assert!(
            node1_toml.contains("nvidia-test-gpu"),
            "Node 1 config missing accelerator type"
        );
        println!("Node 1 configuration verified: Compute Role (nvidia-test-gpu).");

        Ok(())
    }
    .await;

    // Cleanup
    for guard in cluster.validators {
        guard.shutdown().await?;
    }

    test_result?;
    println!("--- Mixed Validator Topology E2E Test Passed ---");
    Ok(())
}
