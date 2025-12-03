// Path: crates/forge/tests/oracle_signer_e2e.rs
#![cfg(all(feature = "consensus-poa", feature = "vm-wasm"))]

use anyhow::Result;
use ioi_forge::testing::{
    build_test_artifacts,
    wait_for_height, TestCluster,
};
use ioi_types::app::{
    ActiveKeyRecord, BlockTimingParams, BlockTimingRuntime,
    SignatureSuite, ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
};
use std::time::Duration;

#[tokio::test]
async fn test_remote_oracle_signing_flow_implicit() -> Result<()> {
    // 1. Build binaries
    let status = std::process::Command::new("cargo")
        .args(&["build", "--release", "-p", "ioi-node", "--bin", "ioi-signer", "--features", "validator-bins"])
        .status()?;
    assert!(status.success());

    build_test_artifacts();

    // 2. Configure Cluster
    let kp = libp2p::identity::Keypair::generate_ed25519();
    let kp_clone = kp.clone();

    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_keypairs(vec![kp])
        .with_consensus_type("ProofOfAuthority")
        .with_state_tree("IAVL")
        .with_genesis_modifier(move |builder, _ignored_keys| {
            let account_id = builder.add_identity(&kp_clone);

            let vs = ValidatorSetsV1 {
                current: ValidatorSetV1 {
                    effective_from_height: 1,
                    total_weight: 1,
                    validators: vec![ValidatorV1 {
                        account_id,
                        weight: 1,
                        consensus_key: ActiveKeyRecord {
                            suite: SignatureSuite::Ed25519,
                            public_key_hash: account_id.0,
                            since_height: 0,
                        },
                    }],
                },
                next: None,
            };
            builder.set_validators(&vs);

            let timing = BlockTimingParams {
                base_interval_secs: 1,
                ..Default::default()
            };
            builder.set_block_timing(&timing, &BlockTimingRuntime::default());
        })
        .build()
        .await?;

    let node = cluster.validators[0].validator();
    
    // Verify the signing oracle guard is present
    assert!(node.signing_oracle_guard.is_some(), "Signing Oracle should have been auto-spawned");

    // 3. Wait for blocks
    wait_for_height(&node.rpc_addr, 5, Duration::from_secs(30)).await?;

    // 4. Verify Block Header Metadata
    use ioi_forge::testing::rpc::get_block_by_height_resilient;
    
    let block = get_block_by_height_resilient(&node.rpc_addr, 2).await?.unwrap();
    println!("Block 2 Oracle Counter: {}", block.header.oracle_counter);
    
    assert!(block.header.oracle_counter > 0, "Oracle counter should increment");
    assert_ne!(block.header.oracle_trace_hash, [0u8; 32], "Trace hash should not be zero");

    let block3 = get_block_by_height_resilient(&node.rpc_addr, 3).await?.unwrap();
    assert!(block3.header.oracle_counter > block.header.oracle_counter, "Counter must be monotonic");

    Ok(())
}