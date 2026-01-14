// Path: crates/cli/tests/admft_e2e.rs
#![cfg(all(feature = "consensus-admft", feature = "vm-wasm", feature = "state-iavl"))]

use anyhow::Result;
use ioi_cli::testing::{build_test_artifacts, rpc, wait_for_height, TestCluster};
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, BlockTimingParams,
        BlockTimingRuntime, SignatureSuite, ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    config::{InitialServiceConfig, ValidatorRole},
    service_configs::MigrationConfig,
};
use std::collections::HashSet;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_admft_leader_rotation() -> Result<()> {
    println!("--- Running A-DMFT Leader Rotation E2E Test ---");
    build_test_artifacts();

    // 1. Setup a 3-node cluster
    let cluster = TestCluster::builder()
        .with_validators(3)
        .with_consensus_type("Admft")
        .with_state_tree("IAVL")
        .with_chain_id(1)
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::ED25519],
            allow_downgrade: false,
        }))
        .with_genesis_modifier(move |builder, keys| {
            let mut validators = Vec::new();
            for key in keys {
                let account_id = builder.add_identity(key);
                let pk = key.public().encode_protobuf();
                let hash = account_id_from_key_material(SignatureSuite::ED25519, &pk).unwrap();

                validators.push(ValidatorV1 {
                    account_id,
                    weight: 1, // Equal weight for round-robin
                    consensus_key: ActiveKeyRecord {
                        suite: SignatureSuite::ED25519,
                        public_key_hash: hash,
                        since_height: 0,
                    },
                });
            }
            // Deterministic sort for stable leader schedule
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

            // Fast blocks for testing
            let timing_params = BlockTimingParams {
                base_interval_secs: 1,
                min_interval_secs: 1,
                max_interval_secs: 5,
                target_gas_per_block: 1_000_000,
                retarget_every_blocks: 0,
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

    // [FIX] Spawn log printers for debugging - Handle closed channels gracefully
    for (i, guard) in cluster.validators.iter().enumerate() {
        let (mut orch_logs, mut work_logs, _) = guard.validator().subscribe_logs();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                     res = orch_logs.recv() => {
                        match res {
                            Ok(line) => println!("[Node {} ORCH] {}", i, line),
                            Err(_) => break, // Channel closed, exit loop
                        }
                     }
                     res = work_logs.recv() => {
                        match res {
                            Ok(line) => println!("[Node {} WORK] {}", i, line),
                            Err(_) => break, // Channel closed, exit loop
                        }
                     }
                }
            }
        });
    }

    let rpc_addr = &cluster.validators[0].validator().rpc_addr;

    let test_logic = async {
        // 2. Wait for chain progression
        let target_height = 6;
        println!("Waiting for height {}...", target_height);
        wait_for_height(rpc_addr, target_height, Duration::from_secs(30)).await?;

        // 3. Analyze Blocks
        let mut producers = HashSet::new();
        let mut last_height = 0;

        for h in 1..=target_height {
            // [FIX] Add explicit retry loop with logging for the test
            let mut block = None;
            for _ in 0..10 {
                match rpc::get_block_by_height_resilient(rpc_addr, h).await {
                    Ok(Some(b)) => { block = Some(b); break; },
                    Ok(None) => {
                         println!("Block {} not found yet, retrying...", h);
                         tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    Err(e) => {
                         println!("RPC error for block {}: {}, retrying...", h, e);
                         tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            }
            let block = block.ok_or_else(|| anyhow::anyhow!("Block {} not found after retries", h))?;

            println!(
                "Block #{}: Producer 0x{}, View {}",
                h,
                hex::encode(&block.header.producer_account_id.0[0..4]),
                block.header.view
            );

            // Verify height continuity
            if block.header.height != last_height + 1 {
                 return Err(anyhow::anyhow!("Height gap detected"));
            }
            last_height = block.header.height;

            producers.insert(block.header.producer_account_id);
        }

        // 4. Verify Rotation
        // With 3 validators and 6 blocks, we expect at least 2 unique producers (ideally 3).
        // If only 1 produced all blocks, round-robin failed.
        if producers.len() < 2 {
            return Err(anyhow::anyhow!(
                "Leader rotation failed: observed {:?} unique producers out of 3 validators",
                producers.len()
            ));
        }

        println!("--- A-DMFT Leader Rotation Test Passed ---");
        Ok(())
    };

    let result = test_logic.await;
    
    // Always shutdown
    if let Err(e) = cluster.shutdown().await {
        eprintln!("Error shutting down cluster: {}", e);
    }

    result
}