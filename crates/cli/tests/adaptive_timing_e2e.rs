// Path: crates/cli/tests/adaptive_timing_e2e.rs
#![cfg(all(feature = "consensus-poa", feature = "vm-wasm", feature = "state-iavl"))]

use anyhow::{anyhow, Result};
use ioi_cli::testing::{
    build_test_artifacts,
    rpc::{query_state_key, submit_transaction_no_wait},
    wait_for_height, TestCluster,
};
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, ApplicationTransaction,
        BlockTimingParams, BlockTimingRuntime, ChainId, ChainTransaction, SignHeader,
        SignatureProof, SignatureSuite, ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    codec,
    config::InitialServiceConfig,
    keys::BLOCK_TIMING_RUNTIME_KEY,
    service_configs::MigrationConfig,
};
use libp2p::identity::Keypair;
use std::path::Path;
use std::time::Duration;

// Helper to create a signed Application Transaction
fn create_signed_app_tx(
    keypair: &Keypair,
    mut tx: ApplicationTransaction,
    nonce: u64,
    chain_id: ChainId,
) -> ChainTransaction {
    let public_key = keypair.public().encode_protobuf();
    let account_id_hash =
        account_id_from_key_material(SignatureSuite::ED25519, &public_key).unwrap();
    let account_id = ioi_types::app::AccountId(account_id_hash);

    let header = SignHeader {
        account_id,
        nonce,
        chain_id,
        tx_version: 1,
    };

    match &mut tx {
        ApplicationTransaction::DeployContract { header: h, .. } => *h = header,
        ApplicationTransaction::CallContract { header: h, .. } => *h = header,
        _ => panic!("Unsupported tx type"),
    }

    let payload_bytes = tx.to_sign_bytes().unwrap();
    let signature = keypair.sign(&payload_bytes).unwrap();

    let proof = SignatureProof {
        suite: SignatureSuite::ED25519,
        public_key,
        signature,
    };

    match &mut tx {
        ApplicationTransaction::DeployContract {
            signature_proof, ..
        } => *signature_proof = proof,
        ApplicationTransaction::CallContract {
            signature_proof, ..
        } => *signature_proof = proof,
        _ => panic!("Unsupported tx type"),
    }

    ChainTransaction::Application(tx)
}

#[tokio::test]
async fn test_adaptive_block_timing_responds_to_load() -> Result<()> {
    // 1. Build artifacts (contracts)
    build_test_artifacts();

    // Locate the compiled contract
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().and_then(|p| p.parent()).unwrap();
    let wasm_path = workspace_root.join("target/wasm32-wasip1/release/counter_contract.wasm");
    let counter_wasm = std::fs::read(&wasm_path).map_err(|e| {
        anyhow!(
            "Failed to read contract artifact at {:?}: {}. Ensure `build_test_artifacts()` ran.",
            wasm_path,
            e
        )
    })?;

    // 2. Configure Cluster
    let cluster = TestCluster::builder()
        .with_validators(1)
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
        // --- CHANGED: Use the new builder API in the modifier ---
        .with_genesis_modifier(move |genesis_builder, keys| {
            let keypair = &keys[0];

            // 1. Register Identity using the builder helper
            let account_id = genesis_builder.add_identity(keypair);

            // 2. Set Validators
            let vs = ValidatorSetsV1 {
                current: ValidatorSetV1 {
                    effective_from_height: 1,
                    total_weight: 1,
                    validators: vec![ValidatorV1 {
                        account_id,
                        weight: 1,
                        consensus_key: ActiveKeyRecord {
                            suite: SignatureSuite::ED25519,
                            public_key_hash: account_id.0,
                            since_height: 0,
                        },
                    }],
                },
                next: None,
            };
            genesis_builder.set_validators(&vs);

            // 3. Set Block Timing (Adaptive Configuration)
            let timing_params = BlockTimingParams {
                base_interval_secs: 5,
                min_interval_secs: 1,
                max_interval_secs: 10,
                target_gas_per_block: 100, // Low target to ensure we exceed it
                ema_alpha_milli: 800,      // High alpha for fast reaction
                interval_step_bps: 5000,   // 50% change allowed per retarget
                retarget_every_blocks: 2,
            };
            let timing_runtime = BlockTimingRuntime {
                ema_gas_used: 0,
                effective_interval_secs: timing_params.base_interval_secs,
            };

            // Use the new typed method! No more manual base64 or SCALE encoding.
            genesis_builder.set_block_timing(&timing_params, &timing_runtime);
        })
        // ---------------------------------------------------------
        .build()
        .await?;

    // Wrap the test logic in an async block to guarantee cleanup
    let test_result: Result<()> = async {
        let node = cluster.validators[0].validator();
        let rpc_addr = &node.rpc_addr;
        let keypair = &node.keypair;

        // 3. Wait for chain start
        wait_for_height(rpc_addr, 1, Duration::from_secs(20)).await?;

        // 4. Send a High-Gas Transaction
        let deploy_tx_unsigned = ApplicationTransaction::DeployContract {
            header: Default::default(),
            code: counter_wasm.clone(),
            signature_proof: Default::default(),
        };
        let deploy_tx = create_signed_app_tx(keypair, deploy_tx_unsigned, 0, 1.into());

        println!("Submitting high-gas transaction...");
        // If this returns Ok, the transaction was accepted. Errors are returned as Err.
        let _tx_hash = submit_transaction_no_wait(rpc_addr, &deploy_tx).await?;

        // 5. Wait for Retargeting
        println!("Waiting for height 5...");
        wait_for_height(rpc_addr, 5, Duration::from_secs(60)).await?;

        // 6. Verify Adaptation
        let runtime_bytes_opt = query_state_key(rpc_addr, BLOCK_TIMING_RUNTIME_KEY).await?;
        let runtime_bytes =
            runtime_bytes_opt.ok_or_else(|| anyhow!("BlockTimingRuntime key missing"))?;
        let runtime: BlockTimingRuntime = codec::from_bytes_canonical(&runtime_bytes)
            .map_err(|e| anyhow!("Failed to decode runtime: {}", e))?;

        println!("New Runtime State: {:?}", runtime);

        assert!(runtime.ema_gas_used > 0, "EMA gas used should be non-zero");
        assert!(
            runtime.effective_interval_secs < 5,
            "Effective interval should have decreased due to high load"
        );

        Ok(())
    }
    .await;

    for guard in cluster.validators {
        guard.shutdown().await?;
    }

    test_result?;
    Ok(())
}
