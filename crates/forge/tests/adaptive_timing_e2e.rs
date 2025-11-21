// Path: crates/forge/tests/adaptive_timing_e2e.rs
#![cfg(all(feature = "consensus-poa", feature = "vm-wasm", feature = "state-iavl"))]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ioi_forge::testing::{
    build_test_artifacts,
    rpc::{query_state_key, submit_transaction},
    wait_for_height, TestCluster,
};
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, ApplicationTransaction,
        BlockTimingParams, BlockTimingRuntime, ChainId, ChainTransaction, Credential, SignHeader,
        SignatureProof, SignatureSuite, ValidatorSetBlob, ValidatorSetV1, ValidatorSetsV1,
        ValidatorV1,
    },
    codec,
    config::InitialServiceConfig,
    keys::{
        ACCOUNT_ID_TO_PUBKEY_PREFIX, BLOCK_TIMING_PARAMS_KEY, BLOCK_TIMING_RUNTIME_KEY,
        IDENTITY_CREDENTIALS_PREFIX, VALIDATOR_SET_KEY,
    },
    service_configs::MigrationConfig,
};
use libp2p::identity::Keypair;
use serde_json::json;
use std::path::Path;
use std::time::Duration;

// Helper to create a signed Application Transaction (copied from contract_e2e)
fn create_signed_app_tx(
    keypair: &Keypair,
    mut tx: ApplicationTransaction,
    nonce: u64,
    chain_id: ChainId,
) -> ChainTransaction {
    let public_key = keypair.public().encode_protobuf();
    let account_id_hash =
        account_id_from_key_material(SignatureSuite::Ed25519, &public_key).unwrap();
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
        suite: SignatureSuite::Ed25519,
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
    let wasm_path =
        workspace_root.join("target/wasm32-unknown-unknown/release/counter_contract.wasm");
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
        .with_consensus_type("ProofOfAuthority")
        .with_state_tree("IAVL")
        .with_chain_id(1)
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
        }))
        .with_genesis_modifier(move |genesis, keys| {
            let keypair = &keys[0];
            let suite = SignatureSuite::Ed25519;
            let public_key_bytes = keypair.public().encode_protobuf();
            let account_id_hash = account_id_from_key_material(suite, &public_key_bytes).unwrap();
            let account_id = AccountId(account_id_hash);

            let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();

            // Standard PoA Validator Setup
            let vs_blob = ValidatorSetBlob {
                schema_version: 2,
                payload: ValidatorSetsV1 {
                    current: ValidatorSetV1 {
                        effective_from_height: 1,
                        total_weight: 1,
                        validators: vec![ValidatorV1 {
                            account_id,
                            weight: 1,
                            consensus_key: ActiveKeyRecord {
                                suite: SignatureSuite::Ed25519,
                                public_key_hash: account_id_hash,
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

            // Identity Records
            let initial_cred = Credential {
                suite,
                public_key_hash: account_id_hash,
                activation_height: 0,
                l2_location: None,
            };
            let creds_array: [Option<Credential>; 2] = [Some(initial_cred), None];
            let creds_bytes = codec::to_bytes_canonical(&creds_array).unwrap();
            let creds_key = [IDENTITY_CREDENTIALS_PREFIX, account_id.as_ref()].concat();
            genesis_state.insert(
                format!("b64:{}", BASE64_STANDARD.encode(&creds_key)),
                json!(format!("b64:{}", BASE64_STANDARD.encode(&creds_bytes))),
            );

            let pubkey_map_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, account_id.as_ref()].concat();
            genesis_state.insert(
                format!("b64:{}", BASE64_STANDARD.encode(&pubkey_map_key)),
                json!(format!("b64:{}", BASE64_STANDARD.encode(&public_key_bytes))),
            );

            // --- ADAPTIVE TIMING CONFIGURATION ---
            // We set a very low target gas so any substantial transaction will trigger
            // an "overloaded" state, causing the block time to decrease (speed up).
            // Increased step to 5000 (50%) to ensure it can drop below 5s even after an initial increase.
            let timing_params = BlockTimingParams {
                base_interval_secs: 5,
                min_interval_secs: 1,
                max_interval_secs: 10,
                target_gas_per_block: 100, // Low target to ensure we exceed it
                ema_alpha_milli: 800,      // High alpha for fast reaction
                interval_step_bps: 5000,   // 50% change allowed per retarget (increased)
                retarget_every_blocks: 2,  // Retarget frequently (every 2 blocks)
            };
            let timing_runtime = BlockTimingRuntime {
                ema_gas_used: 0,
                effective_interval_secs: timing_params.base_interval_secs,
            };

            genesis_state.insert(
                std::str::from_utf8(BLOCK_TIMING_PARAMS_KEY)
                    .unwrap()
                    .to_string(),
                json!(format!(
                    "b64:{}",
                    BASE64_STANDARD.encode(codec::to_bytes_canonical(&timing_params).unwrap())
                )),
            );
            genesis_state.insert(
                std::str::from_utf8(BLOCK_TIMING_RUNTIME_KEY)
                    .unwrap()
                    .to_string(),
                json!(format!(
                    "b64:{}",
                    BASE64_STANDARD.encode(codec::to_bytes_canonical(&timing_runtime).unwrap())
                )),
            );
        })
        .build()
        .await?;

    let node = cluster.validators[0].validator();
    let rpc_addr = &node.rpc_addr;
    let keypair = &node.keypair;

    // 3. Wait for chain start
    wait_for_height(rpc_addr, 1, Duration::from_secs(20)).await?;

    // 4. Send a High-Gas Transaction (Deploy Contract)
    let deploy_tx_unsigned = ApplicationTransaction::DeployContract {
        header: Default::default(),
        code: counter_wasm.clone(),
        signature_proof: Default::default(),
    };
    let deploy_tx = create_signed_app_tx(keypair, deploy_tx_unsigned, 0, 1.into());

    println!("Submitting high-gas transaction...");
    submit_transaction(rpc_addr, &deploy_tx).await?;

    // 5. Wait for Retargeting
    // Genesis (0) -> Block 1 (empty) -> Block 2 (empty) -> Block 3 (tx) -> Block 4 (retarget) -> Block 5.
    // We wait for Height 5 to ensure the retargeting update at Height 4 is visible in the query.
    wait_for_height(rpc_addr, 5, Duration::from_secs(30)).await?;

    // 6. Verify Adaptation
    let height = ioi_forge::testing::rpc::get_chain_height(rpc_addr).await?;
    println!("Checking BlockTimingRuntime state at height {}...", height);

    let runtime_bytes_opt = query_state_key(rpc_addr, BLOCK_TIMING_RUNTIME_KEY).await?;
    let runtime_bytes =
        runtime_bytes_opt.ok_or_else(|| anyhow!("BlockTimingRuntime key missing"))?;
    let runtime: BlockTimingRuntime = codec::from_bytes_canonical(&runtime_bytes)
        .map_err(|e| anyhow!("Failed to decode runtime: {}", e))?;

    println!("New Runtime State: {:?}", runtime);

    // Assertions
    assert!(runtime.ema_gas_used > 0, "EMA gas used should be non-zero");

    assert!(
        runtime.effective_interval_secs < 5,
        "Effective interval should have decreased due to high load (expected < 5, got {})",
        runtime.effective_interval_secs
    );

    println!("--- Adaptive Timing E2E Test Passed ---");

    // Cleanup
    for guard in cluster.validators {
        guard.shutdown().await?;
    }
    Ok(())
}
