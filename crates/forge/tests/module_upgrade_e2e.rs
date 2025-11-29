// Path: crates/forge/tests/module_upgrade_e2e.rs
#![cfg(all(feature = "consensus-poa", feature = "vm-wasm", feature = "state-iavl"))]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ioi_forge::testing::{
    add_genesis_identity, assert_log_contains,
    rpc::{query_state_key, query_state_key_at_root, tip_height_resilient},
    submit_transaction, wait_for_height, wait_until, TestCluster,
};
use ioi_services::governance::{StoreModuleParams, SwapModuleParams};
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, BlockTimingParams,
        BlockTimingRuntime, ChainId, ChainTransaction, Credential, Proposal, ProposalStatus,
        ProposalType, SignHeader, SignatureProof, SignatureSuite, StateEntry, SystemPayload,
        SystemTransaction, ValidatorSetV1, ValidatorSetsV1, ValidatorV1, VoteOption,
    },
    codec,
    config::InitialServiceConfig,
    keys::{
        active_service_key, BLOCK_TIMING_PARAMS_KEY, BLOCK_TIMING_RUNTIME_KEY, GOVERNANCE_KEY,
        GOVERNANCE_PROPOSAL_KEY_PREFIX, UPGRADE_ARTIFACT_PREFIX, UPGRADE_MANIFEST_PREFIX,
        UPGRADE_PENDING_PREFIX, VALIDATOR_SET_KEY,
    },
    service_configs::{
        ActiveServiceMeta, GovernancePolicy, GovernanceSigner, MethodPermission, MigrationConfig,
    },
};
use libp2p::identity::{self, Keypair};
use parity_scale_codec::Encode;
use serde_json::{json, Map, Value};
use std::path::Path;
use std::time::Duration;

/// Parameters for the `governance` service's `vote@v1` method.
#[derive(Encode)]
struct VoteParams {
    proposal_id: u64,
    option: VoteOption,
}

/// Helper function to add a full identity record for a key to the genesis state.
fn add_identity_to_genesis(genesis_state: &mut Map<String, Value>, keypair: &Keypair) -> AccountId {
    let suite = SignatureSuite::Ed25519;
    let public_key_bytes = keypair.public().encode_protobuf();
    let account_id_hash = account_id_from_key_material(suite, &public_key_bytes).unwrap();
    let account_id = AccountId(account_id_hash);

    // Set IdentityHub credentials
    let initial_cred = Credential {
        suite,
        public_key_hash: account_id_hash,
        activation_height: 0,
        l2_location: None,
    };
    let creds_array: [Option<Credential>; 2] = [Some(initial_cred), None];
    let creds_bytes = codec::to_bytes_canonical(&creds_array).unwrap();
    let creds_key = [
        ioi_types::keys::IDENTITY_CREDENTIALS_PREFIX,
        account_id.as_ref(),
    ]
    .concat();

    genesis_state.insert(
        format!("b64:{}", BASE64_STANDARD.encode(&creds_key)),
        json!(format!("b64:{}", BASE64_STANDARD.encode(&creds_bytes))),
    );

    account_id
}

/// Helper to create a signed System transaction.
fn create_system_tx(
    signer: &Keypair,
    payload: SystemPayload,
    nonce: u64,
    chain_id: ChainId,
) -> Result<ChainTransaction> {
    let public_key_bytes = signer.public().encode_protobuf();
    let account_id = AccountId(
        account_id_from_key_material(SignatureSuite::Ed25519, &public_key_bytes).unwrap(),
    );
    let mut tx = SystemTransaction {
        header: ioi_types::app::SignHeader {
            account_id,
            nonce,
            chain_id,
            tx_version: 1,
        },
        payload,
        signature_proof: Default::default(),
    };
    let sign_bytes = tx.to_sign_bytes().map_err(|e| anyhow!(e))?;
    tx.signature_proof = ioi_types::app::SignatureProof {
        suite: SignatureSuite::Ed25519,
        public_key: public_key_bytes,
        signature: signer.sign(&sign_bytes).unwrap(),
    };
    Ok(ChainTransaction::System(Box::new(tx)))
}

async fn service_v2_registered(
    rpc_addr: &str,
    activation_height: u64,
    expected_artifact_hash: [u8; 32],
) -> Result<bool> {
    // Ensure a couple of blocks beyond activation are available.
    wait_for_height(rpc_addr, activation_height + 2, Duration::from_secs(20)).await?;

    let fee_v2_key = active_service_key("fee_calculator");

    for h in [
        activation_height,
        activation_height + 1,
        activation_height + 2,
    ] {
        // Swallow transient RPC errors here; let the outer `wait_until` keep polling.
        if let Ok(Some(block)) =
            ioi_forge::testing::rpc::get_block_by_height_resilient(rpc_addr, h).await
        {
            if let Ok(Some(meta_bytes)) =
                query_state_key_at_root(rpc_addr, &block.header.state_root, &fee_v2_key).await
            {
                // The active service metadata is stored directly, not wrapped in a StateEntry.
                if let Ok(meta) = codec::from_bytes_canonical::<ActiveServiceMeta>(&meta_bytes) {
                    if meta.id == "fee_calculator" && meta.artifact_hash == expected_artifact_hash {
                        return Ok(true);
                    }
                }
            }
        }
    }
    Ok(false)
}

#[tokio::test]
async fn test_forkless_module_upgrade() -> Result<()> {
    // 1. SETUP & BUILD
    println!("--- Building fee-calculator-service WASM for upgrade test ---");
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let contract_manifest_path =
        manifest_dir.join("tests/contracts/fee-calculator-service/Cargo.toml");

    let workspace_root = manifest_dir.parent().and_then(|p| p.parent()).unwrap();
    let target_dir = workspace_root.join("target");
    let status = std::process::Command::new("cargo")
        .env("CARGO_TARGET_DIR", target_dir)
        .args([
            "component",
            "build",
            "--release",
            "--manifest-path",
            contract_manifest_path.to_str().unwrap(),
            "--target",
            "wasm32-wasip1",
            // Remove "--target-dir" arg here as we set it via env var which is safer for nested calls
        ])
        .status()?;
    assert!(
        status.success(),
        "Failed to build fee-calculator-service WASM"
    );

    let wasm_path = workspace_root.join("target/wasm32-wasip1/release/fee_calculator_service.wasm");
    let service_artifact = std::fs::read(&wasm_path)?;

    let manifest_toml = r#"
id = "fee_calculator"
abi_version = 1
state_schema = "v1"
runtime = "wasm"
capabilities = ["TxDecorator"]

[methods]
"ante_handle@v1" = "Internal"
"#
    .to_string();

    let governance_key = identity::Keypair::generate_ed25519();
    let user_key = identity::Keypair::generate_ed25519();
    let chain_id: ChainId = 1.into();
    let mut governance_nonce = 0;
    let user_nonce = 0;

    let governance_key_clone_for_genesis = governance_key.clone();
    let user_key_clone_for_genesis = user_key.clone();

    // 2. LAUNCH CLUSTER
    let governance_key_for_test = governance_key.clone();
    let mut cluster = TestCluster::builder()
        .with_validators(1)
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
        }))
        .with_initial_service(InitialServiceConfig::Governance(Default::default()))
        .with_genesis_modifier(move |genesis, keys| {
            let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();

            // Use shared helper for identity injection (IdentityHub service data)
            let validator_id = add_genesis_identity(genesis_state, &keys[0]);
            let governance_id =
                add_genesis_identity(genesis_state, &governance_key_clone_for_genesis);
            add_genesis_identity(genesis_state, &user_key_clone_for_genesis);

            // Governance Policy
            let policy = GovernancePolicy {
                signer: GovernanceSigner::Single(governance_id),
            };
            let policy_bytes = codec::to_bytes_canonical(&policy).unwrap();
            genesis_state.insert(
                format!("b64:{}", BASE64_STANDARD.encode(GOVERNANCE_KEY)),
                json!(format!("b64:{}", BASE64_STANDARD.encode(policy_bytes))),
            );

            // Validator Set (Consensus)
            let vs_bytes = codec::to_bytes_canonical(&ValidatorSetsV1 {
                current: ValidatorSetV1 {
                    effective_from_height: 1,
                    total_weight: 1,
                    validators: vec![ValidatorV1 {
                        account_id: validator_id,
                        weight: 1,
                        consensus_key: ActiveKeyRecord {
                            suite: SignatureSuite::Ed25519,
                            public_key_hash: validator_id.0,
                            since_height: 0,
                        },
                    }],
                },
                next: None,
            })
            .unwrap();
            genesis_state.insert(
                std::str::from_utf8(VALIDATOR_SET_KEY).unwrap().to_string(),
                json!(format!("b64:{}", BASE64_STANDARD.encode(vs_bytes))),
            );

            // Add a dummy proposal
            let proposal = Proposal {
                id: 1,
                title: "Dummy Proposal".to_string(),
                description: "".to_string(),
                proposal_type: ProposalType::Text,
                status: ProposalStatus::VotingPeriod,
                submitter: vec![],
                submit_height: 0,
                deposit_end_height: 0,
                voting_start_height: 1,
                voting_end_height: u64::MAX,
                total_deposit: 0,
                final_tally: None,
            };

            let proposal_key_bytes = [
                ioi_api::state::service_namespace_prefix("governance").as_slice(),
                GOVERNANCE_PROPOSAL_KEY_PREFIX,
                &1u64.to_le_bytes(),
            ]
            .concat();
            let entry = StateEntry {
                value: codec::to_bytes_canonical(&proposal).unwrap(),
                block_height: 0,
            };
            let entry_bytes = codec::to_bytes_canonical(&entry).unwrap();
            genesis_state.insert(
                format!("b64:{}", BASE64_STANDARD.encode(proposal_key_bytes)),
                json!(format!("b64:{}", BASE64_STANDARD.encode(&entry_bytes))),
            );

            // Add mandatory block timing parameters
            let timing_params = BlockTimingParams {
                base_interval_secs: 5,
                retarget_every_blocks: 0,
                ..Default::default()
            };
            let timing_runtime = BlockTimingRuntime {
                effective_interval_secs: timing_params.base_interval_secs,
                ..Default::default()
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

    let test_result: Result<()> = async {
        let node = &mut cluster.validators[0];
        let rpc_addr = &node.validator().rpc_addr;
        let (mut orch_logs, mut workload_logs, _) = node.validator().subscribe_logs();
        wait_for_height(rpc_addr, 1, Duration::from_secs(20)).await?;

        // --- 3. TEST: ATTEMPT TO USE NON-EXISTENT SERVICE ---
        let invalid_service_payload = SystemPayload::CallService {
            service_id: "fee_calculator".to_string(),
            method: "some_method@v1".to_string(),
            params: vec![],
        };
        let tx_fail = create_system_tx(
            &user_key,
            invalid_service_payload.clone(),
            user_nonce,
            chain_id,
        )?;
        let submission_result = submit_transaction(rpc_addr, &tx_fail).await;
        assert!(
            submission_result.is_err(),
            "Transaction to non-existent service should be rejected at RPC level"
        );
        if let Err(e) = submission_result {
            assert!(
                e.to_string()
                    .contains("Service 'fee_calculator' is not active"),
                "Error message should indicate the service is not active, but was: {}",
                e
            );
        }

        println!("SUCCESS: Correctly rejected call to non-existent fee_calculator service.");

        // --- 4. GOVERNANCE: INSTALL THE SERVICE ---
        let artifact_hash = ioi_crypto::algorithms::hash::sha256(&service_artifact)?;
        let manifest_hash = ioi_crypto::algorithms::hash::sha256(manifest_toml.as_bytes())?;

        // Step A: Store module
        let store_params = StoreModuleParams {
            manifest: manifest_toml,
            artifact: service_artifact,
        };
        let store_tx = create_system_tx(
            &governance_key_for_test,
            SystemPayload::CallService {
                service_id: "governance".to_string(),
                method: "store_module@v1".to_string(),
                params: codec::to_bytes_canonical(&store_params).map_err(anyhow::Error::msg)?,
            },
            governance_nonce,
            chain_id,
        )?;
        governance_nonce += 1;
        submit_transaction(rpc_addr, &store_tx).await?;
        wait_for_height(rpc_addr, 2, Duration::from_secs(20)).await?;

        let manifest_key = [UPGRADE_MANIFEST_PREFIX, &manifest_hash].concat();
        let artifact_key = [UPGRADE_ARTIFACT_PREFIX, &artifact_hash].concat();
        wait_until(
            Duration::from_secs(10),
            Duration::from_millis(500),
            || async {
                Ok(query_state_key(rpc_addr, &manifest_key).await?.is_some()
                    && query_state_key(rpc_addr, &artifact_key).await?.is_some())
            },
        )
        .await?;
        println!("SUCCESS: Oracle module components stored on-chain.");

        // Step B: Schedule swap
        let tip = tip_height_resilient(rpc_addr).await?;
        let activation_height = tip + 2;
        println!(
            "Scheduling fee_calculator upgrade at height {}",
            activation_height
        );
        let swap_params = SwapModuleParams {
            service_id: "fee_calculator".to_string(),
            manifest_hash,
            artifact_hash,
            activation_height,
        };
        let swap_tx = create_system_tx(
            &governance_key_for_test,
            SystemPayload::CallService {
                service_id: "governance".to_string(),
                method: "swap_module@v1".to_string(),
                params: codec::to_bytes_canonical(&swap_params).map_err(anyhow::Error::msg)?,
            },
            governance_nonce,
            chain_id,
        )?;
        governance_nonce += 1;
        submit_transaction(rpc_addr, &swap_tx).await?;

        let pending_key = [UPGRADE_PENDING_PREFIX, &activation_height.to_le_bytes()].concat();
        wait_until(
            Duration::from_secs(30),
            Duration::from_millis(500),
            || async { Ok(query_state_key(rpc_addr, &pending_key).await?.is_some()) },
        )
        .await?;
        println!(
            "SUCCESS: fee_calculator module upgrade scheduled for height {}.",
            activation_height
        );

        // --- 5. WAIT & VERIFY ACTIVATION ---
        wait_for_height(rpc_addr, activation_height + 1, Duration::from_secs(30)).await?;
        println!("Waiting for service registration to be confirmed in state...");
        wait_until(Duration::from_secs(20), Duration::from_millis(500), || {
            println!(
                "  - Polling for service_v2_registered at height {}...",
                activation_height
            );
            service_v2_registered(rpc_addr, activation_height, artifact_hash)
        })
        .await?;
        println!("SUCCESS: New service `fee_calculator` is active on-chain.");

        // --- 6. VERIFY FUNCTIONALITY ---
        let vote_params = VoteParams {
            proposal_id: 1,
            option: ioi_types::app::VoteOption::Abstain,
        };
        let encoded_vote =
            ioi_types::codec::to_bytes_canonical(&vote_params).expect("encode vote params");
        let dummy_tx_payload = SystemPayload::CallService {
            service_id: "governance".to_string(),
            method: "vote@v1".to_string(),
            params: encoded_vote,
        };
        // Use governance_key (+nonce) to ensure authorization and inclusion.
        let dummy_tx = create_system_tx(
            &governance_key_for_test,
            dummy_tx_payload,
            governance_nonce,
            chain_id,
        )?;
        submit_transaction(rpc_addr, &dummy_tx).await?;

        // Sanity: ensure the dummy tx actually entered the mempool this time.
        assert_log_contains("Orchestration", &mut orch_logs, "mempool_add").await?;

        // Give the chain one block to include the tx before scanning Workload logs.
        let tip_after_dummy = tip_height_resilient(rpc_addr).await?;
        wait_for_height(rpc_addr, tip_after_dummy + 1, Duration::from_secs(20)).await?;

        assert_log_contains(
            "Workload",
            &mut workload_logs,
            "[WasmService fee_calculator] Calling method 'ante_handle@v1' in WASM",
        )
        .await?;
        println!("SUCCESS: Activated WASM service's TxDecorator hook was correctly invoked.");

        println!("--- Service Architecture Lifecycle E2E Test Passed ---");

        Ok(())
    }
    .await;

    for guard in cluster.validators {
        guard.shutdown().await?;
    }

    test_result?;
    Ok(())
}
