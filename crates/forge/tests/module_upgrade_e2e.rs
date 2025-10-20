// Path: crates/forge/tests/module_upgrade_e2e.rs

#![cfg(all(feature = "consensus-poa", feature = "vm-wasm"))]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use depin_sdk_crypto::algorithms::hash::sha256;
use depin_sdk_forge::testing::{
    assert_log_contains,
    poll::{wait_for_height, wait_until},
    rpc::{get_block_by_height, query_state_key, query_state_key_at_root},
    submit_transaction, TestCluster,
};
use depin_sdk_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, ChainId, ChainTransaction,
        Credential, Proposal, ProposalStatus, ProposalType, SignHeader, SignatureProof,
        SignatureSuite, StateEntry, SystemPayload, SystemTransaction, ValidatorSetV1,
        ValidatorSetsV1, ValidatorV1, VoteOption,
    },
    codec,
    config::InitialServiceConfig,
    keys::{
        active_service_key, GOVERNANCE_KEY, GOVERNANCE_PROPOSAL_KEY_PREFIX,
        IDENTITY_CREDENTIALS_PREFIX, UPGRADE_ARTIFACT_PREFIX, UPGRADE_MANIFEST_PREFIX,
        UPGRADE_PENDING_PREFIX, VALIDATOR_SET_KEY,
    },
    service_configs::MigrationConfig,
};
use libp2p::identity::{self, Keypair};
use parity_scale_codec::Encode;
use serde_json::json;
use std::path::Path;
use std::time::Duration;
use tokio::time::sleep;

// --- Service Parameter Structs (Client-side representation of the ABI) ---
#[derive(Encode)]
struct VoteParams {
    proposal_id: u64,
    option: VoteOption,
}

// --- Test Helpers ---

/// Polls for a key to exist in the current canonical state.
async fn wait_key_exists(rpc: &str, key: &[u8], timeout: Duration) -> Result<()> {
    let start = std::time::Instant::now();
    loop {
        if let Some(_) = query_state_key(rpc, key).await? {
            return Ok(());
        }
        if start.elapsed() > timeout {
            break;
        }
        sleep(Duration::from_millis(200)).await;
    }
    Err(anyhow!("key not found in time: {}", hex::encode(key)))
}

// Helper function to create a signed `CallService` transaction
fn create_call_service_tx<P: Encode>(
    keypair: &Keypair,
    service_id: &str,
    method: &str,
    params: P,
    nonce: u64,
    chain_id: ChainId,
) -> Result<ChainTransaction> {
    let public_key_bytes = keypair.public().encode_protobuf();
    let account_id_hash = account_id_from_key_material(SignatureSuite::Ed25519, &public_key_bytes)?;
    let account_id = AccountId(account_id_hash);

    let payload = SystemPayload::CallService {
        service_id: service_id.to_string(),
        method: method.to_string(),
        params: codec::to_bytes_canonical(&params).map_err(|e| anyhow!(e))?,
    };

    let header = SignHeader {
        account_id,
        nonce,
        chain_id,
        tx_version: 1,
    };

    let mut tx_to_sign = SystemTransaction {
        header,
        payload,
        signature_proof: SignatureProof::default(),
    };
    let sign_bytes = tx_to_sign.to_sign_bytes()?;
    let signature = keypair.sign(&sign_bytes)?;

    tx_to_sign.signature_proof = SignatureProof {
        suite: SignatureSuite::Ed25519,
        public_key: public_key_bytes,
        signature,
    };
    Ok(ChainTransaction::System(Box::new(tx_to_sign)))
}

// Helper function to create a signed system transaction (for non-service calls)
fn create_system_tx(
    keypair: &Keypair,
    payload: SystemPayload,
    nonce: u64,
    chain_id: ChainId,
) -> Result<ChainTransaction> {
    let public_key_bytes = keypair.public().encode_protobuf();
    let account_id_hash = account_id_from_key_material(SignatureSuite::Ed25519, &public_key_bytes)?;
    let account_id = AccountId(account_id_hash);

    let header = SignHeader {
        account_id,
        nonce,
        chain_id,
        tx_version: 1,
    };

    let mut tx_to_sign = SystemTransaction {
        header,
        payload,
        signature_proof: SignatureProof::default(),
    };
    let sign_bytes = tx_to_sign.to_sign_bytes()?;
    let signature = keypair.sign(&sign_bytes)?;

    tx_to_sign.signature_proof = SignatureProof {
        suite: SignatureSuite::Ed25519,
        public_key: public_key_bytes,
        signature,
    };
    Ok(ChainTransaction::System(Box::new(tx_to_sign)))
}

/// State-based check to verify if the new service is active.
async fn service_v2_registered(rpc_addr: &str, activation_height: u64) -> Result<bool> {
    // Make sure we've actually produced the target block.
    wait_for_height(rpc_addr, activation_height, Duration::from_secs(10)).await?;

    let fee_v2_key = active_service_key("fee_calculator");
    let canary_key = active_service_key("identity_hub"); // should exist since genesis

    for h in [
        activation_height,
        activation_height + 1,
        activation_height + 2,
    ] {
        let header = match get_block_by_height(rpc_addr, h).await? {
            Some(h) => h,
            None => {
                log::trace!("[probe h={}] block not yet available", h);
                continue;
            }
        };
        let root = &header.state_root;

        // Canary first: prove we’re looking at the right namespace and reader is sane.
        match query_state_key_at_root(rpc_addr, root, &canary_key).await {
            Ok(Some(_)) => {} // good
            Ok(None) => {
                log::trace!(
                    "[probe h={}] canary key (identity_hub) NOT found at root {}",
                    h,
                    hex::encode(&root.0)
                );
            }
            Err(e) => {
                log::trace!("[probe h={}] canary query error: {}", h, e);
            }
        }

        // Now the actual upgraded service key.
        if let Ok(Some(_)) = query_state_key_at_root(rpc_addr, root, &fee_v2_key).await {
            return Ok(true);
        }
    }
    Ok(false)
}

#[tokio::test]
async fn test_forkless_module_upgrade() -> Result<()> {
    // 1. SETUP & BUILD
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let contract_manifest_path =
        manifest_dir.join("tests/contracts/fee-calculator-service/Cargo.toml");

    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow!("Could not determine workspace root from CARGO_MANIFEST_DIR"))?;
    let target_dir = workspace_root.join("target");

    let status = std::process::Command::new("cargo")
        .args([
            "build",
            "--release",
            "--manifest-path",
            contract_manifest_path
                .to_str()
                .ok_or_else(|| anyhow!("Invalid path to contract manifest"))?,
            "--target",
            "wasm32-unknown-unknown",
            "--target-dir",
            target_dir
                .to_str()
                .ok_or_else(|| anyhow!("Invalid path to target directory"))?,
        ])
        .status()?;
    assert!(
        status.success(),
        "Failed to build fee-calculator-service WASM"
    );

    let wasm_path =
        workspace_root.join("target/wasm32-unknown-unknown/release/fee_calculator_service.wasm");
    let service_artifact = std::fs::read(&wasm_path)
        .map_err(|e| anyhow!("Failed to read WASM file at {:?}: {}", wasm_path, e))?;

    let manifest_toml = r#"
id = "fee_calculator"
abi_version = 1
state_schema = "v1"
runtime = "wasm"
capabilities = ["TxDecorator"]
"#;

    let governance_key = identity::Keypair::generate_ed25519();
    let governance_pubkey_b58 =
        bs58::encode(governance_key.public().try_into_ed25519()?.to_bytes()).into_string();

    let governance_key_clone = governance_key.clone();

    // 2. LAUNCH CLUSTER
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
        .with_initial_service(InitialServiceConfig::Governance(Default::default()))
        .with_genesis_modifier(move |genesis, keys| {
            let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();
            // Setup validator identity
            let validator_key = &keys[0];
            let suite = SignatureSuite::Ed25519;
            let validator_pk_bytes = validator_key.public().encode_protobuf();
            let validator_account_id_hash =
                account_id_from_key_material(suite, &validator_pk_bytes).unwrap();
            let validator_account_id = AccountId(validator_account_id_hash);
            let vs_bytes = codec::to_bytes_canonical(&ValidatorSetsV1 {
                current: ValidatorSetV1 {
                    effective_from_height: 1,
                    total_weight: 1,
                    validators: vec![ValidatorV1 {
                        account_id: validator_account_id,
                        weight: 1,
                        consensus_key: ActiveKeyRecord {
                            suite,
                            public_key_hash: validator_account_id_hash,
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
            genesis_state.insert(
                std::str::from_utf8(GOVERNANCE_KEY).unwrap().to_string(),
                json!(governance_pubkey_b58),
            );

            // Add a dummy proposal so the vote tx is valid
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
                voting_end_height: u64::MAX, // Keep it open forever for simplicity
                total_deposit: 0,
                final_tally: None,
            };
            let proposal_key_bytes = [GOVERNANCE_PROPOSAL_KEY_PREFIX, &1u64.to_le_bytes()].concat();
            let entry = StateEntry {
                value: codec::to_bytes_canonical(&proposal).unwrap(),
                block_height: 0,
            };
            let entry_bytes = codec::to_bytes_canonical(&entry).unwrap();
            genesis_state.insert(
                format!("b64:{}", BASE64_STANDARD.encode(proposal_key_bytes)),
                json!(format!("b64:{}", BASE64_STANDARD.encode(&entry_bytes))),
            );

            let gov_pk_bytes = governance_key_clone.public().encode_protobuf();
            let gov_account_id =
                AccountId(account_id_from_key_material(suite, &gov_pk_bytes).unwrap());

            for (_key, acct_id) in [
                (validator_key, validator_account_id),
                (&governance_key_clone, gov_account_id),
            ] {
                let cred = Credential {
                    suite,
                    public_key_hash: acct_id.0,
                    activation_height: 0,
                    l2_location: None,
                };
                let creds_array: [Option<Credential>; 2] = [Some(cred), None];
                let creds_bytes = codec::to_bytes_canonical(&creds_array).unwrap();
                let creds_key = [IDENTITY_CREDENTIALS_PREFIX, acct_id.as_ref()].concat();
                genesis_state.insert(
                    format!("b64:{}", BASE64_STANDARD.encode(&creds_key)),
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&creds_bytes))),
                );
            }
        })
        .build()
        .await?;

    // 3. GET HANDLES
    let node = &cluster.validators[0];
    let rpc_addr = &node.rpc_addr;
    let mut nonce = 0;

    // 4. SUBMIT TWO-PHASE UPGRADE
    // Phase 1: Store the artifact and manifest on-chain.
    let store_payload = SystemPayload::StoreModule {
        manifest: manifest_toml.to_string(),
        artifact: service_artifact.clone(),
    };
    let store_tx = create_system_tx(&governance_key, store_payload, nonce, 1.into())?;
    nonce += 1;
    submit_transaction(rpc_addr, &store_tx).await?;
    wait_for_height(rpc_addr, 2, Duration::from_secs(20)).await?;

    // --- ASSERT PHASE 1 COMPLETION ---
    let manifest_hash = sha256(manifest_toml.as_bytes())?;
    let artifact_hash = sha256(&service_artifact)?;
    let manifest_key = [UPGRADE_MANIFEST_PREFIX, &manifest_hash].concat();
    let artifact_key = [UPGRADE_ARTIFACT_PREFIX, &artifact_hash].concat();

    // Ensure both components are stored before scheduling the swap.
    wait_key_exists(rpc_addr, &manifest_key, Duration::from_secs(10)).await?;
    wait_key_exists(rpc_addr, &artifact_key, Duration::from_secs(10)).await?;
    println!("SUCCESS: Confirmed module artifact and manifest are stored on-chain.");
    // --- END ASSERTION ---

    // Phase 2: Schedule the upgrade using the hashes of the stored components.
    let activation_height = 5;
    let swap_payload = SystemPayload::SwapModule {
        service_id: "fee_calculator".to_string(),
        manifest_hash,
        artifact_hash,
        activation_height,
    };

    let swap_tx = create_system_tx(&governance_key, swap_payload, nonce, 1.into())?;
    submit_transaction(rpc_addr, &swap_tx).await?;

    // --- ASSERT PHASE 2 SCHEDULING ---
    let pending_key = [UPGRADE_PENDING_PREFIX, &activation_height.to_le_bytes()].concat();
    // Don’t jump straight to height 5; first ensure the pending entry exists.
    wait_key_exists(rpc_addr, &pending_key, Duration::from_secs(20)).await?;
    println!(
        "SUCCESS: Confirmed upgrade is scheduled in state for height {}.",
        activation_height
    );
    // --- END ASSERTION ---

    // 5. WAIT for activation.
    wait_for_height(rpc_addr, activation_height, Duration::from_secs(60)).await?;

    // 6. ASSERT the upgrade was applied by polling state.
    wait_until(
        Duration::from_secs(30),
        Duration::from_millis(500),
        || service_v2_registered(rpc_addr, activation_height),
    )
    .await
    .map_err(|_| {
        anyhow!(
            "State verification failed: fee_calculator was not registered in state at or after height {}",
            activation_height
        )
    })?;

    // 7. Verify Functionality by checking logs
    let (_, mut workload_logs, _) = node.subscribe_logs();
    let dummy_tx = create_call_service_tx(
        &node.keypair,
        "governance",
        "vote@v1",
        VoteParams {
            proposal_id: 1,
            option: VoteOption::Abstain,
        },
        0, // Nonce for the validator keypair
        1.into(),
    )?;
    submit_transaction(rpc_addr, &dummy_tx).await?;
    assert_log_contains(
        "Workload",
        &mut workload_logs,
        "[WasmService fee_calculator] Calling method 'ante_handle@v1' in WASM",
    )
    .await?;

    println!("--- Forkless Module Upgrade E2E Test Successful ---");
    Ok(())
}
