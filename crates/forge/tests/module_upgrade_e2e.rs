// Path: crates/forge/tests/module_upgrade_e2e.rs

#![cfg(all(feature = "consensus-poa", feature = "vm-wasm"))]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use depin_sdk_forge::testing::{
    build_test_artifacts,
    poll::{wait_for_height, wait_until},
    rpc::{get_block_by_height, query_state_key_at_root},
    submit_transaction, TestCluster,
};
use depin_sdk_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, ChainId, ChainTransaction,
        Credential, SignHeader, SignatureProof, SignatureSuite, SystemPayload, SystemTransaction,
        ValidatorSetBlob, ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    codec,
    config::InitialServiceConfig,
    keys::{
        active_service_key, ACCOUNT_ID_TO_PUBKEY_PREFIX, GOVERNANCE_KEY,
        IDENTITY_CREDENTIALS_PREFIX, VALIDATOR_SET_KEY,
    },
    service_configs::MigrationConfig,
};
use libp2p::identity::{self, Keypair};
use serde_json::json;
use std::path::Path;
use std::time::Duration;

// Helper function to create a signed system transaction
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

/// State-based check with a small commit-window and a canary key from genesis.
async fn service_v2_registered(rpc_addr: &str, activation_height: u64) -> Result<bool> {
    // Make sure we've actually produced the target block.
    wait_for_height(rpc_addr, activation_height, Duration::from_secs(10)).await?;

    let fee_v2_key = active_service_key("fee_calculator_v2");
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
    build_test_artifacts();
    // Construct a robust path to the WASM artifact relative to the workspace root.
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| anyhow!("Could not determine workspace root from CARGO_MANIFEST_DIR"))?;
    let wasm_path =
        workspace_root.join("target/wasm32-unknown-unknown/release/test_service_v2.wasm");
    let service_v2_wasm = std::fs::read(&wasm_path)
        .map_err(|e| anyhow!("Failed to read WASM file at {:?}: {}", wasm_path, e))?;

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
        .with_genesis_modifier(move |genesis, keys| {
            let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();
            // Setup validator identity
            let validator_key = &keys[0];
            let suite = SignatureSuite::Ed25519;
            let validator_pk_bytes = validator_key.public().encode_protobuf();
            let validator_account_id_hash =
                account_id_from_key_material(suite, &validator_pk_bytes).unwrap();
            let validator_account_id = AccountId(validator_account_id_hash);
            let vs_blob = ValidatorSetBlob {
                schema_version: 2,
                payload: ValidatorSetsV1 {
                    current: ValidatorSetV1 {
                        effective_from_height: 1,
                        total_weight: 1,
                        validators: vec![ValidatorV1 {
                            account_id: validator_account_id,
                            weight: 1,
                            consensus_key: ActiveKeyRecord {
                                suite,
                                public_key_hash: validator_account_id.0,
                                since_height: 0,
                            },
                        }],
                    },
                    next: None,
                },
            };
            let vs_bytes = depin_sdk_types::app::write_validator_sets(&vs_blob.payload).unwrap();
            genesis_state.insert(
                std::str::from_utf8(VALIDATOR_SET_KEY).unwrap().to_string(),
                json!(format!("b64:{}", BASE64_STANDARD.encode(vs_bytes))),
            );

            // Setup governance identity
            genesis_state.insert(
                std::str::from_utf8(GOVERNANCE_KEY).unwrap().to_string(),
                json!(governance_pubkey_b58),
            );
            let gov_pk_bytes = governance_key_clone.public().encode_protobuf(); // Use the cloned key
            let gov_account_id =
                AccountId(account_id_from_key_material(suite, &gov_pk_bytes).unwrap());

            // Add credentials for both validator and governance key
            for (key, acct_id) in [
                (validator_key, validator_account_id),
                (&governance_key_clone, gov_account_id),
            ] {
                let pk_bytes = key.public().encode_protobuf();
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

                let record = ActiveKeyRecord {
                    suite,
                    public_key_hash: acct_id.0,
                    since_height: 0,
                };
                let record_key = [b"identity::key_record::", acct_id.as_ref()].concat();
                genesis_state.insert(
                    format!("b64:{}", BASE64_STANDARD.encode(&record_key)),
                    json!(format!(
                        "b64:{}",
                        BASE64_STANDARD.encode(codec::to_bytes_canonical(&record).unwrap())
                    )),
                );

                let pubkey_map_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, acct_id.as_ref()].concat();
                genesis_state.insert(
                    format!("b64:{}", BASE64_STANDARD.encode(&pubkey_map_key)),
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&pk_bytes))),
                );
            }
        })
        .build()
        .await?;

    // 3. GET HANDLES
    let node = &cluster.validators[0];
    let rpc_addr = &node.rpc_addr;

    // 4. SUBMIT UPGRADE TRANSACTION
    let activation_height = 5;
    let payload = SystemPayload::SwapModule {
        service_type: "fee_calculator_v2".to_string(),
        module_wasm: service_v2_wasm,
        activation_height,
    };

    let tx = create_system_tx(&governance_key, payload, 0, 1.into())?; // Nonce is 0 for first tx

    submit_transaction(rpc_addr, &tx).await?;

    // 5. WAIT for the chain to advance to the scheduled activation height.
    wait_for_height(rpc_addr, activation_height, Duration::from_secs(60)).await?;

    // 6. ASSERT the upgrade was applied by polling the state. This is the primary, robust assertion.
    // Give CI a little headroom (5s blocks -> 3 heights window).
    wait_until(
        Duration::from_secs(30),
        Duration::from_millis(500),
        || service_v2_registered(rpc_addr, activation_height),
    )
    .await
    .map_err(|_| {
        anyhow!(
            "State verification failed: service_v2 was not registered in state at or after height {}",
            activation_height
        )
    })?;

    println!("--- Forkless Module Upgrade E2E Test Successful ---");

    Ok(())
}