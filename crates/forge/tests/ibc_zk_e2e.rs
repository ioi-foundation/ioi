// Path: crates/forge/tests/ibc_zk_e2e.rs
#![cfg(all(
    feature = "consensus-poa",
    feature = "vm-wasm",
    feature = "state-iavl",
    feature = "ibc-deps",
    feature = "ethereum-zk" // Crucial: gate this test on the feature
))]

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ioi_crypto::algorithms::hash::sha256;
use ioi_forge::testing::{
    add_genesis_identity, build_test_artifacts,
    rpc::{query_state_key, submit_transaction_and_get_block},
    TestCluster,
};
use ioi_types::{
    app::{
        AccountId, ActiveKeyRecord, BlockTimingParams, BlockTimingRuntime, ChainId,
        ChainTransaction, SignHeader, SignatureProof, SignatureSuite, SystemPayload,
        SystemTransaction, ValidatorSetBlob, ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    codec,
    config::{IbcConfig, InitialServiceConfig},
    ibc::{
        EthereumHeader, Finality, Header, InclusionProof, StateProofScheme, SubmitHeaderParams,
        VerifyStateParams,
    },
    keys::{BLOCK_TIMING_PARAMS_KEY, BLOCK_TIMING_RUNTIME_KEY, VALIDATOR_SET_KEY},
    service_configs::MigrationConfig,
};
use libp2p::identity::Keypair;
use serde_json::json;
use std::time::Duration;

fn create_zk_system_tx(
    kp: &Keypair,
    payload: SystemPayload,
    nonce: u64,
) -> Result<ChainTransaction> {
    let pk = kp.public().encode_protobuf();
    let acc_hash = ioi_types::app::account_id_from_key_material(SignatureSuite::Ed25519, &pk)?;
    let account_id = AccountId(acc_hash);

    let mut tx = SystemTransaction {
        header: SignHeader {
            account_id,
            nonce,
            chain_id: ChainId(1),
            tx_version: 1,
        },
        payload,
        signature_proof: SignatureProof::default(),
    };

    let sb = tx.to_sign_bytes().map_err(|e| anyhow::anyhow!(e))?;
    tx.signature_proof = SignatureProof {
        suite: SignatureSuite::Ed25519,
        public_key: pk,
        signature: kp.sign(&sb)?,
    };

    Ok(ChainTransaction::System(Box::new(tx)))
}

#[tokio::test]
async fn test_bridgeless_zk_interoperability() -> Result<()> {
    build_test_artifacts();

    // 1. SETUP: Launch cluster with 'ethereum-zk' enabled
    let mut cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("ProofOfAuthority")
        .with_state_tree("IAVL")
        .with_chain_id(1)
        // Explicitly enable the ZK feature on the node binary
        .with_extra_feature("ethereum-zk")
        // Enable IdentityHub for the signer
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
        }))
        // Enable IBC service
        .with_initial_service(InitialServiceConfig::Ibc(IbcConfig {
            enabled_clients: vec![], // No Tendermint clients needed, but service must be active
        }))
        .with_genesis_modifier(|genesis, keys| {
            let gs = genesis["genesis_state"].as_object_mut().unwrap();
            let kp = &keys[0];
            let acc_id = add_genesis_identity(gs, kp);

            // Minimal Validator Set
            let vs = ValidatorSetV1 {
                effective_from_height: 1,
                total_weight: 1,
                validators: vec![ValidatorV1 {
                    account_id: acc_id,
                    weight: 1,
                    consensus_key: ActiveKeyRecord {
                        suite: SignatureSuite::Ed25519,
                        public_key_hash: acc_id.0,
                        since_height: 0,
                    },
                }],
            };
            let vs_blob = ValidatorSetBlob {
                schema_version: 2,
                payload: ValidatorSetsV1 {
                    current: vs,
                    next: None,
                },
            };
            let vs_bytes = ioi_types::app::write_validator_sets(&vs_blob.payload).unwrap();
            gs.insert(
                std::str::from_utf8(VALIDATOR_SET_KEY).unwrap().to_string(),
                json!(format!("b64:{}", BASE64.encode(vs_bytes))),
            );

            // Block Timing
            let timing = BlockTimingParams {
                base_interval_secs: 2,
                ..Default::default()
            };
            let runtime = BlockTimingRuntime {
                effective_interval_secs: 2,
                ..Default::default()
            };
            gs.insert(
                std::str::from_utf8(BLOCK_TIMING_PARAMS_KEY)
                    .unwrap()
                    .to_string(),
                json!(format!(
                    "b64:{}",
                    BASE64.encode(codec::to_bytes_canonical(&timing).unwrap())
                )),
            );
            gs.insert(
                std::str::from_utf8(BLOCK_TIMING_RUNTIME_KEY)
                    .unwrap()
                    .to_string(),
                json!(format!(
                    "b64:{}",
                    BASE64.encode(codec::to_bytes_canonical(&runtime).unwrap())
                )),
            );
        })
        .build()
        .await?;

    let node = cluster.validators[0].validator();
    let rpc = &node.rpc_addr;
    let kp = &node.keypair;

    // 2. PREPARE FAKE ZK DATA
    // SimulatedGroth16 rule: hash(proof) == public_inputs

    // A. ZK Proof for Header (Simulating a beacon client update)
    let zk_proof_bytes = b"zk_proof_of_valid_header".to_vec();
    // The root is the public input for the circuit
    let state_root_hash = sha256(&zk_proof_bytes)?;
    let mut state_root = [0u8; 32];
    state_root.copy_from_slice(&state_root_hash);

    let eth_header = EthereumHeader { state_root };

    // B. Submit Header Transaction
    let submit_params = SubmitHeaderParams {
        chain_id: "eth-mainnet".to_string(),
        header: Header::Ethereum(eth_header.clone()),
        finality: Finality::EthereumBeaconUpdate {
            update_ssz: zk_proof_bytes.clone(),
        },
    };

    let submit_tx = create_zk_system_tx(
        kp,
        SystemPayload::CallService {
            service_id: "ibc".to_string(),
            method: "submit_header@v1".to_string(),
            params: codec::to_bytes_canonical(&submit_params).unwrap(),
        },
        0,
    )?;

    println!("Submitting ZK Header...");
    submit_transaction_and_get_block(rpc, &submit_tx).await?;

    // 3. VERIFY PERSISTENCE
    // The registry should have stored the root.
    // Key: ibc::light_clients::eth-mainnet::state_root::{hex_root}
    let root_hex = hex::encode(state_root);
    let ns = ioi_api::state::service_namespace_prefix("ibc");
    let check_key = [
        ns.as_slice(),
        format!("ibc::light_clients::eth-mainnet::state_root::{}", root_hex).as_bytes(),
    ]
    .concat();

    let stored = query_state_key(rpc, &check_key).await?;
    assert!(stored.is_some(), "Header root was not persisted!");
    println!("Header persisted successfully.");

    // 4. PROVE INCLUSION (Bridgeless Read)
    // SimulatedGroth16 rule: hash(proof) == public_inputs
    // For inclusion, public_input is the root.
    // We reuse the same proof bytes so they hash to the same root we just trusted.

    let verify_params = VerifyStateParams {
        chain_id: "eth-mainnet".to_string(),
        height: 0,
        path: b"accounts/0x1234".to_vec(),
        value: b"1337".to_vec(),
        proof: InclusionProof::Evm {
            scheme: StateProofScheme::Verkle,
            proof_bytes: zk_proof_bytes, // Same bytes -> Same hash -> Matches stored root
        },
    };

    let verify_tx = create_zk_system_tx(
        kp,
        SystemPayload::CallService {
            service_id: "ibc".to_string(),
            method: "verify_state@v1".to_string(),
            params: codec::to_bytes_canonical(&verify_params).unwrap(),
        },
        1,
    )?;

    println!("Submitting Inclusion Verification...");
    submit_transaction_and_get_block(rpc, &verify_tx).await?;

    // 5. VERIFY MATERIALIZATION
    let materialized_key = [
        ns.as_slice(),
        format!(
            "ibc::verified::kv::eth-mainnet::{}",
            hex::encode(b"accounts/0x1234")
        )
        .as_bytes(),
    ]
    .concat();

    let val = query_state_key(rpc, &materialized_key)
        .await?
        .expect("Value should be materialized");
    assert_eq!(val, b"1337");

    println!("--- Bridgeless ZK Interoperability E2E Passed ---");

    for guard in cluster.validators {
        guard.shutdown().await?;
    }
    Ok(())
}

#[tokio::test]
async fn test_bridgeless_zk_interoperability_failure_case() -> Result<()> {
    // 1. SETUP: Reuse existing builder logic
    build_test_artifacts();

    let mut cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("ProofOfAuthority")
        .with_state_tree("IAVL")
        .with_chain_id(1)
        .with_extra_feature("ethereum-zk")
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
        }))
        .with_initial_service(InitialServiceConfig::Ibc(IbcConfig {
            enabled_clients: vec![],
        }))
        .with_genesis_modifier(|genesis, keys| {
            // ... same genesis logic as positive test ...
            let gs = genesis["genesis_state"].as_object_mut().unwrap();
            let kp = &keys[0];
            let acc_id = add_genesis_identity(gs, kp);

            let vs = ValidatorSetV1 {
                effective_from_height: 1,
                total_weight: 1,
                validators: vec![ValidatorV1 {
                    account_id: acc_id,
                    weight: 1,
                    consensus_key: ActiveKeyRecord {
                        suite: SignatureSuite::Ed25519,
                        public_key_hash: acc_id.0,
                        since_height: 0,
                    },
                }],
            };
            let vs_blob = ValidatorSetBlob {
                schema_version: 2,
                payload: ValidatorSetsV1 {
                    current: vs,
                    next: None,
                },
            };
            let vs_bytes = ioi_types::app::write_validator_sets(&vs_blob.payload).unwrap();
            gs.insert(
                std::str::from_utf8(VALIDATOR_SET_KEY).unwrap().to_string(),
                json!(format!("b64:{}", BASE64.encode(vs_bytes))),
            );

            let timing = BlockTimingParams {
                base_interval_secs: 2,
                ..Default::default()
            };
            let runtime = BlockTimingRuntime {
                effective_interval_secs: 2,
                ..Default::default()
            };
            gs.insert(
                std::str::from_utf8(BLOCK_TIMING_PARAMS_KEY)
                    .unwrap()
                    .to_string(),
                json!(format!(
                    "b64:{}",
                    BASE64.encode(codec::to_bytes_canonical(&timing).unwrap())
                )),
            );
            gs.insert(
                std::str::from_utf8(BLOCK_TIMING_RUNTIME_KEY)
                    .unwrap()
                    .to_string(),
                json!(format!(
                    "b64:{}",
                    BASE64.encode(codec::to_bytes_canonical(&runtime).unwrap())
                )),
            );
        })
        .build()
        .await?;

    let node = cluster.validators[0].validator();
    let rpc = &node.rpc_addr;
    let kp = &node.keypair;

    // 2. PREPARE MALICIOUS ZK DATA

    // Valid proof bytes
    let zk_proof_bytes = b"zk_proof_of_valid_header".to_vec();

    // But the header claims a root that does NOT match hash(proof)
    let fake_root = [0xAA; 32]; // Just some random bytes
    let eth_header = EthereumHeader {
        state_root: fake_root,
    };

    let submit_params = SubmitHeaderParams {
        chain_id: "eth-mainnet".to_string(),
        header: Header::Ethereum(eth_header.clone()),
        finality: Finality::EthereumBeaconUpdate {
            update_ssz: zk_proof_bytes.clone(),
        },
    };

    let submit_tx = create_zk_system_tx(
        kp,
        SystemPayload::CallService {
            service_id: "ibc".to_string(),
            method: "submit_header@v1".to_string(),
            params: codec::to_bytes_canonical(&submit_params).unwrap(),
        },
        0,
    )?;

    println!("Submitting MALICIOUS ZK Header...");
    // We expect this to fail verification.
    // submit_transaction will fail if the RPC returns an error from check_tx.

    let result = ioi_forge::testing::rpc::submit_transaction_no_wait(rpc, &submit_tx).await?;

    // Check if the RPC returned an error object
    if let Some(err) = result.get("error") {
        let msg = err.get("message").and_then(|s| s.as_str()).unwrap_or("");
        println!("Got expected error: {}", msg);
        assert!(
            msg.contains("ZK Beacon verification failed")
                || msg.contains("Transaction pre-check failed"),
            "Error message mismatch: {}",
            msg
        );
    } else {
        // If it was accepted into mempool, it will fail during block execution.
        // The block containing it will essentially be rejected (node stalls on bad block production),
        // or if the system design allows dropping failed txs, the state update won't happen.
        // We wait 4 seconds (2 block times) to give it a chance to process.

        tokio::time::sleep(Duration::from_secs(4)).await;

        let root_hex = hex::encode(fake_root);
        let ns = ioi_api::state::service_namespace_prefix("ibc");
        let check_key = [
            ns.as_slice(),
            format!("ibc::light_clients::eth-mainnet::state_root::{}", root_hex).as_bytes(),
        ]
        .concat();

        let stored = query_state_key(rpc, &check_key).await?;
        assert!(
            stored.is_none(),
            "Malicious header SHOULD NOT be persisted!"
        );
    }

    println!("--- Negative ZK Test Passed ---");

    for guard in cluster.validators {
        guard.shutdown().await?;
    }
    Ok(())
}
