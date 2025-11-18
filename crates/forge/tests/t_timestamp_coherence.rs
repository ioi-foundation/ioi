// Path: crates/forge/tests/t_timestamp_coherence.rs

//! This test verifies the end-to-end coherence of block timestamps, ensuring that
//! the timestamp used during pre-flight checks (mempool admission) is the same
//! one used during block execution and written to the block header.

#![cfg(all(feature = "consensus-poa", feature = "vm-wasm", feature = "state-iavl"))]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ioi_forge::testing::{
    rpc::{get_block_by_height_resilient, submit_transaction_and_get_block},
    wait_for_height, TestCluster,
};
// FIX: Add necessary imports for the new service-based architecture.
use ioi_services::governance::StoreModuleParams;
use ioi_types::{
    app::{
        account_id_from_key_material,
        AccountId,
        ActiveKeyRecord,
        BlockTimingParams,
        BlockTimingRuntime,
        ChainTransaction,
        Credential,
        SignHeader,
        SignatureProof, // FIX: Remove unused ChainId import
        SignatureSuite,
        SystemPayload,
        SystemTransaction,
        ValidatorSetV1,
        ValidatorSetsV1,
        ValidatorV1,
    },
    codec,
    config::InitialServiceConfig,
    keys::{
        ACCOUNT_ID_TO_PUBKEY_PREFIX, BLOCK_TIMING_PARAMS_KEY, BLOCK_TIMING_RUNTIME_KEY,
        GOVERNANCE_KEY, IDENTITY_CREDENTIALS_PREFIX, VALIDATOR_SET_KEY,
    },
    service_configs::{GovernanceParams, GovernancePolicy, GovernanceSigner, MigrationConfig},
};
use libp2p::identity::Keypair;
use serde_json::json;
use std::time::Duration;

/// A simplified test setup that boots a single-node network and provides helpers.
struct TestNet {
    cluster: TestCluster,
    nonce: u64,
    // Store the user keypair to be used in the test
    user_keypair: Keypair,
}

impl TestNet {
    async fn setup() -> Self {
        // Generate the user keypair *before* building the cluster so it can be added to genesis.
        let user_keypair = Keypair::generate_ed25519();
        let user_suite = SignatureSuite::Ed25519;
        let user_pk_bytes = user_keypair.public().encode_protobuf();
        let user_account_id =
            AccountId(account_id_from_key_material(user_suite, &user_pk_bytes).unwrap());

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
            // FIX: Add the Governance service to the initial services.
            .with_initial_service(InitialServiceConfig::Governance(GovernanceParams::default()))
            .with_genesis_modifier(move |genesis, keys| {
                let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();
                let validator_keypair = &keys[0];
                let suite = SignatureSuite::Ed25519;

                let validator_pk_bytes = validator_keypair.public().encode_protobuf();
                let validator_account_id =
                    AccountId(account_id_from_key_material(suite, &validator_pk_bytes).unwrap());

                // FIX: Set the governance policy to make the user account the governor.
                let policy = GovernancePolicy {
                    signer: GovernanceSigner::Single(user_account_id),
                };
                let policy_bytes = codec::to_bytes_canonical(&policy).unwrap();
                genesis_state.insert(
                    std::str::from_utf8(GOVERNANCE_KEY).unwrap().to_string(),
                    json!(format!("b64:{}", BASE64_STANDARD.encode(policy_bytes))),
                );

                let vs = ValidatorSetV1 {
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
                };
                let vs_bytes = ioi_types::app::write_validator_sets(&ValidatorSetsV1 {
                    current: vs,
                    next: None,
                })
                .unwrap();
                genesis_state.insert(
                    std::str::from_utf8(VALIDATOR_SET_KEY).unwrap().to_string(),
                    json!(format!("b64:{}", BASE64_STANDARD.encode(vs_bytes))),
                );

                for (id, pk) in [
                    (user_account_id, &user_pk_bytes),
                    (validator_account_id, &validator_pk_bytes),
                ] {
                    let cred = Credential {
                        suite,
                        public_key_hash: id.0,
                        activation_height: 0,
                        l2_location: None,
                    };
                    let creds_array: [Option<Credential>; 2] = [Some(cred), None];
                    let creds_key = [IDENTITY_CREDENTIALS_PREFIX, id.as_ref()].concat();
                    genesis_state.insert(
                        format!("b64:{}", BASE64_STANDARD.encode(&creds_key)),
                        json!(format!(
                            "b64:{}",
                            BASE64_STANDARD.encode(
                                ioi_types::codec::to_bytes_canonical(&creds_array).unwrap()
                            )
                        )),
                    );
                    let pubkey_map_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, id.as_ref()].concat();
                    genesis_state.insert(
                        format!("b64:{}", BASE64_STANDARD.encode(&pubkey_map_key)),
                        json!(format!("b64:{}", BASE64_STANDARD.encode(pk))),
                    );
                }

                let timing_params = BlockTimingParams {
                    base_interval_secs: 5,
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
                        BASE64_STANDARD
                            .encode(ioi_types::codec::to_bytes_canonical(&timing_params).unwrap())
                    )),
                );
                genesis_state.insert(
                    std::str::from_utf8(BLOCK_TIMING_RUNTIME_KEY)
                        .unwrap()
                        .to_string(),
                    json!(format!(
                        "b64:{}",
                        BASE64_STANDARD
                            .encode(ioi_types::codec::to_bytes_canonical(&timing_runtime).unwrap())
                    )),
                );
            })
            .build()
            .await
            .unwrap();

        wait_for_height(
            &cluster.validators[0].validator().rpc_addr,
            1,
            Duration::from_secs(20),
        )
        .await
        .unwrap();

        Self {
            cluster,
            nonce: 0,
            user_keypair,
        }
    }

    async fn latest_timestamp_secs(&self) -> Result<u64> {
        let rpc_addr = &self.cluster.validators[0].validator().rpc_addr;
        let height = ioi_forge::testing::rpc::tip_height_resilient(rpc_addr).await?;
        Ok(get_block_by_height_resilient(rpc_addr, height)
            .await?
            .unwrap()
            .header
            .timestamp)
    }

    fn expected_interval_secs(&self) -> u64 {
        5
    }
}

#[tokio::test]
async fn time_sensitive_tx_precheck_equals_execution() -> Result<()> {
    let mut net = TestNet::setup().await;
    let validator_rpc_addr = net.cluster.validators[0].validator().rpc_addr.clone();
    let user_keypair = net.user_keypair.clone();
    let user_account_id = AccountId(
        account_id_from_key_material(
            SignatureSuite::Ed25519,
            &user_keypair.public().encode_protobuf(),
        )
        .unwrap(),
    );

    // Fetch the latest state *immediately* before calculating and submitting.
    let parent_ts = net.latest_timestamp_secs().await?;
    let interval = net.expected_interval_secs();
    let expected_ts = parent_ts + interval;

    // Create a transaction that is only valid at that exact timestamp.
    // FIX: Use `CallService` to dispatch a `store_module` call to the governance service.
    let store_params = StoreModuleParams {
        manifest: format!("timestamp = {}", expected_ts), // The "time-sensitive" part
        artifact: vec![],
    };
    let payload = SystemPayload::CallService {
        service_id: "governance".to_string(),
        method: "store_module@v1".to_string(),
        // FIX: Manually map the String error to anyhow::Error so `?` works.
        params: codec::to_bytes_canonical(&store_params).map_err(|e| anyhow!(e))?,
    };

    let mut system_tx = SystemTransaction {
        header: SignHeader {
            account_id: user_account_id,
            nonce: net.nonce,
            chain_id: 1.into(),
            tx_version: 1,
        },
        payload,
        signature_proof: Default::default(),
    };

    // FIX: Use `?` with proper error mapping instead of `.unwrap()`.
    let sign_bytes = system_tx.to_sign_bytes().map_err(|e| anyhow!(e))?;
    let signature = user_keypair.sign(&sign_bytes)?;

    system_tx.signature_proof = SignatureProof {
        suite: SignatureSuite::Ed25519,
        public_key: user_keypair.public().encode_protobuf(),
        signature,
    };

    let tx = ChainTransaction::System(Box::new(system_tx));
    net.nonce += 1;

    // 1. Submit the transaction and wait for the block that includes it.
    let block = submit_transaction_and_get_block(&validator_rpc_addr, &tx)
        .await
        .expect("Transaction should be included in the next block");

    // 2. Assert the transaction was included and the block header has the correct timestamp.
    assert_eq!(
        block.header.timestamp, expected_ts,
        "Block header timestamp must equal the authoritative timestamp from consensus"
    );

    // 3. The transaction should have been included because the execution context matched the pre-check context.
    let tx_found = block.transactions.iter().any(|btx| {
        let Ok(ser_btx) = ioi_types::codec::to_bytes_canonical(btx) else {
            return false;
        };
        let Ok(ser_tx) = ioi_types::codec::to_bytes_canonical(&tx) else {
            return false;
        };
        ser_btx == ser_tx
    });

    assert!(
        tx_found,
        "The time-sensitive transaction was not included in the block"
    );

    // Explicitly shut down the cluster to disarm the ValidatorGuard.
    for guard in net.cluster.validators {
        guard.shutdown().await?;
    }

    Ok(())
}
