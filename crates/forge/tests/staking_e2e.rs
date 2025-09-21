// Path: crates/forge/tests/staking_e2e.rs

#![cfg(all(feature = "consensus-pos", feature = "vm-wasm"))]

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use depin_sdk_client::WorkloadClient;
use depin_sdk_forge::testing::{
    build_test_artifacts,
    poll::{wait_for_height, wait_for_stake_to_be},
    submit_transaction, TestCluster,
};
use depin_sdk_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, ChainId, ChainTransaction,
        Credential, SignHeader, SignatureProof, SignatureSuite, SystemPayload, SystemTransaction,
        ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    codec,
    config::InitialServiceConfig,
    keys::{ACCOUNT_ID_TO_PUBKEY_PREFIX, IDENTITY_CREDENTIALS_PREFIX, VALIDATOR_SET_KEY},
    service_configs::MigrationConfig,
};
use libp2p::identity::Keypair;
use serde_json::json;
use std::time::Duration;
use tokio::time::interval;

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

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_staking_lifecycle() -> Result<()> {
    build_test_artifacts();

    let mut cluster = TestCluster::builder()
        .with_validators(3)
        .with_consensus_type("ProofOfStake")
        .with_state_tree("IAVL")
        .with_chain_id(1)
        .with_commitment_scheme("Hash")
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
        }))
        .with_genesis_modifier(|genesis, keys| {
            let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();
            let initial_stake = 100_000u128;

            let validators: Vec<ValidatorV1> = keys
                .iter()
                .map(|keypair| {
                    let pk_bytes = keypair.public().encode_protobuf();
                    let account_id_hash =
                        account_id_from_key_material(SignatureSuite::Ed25519, &pk_bytes).unwrap();
                    let account_id = AccountId(account_id_hash);

                    ValidatorV1 {
                        account_id,
                        weight: initial_stake,
                        consensus_key: ActiveKeyRecord {
                            suite: SignatureSuite::Ed25519,
                            pubkey_hash: account_id_hash,
                            since_height: 0,
                        },
                    }
                })
                .collect();

            let total_weight = validators.iter().map(|v| v.weight).sum();

            let validator_sets = ValidatorSetsV1 {
                current: ValidatorSetV1 {
                    effective_from_height: 1,
                    total_weight,
                    validators,
                },
                next: None,
            };

            let vs_bytes = depin_sdk_types::app::write_validator_sets(&validator_sets);
            genesis_state.insert(
                std::str::from_utf8(VALIDATOR_SET_KEY).unwrap().to_string(),
                json!(format!("b64:{}", BASE64_STANDARD.encode(&vs_bytes))),
            );

            for keypair in keys {
                let pk_bytes = keypair.public().encode_protobuf();
                let suite = SignatureSuite::Ed25519;
                let account_id_hash = account_id_from_key_material(suite, &pk_bytes).unwrap();
                let account_id = AccountId(account_id_hash);
                let pubkey_hash = account_id_from_key_material(suite, &pk_bytes).unwrap();

                let pubkey_map_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, account_id.as_ref()].concat();
                genesis_state.insert(
                    format!("b64:{}", BASE64_STANDARD.encode(&pubkey_map_key)),
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&pk_bytes))),
                );

                let record = ActiveKeyRecord {
                    suite,
                    pubkey_hash,
                    since_height: 0,
                };
                let record_key = [b"identity::key_record::", account_id.as_ref()].concat();
                let record_bytes = codec::to_bytes_canonical(&record);
                genesis_state.insert(
                    format!("b64:{}", BASE64_STANDARD.encode(&record_key)),
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&record_bytes))),
                );

                let cred = Credential {
                    suite,
                    public_key_hash: account_id.0,
                    activation_height: 0,
                    l2_location: None,
                };
                let creds_array: [Option<Credential>; 2] = [Some(cred), None];
                let creds_bytes = serde_json::to_vec(&creds_array).unwrap();
                let creds_key = [IDENTITY_CREDENTIALS_PREFIX, account_id.as_ref()].concat();
                genesis_state.insert(
                    format!("b64:{}", BASE64_STANDARD.encode(&creds_key)),
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&creds_bytes))),
                );
            }
        })
        .build()
        .await?;

    // Get cert paths for node 0
    let certs0_path = &cluster.validators[0].certs_dir_path;
    let ca0_path = certs0_path.join("ca.pem").to_string_lossy().to_string();
    let cert0_path = certs0_path
        .join("orchestration.pem")
        .to_string_lossy()
        .to_string();
    let key0_path = certs0_path
        .join("orchestration.key")
        .to_string_lossy()
        .to_string();
    // Get cert paths for node 1
    let certs1_path = &cluster.validators[1].certs_dir_path;
    let ca1_path = certs1_path.join("ca.pem").to_string_lossy().to_string();
    let cert1_path = certs1_path
        .join("orchestration.pem")
        .to_string_lossy()
        .to_string();
    let key1_path = certs1_path
        .join("orchestration.key")
        .to_string_lossy()
        .to_string();
    // Get cert paths for node 2
    let certs2_path = &cluster.validators[2].certs_dir_path;
    let ca2_path = certs2_path.join("ca.pem").to_string_lossy().to_string();
    let cert2_path = certs2_path
        .join("orchestration.pem")
        .to_string_lossy()
        .to_string();
    let key2_path = certs2_path
        .join("orchestration.key")
        .to_string_lossy()
        .to_string();

    let rpc_addr = cluster.validators[0].rpc_addr.clone();
    let client0 = WorkloadClient::new(
        &cluster.validators[0].workload_ipc_addr,
        &ca0_path,
        &cert0_path,
        &key0_path,
    )
    .await?;
    let client1 = WorkloadClient::new(
        &cluster.validators[1].workload_ipc_addr,
        &ca1_path,
        &cert1_path,
        &key1_path,
    )
    .await?;
    let client2 = WorkloadClient::new(
        &cluster.validators[2].workload_ipc_addr,
        &ca2_path,
        &cert2_path,
        &key2_path,
    )
    .await?;
    let keypair0 = cluster.validators[0].keypair.clone();
    let keypair1 = cluster.validators[1].keypair.clone();
    let client1_rpc_addr = cluster.validators[1].rpc_addr.clone(); // For waiting on node 1

    // --- FIX START: Use the new `subscribe_logs` method ---
    let (mut orch_logs_0, mut work_logs_0, _) = cluster.validators[0].subscribe_logs();
    let (mut orch_logs_1, mut work_logs_1, _) = cluster.validators[1].subscribe_logs();
    let (mut orch_logs_2, mut work_logs_2, _) = cluster.validators[2].subscribe_logs();
    // --- FIX END ---

    // Logging task to drain all logs in the background and prevent backpressure
    let logging_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                // Node 0
                Ok(line) = orch_logs_0.recv() => println!("[Orch-0]: {}", line),
                Ok(line) = work_logs_0.recv() => println!("[Work-0]: {}", line),
                // Node 1
                Ok(line) = orch_logs_1.recv() => println!("[Orch-1]: {}", line),
                Ok(line) = work_logs_1.recv() => println!("[Work-1]: {}", line),
                // Node 2
                Ok(line) = orch_logs_2.recv() => println!("[Orch-2]: {}", line),
                Ok(line) = work_logs_2.recv() => println!("[Work-2]: {}", line),
                else => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    });

    wait_for_height(&rpc_addr, 1, Duration::from_secs(20)).await?;
    wait_for_height(&client1_rpc_addr, 1, Duration::from_secs(30)).await?;

    let unstake_payload = SystemPayload::Unstake { amount: 100_000 };
    let unstake_tx = create_system_tx(&keypair0, unstake_payload, 0, 1.into())?;
    submit_transaction(&rpc_addr, &unstake_tx).await?;

    let stake_payload = SystemPayload::Stake {
        public_key: keypair1.public().encode_protobuf(),
        amount: 50_000,
    };
    let stake_tx = create_system_tx(&keypair1, stake_payload, 0, 1.into())?;
    submit_transaction(&rpc_addr, &stake_tx).await?;

    println!("--- Waiting for block 3 with periodic status checks ---");
    let wait_fut = wait_for_height(&rpc_addr, 3, Duration::from_secs(60));
    let clients = [&client0, &client1, &client2];
    let mut poll_interval = interval(Duration::from_secs(2));

    let polling_task = async {
        loop {
            poll_interval.tick().await;
            let mut statuses = Vec::new();
            for (i, client) in clients.iter().enumerate() {
                let status_str = match client.get_status().await {
                    Ok(status) => format!("[Node{} H:{}]", i, status.height),
                    Err(_) => format!("[Node{} H:ERR]", i),
                };
                statuses.push(status_str);
            }
            println!("Cluster Status: {}", statuses.join(" "));
        }
    };

    tokio::select! {
        res = wait_fut => {
            res?
        },
        _ = polling_task => {},
    };

    let node0_account_id = AccountId(account_id_from_key_material(
        SignatureSuite::Ed25519,
        &keypair0.public().encode_protobuf(),
    )?);
    let node1_account_id = AccountId(account_id_from_key_material(
        SignatureSuite::Ed25519,
        &keypair1.public().encode_protobuf(),
    )?);

    wait_for_stake_to_be(&client0, &node0_account_id, 0, Duration::from_secs(30)).await?;
    wait_for_stake_to_be(
        &client1,
        &node1_account_id,
        150_000,
        Duration::from_secs(30),
    )
    .await?;

    logging_task.abort();
    println!("--- Staking Lifecycle E2E Test Passed ---");
    Ok(())
}
