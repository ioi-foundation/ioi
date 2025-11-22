// Path: crates/forge/tests/staking_e2e.rs
#![cfg(all(feature = "consensus-pos", feature = "vm-wasm"))]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ioi_client::WorkloadClient;
use ioi_forge::testing::{
    add_genesis_identity, build_test_artifacts, submit_transaction, wait_for_height,
    wait_for_stake_to_be, TestCluster,
};
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, BlockTimingParams,
        BlockTimingRuntime, ChainId, ChainTransaction, SignHeader, SignatureProof, SignatureSuite,
        SystemPayload, SystemTransaction, ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    codec,
    config::InitialServiceConfig,
    keys::{
        active_service_key, BLOCK_TIMING_PARAMS_KEY, BLOCK_TIMING_RUNTIME_KEY, VALIDATOR_SET_KEY,
    },
    service_configs::{ActiveServiceMeta, Capabilities, MethodPermission, MigrationConfig},
};
use libp2p::identity::Keypair;
use parity_scale_codec::Encode;
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;

#[derive(Encode)]
struct StakeParams {
    public_key: Vec<u8>,
    amount: u64,
}

#[derive(Encode)]
struct UnstakeParams {
    amount: u64,
}

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
    let sign_bytes = tx_to_sign.to_sign_bytes().map_err(|e| anyhow!(e))?;
    let signature = keypair.sign(&sign_bytes)?;

    tx_to_sign.signature_proof = SignatureProof {
        suite: SignatureSuite::Ed25519,
        public_key: public_key_bytes,
        signature,
    };
    Ok(ChainTransaction::System(Box::new(tx_to_sign)))
}

#[tokio::test(flavor = "multi_thread")]
async fn test_staking_lifecycle() -> Result<()> {
    build_test_artifacts();

    let initial_stake = 100_000u64;

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
        .with_initial_service(InitialServiceConfig::Governance(Default::default()))
        .with_genesis_modifier(move |genesis, keys| {
            let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();
            let initial_stake = 100_000u128;

            let mut validators: Vec<ValidatorV1> = keys
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
                            public_key_hash: account_id_hash,
                            since_height: 0,
                        },
                    }
                })
                .collect();
            validators.sort_by(|a, b| a.account_id.cmp(&b.account_id));

            let total_weight = validators.iter().map(|v| v.weight).sum();

            let validator_sets = ValidatorSetsV1 {
                current: ValidatorSetV1 {
                    effective_from_height: 1,
                    total_weight,
                    validators,
                },
                next: None,
            };

            let vs_bytes = ioi_types::app::write_validator_sets(&validator_sets).unwrap();
            genesis_state.insert(
                std::str::from_utf8(VALIDATOR_SET_KEY).unwrap().to_string(),
                json!(format!("b64:{}", BASE64_STANDARD.encode(&vs_bytes))),
            );

            let timing_params = BlockTimingParams {
                base_interval_secs: 5,
                min_interval_secs: 2,
                max_interval_secs: 10,
                target_gas_per_block: 1_000_000,
                ema_alpha_milli: 200,
                interval_step_bps: 500,
                retarget_every_blocks: 0,
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

            // Use shared helper for identity injection
            for keypair in keys {
                add_genesis_identity(genesis_state, keypair);
            }

            let mut methods = BTreeMap::new();
            methods.insert("stake@v1".to_string(), MethodPermission::User);
            methods.insert("unstake@v1".to_string(), MethodPermission::User);
            let meta = ActiveServiceMeta {
                id: "governance".to_string(),
                abi_version: 1,
                state_schema: "v1".to_string(),
                caps: Capabilities::ON_END_BLOCK,
                artifact_hash: [0; 32],
                activated_at: 0,
                methods,
                allowed_system_prefixes: vec![
                    "system::validators::".to_string(),
                    "identity::".to_string(),
                ],
            };
            let meta_key = active_service_key("governance");
            let entry = ioi_types::app::StateEntry {
                value: codec::to_bytes_canonical(&meta).unwrap(),
                block_height: 0,
            };
            let entry_bytes = codec::to_bytes_canonical(&entry).unwrap();
            genesis_state.insert(
                format!("b64:{}", BASE64_STANDARD.encode(&meta_key)),
                json!(format!("b64:{}", BASE64_STANDARD.encode(&entry_bytes))),
            );
        })
        .build()
        .await?;

    let test_result: anyhow::Result<()> = async {
        let certs0_path = &cluster.validators[0].validator().certs_dir_path;
        let ca0_path = certs0_path.join("ca.pem").to_string_lossy().to_string();
        let cert0_path = certs0_path
            .join("orchestration.pem")
            .to_string_lossy()
            .to_string();
        let key0_path = certs0_path
            .join("orchestration.key")
            .to_string_lossy()
            .to_string();
        let certs1_path = &cluster.validators[1].validator().certs_dir_path;
        let ca1_path = certs1_path.join("ca.pem").to_string_lossy().to_string();
        let cert1_path = certs1_path
            .join("orchestration.pem")
            .to_string_lossy()
            .to_string();
        let key1_path = certs1_path
            .join("orchestration.key")
            .to_string_lossy()
            .to_string();

        let rpc_addr = cluster.validators[0].validator().rpc_addr.clone();
        let client0 = WorkloadClient::new(
            &cluster.validators[0].validator().workload_ipc_addr,
            &ca0_path,
            &cert0_path,
            &key0_path,
        )
        .await?;
        let client1 = WorkloadClient::new(
            &cluster.validators[1].validator().workload_ipc_addr,
            &ca1_path,
            &cert1_path,
            &key1_path,
        )
        .await?;
        let keypair0 = cluster.validators[0].validator().keypair.clone();
        let keypair1 = cluster.validators[1].validator().keypair.clone();
        let client1_rpc_addr = cluster.validators[1].validator().rpc_addr.clone();

        wait_for_height(&rpc_addr, 1, Duration::from_secs(20)).await?;
        wait_for_height(&client1_rpc_addr, 1, Duration::from_secs(30)).await?;

        let unstake_payload = SystemPayload::CallService {
            service_id: "governance".to_string(),
            method: "unstake@v1".to_string(),
            params: codec::to_bytes_canonical(&UnstakeParams {
                amount: initial_stake,
            })
            .map_err(|e| anyhow!(e))?,
        };
        let unstake_tx = create_system_tx(&keypair0, unstake_payload, 0, 1.into())?;
        submit_transaction(&rpc_addr, &unstake_tx).await?;

        let stake_payload = SystemPayload::CallService {
            service_id: "governance".to_string(),
            method: "stake@v1".to_string(),
            params: codec::to_bytes_canonical(&StakeParams {
                public_key: keypair1.public().encode_protobuf(),
                amount: 50_000,
            })
            .map_err(|e| anyhow!(e))?,
        };
        let stake_tx = create_system_tx(&keypair1, stake_payload, 0, 1.into())?;
        submit_transaction(&rpc_addr, &stake_tx).await?;

        wait_for_height(&rpc_addr, 3, Duration::from_secs(30)).await?;

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
        Ok(())
    }
    .await;

    for guard in cluster.validators {
        guard.shutdown().await?;
    }

    test_result?;

    println!("--- Staking Lifecycle E2E Test Passed ---");
    Ok(())
}
