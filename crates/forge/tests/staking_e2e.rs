// Path: crates/forge/tests/staking_e2e.rs
#![cfg(all(feature = "consensus-pos", feature = "vm-wasm"))]

use anyhow::{anyhow, Result};
use ioi_client::WorkloadClient;
use ioi_forge::testing::{
    build_test_artifacts, submit_transaction, wait_for_height, wait_for_stake_to_be, TestCluster,
};
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, BlockTimingParams,
        BlockTimingRuntime, ChainId, ChainTransaction, SignHeader, SignatureProof, SignatureSuite,
        SystemPayload, SystemTransaction, ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    codec,
    config::InitialServiceConfig,
    keys::active_service_key,
    service_configs::{ActiveServiceMeta, Capabilities, MethodPermission, MigrationConfig},
};
use libp2p::identity::Keypair;
use parity_scale_codec::Encode;
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
    let account_id_hash = account_id_from_key_material(SignatureSuite::ED25519, &public_key_bytes)?;
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
        suite: SignatureSuite::ED25519,
        public_key: public_key_bytes,
        signature,
    };
    Ok(ChainTransaction::System(Box::new(tx_to_sign)))
}

#[tokio::test(flavor = "multi_thread")]
async fn test_staking_lifecycle() -> Result<()> {
    build_test_artifacts();

    let initial_stake = 100_000u64;

    let cluster = TestCluster::builder()
        .with_validators(3)
        .with_consensus_type("ProofOfStake")
        .with_state_tree("IAVL")
        .with_chain_id(1)
        .with_commitment_scheme("Hash")
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::ED25519],
            allow_downgrade: false,
        }))
        .with_initial_service(InitialServiceConfig::Governance(Default::default()))
        // --- UPDATED: Using GenesisBuilder API ---
        .with_genesis_modifier(move |builder, keys| {
            // 1. Setup Identities (and get AccountIds)
            let mut validators: Vec<ValidatorV1> = Vec::new();

            for keypair in keys {
                // Register identity using the builder helper
                let account_id = builder.add_identity(keypair);

                // Construct ValidatorV1 manually as we need the hash for consensus key record
                let pk_bytes = keypair.public().encode_protobuf();
                let account_id_hash = account_id.0;

                validators.push(ValidatorV1 {
                    account_id,
                    weight: initial_stake as u128,
                    consensus_key: ActiveKeyRecord {
                        suite: SignatureSuite::ED25519,
                        public_key_hash: account_id_hash,
                        since_height: 0,
                    },
                });
            }

            // Sort to ensure deterministic consensus
            validators.sort_by(|a, b| a.account_id.cmp(&b.account_id));
            let total_weight = validators.iter().map(|v| v.weight).sum();

            // 2. Set Validator Set
            let validator_sets = ValidatorSetsV1 {
                current: ValidatorSetV1 {
                    effective_from_height: 1,
                    total_weight,
                    validators,
                },
                next: None,
            };
            builder.set_validators(&validator_sets);

            // 3. Set Block Timing
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
            builder.set_block_timing(&timing_params, &timing_runtime);

            // 4. Manually register Governance Service Meta (as it has custom permissions in this test)
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

            // Insert the metadata using the builder's typed insertion
            builder.insert_typed(active_service_key("governance"), &meta);
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
            SignatureSuite::ED25519,
            &keypair0.public().encode_protobuf(),
        )?);
        let node1_account_id = AccountId(account_id_from_key_material(
            SignatureSuite::ED25519,
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
