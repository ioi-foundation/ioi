// Path: crates/forge/tests/t_timestamp_coherence.rs
#![cfg(all(feature = "consensus-poa", feature = "vm-wasm", feature = "state-iavl"))]

use anyhow::{anyhow, Result};
use ioi_forge::testing::{
    rpc::{get_block_by_height_resilient, get_chain_height, submit_transaction_no_wait},
    wait_for_height, TestCluster,
};
use ioi_services::governance::StoreModuleParams;
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, BlockTimingParams,
        BlockTimingRuntime, ChainTransaction, SignHeader, SignatureProof, SignatureSuite,
        SystemPayload, SystemTransaction, ValidatorSetV1, ValidatorSetsV1, ValidatorV1,
    },
    codec,
    config::InitialServiceConfig,
    service_configs::{GovernanceParams, GovernancePolicy, GovernanceSigner, MigrationConfig},
};
use libp2p::identity::Keypair;
use std::time::Duration;

struct TestNet {
    cluster: TestCluster,
    nonce: u64,
    user_keypair: Keypair,
}

impl TestNet {
    async fn setup() -> Self {
        let user_keypair = Keypair::generate_ed25519();
        let user_keypair_for_genesis = user_keypair.clone();

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
            .with_initial_service(InitialServiceConfig::Governance(GovernanceParams::default()))
            // --- UPDATED: Using GenesisBuilder API ---
            .with_genesis_modifier(move |builder, keys| {
                let validator_keypair = &keys[0];

                // 1. Identities
                let user_account_id = builder.add_identity(&user_keypair_for_genesis);
                let validator_account_id = builder.add_identity(validator_keypair);
                let validator_hash = validator_account_id.0;

                // 2. Governance Policy
                let policy = GovernancePolicy {
                    signer: GovernanceSigner::Single(user_account_id),
                };
                builder.set_governance_policy(&policy);

                // 3. Validator Set
                let vs = ValidatorSetsV1 {
                    current: ValidatorSetV1 {
                        effective_from_height: 1,
                        total_weight: 1,
                        validators: vec![ValidatorV1 {
                            account_id: validator_account_id,
                            weight: 1,
                            consensus_key: ActiveKeyRecord {
                                suite: SignatureSuite::Ed25519,
                                public_key_hash: validator_hash,
                                since_height: 0,
                            },
                        }],
                    },
                    next: None,
                };
                builder.set_validators(&vs);

                // 4. Block Timing
                // [+] FIX: Set valid min/max intervals to prevent clamping to 0
                let timing_params = BlockTimingParams {
                    base_interval_secs: 5,
                    min_interval_secs: 1,
                    max_interval_secs: 60,
                    ..Default::default()
                };
                let timing_runtime = BlockTimingRuntime {
                    effective_interval_secs: timing_params.base_interval_secs,
                    ..Default::default()
                };
                builder.set_block_timing(&timing_params, &timing_runtime);
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
        let height = get_chain_height(rpc_addr).await?;
        for _ in 0..10 {
            if let Some(b) = get_block_by_height_resilient(rpc_addr, height).await? {
                return Ok(b.header.timestamp);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Err(anyhow!("Failed to fetch block at height {}", height))
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

    let initial_height = get_chain_height(&validator_rpc_addr).await?;
    println!("Current chain height from state: {}", initial_height);

    let mut parent_block = None;
    for _ in 0..20 {
        if let Ok(Some(b)) =
            get_block_by_height_resilient(&validator_rpc_addr, initial_height).await
        {
            parent_block = Some(b);
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let parent_block = parent_block.expect("Failed to fetch parent block");
    let parent_ts = parent_block.header.timestamp;
    println!(
        "Parent block (H={}) timestamp: {}",
        initial_height, parent_ts
    );

    let interval = net.expected_interval_secs();
    let expected_ts = parent_ts + interval;
    println!("Expected timestamp for next block: {}", expected_ts);

    let store_params = StoreModuleParams {
        manifest: format!("timestamp = {}", expected_ts),
        artifact: vec![],
    };
    let payload = SystemPayload::CallService {
        service_id: "governance".to_string(),
        method: "store_module@v1".to_string(),
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

    let sign_bytes = system_tx.to_sign_bytes().map_err(|e| anyhow!(e))?;
    let signature = user_keypair.sign(&sign_bytes)?;

    system_tx.signature_proof = SignatureProof {
        suite: SignatureSuite::Ed25519,
        public_key: user_keypair.public().encode_protobuf(),
        signature,
    };

    let tx = ChainTransaction::System(Box::new(system_tx));
    net.nonce += 1;

    println!("Submitting transaction...");
    submit_transaction_no_wait(&validator_rpc_addr, &tx).await?;

    let target_height = initial_height + 1;
    println!("Waiting for height {}...", target_height);
    wait_for_height(&validator_rpc_addr, target_height, Duration::from_secs(30)).await?;

    println!("Fetching block {}...", target_height);
    let mut block_opt = None;
    for _ in 0..20 {
        if let Ok(Some(b)) = get_block_by_height_resilient(&validator_rpc_addr, target_height).await
        {
            block_opt = Some(b);
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let block = block_opt.expect("Failed to fetch block after wait_for_height");

    println!(
        "Block {} timestamp: {}",
        target_height, block.header.timestamp
    );

    let tx_found = block.transactions.iter().any(|btx| {
        let Ok(ser_btx) = ioi_types::codec::to_bytes_canonical(btx) else {
            return false;
        };
        let Ok(ser_tx) = ioi_types::codec::to_bytes_canonical(&tx) else {
            return false;
        };
        ser_btx == ser_tx
    });

    if !tx_found {
        if block.header.timestamp == expected_ts {
            println!(
                "WARN: Block has correct timestamp but transaction is missing. Mempool latency?"
            );
        }
        panic!("Transaction not found in block {}", target_height);
    }

    assert_eq!(
        block.header.timestamp, expected_ts,
        "Block header timestamp must equal the authoritative timestamp from consensus"
    );

    for guard in net.cluster.validators {
        guard.shutdown().await?;
    }

    Ok(())
}
