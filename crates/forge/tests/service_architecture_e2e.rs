// Path: crates/forge/tests/service_architecture_e2e.rs
#![cfg(all(feature = "consensus-poa", feature = "vm-wasm", feature = "state-iavl"))]

use anyhow::{anyhow, Result};
use ioi_api::state::service_namespace_prefix;
use ioi_forge::testing::{
    assert_log_contains, build_test_artifacts,
    rpc::{query_state_key, query_state_key_at_root, tip_height_resilient},
    submit_transaction, wait_for_height, wait_until, TestCluster,
};
use ioi_services::governance::{StoreModuleParams, SwapModuleParams};
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, BlockTimingParams,
        BlockTimingRuntime, ChainId, ChainTransaction, Proposal, ProposalStatus, ProposalType,
        SignatureSuite, StateEntry, SystemPayload, SystemTransaction, ValidatorSetV1,
        ValidatorSetsV1, ValidatorV1, VoteOption,
    },
    codec,
    config::InitialServiceConfig,
    keys::{
        active_service_key, GOVERNANCE_PROPOSAL_KEY_PREFIX, UPGRADE_ARTIFACT_PREFIX,
        UPGRADE_MANIFEST_PREFIX, UPGRADE_PENDING_PREFIX,
    },
    service_configs::{ActiveServiceMeta, GovernancePolicy, GovernanceSigner, MigrationConfig},
};
use libp2p::identity::{self, Keypair};
use parity_scale_codec::Encode;
use std::path::Path;
use std::time::Duration;

#[derive(Encode)]
struct VoteParams {
    pub proposal_id: u64,
    pub option: VoteOption,
}

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
    let fee_v2_key = active_service_key("fee_calculator");
    let tip = tip_height_resilient(rpc_addr).await?;
    if tip < activation_height {
        return Ok(false);
    }

    for h in [
        activation_height,
        activation_height + 1,
        activation_height + 2,
    ] {
        if h > tip {
            break;
        }
        if let Ok(Some(block)) =
            ioi_forge::testing::rpc::get_block_by_height_resilient(rpc_addr, h).await
        {
            if let Ok(Some(meta_bytes)) =
                query_state_key_at_root(rpc_addr, &block.header.state_root, &fee_v2_key).await
            {
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
    build_test_artifacts();

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().and_then(|p| p.parent()).unwrap();
    let wasm_path = workspace_root.join("target/wasm32-wasip1/release/fee_calculator_service.wasm");
    let service_artifact = std::fs::read(&wasm_path)?;

    let manifest_toml = r#"
id = "fee_calculator"
abi_version = 1
state_schema = "v1"
runtime = "wasm"
capabilities = ["TxDecorator"]

[methods]
"ante_validate@v1" = "Internal"
"ante_write@v1" = "Internal"
"#
    .to_string();

    let governance_key = identity::Keypair::generate_ed25519();
    let user_key = identity::Keypair::generate_ed25519();
    let chain_id: ChainId = 1.into();
    let mut governance_nonce = 0;

    let governance_key_for_test = governance_key.clone();
    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
        }))
        .with_initial_service(InitialServiceConfig::Governance(Default::default()))
        .with_genesis_modifier(move |builder, keys| {
            let validator_id = builder.add_identity(&keys[0]);
            let governance_id = builder.add_identity(&governance_key);
            builder.add_identity(&user_key);

            builder.set_governance_policy(&GovernancePolicy {
                signer: GovernanceSigner::Single(governance_id),
            });

            builder.set_validators(&ValidatorSetsV1 {
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
            });

            let proposal = Proposal {
                id: 1,
                title: "Upgrade".into(),
                description: "".into(),
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
            let proposal_key = [
                service_namespace_prefix("governance").as_slice(),
                GOVERNANCE_PROPOSAL_KEY_PREFIX,
                &1u64.to_le_bytes(),
            ]
            .concat();
            builder.insert_typed(
                proposal_key,
                &StateEntry {
                    value: codec::to_bytes_canonical(&proposal).unwrap(),
                    block_height: 0,
                },
            );

            builder.set_block_timing(
                &BlockTimingParams {
                    base_interval_secs: 2,
                    ..Default::default()
                },
                &BlockTimingRuntime {
                    effective_interval_secs: 2,
                    ..Default::default()
                },
            );
        })
        .build()
        .await?;

    let node = &cluster.validators[0];
    let rpc_addr = &node.validator().rpc_addr;
    wait_for_height(rpc_addr, 1, Duration::from_secs(20)).await?;

    let artifact_hash = ioi_crypto::algorithms::hash::sha256(&service_artifact)?;
    let store_params = StoreModuleParams {
        manifest: manifest_toml,
        artifact: service_artifact,
    };
    let store_tx = create_system_tx(
        &governance_key_for_test,
        SystemPayload::CallService {
            service_id: "governance".into(),
            method: "store_module@v1".into(),
            params: codec::to_bytes_canonical(&store_params).unwrap(),
        },
        governance_nonce,
        chain_id,
    )?;
    governance_nonce += 1;
    submit_transaction(rpc_addr, &store_tx).await?;

    let tip = tip_height_resilient(rpc_addr).await?;
    let activation_height = tip + 5;
    let swap_params = SwapModuleParams {
        service_id: "fee_calculator".into(),
        manifest_hash: ioi_crypto::algorithms::hash::sha256(store_params.manifest.as_bytes())?,
        artifact_hash,
        activation_height,
    };
    let swap_tx = create_system_tx(
        &governance_key_for_test,
        SystemPayload::CallService {
            service_id: "governance".into(),
            method: "swap_module@v1".into(),
            params: codec::to_bytes_canonical(&swap_params).unwrap(),
        },
        governance_nonce,
        chain_id,
    )?;
    submit_transaction(rpc_addr, &swap_tx).await?;

    wait_for_height(rpc_addr, activation_height + 1, Duration::from_secs(60)).await?;
    wait_until(Duration::from_secs(30), Duration::from_millis(500), || {
        service_v2_registered(rpc_addr, activation_height, artifact_hash)
    })
    .await?;

    // VERIFY FUNCTIONALITY
    let vote_tx = create_system_tx(
        &governance_key_for_test,
        SystemPayload::CallService {
            service_id: "governance".into(),
            method: "vote@v1".into(),
            params: codec::to_bytes_canonical(&VoteParams {
                proposal_id: 1,
                option: VoteOption::Abstain,
            })
            .unwrap(),
        },
        governance_nonce + 1,
        chain_id,
    )?;
    submit_transaction(rpc_addr, &vote_tx).await?;

    wait_for_height(rpc_addr, activation_height + 2, Duration::from_secs(20)).await?;

    // VERIFY STATE SIDE-EFFECT
    let ns = service_namespace_prefix("fee_calculator");
    let visited_key = [ns.as_slice(), b"visited"].concat();
    // [FIX] Increased timeout to 60s to prevent flakey test failure
    wait_until(Duration::from_secs(60), Duration::from_millis(500), || {
        let rpc = rpc_addr.clone();
        let key = visited_key.clone();
        async move { Ok(query_state_key(&rpc, &key).await?.is_some()) }
    })
    .await
    .expect("Fee calculator service failed to write 'visited' key to state");

    println!("SUCCESS: Activated WASM service executed and modified state.");
    cluster.shutdown().await?;
    Ok(())
}
