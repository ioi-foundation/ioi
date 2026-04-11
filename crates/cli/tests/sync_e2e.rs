// Path: crates/cli/tests/sync_e2e.rs
#![cfg(all(
    any(feature = "consensus-aft", feature = "consensus-pos"),
    feature = "vm-wasm",
    feature = "state-iavl"
))]

use anyhow::{anyhow, Result};
use ioi_api::state::service_namespace_prefix;
use ioi_cli::testing::{
    build_test_artifacts, genesis::GenesisBuilder, rpc, wait_for, wait_for_height, TestCluster,
};
use ioi_services::governance::VoteParams;
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, BlockTimingParams,
        BlockTimingRuntime, ChainId, ChainTransaction, Proposal, ProposalStatus, ProposalType,
        SignHeader, SignatureProof, SignatureSuite, StateEntry, SystemPayload, SystemTransaction,
        ValidatorSetV1, ValidatorSetsV1, ValidatorV1, VoteOption,
    },
    codec,
    config::InitialServiceConfig,
    keys::GOVERNANCE_PROPOSAL_KEY_PREFIX,
    service_configs::MigrationConfig,
};
use libp2p::identity::Keypair;
use std::time::Duration;

async fn fetch_metric(metrics_addr: &str, name: &str) -> String {
    let url = format!("http://{metrics_addr}/metrics");
    match reqwest::get(&url).await {
        Ok(resp) => match resp.text().await {
            Ok(body) => body
                .lines()
                .find_map(|line| {
                    line.starts_with(name)
                        .then(|| line.split_whitespace().last().unwrap_or("?").to_string())
                })
                .unwrap_or_else(|| "missing".to_string()),
            Err(_) => "Err".to_string(),
        },
        Err(_) => "Down".to_string(),
    }
}

fn create_dummy_tx(keypair: &Keypair, nonce: u64, chain_id: ChainId) -> Result<ChainTransaction> {
    let vote_yes = (nonce & 1) == 0;
    let params = VoteParams {
        proposal_id: 1,
        option: if vote_yes {
            VoteOption::Yes
        } else {
            VoteOption::No
        },
    };
    let payload = SystemPayload::CallService {
        service_id: "governance".to_string(),
        method: "vote@v1".to_string(),
        params: codec::to_bytes_canonical(&params).map_err(|e| anyhow!(e))?,
    };

    let public_key_bytes = keypair.public().encode_protobuf();
    let account_id_hash = account_id_from_key_material(SignatureSuite::ED25519, &public_key_bytes)?;
    let account_id = AccountId(account_id_hash);

    let header = SignHeader {
        account_id,
        nonce,
        chain_id,
        tx_version: 1,
        session_auth: None, // [FIX] Initialize session_auth
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_multi_batch_sync() -> Result<()> {
    build_test_artifacts();

    #[cfg(feature = "consensus-pos")]
    let (consensus_type, initial_weight) = ("ProofOfStake", 100_000u128);
    #[cfg(not(feature = "consensus-pos"))]
    let (consensus_type, initial_weight) = ("Aft", 1u128);

    let genesis_modifier = move |builder: &mut GenesisBuilder, keys: &Vec<Keypair>| {
        let mut validators = Vec::new();

        for key in keys {
            let account_id = builder.add_identity(key);

            validators.push(ValidatorV1 {
                account_id,
                weight: initial_weight,
                consensus_key: ActiveKeyRecord {
                    suite: SignatureSuite::ED25519,
                    public_key_hash: account_id.0,
                    since_height: 0,
                },
            });
        }
        validators.sort_by(|a, b| a.account_id.cmp(&b.account_id));

        let vs = ValidatorSetsV1 {
            current: ValidatorSetV1 {
                effective_from_height: 1,
                total_weight: validators.iter().map(|v| v.weight).sum(),
                validators,
            },
            next: None,
        };
        builder.set_validators(&vs);

        // Add dummy proposal
        let proposal = Proposal {
            id: 1,
            title: "Sync Test Dummy Proposal".to_string(),
            description: "Allows vote transactions during sync tests.".to_string(),
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
            service_namespace_prefix("governance").as_slice(),
            GOVERNANCE_PROPOSAL_KEY_PREFIX,
            &1u64.to_le_bytes(),
        ]
        .concat();
        let entry = StateEntry {
            value: codec::to_bytes_canonical(&proposal).unwrap(),
            block_height: 0,
        };
        builder.insert_typed(proposal_key_bytes, &entry);

        let timing_params = BlockTimingParams {
            base_interval_secs: 1,
            min_interval_secs: 1,
            max_interval_secs: 5,
            retarget_every_blocks: 0,
            base_interval_ms: 1_000,
            min_interval_ms: 1_000,
            max_interval_ms: 5_000,
            ..Default::default()
        };
        let timing_runtime = BlockTimingRuntime {
            effective_interval_secs: 1,
            effective_interval_ms: 1_000,
            ..Default::default()
        };
        builder.set_block_timing(&timing_params, &timing_runtime);
    };

    let cluster = TestCluster::builder()
        .with_validators(2)
        .with_consensus_type(consensus_type)
        .with_genesis_modifier(genesis_modifier)
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::ED25519],
            allow_downgrade: false,
        }))
        .with_initial_service(InitialServiceConfig::Governance(Default::default()))
        .build()
        .await?;

    let test_result = async {
        let node0 = &cluster.validators[0];
        let node1 = &cluster.validators[1];

        let target_tx_count = 40;
        let mut nonce = 0;
        let mut committed_height = 0;
        for _ in 0..target_tx_count {
            let tx = create_dummy_tx(&node0.validator().keypair, nonce, 1.into())?;
            let committed_block =
                rpc::submit_transaction_and_get_block(&node0.validator().rpc_addr, &tx).await?;
            committed_height = committed_block.header.height;
            nonce += 1;
        }

        wait_for_height(
            &node0.validator().rpc_addr,
            committed_height,
            Duration::from_secs(240),
        )
        .await?;
        wait_for_height(
            &node1.validator().rpc_addr,
            committed_height,
            Duration::from_secs(240),
        )
        .await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;

    for guard in cluster.validators {
        guard.shutdown().await?;
    }

    test_result?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_sync_with_peer_drop() -> Result<()> {
    build_test_artifacts();

    #[cfg(feature = "consensus-pos")]
    let (consensus_type, initial_weight) = ("ProofOfStake", 100_000u128);
    #[cfg(not(feature = "consensus-pos"))]
    let (consensus_type, initial_weight) = ("Aft", 1u128);

    let genesis_modifier = move |builder: &mut GenesisBuilder, keys: &Vec<Keypair>| {
        let mut validators = Vec::new();

        for key in keys {
            let account_id = builder.add_identity(key);
            validators.push(ValidatorV1 {
                account_id,
                weight: initial_weight,
                consensus_key: ActiveKeyRecord {
                    suite: SignatureSuite::ED25519,
                    public_key_hash: account_id.0,
                    since_height: 0,
                },
            });
        }
        validators.sort_by(|a, b| a.account_id.cmp(&b.account_id));

        let vs = ValidatorSetsV1 {
            current: ValidatorSetV1 {
                effective_from_height: 1,
                total_weight: validators.iter().map(|v| v.weight).sum(),
                validators,
            },
            next: None,
        };
        builder.set_validators(&vs);

        let proposal = Proposal {
            id: 1,
            title: "Sync Test Dummy Proposal".to_string(),
            description: "Allows vote transactions during sync tests.".to_string(),
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
            service_namespace_prefix("governance").as_slice(),
            GOVERNANCE_PROPOSAL_KEY_PREFIX,
            &1u64.to_le_bytes(),
        ]
        .concat();
        let entry = StateEntry {
            value: codec::to_bytes_canonical(&proposal).unwrap(),
            block_height: 0,
        };
        builder.insert_typed(proposal_key_bytes, &entry);

        let timing_params = BlockTimingParams {
            base_interval_secs: 1,
            min_interval_secs: 1,
            max_interval_secs: 5,
            retarget_every_blocks: 0,
            base_interval_ms: 1_000,
            min_interval_ms: 1_000,
            max_interval_ms: 5_000,
            ..Default::default()
        };
        let timing_runtime = BlockTimingRuntime {
            effective_interval_secs: 1,
            effective_interval_ms: 1_000,
            ..Default::default()
        };
        builder.set_block_timing(&timing_params, &timing_runtime);
    };

    let mut cluster = TestCluster::builder()
        .with_validators(3)
        .with_consensus_type(consensus_type)
        .with_genesis_modifier(genesis_modifier)
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::ED25519],
            allow_downgrade: false,
        }))
        .with_initial_service(InitialServiceConfig::Governance(Default::default()))
        .build()
        .await?;

    let test_result: Result<()> = async {
        let target_height = 10;
        wait_for_height(
            &cluster.validators[0].validator().rpc_addr,
            target_height,
            Duration::from_secs(60),
        )
        .await?;

        println!("--- Seed cluster reached height {} ---", target_height);

        if let Some(node_to_shutdown) = cluster.validators.pop() {
            println!(
                "Shutting down node ({}) to create a stable 2-node cluster.",
                node_to_shutdown.validator().peer_id
            );
            node_to_shutdown.shutdown().await?;
        } else {
            return Err(anyhow!(
                "expected a third validator to remove for peer-drop testing"
            ));
        }
        wait_for(
            "remaining seed peers to observe the removed validator disconnect",
            Duration::from_millis(500),
            Duration::from_secs(60),
            || async {
                let mut all_disconnected = true;
                for seed in &cluster.validators {
                    let peer_count = fetch_metric(
                        &seed.validator().orchestration_telemetry_addr,
                        "ioi_networking_connected_peers",
                    )
                    .await;
                    match peer_count.parse::<u64>() {
                        Ok(1) => {}
                        _ => {
                            all_disconnected = false;
                            break;
                        }
                    }
                }
                if all_disconnected {
                    Ok(Some(()))
                } else {
                    Ok(None)
                }
            },
        )
        .await?;

        let leader = &cluster.validators[0];
        let follower = &cluster.validators[1];
        let synced_tip = rpc::get_chain_height(&leader.validator().rpc_addr).await?;
        let resume_tx = create_dummy_tx(&leader.validator().keypair, 0, 1.into())?;
        rpc::submit_transaction(&leader.validator().rpc_addr, &resume_tx).await?;
        wait_for_height(
            &leader.validator().rpc_addr,
            synced_tip + 1,
            Duration::from_secs(120),
        )
        .await?;
        wait_for_height(
            &follower.validator().rpc_addr,
            synced_tip + 1,
            Duration::from_secs(120),
        )
        .await?;
        println!("--- Sync with peer drop successful ---");

        Ok(())
    }
    .await;

    for guard in cluster.validators {
        guard.shutdown().await?;
    }

    test_result?;

    Ok(())
}
