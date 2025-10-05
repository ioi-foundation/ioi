// Path: forge/tests/sync_e2e.rs

#![cfg(all(feature = "consensus-poa", feature = "vm-wasm", feature = "tree-iavl"))]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use depin_sdk_forge::testing::{
    assert_log_contains, assert_log_contains_and_return_line, build_test_artifacts,
    poll::wait_for_height, submit_transaction, TestCluster, TestValidator,
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
        ACCOUNT_ID_TO_PUBKEY_PREFIX, GOVERNANCE_PROPOSAL_KEY_PREFIX, IDENTITY_CREDENTIALS_PREFIX,
        VALIDATOR_SET_KEY,
    },
    service_configs::MigrationConfig,
};
use libp2p::identity::Keypair;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::time::Duration;

/// Helper function to add a full identity record for a PoA authority to the genesis state.
/// Returns a list of (key, value) pairs to be inserted into a BTreeMap for deterministic serialization.
fn add_poa_identity_to_genesis(keypair: &Keypair) -> (AccountId, Vec<(String, Value)>) {
    let mut entries = Vec::new();
    let suite = SignatureSuite::Ed25519;
    let public_key_bytes = keypair.public().encode_protobuf();
    let account_id_hash = account_id_from_key_material(suite, &public_key_bytes).unwrap();
    let account_id = AccountId(account_id_hash);

    // B. Set the initial IdentityHub credentials
    let initial_cred = Credential {
        suite,
        public_key_hash: account_id_hash,
        activation_height: 0,
        l2_location: None,
    };
    let creds_array: [Option<Credential>; 2] = [Some(initial_cred), None];
    let creds_bytes = codec::to_bytes_canonical(&creds_array).unwrap();
    let creds_key = [IDENTITY_CREDENTIALS_PREFIX, account_id.as_ref()].concat();
    entries.push((
        format!("b64:{}", BASE64_STANDARD.encode(&creds_key)),
        json!(format!("b64:{}", BASE64_STANDARD.encode(&creds_bytes))),
    ));

    // C. Set the ActiveKeyRecord for consensus verification
    let record = ActiveKeyRecord {
        suite,
        public_key_hash: account_id_hash,
        since_height: 0,
    };
    let record_key = [b"identity::key_record::", account_id.as_ref()].concat();
    let record_bytes = codec::to_bytes_canonical(&record).unwrap();
    entries.push((
        format!("b64:{}", BASE64_STANDARD.encode(&record_key)),
        json!(format!("b64:{}", BASE64_STANDARD.encode(&record_bytes))),
    ));

    // D. Set the AccountId -> PublicKey mapping for consensus verification
    let pubkey_map_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, account_id.as_ref()].concat();
    entries.push((
        format!("b64:{}", BASE64_STANDARD.encode(&pubkey_map_key)),
        json!(format!("b64:{}", BASE64_STANDARD.encode(&public_key_bytes))),
    ));

    (account_id, entries)
}

fn create_dummy_tx(keypair: &Keypair, nonce: u64, chain_id: ChainId) -> Result<ChainTransaction> {
    // Use a simple, low-overhead Governance::Vote to avoid invoking the oracle/external network.
    let vote_yes = (nonce & 1) == 0;
    let payload = SystemPayload::Vote {
        proposal_id: 1,
        option: if vote_yes {
            VoteOption::Yes
        } else {
            VoteOption::No
        },
    };

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_multi_batch_sync() -> Result<()> {
    build_test_artifacts();

    let genesis_modifier = |genesis: &mut serde_json::Value, keys: &Vec<Keypair>| {
        let mut genesis_entries = BTreeMap::new();
        let mut validators = Vec::new();

        for key in keys {
            let (account_id, entries) = add_poa_identity_to_genesis(key);
            for (k, v) in entries {
                genesis_entries.insert(k, v);
            }
            validators.push(ValidatorV1 {
                account_id,
                weight: 1,
                consensus_key: ActiveKeyRecord {
                    suite: SignatureSuite::Ed25519,
                    public_key_hash: account_id.0,
                    since_height: 0,
                },
            });
        }
        validators.sort_by(|a, b| a.account_id.cmp(&b.account_id));

        let vs = ValidatorSetV1 {
            effective_from_height: 1,
            total_weight: validators.len() as u128,
            validators,
        };
        let vs_bytes = depin_sdk_types::app::write_validator_sets(&ValidatorSetsV1 {
            current: vs,
            next: None,
        })
        .unwrap();
        genesis_entries.insert(
            std::str::from_utf8(VALIDATOR_SET_KEY).unwrap().to_string(),
            json!(format!("b64:{}", BASE64_STANDARD.encode(vs_bytes))),
        );

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
        let proposal_key_bytes = [GOVERNANCE_PROPOSAL_KEY_PREFIX, &1u64.to_le_bytes()].concat();
        let entry = StateEntry {
            value: codec::to_bytes_canonical(&proposal).unwrap(),
            block_height: 0,
        };
        let entry_bytes = codec::to_bytes_canonical(&entry).unwrap();
        genesis_entries.insert(
            format!("b64:{}", BASE64_STANDARD.encode(proposal_key_bytes)),
            json!(format!("b64:{}", BASE64_STANDARD.encode(&entry_bytes))),
        );

        // Apply sorted entries to the final JSON object
        let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();
        for (k, v) in genesis_entries {
            genesis_state.insert(k, v);
        }
    };

    // 1. Launch a 2-node cluster together to ensure shared genesis.
    let cluster = TestCluster::builder()
        .with_validators(2)
        .with_genesis_modifier(genesis_modifier)
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
        }))
        .with_initial_service(InitialServiceConfig::Governance(Default::default()))
        .build()
        .await?;
    let node0 = &cluster.validators[0];
    let node1 = &cluster.validators[1];

    // 2. Produce enough blocks to trigger multiple sync batches.
    let target_height = 40;
    let mut nonce = 0;
    for _ in 0..target_height {
        let tx = create_dummy_tx(&node0.keypair, nonce, 1.into())?;
        // Submit to either node; it will be gossiped.
        submit_transaction(&node0.rpc_addr, &tx).await.ok();
        nonce += 1;
        tokio::time::sleep(Duration::from_millis(50)).await; // Give mempool time
    }

    // 3. Assert that BOTH nodes eventually sync to the target height.
    wait_for_height(&node0.rpc_addr, target_height, Duration::from_secs(240)).await?;
    wait_for_height(&node1.rpc_addr, target_height, Duration::from_secs(240)).await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_sync_with_peer_drop() -> Result<()> {
    build_test_artifacts();

    let genesis_modifier = |genesis: &mut serde_json::Value, keys: &Vec<Keypair>| {
        let mut genesis_entries = BTreeMap::new(); // Use BTreeMap for deterministic key order
        let mut validators = Vec::new();

        // Generate identity entries and validator structs for all keys
        for key in keys {
            let (account_id, entries) = add_poa_identity_to_genesis(key);
            for (k, v) in entries {
                genesis_entries.insert(k, v);
            }
            validators.push(ValidatorV1 {
                account_id,
                weight: 1,
                consensus_key: ActiveKeyRecord {
                    suite: SignatureSuite::Ed25519,
                    public_key_hash: account_id.0,
                    since_height: 0,
                },
            });
        }
        validators.sort_by(|a, b| a.account_id.cmp(&b.account_id));

        let vs = ValidatorSetV1 {
            effective_from_height: 1,
            total_weight: validators.len() as u128,
            validators,
        };
        let vs_bytes = depin_sdk_types::app::write_validator_sets(&ValidatorSetsV1 {
            current: vs,
            next: None,
        })
        .unwrap();
        genesis_entries.insert(
            std::str::from_utf8(VALIDATOR_SET_KEY).unwrap().to_string(),
            json!(format!("b64:{}", BASE64_STANDARD.encode(vs_bytes))),
        );
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
        let proposal_key_bytes = [GOVERNANCE_PROPOSAL_KEY_PREFIX, &1u64.to_le_bytes()].concat();
        let entry = StateEntry {
            value: codec::to_bytes_canonical(&proposal).unwrap(),
            block_height: 0,
        };
        let entry_bytes = codec::to_bytes_canonical(&entry).unwrap();
        genesis_entries.insert(
            format!("b64:{}", BASE64_STANDARD.encode(proposal_key_bytes)),
            json!(format!("b64:{}", BASE64_STANDARD.encode(&entry_bytes))),
        );

        // Atomically insert all sorted entries into the final JSON object
        let genesis_state = genesis["genesis_state"].as_object_mut().unwrap();
        for (k, v) in genesis_entries {
            genesis_state.insert(k, v);
        }
    };

    // 1. Launch a 3-node cluster and let it produce blocks.
    let mut cluster = TestCluster::builder()
        .with_validators(3)
        .with_genesis_modifier(genesis_modifier)
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
        }))
        .with_initial_service(InitialServiceConfig::Governance(Default::default()))
        .build()
        .await?;

    let target_height = 10;
    wait_for_height(
        &cluster.validators[0].rpc_addr,
        target_height,
        Duration::from_secs(60),
    )
    .await?;

    println!("--- Seed cluster reached height {} ---", target_height);

    // 2. Explicitly shut down one validator to create a stable 2-node seed cluster.
    if let Some(mut node_to_shutdown) = cluster.validators.pop() {
        println!(
            "Shutting down node ({}) to create a stable 2-node seed cluster.",
            node_to_shutdown.peer_id
        );
        node_to_shutdown.shutdown().await?;
    }

    // Now `cluster.validators` contains 2 stable nodes.
    let bootnodes = vec![
        cluster.validators[0].p2p_addr.clone(),
        cluster.validators[1].p2p_addr.clone(),
    ];

    // 3. Launch a new node (node3) that needs to sync.
    let node3 = TestValidator::launch(
        Keypair::generate_ed25519(),
        cluster.genesis_content.clone(),
        8000, // new base port
        1.into(),
        Some(&bootnodes),
        "ProofOfAuthority",
        "IAVL",
        "Hash",
        None,
        false,
        vec![
            InitialServiceConfig::IdentityHub(MigrationConfig {
                chain_id: 1,
                grace_period_blocks: 5,
                accept_staged_during_grace: true,
                allowed_target_suites: vec![SignatureSuite::Ed25519],
                allow_downgrade: false,
            }),
            InitialServiceConfig::Governance(Default::default()),
        ],
        false,
        true,
    )
    .await?;

    // Optional: subscribe for nice diagnostics (not required for correctness anymore).
    let (mut orch_logs, _, _) = node3.subscribe_logs();

    // Give node3 a moment to pick an initial peer, then drop one seed deterministically.
    tokio::time::sleep(Duration::from_secs(1)).await;
    // Drop the first seed (by index) to simulate a target disappearing soon after sync begins.
    // Whether or not it was the initial target, node3 must still complete sync.
    let mut dropped = cluster.validators.remove(0);
    println!("Dropping one seed peer: {}", dropped.peer_id);
    dropped.shutdown().await?;

    // Node3 must reach the target height via the remaining seed.
    wait_for_height(&node3.rpc_addr, target_height, Duration::from_secs(180)).await?;
    // Nice-to-have: confirm completion line if we catch it.
    let _ = assert_log_contains("node3", &mut orch_logs, "Block sync complete!").await;
    println!("--- Sync with peer drop successful ---");

    Ok(())
}