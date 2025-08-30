// Path: crates/forge/tests/staking_e2e.rs

#![cfg(all(feature = "consensus-pos", feature = "vm-wasm"))]

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use depin_sdk_forge::testing::{
    assert_log_contains, build_test_artifacts, submit_transaction, TestCluster,
};
use depin_sdk_types::app::{
    account_id_from_pubkey, ChainTransaction, SignHeader, SignatureProof, SignatureSuite,
    SystemPayload, SystemTransaction,
};
// --- FIX START: Add necessary imports ---
use depin_sdk_types::app::AccountId;
use depin_sdk_types::codec;
use std::collections::BTreeMap;
// --- FIX END ---
use depin_sdk_types::config::InitialServiceConfig;
use depin_sdk_types::keys::{ACCOUNT_ID_TO_PUBKEY_PREFIX, STAKES_KEY_CURRENT, STAKES_KEY_NEXT};
use depin_sdk_types::service_configs::MigrationConfig;
use libp2p::identity::Keypair;
use serde_json::json;

// Helper function to create a signed system transaction
fn create_system_tx(
    keypair: &Keypair,
    payload: SystemPayload,
    nonce: u64,
) -> Result<ChainTransaction> {
    let public_key_bytes = keypair.public().encode_protobuf();
    let account_id = account_id_from_pubkey(&keypair.public());

    let header = SignHeader {
        account_id,
        nonce,
        chain_id: 1, // Matches chain default
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
    Ok(ChainTransaction::System(tx_to_sign))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_staking_lifecycle() -> Result<()> {
    // 1. SETUP: Build artifacts with the specific features needed for the spawned binaries.
    build_test_artifacts("consensus-pos,vm-wasm,tree-file,primitive-hash");

    // 2. LAUNCH CLUSTER: 3-node PoS cluster with Node0 as the sole initial staker.
    let mut cluster = TestCluster::builder()
        .with_validators(3)
        .with_consensus_type("ProofOfStake")
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
            chain_id: 1,
        }))
        .with_genesis_modifier(|genesis, keys| {
            let mut stakes = BTreeMap::new();
            let initial_staker_account_id = account_id_from_pubkey(&keys[0].public());
            stakes.insert(initial_staker_account_id, 100_000u64);

            let stakes_bytes = codec::to_bytes_canonical(&stakes);
            let stakes_b64 = format!("b64:{}", BASE64_STANDARD.encode(&stakes_bytes));

            genesis["genesis_state"][std::str::from_utf8(STAKES_KEY_CURRENT).unwrap()] =
                json!(stakes_b64.clone());
            genesis["genesis_state"][std::str::from_utf8(STAKES_KEY_NEXT).unwrap()] =
                json!(stakes_b64);

            // Populate the pubkey lookup map for the initial staker
            let pubkey_map_key = [
                ACCOUNT_ID_TO_PUBKEY_PREFIX,
                initial_staker_account_id.as_ref(),
            ]
            .concat();
            let pubkey_bytes = keys[0].public().encode_protobuf();
            genesis["genesis_state"][format!("b64:{}", BASE64_STANDARD.encode(&pubkey_map_key))] =
                json!(format!("b64:{}", BASE64_STANDARD.encode(&pubkey_bytes)));
        })
        .build()
        .await?;

    // 3. GET HANDLES: Get mutable references to the nodes and their log streams.
    let (node0, node1, node2) = {
        let mut it = cluster.validators.iter_mut();
        (it.next().unwrap(), it.next().unwrap(), it.next().unwrap())
    };
    let rpc_addr = node0.rpc_addr.clone();
    let node1_account_id_hex = hex::encode(account_id_from_pubkey(&node1.keypair.public()));
    let mut logs1 = node1.orch_log_stream.lock().await.take().unwrap();
    let mut logs2 = node2.orch_log_stream.lock().await.take().unwrap();

    // 4. PRE-CONDITION: Wait for the network to be active by seeing the first block gossiped.
    assert_log_contains("Node2", &mut logs2, "Received gossiped block #1").await?;

    // 5. ACTION: Submit staking transactions via Node0's RPC.
    // Transaction 1: Node0 (the current leader) unstakes all its funds.
    let unstake_payload = SystemPayload::Unstake { amount: 100_000 };
    let unstake_tx = create_system_tx(&node0.keypair, unstake_payload, 0)?;
    submit_transaction(&rpc_addr, &unstake_tx).await?;

    // --- FIX START: Add the public_key field to the Stake payload ---
    // Transaction 2: Node1 stakes some funds to become the new (and only) validator.
    let stake_payload = SystemPayload::Stake {
        public_key: node1.keypair.public().encode_protobuf(),
        amount: 50_000,
    };
    // --- FIX END ---
    let stake_tx = create_system_tx(&node1.keypair, stake_payload, 0)?;
    submit_transaction(&rpc_addr, &stake_tx).await?;

    // 6. VERIFICATION: Wait for the ultimate desired outcome: Node1 is elected as the leader.
    // The state transition happens at the end of block 2, so the new leader is for block 3.
    let expected_leader_log = format!("[PoS] Leader for height 3: {}", node1_account_id_hex);

    assert_log_contains(
        "Node1", // We can check any node's log, as they all run the same consensus.
        &mut logs1,
        &expected_leader_log,
    )
    .await?;

    println!("--- Staking Lifecycle E2E Test Passed ---");
    Ok(())
}
