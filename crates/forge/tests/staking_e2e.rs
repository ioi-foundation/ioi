// Path: crates/forge/tests/staking_e2e.rs

#![cfg(all(feature = "consensus-pos", feature = "vm-wasm"))]

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use depin_sdk_api::consensus::ChainStateReader; // FIX: Import the required trait
use depin_sdk_forge::testing::{
    build_test_artifacts, poll::wait_for_height, submit_transaction, TestCluster,
};
use depin_sdk_types::app::AccountId;
use depin_sdk_types::app::{
    account_id_from_key_material, ActiveKeyRecord, ChainTransaction, Credential, SignHeader,
    SignatureProof, SignatureSuite, SystemPayload, SystemTransaction,
};
use depin_sdk_types::codec;
use depin_sdk_types::config::InitialServiceConfig;
use depin_sdk_types::keys::{
    ACCOUNT_ID_TO_PUBKEY_PREFIX, IDENTITY_CREDENTIALS_PREFIX, STAKES_KEY_CURRENT, STAKES_KEY_NEXT,
};
use depin_sdk_types::service_configs::MigrationConfig;
use libp2p::identity::Keypair;
use serde_json::json;
use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;
use tokio::time::{sleep, Instant};

// --- FIX START: Move polling helper functions into the test module ---
// This makes the test self-contained after the refactor.

/// Generic polling function that waits for an async condition to be met.
async fn wait_for<F, Fut, T>(
    description: &str,
    interval: Duration,
    timeout: Duration,
    mut condition: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Option<T>>>,
{
    let start = Instant::now();
    loop {
        match condition().await {
            Ok(Some(value)) => return Ok(value),
            Ok(None) => { /* continue polling */ }
            Err(e) => {
                log::trace!(
                    "Polling for '{}' received transient error: {}",
                    description,
                    e
                );
            }
        }
        if start.elapsed() > timeout {
            return Err(anyhow!("Timeout waiting for {}", description));
        }
        sleep(interval).await;
    }
}

/// Waits for a specific account to have a specific stake amount using the new WorkloadClient.
async fn wait_for_stake_to_be(
    client: &depin_sdk_client::WorkloadClient,
    account_id: &AccountId,
    target_stake: u64,
    timeout: Duration,
) -> Result<()> {
    wait_for(
        &format!(
            "stake for account {} to be {}",
            hex::encode(account_id.as_ref()),
            target_stake
        ),
        Duration::from_millis(500),
        timeout,
        || async {
            // FIX: This now compiles because the ChainStateReader trait is in scope.
            let stakes = client
                .get_next_staked_validators()
                .await
                .map_err(|e| anyhow!(e))?;
            let hex_id = hex::encode(account_id.as_ref());
            let current_stake = stakes.get(&hex_id).copied().unwrap_or(0);
            if current_stake == target_stake {
                Ok(Some(()))
            } else {
                Ok(None)
            }
        },
    )
    .await
}
// --- FIX END ---

// Helper function to create a signed system transaction
fn create_system_tx(
    keypair: &Keypair,
    payload: SystemPayload,
    nonce: u64,
) -> Result<ChainTransaction> {
    let public_key_bytes = keypair.public().encode_protobuf();

    // Use the canonical function to derive the account ID
    let account_id_hash = account_id_from_key_material(SignatureSuite::Ed25519, &public_key_bytes)?;
    let account_id = AccountId(account_id_hash);

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
    Ok(ChainTransaction::System(Box::new(tx_to_sign)))
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
            // Grant initial stake only to the first validator (the bootnode) to ensure it's the sole
            // leader at genesis, allowing the chain to start without waiting for peers.
            let initial_stake = 100_000u64;
            let mut stakes = BTreeMap::new();
            let pk_bytes_0 = keys[0].public().encode_protobuf();
            let account_id_hash_0 =
                account_id_from_key_material(SignatureSuite::Ed25519, &pk_bytes_0).unwrap();
            stakes.insert(AccountId(account_id_hash_0), initial_stake);

            let stakes_bytes = codec::to_bytes_canonical(&stakes);
            let stakes_b64 = format!("b64:{}", BASE64_STANDARD.encode(&stakes_bytes));

            genesis["genesis_state"][std::str::from_utf8(STAKES_KEY_CURRENT).unwrap()] =
                json!(&stakes_b64);
            genesis["genesis_state"][std::str::from_utf8(STAKES_KEY_NEXT).unwrap()] =
                json!(&stakes_b64);

            // Populate the pubkey lookup map and ActiveKeyRecord for all keys
            for keypair in keys {
                let pk_bytes = keypair.public().encode_protobuf();
                let suite = SignatureSuite::Ed25519;
                let account_id_hash = account_id_from_key_material(suite, &pk_bytes).unwrap();
                let account_id = AccountId(account_id_hash);

                // Add the pubkey lookup entry
                let pubkey_map_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, account_id.as_ref()].concat();
                genesis["genesis_state"]
                    [format!("b64:{}", BASE64_STANDARD.encode(&pubkey_map_key))] =
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&pk_bytes)));

                // Add the ActiveKeyRecord entry for consensus
                let record = ActiveKeyRecord {
                    suite,
                    pubkey_hash: account_id_hash,
                    since_height: 0, // Active from genesis
                };
                let record_key = [b"identity::key_record::", account_id.as_ref()].concat();
                let record_bytes = codec::to_bytes_canonical(&record);
                genesis["genesis_state"][format!("b64:{}", BASE64_STANDARD.encode(&record_key))] =
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&record_bytes)));

                // Add IdentityHub credentials
                let cred = Credential {
                    suite,
                    public_key_hash: account_id.0,
                    activation_height: 0,
                    l2_location: None,
                };
                let creds_array: [Option<Credential>; 2] = [Some(cred), None];
                let creds_bytes = serde_json::to_vec(&creds_array).unwrap();
                let creds_key = [IDENTITY_CREDENTIALS_PREFIX, account_id.as_ref()].concat();
                genesis["genesis_state"][format!("b64:{}", BASE64_STANDARD.encode(&creds_key))] =
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&creds_bytes)));
            }
        })
        .build()
        .await?;

    // 3. GET HANDLES
    let (node0, node1, _node2) = {
        let mut it = cluster.validators.iter_mut();
        (it.next().unwrap(), it.next().unwrap(), it.next().unwrap())
    };
    let rpc_addr = &node0.rpc_addr;

    let ipc_addr0 = &node0.workload_ipc_addr;
    let client0 = depin_sdk_client::WorkloadClient::new(ipc_addr0).await?;
    let client1 = depin_sdk_client::WorkloadClient::new(&node1.workload_ipc_addr).await?;

    let node0_account_id = AccountId(account_id_from_key_material(
        SignatureSuite::Ed25519,
        &node0.keypair.public().encode_protobuf(),
    )?);
    let node1_account_id = AccountId(account_id_from_key_material(
        SignatureSuite::Ed25519,
        &node1.keypair.public().encode_protobuf(),
    )?);

    // 4. PRE-CONDITION: Wait for the chain to start and for the eventual leader (node-1) to be ready.
    // node-0 (bootnode) reaches H=1 first...
    wait_for_height(rpc_addr, 1, Duration::from_secs(20)).await?;
    // ...then ensure node-1 has also received block #1 before we rotate leadership to it.
    wait_for_height(&node1.rpc_addr, 1, Duration::from_secs(30)).await?;

    // 5. ACTION: Submit staking transactions via Node0's RPC.
    // Node 0 unstakes its full amount.
    let unstake_payload = SystemPayload::Unstake { amount: 100_000 };
    let unstake_tx = create_system_tx(&node0.keypair, unstake_payload, 0)?;
    submit_transaction(rpc_addr, &unstake_tx).await?;

    // Node 1 stakes a new amount.
    let stake_payload = SystemPayload::Stake {
        public_key: node1.keypair.public().encode_protobuf(),
        amount: 50_000,
    };
    let stake_tx = create_system_tx(&node1.keypair, stake_payload, 0)?;
    submit_transaction(rpc_addr, &stake_tx).await?;

    // 6. VERIFICATION: Wait two blocks for stake changes to become effective, then verify the state.
    // H=2 is produced with old stake set. H=3 is produced with new stake set.
    wait_for_height(rpc_addr, 3, Duration::from_secs(60)).await?;

    wait_for_stake_to_be(&client0, &node0_account_id, 0, Duration::from_secs(10)).await?;
    wait_for_stake_to_be(&client1, &node1_account_id, 50_000, Duration::from_secs(10)).await?;

    println!("--- Staking Lifecycle E2E Test Passed ---");
    Ok(())
}