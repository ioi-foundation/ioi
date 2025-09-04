// Path: crates/forge/tests/state_verkle_e2e.rs
#![cfg(all(
    feature = "consensus-poa",
    feature = "vm-wasm",
    feature = "tree-verkle",
    feature = "primitive-kzg"
))]

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use depin_sdk_forge::testing::{
    build_test_artifacts,
    poll::{wait_for_height, wait_for_stake_to_be}, // Use the correct polling helper name
    submit_transaction,
    TestCluster,
};
use depin_sdk_types::{
    app::{
        account_id_from_key_material, AccountId, ActiveKeyRecord, ChainTransaction, Credential,
        SignHeader, SignatureProof, SignatureSuite, SystemPayload, SystemTransaction,
    },
    codec,
    config::InitialServiceConfig,
    keys::{
        ACCOUNT_ID_TO_PUBKEY_PREFIX, AUTHORITY_SET_KEY, IDENTITY_CREDENTIALS_PREFIX,
        STAKES_KEY_NEXT,
    },
    service_configs::MigrationConfig,
};
use libp2p::identity::Keypair;
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;

// Helper function to create a signed system transaction
fn create_system_tx(
    keypair: &Keypair,
    payload: SystemPayload,
    nonce: u64,
) -> Result<ChainTransaction> {
    let public_key_bytes = keypair.public().encode_protobuf();
    let account_id_hash = account_id_from_key_material(SignatureSuite::Ed25519, &public_key_bytes)?;
    let account_id = AccountId(account_id_hash);

    let header = SignHeader {
        account_id,
        nonce,
        chain_id: 1, // Default chain_id for tests
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

#[tokio::test]
async fn test_verkle_tree_e2e() -> Result<()> {
    // 1. Build binaries with the specific Verkle feature enabled
    build_test_artifacts("consensus-poa,vm-wasm,tree-verkle,primitive-kzg");

    // 2. Launch a cluster configured to use the VerkleTree
    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("ProofOfAuthority")
        .with_state_tree("Verkle")
        .with_commitment_scheme("KZG")
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
            chain_id: 1,
        }))
        .with_genesis_modifier(|genesis, keys| {
            let suite = SignatureSuite::Ed25519;
            let pk = keys[0].public().encode_protobuf();
            let acct_hash = account_id_from_key_material(suite, &pk).unwrap();
            let acct = AccountId(acct_hash);

            // PoA authority set
            let auth_bytes = codec::to_bytes_canonical(&vec![acct]);
            genesis["genesis_state"][std::str::from_utf8(AUTHORITY_SET_KEY).unwrap()] =
                json!(format!("b64:{}", BASE64_STANDARD.encode(&auth_bytes)));

            // ActiveKeyRecord for consensus verification
            let record = ActiveKeyRecord {
                suite,
                pubkey_hash: acct.0,
                since_height: 0,
            };
            let record_key = [b"identity::key_record::", acct.as_ref()].concat();
            let record_bytes = codec::to_bytes_canonical(&record);
            genesis["genesis_state"][format!("b64:{}", BASE64_STANDARD.encode(&record_key))] =
                json!(format!("b64:{}", BASE64_STANDARD.encode(&record_bytes)));

            // AccountId -> PubKey map for consensus verification
            let map_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, acct.as_ref()].concat();
            genesis["genesis_state"][format!("b64:{}", BASE64_STANDARD.encode(&map_key))] =
                json!(format!("b64:{}", BASE64_STANDARD.encode(&pk)));

            // Initial credentials for the IdentityHub
            let initial_cred = Credential {
                suite,
                public_key_hash: acct_hash,
                activation_height: 0,
                l2_location: None,
            };
            let creds_array: [Option<Credential>; 2] = [Some(initial_cred), None];
            let creds_bytes = serde_json::to_vec(&creds_array).unwrap();
            let creds_key = [IDENTITY_CREDENTIALS_PREFIX, acct.as_ref()].concat();
            genesis["genesis_state"][format!("b64:{}", BASE64_STANDARD.encode(&creds_key))] =
                json!(format!("b64:{}", BASE64_STANDARD.encode(&creds_bytes)));

            // Initial empty stakes map
            let empty_stakes: BTreeMap<AccountId, u64> = BTreeMap::new();
            let empty_stakes_bytes = codec::to_bytes_canonical(&empty_stakes);
            genesis["genesis_state"][std::str::from_utf8(STAKES_KEY_NEXT).unwrap()] = json!(
                format!("b64:{}", BASE64_STANDARD.encode(&empty_stakes_bytes))
            );
        })
        .build()
        .await?;

    // 3. Get handles and wait for node to be ready
    let node = &cluster.validators[0];
    let rpc_addr = &node.rpc_addr;

    println!("--- Verkle Node Launched ---");

    // 1. Wait for the node to be live and produce its first block.
    wait_for_height(rpc_addr, 1, Duration::from_secs(20)).await?;
    println!("--- Bootstrap Block #1 Processed ---");

    // 2. Submit the stake transaction.
    let stake_amount = 100u64;
    let staker_account_id = AccountId(account_id_from_key_material(
        SignatureSuite::Ed25519,
        &node.keypair.public().encode_protobuf(),
    )?);
    let payload = SystemPayload::Stake {
        public_key: node.keypair.public().encode_protobuf(),
        amount: stake_amount,
    };
    let tx = create_system_tx(&node.keypair, payload, 0)?;
    submit_transaction(rpc_addr, &tx).await?;
    println!("--- Submitted Stake Transaction ---");

    // 3. Poll the state directly until the stake appears and is correct.
    wait_for_stake_to_be(
        rpc_addr,
        &staker_account_id,
        stake_amount,
        Duration::from_secs(20),
    )
    .await?;

    // 4. Assert the final state is correct (wait_for_stake_to_be already does this).
    println!(
        "--- State Verification Passed: Found correct stake of {} for validator ---",
        stake_amount
    );

    println!("--- Verkle Tree E2E Test Passed ---");
    Ok(())
}
