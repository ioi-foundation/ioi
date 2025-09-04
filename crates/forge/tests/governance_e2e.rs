// Path: crates/forge/tests/governance_e2e.rs

#![cfg(all(feature = "consensus-poa", feature = "vm-wasm"))]

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use depin_sdk_forge::testing::{
    assert_log_contains, build_test_artifacts, poll::wait_for_proposal_status, submit_transaction,
    TestCluster,
};
use depin_sdk_types::app::{
    account_id_from_key_material, AccountId, ActiveKeyRecord, ChainTransaction, Credential,
    Proposal, ProposalStatus, ProposalType, SignHeader, SignatureProof, SignatureSuite,
    SystemPayload, SystemTransaction, VoteOption,
};
use depin_sdk_types::codec;
use depin_sdk_types::config::InitialServiceConfig;
use depin_sdk_types::keys::{
    ACCOUNT_ID_TO_PUBKEY_PREFIX, AUTHORITY_SET_KEY, GOVERNANCE_KEY, GOVERNANCE_PROPOSAL_KEY_PREFIX,
    IDENTITY_CREDENTIALS_PREFIX, STAKES_KEY_CURRENT, STAKES_KEY_NEXT,
};
use depin_sdk_types::service_configs::MigrationConfig;
use libp2p::identity::{self, Keypair};
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
    Ok(ChainTransaction::System(Box::new(tx_to_sign)))
}

#[tokio::test]
async fn test_governance_proposal_lifecycle_with_tallying() -> Result<()> {
    // 1. SETUP: Build artifacts and define keypairs
    build_test_artifacts("consensus-poa,vm-wasm,tree-file,primitive-hash");
    let governance_key = identity::Keypair::generate_ed25519();
    let governance_pubkey_b58 =
        bs58::encode(governance_key.public().try_into_ed25519()?.to_bytes()).into_string();

    let governance_key_clone = governance_key.clone();

    // 2. LAUNCH CLUSTER with a custom genesis state
    let mut cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("ProofOfAuthority")
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            chain_id: 1,
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
        }))
        .with_genesis_modifier(move |genesis, keys| {
            let validator_key = &keys[0];
            let suite = SignatureSuite::Ed25519;
            let validator_pk_bytes = validator_key.public().encode_protobuf();
            let validator_account_id_hash =
                account_id_from_key_material(suite, &validator_pk_bytes).unwrap();
            let validator_account_id = AccountId(validator_account_id_hash);

            // A. Set the validator as the authority using AccountId
            let authorities = vec![validator_account_id];
            let authorities_bytes = codec::to_bytes_canonical(&authorities);
            genesis["genesis_state"][std::str::from_utf8(AUTHORITY_SET_KEY).unwrap()] =
                json!(format!("b64:{}", BASE64_STANDARD.encode(authorities_bytes)));

            // B. Set the governance key
            genesis["genesis_state"][std::str::from_utf8(GOVERNANCE_KEY).unwrap()] =
                json!(governance_pubkey_b58);

            // C. Give the validator some stake so their vote has power
            let mut stakes = BTreeMap::new();
            stakes.insert(validator_account_id, 1_000_000u64);
            let stakes_bytes = codec::to_bytes_canonical(&stakes);
            let stakes_b64 = format!("b64:{}", BASE64_STANDARD.encode(stakes_bytes));
            let stakes_key_current_str = std::str::from_utf8(STAKES_KEY_CURRENT).unwrap();
            let stakes_key_next_str = std::str::from_utf8(STAKES_KEY_NEXT).unwrap();
            genesis["genesis_state"][stakes_key_current_str] = json!(stakes_b64.clone());
            genesis["genesis_state"][stakes_key_next_str] = json!(stakes_b64);

            // D. Create a pre-funded proposal that will end soon
            let proposal = Proposal {
                id: 1,
                title: "Test Proposal".to_string(),
                description: "This proposal should pass.".to_string(),
                proposal_type: ProposalType::Text,
                status: ProposalStatus::VotingPeriod,
                submitter: vec![1, 2, 3],
                submit_height: 0,
                deposit_end_height: 0,
                voting_start_height: 1,
                voting_end_height: 3, // Voting ends after block 3
                total_deposit: 10000,
                final_tally: None,
            };
            let proposal_key_bytes = [GOVERNANCE_PROPOSAL_KEY_PREFIX, &1u64.to_le_bytes()].concat();
            let proposal_key_b64 = format!("b64:{}", BASE64_STANDARD.encode(&proposal_key_bytes));
            let proposal_bytes = serde_json::to_vec(&proposal).unwrap();
            genesis["genesis_state"][proposal_key_b64] =
                json!(format!("b64:{}", BASE64_STANDARD.encode(proposal_bytes)));

            // E. Set up identity records needed for signature validation
            for (key, acct_id) in [
                (validator_key, validator_account_id),
                (
                    &governance_key_clone,
                    AccountId(
                        account_id_from_key_material(
                            suite,
                            &governance_key_clone.public().encode_protobuf(),
                        )
                        .unwrap(),
                    ),
                ),
            ] {
                let pk_bytes = key.public().encode_protobuf();
                let cred = Credential {
                    suite,
                    public_key_hash: acct_id.0,
                    activation_height: 0,
                    l2_location: None,
                };
                let creds_array: [Option<Credential>; 2] = [Some(cred), None];
                let creds_bytes = serde_json::to_vec(&creds_array).unwrap();
                let creds_key = [IDENTITY_CREDENTIALS_PREFIX, acct_id.as_ref()].concat();
                genesis["genesis_state"][format!("b64:{}", BASE64_STANDARD.encode(&creds_key))] =
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&creds_bytes)));

                let pubkey_map_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, acct_id.as_ref()].concat();
                genesis["genesis_state"]
                    [format!("b64:{}", BASE64_STANDARD.encode(&pubkey_map_key))] =
                    json!(format!("b64:{}", BASE64_STANDARD.encode(&pk_bytes)));

                let record = ActiveKeyRecord {
                    suite,
                    pubkey_hash: acct_id.0,
                    since_height: 0,
                };
                let record_key = [b"identity::key_record::", acct_id.as_ref()].concat();
                genesis["genesis_state"][format!("b64:{}", BASE64_STANDARD.encode(&record_key))] =
                    json!(format!(
                        "b64:{}",
                        BASE64_STANDARD.encode(codec::to_bytes_canonical(&record))
                    ));
            }
        })
        .build()
        .await?;

    // 3. GET HANDLES to the node and its logs
    let node = &mut cluster.validators[0];
    let rpc_addr = &node.rpc_addr;
    let validator_key = &node.keypair;
    let mut orch_logs = node.orch_log_stream.lock().await.take().unwrap();

    // 4. SUBMIT a VOTE from the validator
    let payload = SystemPayload::Vote {
        proposal_id: 1,
        option: VoteOption::Yes,
    };
    // Use nonce 0 for the validator's first transaction
    let tx = create_system_tx(validator_key, payload, 0)?;
    submit_transaction(rpc_addr, &tx).await?;

    // 5. ASSERT the vote was accepted & gossiped (confirms the transaction part of the flow)
    assert_log_contains(
        "Orchestration",
        &mut orch_logs,
        "[RPC] Published transaction via gossip.",
    )
    .await?;

    // 6. WAIT AND ASSERT the tallying outcome using state polling
    wait_for_proposal_status(rpc_addr, 1, ProposalStatus::Passed, Duration::from_secs(30)).await?;

    println!("--- Governance Lifecycle E2E Test Successful ---");
    Ok(())
}
