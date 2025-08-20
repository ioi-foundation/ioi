// crates/forge/tests/governance_e2e.rs

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use depin_sdk_forge::testing::{
    assert_log_contains, build_test_artifacts, submit_transaction, TestCluster,
};
use depin_sdk_services::governance::{Proposal, ProposalStatus, ProposalType};
use depin_sdk_types::app::{ChainTransaction, SystemPayload, SystemTransaction, VoteOption};
use depin_sdk_types::keys::{GOVERNANCE_PROPOSAL_KEY_PREFIX, STAKES_KEY_CURRENT, STAKES_KEY_NEXT};
use libp2p::identity;
use serde_json::json;
use std::collections::BTreeMap;

#[tokio::test]
async fn test_governance_proposal_lifecycle_with_tallying() -> Result<()> {
    // 1. SETUP: Build artifacts and define keypairs
    build_test_artifacts("consensus-poa,vm-wasm");
    let governance_key = identity::Keypair::generate_ed25519();
    let governance_pubkey_b58 =
        bs58::encode(governance_key.public().try_into_ed25519()?.to_bytes()).into_string();

    // 2. LAUNCH CLUSTER with a custom genesis state
    let mut cluster = TestCluster::new()
        .with_validators(1)
        .with_consensus_type("ProofOfAuthority")
        .with_genesis_modifier(move |genesis, keys| {
            let validator_key = &keys[0];
            let validator_peer_id = validator_key.public().to_peer_id();

            // A. Set the validator as the authority
            genesis["genesis_state"]["system::authorities"] = json!([validator_peer_id.to_bytes()]);

            // B. Set the governance key
            genesis["genesis_state"]["system::governance_key"] = json!(governance_pubkey_b58);

            // C. Give the validator some stake so their vote has power
            let mut stakes = BTreeMap::new();
            stakes.insert(validator_peer_id.to_base58(), 1_000_000u64);
            let stakes_bytes = serde_json::to_vec(&stakes).unwrap();
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
                status: ProposalStatus::VotingPeriod, // Start it in the voting period
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
    let payload_bytes = serde_json::to_vec(&payload)?;

    let pubkey_bytes = validator_key
        .public()
        .try_into_ed25519()?
        .to_bytes()
        .to_vec();
    let signature_bytes = validator_key.sign(&payload_bytes)?;
    let full_signature = [pubkey_bytes, signature_bytes].concat();

    let tx = ChainTransaction::System(SystemTransaction {
        payload,
        signature: full_signature,
    });
    submit_transaction(rpc_addr, &tx).await?;

    // *** START FIX: Align assertion with actual node logs ***
    // 5. ASSERT the vote was accepted & gossiped (confirms the transaction part of the flow)
    assert_log_contains(
        "Orchestration",
        &mut orch_logs,
        "[RPC] Published transaction via gossip.",
    )
    .await?;
    // *** END FIX ***

    // 6. WAIT AND ASSERT the tallying outcome
    assert_log_contains(
        "Orchestration",
        &mut orch_logs,
        "Proposal 1 tallied: Passed",
    )
    .await?;

    println!("--- Governance Lifecycle E2E Test Successful ---");
    Ok(())
}
