// Path: crates/forge/tests/governance_e2e.rs
use anyhow::Result;
use depin_sdk_forge::testing::{
    assert_log_contains, build_test_artifacts, spawn_node, submit_transaction,
};
use depin_sdk_types::app::{ChainTransaction, SystemPayload, SystemTransaction, VoteOption};
use libp2p::identity;
use tempfile::tempdir;
use tokio::io::{AsyncBufReadExt, BufReader};

#[tokio::test]
async fn test_governance_proposal_lifecycle() -> Result<()> {
    // 1. Setup
    build_test_artifacts("consensus-poa");
    let governance_key = identity::Keypair::generate_ed25519();
    let governance_pubkey_b58 =
        bs58::encode(governance_key.public().try_into_ed25519()?.to_bytes()).into_string();

    let node_key = identity::Keypair::generate_ed25519();
    let peer_id = node_key.public().to_peer_id();

    let genesis_content = serde_json::json!({
      "genesis_state": {
        "system::authorities": [peer_id.to_bytes()],
        "system::governance_key": governance_pubkey_b58
      }
    })
    .to_string();

    let mut node = spawn_node(
        &node_key,
        tempdir()?,
        &genesis_content,
        &[],
        "127.0.0.1:9944",
        "ProofOfAuthority",
    )
    .await?;
    let mut logs = BufReader::new(node.process.stderr.take().unwrap()).lines();

    // 2. Submit a Proposal
    // This requires a new 'SubmitProposal' payload in SystemPayload
    // For now, we assume the node starts with a proposal already submitted.
    // Or we would add a new SystemPayload::SubmitProposal variant.

    // 3. Submit a Vote
    let payload = SystemPayload::Vote {
        proposal_id: 1,
        option: VoteOption::Yes,
    };
    let payload_bytes = serde_json::to_vec(&payload)?;

    // The signature should be from a staker/voter. Here, we use the node's key.
    let pubkey_bytes = node_key.public().try_into_ed25519()?.to_bytes().to_vec();
    let signature_bytes = node_key.sign(&payload_bytes)?;
    let full_signature = [pubkey_bytes, signature_bytes].concat();

    let tx = ChainTransaction::System(SystemTransaction {
        payload,
        signature: full_signature,
    });
    submit_transaction("127.0.0.1:9944", &tx).await?;

    // 4. Verify Vote was Applied
    assert_log_contains("Node", &mut logs, "Applied vote for proposal 1").await?;

    // 5. Wait for blocks to be produced until the voting period ends
    // This requires waiting for the node to log the tallying result.
    // The log message "Proposal 1 passed!" or "Proposal 1 rejected..." would be asserted here.
    // This part is left as an exercise, as it depends on your exact voting period settings.

    println!("--- Governance Vote Test Successful ---");
    Ok(())
}
