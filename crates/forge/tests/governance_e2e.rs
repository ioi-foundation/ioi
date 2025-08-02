// Path: crates/forge/tests/governance_e2e.rs
use anyhow::{anyhow, Result};
use depin_sdk_core::app::{ProtocolTransaction, SystemPayload, SystemTransaction};
use depin_sdk_forge::testing::{
    assert_log_contains, build_node_binary, spawn_node, submit_transaction,
};
use libp2p::identity;
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::time::timeout;

#[tokio::test]
#[ignore]
async fn test_governance_authority_change_lifecycle() -> Result<()> {
    println!("--- Building Node Binary for Governance Test ---");
    build_node_binary("consensus-poa,vm-wasm");

    // Identities and Genesis setup...
    let key_node1 = identity::Keypair::generate_ed25519();
    let peer_id_node1 = key_node1.public().to_peer_id();
    let key_node2 = identity::Keypair::generate_ed25519();
    let peer_id_node2 = key_node2.public().to_peer_id();
    let key_node3 = identity::Keypair::generate_ed25519();
    let peer_id_node3 = key_node3.public().to_peer_id();
    let governance_keypair = identity::Keypair::generate_ed25519();
    let governance_pubkey_bytes = governance_keypair
        .public()
        .try_into_ed25519()?
        .to_bytes()
        .to_vec();

    let genesis_content = serde_json::json!({
      "genesis_state": {
        "system::authorities": [peer_id_node1.to_base58(), peer_id_node2.to_base58()],
        "system::governance_key": bs58::encode(&governance_pubkey_bytes).into_string()
      }
    });
    let genesis_string = genesis_content.to_string();

    // Spawn nodes using the forge helper...
    println!("--- Launching 3-Node Cluster ---");
    let mut node1 = spawn_node(
        &key_node1,
        tempdir()?,
        &genesis_string,
        &["--listen-address", "/ip4/127.0.0.1/tcp/4001"],
        "127.0.0.1:9944",
        "ProofOfAuthority",
    )
    .await?;

    let bootnode_addr = format!("/ip4/127.0.0.1/tcp/4001/p2p/{}", peer_id_node1);

    let mut node2 = spawn_node(
        &key_node2,
        tempdir()?,
        &genesis_string,
        &[
            "--listen-address",
            "/ip4/127.0.0.1/tcp/4002",
            "--peer",
            &bootnode_addr,
        ],
        "127.0.0.1:9945",
        "ProofOfAuthority",
    )
    .await?;

    let mut node3 = spawn_node(
        &key_node3,
        tempdir()?,
        &genesis_string,
        &[
            "--listen-address",
            "/ip4/127.0.0.1/tcp/4003",
            "--peer",
            &bootnode_addr,
        ],
        "127.0.0.1:9946",
        "ProofOfAuthority",
    )
    .await?;

    // Setup log streams...
    let mut logs1 = BufReader::new(node1.process.stderr.take().unwrap()).lines();
    let mut logs2 = BufReader::new(node2.process.stderr.take().unwrap()).lines();
    let mut logs3 = BufReader::new(node3.process.stderr.take().unwrap()).lines();

    // Phase 1: Verify Initial State...
    println!("--- Phase 1: Verifying Initial State ---");
    assert_log_contains("Node1", &mut logs1, "Consensus decision: Produce block").await?;
    assert_log_contains("Node2", &mut logs2, "Consensus decision: Produce block").await?;

    // Phase 2: Submit Governance Transaction...
    println!("--- Phase 2: Submitting Governance Transaction ---");
    let payload = SystemPayload::UpdateAuthorities {
        new_authorities: vec![peer_id_node1.to_bytes(), peer_id_node3.to_bytes()],
    };
    let payload_bytes = serde_json::to_vec(&payload)?;
    let signature = governance_keypair.sign(&payload_bytes)?;
    let tx = ProtocolTransaction::System(SystemTransaction { payload, signature });
    submit_transaction("127.0.0.1:9944", &tx).await?;

    // Phase 3: Verify New State...
    println!("--- Phase 3: Verifying New State ---");
    assert_log_contains("Node3", &mut logs3, "Successfully updated authority set").await?;
    assert_log_contains("Node2", &mut logs2, "Successfully updated authority set").await?;
    assert_log_contains("Node3", &mut logs3, "Consensus decision: Produce block").await?;

    let res = timeout(
        Duration::from_secs(20),
        assert_log_contains("Node2", &mut logs2, "Consensus decision: Produce block"),
    )
    .await;
    if res.is_ok() {
        return Err(anyhow!(
            "Node 2 unexpectedly produced a block after being removed."
        ));
    }

    println!("--- Test finished. Cleaning up. ---");
    Ok(())
}
