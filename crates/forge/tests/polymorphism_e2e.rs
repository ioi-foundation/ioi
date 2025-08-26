// Path: crates/forge/tests/polymorphism_e2e.rs

use anyhow::Result;
use depin_sdk_forge::testing::{
    assert_log_contains, build_test_artifacts, submit_transaction, TestCluster,
};
use depin_sdk_types::app::{
    ChainTransaction, SignHeader, SignatureProof, SystemPayload, SystemTransaction,
};
use libp2p::identity::Keypair;
use serde_json::json;

// Helper function to create a signed system transaction
fn create_system_tx(keypair: &Keypair, payload: SystemPayload) -> Result<ChainTransaction> {
    let mut tx_to_sign = SystemTransaction {
        header: SignHeader::default(),
        payload,
        signature_proof: SignatureProof::default(),
    };
    let sign_bytes = tx_to_sign.to_sign_bytes()?;
    let signature = keypair.sign(&sign_bytes)?;
    let public_key = keypair.public().encode_protobuf();

    tx_to_sign.signature_proof = SignatureProof {
        suite: Default::default(),
        public_key,
        signature,
    };
    Ok(ChainTransaction::System(tx_to_sign))
}

#[tokio::test]
async fn l1_polymorphism_e2e() -> Result<()> {
    // 1. SETUP & BUILD
    build_test_artifacts("consensus-poa,vm-wasm");

    // 2. CONFIGURE & LAUNCH CLUSTER
    let mut cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("ProofOfAuthority")
        .with_genesis_modifier(|genesis, keys| {
            let authority_peer_id = keys[0].public().to_peer_id();
            genesis["genesis_state"]["system::authorities"] = json!([authority_peer_id.to_bytes()]);
        })
        .build()
        .await?;

    let node = &mut cluster.validators[0];
    let rpc_addr = &node.rpc_addr;
    let mut orch_logs = node.orch_log_stream.lock().await.take().unwrap();

    // 3. SUBMIT A TRANSACTION to trigger block production
    let payload = SystemPayload::Stake { amount: 100 };
    let tx = create_system_tx(&node.keypair, payload)?;

    submit_transaction(rpc_addr, &tx).await?;

    // 4. ASSERT
    assert_log_contains(
        "Orchestration",
        &mut orch_logs,
        "Produced and processed new block #1",
    )
    .await?;

    println!("--- Polymorphism E2E Test Passed: StateManager is fully generic ---");

    Ok(())
}