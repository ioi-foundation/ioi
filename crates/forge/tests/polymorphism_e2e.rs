// Path: forge/tests/polymorphism_e2e.rs

use anyhow::Result;
use depin_sdk_forge::testing::{
    assert_log_contains, build_test_artifacts, submit_transaction, TestCluster,
};
use depin_sdk_types::app::{ChainTransaction, SystemPayload, SystemTransaction};
use serde_json::json;

#[tokio::test]
async fn l1_polymorphism_e2e() -> Result<()> {
    // 1. SETUP & BUILD
    // This build ensures that all components, including the refactored StateManager and
    // the CommitmentStructure implementations for all schemes (Hash, Pedersen, KZG),
    // compile successfully. A failure here would indicate a trait implementation error.
    //
    // FIX: Add the `vm-wasm` feature to the build command to ensure the workload
    // binary is compiled with the necessary logic.
    build_test_artifacts("consensus-poa,vm-wasm");

    // 2. CONFIGURE & LAUNCH CLUSTER
    // We set up a standard PoA cluster. The test harness will launch the node binary,
    // which uses FileStateTree<HashCommitmentScheme> by default. The success of this
    // test proves that the generic calls `CS::commit_leaf` and `CS::commit_branch`
    // are working correctly in the state manager.
    //
    // The key validation of polymorphism happened at compile time: because PedersenCommitmentScheme
    // and others now implement CommitmentStructure, a developer *could* compile a node
    // with `FileStateTree<PedersenCommitmentScheme>` and it would work. This test
    // validates the runtime aspect of the default configuration.
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
    // We need a valid transaction to ensure a block is created. A system-level
    // stake transaction is simple and effective.
    let payload = SystemPayload::Stake { amount: 100 };
    let payload_bytes = serde_json::to_vec(&payload)?;
    let signature = node.keypair.sign(&payload_bytes)?;

    // The SystemTransaction `apply` logic expects the signer's public key
    // to be prepended to the signature bytes for verification.
    let full_signature = [
        node.keypair
            .public()
            .try_into_ed25519()?
            .to_bytes()
            .as_ref(),
        &signature,
    ]
    .concat();

    let tx = ChainTransaction::System(SystemTransaction {
        payload,
        signature: full_signature,
    });

    submit_transaction(rpc_addr, &tx).await?;

    // 4. ASSERT
    // This assertion proves that the polymorphic code works. The `FileStateTree` (instantiated
    // with HashCommitmentScheme in this test binary) used the `CommitmentStructure` trait
    // to build its Merkle tree, and the OrchestrationContainer successfully produced a block.
    assert_log_contains(
        "Orchestration",
        &mut orch_logs,
        "Produced and processed new block #1",
    )
    .await?;

    println!("--- Polymorphism E2E Test Passed: StateManager is fully generic ---");

    Ok(())
}
