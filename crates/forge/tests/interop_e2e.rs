// Path: crates/forge/tests/interop_e2e.rs

#![cfg(all(
    feature = "consensus-poa",
    feature = "vm-wasm",
    feature = "tree-file",
    feature = "primitive-hash"
))]

use anyhow::Result;
use depin_sdk_api::commitment::SchemeIdentifier;
use depin_sdk_api::ibc::{
    BlockAnchor, DigestAlgo, FinalityEvidence, KeyCodec, MembershipWitness, ProofTarget,
    UniversalExecutionReceipt, UniversalProofFormat,
};
use depin_sdk_forge::testing::{
    assert_log_contains, build_test_artifacts, submit_transaction, TestCluster,
};
use depin_sdk_types::app::{ChainTransaction, SystemPayload, SystemTransaction};
use serde_json::json;
// FIX: Use dcrypt's Blake3 XOF for hashing.
use dcrypt::algorithms::xof::Blake3Xof;

#[tokio::test]
async fn test_universal_verification_e2e() -> Result<()> {
    // 1. SETUP & BUILD
    build_test_artifacts("consensus-poa,vm-wasm,tree-file,primitive-hash");

    // 2. LAUNCH CLUSTER
    let mut cluster = TestCluster::builder()
        .with_validators(1)
        .with_genesis_modifier(|genesis, keys| {
            let authority = keys[0].public().to_peer_id().to_bytes();
            genesis["genesis_state"]["system::authorities"] = json!([authority]);
        })
        .build()
        .await?;

    let node = &mut cluster.validators[0];
    let rpc_addr = &node.rpc_addr;
    let mut workload_logs = node.workload_log_stream.lock().await.take().unwrap();
    // FIX: Get the orchestration logs to check for the replay failure.
    let mut orch_logs = node.orch_log_stream.lock().await.take().unwrap();

    // 3. CONSTRUCT MOCK FOREIGN RECEIPT & PROOF
    let mock_anchor = BlockAnchor {
        block_hash: [1; 32],
        block_number: 1000000,
        state_root: [2; 32],
        receipts_root: [3; 32],
        transactions_root: [4; 32],
    };
    let mock_witness = MembershipWitness {
        key_preimage: 1u32.to_be_bytes().to_vec(), // Preimage for txIndex=1
        key_codec: KeyCodec::RlpScalar,
        value: b"mock_rlp_encoded_receipt_data".to_vec(),
    };

    // Calculate unique ID and CEM hash before constructing the receipt
    let unique_leaf_id = Blake3Xof::generate(b"eth-mainnet/block1000000/log/tx1/log0", 32)?;
    // FIX: Correct the relative path and use dcrypt's Blake3Xof.
    let cem_bytes = include_str!("../../services/src/ibc/src/endpoints/cem.json").as_bytes();
    let cem_hash: [u8; 32] = Blake3Xof::generate(cem_bytes, 32)?.try_into().unwrap();

    let mock_receipt = UniversalExecutionReceipt {
        source_chain_id: "eth-mainnet".to_string(),
        anchor: mock_anchor,
        target: ProofTarget::Log {
            tx_index: 1,
            log_index: 0,
        },
        finality: Some(FinalityEvidence::TrustedCheckpoint {
            checkpoint_id: "test-ckpt".into(),
            sigs: vec![1, 2, 3],
        }),
        unique_leaf_id,
        endpoint_id: "token.transfer@1.0".to_string(),
        params_jcs: serde_jcs::to_vec(&json!({"from": "0xaaa", "to": "0xbbb", "amount": "100"}))?,
        result_digest: [5; 32],
        result_digest_algo: DigestAlgo::Sha256,
        cem_hash,
    };

    let mock_proof = UniversalProofFormat {
        scheme_id: SchemeIdentifier("eth-mpt-keccak256".to_string()),
        proof_data: b"mock_mpt_proof_data".to_vec(),
        witness: mock_witness,
    };

    // 4. SUBMIT THE VERIFICATION TRANSACTION
    let payload = SystemPayload::VerifyForeignReceipt {
        receipt: mock_receipt.clone(),
        proof: mock_proof.clone(),
    };
    // --- FIX START: Use the correct struct definition ---
    let tx = ChainTransaction::System(SystemTransaction {
        payload,
        header: Default::default(),
        signature_proof: Default::default(),
    });
    // --- FIX END ---
    submit_transaction(rpc_addr, &tx).await?;

    // 5. ASSERT SUCCESS
    assert_log_contains(
        "Workload",
        &mut workload_logs,
        "Foreign receipt processed successfully. Emitting local event for endpoint: token.transfer@1.0",
    ).await?;

    // 6. TEST ANTI-REPLAY
    // Submit the same transaction again. The RPC call will succeed because it only adds to the mempool.
    let replay_result = submit_transaction(rpc_addr, &tx).await;
    assert!(
        replay_result.is_ok(),
        "Submitting a replay transaction to the mempool should succeed initially"
    );

    // Now, assert that when the node tries to process the block containing the replay, it fails.
    // This error is logged by the Orchestration container, which coordinates block processing.
    assert_log_contains(
        "Orchestration",
        &mut orch_logs,
        "Workload failed to process new block: Transaction processing error: Invalid transaction: Foreign receipt has already been processed (replay attack)",
    ).await?;

    println!("--- Universal Interoperability E2E Test Passed ---");
    Ok(())
}
