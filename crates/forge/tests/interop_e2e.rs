// Path: crates/forge/tests/interop_e2e.rs

#![cfg(all(
    feature = "consensus-poa",
    feature = "vm-wasm",
    feature = "tree-file",
    feature = "primitive-hash"
))]

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use dcrypt::algorithms::xof::Blake3Xof;
use depin_sdk_api::commitment::SchemeIdentifier;
use depin_sdk_api::ibc::{
    BlockAnchor, DigestAlgo, FinalityEvidence, KeyCodec, MembershipWitness, ProofTarget,
    UniversalExecutionReceipt, UniversalProofFormat,
};
use depin_sdk_forge::testing::{
    assert_log_contains, build_test_artifacts, submit_transaction, TestCluster,
};
use depin_sdk_types::{
    app::{
        account_id_from_key_material, ChainTransaction, Credential, SignHeader, SignatureProof,
        SignatureSuite, SystemPayload, SystemTransaction,
    },
    config::InitialServiceConfig,
    keys::IDENTITY_CREDENTIALS_PREFIX,
    service_configs::MigrationConfig,
};
use libp2p::identity::Keypair;
use serde_json::json;

// Helper to create a signed system transaction with a specific nonce
fn create_signed_system_tx(
    keypair: &Keypair,
    payload: SystemPayload,
    nonce: u64,
) -> Result<ChainTransaction> {
    let public_key = keypair.public().encode_protobuf();
    let account_id_hash = account_id_from_key_material(SignatureSuite::Ed25519, &public_key)?;
    let account_id = depin_sdk_types::app::AccountId(account_id_hash);

    let header = SignHeader {
        account_id,
        nonce,
        chain_id: 1, // Must match the chain's config
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
        public_key,
        signature,
    };
    Ok(ChainTransaction::System(tx_to_sign))
}

#[tokio::test]
async fn test_universal_verification_e2e() -> Result<()> {
    // 1. SETUP & BUILD
    build_test_artifacts("consensus-poa,vm-wasm,tree-file,primitive-hash");

    // 2. LAUNCH CLUSTER
    let mut cluster = TestCluster::builder()
        .with_validators(1)
        .with_initial_service(InitialServiceConfig::IdentityHub(MigrationConfig {
            grace_period_blocks: 5,
            accept_staged_during_grace: true,
            allowed_target_suites: vec![SignatureSuite::Ed25519],
            allow_downgrade: false,
            chain_id: 1,
        }))
        .with_genesis_modifier(|genesis, keys| {
            let keypair = &keys[0];
            let authority = keypair.public().to_peer_id().to_bytes();
            genesis["genesis_state"]["system::authorities"] = json!([authority]);

            let public_key_bytes = keypair.public().encode_protobuf();
            let public_key_hash =
                account_id_from_key_material(SignatureSuite::Ed25519, &public_key_bytes).unwrap();
            let account_id = depin_sdk_types::app::AccountId(public_key_hash);

            let initial_cred = Credential {
                suite: SignatureSuite::Ed25519,
                public_key_hash,
                activation_height: 0,
                l2_location: None,
            };

            let creds_array: [Option<Credential>; 2] = [Some(initial_cred), None];
            let creds_bytes = serde_json::to_vec(&creds_array).unwrap();
            let creds_key = [IDENTITY_CREDENTIALS_PREFIX, account_id.as_ref()].concat();
            let creds_key_b64 = format!("b64:{}", BASE64_STANDARD.encode(&creds_key));
            genesis["genesis_state"][creds_key_b64] =
                json!(format!("b64:{}", BASE64_STANDARD.encode(&creds_bytes)));
        })
        .build()
        .await?;

    let node = &mut cluster.validators[0];
    let rpc_addr = &node.rpc_addr;
    let keypair = &node.keypair;
    let mut workload_logs = node.workload_log_stream.lock().await.take().unwrap();
    let mut orch_logs = node.orch_log_stream.lock().await.take().unwrap();
    let mut nonce = 0;

    // 3. CONSTRUCT MOCK FOREIGN RECEIPT & PROOF
    let mock_anchor = BlockAnchor {
        block_hash: [1; 32],
        block_number: 1000000,
        state_root: [2; 32],
        receipts_root: [3; 32],
        transactions_root: [4; 32],
    };
    let mock_witness = MembershipWitness {
        key_preimage: 1u32.to_be_bytes().to_vec(),
        key_codec: KeyCodec::RlpScalar,
        value: b"mock_rlp_encoded_receipt_data".to_vec(),
    };

    let unique_leaf_id = Blake3Xof::generate(b"eth-mainnet/block1000000/log/tx1/log0", 32)?;
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
    let tx = create_signed_system_tx(keypair, payload.clone(), nonce)?;
    submit_transaction(rpc_addr, &tx).await?;
    nonce += 1;

    // 5. ASSERT SUCCESS
    assert_log_contains(
        "Workload",
        &mut workload_logs,
        "Foreign receipt processed successfully. Emitting local event for endpoint: token.transfer@1.0",
    ).await?;

    // 6. TEST ANTI-REPLAY
    let replay_tx = create_signed_system_tx(keypair, payload, nonce)?;
    submit_transaction(rpc_addr, &replay_tx).await?;

    assert_log_contains(
        "Orchestration",
        &mut orch_logs,
        "Workload failed to process new block: Transaction processing error: Invalid transaction: Foreign receipt has already been processed (replay attack)",
    ).await?;

    println!("--- Universal Interoperability E2E Test Passed ---");
    Ok(())
}
