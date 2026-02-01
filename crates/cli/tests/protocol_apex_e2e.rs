// Path: crates/cli/tests/protocol_apex_e2e.rs

use ioi_cli::testing::cluster::TestCluster;
use ioi_cli::testing::rpc::get_status;
use ioi_types::app::{
    AccountId, BlockHeader, ProofOfDivergence, SignatureSuite, StateRoot, QuorumCertificate,
    // [FIX] Removed unused PanicMessage import
};
use libp2p::identity::Keypair;
use std::time::Duration;
use tokio::time::sleep;
// [FIX] Removed unused SigningKey import
use tokio::task;

// Helper to forge a divergence proof using a validator's key
fn forge_divergence(
    keypair: &Keypair, 
    account_id: AccountId,
    height: u64, 
    view: u64
) -> ProofOfDivergence {
    let ed_key = keypair.clone().try_into_ed25519().unwrap();
    let pubkey = ed_key.public().to_bytes().to_vec();

    // Create Header A
    let mut header_a = BlockHeader {
        height,
        view,
        parent_hash: [0u8; 32], 
        parent_state_root: StateRoot(vec![]),
        state_root: StateRoot(vec![0xAA; 32]), 
        transactions_root: vec![],
        timestamp: 1000,
        gas_used: 0,
        validator_set: vec![],
        producer_account_id: account_id,
        producer_key_suite: SignatureSuite::ED25519,
        producer_pubkey_hash: account_id.0,
        producer_pubkey: pubkey.clone(),
        signature: vec![],
        oracle_counter: 100, 
        oracle_trace_hash: [0u8; 32],
        parent_qc: QuorumCertificate::default(),
    };
    
    // Sign A
    let preimage_a = header_a.to_preimage_for_signing().unwrap();
    
    // Construct Oracle Payload for signature verification
    let hash_a = ioi_crypto::algorithms::hash::sha256(&preimage_a).unwrap();
    let mut payload_a = Vec::new();
    payload_a.extend_from_slice(&hash_a);
    payload_a.extend_from_slice(&100u64.to_be_bytes());
    payload_a.extend_from_slice(&[0u8; 32]);
    // [FIX] libp2p sign returns Vec<u8> directly, removed unwrap().to_bytes().
    header_a.signature = ed_key.sign(&payload_a);

    // Create Header B (Conflict)
    let mut header_b = header_a.clone();
    header_b.state_root = StateRoot(vec![0xBB; 32]); 
    
    // Sign B
    let preimage_b = header_b.to_preimage_for_signing().unwrap();
    let hash_b = ioi_crypto::algorithms::hash::sha256(&preimage_b).unwrap();
    let mut payload_b = Vec::new();
    payload_b.extend_from_slice(&hash_b);
    payload_b.extend_from_slice(&100u64.to_be_bytes()); 
    payload_b.extend_from_slice(&[0u8; 32]);
    // [FIX] libp2p sign returns Vec<u8> directly, removed unwrap().to_bytes().
    header_b.signature = ed_key.sign(&payload_b);

    ProofOfDivergence {
        offender: account_id,
        evidence_a: header_a,
        evidence_b: header_b,
    }
}

#[tokio::test]
async fn test_protocol_apex_lifecycle() {
    // 1. Setup Cluster
    let cluster = TestCluster::builder()
        .with_validators(4)
        .with_consensus_type("Admft")
        .build()
        .await
        .expect("Failed to build cluster");

    // Spawn background tasks to stream logs from all nodes
    for (i, guard) in cluster.validators.iter().enumerate() {
        let (mut orch_rx, mut work_rx, _) = guard.validator().subscribe_logs();
        
        task::spawn(async move {
            loop {
                tokio::select! {
                    Ok(line) = orch_rx.recv() => println!("[Node{}|ORCH] {}", i, line),
                    Ok(line) = work_rx.recv() => println!("[Node{}|WORK] {}", i, line),
                }
            }
        });
    }

    // Wait for startup
    sleep(Duration::from_secs(5)).await;
    
    // 2. Verify Normal Operation (Engine A)
    let client_0 = &cluster.validators[0];
    let status = get_status(&client_0.validator().rpc_addr).await.expect("RPC failed");
    assert!(status.is_running);
    println!("Initial Height: {}", status.height);

    // 3. The Attack (Inject Panic)
    println!("⚡ Constructing Hardware Equivocation Proof...");
    
    // We compromise Node 3's key
    let malicious_node = &cluster.validators[3];
    let mal_key = malicious_node.validator().keypair.clone();
    
    let pk = mal_key.public().encode_protobuf();
    let offender_id = AccountId(ioi_types::app::account_id_from_key_material(SignatureSuite::ED25519, &pk).unwrap());

    // Forge proof for a future height
    let target_height = status.height + 5;
    let proof = forge_divergence(&mal_key, offender_id, target_height, 0);
    
    // 4. Verify Proof Logic (Unit Test the Divergence Detector)
    use ioi_consensus::admft::divergence::verify_divergence_proof;
    
    let is_valid = verify_divergence_proof(&proof).expect("Verification failed");
    assert!(is_valid, "Forged divergence proof should be valid");
    
    println!("✅ Proof of Divergence verified successfully.");

    // 5. Shutdown
    cluster.shutdown().await.expect("Shutdown failed");
}