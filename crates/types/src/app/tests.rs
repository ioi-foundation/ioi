use super::*;

fn sample_header() -> BlockHeader {
    BlockHeader {
        height: 7,
        view: 3,
        parent_hash: [1u8; 32],
        parent_state_root: StateRoot(vec![2u8; 32]),
        state_root: StateRoot(vec![3u8; 32]),
        transactions_root: vec![4u8; 32],
        timestamp: 123_456,
        timestamp_ms: 123_456_000,
        gas_used: 789,
        validator_set: vec![vec![5u8; 32], vec![6u8; 32]],
        producer_account_id: AccountId([7u8; 32]),
        producer_key_suite: SignatureSuite::ED25519,
        producer_pubkey_hash: [8u8; 32],
        producer_pubkey: vec![9u8; 32],
        oracle_counter: 0,
        oracle_trace_hash: [0u8; 32],
        guardian_certificate: None,
        sealed_finality_proof: None,
        canonical_order_certificate: None,
        timeout_certificate: None,
        parent_qc: QuorumCertificate::default(),
        previous_canonical_collapse_commitment_hash: [0u8; 32],
        canonical_collapse_extension_certificate: None,
        publication_frontier: None,
        signature: vec![],
    }
}

#[test]
fn block_header_hash_is_stable_across_post_finalize_enrichment() {
    let mut header = sample_header();
    let before = header.hash().expect("hash before enrichment");

    header.signature = vec![1, 2, 3];
    header.oracle_counter = 42;
    header.oracle_trace_hash = [11u8; 32];

    let after = header.hash().expect("hash after enrichment");
    assert_eq!(before, after);
}
