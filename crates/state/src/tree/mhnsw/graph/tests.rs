use super::*;
use crate::tree::mhnsw::metric::{Euclidean, Vector};

fn sample_graph() -> HnswGraph<Euclidean> {
    let mut graph = HnswGraph::new(Euclidean, 8, 32);
    for i in 0..24u32 {
        let vector = Vector(vec![i as f32, (i % 3) as f32, (i % 5) as f32]);
        let payload = format!("frame-{i}").into_bytes();
        graph
            .insert(vector, payload)
            .expect("inserting fixture vectors should succeed");
    }
    graph
}

fn policy(k: u32, ef_search: u32, candidate_limit: u32) -> RetrievalSearchPolicy {
    RetrievalSearchPolicy {
        k,
        ef_search,
        candidate_limit,
        distance_metric: "euclidean".to_string(),
        embedding_normalized: false,
    }
}

#[test]
fn traversal_proof_roundtrip_verifies() {
    let graph = sample_graph();
    let query = Vector(vec![11.2, 2.0, 1.0]);
    let search_policy = policy(4, 32, 12);

    let (results, proof) = graph
        .search_with_proof_policy(&query, &search_policy)
        .expect("search_with_proof_policy should succeed");

    assert!(!results.is_empty());
    assert_eq!(results.len(), search_policy.k as usize);
    graph
        .verify_traversal_proof(&query, &proof)
        .expect("proof produced by the graph should verify");
}

#[test]
fn traversal_proof_detects_topk_tampering() {
    let graph = sample_graph();
    let query = Vector(vec![7.9, 1.0, 2.0]);
    let search_policy = policy(3, 24, 10);

    let (_, mut proof) = graph
        .search_with_proof_policy(&query, &search_policy)
        .expect("search_with_proof_policy should succeed");
    assert_eq!(proof.results.len(), 3);

    // Mutating result order should invalidate strict top-k semantics.
    proof.results.swap(0, 1);

    let err = graph
        .verify_traversal_proof(&query, &proof)
        .expect_err("tampered top-k order must fail verification");
    assert!(format!("{err}").contains("Top-k results mismatch"));
}

#[test]
fn candidate_truncation_semantics_are_committed() {
    let graph = sample_graph();
    let query = Vector(vec![15.0, 0.5, 4.0]);
    let search_policy = policy(2, 64, 3);

    let (_, proof) = graph
        .search_with_proof_policy(&query, &search_policy)
        .expect("search_with_proof_policy should succeed");

    assert!(proof.candidate_count_total >= proof.candidate_ids.len() as u32);
    assert_eq!(
        proof.candidate_ids.len(),
        (proof.candidate_count_total as usize).min(search_policy.candidate_limit as usize)
    );
    assert_eq!(
        proof.candidate_truncated,
        proof.candidate_count_total > search_policy.candidate_limit
    );
    graph
        .verify_traversal_proof(&query, &proof)
        .expect("candidate completeness metadata must verify");
}
