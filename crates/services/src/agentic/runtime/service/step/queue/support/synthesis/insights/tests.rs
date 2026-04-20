use super::*;
use crate::agentic::runtime::service::step::queue::envelope::{OutputContract, ProvenancePolicy};

fn unconstrained_set() -> ConstraintSet {
    ConstraintSet {
        target: String::new(),
        required_facets: BTreeSet::new(),
        scopes: BTreeSet::new(),
        provenance_policy: ProvenancePolicy {
            min_independent_sources: 1,
        },
        output_contract: OutputContract {
            requires_absolute_utc: false,
            unresolved_requires_caveat: true,
        },
    }
}

#[test]
fn insight_hard_policy_requires_successful_read_backing_when_evidence_can_meet_floor() {
    let candidates = vec![
        CitationCandidate {
            id: "C1".to_string(),
            url: "https://news.example.com/article-a".to_string(),
            source_label: "Article A".to_string(),
            excerpt: "Verified readable evidence for story A.".to_string(),
            timestamp_utc: "2026-03-11T00:00:00Z".to_string(),
            note: "retrieved_utc".to_string(),
            from_successful_read: true,
        },
        CitationCandidate {
            id: "C2".to_string(),
            url: "https://news.example.com/article-b".to_string(),
            source_label: "Article B".to_string(),
            excerpt: "Metadata-only candidate for story B.".to_string(),
            timestamp_utc: "2026-03-11T00:00:00Z".to_string(),
            note: "retrieved_utc".to_string(),
            from_successful_read: false,
        },
    ];
    let ranked = vec![
        (
            0usize,
            SourceSignalProfile::default(),
            CandidateEvidenceScore::default(),
        ),
        (
            1usize,
            SourceSignalProfile::default(),
            CandidateEvidenceScore::default(),
        ),
    ];
    let policy_flags_by_id = candidates
        .iter()
        .map(|candidate| (candidate.id.clone(), InsightPolicyFlags::default()))
        .collect::<BTreeMap<_, _>>();
    let hard_policy = derive_insight_hard_policy_gates(
        &ranked,
        &candidates,
        &policy_flags_by_id,
        &BTreeSet::new(),
        1,
        false,
        &unconstrained_set(),
    );

    assert!(hard_policy.require_successful_read_backing);
    assert!(candidate_passes_insight_hard_policy(
        &candidates[0],
        SourceSignalProfile::default(),
        &CandidateEvidenceScore::default(),
        hard_policy,
        &unconstrained_set(),
        &InsightPolicyFlags::default(),
    ));
    assert!(!candidate_passes_insight_hard_policy(
        &candidates[1],
        SourceSignalProfile::default(),
        &CandidateEvidenceScore::default(),
        hard_policy,
        &unconstrained_set(),
        &InsightPolicyFlags::default(),
    ));
}

#[test]
fn insight_hard_policy_keeps_metadata_candidates_when_verified_floor_is_unavailable() {
    let candidates = vec![CitationCandidate {
        id: "C1".to_string(),
        url: "https://news.example.com/article-a".to_string(),
        source_label: "Article A".to_string(),
        excerpt: "Metadata-only candidate for story A.".to_string(),
        timestamp_utc: "2026-03-11T00:00:00Z".to_string(),
        note: "retrieved_utc".to_string(),
        from_successful_read: false,
    }];
    let ranked = vec![(
        0usize,
        SourceSignalProfile::default(),
        CandidateEvidenceScore::default(),
    )];
    let policy_flags_by_id = candidates
        .iter()
        .map(|candidate| (candidate.id.clone(), InsightPolicyFlags::default()))
        .collect::<BTreeMap<_, _>>();
    let hard_policy = derive_insight_hard_policy_gates(
        &ranked,
        &candidates,
        &policy_flags_by_id,
        &BTreeSet::new(),
        1,
        false,
        &unconstrained_set(),
    );

    assert!(!hard_policy.require_successful_read_backing);
}
