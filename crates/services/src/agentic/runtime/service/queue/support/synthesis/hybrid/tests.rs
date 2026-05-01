use super::*;

fn nist_briefing_contract() -> ioi_types::app::agentic::WebRetrievalContract {
    crate::agentic::web::derive_web_retrieval_contract(
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.",
        None,
    )
    .expect("retrieval contract")
}

fn nist_briefing_base_draft() -> SynthesisDraft {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let mut citations_by_id = BTreeMap::new();
    citations_by_id.insert(
        "C1".to_string(),
        CitationCandidate {
            id: "C1".to_string(),
            url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
            source_label: "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                .to_string(),
            excerpt: "NIST released FIPS 203, FIPS 204, and FIPS 205 as the first finalized post-quantum encryption standards."
                .to_string(),
            timestamp_utc: "2026-03-10T12:00:00Z".to_string(),
            note: "retrieved_utc".to_string(),
            from_successful_read: true,
        },
    );
    citations_by_id.insert(
        "C2".to_string(),
        CitationCandidate {
            id: "C2".to_string(),
            url: "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
            source_label: "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption"
                .to_string(),
            excerpt: "NIST selected HQC in March 2025 as the fifth post-quantum algorithm for standardization."
                .to_string(),
            timestamp_utc: "2026-03-10T12:00:00Z".to_string(),
            note: "retrieved_utc".to_string(),
            from_successful_read: true,
        },
    );
    citations_by_id.insert(
        "C3".to_string(),
        CitationCandidate {
            id: "C3".to_string(),
            url: "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
            source_label: "Federal Information Processing Standard (FIPS) 204".to_string(),
            excerpt: "Federal Information Processing Standard (FIPS) 204 specifies ML-DSA."
                .to_string(),
            timestamp_utc: "2026-03-10T12:00:00Z".to_string(),
            note: "retrieved_utc".to_string(),
            from_successful_read: true,
        },
    );
    citations_by_id.insert(
        "C4".to_string(),
        CitationCandidate {
            id: "C4".to_string(),
            url: "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/"
                .to_string(),
            source_label: "Diving into NIST's new post-quantum standards".to_string(),
            excerpt: "The finalized standards set includes FIPS 203, FIPS 204, and FIPS 205."
                .to_string(),
            timestamp_utc: "2026-03-10T12:00:00Z".to_string(),
            note: "retrieved_utc".to_string(),
            from_successful_read: true,
        },
    );

    SynthesisDraft {
        query: query.to_string(),
        retrieval_contract: Some(nist_briefing_contract()),
        run_date: "2026-03-10".to_string(),
        run_timestamp_ms: 1_773_174_400_000,
        run_timestamp_iso_utc: "2026-03-10T12:00:00Z".to_string(),
        completion_reason: "Completed after meeting the source floor.".to_string(),
        overall_confidence: "high".to_string(),
        overall_caveat: "caveat".to_string(),
        stories: vec![
            StoryDraft {
                title: "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                    .to_string(),
                what_happened: "NIST finalized FIPS 203, FIPS 204, and FIPS 205 in August 2024."
                    .to_string(),
                changed_last_hour: String::new(),
                why_it_matters: "These standards define the initial federal PQC baseline."
                    .to_string(),
                user_impact: String::new(),
                workaround: String::new(),
                eta_confidence: "high".to_string(),
                citation_ids: vec!["C1".to_string(), "C3".to_string()],
                confidence: "high".to_string(),
                caveat: "caveat".to_string(),
            },
            StoryDraft {
                title: "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption"
                    .to_string(),
                what_happened: "NIST selected HQC in March 2025 for standardization.".to_string(),
                changed_last_hour: String::new(),
                why_it_matters:
                    "The selection expands the PQC roadmap beyond the first finalized trio."
                        .to_string(),
                user_impact: String::new(),
                workaround: String::new(),
                eta_confidence: "medium".to_string(),
                citation_ids: vec!["C2".to_string(), "C4".to_string()],
                confidence: "medium".to_string(),
                caveat: "caveat".to_string(),
            },
        ],
        citations_by_id,
        blocked_urls: Vec::new(),
        partial_note: None,
    }
}

#[test]
fn document_briefing_hybrid_response_requires_support_coverage_on_single_item() {
    let base = nist_briefing_base_draft();
    let required_sections = build_hybrid_required_sections(&base.query);
    let single_item_response = HybridSynthesisResponse {
        heading: "Briefing".to_string(),
        items: vec![HybridItemResponse {
            title: "Summary".to_string(),
            sections: vec![
                HybridSectionResponse {
                    key: "what_happened".to_string(),
                    label: "What happened".to_string(),
                    content: "NIST finalized the first PQC standards.".to_string(),
                },
                HybridSectionResponse {
                    key: "key_evidence".to_string(),
                    label: "Key evidence".to_string(),
                    content: "Official NIST citations support the standards summary.".to_string(),
                },
            ],
            citation_ids: vec!["C1".to_string()],
            confidence: "high".to_string(),
            caveat: "caveat".to_string(),
        }],
        overall_confidence: "high".to_string(),
        overall_caveat: "caveat".to_string(),
    };

    assert!(
        apply_hybrid_synthesis_response(&base, &required_sections, single_item_response).is_none()
    );
}

#[test]
fn document_briefing_hybrid_response_rejects_multi_item_shape() {
    let base = nist_briefing_base_draft();
    let required_sections = build_hybrid_required_sections(&base.query);
    let response = HybridSynthesisResponse {
        heading: "Briefing".to_string(),
        items: vec![
            HybridItemResponse {
                title: "First standards".to_string(),
                sections: vec![
                    HybridSectionResponse {
                        key: "what_happened".to_string(),
                        label: "What happened".to_string(),
                        content: "NIST finalized FIPS 203, FIPS 204, and FIPS 205 in August 2024."
                            .to_string(),
                    },
                    HybridSectionResponse {
                        key: "key_evidence".to_string(),
                        label: "Key evidence".to_string(),
                        content: "NIST's August 2024 release and the FIPS 204 publication anchor the current baseline."
                            .to_string(),
                    },
                ],
                citation_ids: vec!["C1".to_string(), "C3".to_string()],
                confidence: "high".to_string(),
                caveat: "caveat".to_string(),
            },
            HybridItemResponse {
                title: "HQC selection".to_string(),
                sections: vec![
                    HybridSectionResponse {
                        key: "what_happened".to_string(),
                        label: "What happened".to_string(),
                        content: "NIST selected HQC in March 2025 as a fifth algorithm for standardization."
                            .to_string(),
                    },
                    HybridSectionResponse {
                        key: "key_evidence".to_string(),
                        label: "Key evidence".to_string(),
                        content: "The March 2025 NIST announcement and supporting standards analysis describe the expanded roadmap."
                            .to_string(),
                    },
                ],
                citation_ids: vec!["C2".to_string(), "C4".to_string()],
                confidence: "medium".to_string(),
                caveat: "caveat".to_string(),
            },
        ],
        overall_confidence: "high".to_string(),
        overall_caveat: "caveat".to_string(),
    };

    assert!(apply_hybrid_synthesis_response(&base, &required_sections, response).is_none());
}

#[test]
fn document_briefing_hybrid_response_accepts_single_briefing_item() {
    let base = nist_briefing_base_draft();
    let required_sections = build_hybrid_required_sections(&base.query);
    let response = HybridSynthesisResponse {
        heading: "Briefing".to_string(),
        items: vec![HybridItemResponse {
            title: "NIST PQC briefing".to_string(),
            sections: vec![
                HybridSectionResponse {
                    key: "what_happened".to_string(),
                    label: "What happened".to_string(),
                    content: "NIST finalized FIPS 203, FIPS 204, and FIPS 205 in August 2024, then selected HQC in March 2025 as an additional algorithm for standardization."
                        .to_string(),
                },
                HybridSectionResponse {
                    key: "key_evidence".to_string(),
                    label: "Key evidence".to_string(),
                    content: "NIST's August 2024 release, the March 2025 HQC announcement, and the FIPS 204 publication collectively anchor the current standards picture."
                        .to_string(),
                },
            ],
            citation_ids: vec!["C1".to_string(), "C2".to_string()],
            confidence: "high".to_string(),
            caveat: "caveat".to_string(),
        }],
        overall_confidence: "high".to_string(),
        overall_caveat: "caveat".to_string(),
    };

    let updated = apply_hybrid_synthesis_response(&base, &required_sections, response)
        .expect("response should satisfy single-item briefing contract");
    assert_eq!(updated.stories.len(), 1);
    assert_eq!(updated.stories[0].citation_ids.len(), 2);
}

#[test]
fn section_kind_resolution_prefers_exact_evidence_key_over_summary_aliases() {
    assert_eq!(
        section_kind_from_key("key_evidence"),
        Some(ReportSectionKind::Evidence)
    );
    assert_eq!(
        section_kind_from_key("what_happened"),
        Some(ReportSectionKind::Summary)
    );
}
