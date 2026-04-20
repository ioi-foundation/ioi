use super::*;

#[test]
fn document_briefing_layout_renders_single_document_without_story_headers() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
            .to_string();
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(&query, Some(&query)).ok();
    let mut citations_by_id = BTreeMap::new();
    for (idx, (label, url)) in [
        ("Post-quantum cryptography | NIST", "https://www.nist.gov/pqc"),
        (
            "NIST’s post-quantum cryptography standards are here - IBM Research",
            "https://research.ibm.com/blog/nist-pqc-standards",
        ),
        (
            "IBM-Developed Algorithms Announced as NIST's First Published Post-Quantum Cryptography Standards",
            "https://newsroom.ibm.com/2024-08-13-ibm-developed-algorithms-announced-as-worlds-first-post-quantum-cryptography-standards",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        citations_by_id.insert(
            format!("c{}", idx + 1),
            CitationCandidate {
                id: format!("c{}", idx + 1),
                url: url.to_string(),
                source_label: label.to_string(),
                excerpt: label.to_string(),
                timestamp_utc: "2026-03-10T12:19:24Z".to_string(),
                note: "retrieved_utc".to_string(),
                from_successful_read: true,
            },
        );
    }

    let draft = SynthesisDraft {
        query: query.clone(),
        retrieval_contract,
        run_date: "2026-03-10".to_string(),
        run_timestamp_ms: 1_773_145_164_000,
        run_timestamp_iso_utc: "2026-03-10T12:19:24Z".to_string(),
        completion_reason: "min_sources_reached".to_string(),
        overall_confidence: "high".to_string(),
        overall_caveat: "retrieval receipts available".to_string(),
        stories: vec![
            StoryDraft {
                title: "NIST".to_string(),
                what_happened:
                    "NIST finalized its first post-quantum cryptography standards and updated migration guidance."
                        .to_string(),
                changed_last_hour: String::new(),
                why_it_matters: String::new(),
                user_impact: String::new(),
                workaround: String::new(),
                eta_confidence: "high".to_string(),
                citation_ids: vec!["c1".to_string()],
                confidence: "high".to_string(),
                caveat: "timestamps may reflect retrieval time".to_string(),
            },
            StoryDraft {
                title: "IBM Research".to_string(),
                what_happened:
                    "IBM Research summarized the finalized standards as ML-KEM, ML-DSA, and SLH-DSA."
                        .to_string(),
                changed_last_hour: String::new(),
                why_it_matters: String::new(),
                user_impact: String::new(),
                workaround: String::new(),
                eta_confidence: "high".to_string(),
                citation_ids: vec!["c2".to_string()],
                confidence: "high".to_string(),
                caveat: "timestamps may reflect retrieval time".to_string(),
            },
            StoryDraft {
                title: "IBM Newsroom".to_string(),
                what_happened:
                    "IBM noted the August 13, 2024 publication milestone for the first finalized standards."
                        .to_string(),
                changed_last_hour: String::new(),
                why_it_matters: String::new(),
                user_impact: String::new(),
                workaround: String::new(),
                eta_confidence: "high".to_string(),
                citation_ids: vec!["c3".to_string()],
                confidence: "high".to_string(),
                caveat: "timestamps may reflect retrieval time".to_string(),
            },
        ],
        citations_by_id,
        blocked_urls: Vec::new(),
        partial_note: None,
    };

    let rendered = render_user_synthesis_draft(&draft);
    assert!(rendered.contains("Briefing for"));
    assert!(rendered.contains("What happened:"));
    assert!(rendered.contains("Key evidence:"));
    assert!(!rendered.contains("Story 1:"));
    assert!(!rendered.contains("Comparison:"));
}

#[test]
fn document_briefing_render_facts_require_authority_identifier_coverage() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
            .to_string();
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(&query, Some(&query)).ok();
    let mut citations_by_id = BTreeMap::new();
    for (id, label, url, excerpt) in [
        (
            "c1",
            "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption | NIST",
            "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption",
            "The other two finished standards, FIPS 204 and FIPS 205, contain digital signature algorithms, while HQC was selected as an additional algorithm.",
        ),
        (
            "c2",
            "Diving Into NIST’s New Post-Quantum Standards",
            "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/",
            "NIST has released FIPS 203, FIPS 204, and FIPS 205 as finalized post-quantum cryptography standards.",
        ),
        (
            "c3",
            "IBM Research on NIST's post-quantum cryptography standards",
            "https://research.ibm.com/blog/nist-pqc-standards",
            "IBM summarized FIPS 203, FIPS 204, and FIPS 205 after NIST released the finalized standards.",
        ),
        (
            "c4",
            "Federal Information Processing Standard (FIPS) 204",
            "https://csrc.nist.gov/pubs/fips/204/final",
            "Federal Information Processing Standard (FIPS) 204 specifies ML-DSA.",
        ),
    ] {
        citations_by_id.insert(
            id.to_string(),
            CitationCandidate {
                id: id.to_string(),
                url: url.to_string(),
                source_label: label.to_string(),
                excerpt: excerpt.to_string(),
                timestamp_utc: "2026-03-10T20:58:06Z".to_string(),
                note: "retrieved_utc".to_string(),
                from_successful_read: true,
            },
        );
    }

    let draft = SynthesisDraft {
        query: query.clone(),
        retrieval_contract,
        run_date: "2026-03-10".to_string(),
        run_timestamp_ms: 1_773_176_286_000,
        run_timestamp_iso_utc: "2026-03-10T20:58:06Z".to_string(),
        completion_reason: "min_sources_reached".to_string(),
        overall_confidence: "high".to_string(),
        overall_caveat: "retrieval receipts available".to_string(),
        stories: vec![StoryDraft {
            title: "NIST PQC briefing".to_string(),
            what_happened:
                "NIST finalized its first post-quantum cryptography standards and later selected HQC as an additional algorithm."
                    .to_string(),
            changed_last_hour: String::new(),
            why_it_matters: String::new(),
            user_impact: String::new(),
            workaround: String::new(),
            eta_confidence: "high".to_string(),
            citation_ids: vec![
                "c1".to_string(),
                "c2".to_string(),
                "c3".to_string(),
                "c4".to_string(),
            ],
            confidence: "high".to_string(),
            caveat: "timestamps may reflect retrieval time".to_string(),
        }],
        citations_by_id,
        blocked_urls: Vec::new(),
        partial_note: None,
    };

    let required_sections = build_hybrid_required_sections(&query);
    let facts = document_briefing_render_facts(&draft, &required_sections, 1);
    assert!(facts.standard_identifier_floor_met);
    assert_eq!(facts.required_standard_identifier_count, 3);
    assert_eq!(facts.required_authority_standard_identifier_count, 2);
    assert!(!facts.authority_standard_identifier_floor_met);
}

#[test]
fn document_briefing_render_facts_pass_when_authority_sources_cover_required_identifiers() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
            .to_string();
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(&query, Some(&query)).ok();
    let mut citations_by_id = BTreeMap::new();
    for (id, label, url, excerpt) in [
        (
            "c1",
            "NIST Releases First 3 Finalized Post-Quantum Encryption Standards",
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards",
            "NIST released FIPS 203, FIPS 204 and FIPS 205 as its first three finalized post-quantum encryption standards.",
        ),
        (
            "c2",
            "Federal Information Processing Standard (FIPS) 204",
            "https://csrc.nist.gov/pubs/fips/204/final",
            "Federal Information Processing Standard (FIPS) 204 specifies ML-DSA.",
        ),
    ] {
        citations_by_id.insert(
            id.to_string(),
            CitationCandidate {
                id: id.to_string(),
                url: url.to_string(),
                source_label: label.to_string(),
                excerpt: excerpt.to_string(),
                timestamp_utc: "2026-03-10T20:58:06Z".to_string(),
                note: "retrieved_utc".to_string(),
                from_successful_read: true,
            },
        );
    }

    let draft = SynthesisDraft {
        query: query.clone(),
        retrieval_contract,
        run_date: "2026-03-10".to_string(),
        run_timestamp_ms: 1_773_176_286_000,
        run_timestamp_iso_utc: "2026-03-10T20:58:06Z".to_string(),
        completion_reason: "min_sources_reached".to_string(),
        overall_confidence: "high".to_string(),
        overall_caveat: "retrieval receipts available".to_string(),
        stories: vec![StoryDraft {
            title: "NIST PQC briefing".to_string(),
            what_happened: "NIST finalized its first post-quantum cryptography standards."
                .to_string(),
            changed_last_hour: String::new(),
            why_it_matters: String::new(),
            user_impact: String::new(),
            workaround: String::new(),
            eta_confidence: "high".to_string(),
            citation_ids: vec!["c1".to_string(), "c2".to_string()],
            confidence: "high".to_string(),
            caveat: "timestamps may reflect retrieval time".to_string(),
        }],
        citations_by_id,
        blocked_urls: Vec::new(),
        partial_note: None,
    };

    let required_sections = build_hybrid_required_sections(&query);
    let facts = document_briefing_render_facts(&draft, &required_sections, 1);
    assert!(facts.standard_identifier_floor_met);
    assert_eq!(facts.required_authority_standard_identifier_count, 3);
    assert!(facts.authority_standard_identifier_floor_met);
}

#[test]
fn document_briefing_render_facts_backfill_authority_identifier_coverage_from_official_citations() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
            .to_string();
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(&query, Some(&query)).ok();
    let mut citations_by_id = BTreeMap::new();
    for (id, label, url, excerpt) in [
        (
            "c1",
            "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption | NIST",
            "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption",
            "The other two finished standards, FIPS 204 and FIPS 205, contain digital signature algorithms, while HQC was selected as an additional algorithm.",
        ),
        (
            "c2",
            "Diving Into NIST’s New Post-Quantum Standards",
            "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/",
            "NIST has released FIPS 203, FIPS 204, and FIPS 205 as finalized post-quantum cryptography standards.",
        ),
        (
            "c3",
            "NIST Releases First 3 Finalized Post-Quantum Encryption Standards",
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards",
            "NIST released FIPS 203, FIPS 204 and FIPS 205 as its first three finalized post-quantum encryption standards.",
        ),
    ] {
        citations_by_id.insert(
            id.to_string(),
            CitationCandidate {
                id: id.to_string(),
                url: url.to_string(),
                source_label: label.to_string(),
                excerpt: excerpt.to_string(),
                timestamp_utc: "2026-03-10T20:58:06Z".to_string(),
                note: "retrieved_utc".to_string(),
                from_successful_read: true,
            },
        );
    }

    let draft = SynthesisDraft {
        query: query.clone(),
        retrieval_contract,
        run_date: "2026-03-10".to_string(),
        run_timestamp_ms: 1_773_176_286_000,
        run_timestamp_iso_utc: "2026-03-10T20:58:06Z".to_string(),
        completion_reason: "min_sources_reached".to_string(),
        overall_confidence: "high".to_string(),
        overall_caveat: "retrieval receipts available".to_string(),
        stories: vec![
            StoryDraft {
                title: "NIST HQC update".to_string(),
                what_happened:
                    "NIST selected HQC after publishing its first set of finalized post-quantum standards."
                        .to_string(),
                changed_last_hour: String::new(),
                why_it_matters: String::new(),
                user_impact: String::new(),
                workaround: String::new(),
                eta_confidence: "high".to_string(),
                citation_ids: vec!["c1".to_string()],
                confidence: "high".to_string(),
                caveat: "timestamps may reflect retrieval time".to_string(),
            },
            StoryDraft {
                title: "Independent corroboration".to_string(),
                what_happened:
                    "Independent analysis summarized the finalized standards set."
                        .to_string(),
                changed_last_hour: String::new(),
                why_it_matters: String::new(),
                user_impact: String::new(),
                workaround: String::new(),
                eta_confidence: "high".to_string(),
                citation_ids: vec!["c2".to_string()],
                confidence: "high".to_string(),
                caveat: "timestamps may reflect retrieval time".to_string(),
            },
        ],
        citations_by_id,
        blocked_urls: Vec::new(),
        partial_note: None,
    };

    let required_sections = build_hybrid_required_sections(&query);
    let facts = document_briefing_render_facts(&draft, &required_sections, 2);
    assert_eq!(facts.required_authority_standard_identifier_count, 3);
    assert!(facts.authority_standard_identifier_floor_met);

    let rendered = render_document_briefing_layout(&draft, &required_sections, 2, 2, &[], &[], &[]);

    let nist_2025_idx = rendered
        .find("https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption")
        .expect("2025 NIST citation");
    let nist_2024_idx = rendered
        .find("https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards")
        .expect("2024 NIST citation");
    let terraquantum_idx = rendered
        .find("https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/")
        .expect("terraquantum citation");
    assert!(nist_2025_idx < terraquantum_idx);
    assert!(nist_2024_idx < terraquantum_idx);
}

#[test]
fn render_document_briefing_layout_uses_evidence_bullets_and_required_inventory() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
            .to_string();
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(&query, Some(&query)).ok();
    let mut citations_by_id = BTreeMap::new();
    for (id, label, url, excerpt) in [
        (
            "c1",
            "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption | NIST",
            "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption",
            "The other two finished standards, FIPS 204 and FIPS 205, contain digital signature algorithms, while HQC was selected as an additional algorithm.",
        ),
        (
            "c2",
            "NIST Releases First 3 Finalized Post-Quantum Encryption Standards",
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards",
            "NIST released FIPS 203, FIPS 204 and FIPS 205 as its first three finalized post-quantum encryption standards.",
        ),
    ] {
        citations_by_id.insert(
            id.to_string(),
            CitationCandidate {
                id: id.to_string(),
                url: url.to_string(),
                source_label: label.to_string(),
                excerpt: excerpt.to_string(),
                timestamp_utc: "2026-03-10T20:58:06Z".to_string(),
                note: "retrieved_utc".to_string(),
                from_successful_read: true,
            },
        );
    }

    let draft = SynthesisDraft {
        query: query.clone(),
        retrieval_contract,
        run_date: "2026-03-10".to_string(),
        run_timestamp_ms: 1_773_176_286_000,
        run_timestamp_iso_utc: "2026-03-10T20:58:06Z".to_string(),
        completion_reason: "min_sources_reached".to_string(),
        overall_confidence: "high".to_string(),
        overall_caveat: "retrieval receipts available".to_string(),
        stories: vec![StoryDraft {
            title: "NIST PQC briefing".to_string(),
            what_happened:
                "NIST finalized its first post-quantum cryptography standards and later selected HQC as an additional algorithm."
                    .to_string(),
            changed_last_hour: String::new(),
            why_it_matters: String::new(),
            user_impact: String::new(),
            workaround: String::new(),
            eta_confidence: "high".to_string(),
            citation_ids: vec!["c1".to_string(), "c2".to_string()],
            confidence: "high".to_string(),
            caveat: "timestamps may reflect retrieval time".to_string(),
        }],
        citations_by_id,
        blocked_urls: Vec::new(),
        partial_note: None,
    };

    let rendered = render_document_briefing_layout(
        &draft,
        &build_hybrid_required_sections(&query),
        2,
        2,
        &[],
        &[],
        &[],
    );

    assert!(rendered.contains("currently published standards as FIPS 203"));
    assert!(rendered.contains("FIPS 204"));
    assert!(rendered.contains("FIPS 205"));
    assert!(!rendered.contains("currently published standards as FIPS 204, FIPS 205, HQC"));
    assert!(rendered.contains("\nKey evidence:\n- According to "));
    assert!(rendered.contains("- According to NIST Selects HQC"));
    assert!(rendered.contains(
        "\n- According to NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
    ));
}

#[test]
fn render_document_briefing_layout_surfaces_ir_inventory_for_authoritative_publications() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
            .to_string();
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(&query, Some(&query)).ok();
    let mut citations_by_id = BTreeMap::new();
    for (id, label, url, excerpt) in [
        (
            "c1",
            "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC",
            "https://csrc.nist.gov/pubs/ir/8413/upd1/final",
            "IR 8413 documents NIST's third-round post-quantum standardization status report and notes that new public-key standards will augment FIPS 186-4.",
        ),
        (
            "c2",
            "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC",
            "https://csrc.nist.gov/pubs/ir/8413/final",
            "IR 8413 tracks the post-quantum cryptography standardization process and references the new public-key standards effort.",
        ),
    ] {
        citations_by_id.insert(
            id.to_string(),
            CitationCandidate {
                id: id.to_string(),
                url: url.to_string(),
                source_label: label.to_string(),
                excerpt: excerpt.to_string(),
                timestamp_utc: "2026-04-02T01:15:13Z".to_string(),
                note: "retrieved_utc".to_string(),
                from_successful_read: true,
            },
        );
    }

    let draft = SynthesisDraft {
        query: query.clone(),
        retrieval_contract,
        run_date: "2026-04-02".to_string(),
        run_timestamp_ms: 1_775_092_513_000,
        run_timestamp_iso_utc: "2026-04-02T01:15:13Z".to_string(),
        completion_reason: "min_sources_reached".to_string(),
        overall_confidence: "medium".to_string(),
        overall_caveat: "retrieval receipts available".to_string(),
        stories: vec![StoryDraft {
            title: "NIST PQC status report".to_string(),
            what_happened:
                "NIST's current authoritative publication set includes IR 8413 status reports for the post-quantum cryptography standardization process."
                    .to_string(),
            changed_last_hour: String::new(),
            why_it_matters: String::new(),
            user_impact: String::new(),
            workaround: String::new(),
            eta_confidence: "medium".to_string(),
            citation_ids: vec!["c1".to_string(), "c2".to_string()],
            confidence: "medium".to_string(),
            caveat: "timestamps may reflect retrieval time".to_string(),
        }],
        citations_by_id,
        blocked_urls: Vec::new(),
        partial_note: None,
    };

    let required_sections = build_hybrid_required_sections(&query);
    let rendered = render_document_briefing_layout(&draft, &required_sections, 2, 2, &[], &[], &[]);
    let facts = document_briefing_render_facts(&draft, &required_sections, 2);

    assert!(rendered.contains("current authoritative publications as IR 8413."));
    assert!(facts.summary_inventory_floor_met);
    assert_eq!(facts.summary_inventory_required_identifier_count, 1);
    assert_eq!(facts.summary_inventory_authority_identifier_count, 1);
}

#[test]
fn render_document_briefing_layout_preserves_distinct_read_backed_evidence_lines() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
            .to_string();
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(&query, Some(&query)).ok();
    let mut citations_by_id = BTreeMap::new();
    for (id, label, url, excerpt) in [
        (
            "c1",
            "NIST Releases First 3 Finalized Post-Quantum Encryption Standards",
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards",
            "NIST released FIPS 203, FIPS 204 and FIPS 205 as its first three finalized post-quantum encryption standards.",
        ),
        (
            "c2",
            "Diving Into NIST’s New Post-Quantum Standards",
            "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/",
            "The finalized standards set includes FIPS 203, FIPS 204, and FIPS 205.",
        ),
    ] {
        citations_by_id.insert(
            id.to_string(),
            CitationCandidate {
                id: id.to_string(),
                url: url.to_string(),
                source_label: label.to_string(),
                excerpt: excerpt.to_string(),
                timestamp_utc: "2026-03-11T06:21:17Z".to_string(),
                note: "retrieved_utc".to_string(),
                from_successful_read: true,
            },
        );
    }

    let draft = SynthesisDraft {
        query: query.clone(),
        retrieval_contract,
        run_date: "2026-03-11".to_string(),
        run_timestamp_ms: 1_773_210_077_000,
        run_timestamp_iso_utc: "2026-03-11T06:21:17Z".to_string(),
        completion_reason: "min_sources_reached".to_string(),
        overall_confidence: "medium".to_string(),
        overall_caveat: "retrieval receipts available".to_string(),
        stories: vec![
            StoryDraft {
                title: "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                    .to_string(),
                what_happened: "NIST finalized FIPS 203, FIPS 204, and FIPS 205 in August 2024."
                    .to_string(),
                changed_last_hour: String::new(),
                why_it_matters: String::new(),
                user_impact: String::new(),
                workaround: String::new(),
                eta_confidence: "high".to_string(),
                citation_ids: vec!["c1".to_string()],
                confidence: "high".to_string(),
                caveat: "caveat".to_string(),
            },
            StoryDraft {
                title: "Diving Into NIST’s New Post-Quantum Standards".to_string(),
                what_happened:
                    "Independent coverage summarized the finalized post-quantum standards set."
                        .to_string(),
                changed_last_hour: String::new(),
                why_it_matters: String::new(),
                user_impact: String::new(),
                workaround: String::new(),
                eta_confidence: "medium".to_string(),
                citation_ids: vec!["c2".to_string()],
                confidence: "medium".to_string(),
                caveat: "caveat".to_string(),
            },
        ],
        citations_by_id,
        blocked_urls: Vec::new(),
        partial_note: None,
    };

    let rendered = render_document_briefing_layout(
        &draft,
        &build_hybrid_required_sections(&query),
        2,
        2,
        &[],
        &[],
        &[],
    );

    assert!(rendered.contains("\nKey evidence:\n- According to NIST Releases First 3 Finalized Post-Quantum Encryption Standards"));
    assert!(rendered.contains("\n- According to Diving Into NIST’s New Post-Quantum Standards"));
}

#[test]
fn render_document_briefing_layout_omits_unread_citations() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
            .to_string();
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(&query, Some(&query)).ok();
    let mut citations_by_id = BTreeMap::new();
    for (id, label, url, excerpt, from_successful_read) in [
        (
            "c1",
            "NIST Releases First 3 Finalized Post-Quantum Encryption Standards",
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards",
            "NIST released FIPS 203, FIPS 204 and FIPS 205 as its first three finalized post-quantum encryption standards.",
            true,
        ),
        (
            "c2",
            "NIST's new timeline for post-quantum encryption",
            "https://www.cyberark.com/resources/blog/nist-s-new-timeline-for-post-quantum-encryption",
            "CyberArk summarizes NIST's post-quantum migration timeline.",
            false,
        ),
    ] {
        citations_by_id.insert(
            id.to_string(),
            CitationCandidate {
                id: id.to_string(),
                url: url.to_string(),
                source_label: label.to_string(),
                excerpt: excerpt.to_string(),
                timestamp_utc: "2026-03-10T20:58:06Z".to_string(),
                note: "retrieved_utc".to_string(),
                from_successful_read,
            },
        );
    }

    let draft = SynthesisDraft {
        query: query.clone(),
        retrieval_contract,
        run_date: "2026-03-10".to_string(),
        run_timestamp_ms: 1_773_176_286_000,
        run_timestamp_iso_utc: "2026-03-10T20:58:06Z".to_string(),
        completion_reason: "min_sources_reached".to_string(),
        overall_confidence: "high".to_string(),
        overall_caveat: "retrieval receipts available".to_string(),
        stories: vec![StoryDraft {
            title: "NIST PQC briefing".to_string(),
            what_happened: "NIST finalized its first post-quantum cryptography standards."
                .to_string(),
            changed_last_hour: String::new(),
            why_it_matters: String::new(),
            user_impact: String::new(),
            workaround: String::new(),
            eta_confidence: "high".to_string(),
            citation_ids: vec!["c1".to_string(), "c2".to_string()],
            confidence: "high".to_string(),
            caveat: "timestamps may reflect retrieval time".to_string(),
        }],
        citations_by_id,
        blocked_urls: Vec::new(),
        partial_note: None,
    };

    let rendered = render_document_briefing_layout(
        &draft,
        &build_hybrid_required_sections(&query),
        1,
        2,
        &[],
        &[],
        &[],
    );

    assert!(rendered.contains(
        "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
    ));
    assert!(!rendered.contains(
        "https://www.cyberark.com/resources/blog/nist-s-new-timeline-for-post-quantum-encryption"
    ));
}
