use super::*;

#[test]
fn selected_url_resolution_does_not_escape_allowed_alignment_set() {
    let mut selected_urls =
        vec!["https://research.ibm.com/blog/nist-pqc-standards".to_string()];
    let source_hints = vec![PendingSearchReadSummary {
        url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
        title: Some("NIST's post-quantum cryptography standards are here".to_string()),
        excerpt: "IBM Research | source_url=https://www.hashicorp.com/en/blog/nist-s-post-quantum-cryptography-standards-our-plans".to_string(),
    }];
    let allowed_resolution_urls = vec![
        "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
        "https://www.nist.gov/pqc".to_string(),
    ];

    resolve_selected_urls_from_hints(
        &mut selected_urls,
        &source_hints,
        Some(&allowed_resolution_urls),
    );

    assert_eq!(
        selected_urls,
        vec!["https://research.ibm.com/blog/nist-pqc-standards".to_string()]
    );
}

#[test]
fn selected_url_resolution_keeps_resolved_url_within_allowed_alignment_set() {
    let mut selected_urls =
        vec!["https://news.google.com/rss/articles/CBMiUkFVX3lxTE0x?oc=5".to_string()];
    let source_hints = vec![PendingSearchReadSummary {
        url: "https://news.google.com/rss/articles/CBMiUkFVX3lxTE0x?oc=5".to_string(),
        title: Some("NIST releases first 3 finalized post-quantum encryption standards".to_string()),
        excerpt: "Google News | source_url=https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
    }];
    let allowed_resolution_urls = vec![
        "https://news.google.com/rss/articles/CBMiUkFVX3lxTE0x?oc=5".to_string(),
        "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
    ];

    resolve_selected_urls_from_hints(
        &mut selected_urls,
        &source_hints,
        Some(&allowed_resolution_urls),
    );

    assert_eq!(
        selected_urls,
        vec![
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string()
        ]
    );
}

#[test]
fn selected_url_resolution_preserves_deep_article_urls_when_metadata_points_to_root() {
    let mut selected_urls = vec![
        "https://www.cbsnews.com/live-updates/iran-war-us-israel-strait-of-hormuz-ship-attacks-persian-gulf-drones-missiles/".to_string(),
    ];
    let source_hints = vec![PendingSearchReadSummary {
        url: "https://www.cbsnews.com/live-updates/iran-war-us-israel-strait-of-hormuz-ship-attacks-persian-gulf-drones-missiles/".to_string(),
        title: Some("Live Updates".to_string()),
        excerpt: "CBS News | source_url=https://www.cbsnews.com".to_string(),
    }];

    resolve_selected_urls_from_hints(&mut selected_urls, &source_hints, None);

    assert_eq!(
        selected_urls,
        vec![
            "https://www.cbsnews.com/live-updates/iran-war-us-israel-strait-of-hormuz-ship-attacks-persian-gulf-drones-missiles/"
                .to_string()
        ]
    );
}

#[test]
fn lint_reserves_slot_for_independent_corroboration_when_domain_diversity_is_required() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("contract");
    let discovery_sources = vec![
        WebSource {
            source_id: "official-nist-pqc".to_string(),
            rank: Some(1),
            url: "https://www.nist.gov/pqc".to_string(),
            title: Some("Post-quantum cryptography | NIST".to_string()),
            snippet: Some(
                "December 8, 2025 - These Federal Information Processing Standards (FIPS) are mandatory for federal systems and adopted around the world."
                    .to_string(),
            ),
            domain: Some("nist.gov".to_string()),
        },
        WebSource {
            source_id: "official-nist-news".to_string(),
            rank: Some(2),
            url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
            title: Some(
                "NIST releases first 3 finalized post-quantum encryption standards"
                    .to_string(),
            ),
            snippet: Some(
                "NIST finalized FIPS 203, FIPS 204 and FIPS 205 for post-quantum cryptography."
                    .to_string(),
            ),
            domain: Some("nist.gov".to_string()),
        },
        WebSource {
            source_id: "secondary-ibm".to_string(),
            rank: Some(3),
            url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
            title: Some(
                "NIST’s post-quantum cryptography standards are here - IBM Research"
                    .to_string(),
            ),
            snippet: Some(
                "IBM summarized FIPS 203, FIPS 204, and FIPS 205 after NIST released the standards."
                    .to_string(),
            ),
            domain: Some("research.ibm.com".to_string()),
        },
    ];

    lint_pre_read_payload_urls(
        Some(&retrieval_contract),
        query,
        &discovery_sources,
        &[],
        &PreReadSelectionMode::DirectDetail,
        &[
            "https://www.nist.gov/pqc".to_string(),
            "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
        ],
        2,
    )
    .expect("one authority source should leave room for independent corroboration");
}

#[test]
fn deterministic_pre_read_selection_rejects_generic_authority_neighbor_fill() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("contract");
    let discovery_sources = vec![
        WebSource {
            source_id: "nccoe".to_string(),
            rank: Some(1),
            url: "https://www.nccoe.nist.gov/sites/default/files/2023-12/pqc-migration-nist-sp-1800-38c-preliminary-draft.pdf".to_string(),
            title: Some("Migration to Post-Quantum Cryptography".to_string()),
            snippet: Some(
                "NCCoE migration guidance for post-quantum cryptography at NIST.".to_string(),
            ),
            domain: Some("www.nccoe.nist.gov".to_string()),
        },
        WebSource {
            source_id: "ibm-topic".to_string(),
            rank: Some(2),
            url: "https://www.ibm.com/think/topics/nist".to_string(),
            title: Some("What is the NIST Cybersecurity Framework? - IBM".to_string()),
            snippet: Some(
                "IBM overview of NIST guidance and cybersecurity best practices.".to_string(),
            ),
            domain: Some("www.ibm.com".to_string()),
        },
        WebSource {
            source_id: "ibm-insight".to_string(),
            rank: Some(3),
            url: "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2"
                .to_string(),
            title: Some("NIST Cybersecurity Framework 2 - IBM".to_string()),
            snippet: Some(
                "IBM insight on NIST Cybersecurity Framework 2 updates.".to_string(),
            ),
            domain: Some("www.ibm.com".to_string()),
        },
    ];

    let err = deterministic_pre_read_selection(
        Some(&retrieval_contract),
        query,
        2,
        &discovery_sources,
        &[],
    )
    .expect_err("generic authority-neighbor fill should not satisfy deterministic selection");

    assert!(err.contains("could not satisfy 2 typed source(s)"));
}

#[test]
fn deterministic_pre_read_selection_keeps_on_topic_secondary_fill() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("contract");
    let discovery_sources = vec![
        WebSource {
            source_id: "nccoe".to_string(),
            rank: Some(1),
            url: "https://www.nccoe.nist.gov/sites/default/files/2023-12/pqc-migration-nist-sp-1800-38c-preliminary-draft.pdf".to_string(),
            title: Some("Migration to Post-Quantum Cryptography".to_string()),
            snippet: Some(
                "NCCoE migration guidance for post-quantum cryptography at NIST.".to_string(),
            ),
            domain: Some("www.nccoe.nist.gov".to_string()),
        },
        WebSource {
            source_id: "ibm-pqc".to_string(),
            rank: Some(2),
            url: "https://www.ibm.com/think/insights/post-quantum-cryptography-transition"
                .to_string(),
            title: Some("Post-quantum cryptography transition guidance".to_string()),
            snippet: Some(
                "March 2026 - IBM explains recent NIST post-quantum cryptography transition planning for enterprises.".to_string(),
            ),
            domain: Some("www.ibm.com".to_string()),
        },
    ];

    let selection = deterministic_pre_read_selection(
        Some(&retrieval_contract),
        query,
        2,
        &discovery_sources,
        &[],
    )
    .expect("deterministic selection");

    assert_eq!(selection.selection_mode, PreReadSelectionMode::DirectDetail);
    assert_eq!(selection.urls.len(), 2);
    assert_eq!(
        selection.urls.first().map(String::as_str),
        Some(
            "https://www.nccoe.nist.gov/sites/default/files/2023-12/pqc-migration-nist-sp-1800-38c-preliminary-draft.pdf"
        )
    );
    assert!(selection.urls.iter().any(|url| {
        url == "https://www.ibm.com/think/insights/post-quantum-cryptography-transition"
    }));
}

#[test]
fn deterministic_pre_read_selection_prefers_grounded_external_publication_artifact_over_same_host_authority_tail(
) {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("contract");
    let discovery_sources = vec![
        WebSource {
            source_id: "official-ir-8413-update".to_string(),
            rank: Some(1),
            url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            snippet: Some(
                "The report references FIPS 203, FIPS 204, and FIPS 205 in the NIST post-quantum cryptography standardization process."
                    .to_string(),
            ),
            domain: Some("csrc.nist.gov".to_string()),
        },
        WebSource {
            source_id: "official-pqc-program".to_string(),
            rank: Some(2),
            url: "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization".to_string(),
            title: Some("Post-Quantum Cryptography Standardization | CSRC".to_string()),
            snippet: Some(
                "Current CSRC project page for the latest NIST post-quantum cryptography standardization updates."
                    .to_string(),
            ),
            domain: Some("csrc.nist.gov".to_string()),
        },
        WebSource {
            source_id: "external-pqc-readiness-report".to_string(),
            rank: Some(3),
            url: "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf".to_string(),
            title: Some("State of PQC Readiness 2025".to_string()),
            snippet: Some(
                "Independent November 2025 report on post-quantum cryptography readiness after NIST finalized its first post-quantum standards."
                    .to_string(),
            ),
            domain: Some("trustedcomputinggroup.org".to_string()),
        },
    ];

    let selection = deterministic_pre_read_selection(
        Some(&retrieval_contract),
        query,
        2,
        &discovery_sources,
        &[],
    )
    .expect("deterministic selection");

    assert_eq!(selection.selection_mode, PreReadSelectionMode::DirectDetail);
    assert_eq!(selection.urls.len(), 2);
    assert!(selection
        .urls
        .iter()
        .any(|url| url == "https://csrc.nist.gov/pubs/ir/8413/upd1/final"));
    assert!(selection.urls.iter().any(|url| {
        url == "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf"
    }));
}

#[test]
fn lint_allows_grounded_same_authority_fill_for_document_briefing() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("contract");
    let discovery_sources = vec![
        WebSource {
            source_id: "official-fips-203".to_string(),
            rank: Some(1),
            url: "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
            title: Some(
                "FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism Standard"
                    .to_string(),
            ),
            snippet: Some(
                "NIST finalized FIPS 203 as a post-quantum cryptography standard based on ML-KEM."
                    .to_string(),
            ),
            domain: Some("csrc.nist.gov".to_string()),
        },
        WebSource {
            source_id: "official-fips-204".to_string(),
            rank: Some(2),
            url: "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
            title: Some(
                "FIPS 204 Module-Lattice-Based Digital Signature Standard".to_string(),
            ),
            snippet: Some(
                "NIST finalized FIPS 204 as a post-quantum cryptography standard based on ML-DSA."
                    .to_string(),
            ),
            domain: Some("csrc.nist.gov".to_string()),
        },
    ];
    let left_family = pre_read_primary_authority_family_key(
        query,
        &discovery_sources[0].url,
        discovery_sources[0].title.as_deref().unwrap_or_default(),
        discovery_sources[0].snippet.as_deref().unwrap_or_default(),
    );
    let right_family = pre_read_primary_authority_family_key(
        query,
        &discovery_sources[1].url,
        discovery_sources[1].title.as_deref().unwrap_or_default(),
        discovery_sources[1].snippet.as_deref().unwrap_or_default(),
    );
    let payload_primary_authority_families = discovery_sources
        .iter()
        .filter(|source| {
            pre_read_source_has_primary_authority(
                query,
                &source.url,
                source.title.as_deref().unwrap_or_default(),
                source.snippet.as_deref().unwrap_or_default(),
            )
        })
        .map(|source| {
            pre_read_primary_authority_family_key(
                query,
                &source.url,
                source.title.as_deref().unwrap_or_default(),
                source.snippet.as_deref().unwrap_or_default(),
            )
        })
        .collect::<std::collections::BTreeSet<_>>()
        .len();

    assert!(pre_read_authority_source_required(
        Some(&retrieval_contract),
        query
    ));
    assert_ne!(left_family, right_family);
    assert_eq!(payload_primary_authority_families, 2);

    let selected = lint_pre_read_payload_urls(
        Some(&retrieval_contract),
        query,
        &discovery_sources,
        &[],
        &PreReadSelectionMode::DirectDetail,
        &[
            "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
            "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
        ],
        2,
    )
    .expect("grounded same-authority fill should pass");

    assert_eq!(selected.len(), 2);
}

#[test]
fn deterministic_pre_read_selection_allows_grounded_same_authority_fill() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("contract");
    let discovery_sources = vec![
        WebSource {
            source_id: "official-fips-203".to_string(),
            rank: Some(1),
            url: "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
            title: Some(
                "FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism Standard"
                    .to_string(),
            ),
            snippet: Some(
                "NIST finalized FIPS 203 as a post-quantum cryptography standard based on ML-KEM."
                    .to_string(),
            ),
            domain: Some("csrc.nist.gov".to_string()),
        },
        WebSource {
            source_id: "official-fips-204".to_string(),
            rank: Some(2),
            url: "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
            title: Some(
                "FIPS 204 Module-Lattice-Based Digital Signature Standard".to_string(),
            ),
            snippet: Some(
                "NIST finalized FIPS 204 as a post-quantum cryptography standard based on ML-DSA."
                    .to_string(),
            ),
            domain: Some("csrc.nist.gov".to_string()),
        },
    ];

    let selection = deterministic_pre_read_selection(
        Some(&retrieval_contract),
        query,
        2,
        &discovery_sources,
        &[],
    )
    .expect("grounded same-authority fill should satisfy deterministic selection");

    assert_eq!(selection.selection_mode, PreReadSelectionMode::DirectDetail);
    assert_eq!(
        selection.urls,
        vec![
            "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
            "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
        ]
    );
}

#[test]
fn lint_pre_read_payload_urls_requires_primary_authority_for_latest_pricing_queries() {
    let query = "What is the latest OpenAI API pricing?";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("contract");
    let discovery_sources = vec![
        WebSource {
            source_id: "official-openai-pricing".to_string(),
            rank: Some(1),
            url: "https://openai.com/api/pricing/".to_string(),
            title: Some(
                "OpenAI openai.com › api › pricing OpenAI API Pricing | OpenAI"
                    .to_string(),
            ),
            snippet: Some(
                "2 days ago - Explore OpenAI API pricing for GPT-5.4, multimodal models, and tools. Compare token costs, realtime, image, and video pricing, plus service tiers."
                    .to_string(),
            ),
            domain: Some("openai.com".to_string()),
        },
        WebSource {
            source_id: "third-party-pricing".to_string(),
            rank: Some(2),
            url: "https://www.arsturn.com/blog/making-sense-of-the-openai-apis-pricing-and-services"
                .to_string(),
            title: Some("OpenAI API Pricing & Services - A Comprehensive Guide".to_string()),
            snippet: Some(
                "April 24, 2025 - OpenAI o4-mini: A cost-efficient alternative to the o3 model with commendable performance metrics. Price: Input: $1.10 per 1M tokens, Cached input: $0.275 per 1M tokens, Output: $4.40 per 1M tokens."
                    .to_string(),
            ),
            domain: Some("www.arsturn.com".to_string()),
        },
    ];

    assert!(pre_read_authority_source_required(
        Some(&retrieval_contract),
        query
    ));
    assert!(pre_read_source_has_primary_authority(
        query,
        &discovery_sources[0].url,
        discovery_sources[0].title.as_deref().unwrap_or_default(),
        discovery_sources[0].snippet.as_deref().unwrap_or_default(),
    ));
    assert!(pre_read_source_counts_as_primary_authority(
        query,
        &discovery_sources[0].url,
        discovery_sources[0].title.as_deref().unwrap_or_default(),
        discovery_sources[0].snippet.as_deref().unwrap_or_default(),
    ));
    assert!(!pre_read_source_counts_as_primary_authority(
        query,
        &discovery_sources[1].url,
        discovery_sources[1].title.as_deref().unwrap_or_default(),
        discovery_sources[1].snippet.as_deref().unwrap_or_default(),
    ));
    let source_hints = discovery_source_hints(&discovery_sources);
    assert!(pre_read_candidate_url_allowed_for_query(
        Some(&retrieval_contract),
        query,
        1,
        &source_hints,
        None,
        &discovery_sources[0].url,
        discovery_sources[0].title.as_deref().unwrap_or_default(),
        discovery_sources[0].snippet.as_deref().unwrap_or_default(),
    ));
    assert!(pre_read_url_has_allowed_affordance(
        Some(&retrieval_contract),
        query,
        1,
        &source_hints,
        None,
        &discovery_sources[0].url,
        discovery_sources[0].title.as_deref().unwrap_or_default(),
        discovery_sources[0].snippet.as_deref().unwrap_or_default(),
    ));
    let payload_primary_authority_families = source_hints
        .iter()
        .filter(|hint| {
            pre_read_url_has_allowed_affordance(
                Some(&retrieval_contract),
                query,
                1,
                &source_hints,
                None,
                &hint.url,
                hint.title.as_deref().unwrap_or_default(),
                &hint.excerpt,
            ) && pre_read_source_counts_as_primary_authority(
                query,
                &hint.url,
                hint.title.as_deref().unwrap_or_default(),
                &hint.excerpt,
            )
        })
        .map(|hint| {
            pre_read_primary_authority_family_key(
                query,
                &hint.url,
                hint.title.as_deref().unwrap_or_default(),
                &hint.excerpt,
            )
        })
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    assert_eq!(payload_primary_authority_families, 1);
    let rejection = lint_pre_read_payload_urls(
        Some(&retrieval_contract),
        query,
        &discovery_sources,
        &[],
        &PreReadSelectionMode::DirectDetail,
        &[
            "https://www.arsturn.com/blog/making-sense-of-the-openai-apis-pricing-and-services"
                .to_string(),
        ],
        1,
    )
    .expect_err("third-party pricing page should not satisfy authority floor");
    assert!(rejection.contains("primary authority"));

    let selected = lint_pre_read_payload_urls(
        Some(&retrieval_contract),
        query,
        &discovery_sources,
        &[],
        &PreReadSelectionMode::DirectDetail,
        &["https://openai.com/api/pricing/".to_string()],
        1,
    )
    .expect("official pricing page should satisfy authority floor");
    assert_eq!(
        selected,
        vec!["https://openai.com/api/pricing/".to_string()]
    );
}

#[test]
fn lint_rejects_duplicate_authority_family_fill_for_document_briefing() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("contract");
    let discovery_sources = vec![
        WebSource {
            source_id: "official-ir-8413-update".to_string(),
            rank: Some(1),
            url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            snippet: Some(
                "The report references FIPS 203, FIPS 204, and FIPS 205 in the NIST post-quantum cryptography standardization process."
                    .to_string(),
            ),
            domain: Some("csrc.nist.gov".to_string()),
        },
        WebSource {
            source_id: "official-ir-8413".to_string(),
            rank: Some(2),
            url: "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            snippet: Some(
                "The report references FIPS 203, FIPS 204, and FIPS 205 in the NIST post-quantum cryptography standardization process."
                    .to_string(),
            ),
            domain: Some("csrc.nist.gov".to_string()),
        },
    ];

    let err = lint_pre_read_payload_urls(
        Some(&retrieval_contract),
        query,
        &discovery_sources,
        &[],
        &PreReadSelectionMode::DirectDetail,
        &[
            "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
        ],
        2,
    )
    .expect_err("duplicate authority family fill should fail lint");

    assert!(err.contains("distinct domains"));
}

#[test]
fn deterministic_pre_read_selection_avoids_duplicate_authority_family_fill() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("contract");
    let discovery_sources = vec![
        WebSource {
            source_id: "official-ir-8413-update".to_string(),
            rank: Some(1),
            url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            snippet: Some(
                "The report references FIPS 203, FIPS 204, and FIPS 205 in the NIST post-quantum cryptography standardization process."
                    .to_string(),
            ),
            domain: Some("csrc.nist.gov".to_string()),
        },
        WebSource {
            source_id: "official-ir-8413".to_string(),
            rank: Some(2),
            url: "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            snippet: Some(
                "The report references FIPS 203, FIPS 204, and FIPS 205 in the NIST post-quantum cryptography standardization process."
                    .to_string(),
            ),
            domain: Some("csrc.nist.gov".to_string()),
        },
        WebSource {
            source_id: "official-news".to_string(),
            rank: Some(3),
            url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
            title: Some(
                "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                    .to_string(),
            ),
            snippet: Some(
                "NIST released FIPS 203, FIPS 204, and FIPS 205 as its first three finalized post-quantum cryptography standards."
                    .to_string(),
            ),
            domain: Some("www.nist.gov".to_string()),
        },
    ];

    let selection = deterministic_pre_read_selection(
        Some(&retrieval_contract),
        query,
        2,
        &discovery_sources,
        &[],
    )
    .expect("deterministic selection should avoid duplicate authority-family fill");

    assert_eq!(selection.selection_mode, PreReadSelectionMode::DirectDetail);
    assert_eq!(selection.urls.len(), 2);
    assert!(selection
        .urls
        .iter()
        .any(|url| url.contains("csrc.nist.gov/pubs/ir/8413/")));
    assert!(selection.urls.iter().any(|url| {
        url == "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
    }));
}

#[test]
fn lint_pre_read_payload_urls_rejects_same_authority_fill_when_cross_domain_option_exists() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("contract");
    let discovery_sources = vec![
        WebSource {
            source_id: "official-fips-203".to_string(),
            rank: Some(1),
            url: "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
            title: Some(
                "FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism Standard"
                    .to_string(),
            ),
            snippet: Some(
                "NIST finalized FIPS 203 as a post-quantum cryptography standard based on ML-KEM."
                    .to_string(),
            ),
            domain: Some("csrc.nist.gov".to_string()),
        },
        WebSource {
            source_id: "official-fips-204".to_string(),
            rank: Some(2),
            url: "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
            title: Some(
                "FIPS 204 Module-Lattice-Based Digital Signature Standard".to_string(),
            ),
            snippet: Some(
                "NIST finalized FIPS 204 as a post-quantum cryptography standard based on ML-DSA."
                    .to_string(),
            ),
            domain: Some("csrc.nist.gov".to_string()),
        },
        WebSource {
            source_id: "official-news".to_string(),
            rank: Some(3),
            url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
            title: Some(
                "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                    .to_string(),
            ),
            snippet: Some(
                "NIST released FIPS 203, FIPS 204, and FIPS 205 as its first three finalized post-quantum cryptography standards."
                    .to_string(),
            ),
            domain: Some("www.nist.gov".to_string()),
        },
    ];

    let err = lint_pre_read_payload_urls(
        Some(&retrieval_contract),
        query,
        &discovery_sources,
        &[],
        &PreReadSelectionMode::DirectDetail,
        &[
            "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
            "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
        ],
        2,
    )
    .expect_err("same-domain fill should fail when a cross-domain official option exists");

    assert!(err.contains("expected at least 2 distinct domains"));
}

#[test]
fn deterministic_pre_read_selection_prefers_cross_domain_authority_fill_when_available() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("contract");
    let discovery_sources = vec![
        WebSource {
            source_id: "official-fips-203".to_string(),
            rank: Some(1),
            url: "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
            title: Some(
                "FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism Standard"
                    .to_string(),
            ),
            snippet: Some(
                "NIST finalized FIPS 203 as a post-quantum cryptography standard based on ML-KEM."
                    .to_string(),
            ),
            domain: Some("csrc.nist.gov".to_string()),
        },
        WebSource {
            source_id: "official-fips-204".to_string(),
            rank: Some(2),
            url: "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
            title: Some(
                "FIPS 204 Module-Lattice-Based Digital Signature Standard".to_string(),
            ),
            snippet: Some(
                "NIST finalized FIPS 204 as a post-quantum cryptography standard based on ML-DSA."
                    .to_string(),
            ),
            domain: Some("csrc.nist.gov".to_string()),
        },
        WebSource {
            source_id: "official-news".to_string(),
            rank: Some(3),
            url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
            title: Some(
                "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                    .to_string(),
            ),
            snippet: Some(
                "NIST released FIPS 203, FIPS 204, and FIPS 205 as its first three finalized post-quantum cryptography standards."
                    .to_string(),
            ),
            domain: Some("www.nist.gov".to_string()),
        },
    ];

    let selection = deterministic_pre_read_selection(
        Some(&retrieval_contract),
        query,
        2,
        &discovery_sources,
        &[],
    )
    .expect("cross-domain authority fill should satisfy deterministic selection");

    assert_eq!(selection.selection_mode, PreReadSelectionMode::DirectDetail);
    assert_eq!(selection.urls.len(), 2);
    assert!(selection
        .urls
        .iter()
        .any(|url| url.contains("csrc.nist.gov/pubs/fips/203/final")));
    assert!(selection.urls.iter().any(|url| {
        url.contains("www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards")
    }));
}
