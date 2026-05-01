use super::*;

fn nist_briefing_contract() -> ioi_types::app::agentic::WebRetrievalContract {
    crate::agentic::web::derive_web_retrieval_contract(
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.",
        None,
    )
    .expect("retrieval contract")
}

#[test]
fn single_snapshot_source_selection_honors_support_and_citation_floor() {
    let query = "What's the current price of Bitcoin?";
    let retrieval_contract = ioi_types::app::agentic::WebRetrievalContract {
        contract_version: "test.v1".to_string(),
        entity_cardinality_min: 1,
        comparison_required: false,
        currentness_required: true,
        runtime_locality_required: false,
        source_independence_min: 2,
        citation_count_min: 2,
        structured_record_preferred: true,
        ordered_collection_preferred: false,
        link_collection_preferred: false,
        canonical_link_out_preferred: false,
        geo_scoped_detail_required: false,
        discovery_surface_required: false,
        entity_diversity_required: false,
        scalar_measure_required: true,
        browser_fallback_allowed: true,
    };
    let pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: Some(retrieval_contract),
        url: "https://www.worldcoinindex.com/coin/bitcoin".to_string(),
        started_step: 1,
        started_at_ms: 1_773_236_577_000,
        deadline_ms: 1_773_236_637_000,
        candidate_urls: vec![
            "https://www.worldcoinindex.com/coin/bitcoin".to_string(),
            "https://crypto.com/us/price/bitcoin".to_string(),
        ],
        candidate_source_hints: Vec::new(),
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.worldcoinindex.com/coin/bitcoin".to_string(),
                title: Some("Bitcoin price | index, chart and news | WorldCoinIndex".to_string()),
                excerpt: "Bitcoin price right now: $86,743.63 USD.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://crypto.com/us/price/bitcoin".to_string(),
                title: Some("Bitcoin price - Crypto.com".to_string()),
                excerpt: "BTC price: $86,741.12 USD.".to_string(),
            },
        ],
        min_sources: 2,
    };

    let draft =
        build_deterministic_story_draft(&pending, WebPipelineCompletionReason::MinSourcesReached);
    let required_story_count =
        retrieval_contract_required_story_count(pending.retrieval_contract.as_ref(), query);
    let required_support_count =
        retrieval_contract_required_support_count(pending.retrieval_contract.as_ref(), query);
    let required_citations =
        retrieval_contract_required_citations_per_story(pending.retrieval_contract.as_ref(), query)
            .max(1);
    let selected_source_target = required_story_count
        .max(required_support_count)
        .max(required_citations);
    let read_backed_urls = draft
        .stories
        .iter()
        .flat_map(|story| story.citation_ids.iter())
        .filter_map(|citation_id| draft.citations_by_id.get(citation_id))
        .filter(|citation| citation.from_successful_read)
        .map(|citation| citation.url.as_str())
        .collect::<BTreeSet<_>>();

    assert_eq!(selected_source_target, 2);
    assert_eq!(draft.stories.len(), selected_source_target);
    assert_eq!(read_backed_urls.len(), selected_source_target);
    assert!(read_backed_urls.contains("https://www.worldcoinindex.com/coin/bitcoin"));
    assert!(read_backed_urls.contains("https://crypto.com/us/price/bitcoin"));
}

#[test]
fn single_snapshot_source_selection_preserves_primary_authority_for_latest_pricing_queries() {
    let query = "What is the latest OpenAI API pricing?";
    let retrieval_contract = crate::agentic::web::derive_web_retrieval_contract(query, None)
        .expect("retrieval contract");
    let pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: Some(retrieval_contract),
        url: "https://duckduckgo.com/html/?q=openai+api+pricing".to_string(),
        started_step: 1,
        started_at_ms: 1_776_227_441_000,
        deadline_ms: 1_776_227_561_000,
        candidate_urls: vec![
            "https://openai.com/api/pricing/".to_string(),
            "https://www.arsturn.com/blog/making-sense-of-the-openai-apis-pricing-and-services"
                .to_string(),
        ],
        candidate_source_hints: Vec::new(),
        attempted_urls: Vec::new(),
        blocked_urls: Vec::new(),
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://openai.com/api/pricing/".to_string(),
                title: Some("OpenAI API Pricing | OpenAI".to_string()),
                excerpt: "Image: $8.00 for inputs $2.00 for cached inputs $32.00 for outputs Text: $5.00 for inputs $1.25 for cached inputs $10.00 for outputs".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.arsturn.com/blog/making-sense-of-the-openai-apis-pricing-and-services".to_string(),
                title: Some("OpenAI API Pricing & Services - A Comprehensive Guide".to_string()),
                excerpt: "Price: Input: $1".to_string(),
            },
        ],
        min_sources: 1,
    };

    let draft =
        build_deterministic_story_draft(&pending, WebPipelineCompletionReason::MinSourcesReached);
    assert_eq!(draft.stories.len(), 1);
    let cited_urls = draft
        .stories
        .iter()
        .flat_map(|story| story.citation_ids.iter())
        .filter_map(|citation_id| draft.citations_by_id.get(citation_id))
        .map(|citation| citation.url.as_str())
        .collect::<Vec<_>>();
    assert!(cited_urls
        .iter()
        .any(|url| { url.eq_ignore_ascii_case("https://openai.com/api/pricing/") }));
    assert!(!cited_urls.iter().any(|url| {
        url.eq_ignore_ascii_case(
            "https://www.arsturn.com/blog/making-sense-of-the-openai-apis-pricing-and-services",
        )
    }));
}

#[test]
fn single_snapshot_source_selection_prefers_explicit_current_role_holder_surface() {
    let query = "Who is the current Secretary-General of the UN?";
    let retrieval_contract = crate::agentic::web::derive_web_retrieval_contract(query, None)
        .expect("retrieval contract");
    let pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: Some(retrieval_contract),
        url: "https://search.brave.com/search?q=who+secretary+general".to_string(),
        started_step: 1,
        started_at_ms: 1_776_236_380_000,
        deadline_ms: 1_776_236_500_000,
        candidate_urls: vec![
            "https://ask.un.org/faq/14625".to_string(),
            "https://en.wikipedia.org/wiki/Ant%C3%B3nio_Guterres".to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://ask.un.org/faq/14625".to_string(),
                title: Some(
                    "UN Ask DAG ask.un.org faq 14625 Who is and has been Secretary-General of the United Nations? - Ask DAG!"
                        .to_string(),
                ),
                excerpt:
                    "Ant\u{f3}nio Guterres is the current Secretary-General of the United Nations."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://en.wikipedia.org/wiki/Ant%C3%B3nio_Guterres".to_string(),
                title: Some(
                    "Wikipedia en.wikipedia.org wiki Ant\u{f3}nio_Guterres Ant\u{f3}nio Guterres - Wikipedia"
                        .to_string(),
                ),
                excerpt:
                    "17 hours ago - Guterres was elected secretary-general in October 2016, succeeding Ban Ki-moon at the beginning of the following year."
                        .to_string(),
            },
        ],
        attempted_urls: vec![
            "https://ask.un.org/faq/14625".to_string(),
            "https://en.wikipedia.org/wiki/Ant%C3%B3nio_Guterres".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://ask.un.org/faq/14625".to_string(),
                title: Some(
                    "Who is and has been Secretary-General of the United Nations? - Ask DAG!"
                        .to_string(),
                ),
                excerpt:
                    "Ant\u{f3}nio Guterres is the current Secretary-General of the United Nations."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://en.wikipedia.org/wiki/Ant%C3%B3nio_Guterres".to_string(),
                title: Some("Ant\u{f3}nio Guterres - Wikipedia".to_string()),
                excerpt:
                    "17 hours ago - Guterres was elected secretary-general in October 2016, succeeding Ban Ki-moon at the beginning of the following year."
                        .to_string(),
            },
        ],
        min_sources: 1,
    };

    let draft =
        build_deterministic_story_draft(&pending, WebPipelineCompletionReason::MinSourcesReached);

    assert_eq!(draft.stories.len(), 1, "{draft:#?}");
    assert!(
        draft.stories[0].what_happened.contains(
            "Ant\u{f3}nio Guterres is the current Secretary-General of the United Nations."
        ),
        "{draft:#?}"
    );
    let cited_urls = draft.stories[0]
        .citation_ids
        .iter()
        .filter_map(|citation_id| draft.citations_by_id.get(citation_id))
        .map(|citation| citation.url.as_str())
        .collect::<Vec<_>>();
    assert!(
        cited_urls
            .iter()
            .any(|url| url.eq_ignore_ascii_case("https://ask.un.org/faq/14625")),
        "{draft:#?}"
    );
}

#[test]
fn document_briefing_source_selection_preserves_required_authority_identifier_coverage() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let pending = PendingSearchCompletion {
        query: "nist post quantum cryptography standards".to_string(),
        query_contract: query.to_string(),
        retrieval_contract: Some(nist_briefing_contract()),
        url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_773_177_742_000,
        deadline_ms: 1_773_177_802_000,
        candidate_urls: vec![
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
            "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
            "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/".to_string(),
            "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
        ],
        candidate_source_hints: Vec::new(),
        attempted_urls: vec![
            "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
        ],
        blocked_urls: Vec::new(),
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
                title: Some(
                    "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption"
                        .to_string(),
                ),
                excerpt: "NIST selected HQC as the fifth post-quantum algorithm for standardization in March 2025."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/"
                    .to_string(),
                title: Some("Diving into NIST's new post-quantum standards".to_string()),
                excerpt:
                    "The finalized standards set includes FIPS 203, FIPS 204, and FIPS 205."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                title: Some(
                    "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                        .to_string(),
                ),
                excerpt: "NIST released FIPS 203, FIPS 204, and FIPS 205 as the first finalized post-quantum encryption standards."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
                title: Some(
                    "Federal Information Processing Standard (FIPS) 204".to_string(),
                ),
                excerpt:
                    "Federal Information Processing Standard (FIPS) 204 specifies ML-DSA."
                        .to_string(),
            },
        ],
        min_sources: 2,
    };

    let draft =
        build_deterministic_story_draft(&pending, WebPipelineCompletionReason::MinSourcesReached);
    let required_sections = build_hybrid_required_sections(query);
    let required_support_count =
        retrieval_contract_required_support_count(pending.retrieval_contract.as_ref(), query);
    let facts = document_briefing_render_facts(&draft, &required_sections, required_support_count);
    let story_anchor_urls = draft
        .stories
        .iter()
        .filter_map(|story| story.citation_ids.first())
        .filter_map(|citation_id| draft.citations_by_id.get(citation_id))
        .map(|citation| citation.url.clone())
        .collect::<Vec<_>>();

    assert_eq!(required_support_count, 2);
    assert_eq!(draft.stories.len(), required_support_count);
    assert!(story_anchor_urls.iter().any(|url| {
        url == "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
    }));
    assert!(facts.authority_standard_identifier_floor_met);
}

#[test]
fn document_briefing_source_selection_handles_compressed_fips_enumerations() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let pending = PendingSearchCompletion {
        query: "nist post quantum cryptography standards".to_string(),
        query_contract: query.to_string(),
        retrieval_contract: Some(nist_briefing_contract()),
        url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_773_177_742_000,
        deadline_ms: 1_773_177_802_000,
        candidate_urls: vec![
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
            "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
            "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/".to_string(),
        ],
        candidate_source_hints: Vec::new(),
        attempted_urls: vec![
            "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
        ],
        blocked_urls: Vec::new(),
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
                title: Some(
                    "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption"
                        .to_string(),
                ),
                excerpt: "NIST selected HQC as the fifth algorithm, while the other finalized standards are FIPS 204 and FIPS 205."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/"
                    .to_string(),
                title: Some("Diving into NIST's new post-quantum standards".to_string()),
                excerpt:
                    "The finalized standards set includes FIPS 203, 204, and 205."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                title: Some(
                    "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                        .to_string(),
                ),
                excerpt:
                    "NIST released FIPS 203, 204, and 205 as the first finalized post-quantum encryption standards."
                        .to_string(),
            },
        ],
        min_sources: 2,
    };

    let draft =
        build_deterministic_story_draft(&pending, WebPipelineCompletionReason::MinSourcesReached);
    let required_sections = build_hybrid_required_sections(query);
    let required_support_count =
        retrieval_contract_required_support_count(pending.retrieval_contract.as_ref(), query);
    let facts = document_briefing_render_facts(&draft, &required_sections, required_support_count);
    let story_anchor_urls = draft
        .stories
        .iter()
        .filter_map(|story| story.citation_ids.first())
        .filter_map(|citation_id| draft.citations_by_id.get(citation_id))
        .map(|citation| citation.url.clone())
        .collect::<Vec<_>>();

    assert_eq!(required_support_count, 2);
    assert_eq!(draft.stories.len(), required_support_count);
    assert!(story_anchor_urls.iter().any(|url| {
        url == "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
    }));
    assert!(facts.authority_standard_identifier_floor_met);
}

#[test]
fn document_briefing_source_selection_repairs_authority_coverage_after_general_selection() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let pending = PendingSearchCompletion {
        query: "nist post quantum cryptography standards".to_string(),
        query_contract: query.to_string(),
        retrieval_contract: Some(nist_briefing_contract()),
        url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_773_177_742_000,
        deadline_ms: 1_773_177_802_000,
        candidate_urls: vec![
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
            "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
            "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/".to_string(),
        ],
        candidate_source_hints: Vec::new(),
        attempted_urls: vec![
            "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
        ],
        blocked_urls: Vec::new(),
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/".to_string(),
                title: Some("Diving Into NIST’s New Post-Quantum Standards".to_string()),
                excerpt: "NIST has released FIPS 203, FIPS 204, and FIPS 205 — three post-quantum cryptography standards that pave the way for a more secure future.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
                title: Some(
                    "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption | NIST"
                        .to_string(),
                ),
                excerpt: "Last year, NIST published an encryption standard based on ML-KEM. The new algorithm, called HQC, will serve as a backup defense. The other two finished standards, FIPS 204 and FIPS 205, contain digital signature algorithms.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                title: Some(
                    "NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST"
                        .to_string(),
                ),
                excerpt: "Federal Information Processing Standard (FIPS) 203 is based on ML-KEM, FIPS 204 is based on ML-DSA, and FIPS 205 is based on SLH-DSA.".to_string(),
            },
        ],
        min_sources: 2,
    };

    let draft =
        build_deterministic_story_draft(&pending, WebPipelineCompletionReason::MinSourcesReached);
    let required_support_count =
        retrieval_contract_required_support_count(pending.retrieval_contract.as_ref(), query);
    let story_anchor_urls = draft
        .stories
        .iter()
        .filter_map(|story| story.citation_ids.first())
        .filter_map(|citation_id| draft.citations_by_id.get(citation_id))
        .map(|citation| citation.url.clone())
        .collect::<Vec<_>>();

    assert_eq!(required_support_count, 2);
    assert_eq!(draft.stories.len(), required_support_count);
    assert!(story_anchor_urls.iter().any(|url| {
        url == "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
    }));
}

#[test]
fn document_briefing_retained_like_nist_reads_preserve_project_page_citation_surface() {
    let query = "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
    let retrieval_contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
        .expect("retrieval contract");
    let pending = PendingSearchCompletion {
        query: "nist post quantum cryptography standards".to_string(),
        query_contract: query.to_string(),
        retrieval_contract: Some(retrieval_contract),
        url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_775_118_581_000,
        deadline_ms: 1_775_118_641_000,
        candidate_urls: vec![
            "https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved"
                .to_string(),
            "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization"
                .to_string(),
            "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf"
                .to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved"
                    .to_string(),
                title: Some(
                    "NIST Releases First 3 Finalized Post-Quantum Encryption Standards | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "NIST finalized FIPS 203, FIPS 204, and FIPS 205 as its first post-quantum cryptography standards."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf"
                    .to_string(),
                title: Some("State of PQC Readiness 2025".to_string()),
                excerpt:
                    "Independent November 2025 report on post-quantum cryptography readiness after NIST finalized its first post-quantum standards."
                        .to_string(),
            },
        ],
        attempted_urls: vec![
            "https://www.ciodive.com/spons/building-organizational-readiness-for-post-quantum-cryptography/815308/"
                .to_string(),
            "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
        ],
        blocked_urls: Vec::new(),
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "The new public-key cryptography standards will specify additional digital signature, public-key encryption, and key-establishment algorithms to augment Federal Information Processing Standards 203, 204, and 205."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization"
                    .to_string(),
                title: Some("Post-Quantum Cryptography | CSRC".to_string()),
                excerpt:
                    "FIPS 203, FIPS 204, and FIPS 205 were published August 13, 2024 as the first finalized NIST post-quantum cryptography standards."
                        .to_string(),
            },
        ],
        min_sources: 2,
    };

    let draft =
        build_deterministic_story_draft(&pending, WebPipelineCompletionReason::ExhaustedCandidates);
    let rendered = render_user_synthesis_draft(&draft);
    let required_sections = build_hybrid_required_sections(query);
    let required_support_count =
        retrieval_contract_required_support_count(pending.retrieval_contract.as_ref(), query);
    let facts = document_briefing_render_facts(&draft, &required_sections, required_support_count);
    let project_page_url =
        "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization";
    let rendered_citation_lines = rendered
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("- ") && line.contains("http"))
        .collect::<Vec<_>>();

    assert_eq!(required_support_count, 2);
    assert_eq!(draft.stories.len(), required_support_count, "{draft:#?}");
    assert!(
        draft.citations_by_id.values().any(|candidate| {
            candidate.from_successful_read
                && candidate.url == project_page_url
                && candidate.excerpt.contains("FIPS 203")
                && candidate.excerpt.contains("FIPS 204")
                && candidate.excerpt.contains("FIPS 205")
        }),
        "{draft:#?}"
    );
    assert!(
        rendered_citation_lines
            .iter()
            .any(|line| line.contains(project_page_url)),
        "{rendered}"
    );
    assert!(
        rendered_citation_lines
            .iter()
            .any(|line| { line.contains("https://csrc.nist.gov/pubs/ir/8413/upd1/final") }),
        "{rendered}"
    );
    assert!(
        rendered_citation_lines.len() >= required_support_count,
        "{rendered}"
    );
    assert!(facts.summary_inventory_floor_met, "{facts:#?}\n{rendered}");
    assert!(facts.evidence_block_floor_met, "{facts:#?}\n{rendered}");
}

#[test]
fn document_briefing_source_finalization_trims_to_rendered_authority_coverage() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let terra = PendingSearchReadSummary {
        url: "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/"
            .to_string(),
        title: Some("Diving Into NIST’s New Post-Quantum Standards".to_string()),
        excerpt: "NIST has released FIPS 203, FIPS 204, and FIPS 205 as its first finalized post-quantum cryptography standards."
            .to_string(),
    };
    let nist_2025 = PendingSearchReadSummary {
        url: "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
        title: Some(
            "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption | NIST"
                .to_string(),
        ),
        excerpt: "Last year, NIST published an encryption standard based on ML-KEM. The other finished standards, FIPS 204 and FIPS 205, contain digital signature algorithms."
            .to_string(),
    };
    let nist_2024 = PendingSearchReadSummary {
        url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
        title: Some(
            "NIST nist.gov news events news 2024 08 nist releases first 3 finalized post quantum encryption standards NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST"
                .to_string(),
        ),
        excerpt: "Federal Information Processing Standard (FIPS) 203 is based on ML-KEM, FIPS 204 is based on ML-DSA, and FIPS 205 is based on SLH-DSA."
            .to_string(),
    };
    let candidates = vec![
        CitationCandidate {
            id: "terra".to_string(),
            url: terra.url.clone(),
            source_label: terra.title.clone().unwrap(),
            excerpt: terra.excerpt.clone(),
            timestamp_utc: "2026-03-11T00:00:00Z".to_string(),
            note: "retrieved_utc".to_string(),
            from_successful_read: true,
        },
        CitationCandidate {
            id: "nist_2025".to_string(),
            url: nist_2025.url.clone(),
            source_label: nist_2025.title.clone().unwrap(),
            excerpt: nist_2025.excerpt.clone(),
            timestamp_utc: "2026-03-11T00:00:00Z".to_string(),
            note: "retrieved_utc".to_string(),
            from_successful_read: true,
        },
        CitationCandidate {
            id: "nist_2024".to_string(),
            url: nist_2024.url.clone(),
            source_label: nist_2024.title.clone().unwrap(),
            excerpt: nist_2024.excerpt.clone(),
            timestamp_utc: "2026-03-11T00:00:00Z".to_string(),
            note: "retrieved_utc".to_string(),
            from_successful_read: true,
        },
    ];
    let source_pool = vec![terra.clone(), nist_2025.clone(), nist_2024.clone()];
    let mut selected_sources = vec![terra, nist_2025, nist_2024];
    let retrieval_contract = Some(nist_briefing_contract());

    finalize_document_briefing_selected_sources(
        retrieval_contract.as_ref(),
        query,
        &candidates,
        &source_pool,
        &mut selected_sources,
        2,
    );

    let selected_urls = selected_sources
        .iter()
        .map(|source| source.url.as_str())
        .collect::<Vec<_>>();

    assert_eq!(selected_sources.len(), 2);
    assert!(selected_urls.iter().any(|url| {
        *url
            == "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
    }));
    assert!(selected_urls.iter().any(|url| {
        *url == "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/"
    }));
}

#[test]
fn document_briefing_source_finalization_uses_renderable_citation_identifier_surfaces() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let terra = PendingSearchReadSummary {
        url: "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/"
            .to_string(),
        title: Some("Diving Into NIST’s New Post-Quantum Standards".to_string()),
        excerpt: "NIST has released FIPS 203, FIPS 204, and FIPS 205 as its first finalized post-quantum cryptography standards."
            .to_string(),
    };
    let nist_2025 = PendingSearchReadSummary {
        url: "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
        title: Some(
            "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption | NIST"
                .to_string(),
        ),
        excerpt: "Last year, NIST published an encryption standard based on ML-KEM. The other finished standards, FIPS 204 and FIPS 205, contain digital signature algorithms."
            .to_string(),
    };
    let nist_2024 = PendingSearchReadSummary {
        url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
        title: Some(
            "NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST"
                .to_string(),
        ),
        excerpt: "Federal Information Processing Standard (FIPS) 203 is based on ML-KEM, FIPS 204 is based on ML-DSA, and FIPS 205 is based on SLH-DSA."
            .to_string(),
    };
    let candidates = vec![
        CitationCandidate {
            id: "terra".to_string(),
            url: terra.url.clone(),
            source_label: terra.title.clone().unwrap(),
            excerpt: terra.excerpt.clone(),
            timestamp_utc: "2026-03-11T00:00:00Z".to_string(),
            note: "retrieved_utc".to_string(),
            from_successful_read: true,
        },
        CitationCandidate {
            id: "nist_2025".to_string(),
            url: nist_2025.url.clone(),
            source_label: nist_2025.title.clone().unwrap(),
            excerpt: "The other finished standards, FIPS 204 and FIPS 205, contain digital signature algorithms, while HQC will serve as a backup defense.".to_string(),
            timestamp_utc: "2026-03-11T00:00:00Z".to_string(),
            note: "retrieved_utc".to_string(),
            from_successful_read: true,
        },
        CitationCandidate {
            id: "nist_2024".to_string(),
            url: nist_2024.url.clone(),
            source_label: nist_2024.title.clone().unwrap(),
            excerpt: "NIST released FIPS 203, FIPS 204, and FIPS 205 as the first finalized post-quantum encryption standards.".to_string(),
            timestamp_utc: "2026-03-11T00:00:00Z".to_string(),
            note: "retrieved_utc".to_string(),
            from_successful_read: true,
        },
    ];
    let source_pool = vec![terra.clone(), nist_2025.clone(), nist_2024.clone()];
    let mut selected_sources = vec![terra, nist_2025];

    repair_document_briefing_authority_identifier_coverage(
        query,
        &candidates,
        &source_pool,
        &mut selected_sources,
        2,
    );
    finalize_document_briefing_selected_sources(
        Some(&nist_briefing_contract()),
        query,
        &candidates,
        &source_pool,
        &mut selected_sources,
        2,
    );

    let selected_urls = selected_sources
        .iter()
        .map(|source| source.url.as_str())
        .collect::<Vec<_>>();

    assert_eq!(selected_sources.len(), 2);
    assert!(selected_urls.iter().any(|url| {
        *url
            == "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
    }));
    assert!(selected_urls.iter().any(|url| {
        *url == "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/"
    }));
}

#[test]
fn document_briefing_story_citation_repair_backfills_missing_authority_identifiers() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract = Some(nist_briefing_contract());
    let terra = PendingSearchReadSummary {
        url: "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/"
            .to_string(),
        title: Some("Diving Into NIST’s New Post-Quantum Standards".to_string()),
        excerpt: "NIST has released FIPS 203, FIPS 204, and FIPS 205 as its first finalized post-quantum cryptography standards."
            .to_string(),
    };
    let nist_2025 = PendingSearchReadSummary {
        url: "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
        title: Some(
            "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption | NIST"
                .to_string(),
        ),
        excerpt: "The other finished standards, FIPS 204 and FIPS 205, contain digital signature algorithms while HQC serves as a backup."
            .to_string(),
    };
    let nist_2024 = PendingSearchReadSummary {
        url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
        title: Some(
            "NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST"
                .to_string(),
        ),
        excerpt: "NIST released FIPS 203, FIPS 204, and FIPS 205 as the first finalized post-quantum encryption standards."
            .to_string(),
    };
    let candidates = vec![
        CitationCandidate {
            id: "terra".to_string(),
            url: terra.url.clone(),
            source_label: terra.title.clone().unwrap(),
            excerpt: terra.excerpt.clone(),
            timestamp_utc: "2026-03-11T00:00:00Z".to_string(),
            note: "retrieved_utc".to_string(),
            from_successful_read: true,
        },
        CitationCandidate {
            id: "nist_2025".to_string(),
            url: nist_2025.url.clone(),
            source_label: nist_2025.title.clone().unwrap(),
            excerpt: nist_2025.excerpt.clone(),
            timestamp_utc: "2026-03-11T00:00:00Z".to_string(),
            note: "retrieved_utc".to_string(),
            from_successful_read: true,
        },
        CitationCandidate {
            id: "nist_2024".to_string(),
            url: nist_2024.url.clone(),
            source_label: nist_2024.title.clone().unwrap(),
            excerpt: nist_2024.excerpt.clone(),
            timestamp_utc: "2026-03-11T00:00:00Z".to_string(),
            note: "retrieved_utc".to_string(),
            from_successful_read: true,
        },
    ];
    let citations_by_id = candidates
        .iter()
        .map(|candidate| (candidate.id.clone(), candidate.clone()))
        .collect::<BTreeMap<_, _>>();
    let story_sources = vec![terra.clone(), nist_2025.clone()];
    let mut stories = vec![
        StoryDraft {
            title: terra.title.clone().unwrap(),
            what_happened: terra.excerpt.clone(),
            changed_last_hour: String::new(),
            why_it_matters: String::new(),
            user_impact: String::new(),
            workaround: String::new(),
            eta_confidence: "high".to_string(),
            citation_ids: vec!["terra".to_string(), "nist_2025".to_string()],
            confidence: "high".to_string(),
            caveat: "retrieved_utc".to_string(),
        },
        StoryDraft {
            title: nist_2025.title.clone().unwrap(),
            what_happened: nist_2025.excerpt.clone(),
            changed_last_hour: String::new(),
            why_it_matters: String::new(),
            user_impact: String::new(),
            workaround: String::new(),
            eta_confidence: "high".to_string(),
            citation_ids: vec!["nist_2025".to_string(), "terra".to_string()],
            confidence: "high".to_string(),
            caveat: "retrieved_utc".to_string(),
        },
    ];

    repair_document_briefing_story_citation_coverage(
        retrieval_contract.as_ref(),
        query,
        &story_sources,
        &mut stories,
        &candidates,
        &citations_by_id,
        2,
    );

    let selected_urls = stories
        .iter()
        .flat_map(|story| story.citation_ids.iter())
        .filter_map(|citation_id| citations_by_id.get(citation_id))
        .map(|citation| citation.url.as_str())
        .collect::<BTreeSet<_>>();
    assert!(selected_urls.contains(
        "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
    ));

    let draft = SynthesisDraft {
        query: query.to_string(),
        retrieval_contract,
        run_date: "2026-03-11".to_string(),
        run_timestamp_ms: 1_773_192_000_000,
        run_timestamp_iso_utc: "2026-03-11T00:00:00Z".to_string(),
        completion_reason: "min_sources_reached".to_string(),
        overall_confidence: "high".to_string(),
        overall_caveat: "retrieved_utc".to_string(),
        stories,
        citations_by_id,
        blocked_urls: Vec::new(),
        partial_note: None,
    };
    let required_sections = build_hybrid_required_sections(query);
    let facts = document_briefing_render_facts(&draft, &required_sections, 2);

    assert!(facts.authority_standard_identifier_floor_met);
    assert!(facts.summary_inventory_floor_met);
}

#[test]
fn document_briefing_story_citation_repair_preserves_corroborating_slot_once_authority_floor_is_met(
) {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract = Some(nist_briefing_contract());
    let update = PendingSearchReadSummary {
        url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
        title: Some(
            "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                .to_string(),
        ),
        excerpt:
            "NIST's current authoritative publication set for the post-quantum cryptography standardization process includes IR 8413."
                .to_string(),
    };
    let final_report = PendingSearchReadSummary {
        url: "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
        title: Some(
            "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                .to_string(),
        ),
        excerpt:
            "IR 8413 documents the authoritative NIST status report for the post-quantum cryptography standardization process."
                .to_string(),
    };
    let terra = PendingSearchReadSummary {
        url: "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/"
            .to_string(),
        title: Some("Diving Into NIST’s New Post-Quantum Standards".to_string()),
        excerpt: "Independent coverage summarizing NIST's post-quantum cryptography standards."
            .to_string(),
    };
    let candidates = vec![
        CitationCandidate {
            id: "update".to_string(),
            url: update.url.clone(),
            source_label: update.title.clone().unwrap(),
            excerpt: update.excerpt.clone(),
            timestamp_utc: "2026-04-02T01:48:07Z".to_string(),
            note: "retrieved_utc".to_string(),
            from_successful_read: true,
        },
        CitationCandidate {
            id: "final".to_string(),
            url: final_report.url.clone(),
            source_label: final_report.title.clone().unwrap(),
            excerpt: final_report.excerpt.clone(),
            timestamp_utc: "2026-04-02T01:48:07Z".to_string(),
            note: "retrieved_utc".to_string(),
            from_successful_read: true,
        },
        CitationCandidate {
            id: "terra".to_string(),
            url: terra.url.clone(),
            source_label: terra.title.clone().unwrap(),
            excerpt: terra.excerpt.clone(),
            timestamp_utc: "2026-04-02T01:48:07Z".to_string(),
            note: "retrieved_utc".to_string(),
            from_successful_read: true,
        },
    ];
    let citations_by_id = candidates
        .iter()
        .map(|candidate| (candidate.id.clone(), candidate.clone()))
        .collect::<BTreeMap<_, _>>();
    let story_sources = vec![update.clone(), terra.clone()];
    let mut stories = vec![StoryDraft {
        title: update.title.clone().unwrap(),
        what_happened: update.excerpt.clone(),
        changed_last_hour: String::new(),
        why_it_matters: String::new(),
        user_impact: String::new(),
        workaround: String::new(),
        eta_confidence: "medium".to_string(),
        citation_ids: vec!["update".to_string(), "terra".to_string()],
        confidence: "medium".to_string(),
        caveat: "retrieved_utc".to_string(),
    }];

    repair_document_briefing_story_citation_coverage(
        retrieval_contract.as_ref(),
        query,
        &story_sources,
        &mut stories,
        &candidates,
        &citations_by_id,
        2,
    );

    let selected_urls = stories
        .iter()
        .flat_map(|story| story.citation_ids.iter())
        .filter_map(|citation_id| citations_by_id.get(citation_id))
        .map(|citation| citation.url.as_str())
        .collect::<BTreeSet<_>>();

    assert!(selected_urls.contains("https://csrc.nist.gov/pubs/ir/8413/upd1/final"));
    assert!(selected_urls
        .contains("https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/"));
    assert!(!selected_urls.contains("https://csrc.nist.gov/pubs/ir/8413/final"));
}

#[test]
fn selected_source_citation_backfill_preserves_authoritative_briefing_sources() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let terra = PendingSearchReadSummary {
        url: "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/"
            .to_string(),
        title: Some("Diving Into NIST’s New Post-Quantum Standards".to_string()),
        excerpt: "NIST has released FIPS 203, FIPS 204, and FIPS 205 as its first finalized post-quantum cryptography standards."
            .to_string(),
    };
    let nist_2025 = PendingSearchReadSummary {
        url: "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
        title: Some(
            "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption | NIST"
                .to_string(),
        ),
        excerpt: "The other finished standards, FIPS 204 and FIPS 205, contain digital signature algorithms while HQC serves as a backup."
            .to_string(),
    };
    let nist_2024 = PendingSearchReadSummary {
        url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
        title: Some(
            "NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST"
                .to_string(),
        ),
        excerpt: "NIST released FIPS 203, FIPS 204, and FIPS 205 as the first finalized post-quantum encryption standards."
            .to_string(),
    };
    let retrieval_contract = Some(nist_briefing_contract());
    let mut candidates = vec![
        CitationCandidate {
            id: "C1".to_string(),
            url: terra.url.clone(),
            source_label: terra.title.clone().unwrap(),
            excerpt: terra.excerpt.clone(),
            timestamp_utc: "2026-03-11T00:00:00Z".to_string(),
            note: "retrieved_utc".to_string(),
            from_successful_read: true,
        },
        CitationCandidate {
            id: "C2".to_string(),
            url: nist_2025.url.clone(),
            source_label: nist_2025.title.clone().unwrap(),
            excerpt: nist_2025.excerpt.clone(),
            timestamp_utc: "2026-03-11T00:00:00Z".to_string(),
            note: "retrieved_utc".to_string(),
            from_successful_read: true,
        },
    ];
    let mut citations_by_id = candidates
        .iter()
        .map(|candidate| (candidate.id.clone(), candidate.clone()))
        .collect::<BTreeMap<_, _>>();

    backfill_selected_source_citation_candidates(
        query,
        retrieval_contract.as_ref(),
        2,
        &[terra.clone(), nist_2025.clone(), nist_2024.clone()],
        "2026-03-11T00:00:00Z",
        &mut candidates,
        &mut citations_by_id,
    );

    let backfilled = candidates
        .iter()
        .find(|candidate| {
            candidate.url
                == "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
        })
        .expect("backfilled citation");
    let required_labels = required_document_briefing_identifier_labels(
        query,
        &[terra.clone(), nist_2025.clone(), nist_2024.clone()],
        &candidates,
    );
    let authority_labels = document_briefing_candidate_authoritative_required_identifier_labels(
        query,
        backfilled,
        &required_labels,
    );

    assert_eq!(candidates.len(), 3);
    assert!(authority_labels.contains("FIPS 203"));
    assert!(authority_labels.contains("FIPS 204"));
    assert!(authority_labels.contains("FIPS 205"));
    assert!(citations_by_id.contains_key(&backfilled.id));
}

#[test]
fn document_briefing_identifier_surface_for_source_keeps_selected_source_excerpt_when_matching_citation_is_narrower(
) {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let project_page = PendingSearchReadSummary {
        url: "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization".to_string(),
        title: Some("Post-Quantum Cryptography | CSRC".to_string()),
        excerpt: "NIST finalized FIPS 203, FIPS 204, and FIPS 205 as its first post-quantum cryptography standards."
            .to_string(),
    };
    let candidates = vec![CitationCandidate {
        id: "project".to_string(),
        url: project_page.url.clone(),
        source_label: project_page.title.clone().unwrap(),
        excerpt: "The project page tracks NIST's post-quantum cryptography standardization effort."
            .to_string(),
        timestamp_utc: "2026-04-02T08:10:17Z".to_string(),
        note: "retrieved_utc".to_string(),
        from_successful_read: true,
    }];
    let required_labels = ["FIPS 203", "FIPS 204", "FIPS 205"]
        .into_iter()
        .map(str::to_string)
        .collect::<BTreeSet<_>>();

    let labels = document_briefing_required_identifier_labels_for_source(
        query,
        &project_page,
        &candidates,
        &required_labels,
    );

    assert!(labels.contains("FIPS 203"));
    assert!(labels.contains("FIPS 204"));
    assert!(labels.contains("FIPS 205"));
}

#[test]
fn backfill_selected_source_citation_candidates_upgrades_existing_candidate_excerpt_for_identifier_coverage(
) {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let project_page = PendingSearchReadSummary {
        url: "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization".to_string(),
        title: Some("Post-Quantum Cryptography | CSRC".to_string()),
        excerpt: "NIST finalized FIPS 203, FIPS 204, and FIPS 205 as its first post-quantum cryptography standards."
            .to_string(),
    };
    let mut candidates = vec![CitationCandidate {
        id: "C1".to_string(),
        url: project_page.url.clone(),
        source_label: project_page.title.clone().unwrap(),
        excerpt: "The project page tracks NIST's post-quantum cryptography standardization effort."
            .to_string(),
        timestamp_utc: "2026-04-02T08:10:17Z".to_string(),
        note: "retrieved_utc".to_string(),
        from_successful_read: true,
    }];
    let mut citations_by_id = candidates
        .iter()
        .map(|candidate| (candidate.id.clone(), candidate.clone()))
        .collect::<BTreeMap<_, _>>();

    backfill_selected_source_citation_candidates(
        query,
        Some(&nist_briefing_contract()),
        2,
        std::slice::from_ref(&project_page),
        "2026-04-02T08:10:17Z",
        &mut candidates,
        &mut citations_by_id,
    );

    let updated = candidates
        .iter()
        .find(|candidate| candidate.id == "C1")
        .expect("existing candidate");
    let labels = source_briefing_standard_identifier_labels(
        query,
        &updated.url,
        &updated.source_label,
        &updated.excerpt,
    );

    assert_eq!(candidates.len(), 1);
    assert!(labels.contains("FIPS 203"));
    assert!(labels.contains("FIPS 204"));
    assert!(labels.contains("FIPS 205"));
    assert_eq!(
        citations_by_id.get("C1").expect("updated citation").excerpt,
        updated.excerpt
    );
}
