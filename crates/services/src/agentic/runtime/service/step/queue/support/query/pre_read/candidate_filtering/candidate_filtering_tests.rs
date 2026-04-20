use super::*;

#[test]
fn document_briefing_direct_citation_rejects_non_authority_source_without_identifier_signal() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let contract = crate::agentic::web::derive_web_retrieval_contract(query, None)
        .expect("retrieval contract");
    let projection = build_query_constraint_projection(query, 2, &[]);

    assert!(!projection_candidate_url_allowed_with_contract_and_projection(
        Some(&contract),
        query,
        &projection,
        "https://www.ibm.com/think/insights/post-quantum-cryptography-transition",
        "Post-quantum cryptography transition guidance",
        "March 2026 - IBM explains recent NIST post-quantum cryptography transition planning for enterprises."
    ));
}

#[test]
fn document_briefing_direct_citation_allows_authority_overview_without_identifier_signal() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let contract = crate::agentic::web::derive_web_retrieval_contract(query, None)
        .expect("retrieval contract");
    let projection = build_query_constraint_projection(query, 2, &[]);

    assert!(projection_candidate_url_allowed_with_contract_and_projection(
        Some(&contract),
        query,
        &projection,
        "https://www.nist.gov/pqc",
        "Post-quantum cryptography | NIST",
        "March 2026 - NIST provides post-quantum cryptography migration guidance for federal systems."
    ));
}

#[test]
fn document_briefing_direct_citation_allows_public_authority_publication_with_late_grounding_context(
) {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let contract = crate::agentic::web::derive_web_retrieval_contract(query, None)
        .expect("retrieval contract");
    let projection = build_query_constraint_projection(query, 2, &[]);
    let late_grounding_context = format!(
        "{} post-quantum cryptography standards migration guidance from the NIST PQC program.",
        "context ".repeat(24)
    );

    assert!(projection_candidate_url_allowed_with_contract_and_projection(
        Some(&contract),
        query,
        &projection,
        "https://csrc.nist.gov/pubs/fips/203/final",
        "Module-Lattice-Based Key-Encapsulation Mechanism Standard",
        &late_grounding_context,
    ));
}

#[test]
fn document_briefing_direct_citation_allows_grounded_external_publication_artifact_without_identifier_signal(
) {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let contract = crate::agentic::web::derive_web_retrieval_contract(query, None)
        .expect("retrieval contract");
    let projection = build_query_constraint_projection(query, 2, &[]);

    assert!(projection_candidate_url_allowed_with_contract_and_projection(
        Some(&contract),
        query,
        &projection,
        "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf",
        "State of PQC Readiness 2025",
        "Independent November 2025 report on post-quantum cryptography readiness after NIST finalized its first post-quantum standards."
    ));
}

#[test]
fn local_business_direct_citation_rejects_generic_aggregator_root_domain() {
    let query =
        "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus.";
    let projection = build_query_constraint_projection_with_locality_hint(
        query,
        3,
        &[],
        Some("New York, NY"),
    );

    assert!(!projection_candidate_url_allowed_with_contract_and_projection(
        None,
        query,
        &projection,
        "https://www.tripadvisor.com",
        "Tripadvisor: Best Italian Restaurants in New York",
        "Tripadvisor rankings and ratings for Italian restaurants in New York, NY."
    ));
}

#[test]
fn local_business_direct_citation_allows_grounded_menu_detail_surface() {
    let query =
        "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus.";
    let source_hints = vec![PendingSearchReadSummary {
        url: "https://www.carminesnyc.com/locations/upper-west-side/menus/dinner".to_string(),
        title: Some("Carmine's Upper West Side Dinner Menu".to_string()),
        excerpt:
            "Italian restaurant in New York, NY with family-style pasta, chicken parm and seafood."
                .to_string(),
    }];
    let projection = build_query_constraint_projection_with_locality_hint(
        query,
        3,
        &source_hints,
        Some("New York, NY"),
    );

    assert!(projection_candidate_url_allowed_with_contract_and_projection(
        None,
        query,
        &projection,
        &source_hints[0].url,
        source_hints[0].title.as_deref().unwrap_or_default(),
        &source_hints[0].excerpt,
    ));

    let affordances = retrieval_affordances_with_locality_hint(
        query,
        3,
        &source_hints,
        Some("New York, NY"),
        &source_hints[0].url,
        source_hints[0].title.as_deref().unwrap_or_default(),
        &source_hints[0].excerpt,
    );
    assert!(
        affordances.contains(&RetrievalAffordanceKind::DirectCitationRead),
        "expected direct-read affordance for grounded restaurant menu detail, got {:?}",
        affordances
    );
}

#[test]
fn single_snapshot_direct_citation_allows_official_pricing_authority_without_inline_quote_payload(
) {
    let query = "What is the latest OpenAI API pricing?";
    let contract = crate::agentic::web::derive_web_retrieval_contract(query, None)
        .expect("retrieval contract");
    let projection = build_query_constraint_projection(query, 1, &[]);

    assert!(projection_candidate_url_allowed_with_contract_and_projection(
        Some(&contract),
        query,
        &projection,
        "https://openai.com/api/pricing/",
        "OpenAI API Pricing | OpenAI",
        "Explore OpenAI API pricing for GPT-5.4, multimodal models, and tools. Compare token costs, realtime, image, and video pricing, plus service tiers."
    ));
}

#[test]
fn headline_article_surfaces_remain_direct_read_candidates() {
    let query = "Tell me today's top news headlines.";
    let source_hints = vec![
        PendingSearchReadSummary {
            url: "https://www.foxnews.com/us/example-breaking-story".to_string(),
            title: Some("Emergency response declared after major storm".to_string()),
            excerpt: "Officials declared an emergency response Wednesday morning."
                .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.reuters.com/world/europe/example-story/".to_string(),
            title: Some("European ministers agree on emergency aid package".to_string()),
            excerpt: "Ministers agreed to an aid package after overnight talks."
                .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://apnews.com/article/example-story".to_string(),
            title: Some("Federal agency expands investigation into outage".to_string()),
            excerpt: "Agency officials expanded an investigation late Tuesday.".to_string(),
        },
    ];

    for hint in &source_hints {
        let affordances = retrieval_affordances_with_locality_hint(
            query,
            3,
            &source_hints,
            None,
            &hint.url,
            hint.title.as_deref().unwrap_or_default(),
            &hint.excerpt,
        );
        assert!(
            affordances.contains(&RetrievalAffordanceKind::DirectCitationRead),
            "expected direct-read affordance for {:?}, got {:?}",
            hint,
            affordances
        );
    }
}
