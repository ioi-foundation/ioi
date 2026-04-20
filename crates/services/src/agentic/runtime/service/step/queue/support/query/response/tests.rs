use ioi_types::app::agentic::WebRetrievalContract;

use super::{
    required_citations_per_story, retrieval_contract_min_sources,
    retrieval_contract_primary_authority_source_slot_cap,
    retrieval_contract_required_distinct_citations,
    retrieval_contract_required_document_briefing_citation_count,
    retrieval_contract_required_support_count,
    retrieval_contract_requires_document_briefing_identifier_evidence,
    retrieval_contract_requires_primary_authority_source, retrieval_or_query_requests_comparison,
};

#[test]
fn document_briefing_support_count_follows_structural_source_independence_floor() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
        .expect("retrieval contract");

    assert_eq!(contract.source_independence_min, 2);
    assert_eq!(
        retrieval_contract_required_support_count(Some(&contract), query),
        2
    );
}

#[test]
fn document_briefing_distinct_citations_follow_structural_support_floor() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
        .expect("retrieval contract");

    assert_eq!(
        retrieval_contract_required_document_briefing_citation_count(Some(&contract), query),
        2
    );
    assert_eq!(
        retrieval_contract_required_distinct_citations(Some(&contract), query),
        2
    );
}

#[test]
fn document_briefing_identifier_evidence_is_not_required_without_generic_identifier_model() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
        .expect("retrieval contract");

    assert!(
        !retrieval_contract_requires_document_briefing_identifier_evidence(Some(&contract), query)
    );
}

#[test]
fn single_snapshot_min_sources_honors_citation_floor() {
    let query = "What's the current price of Bitcoin?";
    let contract = WebRetrievalContract {
        contract_version: "test.v1".to_string(),
        entity_cardinality_min: 1,
        comparison_required: false,
        currentness_required: true,
        runtime_locality_required: false,
        source_independence_min: 1,
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

    assert_eq!(retrieval_contract_min_sources(Some(&contract), query), 2);
}

#[test]
fn comparison_requests_fall_back_to_query_when_contract_is_absent() {
    let query =
        "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus.";

    assert!(retrieval_or_query_requests_comparison(None, query));
}

#[test]
fn generic_headline_collections_default_to_one_citation_per_story() {
    let query = "Tell me today's top news headlines.";
    let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
        .expect("retrieval contract");

    assert_eq!(required_citations_per_story(query), 1);
    assert_eq!(contract.citation_count_min, 1);
    assert!(contract.ordered_collection_preferred);
}

#[test]
fn single_snapshot_queries_default_to_one_citation_per_story() {
    let query = "What's the weather like right now in Anderson, SC?";
    let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
        .expect("retrieval contract");

    assert!(super::prefers_single_fact_snapshot(query));
    assert_eq!(required_citations_per_story(query), 1);
    assert_eq!(contract.citation_count_min, 1);
}

#[test]
fn latest_api_pricing_queries_require_primary_authority_source() {
    let query = "What is the latest OpenAI API pricing?";
    let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
        .expect("retrieval contract");

    assert!(contract.currentness_required);
    assert!(retrieval_contract_requires_primary_authority_source(
        Some(&contract),
        query
    ));
    assert_eq!(
        retrieval_contract_primary_authority_source_slot_cap(Some(&contract), query, 1),
        1
    );
}
