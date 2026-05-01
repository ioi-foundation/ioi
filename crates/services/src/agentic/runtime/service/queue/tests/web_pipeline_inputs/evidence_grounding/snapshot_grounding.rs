#[test]
fn web_pipeline_single_snapshot_current_price_rejects_non_quote_price_page_excerpt() {
    let requested_url = "https://crypto.com/en/price/bitcoin";
    let retrieval_contract = WebRetrievalContract {
        entity_cardinality_min: 1,
        comparison_required: false,
        currentness_required: true,
        runtime_locality_required: false,
        source_independence_min: 1,
        citation_count_min: 1,
        structured_record_preferred: true,
        ordered_collection_preferred: false,
        link_collection_preferred: false,
        canonical_link_out_preferred: false,
        geo_scoped_detail_required: false,
        discovery_surface_required: false,
        entity_diversity_required: false,
        scalar_measure_required: true,
        browser_fallback_allowed: true,
        ..WebRetrievalContract::default()
    };
    let mut pending = PendingSearchCompletion {
        query: "What's the current price of Bitcoin?".to_string(),
        query_contract: "What's the current price of Bitcoin?".to_string(),
        retrieval_contract: Some(retrieval_contract),
        url: "https://search.brave.com/search?q=current+bitcoin+price".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some(
                "Bitcoin (BTC) Price Today: BTC Live Price, Charts, News - Crypto.com International"
                    .to_string(),
            ),
            excerpt: "80% in the last 24 hours".to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 1,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(requested_url.to_string()),
        sources: vec![WebSource {
            source_id: "source:crypto-price".to_string(),
            rank: None,
            url: requested_url.to_string(),
            title: Some(
                "Bitcoin (BTC) Price Today: BTC Live Price, Charts, News - Crypto.com International"
                    .to_string(),
            ),
            snippet: Some("80% in the last 24 hours".to_string()),
            domain: Some("crypto.com".to_string()),
        }],
        source_observations: vec![],
        documents: vec![WebDocument {
            source_id: "source:crypto-price".to_string(),
            url: requested_url.to_string(),
            title: Some(
                "Bitcoin (BTC) Price Today: BTC Live Price, Charts, News - Crypto.com International"
                    .to_string(),
            ),
            content_text: "80% in the last 24 hours".to_string(),
            content_hash: "hash".to_string(),
            quote_spans: vec![],
        }],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);

    assert!(
        pending.successful_reads.is_empty(),
        "current price snapshot contracts should reject non-quote percentage pages as successful evidence"
    );
}

#[test]
fn web_pipeline_single_snapshot_current_price_prefers_quote_metric_excerpt_when_available() {
    let requested_url = "https://crypto.com/en/price/bitcoin";
    let retrieval_contract = WebRetrievalContract {
        entity_cardinality_min: 1,
        comparison_required: false,
        currentness_required: true,
        runtime_locality_required: false,
        source_independence_min: 1,
        citation_count_min: 1,
        structured_record_preferred: true,
        ordered_collection_preferred: false,
        link_collection_preferred: false,
        canonical_link_out_preferred: false,
        geo_scoped_detail_required: false,
        discovery_surface_required: false,
        entity_diversity_required: false,
        scalar_measure_required: true,
        browser_fallback_allowed: true,
        ..WebRetrievalContract::default()
    };
    let mut pending = PendingSearchCompletion {
        query: "What's the current price of Bitcoin?".to_string(),
        query_contract: "What's the current price of Bitcoin?".to_string(),
        retrieval_contract: Some(retrieval_contract),
        url: "https://search.brave.com/search?q=current+bitcoin+price".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some(
                "Bitcoin (BTC) Price Today: BTC Live Price, Charts, News - Crypto.com International"
                    .to_string(),
            ),
            excerpt: "80% in the last 24 hours".to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 1,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(requested_url.to_string()),
        sources: vec![WebSource {
            source_id: "source:crypto-price".to_string(),
            rank: None,
            url: requested_url.to_string(),
            title: Some(
                "Bitcoin (BTC) Price Today: BTC Live Price, Charts, News - Crypto.com International"
                    .to_string(),
            ),
            snippet: Some("80% in the last 24 hours".to_string()),
            domain: Some("crypto.com".to_string()),
        }],
        source_observations: vec![],
        documents: vec![WebDocument {
            source_id: "source:crypto-price".to_string(),
            url: requested_url.to_string(),
            title: Some(
                "Bitcoin (BTC) Price Today: BTC Live Price, Charts, News - Crypto.com International"
                    .to_string(),
            ),
            content_text:
                "80% in the last 24 hours. Bitcoin price right now: $86,743.63 USD as of 17:23 UTC."
                    .to_string(),
            content_hash: "hash".to_string(),
            quote_spans: vec![],
        }],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);

    assert_eq!(pending.successful_reads.len(), 1);
    assert!(
        pending.successful_reads[0].excerpt.contains("$86,743"),
        "expected quote-bearing metric excerpt to win over non-price percentage text: {:?}",
        pending.successful_reads
    );
}

#[test]
fn current_price_query_grounding_excerpt_requires_price_quote_payload() {
    let retrieval_contract = WebRetrievalContract {
        entity_cardinality_min: 1,
        comparison_required: false,
        currentness_required: true,
        runtime_locality_required: false,
        source_independence_min: 1,
        citation_count_min: 1,
        structured_record_preferred: true,
        ordered_collection_preferred: false,
        link_collection_preferred: false,
        canonical_link_out_preferred: false,
        geo_scoped_detail_required: false,
        discovery_surface_required: false,
        entity_diversity_required: false,
        scalar_measure_required: true,
        browser_fallback_allowed: true,
        ..WebRetrievalContract::default()
    };
    let query = "What's the current price of Bitcoin?";
    let url = "https://crypto.com/en/price/bitcoin";
    let title = "Bitcoin (BTC) Price Today: BTC Live Price, Charts, News - Crypto.com International";
    assert!(!excerpt_has_query_grounding_signal_with_contract(
        Some(&retrieval_contract),
        query,
        1,
        url,
        title,
        "80% in the last 24 hours",
    ));
    assert!(excerpt_has_query_grounding_signal_with_contract(
        Some(&retrieval_contract),
        query,
        1,
        url,
        title,
        "Bitcoin price right now: $86,743.63 USD as of 17:23 UTC.",
    ));
}
