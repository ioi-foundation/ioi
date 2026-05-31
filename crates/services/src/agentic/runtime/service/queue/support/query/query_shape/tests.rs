use super::*;

#[test]
fn document_report_layout_wins_for_one_page_answer_queries() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    assert!(query_prefers_document_report_layout(query));
    assert!(query_requires_structured_synthesis(query));
    assert!(!query_prefers_multi_item_cardinality(query));
}

#[test]
fn explicit_multi_item_shape_overrides_document_report_layout() {
    let query = "Write a briefing comparing the top three post-quantum cryptography standards.";
    assert!(!query_prefers_document_report_layout(query));
    assert!(query_prefers_multi_item_cardinality(query));
}

#[test]
fn specific_current_comparisons_are_not_generic_headline_collections() {
    let query = "Which is a better investment right now, Akash or Filecoin?";

    assert!(query_requests_comparison(query));
    assert!(query_prefers_multi_item_cardinality(query));
    assert!(!query_is_generic_headline_collection(query));
    assert!(query_requires_market_quote_grounding(query));
    assert!(query_metric_axes(query).contains(&MetricAxis::Price));
    let groups = query_market_quote_entity_anchor_groups(query);
    assert_eq!(groups.len(), 2);
    assert!(groups[0].contains("akash"));
    assert!(groups[1].contains("filecoin"));
    assert_eq!(
        market_quote_grounding_search_query(query).as_deref(),
        Some(
            "akash filecoin crypto token live price quote market cap USD today comparison investment use case performance risk investors"
        )
    );
}

#[test]
fn investment_comparisons_require_market_quotes_without_right_now_wording() {
    let query = "which is a better investment, filecoin or akash network?";

    assert!(query_requires_market_quote_grounding(query));
    let groups = query_market_quote_entity_anchor_groups(query);
    assert_eq!(groups.len(), 2);
    assert!(groups[0].contains("filecoin"));
    assert!(groups[1].contains("akash"));

    let hints = market_quote_grounding_direct_source_hints(query);
    let urls = hints
        .iter()
        .map(|hint| hint.url.as_str())
        .collect::<Vec<_>>();
    assert!(urls.contains(&"https://www.coingecko.com/en/coins/filecoin"));
    assert!(urls.contains(&"https://www.coingecko.com/en/coins/akash-network"));
}

#[test]
fn subject_specific_current_issue_queries_are_not_generic_headline_collections() {
    let query = "Find current sources for today's top local AI model runtime issue.";

    assert!(!prefers_single_fact_snapshot(query));
    assert!(query_prefers_multi_item_cardinality(query));
    assert!(!query_is_generic_headline_collection(query));
}
