use super::*;

#[test]
fn document_briefing_layout_wins_for_one_page_briefing_queries() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    assert!(query_prefers_document_briefing_layout(query));
    assert!(query_requires_structured_synthesis(query));
    assert!(!query_prefers_multi_item_cardinality(query));
}

#[test]
fn explicit_multi_item_shape_overrides_document_briefing_layout() {
    let query = "Write a briefing comparing the top three post-quantum cryptography standards.";
    assert!(!query_prefers_document_briefing_layout(query));
    assert!(query_prefers_multi_item_cardinality(query));
}
