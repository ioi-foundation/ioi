use super::{is_search_results_url, is_search_scope, search_query_from_url};
use ioi_types::app::agentic::{IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState};

#[test]
fn detects_search_scope_from_resolved_intent() {
    let state = ResolvedIntentState {
        intent_id: "web.research".to_string(),
        scope: IntentScopeProfile::WebResearch,
        band: IntentConfidenceBand::High,
        score: 0.99,
        top_k: vec![],
        required_capabilities: vec![],
        required_receipts: vec![],
        required_postconditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        matrix_version: "v1".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        matrix_source_hash: [0u8; 32],
        receipt_hash: [0u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    };
    assert!(is_search_scope(Some(&state)));
    assert!(!is_search_scope(None));
}

#[test]
fn detects_search_result_urls() {
    assert!(is_search_results_url(
        "https://duckduckgo.com/?q=internet+of+intelligence"
    ));
    assert!(is_search_results_url(
        "https://www.google.com/search?q=internet+of+intelligence"
    ));
    assert!(!is_search_results_url("https://example.com/docs/ioi"));
}

#[test]
fn extracts_search_query_from_url() {
    assert_eq!(
        search_query_from_url("https://duckduckgo.com/?q=internet+of+intelligence").as_deref(),
        Some("internet of intelligence")
    );
}
