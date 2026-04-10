#[test]
fn web_pipeline_runtime_locality_scope_keeps_near_me_unresolved_until_runtime_scope_is_bound() {
    let query = "Find the three best-reviewed Italian restaurants near me and compare their menus.";
    assert_eq!(explicit_query_scope_hint(query), None);
    assert!(query_requires_runtime_locality_scope(query));
}

#[test]
fn web_pipeline_resolved_query_contract_replaces_locality_placeholder_with_trusted_scope() {
    let query = "Find the three best-reviewed Italian restaurants near me and compare their menus.";
    let resolved = resolved_query_contract_with_locality_hint(query, Some("New York, NY"));
    let normalized = resolved.to_ascii_lowercase();
    assert!(
        normalized.contains("in new york, ny"),
        "resolved contract should bind the trusted locality: {}",
        resolved
    );
    assert!(
        !normalized.contains("near me"),
        "resolved contract should replace the unresolved placeholder: {}",
        resolved
    );
    assert!(
        normalized.contains("compare their menus"),
        "resolved contract should preserve the comparison clause: {}",
        resolved
    );
}

#[test]
fn web_pipeline_explicit_query_scope_hint_truncates_follow_on_comparison_clause() {
    let query =
        "Find the three best-reviewed Italian restaurants in New York and compare their menus.";
    assert_eq!(
        explicit_query_scope_hint(query).as_deref(),
        Some("New York")
    );
}

#[test]
fn web_pipeline_query_shape_detects_explicit_count_for_restaurant_comparison() {
    let query = "Find the three best-reviewed Italian restaurants near me and compare their menus.";
    assert_eq!(required_story_count(query), 3);
    assert!(query_prefers_multi_item_cardinality(query));
    assert!(query_requests_comparison(query));
    assert!(query_requires_structured_synthesis(query));
}

#[test]
fn web_pipeline_query_shape_detects_plural_briefing_research_without_headline_mode() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    assert_eq!(required_story_count(query), 1);
    assert!(!query_prefers_multi_item_cardinality(query));
    assert!(!prefers_single_fact_snapshot(query));
    assert!(query_requires_structured_synthesis(query));
    assert!(!query_is_generic_headline_collection(query));
}

#[test]
fn web_pipeline_select_query_contract_prefers_scope_grounded_retrieval_query() {
    let selected = select_web_pipeline_query_contract(
        "what's the weather right now",
        "what's the weather right now in Anderson, SC",
    );
    let normalized = selected.to_ascii_lowercase();
    assert!(normalized.starts_with("what's the weather right now in"));
    assert!(normalized.contains("anderson"));
    assert!(normalized.contains("sc"));
}

#[test]
fn web_pipeline_select_query_contract_preserves_goal_when_it_has_scope_and_retrieval_does_not() {
    let selected = select_web_pipeline_query_contract(
        "what's the weather right now in Anderson, SC",
        "what's the weather right now",
    );
    assert_eq!(selected, "what's the weather right now in Anderson, SC");
}

#[test]
fn web_pipeline_select_query_contract_drops_probe_term_inflation_from_retrieval_query() {
    let selected = select_web_pipeline_query_contract(
        "what's the weather right now",
        "what's the weather right now in Anderson, SC \"anderson weather\" \"anderson weather\" \"anderson weather\"",
    );
    let normalized = selected.to_ascii_lowercase();
    assert!(normalized.starts_with("what's the weather right now in"));
    assert!(normalized.contains("anderson"));
    assert!(normalized.contains("sc"));
    assert!(!normalized.contains("\""));
    assert!(
        !normalized.contains("anderson weather"),
        "scope merge should not include probe-term inflation: {}",
        selected
    );
}

#[test]
fn web_pipeline_select_query_contract_prefers_runtime_scope_over_probe_expansion() {
    std::env::set_var("IOI_SESSION_LOCALITY", "Anderson, SC");
    let selected = select_web_pipeline_query_contract(
        "What's the weather like right now?",
        "weather current conditions temperature humidity wind in Anderson, SC \"Anderson, SC\" \"observed now\"",
    );
    std::env::remove_var("IOI_SESSION_LOCALITY");
    assert_eq!(
        selected,
        "What's the weather like right now in Anderson, SC?"
    );
}

#[test]
fn web_pipeline_select_query_contract_rejects_semantic_fragment_as_scope() {
    let selected = select_web_pipeline_query_contract(
        "Find the three best-reviewed Italian restaurants near me and compare their menus.",
        "Find the three best-reviewed Italian restaurants in Anderson, SC italian restaurants menus Anderson, SC and compare their menus.",
    );
    assert_eq!(
        selected,
        "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus."
    );
}

#[test]
fn web_pipeline_select_query_contract_ignores_parent_playbook_context() {
    let selected = select_web_pipeline_query_contract(
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.\n\n[PARENT PLAYBOOK CONTEXT]\n- prep_summary: Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.",
        "nist post quantum cryptography standards parent playbook context prep summary site:context.gov site:nist.gov",
    );
    let normalized = selected.to_ascii_lowercase();
    assert!(
        !normalized.contains("parent playbook context"),
        "selected contract should ignore delegated parent context: {}",
        selected
    );
    assert!(
        !normalized.contains("prep_summary"),
        "selected contract should ignore prep summary leakage: {}",
        selected
    );
    assert!(normalized.contains("latest nist post-quantum cryptography standards"));
}
