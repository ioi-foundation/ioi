use super::{
    analyze_goal_signals, analyze_metric_schema, analyze_query_facets,
    analyze_source_record_signals, analyze_source_text_signals, infer_interaction_target,
    infer_report_sections, is_live_external_research_goal, is_mail_connector_tool_name,
    is_mailbox_connector_intent, query_semantic_anchor_tokens, query_structural_directive_tokens,
    report_section_label, GoalSignalProfile, MetricAxis, ReportSectionKind,
};

#[test]
fn live_external_research_signal_ignores_workspace_local_prompts() {
    assert!(is_live_external_research_goal(
        "As of now (UTC), summarize active provider incidents with citations"
    ));
    assert!(!is_live_external_research_goal(
        "As of now, search this repository for incident handler changes and cite files"
    ));
}

#[test]
fn infers_interaction_target_from_launch_goal() {
    let target = infer_interaction_target("Launch Visual Studio Code and open this folder")
        .expect("target should be inferred");
    assert_eq!(target.app_hint.as_deref(), Some("code"));
}

#[test]
fn infers_report_sections_from_query_signals() {
    let sections = infer_report_sections(
        "top incidents, what changed in last hour, user impact, workaround, eta confidence, citations",
    );
    assert!(sections.contains(&ReportSectionKind::Summary));
    assert!(sections.contains(&ReportSectionKind::RecentChange));
    assert!(sections.contains(&ReportSectionKind::UserImpact));
    assert!(sections.contains(&ReportSectionKind::Mitigation));
    assert!(sections.contains(&ReportSectionKind::EtaConfidence));
    assert!(sections.contains(&ReportSectionKind::Evidence));
    assert_eq!(
        report_section_label(ReportSectionKind::RecentChange, "what changed in last hour"),
        "What changed in the last hour"
    );
    assert_eq!(
        report_section_label(ReportSectionKind::RecentChange, "include last-hour change"),
        "What changed in the last hour"
    );
}

#[test]
fn source_signals_rank_operational_updates_above_roundups() {
    let status = analyze_source_text_signals(
        "Provider status page: investigating API outage, mitigation in progress, next update in 30 minutes.",
    );
    let roundup = analyze_source_text_signals("Weekly roundup and opinion analysis.");
    assert!(status.relevance_score(false) > roundup.relevance_score(false));
    assert!(roundup.low_priority_dominates());
}

#[test]
fn source_signals_prefer_primary_status_surface_over_secondary_aggregation() {
    let primary = analyze_source_record_signals(
        "https://status.vendor-a.com/incidents/12345",
        "Service health incident",
        "Investigating elevated API errors; next update in 30 minutes.",
    );
    let secondary = analyze_source_record_signals(
        "https://example-monitor.com/cloud/incidents",
        "Cloud status page aggregator",
        "Track incidents across providers with community outage reports.",
    );
    assert!(primary.primary_status_surface_hits > 0);
    assert!(primary.official_status_host_hits > 0);
    assert!(secondary.secondary_coverage_hits > 0);
    assert!(primary.relevance_score(false) > secondary.relevance_score(false));
}

#[test]
fn source_signals_demote_documentation_surface_vs_operational_status_host() {
    let status_host = analyze_source_record_signals(
        "https://status.vendor-a.com/incidents/12345",
        "Provider status incident",
        "Investigating elevated API errors with mitigation in progress.",
    );
    let docs_surface = analyze_source_record_signals(
        "https://learn.vendor-a.com/service-health/overview",
        "Service health overview",
        "Documentation overview for service health capabilities and guidance.",
    );

    assert!(status_host.official_status_host_hits > docs_surface.official_status_host_hits);
    assert!(docs_surface.documentation_surface_hits > 0);
    assert!(status_host.relevance_score(false) > docs_surface.relevance_score(false));
}

#[test]
fn goal_profile_handles_empty_input() {
    assert_eq!(analyze_goal_signals(""), GoalSignalProfile::default());
}

#[test]
fn mailbox_connector_signal_detects_personal_mailbox_intent() {
    assert!(is_mailbox_connector_intent(
        "Read me the latest email in my inbox"
    ));
    assert!(!is_live_external_research_goal(
        "Read me the latest email in my inbox"
    ));
}

#[test]
fn mailbox_connector_signal_ignores_general_web_queries() {
    assert!(!is_mailbox_connector_intent(
        "Find the latest cloud outage updates with citations"
    ));
    assert!(is_live_external_research_goal(
        "Find the latest cloud outage updates with citations"
    ));
}

#[test]
fn live_external_research_detects_time_sensitive_public_fact_lookups() {
    assert!(is_live_external_research_goal(
        "What's the weather right now in Anderson, SC?"
    ));
    assert!(is_live_external_research_goal(
        "Current USD to EUR exchange rate right now."
    ));
    assert!(!is_live_external_research_goal(
        "In this repository, what's the current weather parser logic?"
    ));
}

#[test]
fn mailbox_tool_name_signal_matches_connector_prefixes() {
    assert!(is_mail_connector_tool_name(
        "wallet_network__mail_read_latest"
    ));
    assert!(is_mail_connector_tool_name("wallet_mail_handle_intent"));
    assert!(!is_mail_connector_tool_name("web__search"));
}

#[test]
fn metric_schema_distinguishes_current_observation_from_forecast_horizon() {
    let current = analyze_metric_schema(
        "Current conditions as of 10:35 AM: temperature 62F, humidity 42%, wind 4 mph.",
    );
    let forecast = analyze_metric_schema("Tomorrow forecast: high 65, low 49, rain chance 60%.");
    assert!(current.has_metric_payload());
    assert!(current.has_current_observation_payload());
    assert!(forecast.has_metric_payload());
    assert!(!forecast.has_current_observation_payload());
    assert!(current.axis_hits.contains(&MetricAxis::Temperature));
    assert!(current.axis_hits.contains(&MetricAxis::Humidity));
    assert!(forecast.axis_hits.contains(&MetricAxis::Precipitation));
}

#[test]
fn query_facets_capture_time_sensitive_public_fact_contract() {
    let facets = analyze_query_facets("What's the weather right now with UTC timestamp?");
    assert!(facets.time_sensitive_public_fact);
    assert!(facets.locality_sensitive_public_fact);
    assert!(facets.grounded_external_required);
    assert!(!facets.workspace_constrained);

    let rate_facets =
        analyze_query_facets("Current USD to EUR exchange rate right now with sources.");
    assert!(rate_facets.time_sensitive_public_fact);
    assert!(!rate_facets.locality_sensitive_public_fact);
}

#[test]
fn semantic_anchor_tokens_exclude_structural_directives() {
    let query = "Current weather in Anderson, SC right now with sources and UTC timestamp.";
    let structural = query_structural_directive_tokens(query);
    assert!(structural.contains("sources"));
    assert!(structural.contains("utc"));
    assert!(structural.contains("timestamp"));

    let semantic = query_semantic_anchor_tokens(query);
    assert!(semantic.contains("weather"));
    assert!(semantic.contains("anderson"));
    assert!(!semantic.contains("sources"));
    assert!(!semantic.contains("utc"));
    assert!(!semantic.contains("timestamp"));
}
