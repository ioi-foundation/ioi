use super::{
    analyze_goal_signals, analyze_metric_schema, analyze_query_facets,
    analyze_source_record_signals, analyze_source_text_signals, has_price_quote_payload,
    infer_interaction_target, infer_report_sections, is_live_external_research_goal,
    is_mail_connector_tool_name, is_mailbox_connector_intent, query_semantic_anchor_tokens,
    query_structural_directive_tokens, report_section_label, GoalSignalProfile, MetricAxis,
    ReportSectionKind,
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
fn live_external_research_signal_respects_explicit_browser_only_constraints() {
    assert!(!is_live_external_research_goal(
        "Navigate to the assigned MiniWoB page and complete the on-page task using browser tools only. Do not use web retrieval tools. Search the queue for fiber, switch the sort to Recently Updated, and verify the saved dispatch update was not persisted."
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
fn source_signals_demote_word_puzzle_content() {
    let puzzle = analyze_source_record_signals(
        "https://www.forbes.com/sites/example/2026/02/27/wordle-answer-saturday-february-28/",
        "Today’s Wordle hints and answer",
        "Wordle hints and answer for today.",
    );
    assert!(puzzle.low_priority_dominates());
}

#[test]
fn source_signals_demote_headline_roundup_and_horoscope_content() {
    let roundup = analyze_source_record_signals(
        "https://www.timesnownews.com/education/school-assembly-news-headlines-today-feb-28-top-national-international-sports-updates-thought-of-the-day-article-153711381",
        "School Assembly News Headlines Today (Feb 28)",
        "Top national, international and sports updates with thought of the day.",
    );
    let horoscope = analyze_source_record_signals(
        "https://www.today.com/life/astrology/march-2026-horoscopes-each-zodiac-sign-rcna260859",
        "March 2026 horoscopes for each zodiac sign",
        "Astrology predictions for each zodiac sign.",
    );
    assert!(roundup.low_priority_dominates());
    assert!(horoscope.low_priority_dominates());
}

#[test]
fn source_signals_demote_community_discussion_surfaces() {
    let discussion = analyze_source_record_signals(
        "https://community.example.com/discussions/bitcoin-price-outlook",
        "Bitcoin price outlook discussion thread",
        "Community discussion about where the price goes next.",
    );
    assert!(discussion.low_priority_hits > 0);
    assert!(discussion.low_priority_dominates());
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
fn goal_profile_treats_last_week_file_queries_as_recency_sensitive() {
    let profile =
        analyze_goal_signals("Find all PDF files on my computer modified in the last week.");
    assert!(profile.recency_hits > 0);
    assert!(profile.workspace_hits > 0 || profile.filesystem_hits > 0);
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
fn mailbox_connector_signal_detects_send_intent_without_personal_pronouns() {
    assert!(is_mailbox_connector_intent(
        "Draft an email to team@ioi.network saying tomorrow's standup is moved to 2 PM and send it."
    ));
    assert!(!is_live_external_research_goal(
        "Draft an email to team@ioi.network saying tomorrow's standup is moved to 2 PM and send it."
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
fn live_external_research_detects_latest_plural_briefing_queries() {
    assert!(is_live_external_research_goal(
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
    ));
}

#[test]
fn live_external_research_detects_local_business_lookup_queries() {
    assert!(is_live_external_research_goal(
        "Find the three best-reviewed Italian restaurants near me and compare their menus."
    ));
    assert!(!is_live_external_research_goal(
        "Compare the restaurant menu components defined in this repository."
    ));
}

#[test]
fn mailbox_tool_name_signal_matches_connector_prefixes() {
    assert!(is_mail_connector_tool_name(
        "wallet_network__mail_read_latest"
    ));
    assert!(is_mail_connector_tool_name("wallet_network__mail_reply"));
    assert!(is_mail_connector_tool_name(
        "connector__google__gmail_send_email"
    ));
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
fn metric_schema_marks_temperature_axis_for_degree_only_observations() {
    let observation = analyze_metric_schema("Fair 35°F 2°C");
    assert!(observation.has_metric_payload());
    assert!(observation.axis_hits.contains(&MetricAxis::Temperature));
}

#[test]
fn price_quote_signal_requires_explicit_quote_shape() {
    assert!(has_price_quote_payload(
        "Bitcoin price right now: $86,743.63 USD as of 17:23 UTC."
    ));
    assert!(!has_price_quote_payload(
        "2 million BTC valued at about $36 billion at the current price."
    ));
    assert!(!has_price_quote_payload(
        "84 per (BTC / USD) with a current market cap of $1,364."
    ));
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
fn query_facets_capture_latest_plural_briefing_contract() {
    let facets = analyze_query_facets(
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.",
    );
    assert!(facets.time_sensitive_public_fact);
    assert!(facets.grounded_external_required);
    assert!(!facets.locality_sensitive_public_fact);
    assert!(!facets.workspace_constrained);
}

#[test]
fn query_facets_capture_local_business_locality_contract() {
    let facets = analyze_query_facets(
        "Find the three best-reviewed Italian restaurants near me and compare their menus.",
    );
    assert!(!facets.time_sensitive_public_fact);
    assert!(facets.locality_sensitive_public_fact);
    assert!(facets.grounded_external_required);
    assert!(!facets.workspace_constrained);
}

#[test]
fn query_facets_capture_explicit_scope_local_business_contract() {
    let facets = analyze_query_facets(
        "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus.",
    );
    assert!(!facets.time_sensitive_public_fact);
    assert!(facets.locality_sensitive_public_fact);
    assert!(facets.grounded_external_required);
    assert!(!facets.workspace_constrained);
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

#[test]
fn semantic_anchor_tokens_keep_local_business_entities_but_drop_control_terms() {
    let query = "Find the three best-reviewed Italian restaurants near me and compare their menus.";
    let structural = query_structural_directive_tokens(query);
    assert!(structural.contains("find"));
    assert!(structural.contains("three"));
    assert!(structural.contains("best"));
    assert!(structural.contains("reviewed"));
    assert!(structural.contains("compare"));
    assert!(structural.contains("near"));

    let semantic = query_semantic_anchor_tokens(query);
    assert!(semantic.contains("italian"));
    assert!(semantic.contains("restaurants"));
    assert!(semantic.contains("menus"));
    assert!(!semantic.contains("find"));
    assert!(!semantic.contains("three"));
    assert!(!semantic.contains("best"));
    assert!(!semantic.contains("reviewed"));
    assert!(!semantic.contains("compare"));
    assert!(!semantic.contains("near"));
}

#[test]
fn semantic_anchor_tokens_drop_research_and_briefing_control_terms() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let structural = query_structural_directive_tokens(query);
    assert!(structural.contains("research"));
    assert!(structural.contains("briefing"));

    let semantic = query_semantic_anchor_tokens(query);
    assert!(semantic.contains("nist"));
    assert!(semantic.contains("standards"));
    assert!(!semantic.contains("research"));
    assert!(!semantic.contains("briefing"));
}
