use super::*;

#[test]
fn web_pipeline_constraint_grounded_search_query_appends_typed_facets() {
    let query =
        constraint_grounded_search_query("what is the current price of bitcoin right now", 2);
    let normalized = query.to_ascii_lowercase();
    assert!(normalized.contains("latest measured data"));
    assert!(normalized.contains("as-of observation"));
    assert!(normalized.contains("price values"));
    assert!(normalized.contains("2 independent sources"));
    assert!(normalized.contains("\"bitcoin price\""));
}

#[test]
fn web_pipeline_constraint_grounded_search_query_with_hints_adds_anchor_phrase() {
    let hints = vec![
        PendingSearchReadSummary {
            url: "https://weather.com/weather/today/l/Anderson+SC".to_string(),
            title: Some("Current weather Anderson South Carolina".to_string()),
            excerpt:
                "Current conditions in Anderson South Carolina: temperature 62 F, humidity 44%."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC".to_string(),
            title: Some("Anderson South Carolina current conditions".to_string()),
            excerpt: "Observed weather for Anderson South Carolina: temperature 60 F, wind 3 mph."
                .to_string(),
        },
    ];

    let query =
        constraint_grounded_search_query_with_hints("what's the weather right now", 2, &hints);
    let normalized = query.to_ascii_lowercase();
    assert!(normalized.contains("anderson"));
    assert!(normalized.contains("\""));
}

#[test]
fn web_pipeline_constraint_grounded_search_query_anchor_phrase_ignores_output_contract_terms() {
    let hints = vec![
        PendingSearchReadSummary {
            url: "https://weather.com/weather/today/l/Anderson+SC".to_string(),
            title: Some("Current weather Anderson South Carolina".to_string()),
            excerpt:
                "Current conditions in Anderson South Carolina: temperature 62 F, humidity 44%."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC".to_string(),
            title: Some("Anderson South Carolina current conditions".to_string()),
            excerpt: "Observed weather for Anderson South Carolina: temperature 60 F, wind 3 mph."
                .to_string(),
        },
    ];

    let query = constraint_grounded_search_query_with_hints(
        "Current weather in Anderson, SC right now with sources and UTC timestamp.",
        2,
        &hints,
    );
    let normalized = query.to_ascii_lowercase();
    let utc_phrase_count = normalized.match_indices("utc timestamp").count();
    assert_eq!(
        utc_phrase_count, 1,
        "expected deduped output-contract term in query: {query}"
    );
    assert!(
        !normalized.contains("\"anderson sources"),
        "anchor phrase should be semantic-only: {query}"
    );
    assert!(
        !normalized.contains("\"sources utc"),
        "anchor phrase should be semantic-only: {query}"
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_projects_semantic_target_when_provenance_directives_present(
) {
    let query = constraint_grounded_search_query(
        "Current weather in Anderson, SC right now with sources and UTC timestamp.",
        2,
    );
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.starts_with("weather in anderson"),
        "expected semantic retrieval projection: {query}"
    );
    assert!(
        !normalized.starts_with("current weather in anderson, sc right now with sources"),
        "retrieval query should not be dominated by output-contract directives: {query}"
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_projects_semantic_target_for_locality_query() {
    let query =
        constraint_grounded_search_query("What's the weather right now in Anderson, SC?", 2);
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.starts_with("weather in anderson"),
        "expected locality-scoped semantic projection: {query}"
    );
    assert!(
        !normalized.starts_with("what's the weather right now"),
        "retrieval query should avoid conversational framing: {query}"
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_bootstrap_keeps_scoped_time_sensitive_query_concise(
) {
    let query = constraint_grounded_search_query(
        "Current weather in Anderson, SC right now with sources and UTC timestamp.",
        2,
    );
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.starts_with("weather in anderson"),
        "query={}",
        query
    );
    assert!(
        !normalized.contains("latest measured data"),
        "query={}",
        query
    );
    assert!(
        !normalized.contains("independent sources"),
        "query={}",
        query
    );
    assert!(!normalized.contains("utc timestamp"), "query={}", query);
}

#[test]
fn web_pipeline_constraint_grounded_search_query_infers_locality_scope_from_candidate_hints() {
    let hints = vec![PendingSearchReadSummary {
        url: "https://weather.com/weather/today/l/Anderson+SC".to_string(),
        title: Some("Anderson, SC current weather".to_string()),
        excerpt:
            "Current conditions in Anderson, South Carolina: temperature 62 F, humidity 42%, wind 4 mph."
                .to_string(),
    }];
    let query = constraint_grounded_search_query_with_hints_and_locality_hint(
        "what's the weather right now",
        2,
        &hints,
        None,
    );
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.contains("anderson"),
        "expected inferred locality token in grounded query: {}",
        query
    );
    assert!(
        normalized.contains("sc"),
        "expected inferred locality token in grounded query: {}",
        query
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_does_not_infer_scope_from_rss_proxy_tokens() {
    let hints = vec![PendingSearchReadSummary {
        url: "https://news.google.com/rss/articles/CBMimAFBVV95cUxNcVZDZVYtQXVXRFlLQmdCVnVuVlZjMlNZcTNGWm9WN0ZPb0pvMUpBMllJVFo0V3IxZ21RNUtQZTVkc3Joc0c2U2V6ZlA0OHEwdTlHNm8zanp5QmlUUERSVzBQTXJUMXlEVXctZkhUT085SVBvWmVjRWZPNFE4NFZ3LUpOemMyekVMVlRXejl6cHdjYUM2R3cxcw?oc=5".to_string(),
        title: None,
        excerpt: String::new(),
    }];

    let query =
        constraint_grounded_search_query_with_hints("what's the weather right now", 2, &hints);
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.starts_with("weather current conditions"),
        "scope should stay unresolved when hints are rss proxy links: {}",
        query
    );
    assert!(
        !normalized.contains("rss") && !normalized.contains("articles"),
        "rss proxy path tokens should not leak into inferred scope: {}",
        query
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_avoids_scope_inference_from_non_resolvable_hints()
{
    let hints = vec![PendingSearchReadSummary {
        url: "https://forums.x-plane.org/forums/topic/337131-weather-radar-not-working-for-me/"
            .to_string(),
        title: Some("Weather radar not working for me - X-Plane.Org Forum".to_string()),
        excerpt: "Despite updates to aircraft and sim builds, weather radar does not appear on ND."
            .to_string(),
    }];

    let query =
        constraint_grounded_search_query_with_hints("what's the weather right now", 2, &hints);
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.starts_with("weather current conditions"),
        "scope should stay unresolved for non-resolvable hints: {}",
        query
    );
    assert!(
        !normalized.contains("forum") && !normalized.contains("plane"),
        "non-resolvable hint tokens should not leak into query scope: {}",
        query
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_bootstrap_applies_trusted_locality_hint_without_hints(
) {
    let query = constraint_grounded_search_query_with_hints_and_locality_hint(
        "what's the weather right now",
        2,
        &[],
        Some("Anderson, SC"),
    );
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.starts_with("weather in anderson"),
        "query={}",
        query
    );
    assert!(
        normalized.contains("sc"),
        "query should preserve trusted locality tokens: {}",
        query
    );
    assert!(
        !normalized.contains("\"near me\""),
        "query should avoid locality placeholder terms when scope is resolved: {}",
        query
    );
    assert!(
        !normalized.contains("latest measured data"),
        "query={}",
        query
    );
    assert!(!normalized.contains("as-of observation"), "query={}", query);
}

#[test]
fn web_pipeline_constraint_grounded_search_query_prefers_explicit_locality_over_trusted_hint() {
    let query = constraint_grounded_search_query_with_hints_and_locality_hint(
        "what's the weather right now in Boise, ID",
        2,
        &[],
        Some("Anderson, SC"),
    );
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.contains("boise"),
        "query should preserve explicit query locality: {}",
        query
    );
    assert!(
        normalized.contains("id"),
        "query should preserve explicit query locality tokens: {}",
        query
    );
    assert!(
        !normalized.contains("anderson"),
        "trusted locality hint must not override explicit query locality: {}",
        query
    );
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
fn web_pipeline_constraint_grounded_search_query_avoids_locality_placeholder_when_scope_missing() {
    let query = constraint_grounded_search_query("what's the weather right now", 2);
    let normalized = query.to_ascii_lowercase();
    assert!(normalized.starts_with("weather current conditions"));
    assert!(!normalized.contains("\"near me\""), "query={}", query);
}

#[test]
fn web_pipeline_constraint_grounded_search_query_avoids_native_anchor_phrase_for_explicit_locality()
{
    let query =
        constraint_grounded_search_query("What's the weather right now in Anderson, SC?", 2);
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.starts_with("weather in anderson"),
        "query={}",
        query
    );
    assert!(
        !normalized.contains("\"anderson weather\""),
        "query should avoid quoted native-anchor inflation for explicit-locality lookups: {}",
        query
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_ignores_forecast_only_axis_hints() {
    let hints = vec![
        PendingSearchReadSummary {
            url: "https://weather.example.com/a".to_string(),
            title: Some("Anderson forecast".to_string()),
            excerpt: "Tomorrow forecast: high 65, low 49, chance of rain 60%.".to_string(),
        },
        PendingSearchReadSummary {
            url: "https://weather2.example.com/b".to_string(),
            title: Some("Anderson 10-day outlook".to_string()),
            excerpt: "Weekly outlook with precipitation chance and daily high/low values."
                .to_string(),
        },
    ];

    let query = constraint_grounded_search_query_with_hints(
        "What's the weather right now in Anderson, SC?",
        2,
        &hints,
    );
    assert!(
        !query.to_ascii_lowercase().contains("precipitation values"),
        "forecast-only hints should not infer precipitation axis constraints: {}",
        query
    );
}

#[test]
fn web_pipeline_constraint_grounded_probe_query_escalates_when_prior_equals_grounded() {
    let query = "what's the weather right now";
    let hints = vec![PendingSearchReadSummary {
        url: "https://www.weather-atlas.com/en/wyoming-usa/cheyenne".to_string(),
        title: Some("Weather today - Cheyenne, WY".to_string()),
        excerpt:
            "Current weather in Cheyenne, Wyoming: temperature 30 F, humidity 68%, wind 11 mph."
                .to_string(),
    }];
    let grounded = constraint_grounded_search_query_with_hints_and_locality_hint(
        query,
        2,
        &hints,
        Some("Anderson, SC"),
    );
    let probe = constraint_grounded_probe_query_with_hints_and_locality_hint(
        query,
        2,
        &hints,
        &grounded,
        Some("Anderson, SC"),
    )
    .expect("probe query should be generated");
    assert!(
        !probe.eq_ignore_ascii_case(&grounded),
        "probe should differ from prior grounded query"
    );
    let normalized = probe.to_ascii_lowercase();
    assert!(
        normalized.contains("cheyenne") || normalized.contains("wyoming"),
        "expected locality-aware escalation terms in probe query: {}",
        probe
    );
}

#[test]
fn web_pipeline_constraint_grounded_probe_query_adds_metric_probe_terms_when_locality_query_stalls()
{
    let query = "what's the weather right now";
    let grounded = constraint_grounded_search_query_with_hints_and_locality_hint(
        query,
        2,
        &[],
        Some("New York"),
    );
    let probe = constraint_grounded_probe_query_with_hints_and_locality_hint(
        query,
        2,
        &[],
        &grounded,
        Some("New York"),
    )
    .expect("probe query should be generated for stalled locality-sensitive query");
    let normalized = probe.to_ascii_lowercase();
    assert!(
        normalized.contains("temperature")
            && normalized.contains("humidity")
            && normalized.contains("wind"),
        "expected metric-oriented fallback probe terms: {}",
        probe
    );
    assert!(
        !probe.eq_ignore_ascii_case(&grounded),
        "fallback probe query should differ from grounded query"
    );
}

#[test]
fn web_pipeline_constraint_grounded_probe_query_diversifies_generic_headline_queries() {
    let query = "Tell me today's top news headlines.";
    let hints = vec![PendingSearchReadSummary {
        url: "https://www.foxnews.com/us/example-headline".to_string(),
        title: Some("Top headlines from Fox News".to_string()),
        excerpt: "Breaking U.S. and world coverage from Fox.".to_string(),
    }];
    let grounded = constraint_grounded_search_query_with_hints(query, 3, &hints);
    let probe = constraint_grounded_probe_query_with_hints_and_locality_hint(
        query, 3, &hints, &grounded, None,
    )
    .expect("headline probe query should be generated");
    let normalized = probe.to_ascii_lowercase();
    assert!(
        normalized.contains("reuters")
            && (normalized.contains("ap news") || normalized.contains("ap")),
        "expected diversified newsroom anchors in headline probe query: {}",
        probe
    );
    assert!(
        normalized.contains("-site:www.foxnews.com") || normalized.contains("-site:foxnews.com"),
        "expected repeated-domain exclusion in headline probe query: {}",
        probe
    );
    assert!(
        !probe.eq_ignore_ascii_case(&grounded),
        "headline probe query should differ from grounded query"
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_keeps_generic_headline_contract_clean() {
    let query = "Tell me today's top news headlines.";
    let hints = vec![PendingSearchReadSummary {
        url: "https://www.foxnews.com/us/example-headline?msockid=abc123".to_string(),
        title: Some("Dems score rare Florida win and more top headlines".to_string()),
        excerpt: "Breaking updates from Fox with msockid=abc123 tracking.".to_string(),
    }];
    let grounded = constraint_grounded_search_query_with_hints(query, 3, &hints);
    let normalized = grounded.to_ascii_lowercase();
    assert!(
        normalized.contains("today")
            && normalized.contains("top")
            && normalized.contains("news")
            && normalized.contains("headlines"),
        "headline grounded query should preserve headline intent anchors: {}",
        grounded
    );
    assert!(
        !normalized.contains("score values")
            && !normalized.contains("independent sources")
            && !normalized.contains("msockid"),
        "headline grounded query should avoid metric and tracking-noise terms: {}",
        grounded
    );
}

#[test]
fn web_pipeline_constraint_grounded_probe_query_excludes_low_signal_hosts_when_metric_gap_persists()
{
    let query = "what's the weather right now in anderson, sc";
    let hints = vec![
        PendingSearchReadSummary {
            url: "https://www.weather-forecast.com/locations/Anderson/forecasts/latest".to_string(),
            title: Some("Anderson, South Carolina Weather Forecast".to_string()),
            excerpt: "Providing a local hourly Anderson (South Carolina) weather forecast."
                .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.accuweather.com/en/us/anderson/29624/weather-forecast/330677"
                .to_string(),
            title: Some("Anderson, SC Weather Forecast".to_string()),
            excerpt: "Anderson, SC Weather Forecast, with current conditions and next 3 days."
                .to_string(),
        },
    ];
    let grounded = constraint_grounded_search_query_with_hints(query, 2, &hints);
    let probe = constraint_grounded_probe_query_with_hints_and_locality_hint(
        query, 2, &hints, &grounded, None,
    )
    .expect("probe query should be generated when metric grounding remains weak");
    let normalized = probe.to_ascii_lowercase();
    assert!(
        normalized.contains("-site:www.accuweather.com")
            || normalized.contains("-site:www.weather-forecast.com"),
        "expected probe to exclude at least one previously low-signal host: {}",
        probe
    );
    assert!(
        !probe.eq_ignore_ascii_case(&grounded),
        "host-exclusion probe should differ from grounded query"
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_adds_status_surface_terms_for_incident_queries() {
    let query = "As of now (UTC), top 3 active U.S.-impacting cloud/SaaS incidents from major status pages with citations.";
    let grounded = constraint_grounded_search_query(query, 3);
    let normalized = grounded.to_ascii_lowercase();
    assert!(
        normalized.contains("official status page"),
        "expected status-surface grounding term: {}",
        grounded
    );
    assert!(
        normalized.contains("service health dashboard"),
        "expected service-health grounding term: {}",
        grounded
    );
}

#[test]
fn web_pipeline_constraint_grounded_probe_query_excludes_repeated_hosts_for_incident_queries() {
    let query = "As of now (UTC), top 3 active U.S.-impacting cloud/SaaS incidents from major status pages with citations.";
    let hints = vec![
        PendingSearchReadSummary {
            url: "https://www.reddit.com/r/MicrosoftTeams/comments/1crvhbg/accidentally_found_the_best_way_to_keep_active/".to_string(),
            title: Some("Accidentally found the best way to keep active status".to_string()),
            excerpt: "Discussion thread repeating active-status phrasing.".to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.reddit.com/r/WindowsHelp/comments/17qndbf/search_active_directory_in_windows_11/".to_string(),
            title: Some("Search Active Directory in Windows 11".to_string()),
            excerpt: "Another thread unrelated to provider status dashboards.".to_string(),
        },
    ];
    let grounded = constraint_grounded_search_query_with_hints(query, 3, &hints);
    let probe = constraint_grounded_probe_query_with_hints_and_locality_hint(
        query, 3, &hints, &grounded, None,
    )
    .expect("probe query should be generated when incident retrieval stalls on repeated hosts");
    let normalized = probe.to_ascii_lowercase();
    assert!(
        normalized.contains("-site:www.reddit.com") || normalized.contains("-site:reddit.com"),
        "expected host exclusion for repeated low-signal domain: {}",
        probe
    );
    assert!(
        !probe.eq_ignore_ascii_case(&grounded),
        "probe query should differ from grounded query"
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_preserves_non_locality_queries() {
    let query = constraint_grounded_search_query("summarize this local file", 2);
    assert_eq!(query, "summarize this local file");
}
