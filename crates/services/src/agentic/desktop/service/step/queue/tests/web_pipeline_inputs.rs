use super::*;

#[test]
fn web_pipeline_min_sources_scales_with_explicit_citation_contract() {
    let query = "As of now (UTC), top 3 active U.S.-impacting cloud/SaaS incidents from major status pages with 2 citations each.";
    assert_eq!(web_pipeline_min_sources(query), 6);
}

#[test]
fn web_pipeline_min_sources_defaults_without_explicit_citation_contract() {
    let query = "Summarize active cloud incidents from major status pages.";
    assert_eq!(web_pipeline_min_sources(query), 1);
}

#[test]
fn summary_contains_topic_and_refinement_hint() {
    let summary = summarize_search_results(
        "internet of intelligence",
        "https://duckduckgo.com/?q=internet+of+intelligence",
        "<html><body><a href=\"https://example.com/a\">A</a>\nThe Internet of Intelligence explores decentralized agent coordination.\nOpen protocols enable verifiable execution and policy enforcement.</body></html>",
    );
    assert!(summary.contains("Search summary for 'internet of intelligence'"));
    assert!(summary.contains("Source URL: https://duckduckgo.com/?q=internet+of+intelligence"));
    assert!(summary.contains("Next refinement:"));
}

#[test]
fn fallback_summary_is_deterministic() {
    let msg = fallback_search_summary(
        "internet of intelligence",
        "https://duckduckgo.com/?q=internet+of+intelligence",
    );
    assert_eq!(
        msg,
        "Searched 'internet of intelligence' at https://duckduckgo.com/?q=internet+of+intelligence, but structured extraction failed. Retry refinement if needed."
    );
}

#[test]
fn web_pipeline_candidate_urls_preserve_rank_order() {
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:ddg".to_string(),
        query: Some("latest news".to_string()),
        url: Some("https://duckduckgo.com/?q=latest+news".to_string()),
        sources: vec![
            WebSource {
                source_id: "b".to_string(),
                rank: Some(2),
                url: "https://b.example.com".to_string(),
                title: Some("B".to_string()),
                snippet: None,
                domain: Some("b.example.com".to_string()),
            },
            WebSource {
                source_id: "a".to_string(),
                rank: Some(1),
                url: "https://a.example.com".to_string(),
                title: Some("A".to_string()),
                snippet: None,
                domain: Some("a.example.com".to_string()),
            },
        ],
        documents: vec![],
    };

    let urls = candidate_urls_from_bundle(&bundle);
    assert_eq!(
        urls,
        vec![
            "https://a.example.com".to_string(),
            "https://b.example.com".to_string()
        ]
    );
}

#[test]
fn web_pipeline_source_hints_preserve_rank_order() {
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:ddg".to_string(),
        query: Some("latest news".to_string()),
        url: Some("https://duckduckgo.com/?q=latest+news".to_string()),
        sources: vec![
            WebSource {
                source_id: "b".to_string(),
                rank: Some(2),
                url: "https://b.example.com".to_string(),
                title: Some("Headline B".to_string()),
                snippet: Some("Summary B".to_string()),
                domain: Some("b.example.com".to_string()),
            },
            WebSource {
                source_id: "a".to_string(),
                rank: Some(1),
                url: "https://a.example.com".to_string(),
                title: Some("Headline A".to_string()),
                snippet: Some("Summary A".to_string()),
                domain: Some("a.example.com".to_string()),
            },
        ],
        documents: vec![],
    };

    let hints = candidate_source_hints_from_bundle(&bundle);
    assert_eq!(hints.len(), 2);
    assert_eq!(hints[0].url, "https://a.example.com");
    assert_eq!(hints[0].title.as_deref(), Some("Headline A"));
    assert_eq!(hints[1].url, "https://b.example.com");
    assert_eq!(hints[1].title.as_deref(), Some("Headline B"));
}

#[test]
fn web_pipeline_source_hints_prioritize_primary_status_surfaces_over_secondary_aggregation() {
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:ddg".to_string(),
        query: Some("active cloud incidents".to_string()),
        url: Some("https://duckduckgo.com/?q=active+cloud+incidents".to_string()),
        sources: vec![
            WebSource {
                source_id: "agg".to_string(),
                rank: Some(1),
                url: "https://example-monitor.com/cloud/incidents".to_string(),
                title: Some("Cloud status page aggregator".to_string()),
                snippet: Some(
                    "Track incidents across providers with community outage reports.".to_string(),
                ),
                domain: Some("example-monitor.com".to_string()),
            },
            WebSource {
                source_id: "primary".to_string(),
                rank: Some(5),
                url: "https://status.vendor-a.com/incidents/123".to_string(),
                title: Some("API outage impacting U.S. region".to_string()),
                snippet: Some(
                    "Status page shows investigating with mitigation underway.".to_string(),
                ),
                domain: Some("status.vendor-a.com".to_string()),
            },
        ],
        documents: vec![],
    };

    let hints = candidate_source_hints_from_bundle(&bundle);
    assert_eq!(hints.len(), 2);
    assert_eq!(hints[0].url, "https://status.vendor-a.com/incidents/123");
    assert_eq!(hints[1].url, "https://example-monitor.com/cloud/incidents");
}

#[test]
fn web_pipeline_source_hints_prioritize_operational_status_hosts_over_documentation_surfaces() {
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:ddg".to_string(),
        query: Some("service health incidents".to_string()),
        url: Some("https://duckduckgo.com/?q=service+health+incidents".to_string()),
        sources: vec![
            WebSource {
                source_id: "docs".to_string(),
                rank: Some(1),
                url: "https://learn.vendor-a.com/service-health/overview".to_string(),
                title: Some("Service health overview".to_string()),
                snippet: Some(
                    "Documentation overview for service health capabilities and guidance."
                        .to_string(),
                ),
                domain: Some("learn.vendor-a.com".to_string()),
            },
            WebSource {
                source_id: "status-a".to_string(),
                rank: Some(5),
                url: "https://status.vendor-a.com/incidents/123".to_string(),
                title: Some("API outage impacting U.S. region".to_string()),
                snippet: Some(
                    "Status page shows investigating with mitigation underway.".to_string(),
                ),
                domain: Some("status.vendor-a.com".to_string()),
            },
            WebSource {
                source_id: "status-b".to_string(),
                rank: Some(6),
                url: "https://status.vendor-b.com/incidents/456".to_string(),
                title: Some("Authentication degradation for North America".to_string()),
                snippet: Some("Users may see login errors; next update expected soon.".to_string()),
                domain: Some("status.vendor-b.com".to_string()),
            },
        ],
        documents: vec![],
    };

    let hints = candidate_source_hints_from_bundle(&bundle);
    assert_eq!(hints.len(), 3);
    assert_eq!(hints[0].url, "https://status.vendor-a.com/incidents/123");
    assert_eq!(hints[1].url, "https://status.vendor-b.com/incidents/456");
    assert_eq!(
        hints[2].url,
        "https://learn.vendor-a.com/service-health/overview"
    );
}

#[test]
fn web_pipeline_pre_read_prunes_unresolvable_candidates_when_resolvable_inventory_exists() {
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:ddg".to_string(),
        query: Some("weather right now anderson sc".to_string()),
        url: Some("https://duckduckgo.com/?q=weather+right+now+anderson+sc".to_string()),
        sources: vec![
            WebSource {
                source_id: "tenday".to_string(),
                rank: Some(1),
                url: "https://weather.com/weather/tenday/l/Anderson%20SC".to_string(),
                title: Some("Anderson, SC 10-Day Weather Forecast".to_string()),
                snippet: Some(
                    "Be prepared with the most accurate 10-day forecast for Anderson.".to_string(),
                ),
                domain: Some("weather.com".to_string()),
            },
            WebSource {
                source_id: "current-a".to_string(),
                rank: Some(2),
                url: "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327"
                    .to_string(),
                title: Some("Anderson, SC Current Weather".to_string()),
                snippet: Some(
                    "Current conditions: temperature near 61 F, wind 4 mph, humidity 48%."
                        .to_string(),
                ),
                domain: Some("accuweather.com".to_string()),
            },
            WebSource {
                source_id: "current-b".to_string(),
                rank: Some(3),
                url: "https://forecast.weather.gov/MapClick.php?lat=34.5&lon=-82.65".to_string(),
                title: Some("Anderson SC Current Conditions".to_string()),
                snippet: Some(
                    "Observed at 2:00 AM: temperature 60 F, humidity 50%, calm wind.".to_string(),
                ),
                domain: Some("weather.gov".to_string()),
            },
        ],
        documents: vec![],
    };

    let plan = pre_read_candidate_plan_from_bundle("what's the weather right now", 2, &bundle);
    assert!(
        plan.total_candidates >= 2,
        "expected constraint-aware acquisition to keep at least the source floor, got {}",
        plan.total_candidates
    );
    assert!(
        plan.total_candidates <= 3,
        "constraint-aware acquisition should not expand candidate inventory: {:?}",
        plan
    );
    assert_eq!(plan.candidate_urls.len(), 2);
    assert!(
        plan.candidate_urls
            .iter()
            .all(|url| !url.contains("/tenday/")),
        "expected 10-day forecast candidate to be pruned: {:?}",
        plan.candidate_urls
    );
    assert!(!plan.requires_constraint_search_probe);
}

#[test]
fn web_pipeline_pre_read_prunes_irrelevant_candidates_when_compatible_inventory_exists() {
    let bundle = anderson_weather_search_bundle(
        ANDERSON_WEATHER_QUERY,
        vec![
            source_att_forum_account_usage(1),
            source_accuweather_anderson(2),
            source_weather_gov_anderson(3),
        ],
    );

    let plan = pre_read_candidate_plan_from_bundle(
        "what's the weather right now in anderson sc",
        2,
        &bundle,
    );
    assert!(
        plan.total_candidates <= 3,
        "constraint-aware acquisition should not expand candidate inventory: {:?}",
        plan
    );
    assert!(
        plan.candidate_urls
            .iter()
            .all(|url| !url.contains("forums.att.com")),
        "expected incompatible candidate to be pruned: {:?}",
        plan.candidate_urls
    );
    assert_eq!(plan.candidate_urls.len(), 2);
}

#[test]
fn web_pipeline_pre_read_acquisition_filters_incompatible_candidates_for_single_anchor_queries() {
    let bundle = anderson_weather_search_bundle(
        "weather right now",
        vec![
            source_att_forum_account_usage(1),
            source_accuweather_anderson(2),
            source_weather_gov_anderson(3),
        ],
    );

    let plan = pre_read_candidate_plan_from_bundle("what's the weather right now", 2, &bundle);
    assert_eq!(plan.total_candidates, 2, "plan={:?}", plan);
    assert!(
        plan.candidate_urls
            .iter()
            .all(|url| !url.contains("forums.att.com")),
        "expected incompatible candidate to be filtered during acquisition: {:?}",
        plan.candidate_urls
    );
    assert!(!plan.requires_constraint_search_probe);
}

#[test]
fn web_pipeline_pre_read_prunes_search_hub_urls_for_grounded_time_sensitive_queries() {
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:bing:http".to_string(),
        query: Some("what's the weather right now".to_string()),
        url: Some("https://www.bing.com/search?q=what%27s+the+weather+right+now".to_string()),
        sources: vec![
            WebSource {
                source_id: "serp".to_string(),
                rank: Some(1),
                url: "https://www.bing.com/search?q=what%27s+the+weather+right+now".to_string(),
                title: Some("Bing".to_string()),
                snippet: Some("Search results for weather right now".to_string()),
                domain: Some("bing.com".to_string()),
            },
            WebSource {
                source_id: "wx-a".to_string(),
                rank: Some(2),
                url: "https://www.accuweather.com/en/us/anderson/29624/current-weather/330677"
                    .to_string(),
                title: Some("Anderson, SC Current Weather".to_string()),
                snippet: Some(
                    "Current conditions: 62 F, feels like 64 F, wind 4 mph, humidity 42%."
                        .to_string(),
                ),
                domain: Some("accuweather.com".to_string()),
            },
            WebSource {
                source_id: "wx-b".to_string(),
                rank: Some(3),
                url: "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC".to_string(),
                title: Some("Current Conditions for Anderson, SC".to_string()),
                snippet: Some(
                    "Observed at 02:00 AM: temperature 60 F, humidity 50%, calm wind.".to_string(),
                ),
                domain: Some("weather.gov".to_string()),
            },
        ],
        documents: vec![],
    };

    let plan = pre_read_candidate_plan_from_bundle("what's the weather right now", 2, &bundle);
    assert!(
        plan.candidate_urls
            .iter()
            .all(|url| !url.contains("bing.com/search")),
        "search hub url should be pruned from evidence candidates: {:?}",
        plan.candidate_urls
    );
    assert!(plan
        .candidate_urls
        .iter()
        .any(|url| url.contains("accuweather.com")));
}

#[test]
fn web_pipeline_pre_read_requires_probe_when_time_sensitive_candidates_are_incompatible() {
    let bundle = anderson_weather_search_bundle(
        ANDERSON_WEATHER_QUERY,
        vec![source_att_forum_account_usage(1), source_att_forum_apple(2)],
    );

    let plan = pre_read_candidate_plan_from_bundle(
        "what's the weather right now in anderson sc",
        2,
        &bundle,
    );
    assert!(plan.requires_constraint_search_probe);
    assert_eq!(
        plan.candidate_urls.len(),
        0,
        "when strict compatibility prunes everything, pipeline should force a follow-up probe instead of admitting zero-compatibility exploratory reads"
    );
}

#[test]
fn web_pipeline_pre_read_requires_probe_when_resolvable_inventory_below_source_floor() {
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:bing:http".to_string(),
        query: Some("current weather in anderson sc".to_string()),
        url: Some("https://www.bing.com/search?q=current+weather+anderson+sc".to_string()),
        sources: vec![
            WebSource {
                source_id: "weather-a".to_string(),
                rank: Some(1),
                url: "https://www.weather-forecast.com/locations/Anderson/forecasts/latest"
                    .to_string(),
                title: Some("Anderson, South Carolina Weather Forecast".to_string()),
                snippet: Some(
                    "Providing a local hourly weather forecast with wind, humidity and temperature."
                        .to_string(),
                ),
                domain: Some("weather-forecast.com".to_string()),
            },
            WebSource {
                source_id: "weather-b".to_string(),
                rank: Some(2),
                url: "https://www.theweathernetwork.com/en/city/us/south-carolina/anderson/hourly"
                    .to_string(),
                title: Some("Anderson, SC Hourly Forecast - The Weather Network".to_string()),
                snippet: Some(
                    "Get Anderson current weather report with temperature, feels like, wind, humidity and pressure."
                        .to_string(),
                ),
                domain: Some("theweathernetwork.com".to_string()),
            },
        ],
        documents: vec![],
    };

    let plan = pre_read_candidate_plan_from_bundle(
        "what's the weather right now in anderson sc",
        2,
        &bundle,
    );
    assert_eq!(plan.candidate_urls.len(), 2, "plan={:?}", plan);
    assert!(
        plan.candidate_urls[0].contains("theweathernetwork.com"),
        "expected current-observation surface candidate to lead ranking: {:?}",
        plan.candidate_urls
    );
    assert!(
        plan.candidate_urls
            .iter()
            .any(|url| url.contains("weather-forecast.com")),
        "expected floor top-up to keep an additional non-hub weather candidate: {:?}",
        plan.candidate_urls
    );
    assert!(
        plan.requires_constraint_search_probe,
        "expected typed-facet probe when compatible candidates are not resolvable: {:?}",
        plan
    );
}

#[test]
fn web_pipeline_pre_read_does_not_learn_facets_from_incompatible_candidates() {
    let bundle = anderson_weather_search_bundle(
        ANDERSON_WEATHER_QUERY,
        vec![
            WebSource {
                source_id: "shopping".to_string(),
                rank: Some(1),
                url: "https://www.bestbuy.com/trade-in".to_string(),
                title: Some("Trade-In - Best Buy".to_string()),
                snippet: Some(
                    "Save $50 or more on your next Windows 11 PC with in-store trade-in."
                        .to_string(),
                ),
                domain: Some("bestbuy.com".to_string()),
            },
            source_accuweather_anderson(2),
            source_weather_gov_anderson(3),
        ],
    );

    let plan = pre_read_candidate_plan_from_bundle(
        "what's the weather right now in anderson sc",
        2,
        &bundle,
    );
    assert_eq!(plan.candidate_urls.len(), 2, "plan={:?}", plan);
    assert!(
        plan.candidate_urls
            .iter()
            .all(|url| !url.contains("bestbuy.com")),
        "expected incompatible shopping candidate to be excluded: {:?}",
        plan.candidate_urls
    );
}

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

#[test]
fn web_pipeline_pre_read_locality_scope_hint_filters_non_local_weather_candidates() {
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:ddg".to_string(),
        query: Some("what's the weather right now".to_string()),
        url: Some("https://duckduckgo.com/?q=weather+right+now".to_string()),
        sources: vec![
            WebSource {
                source_id: "anderson-local".to_string(),
                rank: Some(1),
                url: "https://weather.com/weather/today/l/Anderson+SC".to_string(),
                title: Some("Anderson, SC current weather".to_string()),
                snippet: Some(
                    "Current conditions in Anderson, South Carolina: temperature 62 F, humidity 42%, wind 4 mph."
                        .to_string(),
                ),
                domain: Some("weather.com".to_string()),
            },
            WebSource {
                source_id: "cheyenne-non-local".to_string(),
                rank: Some(2),
                url: "https://www.weather-atlas.com/en/wyoming-usa/cheyenne".to_string(),
                title: Some("Weather today - Cheyenne, WY".to_string()),
                snippet: Some(
                    "Current weather in Cheyenne, Wyoming: temperature 30 F, humidity 68%, wind 11 mph."
                        .to_string(),
                ),
                domain: Some("weather-atlas.com".to_string()),
            },
        ],
        documents: vec![],
    };

    let plan = pre_read_candidate_plan_from_bundle_with_locality_hint(
        "what's the weather right now",
        2,
        &bundle,
        Some("Anderson, SC"),
    );

    assert!(
        plan.candidate_urls
            .iter()
            .any(|url| url.contains("Anderson") || url.contains("anderson")),
        "expected localized candidate to remain: {:?}",
        plan.candidate_urls
    );
    assert!(
        plan.candidate_urls
            .iter()
            .all(|url| !url.contains("wyoming-usa/cheyenne")),
        "expected non-local candidate to be pruned: {:?}",
        plan.candidate_urls
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_limit_tracks_time_sensitive_constraints() {
    assert_eq!(
        constraint_grounded_search_limit("what's the weather right now in anderson sc", 2),
        6
    );
    assert_eq!(
        constraint_grounded_search_limit("summarize this local file", 2),
        10
    );
}

#[test]
fn web_pipeline_uses_source_hints_when_read_output_is_low_signal() {
    let mut pending = PendingSearchCompletion {
        query: "latest breaking news".to_string(),
        query_contract: "latest breaking news".to_string(),
        url: "https://news.google.com/rss/search?q=latest+breaking+news".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec!["https://news.google.com/rss/articles/abc".to_string()],
        candidate_source_hints: vec![crate::agentic::desktop::types::PendingSearchReadSummary {
            url: "https://news.google.com/rss/articles/abc".to_string(),
            title: Some("Major storm causes widespread flight delays".to_string()),
            excerpt: "Airports across the U.S. reported cancellations and delays overnight."
                .to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 1,
    };

    append_pending_web_success_fallback(
        &mut pending,
        "https://news.google.com/rss/articles/abc",
        Some("Google News"),
    );
    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    assert!(reply.contains("Major storm causes widespread flight delays"));
    assert!(reply.contains("Airports across the U.S."));
}

#[test]
fn web_pipeline_rejects_incompatible_read_evidence_for_grounded_queries() {
    let mut pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        url: "https://www.bing.com/search?q=current+weather+anderson+sc".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec!["https://www.bestbuy.com/trade-in".to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://www.bestbuy.com/trade-in".to_string(),
            title: Some("Trade-In - Best Buy".to_string()),
            excerpt: "Save $50 or more on your next Windows 11 PC with in-store trade-in."
                .to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };

    append_pending_web_success_fallback(
        &mut pending,
        "https://www.bestbuy.com/trade-in",
        Some("Save $50 on your next PC purchase."),
    );
    assert!(
        pending.successful_reads.is_empty(),
        "incompatible source should not be retained as successful evidence"
    );
}

#[test]
fn web_pipeline_accepts_hint_compatible_read_when_page_extract_is_low_signal() {
    let mut pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        url: "https://www.bing.com/search?q=current+weather+anderson+sc".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec!["https://weather.com/weather/today/l/Anderson+SC".to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://weather.com/weather/today/l/Anderson+SC".to_string(),
            title: Some("Anderson, SC Current Weather".to_string()),
            excerpt:
                "Current conditions in Anderson, SC: temperature 62 F, humidity 42%, wind 4 mph."
                    .to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };

    append_pending_web_success_fallback(
        &mut pending,
        "https://weather.com/weather/today/l/Anderson+SC",
        Some("Weather navigation and legal terms."),
    );

    assert_eq!(pending.successful_reads.len(), 1);
    assert!(
        pending.successful_reads[0]
            .excerpt
            .to_ascii_lowercase()
            .contains("temperature"),
        "expected compatible hint excerpt to be retained"
    );
}

#[test]
fn web_pipeline_hint_lookup_matches_structurally_equivalent_urls() {
    let mut pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        url: "https://www.bing.com/search?q=current+weather+anderson+sc".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec![
            "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC".to_string(),
        ],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC".to_string(),
            title: Some("Current Weather - Anderson, SC".to_string()),
            excerpt: "Current weather in Anderson, SC: temperature 61 F, humidity 48%, wind 3 mph."
                .to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };

    append_pending_web_success_fallback(
        &mut pending,
        "https://forecast.weather.gov/zipcity.php?inputstring=Anderson%2CSC",
        Some("Cookie banner and navigation links."),
    );

    assert_eq!(pending.successful_reads.len(), 1);
    assert!(
        pending.successful_reads[0]
            .excerpt
            .to_ascii_lowercase()
            .contains("current weather in anderson"),
        "expected structurally equivalent URL to reuse compatible hint evidence"
    );
}

#[test]
fn web_pipeline_bundle_success_retries_with_requested_url_when_document_url_fails() {
    let requested_url = "https://weather.com/weather/today/l/Anderson+SC";
    let mut pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        url: "https://www.bing.com/search?q=current+weather+anderson+sc".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some("Anderson, SC Current Weather".to_string()),
            excerpt: "Current weather in Anderson, SC: temperature 62 F, humidity 42%, wind 4 mph."
                .to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some("https://example.com/redirect".to_string()),
        sources: vec![WebSource {
            source_id: "source:redirect".to_string(),
            rank: None,
            url: "https://example.com/redirect".to_string(),
            title: Some("Redirect landing page".to_string()),
            snippet: Some("Navigation links and policy text.".to_string()),
            domain: Some("example.com".to_string()),
        }],
        documents: vec![WebDocument {
            source_id: "source:redirect".to_string(),
            url: "https://example.com/redirect".to_string(),
            title: Some("Redirect landing page".to_string()),
            content_text: "Navigation and legal terms. Sign in to continue.".to_string(),
            content_hash: "hash".to_string(),
            quote_spans: vec![],
        }],
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);

    assert_eq!(pending.successful_reads.len(), 1);
    assert_eq!(pending.successful_reads[0].url, requested_url);
    assert!(
        pending.successful_reads[0]
            .excerpt
            .to_ascii_lowercase()
            .contains("temperature"),
        "expected fallback requested URL to retain compatible hint payload"
    );
}

#[test]
fn web_pipeline_merge_pending_search_completion_preserves_existing_inventory() {
    let existing = PendingSearchCompletion {
        query: "what's the weather right now".to_string(),
        query_contract: "what's the weather right now".to_string(),
        url: "https://duckduckgo.com/?q=weather".to_string(),
        started_step: 3,
        started_at_ms: 1_000,
        deadline_ms: 51_000,
        candidate_urls: vec![
            "https://weather.com/weather/today/l/Anderson+SC".to_string(),
            "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC".to_string(),
        ],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC".to_string(),
            title: Some("Current Conditions - National Weather Service".to_string()),
            excerpt: "Current conditions at local airport with temperature and humidity."
                .to_string(),
        }],
        attempted_urls: vec!["https://weather.com/weather/today/l/Anderson+SC".to_string()],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };
    let incoming = PendingSearchCompletion {
        query: "what's the weather right now".to_string(),
        query_contract: "what's the weather right now".to_string(),
        url: "https://duckduckgo.com/html/?q=weather".to_string(),
        started_step: 5,
        started_at_ms: 2_000,
        deadline_ms: 52_000,
        candidate_urls: vec![
            "https://duckduckgo.com/feedback.html".to_string(),
            "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC".to_string(),
        ],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://duckduckgo.com/feedback.html".to_string(),
            title: Some("Feedback".to_string()),
            excerpt: "Submit feedback".to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 1,
    };

    let merged = merge_pending_search_completion(existing, incoming);
    assert_eq!(merged.started_at_ms, 1_000);
    assert_eq!(merged.deadline_ms, 51_000);
    assert_eq!(merged.min_sources, 2);
    assert_eq!(
        merged.attempted_urls,
        vec!["https://weather.com/weather/today/l/Anderson+SC".to_string()]
    );
    assert_eq!(
        merged.candidate_urls,
        vec![
            "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC".to_string(),
            "https://duckduckgo.com/feedback.html".to_string(),
        ]
    );
    assert!(merged
        .candidate_source_hints
        .iter()
        .any(|hint| hint.url.contains("forecast.weather.gov")));
}

#[test]
fn web_pipeline_append_success_from_bundle_preserves_non_low_signal_read_excerpt() {
    let requested_url = "https://weather.yahoo.com/us/sc/anderson";
    let mut pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        url: "https://duckduckgo.com/?q=current+weather+anderson+sc".to_string(),
        started_step: 0,
        started_at_ms: 0,
        deadline_ms: 45_000,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some("Anderson, SC Current Weather".to_string()),
            excerpt:
                "Current conditions at Anderson airport: Fair 35°F 2°C Humidity 38% Wind 8 mph."
                    .to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(requested_url.to_string()),
        sources: vec![WebSource {
            source_id: "source:weather".to_string(),
            rank: None,
            url: requested_url.to_string(),
            title: Some("Anderson Forecast".to_string()),
            snippet: None,
            domain: Some("weather.yahoo.com".to_string()),
        }],
        documents: vec![WebDocument {
            source_id: "source:weather".to_string(),
            url: requested_url.to_string(),
            title: Some("Anderson Forecast".to_string()),
            content_text: "Mostly Cloudy today with a high of 61°F and a low of 45°F.".to_string(),
            content_hash: "hash".to_string(),
            quote_spans: vec![],
        }],
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);
    assert_eq!(pending.successful_reads.len(), 1);
    assert!(
        pending.successful_reads[0]
            .excerpt
            .contains("Mostly Cloudy today with a high of 61°F"),
        "expected read excerpt to be preserved when it has a quantitative claim"
    );
}

#[test]
fn web_pipeline_pre_read_preserves_location_weather_candidates_under_grounded_constraints() {
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:bing:http".to_string(),
        query: Some("what's the weather right now in anderson sc".to_string()),
        url: Some("https://www.bing.com/search?q=current+weather+anderson+sc".to_string()),
        sources: vec![
            WebSource {
                source_id: "weather-atlas".to_string(),
                rank: Some(1),
                url: "https://www.weather-atlas.com/en/south-carolina-usa/anderson".to_string(),
                title: Some("Weather today - Anderson, SC".to_string()),
                snippet: Some(
                    "Current weather and hourly forecast page for Anderson, SC.".to_string(),
                ),
                domain: Some("weather-atlas.com".to_string()),
            },
            WebSource {
                source_id: "weather-com".to_string(),
                rank: Some(2),
                url: "https://weather.com/weather/today/l/Anderson+SC".to_string(),
                title: Some(
                    "Weather Forecast and Conditions for Anderson, South Carolina".to_string(),
                ),
                snippet: Some(
                    "Current weather conditions and local radar in Anderson, South Carolina."
                        .to_string(),
                ),
                domain: Some("weather.com".to_string()),
            },
            WebSource {
                source_id: "bing-hub".to_string(),
                rank: Some(3),
                url: "https://www.bing.com/search?q=current+weather+anderson+sc".to_string(),
                title: Some("Bing".to_string()),
                snippet: Some("Search results page.".to_string()),
                domain: Some("bing.com".to_string()),
            },
            WebSource {
                source_id: "rapidtables".to_string(),
                rank: Some(4),
                url: "https://www.rapidtables.com/math/symbols/Basic_Math_Symbols.html".to_string(),
                title: Some("Math Symbols List".to_string()),
                snippet: Some("Basic math symbols and examples.".to_string()),
                domain: Some("rapidtables.com".to_string()),
            },
        ],
        documents: vec![],
    };

    let plan = pre_read_candidate_plan_from_bundle(
        "What's the weather right now in Anderson, SC?",
        2,
        &bundle,
    );
    assert!(
        !plan.candidate_urls.is_empty(),
        "grounded weather candidates should remain available for read acquisition: {:?}",
        plan
    );
    assert!(
        plan.candidate_urls
            .iter()
            .any(|url| url.contains("anderson")),
        "expected Anderson-localized weather candidates, got {:?}",
        plan.candidate_urls
    );
    assert!(
        plan.candidate_urls
            .iter()
            .all(|url| !url.contains("bing.com/search") && !url.contains("rapidtables.com")),
        "search hubs and unrelated pages should be pruned: {:?}",
        plan.candidate_urls
    );
}
