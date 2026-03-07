use super::*;

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
        source_observations: vec![],
        documents: vec![],
        provider_candidates: vec![],
        retrieval_contract: None,
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
        source_observations: vec![],
        documents: vec![],
        provider_candidates: vec![],
        retrieval_contract: None,
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
        source_observations: vec![],
        documents: vec![],
        provider_candidates: vec![],
        retrieval_contract: None,
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
        source_observations: vec![],
        documents: vec![],
        provider_candidates: vec![],
        retrieval_contract: None,
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
        source_observations: vec![],
        documents: vec![],
        provider_candidates: vec![],
        retrieval_contract: None,
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
fn web_pipeline_pre_read_keeps_structural_weather_records_without_lexical_host_overlap() {
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:search:aggregate:edge:wttr:current-conditions-text+edge:weather-gov:locality-detail"
            .to_string(),
        query: Some("weather current conditions temperature humidity wind in Anderson, SC".to_string()),
        url: Some(
            "https://wttr.in/Anderson,%20SC?format=%25l%3A+temp+%25t+humidity+%25h+wind+%25w+pressure+%25P+as+of+%25T"
                .to_string(),
        ),
        sources: vec![
            WebSource {
                source_id: "wttr".to_string(),
                rank: Some(1),
                url: "https://wttr.in/Anderson,%20SC?format=%25l%3A+temp+%25t+humidity+%25h+wind+%25w+pressure+%25P+as+of+%25T".to_string(),
                title: Some("Anderson, SC current conditions".to_string()),
                snippet: Some(
                    "Anderson, SC: temp +70°F humidity 66% wind ←2mph pressure 1023hPa as of 20:26:56-0500"
                        .to_string(),
                ),
                domain: Some("wttr.in".to_string()),
            },
            WebSource {
                source_id: "weather-gov".to_string(),
                rank: Some(2),
                url: "https://forecast.weather.gov/MapClick.php?CityName=Anderson&state=SC&site=GSP&textField1=34.5186&textField2=-82.6458&e=0".to_string(),
                title: Some("Anderson, SC current conditions".to_string()),
                snippet: Some("21°C".to_string()),
                domain: Some("forecast.weather.gov".to_string()),
            },
        ],
        source_observations: vec![],
        documents: vec![],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    let plan = pre_read_candidate_plan_from_bundle_with_locality_hint(
        "What's the weather like right now?",
        2,
        &bundle,
        Some("Anderson, SC"),
    );

    assert_eq!(plan.candidate_urls.len(), 2, "plan={:?}", plan);
    assert!(
        plan.candidate_urls
            .iter()
            .any(|url| url.contains("wttr.in/")),
        "expected typed structural weather record to survive compatibility pruning: {:?}",
        plan.candidate_urls
    );
    assert!(
        plan.candidate_urls
            .iter()
            .any(|url| url.contains("forecast.weather.gov/MapClick.php")),
        "expected weather.gov current-conditions detail to remain: {:?}",
        plan.candidate_urls
    );
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
        source_observations: vec![],
        documents: vec![],
        provider_candidates: vec![],
        retrieval_contract: None,
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
        source_observations: vec![],
        documents: vec![],
        provider_candidates: vec![],
        retrieval_contract: None,
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
