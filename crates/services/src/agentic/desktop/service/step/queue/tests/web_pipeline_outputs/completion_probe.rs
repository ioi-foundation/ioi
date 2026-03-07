use super::*;

#[test]
fn web_pipeline_single_snapshot_degrades_when_probe_budget_is_exhausted() {
    let pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=anderson+sc+weather+right+now".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://weather.com/weather/today/l/Anderson%20SC".to_string(),
            "https://www.foxweather.com/local-weather/south-carolina/anderson".to_string(),
            "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327".to_string(),
        ],
        candidate_source_hints: vec![],
        attempted_urls: vec![
            "https://weather.com/weather/today/l/Anderson%20SC".to_string(),
            "https://www.foxweather.com/local-weather/south-carolina/anderson".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://weather.com/weather/today/l/Anderson%20SC".to_string(),
                title: Some(
                    "Weather Forecast and Conditions for Anderson, South Carolina 29621 | weather.com"
                        .to_string(),
                ),
                excerpt: "Today's and tonight's Anderson, South Carolina 29621 weather forecast and conditions."
                    .to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://www.foxweather.com/local-weather/south-carolina/anderson".to_string(),
                title: Some("Anderson, SC Weather Forecast".to_string()),
                excerpt: "South Carolina has seen several small earthquakes since February started."
                    .to_string(),
            },
        ],
        min_sources: 2,
    };

    let reason = web_pipeline_completion_reason(&pending, 1_771_465_420_000)
        .expect("remaining budget is too low for another probe");
    assert_eq!(reason, WebPipelineCompletionReason::ExhaustedCandidates);
}

#[test]
fn web_pipeline_grounded_external_defers_completion_when_blocked_and_probe_budget_allows() {
    let pending = PendingSearchCompletion {
        query: "As of now (UTC), top 3 active U.S.-impacting cloud/SaaS incidents from major status pages with 2 citations each.".to_string(),
        query_contract:
            "As of now (UTC), top 3 active U.S.-impacting cloud/SaaS incidents from major status pages with 2 citations each."
                .to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=cloud+saas+incidents+status+pages".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://www.reddit.com/r/MicrosoftTeams/comments/1crvhbg/accidentally_found_the_best_way_to_keep_active/"
                .to_string(),
            title: Some("Accidentally found the best way to keep active status".to_string()),
            excerpt: "Thread with no official status-page update.".to_string(),
        }],
        attempted_urls: vec![
            "https://duckduckgo.com/?q=cloud+saas+incidents+status+pages".to_string(),
            "https://www.reddit.com/r/MicrosoftTeams/comments/1crvhbg/accidentally_found_the_best_way_to_keep_active/"
                .to_string(),
        ],
        blocked_urls: vec![
            "https://www.reddit.com/r/MicrosoftTeams/comments/1crvhbg/accidentally_found_the_best_way_to_keep_active/"
                .to_string(),
        ],
        successful_reads: vec![],
        min_sources: 1,
    };

    let reason = web_pipeline_completion_reason(&pending, 1_771_465_380_000);
    assert!(
        reason.is_none(),
        "grounded external probe recovery should defer completion after blocked-only reads; got {:?}",
        reason
    );
}

#[test]
fn web_pipeline_single_snapshot_defers_completion_when_source_floor_unmet_and_probe_budget_allows()
{
    let pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=anderson+sc+weather+right+now".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![],
        candidate_source_hints: vec![],
        attempted_urls: vec![
            "https://www.theweathernetwork.com/en/city/us/south-carolina/anderson/hourly"
                .to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://www.theweathernetwork.com/en/city/us/south-carolina/anderson/hourly"
                .to_string(),
            title: Some("Anderson, SC Hourly Forecast".to_string()),
            excerpt: "Anderson hourly weather forecast.".to_string(),
        }],
        min_sources: 2,
    };

    let reason = web_pipeline_completion_reason(&pending, 1_771_465_380_000);
    assert!(
        reason.is_none(),
        "source-floor gap with remaining probe budget should keep pipeline active for one bounded recovery search; got {:?}",
        reason
    );
}

#[test]
fn web_pipeline_local_business_comparison_defers_completion_until_distinct_entities_are_matched() {
    let pending = PendingSearchCompletion {
        query: "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus."
            .to_string(),
        query_contract:
            "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus."
                .to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=best+reviewed+italian+restaurants+new+york+menus"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec!["https://www.viacarota.com/dinner".to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://www.viacarota.com/dinner".to_string(),
            title: Some("Via Carota Dinner".to_string()),
            excerpt: "Italian restaurant in New York, NY serving cacio e pepe and seasonal plates."
                .to_string(),
        }],
        attempted_urls: vec![
            format!(
                "ioi://local-business-expansion/query/{}",
                local_business_expansion_query(
                    "Via Carota",
                    "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus.",
                    Some("New York, NY"),
                )
                .expect("expansion query")
            ),
            format!(
                "ioi://local-business-expansion/query/{}",
                local_business_expansion_query(
                    "Frankies (457) Spuntino",
                    "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus.",
                    Some("New York, NY"),
                )
                .expect("expansion query")
            ),
            format!(
                "ioi://local-business-expansion/query/{}",
                local_business_expansion_query(
                    "Roscioli",
                    "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus.",
                    Some("New York, NY"),
                )
                .expect("expansion query")
            ),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.timeout.com/newyork/restaurants/roscioli-nyc".to_string(),
                title: Some("Roscioli NYC".to_string()),
                excerpt:
                    "Italian restaurant in New York, NY with Roman pasta, wine and antipasti."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.yelp.com/biz/roscioli-new-york-2".to_string(),
                title: Some("Roscioli".to_string()),
                excerpt:
                    "ROSClOLI in New York, NY with pasta, antipasti and house specialties."
                        .to_string(),
            },
        ],
        min_sources: 3,
    };

    assert!(query_requires_local_business_entity_diversity(
        &pending.query_contract
    ));
    assert_eq!(
        local_business_target_names_from_attempted_urls(
            &pending.attempted_urls,
            Some("New York, NY")
        ),
        vec![
            "Via Carota".to_string(),
            "Frankies Spuntino".to_string(),
            "Roscioli".to_string()
        ]
    );
    assert_eq!(
        matched_local_business_target_names(
            &[
                "Via Carota".to_string(),
                "Frankies Spuntino".to_string(),
                "Roscioli".to_string()
            ],
            &pending.successful_reads,
            Some("New York, NY")
        ),
        vec!["Roscioli".to_string()]
    );

    let reason = web_pipeline_completion_reason(&pending, 1_771_465_380_000);
    assert!(
        reason.is_none(),
        "distinct-entity floor gap should keep the local-business comparison pipeline active; got {:?}",
        reason
    );
}

#[test]
fn web_pipeline_local_business_comparison_defers_completion_until_targets_are_discovered() {
    let pending = PendingSearchCompletion {
        query: "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus."
            .to_string(),
        query_contract:
            "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus."
                .to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=best+reviewed+italian+restaurants+new+york+menus"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://www.timeout.com/newyork/restaurants/best-italian-restaurants-in-nyc"
                .to_string(),
        ],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://www.timeout.com/newyork/restaurants/best-italian-restaurants-in-nyc"
                .to_string(),
            title: Some("Best Italian Restaurants in NYC".to_string()),
            excerpt:
                "Menus, reviews and ratings for Italian restaurants in New York, NY."
                    .to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.eater.com/nyc/italian-restaurant-reviews".to_string(),
                title: Some("The Best Italian Restaurants in NYC".to_string()),
                excerpt:
                    "Restaurant reviews and dining guide for the best Italian restaurants in New York, NY."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.timeout.com/newyork/restaurants/best-italian-restaurants-in-nyc"
                    .to_string(),
                title: Some("Best Italian Restaurants in NYC".to_string()),
                excerpt:
                    "Menus, reviews and ratings for Italian restaurants in New York, NY."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.nytimes.com/section/dining/italian-restaurants-nyc"
                    .to_string(),
                title: Some("Italian Restaurants NYC".to_string()),
                excerpt:
                    "Dining coverage of Italian restaurants in New York, NY with review context."
                        .to_string(),
            },
        ],
        min_sources: 3,
    };

    assert!(query_requires_local_business_entity_diversity(
        &pending.query_contract
    ));
    assert_eq!(
        local_business_target_names_from_attempted_urls(
            &pending.attempted_urls,
            Some("New York, NY")
        ),
        Vec::<String>::new()
    );

    let reason = web_pipeline_completion_reason(&pending, 1_771_465_380_000);
    assert!(
        reason.is_none(),
        "missing target discovery should keep the local-business comparison pipeline active; got {:?}",
        reason
    );
}

#[test]
fn web_pipeline_local_business_comparison_completes_with_same_domain_distinct_target_sources() {
    let pending = PendingSearchCompletion {
        query: "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus."
            .to_string(),
        query_contract:
            "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus."
                .to_string(),
        retrieval_contract: None,
        url: "https://www.bing.com/search?q=italian+restaurants+anderson+sc".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://www.restaurantji.com/sc/anderson/public-well-cafe-and-pizza-/".to_string(),
            "https://www.restaurantji.com/sc/anderson/dolce-vita-italian-bistro-and-pizzeria-/"
                .to_string(),
            "https://www.restaurantji.com/sc/anderson/the-common-house-/".to_string(),
        ],
        candidate_source_hints: vec![],
        attempted_urls: vec![
            format!(
                "ioi://local-business-expansion/query/{}",
                local_business_expansion_query(
                    "Public Well Cafe and Pizza",
                    "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.",
                    Some("Anderson, SC"),
                )
                .expect("expansion query")
            ),
            format!(
                "ioi://local-business-expansion/query/{}",
                local_business_expansion_query(
                    "Dolce Vita Italian Bistro and Pizzeria",
                    "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.",
                    Some("Anderson, SC"),
                )
                .expect("expansion query")
            ),
            format!(
                "ioi://local-business-expansion/query/{}",
                local_business_expansion_query(
                    "The Common House",
                    "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.",
                    Some("Anderson, SC"),
                )
                .expect("expansion query")
            ),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.restaurantji.com/sc/anderson/public-well-cafe-and-pizza-/"
                    .to_string(),
                title: Some(
                    "Public Well Cafe and Pizza, Anderson - Menu, Reviews (205), Photos (34) - Restaurantji"
                        .to_string(),
                ),
                excerpt:
                    "Italian restaurant in Anderson, SC with pizza, pasta, sandwiches and 205 reviews."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.restaurantji.com/sc/anderson/dolce-vita-italian-bistro-and-pizzeria-/"
                    .to_string(),
                title: Some(
                    "Dolce Vita Italian Bistro and Pizzeria, Anderson - Menu, Reviews (278), Photos (51) - Restaurantji"
                        .to_string(),
                ),
                excerpt:
                    "Italian restaurant in Anderson, SC with pasta, pizza, menu highlights and 278 reviews."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.restaurantji.com/sc/anderson/the-common-house-/".to_string(),
                title: Some(
                    "The Common House, Anderson - Menu, Reviews (231), Photos (41) - Restaurantji"
                        .to_string(),
                ),
                excerpt:
                    "Restaurant in Anderson, SC with dinner menu specials, cocktails and 231 reviews."
                        .to_string(),
            },
        ],
        min_sources: 3,
    };

    let reason = web_pipeline_completion_reason(&pending, 1_771_465_380_000)
        .expect("same-domain distinct target sources should allow completion");
    assert_eq!(reason, WebPipelineCompletionReason::MinSourcesReached);
}

#[test]
fn web_pipeline_single_snapshot_requests_extra_probe_when_metric_grounding_missing() {
    let pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=anderson+sc+weather+right+now".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://weather.com/weather/today/l/Anderson%20SC".to_string(),
            "https://www.foxweather.com/local-weather/south-carolina/anderson".to_string(),
            "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327".to_string(),
        ],
        candidate_source_hints: vec![crate::agentic::desktop::types::PendingSearchReadSummary {
            url: "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327"
                .to_string(),
            title: Some("Anderson, SC Current Weather".to_string()),
            excerpt: "Current conditions in Anderson: temperature 62 F, humidity 42%, wind 4 mph."
                .to_string(),
        }],
        attempted_urls: vec![
            "https://weather.com/weather/today/l/Anderson%20SC".to_string(),
            "https://www.foxweather.com/local-weather/south-carolina/anderson".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://weather.com/weather/today/l/Anderson%20SC".to_string(),
                title: Some(
                    "Weather Forecast and Conditions for Anderson, South Carolina 29621 | weather.com"
                        .to_string(),
                ),
                excerpt: "Today's and tonight's Anderson, South Carolina 29621 weather forecast and conditions."
                    .to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://www.foxweather.com/local-weather/south-carolina/anderson".to_string(),
                title: Some("Anderson, SC Weather Forecast".to_string()),
                excerpt: "South Carolina has seen several small earthquakes since February started."
                    .to_string(),
            },
        ],
        min_sources: 2,
    };

    let reason = web_pipeline_completion_reason(&pending, 1_771_465_380_000);
    assert!(
        reason.is_none(),
        "metric grounding gap should keep pipeline active for one bounded probe; got {:?}",
        reason
    );
}

#[test]
fn web_pipeline_single_snapshot_respects_probe_cap_when_metric_grounding_missing() {
    let pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=anderson+sc+weather+right+now".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://weather.com/weather/today/l/Anderson%20SC".to_string(),
            "https://www.foxweather.com/local-weather/south-carolina/anderson".to_string(),
            "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327".to_string(),
            "https://www.wunderground.com/weather/us/sc/anderson".to_string(),
        ],
        candidate_source_hints: vec![],
        attempted_urls: vec![
            "https://weather.com/weather/today/l/Anderson%20SC".to_string(),
            "https://www.foxweather.com/local-weather/south-carolina/anderson".to_string(),
            "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://weather.com/weather/today/l/Anderson%20SC".to_string(),
                title: Some(
                    "Weather Forecast and Conditions for Anderson, South Carolina 29621 | weather.com"
                        .to_string(),
                ),
                excerpt: "Today's and tonight's Anderson, South Carolina 29621 weather forecast and conditions."
                    .to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://www.foxweather.com/local-weather/south-carolina/anderson".to_string(),
                title: Some("Anderson, SC Weather Forecast".to_string()),
                excerpt: "South Carolina has seen several small earthquakes since February started."
                    .to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327"
                    .to_string(),
                title: Some("Anderson, SC Weather Forecast".to_string()),
                excerpt:
                    "Sat, Feb 21 cooler with occasional rain. Hi: 65°. Tonight: Mainly cloudy."
                        .to_string(),
            },
        ],
        min_sources: 2,
    };

    let reason = web_pipeline_completion_reason(&pending, 1_771_465_390_000)
        .expect("probe cap should stop additional source churn");
    assert_eq!(reason, WebPipelineCompletionReason::ExhaustedCandidates);
}

#[test]
fn web_pipeline_single_snapshot_allows_candidate_read_after_additional_search_attempt() {
    let pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=anderson+sc+weather+right+now".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://weather.com/weather/today/l/Anderson%20SC".to_string(),
            "https://www.foxweather.com/local-weather/south-carolina/anderson".to_string(),
            "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327".to_string(),
        ],
        candidate_source_hints: vec![crate::agentic::desktop::types::PendingSearchReadSummary {
            url: "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327"
                .to_string(),
            title: Some("Anderson, SC Current Weather".to_string()),
            excerpt: "Current conditions in Anderson: temperature 62 F, humidity 42%, wind 4 mph."
                .to_string(),
        }],
        attempted_urls: vec![
            "https://weather.com/weather/today/l/Anderson%20SC".to_string(),
            "https://www.foxweather.com/local-weather/south-carolina/anderson".to_string(),
            "https://www.bing.com/search?q=anderson+sc+weather+current+conditions".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://weather.com/weather/today/l/Anderson%20SC".to_string(),
                title: Some(
                    "Weather Forecast and Conditions for Anderson, South Carolina 29621 | weather.com"
                        .to_string(),
                ),
                excerpt: "Today's and tonight's Anderson, South Carolina 29621 weather forecast and conditions."
                    .to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://www.foxweather.com/local-weather/south-carolina/anderson".to_string(),
                title: Some("Anderson, SC Weather Forecast".to_string()),
                excerpt: "South Carolina has seen several small earthquakes since February started."
                    .to_string(),
            },
        ],
        min_sources: 2,
    };

    let reason = web_pipeline_completion_reason(&pending, 1_771_465_380_000);
    assert!(
        reason.is_none(),
        "after one additional search attempt, pipeline should consume actionable candidate reads before completion; got {:?}",
        reason
    );
}

#[test]
fn web_pipeline_single_snapshot_runs_one_pre_emit_recovery_probe_when_metrics_missing() {
    let pending = PendingSearchCompletion {
        query: "what's the weather right now in anderson, sc".to_string(),
        query_contract: "what's the weather right now in anderson, sc".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=anderson+sc+weather+right+now".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://www.weather-forecast.com/locations/Anderson/forecasts/latest"
                    .to_string(),
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
        ],
        attempted_urls: vec![
            "https://www.weather-forecast.com/locations/Anderson/forecasts/latest".to_string(),
            "https://www.accuweather.com/en/us/anderson/29624/weather-forecast/330677".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.weather-forecast.com/locations/Anderson/forecasts/latest"
                    .to_string(),
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
        ],
        min_sources: 2,
    };

    let reason = web_pipeline_completion_reason(&pending, 1_771_465_380_000);
    assert!(
        reason.is_none(),
        "pre-emit gate should schedule one recovery probe before finalizing weak current-weather output; got {:?}",
        reason
    );
}

#[test]
fn web_pipeline_single_snapshot_stops_pre_emit_recovery_after_probe_attempt() {
    let pending = PendingSearchCompletion {
        query: "what's the weather right now in anderson, sc current conditions temperature humidity wind"
            .to_string(),
        query_contract: "what's the weather right now in anderson, sc".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=anderson+sc+weather+right+now".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://www.weather-forecast.com/locations/Anderson/forecasts/latest"
                    .to_string(),
                title: Some("Anderson, South Carolina Weather Forecast".to_string()),
                excerpt:
                    "Providing a local hourly Anderson (South Carolina) weather forecast."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.accuweather.com/en/us/anderson/29624/weather-forecast/330677"
                    .to_string(),
                title: Some("Anderson, SC Weather Forecast".to_string()),
                excerpt:
                    "Anderson, SC Weather Forecast, with current conditions and next 3 days."
                        .to_string(),
            },
        ],
        attempted_urls: vec![
            "https://www.bing.com/search?q=anderson+sc+weather+current+conditions+temperature+humidity+wind"
                .to_string(),
            "https://www.weather-forecast.com/locations/Anderson/forecasts/latest".to_string(),
            "https://www.accuweather.com/en/us/anderson/29624/weather-forecast/330677".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.weather-forecast.com/locations/Anderson/forecasts/latest"
                    .to_string(),
                title: Some("Anderson, South Carolina Weather Forecast".to_string()),
                excerpt:
                    "Providing a local hourly Anderson (South Carolina) weather forecast."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.accuweather.com/en/us/anderson/29624/weather-forecast/330677"
                    .to_string(),
                title: Some("Anderson, SC Weather Forecast".to_string()),
                excerpt:
                    "Anderson, SC Weather Forecast, with current conditions and next 3 days."
                        .to_string(),
            },
        ],
        min_sources: 2,
    };

    let reason = web_pipeline_completion_reason(&pending, 1_771_465_380_000)
        .expect("recovery probe should be bounded to one deterministic attempt");
    assert_eq!(reason, WebPipelineCompletionReason::ExhaustedCandidates);
}

#[test]
fn web_pipeline_single_snapshot_defers_completion_when_post_probe_candidate_is_actionable() {
    let pending = PendingSearchCompletion {
        query: "what's the weather right now in anderson, sc current conditions temperature humidity wind"
            .to_string(),
        query_contract: "what's the weather right now in anderson, sc".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=anderson+sc+weather+right+now".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec!["https://www.weather.com/weather/today/l/Anderson+SC".to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://www.weather.com/weather/today/l/Anderson+SC".to_string(),
            title: Some("Anderson, SC Current Weather".to_string()),
            excerpt: "Current conditions in Anderson: temperature 62 F, humidity 42%, wind 4 mph."
                .to_string(),
        }],
        attempted_urls: vec![
            "https://www.bing.com/search?q=anderson+sc+weather+current+conditions+temperature+humidity+wind"
                .to_string(),
            "https://www.weather-forecast.com/locations/Anderson/forecasts/latest".to_string(),
            "https://www.accuweather.com/en/us/anderson/29624/weather-forecast/330677".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.weather-forecast.com/locations/Anderson/forecasts/latest"
                    .to_string(),
                title: Some("Anderson, South Carolina Weather Forecast".to_string()),
                excerpt:
                    "Providing a local hourly Anderson (South Carolina) weather forecast."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.accuweather.com/en/us/anderson/29624/weather-forecast/330677"
                    .to_string(),
                title: Some("Anderson, SC Weather Forecast".to_string()),
                excerpt:
                    "Anderson, SC Weather Forecast, with current conditions and next 3 days."
                        .to_string(),
            },
        ],
        min_sources: 2,
    };

    let reason = web_pipeline_completion_reason(&pending, 1_771_465_380_000);
    assert!(
        reason.is_none(),
        "post-probe actionable candidate should keep pipeline active for one additional read; got {:?}",
        reason
    );
}

#[test]
fn web_pipeline_single_snapshot_continues_when_grounded_hints_lack_resolvable_metrics() {
    let pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=anderson+sc+weather+right+now".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://weather.com/weather/tenday/l/Anderson%20SC".to_string(),
            "https://www.foxweather.com/local-weather/south-carolina/anderson".to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://weather.com/weather/tenday/l/Anderson%20SC".to_string(),
                title: Some("Anderson, SC 10-Day Weather Forecast".to_string()),
                excerpt: "Daily forecast page with hourly and monthly sections.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.foxweather.com/local-weather/south-carolina/anderson".to_string(),
                title: Some("Anderson, SC Weather Forecast".to_string()),
                excerpt: "Local weather source page with radar and forecast updates.".to_string(),
            },
        ],
        attempted_urls: vec!["https://weather.com/weather/tenday/l/Anderson%20SC".to_string()],
        blocked_urls: vec![],
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://weather.com/weather/tenday/l/Anderson%20SC".to_string(),
            title: Some("Anderson, SC 10-Day Weather Forecast".to_string()),
            excerpt: "10-day outlook with highs and lows; no current observation table in snippet."
                .to_string(),
        }],
        min_sources: 2,
    };

    let reason = web_pipeline_completion_reason(&pending, 1_771_465_390_000);
    assert!(
        reason.is_none(),
        "pipeline should continue probing/reading when grounded hints still lack resolvable metrics; got {:?}",
        reason
    );
}

#[test]
fn web_pipeline_single_snapshot_keeps_running_for_price_queries_when_only_valuation_snippets_exist()
{
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
    let pending = PendingSearchCompletion {
        query: "What's the current price of Bitcoin?".to_string(),
        query_contract: "What's the current price of Bitcoin?".to_string(),
        retrieval_contract: Some(retrieval_contract.clone()),
        url: "https://www.bing.com/search?q=current+bitcoin+price".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://www.coindesk.com/price/bitcoin".to_string(),
            "https://crypto.news/price/bitcoin/".to_string(),
            "https://www.coinbase.com/price/bitcoin".to_string(),
        ],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://www.coinbase.com/price/bitcoin".to_string(),
            title: Some("Coinbase Bitcoin Price".to_string()),
            excerpt: "BTC price right now: $86,743.63 USD.".to_string(),
        }],
        attempted_urls: vec![
            "https://www.coindesk.com/price/bitcoin".to_string(),
            "https://crypto.news/price/bitcoin/".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.coindesk.com/price/bitcoin".to_string(),
                title: Some("CoinDesk Bitcoin price".to_string()),
                excerpt: "Overview and market data for Bitcoin with charts and market cap."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://crypto.news/price/bitcoin/".to_string(),
                title: Some("Crypto.news Bitcoin price".to_string()),
                excerpt: "2 million BTC valued at about $36 billion at the current price."
                    .to_string(),
            },
        ],
        min_sources: 2,
    };

    let reason = web_pipeline_completion_reason(&pending, 1_771_465_380_000);
    assert!(
        reason.is_none(),
        "valuation-only snippets should keep price query pipeline active for a resolvable quote source; got {:?}",
        reason
    );
}

#[test]
fn web_pipeline_single_snapshot_completes_price_queries_when_explicit_quote_is_present() {
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
    let pending = PendingSearchCompletion {
        query: "What's the current price of Bitcoin?".to_string(),
        query_contract: "What's the current price of Bitcoin?".to_string(),
        retrieval_contract: Some(retrieval_contract.clone()),
        url: "https://www.bing.com/search?q=current+bitcoin+price".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://www.coindesk.com/price/bitcoin".to_string(),
            "https://www.coinbase.com/price/bitcoin".to_string(),
        ],
        candidate_source_hints: vec![],
        attempted_urls: vec![
            "https://www.coindesk.com/price/bitcoin".to_string(),
            "https://www.coinbase.com/price/bitcoin".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.coindesk.com/price/bitcoin".to_string(),
                title: Some("CoinDesk Bitcoin price".to_string()),
                excerpt: "Bitcoin price right now: $86,743.63 USD as of 17:23 UTC.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.coinbase.com/price/bitcoin".to_string(),
                title: Some("Coinbase Bitcoin price".to_string()),
                excerpt: "Current BTC quote: 86,744 USD.".to_string(),
            },
        ],
        min_sources: 2,
    };

    let reason = web_pipeline_completion_reason(&pending, 1_771_465_380_000)
        .expect("explicit quote grounding should allow completion");
    assert_eq!(reason, WebPipelineCompletionReason::MinSourcesReached);
}

#[test]
fn web_pipeline_single_snapshot_keeps_running_for_stale_price_snippets() {
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
    let pending = PendingSearchCompletion {
        query: "What's the current price of Bitcoin?".to_string(),
        query_contract: "What's the current price of Bitcoin?".to_string(),
        retrieval_contract: Some(retrieval_contract),
        url: "https://search.brave.com/search?q=current+bitcoin+price".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://www.coindesk.com/price/bitcoin".to_string(),
            "https://www.coinbase.com/price/bitcoin".to_string(),
        ],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://www.coinbase.com/price/bitcoin".to_string(),
            title: Some("Coinbase Bitcoin price".to_string()),
            excerpt: "Current BTC quote: 86,744 USD.".to_string(),
        }],
        attempted_urls: vec!["https://www.coindesk.com/price/bitcoin".to_string()],
        blocked_urls: vec![],
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://www.coindesk.com/price/bitcoin".to_string(),
            title: Some("CoinDesk Bitcoin price".to_string()),
            excerpt: "3 weeks ago - The price of Bitcoin (BTC) is $68,111.".to_string(),
        }],
        min_sources: 1,
    };

    let reason = web_pipeline_completion_reason(&pending, 1_771_465_380_000);
    assert!(
        reason.is_none(),
        "stale age-labelled snippets should not satisfy current price grounding: {:?}",
        reason
    );
}

#[test]
fn web_pipeline_single_snapshot_keeps_running_after_two_unresolved_reads_when_candidates_remain() {
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
    let pending = PendingSearchCompletion {
        query: "What's the current price of Bitcoin?".to_string(),
        query_contract: "What's the current price of Bitcoin?".to_string(),
        retrieval_contract: Some(retrieval_contract),
        url: "https://search.brave.com/search?q=current+bitcoin+price".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://www.coindesk.com/price/bitcoin".to_string(),
            "https://crypto.com/en/price/bitcoin".to_string(),
            "https://www.coinbase.com/price/bitcoin".to_string(),
        ],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://www.coinbase.com/price/bitcoin".to_string(),
            title: Some("Coinbase Bitcoin price".to_string()),
            excerpt: "BTC price right now: $86,743.63 USD.".to_string(),
        }],
        attempted_urls: vec![
            "https://www.coindesk.com/price/bitcoin".to_string(),
            "https://crypto.com/en/price/bitcoin".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.coindesk.com/price/bitcoin".to_string(),
                title: Some("CoinDesk Bitcoin price".to_string()),
                excerpt: "Overview and market data for Bitcoin with charts and market cap."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://crypto.com/en/price/bitcoin".to_string(),
                title: Some(
                    "Bitcoin (BTC) Price Today: BTC Live Price, Charts, News - Crypto.com International"
                        .to_string(),
                ),
                excerpt: "80% in the last 24 hours".to_string(),
            },
        ],
        min_sources: 1,
    };

    let reason = web_pipeline_completion_reason(&pending, 1_771_465_380_000);
    assert!(
        reason.is_none(),
        "unresolved price reads should not terminate the pipeline while more candidates remain: {:?}",
        reason
    );
}

#[test]
fn web_pipeline_grounded_probe_attempts_remain_available_before_limit() {
    let pending = PendingSearchCompletion {
        query: "Tell me today's top news headlines.".to_string(),
        query_contract: "Tell me today's top news headlines.".to_string(),
        retrieval_contract: None,
        url: "https://www.bing.com/search?q=today+top+news+headlines".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![],
        candidate_source_hints: vec![],
        attempted_urls: vec![
            "https://www.bing.com/search?q=today+top+news+headlines".to_string(),
            "https://www.bing.com/search?q=latest+top+news+headlines+world".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 3,
    };

    assert!(web_pipeline_grounded_probe_attempt_available(&pending));
}

#[test]
fn web_pipeline_grounded_probe_attempts_stop_at_limit() {
    let pending = PendingSearchCompletion {
        query: "Tell me today's top news headlines.".to_string(),
        query_contract: "Tell me today's top news headlines.".to_string(),
        retrieval_contract: None,
        url: "https://www.bing.com/search?q=today+top+news+headlines".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![],
        candidate_source_hints: vec![],
        attempted_urls: vec![
            "https://www.bing.com/search?q=today+top+news+headlines".to_string(),
            "https://www.bing.com/search?q=latest+top+news+headlines+world".to_string(),
            "https://www.bing.com/search?q=latest+top+news+headlines+politics".to_string(),
            "https://www.bing.com/search?q=latest+top+news+headlines+business".to_string(),
            "https://www.bing.com/search?q=latest+top+news+headlines+us".to_string(),
            "https://www.bing.com/search?q=latest+top+news+headlines+global".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 3,
    };

    assert!(!web_pipeline_grounded_probe_attempt_available(&pending));
}

#[test]
fn web_pipeline_headline_completion_defers_when_only_roundup_pages_succeeded() {
    let pending = PendingSearchCompletion {
        query: "Tell me today's top news headlines.".to_string(),
        query_contract: "Tell me today's top news headlines.".to_string(),
        retrieval_contract: None,
        url: "https://www.bing.com/search?q=today+top+news+headlines".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://www.today.com/parents/family/viral-teacher-tiktok-cursing-rule-rcna262092"
                .to_string(),
        ],
        candidate_source_hints: vec![],
        attempted_urls: vec![
            "https://www.bing.com/search?q=today+top+news+headlines".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://sundayguardianlive.com/news/school-assembly-news-headlines-today-march-05-top-national-business-news-sports-news-education-news-world-news-with-weather-updates-thought-of-the-day-174036/".to_string(),
                title: Some(
                    "School Assembly News Headlines Today March 05 Top National Business News Sports News Education News World News with Weather Updates Thought of the Day".to_string(),
                ),
                excerpt:
                    "Daily school assembly roundup with thought of the day and headline digest."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://m.economictimes.com/news/new-updates/school-assembly-news-headlines-for-march-7-top-national-international-business-sports-update-and-thought-of-the-day/articleshow/129151758.cms".to_string(),
                title: Some(
                    "School Assembly News Headlines for March 7 Top National International Business Sports Update and Thought of the Day".to_string(),
                ),
                excerpt:
                    "School assembly roundup with top national and international updates."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://bestcolleges.indiatoday.in/news-detail/school-assembly-news-headlines-today-march-7-top-national-sports-and-world-news-curated-for-you-8335".to_string(),
                title: Some(
                    "School Assembly News Headlines Today March 7 Top National Sports and World News Curated for You".to_string(),
                ),
                excerpt: "Curated school assembly headlines and thought of the day.".to_string(),
            },
        ],
        min_sources: 3,
    };

    let reason = web_pipeline_completion_reason(&pending, 1_771_465_380_000);
    assert!(
        reason.is_none(),
        "headline completion should remain active when only low-priority roundup pages have succeeded; got {:?}",
        reason
    );
}

#[test]
fn web_pipeline_headline_completion_finishes_with_three_specific_articles_from_live_mix() {
    let pending = PendingSearchCompletion {
        query: "Tell me today's top news headlines.".to_string(),
        query_contract: "Tell me today's top news headlines.".to_string(),
        retrieval_contract: None,
        url: "https://news.google.com/rss?hl=en-US&gl=US&ceid=US:en".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![],
        candidate_source_hints: vec![],
        attempted_urls: vec![
            "https://news.google.com/rss?hl=en-US&gl=US&ceid=US:en".to_string(),
            "https://www.channel3000.com/video/morning-sprint-march-6-mornings-top-news-and-weather-headlines/video_ae4a4a71-9eb5-5c14-a70a-908f6377ceaa.html".to_string(),
            "https://www.wmar2news.com/local/top-news-headlines-for-thursday-march-5-2026".to_string(),
            "https://apnews.com/article/iran-sri-lanka-iris-bushehr-9b3c31177bf8bf8accf22cf3add241d7".to_string(),
            "https://www.okayafrica.com/today-in-africa-mar-6-2026-wafcon-postponed-uganda-evacuates-43-students-from-iran/1410384".to_string(),
            "https://www.cnbc.com/2026/03/06/trump-trade-tariffs-refunds-customs-border-protection.html".to_string(),
            "https://www.wmar2news.com/local/top-news-headlines-for-friday-march-6".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.channel3000.com/video/morning-sprint-march-6-mornings-top-news-and-weather-headlines/video_ae4a4a71-9eb5-5c14-a70a-908f6377ceaa.html".to_string(),
                title: Some(
                    "Morning Sprint: March 6 morning's top news and weather headlines - Channel 3000".to_string(),
                ),
                excerpt: "Morning roundup video covering the day's top news and weather headlines."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.wmar2news.com/local/top-news-headlines-for-thursday-march-5-2026".to_string(),
                title: Some(
                    "Top News Headlines for Thursday, March 5, 2026 - WMAR 2 News Baltimore"
                        .to_string(),
                ),
                excerpt: "Baltimore roundup of the day's top headlines.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://apnews.com/article/iran-sri-lanka-iris-bushehr-9b3c31177bf8bf8accf22cf3add241d7".to_string(),
                title: Some(
                    "Sri Lanka takes custody of an Iranian vessel off its coast after US sank an Iranian warship - AP News"
                        .to_string(),
                ),
                excerpt:
                    "AP News | source_url=https://apnews.com/article/iran-sri-lanka-iris-bushehr-9b3c31177bf8bf8accf22cf3add241d7"
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.okayafrica.com/today-in-africa-mar-6-2026-wafcon-postponed-uganda-evacuates-43-students-from-iran/1410384".to_string(),
                title: Some(
                    "Mar 6: WAFCON Postponed, Uganda Evacuates 43 Students From Iran"
                        .to_string(),
                ),
                excerpt:
                    "OkayAfrica | source_url=https://www.okayafrica.com/today-in-africa-mar-6-2026-wafcon-postponed-uganda-evacuates-43-students-from-iran/1410384"
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.cnbc.com/2026/03/06/trump-trade-tariffs-refunds-customs-border-protection.html".to_string(),
                title: Some(
                    "Trump tariffs: Customs and Border Protection tells judge it can't comply with refund order - CNBC".to_string(),
                ),
                excerpt:
                    "CNBC | source_url=https://www.cnbc.com/2026/03/06/trump-trade-tariffs-refunds-customs-border-protection.html"
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.wmar2news.com/local/top-news-headlines-for-friday-march-6".to_string(),
                title: Some("Top news headlines for Friday, March 6 - WMAR 2 News Baltimore".to_string()),
                excerpt: "Local roundup of Friday's top headlines.".to_string(),
            },
        ],
        min_sources: 3,
    };

    let reason = web_pipeline_completion_reason(&pending, 1_771_465_380_000)
        .expect("three specific article reads should satisfy the headline story floor");
    assert_eq!(reason, WebPipelineCompletionReason::MinSourcesReached);
}
