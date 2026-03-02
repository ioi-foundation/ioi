use super::*;

#[test]
fn web_pipeline_single_snapshot_degrades_when_probe_budget_is_exhausted() {
    let pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
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
fn web_pipeline_single_snapshot_requests_extra_probe_when_metric_grounding_missing() {
    let pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
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
    let pending = PendingSearchCompletion {
        query: "What's the current price of Bitcoin?".to_string(),
        query_contract: "What's the current price of Bitcoin?".to_string(),
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
    let pending = PendingSearchCompletion {
        query: "What's the current price of Bitcoin?".to_string(),
        query_contract: "What's the current price of Bitcoin?".to_string(),
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
fn web_pipeline_grounded_probe_attempts_remain_available_before_limit() {
    let pending = PendingSearchCompletion {
        query: "Tell me today's top news headlines.".to_string(),
        query_contract: "Tell me today's top news headlines.".to_string(),
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
