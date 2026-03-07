use super::*;
use crate::agentic::desktop::service::step::queue::support::concise_metric_snapshot_line;

#[test]
fn web_pipeline_single_snapshot_renders_actionable_metric_limitation_when_metrics_absent() {
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
            "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327".to_string(),
        ],
        candidate_source_hints: vec![
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://weather.com/weather/today/l/Anderson%20SC".to_string(),
                title: Some(
                    "Weather Forecast and Conditions for Anderson, South Carolina 29621 | weather.com"
                        .to_string(),
                ),
                excerpt: "Today's and tonight's Anderson, South Carolina 29621 weather forecast, weather conditions and Doppler radar from The Weather Channel and weather.com".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327".to_string(),
                title: Some("Anderson, SC Current Weather".to_string()),
                excerpt: "Current weather source page for Anderson with live radar and forecast updates."
                    .to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    assert!(reply.contains("Current metric status:"));
    assert!(reply
        .to_ascii_lowercase()
        .contains("current-condition metrics were not exposed"));
    assert!(reply.contains("Data caveat: Retrieved source snippets did not expose"));
    assert!(reply.to_ascii_lowercase().contains("estimated-right-now:"));
    assert!(reply
        .to_ascii_lowercase()
        .contains("derived from cited forecast range"));
    assert!(reply.contains("Next step: Open"));
}

#[test]
fn web_pipeline_single_snapshot_renders_structured_metric_bullets_when_observed_values_exist() {
    let pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=anderson+sc+weather+right+now".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://www.theweathernetwork.com/en/city/us/south-carolina/anderson/hourly"
                .to_string(),
            "https://www.accuweather.com/en/us/anderson/29624/current-weather/330677".to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://www.theweathernetwork.com/en/city/us/south-carolina/anderson/hourly"
                    .to_string(),
                title: Some("Anderson, SC Hourly Forecast - The Weather Network".to_string()),
                excerpt:
                    "Current weather report with temperature 62 F, feels like 64 F, humidity 42%, wind 4 mph."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.accuweather.com/en/us/anderson/29624/current-weather/330677"
                    .to_string(),
                title: Some("Anderson, SC Current Weather | AccuWeather".to_string()),
                excerpt:
                    "Current conditions as of 2:00 AM: temperature 61 F, humidity 45%, wind calm."
                        .to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://www.theweathernetwork.com/en/city/us/south-carolina/anderson/hourly"
                .to_string(),
            title: Some("Anderson, SC Hourly Forecast - The Weather Network".to_string()),
            excerpt:
                "Current weather report with temperature 62 F, feels like 64 F, humidity 42%, wind 4 mph."
                    .to_string(),
        }],
        min_sources: 2,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    assert!(
        reply.contains("Right now in Anderson, SC (as of"),
        "expected location-aware heading, got:\n{}",
        reply
    );
    assert!(reply.contains("Current conditions:"), "got:\n{}", reply);
    assert!(
        reply.contains("- Temperature:")
            || reply.contains("- Humidity:")
            || reply.contains("- Wind:"),
        "expected at least one structured metric bullet, got:\n{}",
        reply
    );
    assert!(
        reply.contains("(From "),
        "expected source consistency note, got:\n{}",
        reply
    );
}

#[test]
fn web_pipeline_single_snapshot_partial_metric_caveat_mentions_partial_availability() {
    let pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=current+weather+anderson+sc".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC".to_string(),
            "https://www.theweathernetwork.com/en/city/us/south-carolina/anderson/hourly"
                .to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC".to_string(),
                title: Some("National Weather Service".to_string()),
                excerpt: "Overcast 63°F 17°C".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.theweathernetwork.com/en/city/us/south-carolina/anderson/hourly"
                    .to_string(),
                title: Some("Anderson, SC Hourly Forecast - The Weather Network".to_string()),
                excerpt: "Hourly forecast page for Anderson, SC.".to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC".to_string(),
            title: Some("National Weather Service".to_string()),
            excerpt: "Overcast 63°F 17°C".to_string(),
        }],
        min_sources: 2,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    assert!(
        reply.contains("Available observed details from cited source text:")
            || reply.contains("Current conditions from retrieved source text:")
            || reply.contains("Current conditions from cited source text:"),
        "expected metric-oriented summary line, got:\n{}",
        reply
    );
    assert!(reply.contains("Current metric status:"), "got:\n{}", reply);
    assert!(
        reply.contains("partial numeric current-condition metrics"),
        "expected partial-metric caveat wording, got:\n{}",
        reply
    );
    assert!(
        !reply.contains("did not expose numeric current-condition metrics"),
        "partial metrics should not be described as fully absent:\n{}",
        reply
    );
}

#[test]
fn web_pipeline_single_snapshot_partial_metric_summary_keeps_trailing_numeric_value() {
    let mut citations_by_id = BTreeMap::new();
    citations_by_id.insert(
        "C1".to_string(),
        CitationCandidate {
            id: "C1".to_string(),
            url: "https://weather.yahoo.com/us/sc/anderson".to_string(),
            source_label: "Anderson SC Weather Forecast Conditions and Maps - Yahoo Weather"
                .to_string(),
            excerpt: "Mostly Cloudy today with a high of 61°F and a low of 45°F".to_string(),
            timestamp_utc: "2026-02-23T15:19:10Z".to_string(),
            note: "retrieved_utc; source publish/update timestamp unavailable".to_string(),
            from_successful_read: true,
        },
    );

    let draft = SynthesisDraft {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        retrieval_contract: None,
        run_date: "2026-02-23".to_string(),
        run_timestamp_ms: 1_771_859_150_000,
        run_timestamp_iso_utc: "2026-02-23T15:19:10Z".to_string(),
        completion_reason: "Completed because no additional candidate sources remained.".to_string(),
        overall_confidence: "medium".to_string(),
        overall_caveat: "test".to_string(),
        stories: vec![StoryDraft {
            title: "Anderson, SC Weather Forecast".to_string(),
            what_happened: "Current-condition metrics were not exposed in readable source text from Anderson, SC Weather Forecast at retrieval time.".to_string(),
            changed_last_hour: String::new(),
            why_it_matters: String::new(),
            user_impact: String::new(),
            workaround: String::new(),
            eta_confidence: String::new(),
            citation_ids: vec!["C1".to_string()],
            confidence: "high".to_string(),
            caveat: "test caveat".to_string(),
        }],
        citations_by_id,
        blocked_urls: Vec::new(),
        partial_note: None,
    };

    let reply = render_synthesis_draft(&draft);
    assert!(
        reply.contains("Available observed details from cited source text: Mostly Cloudy today with a high of 61°F and a low of 45°F"),
        "expected summary to keep trailing metric value, got:\n{}",
        reply
    );
}

#[test]
fn web_pipeline_single_snapshot_prefers_current_observation_over_forecast_range() {
    let pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=current+weather+anderson+sc".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC".to_string(),
        ],
        candidate_source_hints: vec![],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC".to_string(),
            title: Some("National Weather Service".to_string()),
            excerpt: "Mostly Cloudy today with a high of 61°F and a low of 45°F. Current conditions at Anderson, Anderson County Airport (KAND): Fair 35°F 2°C Humidity 38% Wind Speed W 8G21 mph."
                .to_string(),
        }],
        min_sources: 1,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    assert!(
        reply.contains("Current conditions from retrieved source text:"),
        "expected current-conditions summary, got:\n{}",
        reply
    );
    assert!(
        reply.contains("35°F"),
        "expected observed temperature, got:\n{}",
        reply
    );
    assert!(
        !reply.contains("Available observed details from cited source text: Mostly Cloudy today"),
        "forecast-only sentence should not be preferred when current observation is present:\n{}",
        reply
    );
}

#[test]
fn web_pipeline_single_snapshot_prefers_current_price_source_over_stale_quote() {
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
        candidate_urls: vec![],
        candidate_source_hints: vec![],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://crypto.com/en/price/bitcoin".to_string(),
                title: Some(
                    "Bitcoin (BTC) Price Today: BTC Live Price, Charts, News - Crypto.com International"
                        .to_string(),
                ),
                excerpt: "3 weeks ago - Bitcoin's price today is $70,107".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://mudrex.com/coins/bitcoin".to_string(),
                title: Some("Bitcoin price today is $68,000.6 in USD live on Mudrex".to_string()),
                excerpt: "Bitcoin price right now: $68,000.6 USD as of 17:23 UTC.".to_string(),
            },
        ],
        min_sources: 1,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    assert!(
        reply.contains("$68,000.6"),
        "expected current quoted price source to anchor the snapshot, got:\n{}",
        reply
    );
    assert!(
        !reply.contains("3 weeks ago - Bitcoin's price today is $70,107"),
        "stale relative-age quote should not outrank a current price source:\n{}",
        reply
    );
}

#[test]
fn web_pipeline_single_snapshot_avoids_pseudo_metric_summary_from_forecast_only_text() {
    let pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        retrieval_contract: None,
        url: "https://www.bing.com/search?q=current+weather+anderson+sc".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://www.weather-forecast.com/locations/Anderson/forecasts/latest".to_string(),
            "https://www.theweathernetwork.com/en/city/us/south-carolina/anderson/hourly"
                .to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://www.weather-forecast.com/locations/Anderson/forecasts/latest"
                    .to_string(),
                title: Some("Anderson, South Carolina Weather Forecast".to_string()),
                excerpt: "Providing a local hourly Anderson weather forecast of rain, sun, wind, humidity and temperature. The Long-range 12 day forecast also includes detail."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.theweathernetwork.com/en/city/us/south-carolina/anderson/hourly"
                    .to_string(),
                title: Some("Anderson, SC Hourly Forecast - The Weather Network".to_string()),
                excerpt: "Get Anderson, SC current weather report with temperature, feels like, wind, humidity and pressure."
                    .to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://www.weather-forecast.com/locations/Anderson/forecasts/latest"
                .to_string(),
            title: Some("Anderson, South Carolina Weather Forecast".to_string()),
            excerpt: "Providing a local hourly Anderson weather forecast of rain, sun, wind, humidity and temperature. The Long-range 12 day forecast also includes detail."
                .to_string(),
        }],
        min_sources: 2,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    assert!(
        !reply.contains("Current conditions: It's **wind humidity and temperature"),
        "summary should not promote lexical forecast copy into metric answer:\n{}",
        reply
    );
    assert!(
        !reply.contains("- Temperature: wind humidity and temperature"),
        "metric bullet should only render actionable quantified values:\n{}",
        reply
    );
    assert!(reply.contains("Current metric status:"), "got:\n{}", reply);
    assert!(reply.contains("Data caveat:"), "got:\n{}", reply);
}

#[test]
fn concise_metric_snapshot_line_keeps_price_quote_pairs_intact() {
    let concise = concise_metric_snapshot_line(
        "Current BTC quote: $86,743.63 per BTC / USD with live market data.",
    );
    assert!(
        concise.contains("BTC / USD"),
        "expected slash-delimited quote pair to remain intact, got:\n{}",
        concise
    );
}

#[test]
fn concise_metric_snapshot_line_strips_existing_summary_prefixes() {
    let concise = concise_metric_snapshot_line(
        "Current conditions from retrieved source text: The live price of Bitcoin is $68,211",
    );
    assert_eq!(concise, "The live price of Bitcoin is $68,211");
}

#[test]
fn concise_metric_snapshot_line_handles_unicode_without_panicking() {
    let concise = concise_metric_snapshot_line(
        "Anderson, SC: temp +65°F humidity 87% wind ↑4mph pressure 1023hPa as of 03:38:03-0500",
    );
    assert!(
        concise.contains("wind ↑4mph"),
        "expected unicode wind direction marker to survive summary compaction, got:\n{}",
        concise
    );
}

#[test]
fn web_pipeline_single_snapshot_emits_next_step_when_limitation_summary_present() {
    let pending = PendingSearchCompletion {
        query: "what's the weather right now".to_string(),
        query_contract: "what's the weather right now".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=current+weather".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://www.localconditions.com/us/pendleton/south-carolina/weather/".to_string(),
            "https://forecast.weather.gov/zipcity.php?inputstring=Pendleton,%20SC".to_string(),
        ],
        candidate_source_hints: vec![],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.localconditions.com/us/pendleton/south-carolina/weather/"
                    .to_string(),
                title: Some(
                    "Pendleton, SC Current Weather Today and Forecast with Radar | LocalConditions.com"
                        .to_string(),
                ),
                excerpt: "Current Report Hour By Hour 5 Day Forecast Radar Warnings & Advisories Traffic Conditions Past 56 °F 13 °C Feels Like 56."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://forecast.weather.gov/zipcity.php?inputstring=Pendleton,%20SC"
                    .to_string(),
                title: Some("7-Day Forecast 34.66N 82.78W - National Weather Service".to_string()),
                excerpt: "NOAA National Weather Service Current conditions at Clemson, Clemson-Oconee County Airport (KCEU) Lat: 34.67°N Lon: 82.88°W Elev: 892ft.".to_string(),
            },
        ],
        min_sources: 2,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    if reply.contains("Current-condition metrics were not exposed")
        || reply.contains("Data caveat: Retrieved source snippets did not expose")
    {
        assert!(reply.contains("Next step: Open"));
    }
}

#[test]
fn web_pipeline_single_snapshot_price_followup_guidance_uses_price_axes_not_weather_text() {
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
        candidate_urls: vec![],
        candidate_source_hints: vec![],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://crypto.com/en/price/bitcoin".to_string(),
            title: Some(
                "Bitcoin (BTC) Price Today: BTC Live Price, Charts, News - Crypto.com International"
                    .to_string(),
            ),
            excerpt: "3 weeks ago - Bitcoin's price today is $70,107".to_string(),
        }],
        min_sources: 1,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    assert!(
        reply.contains("live metric details (Price)"),
        "expected follow-up guidance to be derived from unresolved price axes, got:\n{}",
        reply
    );
    assert!(
        !reply.contains("temperature, feels-like, humidity, wind"),
        "price follow-up guidance should not leak weather-specific text:\n{}",
        reply
    );
}

#[test]
fn web_pipeline_single_snapshot_emits_next_step_when_rendered_summary_implies_limitation() {
    let pending = PendingSearchCompletion {
        query: "Current weather in Anderson, SC right now with sources and UTC timestamp."
            .to_string(),
        query_contract: "Current weather in Anderson, SC right now with sources and UTC timestamp."
            .to_string(),
        retrieval_contract: None,
        url: "https://www.bing.com/search?q=current+weather+anderson+sc".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://weather.com/weather/today/l/Anderson%20SC?canonicalCityId=abc".to_string(),
            "https://www.bing.com/search?q=current+weather+anderson+sc".to_string(),
        ],
        candidate_source_hints: vec![],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://weather.com/weather/today/l/Anderson%20SC?canonicalCityId=abc"
                    .to_string(),
                title: Some(
                    "Weather Forecast and Conditions for Anderson, South Carolina 29621"
                        .to_string(),
                ),
                excerpt: "Wind Humidity Air Quality Dew Point Pressure UV Index Visibility Moon Phase Sunrise Sunset 0:52 1:17 0:52 1:17 1:06 0:57 1:14 0:43 1:06 0:57".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.bing.com/search?q=current+weather+anderson+sc".to_string(),
                title: Some(
                    "Update from https://www.bing.com/search?q=current+weather+anderson+sc"
                        .to_string(),
                ),
                excerpt: "Search results for current weather Anderson SC.".to_string(),
            },
        ],
        min_sources: 2,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::DeadlineReached);
    assert!(
        reply
            .to_ascii_lowercase()
            .contains("current-condition metrics were not exposed"),
        "expected limitation summary in this path:\n{}",
        reply
    );
    assert!(
        reply.contains("Next step: Open"),
        "limitation summaries must include an explicit follow-up next step:\n{}",
        reply
    );
    assert!(
        reply.contains("weather.com/weather/today/l/Anderson%20SC"),
        "expected non-hub local source to remain primary evidence:\n{}",
        reply
    );
}

#[test]
fn web_pipeline_single_snapshot_treats_non_measurement_current_labels_as_limitation() {
    let pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=current+weather+anderson+sc".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://www.myforecast.com/index.php?cwid=KAND&language=en-US&metric=false"
                .to_string(),
            "https://www.weather-atlas.com/en/south-carolina-usa/anderson".to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://www.myforecast.com/index.php?cwid=KAND&language=en-US&metric=false"
                    .to_string(),
                title: Some(
                    "Anderson, South Carolina | Current Conditions | NWS Alerts | Maps".to_string(),
                ),
                excerpt: "Daily Forecast Rise: 7:33AM | Set: 5:53PM 10hrs 20mins. More forecasts and maps."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.weather-atlas.com/en/south-carolina-usa/anderson".to_string(),
                title: Some("Weather today - Anderson, SC".to_string()),
                excerpt:
                    "Current temperature and weather conditions. Detailed hourly weather forecast."
                        .to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://www.myforecast.com/index.php?cwid=KAND&language=en-US&metric=false"
                .to_string(),
            title: Some(
                "Anderson, South Carolina | Current Conditions | NWS Alerts | Maps".to_string(),
            ),
            excerpt: "Daily Forecast Rise: 7:33AM | Set: 5:53PM 10hrs 20mins. More forecasts and maps."
                .to_string(),
        }],
        min_sources: 2,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::ExhaustedCandidates);
    let lower = reply.to_ascii_lowercase();
    assert!(lower.contains("estimated-right-now:"));
    assert!(lower.contains("derived from cited forecast range"));
    assert!(lower.contains("data caveat:"));
    assert!(lower.contains("next step: open"));
}

#[test]
fn web_pipeline_single_snapshot_envelope_caveat_overrides_irrelevant_current_conditions_text() {
    let pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        retrieval_contract: None,
        url: "https://www.bing.com/search?q=current+weather+anderson+sc".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://forums.att.com/conversations/account-usage/compesation/5df024adbad5f2f60686b40b".to_string(),
            "https://forums.att.com/conversations/apple/why-do-you-send-electronic-notifications-when-specifically-asked-not-to/5df00f54bad5f2f606253c6e".to_string(),
        ],
        candidate_source_hints: vec![],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://forums.att.com/conversations/account-usage/compesation/5df024adbad5f2f60686b40b".to_string(),
                title: Some("AT&T Digital Resources & Answers - Community Forums has Sunset".to_string()),
                excerpt: "Apr 6, 2019 · I called customer service last night i paid my bill and my phone was working for a few hours and due to a glitch in systems my phone was shut off.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://forums.att.com/conversations/apple/why-do-you-send-electronic-notifications-when-specifically-asked-not-to/5df00f54bad5f2f606253c6e".to_string(),
                title: Some("AT&T Digital Resources & Answers - Community Forums has Sunset".to_string()),
                excerpt: "Dec 16, 2018 · Bought iPhone watch for spouse as Christmas present. Asked there be no electronic notification.".to_string(),
            },
        ],
        min_sources: 2,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    let lower = reply.to_ascii_lowercase();
    assert!(lower.contains("estimated-right-now:"));
    assert!(lower.contains("derived from cited forecast range"));
    assert!(lower.contains("data caveat:"));
    assert!(lower.contains("next step: open"));
}
