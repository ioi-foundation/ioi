use super::*;

#[test]
fn web_pipeline_next_candidate_prefers_distinct_host_for_single_snapshot_queries() {
    let pending = PendingSearchCompletion {
        query: "What's the weather right now?".to_string(),
        query_contract: "What's the weather right now?".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=weather+right+now".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://weather.com/weather/today/l/Anderson%20SC".to_string(),
            "https://weather.com/weather/tenday/l/Anderson%20SC".to_string(),
            "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327".to_string(),
        ],
        candidate_source_hints: vec![],
        attempted_urls: vec!["https://weather.com/weather/today/l/Anderson%20SC".to_string()],
        blocked_urls: vec![],
        successful_reads: vec![crate::agentic::runtime::types::PendingSearchReadSummary {
            url: "https://weather.com/weather/today/l/Anderson%20SC".to_string(),
            title: Some("Anderson weather".to_string()),
            excerpt: "Today's and tonight's weather forecast.".to_string(),
        }],
        min_sources: 2,
    };

    let next = next_pending_web_candidate(&pending).expect("expected next candidate");
    assert_eq!(
        next,
        "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327"
    );
}

fn web_pipeline_next_candidate_prefers_new_domain_for_multi_story_queries() {
    let pending = PendingSearchCompletion {
        query: "Tell me today's top news headlines.".to_string(),
        query_contract: "Tell me today's top news headlines.".to_string(),
        retrieval_contract: None,
        url: "https://news.google.com/rss/search?q=top+headlines".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://www.foxnews.com/us/top-headlines".to_string(),
            "https://www.foxnews.com/politics".to_string(),
            "https://www.reuters.com/world/".to_string(),
        ],
        candidate_source_hints: vec![],
        attempted_urls: vec!["https://www.foxnews.com/us/top-headlines".to_string()],
        blocked_urls: vec![],
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://www.foxnews.com/us/top-headlines".to_string(),
            title: Some("Fox News top headlines".to_string()),
            excerpt: "Breaking U.S. and world coverage.".to_string(),
        }],
        min_sources: 3,
    };

    let next = next_pending_web_candidate(&pending).expect("expected new-domain candidate");
    assert_eq!(next, "https://www.reuters.com/world/");
}

#[test]
fn web_pipeline_next_candidate_returns_none_when_multi_story_only_has_repeat_domain_candidates() {
    let pending = PendingSearchCompletion {
        query: "Tell me today's top news headlines.".to_string(),
        query_contract: "Tell me today's top news headlines.".to_string(),
        retrieval_contract: None,
        url: "https://news.google.com/rss/search?q=top+headlines".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://www.foxnews.com/politics".to_string(),
            "https://www.foxnews.com/world".to_string(),
        ],
        candidate_source_hints: vec![],
        attempted_urls: vec!["https://www.foxnews.com/us/top-headlines".to_string()],
        blocked_urls: vec![],
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://www.foxnews.com/us/top-headlines".to_string(),
            title: Some("Fox News top headlines".to_string()),
            excerpt: "Breaking U.S. and world coverage.".to_string(),
        }],
        min_sources: 3,
    };

    assert!(next_pending_web_candidate(&pending).is_none());
}

#[test]
fn web_pipeline_next_candidate_prefers_immediate_metric_source_for_single_snapshot_queries() {
    let pending = PendingSearchCompletion {
        query: "What's the weather right now?".to_string(),
        query_contract: "What's the weather right now?".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=weather+right+now".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://weather.com/weather/tenday/l/Anderson%20SC".to_string(),
            "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327".to_string(),
        ],
        candidate_source_hints: vec![
            crate::agentic::runtime::types::PendingSearchReadSummary {
                url: "https://weather.com/weather/tenday/l/Anderson%20SC".to_string(),
                title: Some("Anderson, SC 10-Day Weather Forecast".to_string()),
                excerpt: "Be prepared with the most accurate 10-day forecast for Anderson.".to_string(),
            },
            crate::agentic::runtime::types::PendingSearchReadSummary {
                url: "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327"
                    .to_string(),
                title: Some("Anderson, SC Current Weather".to_string()),
                excerpt: "Current conditions: temperature near 61 F with calm wind and humidity around 48 percent."
                    .to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };

    let next = next_pending_web_candidate(&pending).expect("expected next candidate");
    assert_eq!(
        next,
        "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327"
    );
}

#[test]
fn web_pipeline_next_candidate_prefers_named_role_holder_source_over_generic_role_definition() {
    let pending = PendingSearchCompletion {
        query: "Who is the current Secretary-General of the UN?".to_string(),
        query_contract: "Who is the current Secretary-General of the UN?".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=current+Secretary-General+of+the+UN".to_string(),
        started_step: 1,
        started_at_ms: 1_776_200_894_000,
        deadline_ms: 1_776_200_954_000,
        candidate_urls: vec![
            "https://en.wikipedia.org/wiki/Secretary-General_of_the_United_Nations".to_string(),
            "https://ask.un.org/faq/14625".to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://en.wikipedia.org/wiki/Secretary-General_of_the_United_Nations"
                    .to_string(),
                title: Some("Secretary-General of the United Nations - Wikipedia".to_string()),
                excerpt: "The secretary-general of the United Nations is the Head of the United Nations Secretariat."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://ask.un.org/faq/14625".to_string(),
                title: Some(
                    "Who is and has been Secretary-General of the United Nations? - Ask DAG!"
                        .to_string(),
                ),
                excerpt: "António Guterres is the current Secretary-General of the United Nations."
                    .to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 1,
    };

    let next = next_pending_web_candidate(&pending).expect("expected next candidate");
    assert_eq!(next, "https://ask.un.org/faq/14625");
}

#[test]
fn web_pipeline_next_candidate_prefers_current_observation_surface_without_numeric_over_forecast() {
    let pending = PendingSearchCompletion {
        query: "What's the weather right now?".to_string(),
        query_contract: "What's the weather right now?".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=weather+right+now".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://www.weather-forecast.com/locations/Anderson/forecasts/latest".to_string(),
            "https://www.theweathernetwork.com/en/city/us/south-carolina/anderson/hourly"
                .to_string(),
        ],
        candidate_source_hints: vec![
            crate::agentic::runtime::types::PendingSearchReadSummary {
                url: "https://www.weather-forecast.com/locations/Anderson/forecasts/latest"
                    .to_string(),
                title: Some("Anderson, South Carolina Weather Forecast".to_string()),
                excerpt: "Providing a local hourly Anderson weather forecast of rain, sun, wind, humidity and temperature. The long-range 12 day forecast also includes detail."
                    .to_string(),
            },
            crate::agentic::runtime::types::PendingSearchReadSummary {
                url: "https://www.theweathernetwork.com/en/city/us/south-carolina/anderson/hourly"
                    .to_string(),
                title: Some("Anderson, SC Hourly Forecast - The Weather Network".to_string()),
                excerpt: "Get Anderson current weather report with temperature, feels like, wind, humidity and pressure."
                    .to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };

    let next = next_pending_web_candidate(&pending).expect("expected next candidate");
    assert_eq!(
        next,
        "https://www.theweathernetwork.com/en/city/us/south-carolina/anderson/hourly"
    );
}

#[test]
fn web_pipeline_next_candidate_prefers_compatible_source_over_irrelevant_candidate() {
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
            "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327".to_string(),
        ],
        candidate_source_hints: vec![
            crate::agentic::runtime::types::PendingSearchReadSummary {
                url: "https://forums.att.com/conversations/account-usage/compesation/5df024adbad5f2f60686b40b".to_string(),
                title: Some("AT&T Digital Resources & Answers - Community Forums".to_string()),
                excerpt: "Apr 6, 2019 · I called customer service last night and paid my bill."
                    .to_string(),
            },
            crate::agentic::runtime::types::PendingSearchReadSummary {
                url: "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327".to_string(),
                title: Some("Anderson, SC Current Weather".to_string()),
                excerpt: "Current conditions: temperature near 61 F, wind 4 mph, humidity 48%."
                    .to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };

    let next = next_pending_web_candidate(&pending).expect("expected next candidate");
    assert_eq!(
        next,
        "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327"
    );
}

#[test]
fn web_pipeline_next_candidate_allows_single_exploratory_read_when_compatibility_unknown() {
    let pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        retrieval_contract: None,
        url: "https://www.bing.com/search?q=current+weather+anderson+sc".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://example.com/path/a".to_string(),
            "https://example.org/path/b".to_string(),
        ],
        candidate_source_hints: vec![],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };

    let first = next_pending_web_candidate(&pending).expect("expected exploratory candidate");
    assert_eq!(first, "https://example.com/path/a");

    let mut exhausted = pending.clone();
    exhausted.attempted_urls = vec![first];
    let second = next_pending_web_candidate(&exhausted).expect("expected second exploratory read");
    assert_eq!(second, "https://example.org/path/b");

    exhausted.attempted_urls.push(second);
    let third = next_pending_web_candidate(&exhausted);
    assert!(
        third.is_none(),
        "expected probe escalation after exploratory read budget is consumed"
    );
}

#[test]
fn web_pipeline_next_candidate_does_not_reread_successful_single_snapshot_source() {
    let pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        retrieval_contract: None,
        url: "https://www.bing.com/search?q=current+weather+anderson+sc".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec!["https://www.timeanddate.com/weather/usa/anderson".to_string()],
        candidate_source_hints: vec![],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://www.timeanddate.com/weather/usa/anderson".to_string(),
            title: Some("Weather for Anderson, South Carolina, USA".to_string()),
            excerpt: "Current weather: 64°F, fair, wind 4 mph.".to_string(),
        }],
        min_sources: 2,
    };

    assert!(
        next_pending_web_candidate(&pending).is_none(),
        "already-grounded URLs must not be reread as pending candidates"
    );
}

#[test]
fn web_pipeline_next_candidate_keeps_exploration_budget_for_nonqualifying_reads_only() {
    let pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        retrieval_contract: None,
        url: "https://www.bing.com/search?q=current+weather+anderson+sc".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://example.com/path/a".to_string(),
            "https://example.org/path/b".to_string(),
        ],
        candidate_source_hints: vec![],
        attempted_urls: vec![
            "https://www.accuweather.com/en/us/anderson/29624/weather-forecast/330677".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://www.timeanddate.com/weather/usa/anderson".to_string(),
            title: Some("Weather for Anderson, South Carolina, USA".to_string()),
            excerpt: "Current weather: 64°F, fair, wind 4 mph.".to_string(),
        }],
        min_sources: 2,
    };

    let next = next_pending_web_candidate(&pending).expect("expected bounded exploratory read");
    assert_eq!(next, "https://example.com/path/a");
}

#[test]
fn web_pipeline_next_candidate_allows_one_extra_exploratory_read_after_probe_search_attempt() {
    let mut base = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=anderson+sc+weather+right+now".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec!["https://example.net/current-observations".to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://example.net/current-observations".to_string(),
            title: Some("Example forecast page".to_string()),
            excerpt: "General weather outlook content.".to_string(),
        }],
        attempted_urls: vec![
            "https://weather-forecast.com/locations/Anderson/forecasts/latest".to_string(),
            "https://www.accuweather.com/en/us/anderson/29624/weather-forecast/330677".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://weather-forecast.com/locations/Anderson/forecasts/latest".to_string(),
                title: Some("Anderson, South Carolina Weather Forecast".to_string()),
                excerpt: "Local hourly weather forecast.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.accuweather.com/en/us/anderson/29624/weather-forecast/330677"
                    .to_string(),
                title: Some("Anderson, SC Weather Forecast".to_string()),
                excerpt: "Current conditions and next 3 days.".to_string(),
            },
        ],
        min_sources: 2,
    };

    let without_probe = next_pending_web_candidate(&base);
    assert!(
        without_probe.is_none(),
        "without a probe search attempt, exploratory cap should be consumed after two weak reads"
    );

    base.attempted_urls
        .push("https://www.bing.com/search?q=anderson+sc+weather+current+conditions".to_string());
    let with_probe = next_pending_web_candidate(&base);
    assert_eq!(
        with_probe.as_deref(),
        Some("https://example.net/current-observations"),
        "one additional probe search attempt should unlock one extra exploratory read"
    );
}

#[test]
fn web_pipeline_next_candidate_allows_exploratory_read_under_strict_grounding_when_inventory_is_incompatible(
) {
    let pending = PendingSearchCompletion {
        query: "Current weather in Anderson, SC right now with sources and UTC timestamp."
            .to_string(),
        query_contract: "Current weather in Anderson, SC right now with sources and UTC timestamp."
            .to_string(),
        retrieval_contract: None,
        url: "https://www.google.com/search?q=weather+in+anderson+sc".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://forums.x-plane.org/forums/topic/337131-weather-radar-not-working-for-me/"
                .to_string(),
        ],
        candidate_source_hints: vec![crate::agentic::runtime::types::PendingSearchReadSummary {
            url: "https://forums.x-plane.org/forums/topic/337131-weather-radar-not-working-for-me/"
                .to_string(),
            title: Some("Weather radar not working for me. - X-Plane.Org Forum".to_string()),
            excerpt: "Support thread about simulator weather radar behavior.".to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };

    let next = next_pending_web_candidate(&pending);
    assert!(
        next.is_some(),
        "strict grounding should still allow bounded exploratory read when no compatible candidates exist"
    );
}

#[test]
fn web_pipeline_next_candidate_ignores_search_hub_attempts_for_host_diversity() {
    let pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        retrieval_contract: None,
        url: "https://news.google.com/rss/search?q=weather+anderson+sc".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://news.google.com/rss/articles/CBMihAFBVV95cUxOdFBPLTgyNWhXOHVqUXNBbnNrVngxSmZDc0lSS0hVdGpFYzRaRTEwTEZudHBacHB2TkxrdnU4YlVNSFNRTkhsVTlSXzJTOUhkOEsyZFpBVThaSGZ2U0MxNmhtYk9DVTMwbWl1dUdZcllTQVFPLW91RXZxT1BVRF9IaEd6WnY?oc=5".to_string(),
            "https://news.google.com/rss/articles/CBMimAFBVV95cUxNcVZDZVYtQXVXRFlLQmdCVnVuVlZjMlNZcTNGWm9WN0ZPb0pvMUpBMllJVFo0V3IxZ21RNUtQZTVkc3Joc0c2U2V6ZlA0OHEwdTlHNm8zanp5QmlUUERSVzBQTXJUMXlEVXctZkhUT085SVBvWmVjRWZPNFE4NFZ3LUpOemMyekVMVlRXejl6cHdjYUM2R3cxcw?oc=5".to_string(),
        ],
        candidate_source_hints: vec![
            crate::agentic::runtime::types::PendingSearchReadSummary {
                url: "https://news.google.com/rss/articles/CBMihAFBVV95cUxOdFBPLTgyNWhXOHVqUXNBbnNrVngxSmZDc0lSS0hVdGpFYzRaRTEwTEZudHBacHB2TkxrdnU4YlVNSFNRTkhsVTlSXzJTOUhkOEsyZFpBVThaSGZ2U0MxNmhtYk9DVTMwbWl1dUdZcllTQVFPLW91RXZxT1BVRF9IaEd6WnY?oc=5".to_string(),
                title: Some("Serious Car Accident Risks in Anderson, SC - The Weekly Driver".to_string()),
                excerpt: "The Weekly Driver".to_string(),
            },
            crate::agentic::runtime::types::PendingSearchReadSummary {
                url: "https://news.google.com/rss/articles/CBMimAFBVV95cUxNcVZDZVYtQXVXRFlLQmdCVnVuVlZjMlNZcTNGWm9WN0ZPb0pvMUpBMllJVFo0V3IxZ21RNUtQZTVkc3Joc0c2U2V6ZlA0OHEwdTlHNm8zanp5QmlUUERSVzBQTXJUMXlEVXctZkhUT085SVBvWmVjRWZPNFE4NFZ3LUpOemMyekVMVlRXejl6cHdjYUM2R3cxcw?oc=5".to_string(),
                title: Some("Weather pattern clues for April - AccuWeather".to_string()),
                excerpt: "AccuWeather".to_string(),
            },
        ],
        attempted_urls: vec![
            "https://news.google.com/rss/search?q=What%27s+the+weather+right+now+in+Anderson%2C+SC%3F+%22anderson+weather%22&hl=en-US&gl=US&ceid=US%3Aen".to_string(),
            "https://www.bing.com/search?q=What%27s+the+weather+right+now+in+Anderson%2C+SC%3F+%22anderson+weather%22+-articles+-com+-google".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };

    let next = next_pending_web_candidate(&pending).expect("expected exploratory candidate read");
    assert!(
        next.contains("/rss/articles/"),
        "expected a readable article candidate, got {next}"
    );
}

#[test]
fn web_pipeline_next_candidate_prefers_official_grounded_source_for_latest_multi_story_briefing() {
    let pending = PendingSearchCompletion {
        query: "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.".to_string(),
        query_contract:
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                .to_string(),
        retrieval_contract: Some(ioi_types::app::agentic::WebRetrievalContract {
            contract_version: "web_retrieval_contract.v1".to_string(),
            entity_cardinality_min: 3,
            comparison_required: true,
            currentness_required: true,
            runtime_locality_required: false,
            source_independence_min: 3,
            citation_count_min: 1,
            structured_record_preferred: false,
            ordered_collection_preferred: false,
            link_collection_preferred: true,
            canonical_link_out_preferred: true,
            geo_scoped_detail_required: false,
            discovery_surface_required: true,
            entity_diversity_required: true,
            scalar_measure_required: false,
            browser_fallback_allowed: true,
        }),
        url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://www.ibm.com/think/topics/nist".to_string(),
            "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://www.ibm.com/think/topics/nist".to_string(),
                title: Some("What is NIST? | IBM".to_string()),
                excerpt: "Overview of NIST frameworks and cybersecurity topics.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
                title: Some(
                    "NIST selects HQC as fifth algorithm for post-quantum encryption"
                        .to_string(),
                ),
                excerpt:
                    "NIST selected HQC as a backup algorithm in the post-quantum cryptography standards effort."
                        .to_string(),
            },
        ],
        attempted_urls: vec![
            "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                title: Some(
                    "NIST releases first 3 finalized post-quantum encryption standards"
                        .to_string(),
                ),
                excerpt:
                    "NIST finalized FIPS 203, FIPS 204 and FIPS 205 for post-quantum cryptography."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                title: Some("NIST’s post-quantum cryptography standards are here".to_string()),
                excerpt:
                    "IBM summarized the NIST post-quantum standards ML-KEM, ML-DSA and SLH-DSA."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://pqshield.com/nist-recommends-timelines-for-transitioning-cryptographic-algorithms/".to_string(),
                title: Some(
                    "NIST recommends timelines for transitioning cryptographic algorithms"
                        .to_string(),
                ),
                excerpt:
                    "PQShield covered NIST transition guidance for post-quantum cryptography standards."
                        .to_string(),
            },
        ],
        min_sources: 3,
    };

    let next = next_pending_web_candidate(&pending).expect("expected grounded next candidate");
    assert_eq!(
        next,
        "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption"
    );
}

#[test]
fn web_pipeline_next_candidate_returns_none_when_grounded_briefing_only_has_generic_residual_reads()
{
    let pending = PendingSearchCompletion {
        query: "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.".to_string(),
        query_contract:
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                .to_string(),
        retrieval_contract: Some(ioi_types::app::agentic::WebRetrievalContract {
            contract_version: "web_retrieval_contract.v1".to_string(),
            entity_cardinality_min: 3,
            comparison_required: true,
            currentness_required: true,
            runtime_locality_required: false,
            source_independence_min: 3,
            citation_count_min: 1,
            structured_record_preferred: false,
            ordered_collection_preferred: false,
            link_collection_preferred: true,
            canonical_link_out_preferred: true,
            geo_scoped_detail_required: false,
            discovery_surface_required: true,
            entity_diversity_required: true,
            scalar_measure_required: false,
            browser_fallback_allowed: true,
        }),
        url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2".to_string(),
            "https://www.ibm.com/de-de/think/topics/nist".to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2".to_string(),
                title: Some("El marco de ciberseguridad 2.0 del NIST, en detalle | IBM".to_string()),
                excerpt: "General NIST cybersecurity framework overview.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.ibm.com/de-de/think/topics/nist".to_string(),
                title: Some("Was ist das NIST Cybersicherheits-Framework? | IBM".to_string()),
                excerpt: "Generic overview of NIST cybersecurity topics.".to_string(),
            },
        ],
        attempted_urls: vec![
            "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                title: Some(
                    "NIST releases first 3 finalized post-quantum encryption standards"
                        .to_string(),
                ),
                excerpt:
                    "NIST finalized FIPS 203, FIPS 204 and FIPS 205 for post-quantum cryptography."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                title: Some("NIST’s post-quantum cryptography standards are here".to_string()),
                excerpt:
                    "IBM summarized the NIST post-quantum standards ML-KEM, ML-DSA and SLH-DSA."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://pqshield.com/nist-recommends-timelines-for-transitioning-cryptographic-algorithms/".to_string(),
                title: Some(
                    "NIST recommends timelines for transitioning cryptographic algorithms"
                        .to_string(),
                ),
                excerpt:
                    "PQShield covered NIST transition guidance for post-quantum cryptography standards."
                        .to_string(),
            },
        ],
        min_sources: 3,
    };

    assert!(
        next_pending_web_candidate(&pending).is_none(),
        "generic residual NIST-adjacent pages should not keep grounded briefing loops alive"
    );
}
