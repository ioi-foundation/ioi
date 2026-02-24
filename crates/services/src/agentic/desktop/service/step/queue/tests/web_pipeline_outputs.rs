use super::*;

#[test]
fn web_pipeline_latency_budget_escalates_after_slow_attempts() {
    let pending = PendingSearchCompletion {
        query: "what's the weather right now in anderson sc".to_string(),
        query_contract: "what's the weather right now in anderson sc".to_string(),
        url: "https://duckduckgo.com/?q=weather".to_string(),
        started_step: 3,
        started_at_ms: 1_000,
        deadline_ms: 51_000,
        candidate_urls: vec![
            "https://weather.com/weather/today/l/Anderson+SC".to_string(),
            "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC".to_string(),
        ],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://weather.com/weather/today/l/Anderson+SC".to_string(),
            title: Some("Current weather Anderson South Carolina".to_string()),
            excerpt: "Current conditions now with temperature and humidity.".to_string(),
        }],
        attempted_urls: vec!["https://weather.com/weather/today/l/Anderson+SC".to_string()],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };

    let now_ms = 49_000;
    let required_read_ms = web_pipeline_required_read_budget_ms(&pending, now_ms);
    let required_probe_ms = web_pipeline_required_probe_budget_ms(&pending, now_ms);

    assert!(required_read_ms > 20_000);
    assert!(required_probe_ms >= required_read_ms);
    assert!(!web_pipeline_can_queue_initial_read_latency_aware(
        &pending, now_ms
    ));
    assert!(!web_pipeline_can_queue_probe_search_latency_aware(
        &pending, now_ms
    ));
    assert_eq!(
        web_pipeline_latency_pressure_label(&pending, now_ms),
        "critical"
    );
}

#[test]
fn web_pipeline_suppresses_non_actionable_excerpt_noise_in_story_sections() {
    let pending = PendingSearchCompletion {
        query: "top active cloud incidents".to_string(),
        query_contract: "top active cloud incidents".to_string(),
        url: "https://duckduckgo.com/?q=top+active+cloud+incidents".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://status.cloud.google.com/incidents/U39RSGjaANJXtjHpRkdq".to_string(),
            "https://azure.status.microsoft/en-us/status".to_string(),
            "https://health.aws.amazon.com/health/status".to_string(),
            "https://status.cloud.microsoft/en-us/status".to_string(),
            "https://status.salesforce.com/".to_string(),
            "https://status.datadoghq.com/".to_string(),
        ],
        candidate_source_hints: vec![
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.cloud.google.com/incidents/U39RSGjaANJXtjHpRkdq".to_string(),
                title: Some("Google Cloud Service Health".to_string()),
                excerpt: "Multiple cloud products are experiencing networking issues in us-central1."
                    .to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://azure.status.microsoft/en-us/status".to_string(),
                title: Some("Azure Status Overview - Azure Service Health | Microsoft Learn".to_string()),
                excerpt: "Note Access to this page requires authorization. You can try signing in or changing directories. Use Personalized Service Health for a more detailed overview."
                    .to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://health.aws.amazon.com/health/status".to_string(),
                title: Some("AWS Health Dashboard".to_string()),
                excerpt: "Service health updates indicate elevated API error rates.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.cloud.microsoft/en-us/status".to_string(),
                title: Some("Microsoft service health status".to_string()),
                excerpt: "Investigating intermittent authentication failures.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.salesforce.com/".to_string(),
                title: Some("Salesforce Trust".to_string()),
                excerpt: "Monitoring mitigation rollout for affected tenants.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.datadoghq.com/".to_string(),
                title: Some("Datadog Status".to_string()),
                excerpt: "Partial outage under investigation.".to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    let reply_lc = reply.to_ascii_lowercase();
    assert!(!reply_lc.contains("requires authorization"));
    assert!(!reply_lc.contains("you can try signing in"));
    assert!(!reply_lc.contains("use personalized service health"));
}

#[test]
fn web_pipeline_completion_deadline_produces_partial_low_confidence() {
    let pending = PendingSearchCompletion {
        query: "latest news".to_string(),
        query_contract: "latest news".to_string(),
        url: "https://duckduckgo.com/?q=latest+news".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 160,
        candidate_urls: vec!["https://a.example.com".to_string()],
        candidate_source_hints: vec![],
        attempted_urls: vec!["https://a.example.com".to_string()],
        blocked_urls: vec!["https://blocked.example.com".to_string()],
        successful_reads: vec![],
        min_sources: 2,
    };

    let reason = web_pipeline_completion_reason(&pending, 200)
        .expect("deadline should produce completion reason");
    assert_eq!(reason, WebPipelineCompletionReason::DeadlineReached);

    let reply = synthesize_web_pipeline_reply(&pending, reason);
    assert!(reply.contains("Partial evidence"));
    assert!(reply.contains("Blocked sources requiring human challenge"));
    assert!(reply.contains("Run date (UTC): "));
    assert!(reply.contains("Run timestamp (UTC): "));
    assert!(reply.contains("Overall confidence: low"));
}

#[test]
fn web_pipeline_reply_enforces_three_story_structure_with_citations_and_timestamps() {
    let pending = PendingSearchCompletion {
        query: "As of now (UTC), top 3 active U.S.-impacting cloud/SaaS incidents (major status pages), what changed in last hour, user impact, workaround, ETA confidence, 2 citations each."
            .to_string(),
        query_contract: "As of now (UTC), top 3 active U.S.-impacting cloud/SaaS incidents (major status pages), what changed in last hour, user impact, workaround, ETA confidence, 2 citations each."
            .to_string(),
        url: "https://duckduckgo.com/?q=cloud+saas+status+incidents".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://status.example.com/incidents/a".to_string(),
            "https://status.example.com/incidents/b".to_string(),
            "https://status.example.com/incidents/c".to_string(),
            "https://status.example.com/incidents/d".to_string(),
            "https://status.example.com/incidents/e".to_string(),
            "https://status.example.com/incidents/f".to_string(),
        ],
        candidate_source_hints: vec![
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.example.com/incidents/a".to_string(),
                title: Some("Major provider outage impacts API authentication".to_string()),
                excerpt: "Investigating elevated auth errors for U.S. users; mitigation in progress."
                    .to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.example.com/incidents/b".to_string(),
                title: Some("Dashboard degradation in North America region".to_string()),
                excerpt: "Users may see slow dashboard loads; workaround includes retrying in alternate region.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.example.com/incidents/c".to_string(),
                title: Some("Storage control plane incident under active monitoring".to_string()),
                excerpt: "Provider identified root cause and expects next update within 30 minutes."
                    .to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.example.com/incidents/d".to_string(),
                title: Some("Service health: intermittent request timeout".to_string()),
                excerpt: "Mitigation rolled out to reduce elevated latency for U.S. tenants.".to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    assert!(reply.contains("Story 1:"));
    assert!(reply.contains("Story 2:"));
    assert!(reply.contains("Story 3:"));
    assert_eq!(reply.matches("What happened:").count(), 3);
    assert_eq!(reply.matches("What changed in the last hour:").count(), 3);
    assert_eq!(reply.matches("User impact:").count(), 3);
    assert_eq!(reply.matches("Workaround:").count(), 3);
    assert_eq!(reply.matches("ETA confidence:").count(), 3);
    assert_eq!(reply.matches("Citations:").count(), 3);
    assert!(reply.contains("T") && reply.contains("Z"));
    let urls = extract_urls(&reply);
    assert!(
        urls.len() >= 6,
        "expected >= 6 distinct urls, got {}",
        urls.len()
    );
}

#[test]
fn web_pipeline_renders_single_snapshot_for_time_sensitive_public_fact_queries() {
    let pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        url: "https://duckduckgo.com/?q=anderson+sc+weather+right+now".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://forecast.weather.gov/MapClick.php?textField1=34.50&textField2=-82.65"
                .to_string(),
            "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327".to_string(),
        ],
        candidate_source_hints: vec![
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://forecast.weather.gov/MapClick.php?textField1=34.50&textField2=-82.65"
                    .to_string(),
                title: Some("Anderson SC Forecast Office Update".to_string()),
                excerpt: "Current conditions: cloudy skies, temperature near 61 F, calm wind, humidity near 48 percent."
                    .to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327".to_string(),
                title: Some("Anderson, SC Current Weather".to_string()),
                excerpt: "Feels like low 60s with overcast conditions and light wind.".to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 1,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    assert!(reply.contains("Right now"));
    assert!(reply.contains("Citations:"));
    assert!(reply.contains("Run timestamp (UTC):"));
    assert!(!reply.contains("Story 2:"));
    assert!(!reply.contains("Story 3:"));
}

#[test]
fn web_pipeline_next_candidate_prefers_distinct_host_for_single_snapshot_queries() {
    let pending = PendingSearchCompletion {
        query: "What's the weather right now?".to_string(),
        query_contract: "What's the weather right now?".to_string(),
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
        successful_reads: vec![crate::agentic::desktop::types::PendingSearchReadSummary {
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

#[test]
fn web_pipeline_next_candidate_prefers_immediate_metric_source_for_single_snapshot_queries() {
    let pending = PendingSearchCompletion {
        query: "What's the weather right now?".to_string(),
        query_contract: "What's the weather right now?".to_string(),
        url: "https://duckduckgo.com/?q=weather+right+now".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://weather.com/weather/tenday/l/Anderson%20SC".to_string(),
            "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327".to_string(),
        ],
        candidate_source_hints: vec![
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://weather.com/weather/tenday/l/Anderson%20SC".to_string(),
                title: Some("Anderson, SC 10-Day Weather Forecast".to_string()),
                excerpt: "Be prepared with the most accurate 10-day forecast for Anderson.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
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
fn web_pipeline_next_candidate_prefers_current_observation_surface_without_numeric_over_forecast() {
    let pending = PendingSearchCompletion {
        query: "What's the weather right now?".to_string(),
        query_contract: "What's the weather right now?".to_string(),
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
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://www.weather-forecast.com/locations/Anderson/forecasts/latest"
                    .to_string(),
                title: Some("Anderson, South Carolina Weather Forecast".to_string()),
                excerpt: "Providing a local hourly Anderson weather forecast of rain, sun, wind, humidity and temperature. The long-range 12 day forecast also includes detail."
                    .to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
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
        url: "https://www.bing.com/search?q=current+weather+anderson+sc".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://forums.att.com/conversations/account-usage/compesation/5df024adbad5f2f60686b40b".to_string(),
            "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327".to_string(),
        ],
        candidate_source_hints: vec![
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://forums.att.com/conversations/account-usage/compesation/5df024adbad5f2f60686b40b".to_string(),
                title: Some("AT&T Digital Resources & Answers - Community Forums".to_string()),
                excerpt: "Apr 6, 2019 · I called customer service last night and paid my bill."
                    .to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
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
fn web_pipeline_next_candidate_allows_one_extra_exploratory_read_after_probe_search_attempt() {
    let mut base = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
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
        url: "https://www.google.com/search?q=weather+in+anderson+sc".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://forums.x-plane.org/forums/topic/337131-weather-radar-not-working-for-me/"
                .to_string(),
        ],
        candidate_source_hints: vec![crate::agentic::desktop::types::PendingSearchReadSummary {
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
        url: "https://news.google.com/rss/search?q=weather+anderson+sc".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://news.google.com/rss/articles/CBMihAFBVV95cUxOdFBPLTgyNWhXOHVqUXNBbnNrVngxSmZDc0lSS0hVdGpFYzRaRTEwTEZudHBacHB2TkxrdnU4YlVNSFNRTkhsVTlSXzJTOUhkOEsyZFpBVThaSGZ2U0MxNmhtYk9DVTMwbWl1dUdZcllTQVFPLW91RXZxT1BVRF9IaEd6WnY?oc=5".to_string(),
            "https://news.google.com/rss/articles/CBMimAFBVV95cUxNcVZDZVYtQXVXRFlLQmdCVnVuVlZjMlNZcTNGWm9WN0ZPb0pvMUpBMllJVFo0V3IxZ21RNUtQZTVkc3Joc0c2U2V6ZlA0OHEwdTlHNm8zanp5QmlUUERSVzBQTXJUMXlEVXctZkhUT085SVBvWmVjRWZPNFE4NFZ3LUpOemMyekVMVlRXejl6cHdjYUM2R3cxcw?oc=5".to_string(),
        ],
        candidate_source_hints: vec![
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://news.google.com/rss/articles/CBMihAFBVV95cUxOdFBPLTgyNWhXOHVqUXNBbnNrVngxSmZDc0lSS0hVdGpFYzRaRTEwTEZudHBacHB2TkxrdnU4YlVNSFNRTkhsVTlSXzJTOUhkOEsyZFpBVThaSGZ2U0MxNmhtYk9DVTMwbWl1dUdZcllTQVFPLW91RXZxT1BVRF9IaEd6WnY?oc=5".to_string(),
                title: Some("Serious Car Accident Risks in Anderson, SC - The Weekly Driver".to_string()),
                excerpt: "The Weekly Driver".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
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
fn web_pipeline_single_snapshot_renders_actionable_metric_limitation_when_metrics_absent() {
    let pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
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
fn web_pipeline_single_snapshot_avoids_pseudo_metric_summary_from_forecast_only_text() {
    let pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
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
fn web_pipeline_single_snapshot_emits_next_step_when_limitation_summary_present() {
    let pending = PendingSearchCompletion {
        query: "what's the weather right now".to_string(),
        query_contract: "what's the weather right now".to_string(),
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
fn web_pipeline_single_snapshot_emits_next_step_when_rendered_summary_implies_limitation() {
    let pending = PendingSearchCompletion {
        query: "Current weather in Anderson, SC right now with sources and UTC timestamp."
            .to_string(),
        query_contract: "Current weather in Anderson, SC right now with sources and UTC timestamp."
            .to_string(),
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

#[test]
fn web_pipeline_single_snapshot_citation_fallback_prefers_evidence_urls_over_query_hubs_when_available(
) {
    let search_url =
        "https://news.google.com/rss/search?q=What%27s+the+weather+right+now+in+Anderson%2C+SC&hl=en-US&gl=US&ceid=US%3Aen";
    let pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        url: search_url.to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_414_000,
        candidate_urls: vec![
            "https://news.google.com/rss/articles/CBMihAFBVV95cUxOdFBPLTgyNWhXOHVqUXNBbnNrVngxSmZDc0lSS0hVdGpFYzRaRTEwTEZudHBacHB2TkxrdnU4YlVNSFNRTkhsVTlSXzJTOUhkOEsyZFpBVThaSGZ2U0MxNmhtYk9DVTMwbWl1dUdZcllTQVFPLW91RXZxT1BVRF9IaEd6WnY?oc=5".to_string(),
            "https://news.google.com/rss/articles/CBMimAFBVV95cUxNcVZDZVYtQXVXRFlLQmdCVnVuVlZjMlNZcTNGWm9WN0ZPb0pvMUpBMllJVFo0V3IxZ21RNUtQZTVkc3Joc0c2U2V6ZlA0OHEwdTlHNm8zanp5QmlUUERSVzBQTXJUMXlEVXctZkhUT085SVBvWmVjRWZPNFE4NFZ3LUpOemMyekVMVlRXejl6cHdjYUM2R3cxcw?oc=5".to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://news.google.com/rss/articles/CBMihAFBVV95cUxOdFBPLTgyNWhXOHVqUXNBbnNrVngxSmZDc0lSS0hVdGpFYzRaRTEwTEZudHBacHB2TkxrdnU4YlVNSFNRTkhsVTlSXzJTOUhkOEsyZFpBVThaSGZ2U0MxNmhtYk9DVTMwbWl1dUdZcllTQVFPLW91RXZxT1BVRF9IaEd6WnY?oc=5".to_string(),
                title: Some("Serious Car Accident Risks in Anderson, SC - The Weekly Driver".to_string()),
                excerpt: "The Weekly Driver".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://news.google.com/rss/articles/CBMimAFBVV95cUxNcVZDZVYtQXVXRFlLQmdCVnVuVlZjMlNZcTNGWm9WN0ZPb0pvMUpBMllJVFo0V3IxZ21RNUtQZTVkc3Joc0c2U2V6ZlA0OHEwdTlHNm8zanp5QmlUUERSVzBQTXJUMXlEVXctZkhUT085SVBvWmVjRWZPNFE4NFZ3LUpOemMyekVMVlRXejl6cHdjYUM2R3cxcw?oc=5".to_string(),
                title: Some("Weather pattern clues for April - AccuWeather".to_string()),
                excerpt: "AccuWeather".to_string(),
            },
        ],
        attempted_urls: vec![
            search_url.to_string(),
            "https://www.bing.com/search?q=what%27s+weather+anderson+sc".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::DeadlineReached);
    let urls = extract_urls(&reply);
    assert!(
        !urls.contains(search_url),
        "search-hub query provenance should be excluded when evidence URLs are available, urls={:?}",
        urls
    );
    assert!(
        urls.iter().any(|url| url.contains("/rss/articles/")),
        "expected citation fallback to keep non-hub evidence urls, urls={:?}",
        urls
    );
}

#[test]
fn web_pipeline_single_snapshot_scope_hint_ignores_rss_proxy_tokens() {
    let pending = PendingSearchCompletion {
        query: "what's the weather right now".to_string(),
        query_contract: "what's the weather right now".to_string(),
        url: "https://news.google.com/rss/search?q=current+weather".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_414_000,
        candidate_urls: vec![
            "https://news.google.com/rss/articles/CBMihAFBVV95cUxOdFBPLTgyNWhXOHVqUXNBbnNrVngxSmZDc0lSS0hVdGpFYzRaRTEwTEZudHBacHB2TkxrdnU4YlVNSFNRTkhsVTlSXzJTOUhkOEsyZFpBVThaSGZ2U0MxNmhtYk9DVTMwbWl1dUdZcllTQVFPLW91RXZxT1BVRF9IaEd6WnY?oc=5".to_string(),
            "https://news.google.com/rss/articles/CBMimAFBVV95cUxNcVZDZVYtQXVXRFlLQmdCVnVuVlZjMlNZcTNGWm9WN0ZPb0pvMUpBMllJVFo0V3IxZ21RNUtQZTVkc3Joc0c2U2V6ZlA0OHEwdTlHNm8zanp5QmlUUERSVzBQTXJUMXlEVXctZkhUT085SVBvWmVjRWZPNFE4NFZ3LUpOemMyekVMVlRXejl6cHdjYUM2R3cxcw?oc=5".to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://news.google.com/rss/articles/CBMihAFBVV95cUxOdFBPLTgyNWhXOHVqUXNBbnNrVngxSmZDc0lSS0hVdGpFYzRaRTEwTEZudHBacHB2TkxrdnU4YlVNSFNRTkhsVTlSXzJTOUhkOEsyZFpBVThaSGZ2U0MxNmhtYk9DVTMwbWl1dUdZcllTQVFPLW91RXZxT1BVRF9IaEd6WnY?oc=5".to_string(),
                title: None,
                excerpt: String::new(),
            },
            PendingSearchReadSummary {
                url: "https://news.google.com/rss/articles/CBMimAFBVV95cUxNcVZDZVYtQXVXRFlLQmdCVnVuVlZjMlNZcTNGWm9WN0ZPb0pvMUpBMllJVFo0V3IxZ21RNUtQZTVkc3Joc0c2U2V6ZlA0OHEwdTlHNm8zanp5QmlUUERSVzBQTXJUMXlEVXctZkhUT085SVBvWmVjRWZPNFE4NFZ3LUpOemMyekVMVlRXejl6cHdjYUM2R3cxcw?oc=5".to_string(),
                title: None,
                excerpt: String::new(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::DeadlineReached);
    let lower = reply.to_ascii_lowercase();
    assert!(
        lower.contains("right now (as of"),
        "expected locality-free heading when scope cannot be inferred: {}",
        reply
    );
    assert!(
        !lower.contains("right now in rss articles"),
        "rss proxy tokens should never become a location scope: {}",
        reply
    );
}

#[test]
fn web_pipeline_single_snapshot_retains_partial_note_when_grounded_hints_lack_resolvable_metrics() {
    let pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        url: "https://duckduckgo.com/?q=anderson+sc+weather+right+now".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_414_000,
        candidate_urls: vec![
            "https://weather.com/weather/today/l/Anderson%20SC".to_string(),
            "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327".to_string(),
        ],
        candidate_source_hints: vec![crate::agentic::desktop::types::PendingSearchReadSummary {
            url: "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327"
                .to_string(),
            title: Some("Anderson, SC Current Weather".to_string()),
            excerpt: "Current conditions source with hourly metrics and weather updates."
                .to_string(),
        }],
        attempted_urls: vec!["https://weather.com/weather/today/l/Anderson%20SC".to_string()],
        blocked_urls: vec![],
        successful_reads: vec![crate::agentic::desktop::types::PendingSearchReadSummary {
            url: "https://weather.com/weather/today/l/Anderson%20SC".to_string(),
            title: Some("Anderson, SC Forecast".to_string()),
            excerpt: "Today: Hi 65 F. Tonight: Lo 49 F. Mostly cloudy with light rain.".to_string(),
        }],
        min_sources: 2,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::DeadlineReached);
    assert!(
        reply.contains("Partial evidence: confirmed readable sources"),
        "non-resolvable hints should not suppress partial-evidence caveat messaging"
    );
}
