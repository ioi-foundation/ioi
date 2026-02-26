use super::*;

#[test]
fn web_pipeline_single_snapshot_citation_filter_excludes_query_hub_and_rss_wrappers() {
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
        urls.iter().all(|url| !url.contains("/rss/articles/")),
        "rss wrapper urls should be excluded from citation output, urls={:?}",
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
        reply.contains("Partial evidence: verification receipt -> retrieved"),
        "non-resolvable hints should not suppress partial-evidence caveat messaging"
    );
}
