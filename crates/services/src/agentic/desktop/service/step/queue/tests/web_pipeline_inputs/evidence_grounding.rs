use super::*;

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
        url: "https://example.com/news".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec!["https://example.com/news/storm-delays".to_string()],
        candidate_source_hints: vec![crate::agentic::desktop::types::PendingSearchReadSummary {
            url: "https://example.com/news/storm-delays".to_string(),
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
        "https://example.com/news/storm-delays",
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
fn web_pipeline_metadata_noise_excerpt_is_rejected_and_replaced_by_hint_payload() {
    let requested_url = "https://www.foxnews.com/";
    let mut pending = PendingSearchCompletion {
        query: "today's top news headlines".to_string(),
        query_contract: "today's top news headlines".to_string(),
        url: "https://www.bing.com/search?q=today+top+news+headlines".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some("Fox News - Breaking News Updates".to_string()),
            excerpt: "Breaking news updates across U.S. and world stories today.".to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };
    let metadata_blob = r#"{"@context":"https://schema.org","@type":"NewsMediaOrganization","datePublished":"1996-10-07","inLanguage":"en","image":{"@type":"ImageObject","width":1200,"height":630,"caption":"Fox News - Breaking News and Latest Headlines"}}"#;
    assert!(looks_like_structured_metadata_noise(metadata_blob));
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(requested_url.to_string()),
        sources: vec![WebSource {
            source_id: "source:fox-home".to_string(),
            rank: None,
            url: requested_url.to_string(),
            title: Some("Fox News".to_string()),
            snippet: None,
            domain: Some("foxnews.com".to_string()),
        }],
        documents: vec![WebDocument {
            source_id: "source:fox-home".to_string(),
            url: requested_url.to_string(),
            title: Some("Fox News".to_string()),
            content_text: metadata_blob.to_string(),
            content_hash: "hash".to_string(),
            quote_spans: vec![],
        }],
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);
    assert_eq!(pending.successful_reads.len(), 1);
    assert!(
        !pending.successful_reads[0]
            .excerpt
            .to_ascii_lowercase()
            .contains("datepublished"),
        "metadata blob should be filtered from excerpts"
    );
    assert!(
        pending.successful_reads[0]
            .excerpt
            .to_ascii_lowercase()
            .contains("breaking news"),
        "expected fallback to retain actionable search-hint excerpt"
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
