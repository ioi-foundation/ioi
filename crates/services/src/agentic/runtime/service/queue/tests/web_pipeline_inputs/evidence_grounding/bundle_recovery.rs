#[test]
fn web_pipeline_bundle_success_retries_with_requested_url_when_document_url_fails() {
    let requested_url = "https://weather.com/weather/today/l/Anderson+SC";
    let mut pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        retrieval_contract: None,
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
        source_observations: vec![],
        documents: vec![WebDocument {
            source_id: "source:redirect".to_string(),
            url: "https://example.com/redirect".to_string(),
            title: Some("Redirect landing page".to_string()),
            content_text: "Navigation and legal terms. Sign in to continue.".to_string(),
            content_hash: "hash".to_string(),
            quote_spans: vec![],
        }],
        provider_candidates: vec![],
        retrieval_contract: None,
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
fn web_pipeline_bundle_success_marks_human_challenge_pages_blocked() {
    let requested_url =
        "https://www.tripadvisor.com/Restaurant_Review-g60763-d26557158-Reviews-Roscioli-New_York_City_New_York.html";
    let mut pending = PendingSearchCompletion {
        query: "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus."
            .to_string(),
        query_contract:
            "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus."
                .to_string(),
        retrieval_contract: None,
        url: "https://www.bing.com/search?q=Roscioli+restaurant+menu+New+York+NY".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some("tripadvisor.com".to_string()),
            excerpt: "Please enable JS and disable any ad blocker to continue.".to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 3,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(requested_url.to_string()),
        sources: vec![WebSource {
            source_id: "source:tripadvisor".to_string(),
            rank: None,
            url: requested_url.to_string(),
            title: Some("tripadvisor.com".to_string()),
            snippet: Some("Please enable JS and disable any ad blocker to continue.".to_string()),
            domain: Some("tripadvisor.com".to_string()),
        }],
        source_observations: vec![],
        documents: vec![WebDocument {
            source_id: "source:tripadvisor".to_string(),
            url: requested_url.to_string(),
            title: Some("tripadvisor.com".to_string()),
            content_text:
                "Please enable JS and disable any ad blocker var dd={'rt':'c','cid':'token'}"
                    .to_string(),
            content_hash: "hash".to_string(),
            quote_spans: vec![],
        }],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);

    assert!(
        pending.successful_reads.is_empty(),
        "challenge pages should not be recorded as successful reads"
    );
    assert_eq!(pending.blocked_urls, vec![requested_url.to_string()]);
}

#[test]
fn web_pipeline_bundle_success_rejects_rate_limited_terminal_pages() {
    let requested_url =
        "https://sentinelcolorado.com/nation-world/world/friday-news-in-a-rush-top-headlines-in-todays-newsminute-video-257/";
    let mut pending = PendingSearchCompletion {
        query: "Tell me today's top news headlines.".to_string(),
        query_contract: "Tell me today's top news headlines.".to_string(),
        retrieval_contract: None,
        url: "https://www.bing.com/news/search?q=today+top+news+headlines".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some("Friday News in a Rush".to_string()),
            excerpt: "Top world headlines and daily roundup.".to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 3,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(requested_url.to_string()),
        sources: vec![WebSource {
            source_id: "source:sentinel".to_string(),
            rank: None,
            url: requested_url.to_string(),
            title: Some("429 Too Many Requests".to_string()),
            snippet: Some("429 Too Many Requests".to_string()),
            domain: Some("sentinelcolorado.com".to_string()),
        }],
        source_observations: vec![],
        documents: vec![WebDocument {
            source_id: "source:sentinel".to_string(),
            url: requested_url.to_string(),
            title: Some("429 Too Many Requests".to_string()),
            content_text: "429 Too Many Requests".to_string(),
            content_hash: "hash".to_string(),
            quote_spans: vec![],
        }],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);

    assert!(
        pending.successful_reads.is_empty(),
        "rate-limited terminal pages should not be recorded as successful reads"
    );
}

#[test]
fn web_pipeline_append_success_from_bundle_preserves_non_low_signal_read_excerpt() {
    let requested_url = "https://weather.yahoo.com/us/sc/anderson";
    let mut pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        retrieval_contract: None,
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
        source_observations: vec![],
        documents: vec![WebDocument {
            source_id: "source:weather".to_string(),
            url: requested_url.to_string(),
            title: Some("Anderson Forecast".to_string()),
            content_text: "Mostly Cloudy today with a high of 61°F and a low of 45°F.".to_string(),
            content_hash: "hash".to_string(),
            quote_spans: vec![],
        }],
        provider_candidates: vec![],
        retrieval_contract: None,
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
