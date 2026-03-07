#[test]
fn web_pipeline_single_snapshot_completion_receipts_expose_metric_grounding() {
    let pending = PendingSearchCompletion {
        query: "What's the current price of Bitcoin?".to_string(),
        query_contract: "What's the current price of Bitcoin?".to_string(),
        retrieval_contract: None,
        url: "https://www.coindesk.com/price/bitcoin".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://www.coindesk.com/price/bitcoin".to_string(),
            "https://crypto.news/price/bitcoin/".to_string(),
        ],
        candidate_source_hints: vec![],
        attempted_urls: vec![
            "https://www.coindesk.com/price/bitcoin".to_string(),
            "https://crypto.news/price/bitcoin/".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.coindesk.com/price/bitcoin".to_string(),
                title: Some("CoinDesk Bitcoin price".to_string()),
                excerpt: "Bitcoin price right now: $68,214.99 USD as of 19:25 UTC.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://crypto.news/price/bitcoin/".to_string(),
                title: Some("Crypto.news Bitcoin price".to_string()),
                excerpt: "Current BTC quote: $68,267.00 USD.".to_string(),
            },
        ],
        min_sources: 2,
    };

    let mut checks = Vec::new();
    append_final_web_completion_receipts(
        &pending,
        WebPipelineCompletionReason::MinSourcesReached,
        &mut checks,
    );

    assert!(checks
        .iter()
        .any(|check| check == "web_final_single_snapshot_metric_grounding=true"));
    assert!(checks
        .iter()
        .any(|check| check == "web_final_story_citation_floor_met=true"));
}

#[test]
fn web_pipeline_single_fact_query_prefers_direct_answer_layout() {
    let pending = PendingSearchCompletion {
        query: "Who is the latest OpenAI CEO?".to_string(),
        query_contract: "Who is the latest OpenAI CEO?".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=latest+OpenAI+CEO".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://openai.com/".to_string(),
            "https://en.wikipedia.org/wiki/OpenAI".to_string(),
        ],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://openai.com/".to_string(),
            title: Some("OpenAI leadership".to_string()),
            excerpt: "OpenAI is led by CEO Sam Altman.".to_string(),
        }],
        attempted_urls: vec!["https://openai.com/".to_string()],
        blocked_urls: vec![],
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://openai.com/".to_string(),
            title: Some("OpenAI leadership".to_string()),
            excerpt: "OpenAI is led by CEO Sam Altman.".to_string(),
        }],
        min_sources: 1,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    assert!(reply.contains("What happened:"));
    assert!(!reply.contains("Story 1:"));
    assert!(!reply.contains("Answer:"));
    assert!(!reply.contains("Context:"));
}

#[test]
fn web_pipeline_renders_single_snapshot_for_time_sensitive_public_fact_queries() {
    let pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        retrieval_contract: None,
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
