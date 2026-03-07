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
