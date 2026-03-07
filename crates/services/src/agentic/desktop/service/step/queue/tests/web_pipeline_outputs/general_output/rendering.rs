#[test]
fn web_pipeline_latency_budget_escalates_after_slow_attempts() {
    let pending = PendingSearchCompletion {
        query: "what's the weather right now in anderson sc".to_string(),
        query_contract: "what's the weather right now in anderson sc".to_string(),
        retrieval_contract: None,
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
        retrieval_contract: None,
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
        retrieval_contract: None,
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
fn web_pipeline_news_without_read_grounding_avoids_fabricated_story_sections() {
    let pending = PendingSearchCompletion {
        query: "today's top news headlines".to_string(),
        query_contract: "today's top news headlines".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=today+top+news+headlines".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://www.cnn.com/".to_string(),
            "https://www.foxnews.com/".to_string(),
            "https://www.bbc.com/news".to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://www.cnn.com/".to_string(),
                title: Some("Breaking News, Latest News and Videos | CNN".to_string()),
                excerpt: "View the latest news and breaking news today".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.foxnews.com/".to_string(),
                title: Some("Fox News - Breaking News Updates | Latest News Headlines".to_string()),
                excerpt: "Breaking News, Latest News and Current News".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.bbc.com/news".to_string(),
                title: Some("BBC News - Breaking news".to_string()),
                excerpt: "Latest top stories".to_string(),
            },
        ],
        attempted_urls: vec![
            "https://www.cnn.com/".to_string(),
            "https://www.foxnews.com/".to_string(),
            "https://www.bbc.com/news".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 3,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::ExhaustedCandidates);
    assert!(reply.contains("Synthesis unavailable"));
    assert!(!reply.contains("Story 1:"));
}

#[test]
fn web_pipeline_multi_story_query_does_not_duplicate_single_source_into_multiple_story_slots() {
    let pending = PendingSearchCompletion {
        query: "today's top news headlines".to_string(),
        query_contract: "today's top news headlines".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=today+top+news+headlines".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec!["https://www.example.com/news/main".to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://www.example.com/news/main".to_string(),
            title: Some("Top headlines".to_string()),
            excerpt: "Top headlines include market swings and policy updates.".to_string(),
        }],
        attempted_urls: vec!["https://www.example.com/news/main".to_string()],
        blocked_urls: vec![],
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://www.example.com/news/main".to_string(),
            title: Some("Top headlines".to_string()),
            excerpt: "Top headlines include market swings and policy updates.".to_string(),
        }],
        min_sources: 3,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::ExhaustedCandidates);
    assert!(reply.contains("Synthesis unavailable"));
    assert!(!reply.contains("Story 2:"));
    assert!(!reply.contains("Story 3:"));
}

#[test]
fn web_pipeline_append_success_skips_terminal_error_pages() {
    let mut pending = PendingSearchCompletion {
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
        candidate_urls: vec!["https://ny.eater.com/2023/10/5/23890123/best-italian-restaurants-nyc"
            .to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://ny.eater.com/2023/10/5/23890123/best-italian-restaurants-nyc"
                .to_string(),
            title: Some("404 Not Found | Eater NY".to_string()),
            excerpt: "Sorry, the page you were looking for could not be found.".to_string(),
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
        backend: "edge:playwright:http".to_string(),
        query: None,
        url: Some(
            "https://ny.eater.com/2023/10/5/23890123/best-italian-restaurants-nyc".to_string(),
        ),
        sources: vec![WebSource {
            source_id: "eater-404".to_string(),
            rank: Some(1),
            url: "https://ny.eater.com/2023/10/5/23890123/best-italian-restaurants-nyc".to_string(),
            title: Some("404 Not Found | Eater NY".to_string()),
            snippet: Some("Sorry, the page you were looking for could not be found.".to_string()),
            domain: Some("ny.eater.com".to_string()),
        }],
        source_observations: vec![],
        documents: vec![WebDocument {
            source_id: "eater-404".to_string(),
            url: "https://ny.eater.com/2023/10/5/23890123/best-italian-restaurants-nyc".to_string(),
            title: Some("404 Not Found | Eater NY".to_string()),
            content_text: "404 Not Found. Sorry, the page you were looking for could not be found."
                .to_string(),
            content_hash: "deadbeef".to_string(),
            quote_spans: vec![],
        }],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(
        &mut pending,
        &bundle,
        "https://ny.eater.com/2023/10/5/23890123/best-italian-restaurants-nyc",
    );

    assert!(
        pending.successful_reads.is_empty(),
        "terminal error pages should not count as successful reads: {:?}",
        pending.successful_reads
    );
}

#[test]
fn web_pipeline_reply_enforces_three_story_structure_with_citations_and_timestamps() {
    let pending = PendingSearchCompletion {
        query: "As of now (UTC), top 3 active U.S.-impacting cloud/SaaS incidents (major status pages), what changed in last hour, user impact, workaround, ETA confidence, 2 citations each."
            .to_string(),
        query_contract: "As of now (UTC), top 3 active U.S.-impacting cloud/SaaS incidents (major status pages), what changed in last hour, user impact, workaround, ETA confidence, 2 citations each."
            .to_string(),
        retrieval_contract: None,
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
        urls.len() >= 3,
        "expected >= 3 distinct urls, got {}",
        urls.len()
    );
}
