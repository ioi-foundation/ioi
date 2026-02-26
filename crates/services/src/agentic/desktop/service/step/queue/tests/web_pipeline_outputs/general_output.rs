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
fn web_pipeline_news_without_read_grounding_avoids_fabricated_story_sections() {
    let pending = PendingSearchCompletion {
        query: "today's top news headlines".to_string(),
        query_contract: "today's top news headlines".to_string(),
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
fn web_pipeline_headline_reply_excludes_blocked_and_internal_probe_urls_from_citations() {
    let pending = PendingSearchCompletion {
        query: "Tell me today's top news headlines.".to_string(),
        query_contract: "Tell me today's top news headlines.".to_string(),
        url: "https://duckduckgo.com/?q=today+top+news+headlines".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec!["https://www.npr.org/sections/news/".to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://www.npr.org/sections/news/".to_string(),
            title: Some("News : U.S. and World News Headlines : NPR".to_string()),
            excerpt: "Coverage of breaking stories, national and world news.".to_string(),
        }],
        attempted_urls: vec![
            "https://www.npr.org/sections/news/".to_string(),
            "ioi://quality-recovery/probe".to_string(),
        ],
        blocked_urls: vec!["https://www.npr.org/sections/news/".to_string()],
        successful_reads: vec![],
        min_sources: 2,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::ExhaustedCandidates);
    assert!(reply.contains("Synthesis unavailable"));
    assert!(!reply.contains("What happened:"));
    assert!(!reply.contains("ioi://quality-recovery/probe"));
    assert!(!reply.contains(
        "News : U.S. and World News Headlines : NPR | https://www.npr.org/sections/news/"
    ));
    assert!(reply
        .contains("Blocked sources requiring human challenge: https://www.npr.org/sections/news/"));
}

#[test]
fn web_pipeline_single_fact_query_prefers_direct_answer_layout() {
    let pending = PendingSearchCompletion {
        query: "Who is the latest OpenAI CEO?".to_string(),
        query_contract: "Who is the latest OpenAI CEO?".to_string(),
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
        urls.len() >= 3,
        "expected >= 3 distinct urls, got {}",
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
