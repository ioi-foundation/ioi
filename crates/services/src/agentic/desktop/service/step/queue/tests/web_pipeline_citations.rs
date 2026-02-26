use super::*;

#[test]
fn web_pipeline_dedupes_near_duplicate_story_titles() {
    let pending = PendingSearchCompletion {
        query: "top breaking stories".to_string(),
        query_contract: "top breaking stories".to_string(),
        url: "https://duckduckgo.com/?q=top+breaking+stories".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://news1.example.com/a".to_string(),
            "https://news2.example.com/b".to_string(),
            "https://news3.example.com/c".to_string(),
            "https://news4.example.com/d".to_string(),
            "https://news5.example.com/e".to_string(),
            "https://news6.example.com/f".to_string(),
        ],
        candidate_source_hints: vec![
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://news1.example.com/a".to_string(),
                title: Some("Senate passes emergency funding package".to_string()),
                excerpt: "An emergency package advanced after a late-session vote.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://news2.example.com/b".to_string(),
                title: Some("Emergency funding package passes in Senate vote".to_string()),
                excerpt: "Lawmakers approved stopgap funding in an overnight session.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://news3.example.com/c".to_string(),
                title: Some("Wildfire response expands across western states".to_string()),
                excerpt: "Federal and state teams expanded response coverage overnight."
                    .to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://news4.example.com/d".to_string(),
                title: Some("DOJ files updated brief in high-profile case".to_string()),
                excerpt: "New filings add detail to the government legal position.".to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    let story_titles = extract_story_titles(&reply);
    let unique_titles = story_titles.iter().collect::<BTreeSet<_>>();
    assert_eq!(unique_titles.len(), story_titles.len());
}

#[test]
fn web_pipeline_prioritizes_status_page_incidents_over_roundups() {
    let pending = PendingSearchCompletion {
        query: "top active cloud incidents".to_string(),
        query_contract: "top active cloud incidents".to_string(),
        url: "https://duckduckgo.com/?q=top+active+cloud+incidents".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://example.com/roundup/a".to_string(),
            "https://example.com/analysis/b".to_string(),
            "https://status.vendor-a.com/incidents/123".to_string(),
            "https://status.vendor-b.com/incidents/456".to_string(),
            "https://status.vendor-c.com/incidents/789".to_string(),
        ],
        candidate_source_hints: vec![
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://example.com/roundup/a".to_string(),
                title: Some("Weekly cloud outage roundup and analysis".to_string()),
                excerpt: "Opinion and analysis of recent incidents.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://example.com/analysis/b".to_string(),
                title: Some("Fact sheet: cloud reliability trends".to_string()),
                excerpt: "Meta commentary rather than active status updates.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.vendor-a.com/incidents/123".to_string(),
                title: Some("API outage impacting U.S. region".to_string()),
                excerpt: "Status page shows investigating with mitigation underway.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.vendor-b.com/incidents/456".to_string(),
                title: Some("Authentication degradation for North America".to_string()),
                excerpt: "Users may see login errors; next update expected within 30 minutes."
                    .to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.vendor-c.com/incidents/789".to_string(),
                title: Some("Dashboard latency incident on status page".to_string()),
                excerpt: "Workaround suggests retrying read-only operations.".to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    let story_titles = extract_story_titles(&reply);
    assert_eq!(story_titles.len(), 3);
    let story_titles_lc = story_titles
        .iter()
        .map(|title| title.to_ascii_lowercase())
        .collect::<Vec<_>>();
    assert!(
        story_titles_lc
            .iter()
            .all(|title| !title.contains("roundup") && !title.contains("fact sheet")),
        "expected status-page incidents to outrank low-priority roundup sources, got {:?}",
        story_titles
    );
}

#[test]
fn web_pipeline_demotes_secondary_status_aggregators_below_primary_status_surfaces() {
    let pending = PendingSearchCompletion {
        query: "top active cloud incidents".to_string(),
        query_contract: "top active cloud incidents".to_string(),
        url: "https://duckduckgo.com/?q=top+active+cloud+incidents".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://status.vendor-a.com/incidents/123".to_string(),
            "https://status.vendor-b.com/incidents/456".to_string(),
            "https://status.vendor-c.com/incidents/789".to_string(),
            "https://example-monitor.com/cloud/incidents".to_string(),
            "https://ops-tracker.example.net/status".to_string(),
            "https://service-watch.example.org/dashboards/cloud".to_string(),
        ],
        candidate_source_hints: vec![
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.vendor-a.com/incidents/123".to_string(),
                title: Some("API outage impacting U.S. region".to_string()),
                excerpt: "Investigating elevated API errors with mitigation underway.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.vendor-b.com/incidents/456".to_string(),
                title: Some("Authentication degradation for North America".to_string()),
                excerpt: "Users may see login errors; next update expected within 30 minutes."
                    .to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.vendor-c.com/incidents/789".to_string(),
                title: Some("Dashboard latency incident on status page".to_string()),
                excerpt: "Workaround suggests retrying read-only operations.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://example-monitor.com/cloud/incidents".to_string(),
                title: Some("Cloud status page aggregator".to_string()),
                excerpt: "Track incidents across providers with community outage reports."
                    .to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://ops-tracker.example.net/status".to_string(),
                title: Some("Operations tracker across services".to_string()),
                excerpt: "Aggregated signal feed for multiple services and providers.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://service-watch.example.org/dashboards/cloud".to_string(),
                title: Some("Cloud outage monitor dashboard".to_string()),
                excerpt: "Multi-service monitor for industry incidents.".to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    let story_titles = extract_story_titles(&reply);
    assert_eq!(story_titles.len(), 3);
    let story_titles_lc = story_titles
        .iter()
        .map(|title| title.to_ascii_lowercase())
        .collect::<Vec<_>>();
    assert!(
        story_titles_lc.iter().all(|title| {
            !title.contains("aggregator")
                && !title.contains("tracker")
                && !title.contains("monitor")
        }),
        "expected primary status surfaces to outrank secondary aggregators, got {:?}",
        story_titles
    );
}

#[test]
fn web_pipeline_prefers_primary_status_citations_when_sufficient_inventory_exists() {
    let pending = PendingSearchCompletion {
        query: "top active cloud incidents".to_string(),
        query_contract: "top active cloud incidents".to_string(),
        url: "https://duckduckgo.com/?q=top+active+cloud+incidents".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://status.vendor-a.com/incidents/1".to_string(),
            "https://status.vendor-b.com/incidents/2".to_string(),
            "https://status.vendor-c.com/incidents/3".to_string(),
            "https://status.vendor-d.com/incidents/4".to_string(),
            "https://status.vendor-e.com/incidents/5".to_string(),
            "https://status.vendor-f.com/incidents/6".to_string(),
            "https://example-monitor.com/cloud/incidents".to_string(),
            "https://ops-tracker.example.net/status".to_string(),
        ],
        candidate_source_hints: vec![
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.vendor-a.com/incidents/1".to_string(),
                title: Some("API outage impacting U.S. region".to_string()),
                excerpt: "Investigating elevated API errors with mitigation underway.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.vendor-b.com/incidents/2".to_string(),
                title: Some("Authentication degradation for North America".to_string()),
                excerpt: "Users may see login errors; next update expected within 30 minutes."
                    .to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.vendor-c.com/incidents/3".to_string(),
                title: Some("Dashboard latency incident on status page".to_string()),
                excerpt: "Workaround suggests retrying read-only operations.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.vendor-d.com/incidents/4".to_string(),
                title: Some("Storage control-plane incident".to_string()),
                excerpt: "Mitigation in progress; next update in 20 minutes.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.vendor-e.com/incidents/5".to_string(),
                title: Some("Network packet loss in us-east".to_string()),
                excerpt: "Investigating traffic instability for affected tenants.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.vendor-f.com/incidents/6".to_string(),
                title: Some("Control-plane API timeout".to_string()),
                excerpt: "Monitoring mitigation rollout after identified regression.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://example-monitor.com/cloud/incidents".to_string(),
                title: Some("Cloud status page aggregator".to_string()),
                excerpt: "Track incidents across providers with community outage reports."
                    .to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://ops-tracker.example.net/status".to_string(),
                title: Some("Operations tracker across services".to_string()),
                excerpt: "Aggregated signal feed for multiple services and providers.".to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    assert!(
        !reply.contains("https://example-monitor.com/cloud/incidents"),
        "expected primary status citations to be preferred when sufficient inventory exists; reply:\n{}",
        reply
    );
    assert!(
        !reply.contains("https://ops-tracker.example.net/status"),
        "expected primary status citations to be preferred when sufficient inventory exists; reply:\n{}",
        reply
    );
}

#[test]
fn web_pipeline_citation_selector_limits_duplicate_claim_clusters_when_alternatives_exist() {
    let source = PendingSearchReadSummary {
        url: "https://status.vendor-a.com/incidents/alpha".to_string(),
        title: Some("API outage impacting us-east".to_string()),
        excerpt: "Investigating elevated API errors and mitigation underway.".to_string(),
    };
    let candidates = vec![
        CitationCandidate {
            id: "C1".to_string(),
            url: "https://status.vendor-a.com/incidents/alpha".to_string(),
            source_label: "Incident update".to_string(),
            excerpt: "Investigating elevated API errors and mitigation underway.".to_string(),
            timestamp_utc: "2026-02-22T00:00:00Z".to_string(),
            note: "retrieved_utc".to_string(),
            from_successful_read: true,
        },
        CitationCandidate {
            id: "C2".to_string(),
            url: "https://status.vendor-b.com/incidents/beta".to_string(),
            source_label: "Incident update".to_string(),
            excerpt: "Investigating elevated API errors and mitigation underway.".to_string(),
            timestamp_utc: "2026-02-22T00:00:00Z".to_string(),
            note: "retrieved_utc".to_string(),
            from_successful_read: true,
        },
        CitationCandidate {
            id: "C3".to_string(),
            url: "https://status.vendor-c.com/incidents/gamma".to_string(),
            source_label: "Auth incident update".to_string(),
            excerpt: "Users may see login failures while mitigation rolls out.".to_string(),
            timestamp_utc: "2026-02-22T00:00:00Z".to_string(),
            note: "retrieved_utc".to_string(),
            from_successful_read: true,
        },
    ];
    let mut used_urls = BTreeSet::new();
    let constraints = single_snapshot_constraint_set_with_hints("top active incidents", 2, &[]);
    let selected_ids = citation_ids_for_story(
        &source,
        &candidates,
        &mut used_urls,
        2,
        false,
        &constraints,
        ResolutionPolicy::default(),
    );

    assert_eq!(selected_ids.len(), 2);
    assert!(
        selected_ids.iter().any(|id| id == "C1"),
        "expected primary claim citation to remain selected"
    );
    assert!(
        selected_ids.iter().any(|id| id == "C3"),
        "expected selector to diversify claims when a distinct insight exists"
    );
    assert!(
        !selected_ids.iter().any(|id| id == "C2"),
        "expected duplicate claim citation to be deferred behind distinct claim coverage"
    );
}

#[test]
fn web_pipeline_reply_heading_is_query_agnostic() {
    let pending = PendingSearchCompletion {
        query: "latest regional cloud availability updates".to_string(),
        query_contract: "latest regional cloud availability updates".to_string(),
        url: "https://duckduckgo.com/?q=latest+regional+cloud+availability+updates".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://status.vendor-a.com/incidents/123".to_string(),
            "https://status.vendor-b.com/incidents/456".to_string(),
            "https://status.vendor-c.com/incidents/789".to_string(),
            "https://status.vendor-d.com/incidents/999".to_string(),
            "https://status.vendor-e.com/incidents/111".to_string(),
            "https://status.vendor-f.com/incidents/222".to_string(),
        ],
        candidate_source_hints: vec![
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.vendor-a.com/incidents/123".to_string(),
                title: Some("Regional outage in us-east".to_string()),
                excerpt: "Investigating elevated API errors and degraded latency.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.vendor-b.com/incidents/456".to_string(),
                title: Some("Service health alert for dashboard".to_string()),
                excerpt: "Monitoring mitigation rollout for North America users.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.vendor-c.com/incidents/789".to_string(),
                title: Some("Authentication degradation update".to_string()),
                excerpt: "Providers report partial recovery with ongoing monitoring.".to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    assert!(
        reply.contains("Web retrieval summary for 'latest regional cloud availability updates'"),
        "expected query-agnostic heading, got:\n{}",
        reply
    );
}

#[test]
fn web_pipeline_reply_omits_internal_diagnostics_by_default() {
    let pending = PendingSearchCompletion {
        query: "latest regional cloud availability updates".to_string(),
        query_contract: "latest regional cloud availability updates".to_string(),
        url: "https://duckduckgo.com/?q=latest+regional+cloud+availability+updates".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://status.vendor-a.com/incidents/123".to_string(),
            "https://status.vendor-b.com/incidents/456".to_string(),
            "https://status.vendor-c.com/incidents/789".to_string(),
            "https://status.vendor-d.com/incidents/999".to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://status.vendor-a.com/incidents/123".to_string(),
                title: Some("Regional outage in us-east".to_string()),
                excerpt: "Investigating elevated API errors and degraded latency.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://status.vendor-b.com/incidents/456".to_string(),
                title: Some("Service health alert for dashboard".to_string()),
                excerpt: "Monitoring mitigation rollout for North America users.".to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec!["https://status.vendor-c.com/incidents/789".to_string()],
        successful_reads: vec![],
        min_sources: 2,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    assert!(!reply.contains(&format!(
        "Insight selector: {}",
        WEIGHTED_INSIGHT_SIGNAL_VERSION
    )));
    assert!(!reply.contains("Insights used:"));
    assert!(!reply.contains("Evidence gaps:"));
    assert!(reply.contains("Citations:"));
    assert!(reply.contains("Overall confidence:"));
}
