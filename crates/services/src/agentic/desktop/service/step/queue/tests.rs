use super::support::{
    append_pending_web_success_fallback, candidate_source_hints_from_bundle,
    candidate_urls_from_bundle, fallback_search_summary, queue_action_request_to_tool,
    summarize_search_results, synthesize_web_pipeline_reply, web_pipeline_completion_reason,
    WebPipelineCompletionReason,
};
use crate::agentic::desktop::types::PendingSearchCompletion;
use ioi_types::app::agentic::{AgentTool, ComputerAction};
use ioi_types::app::agentic::{WebEvidenceBundle, WebSource};
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget};
use std::collections::BTreeSet;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn build_request(target: ActionTarget, nonce: u64, args: serde_json::Value) -> ActionRequest {
    ActionRequest {
        target,
        params: serde_json::to_vec(&args).expect("params should serialize"),
        context: ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: None,
            window_id: None,
        },
        nonce,
    }
}

fn build_fs_read_request(args: serde_json::Value) -> ActionRequest {
    build_request(ActionTarget::FsRead, 7, args)
}

fn build_fs_write_request(args: serde_json::Value) -> ActionRequest {
    build_request(ActionTarget::FsWrite, 11, args)
}

fn build_custom_request(name: &str, nonce: u64, args: serde_json::Value) -> ActionRequest {
    build_request(ActionTarget::Custom(name.to_string()), nonce, args)
}

fn build_sys_exec_request(args: serde_json::Value) -> ActionRequest {
    build_request(ActionTarget::SysExec, 13, args)
}

fn extract_urls(text: &str) -> BTreeSet<String> {
    text.split_whitespace()
        .filter_map(|token| {
            let trimmed = token
                .trim_matches(|ch: char| ",.;:!?()[]{}\"'|".contains(ch))
                .trim();
            if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
                Some(trimmed.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn extract_story_titles(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.strip_prefix("Story "))
        .map(|line| {
            line.split_once(':')
                .map(|(_, title)| title.trim().to_string())
                .expect("story lines should contain ':' separators")
        })
        .collect()
}

#[test]
fn summary_contains_topic_and_refinement_hint() {
    let summary = summarize_search_results(
        "internet of intelligence",
        "https://duckduckgo.com/?q=internet+of+intelligence",
        "<html><body><a href=\"https://example.com/a\">A</a>\nThe Internet of Intelligence explores decentralized agent coordination.\nOpen protocols enable verifiable execution and policy enforcement.</body></html>",
    );
    assert!(summary.contains("Search summary for 'internet of intelligence'"));
    assert!(summary.contains("Source URL: https://duckduckgo.com/?q=internet+of+intelligence"));
    assert!(summary.contains("Next refinement:"));
}

#[test]
fn fallback_summary_is_deterministic() {
    let msg = fallback_search_summary(
        "internet of intelligence",
        "https://duckduckgo.com/?q=internet+of+intelligence",
    );
    assert_eq!(
        msg,
        "Searched 'internet of intelligence' at https://duckduckgo.com/?q=internet+of+intelligence, but structured extraction failed. Retry refinement if needed."
    );
}

#[test]
fn web_pipeline_candidate_urls_preserve_rank_order() {
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:ddg".to_string(),
        query: Some("latest news".to_string()),
        url: Some("https://duckduckgo.com/?q=latest+news".to_string()),
        sources: vec![
            WebSource {
                source_id: "b".to_string(),
                rank: Some(2),
                url: "https://b.example.com".to_string(),
                title: Some("B".to_string()),
                snippet: None,
                domain: Some("b.example.com".to_string()),
            },
            WebSource {
                source_id: "a".to_string(),
                rank: Some(1),
                url: "https://a.example.com".to_string(),
                title: Some("A".to_string()),
                snippet: None,
                domain: Some("a.example.com".to_string()),
            },
        ],
        documents: vec![],
    };

    let urls = candidate_urls_from_bundle(&bundle);
    assert_eq!(
        urls,
        vec![
            "https://a.example.com".to_string(),
            "https://b.example.com".to_string()
        ]
    );
}

#[test]
fn web_pipeline_source_hints_preserve_rank_order() {
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:ddg".to_string(),
        query: Some("latest news".to_string()),
        url: Some("https://duckduckgo.com/?q=latest+news".to_string()),
        sources: vec![
            WebSource {
                source_id: "b".to_string(),
                rank: Some(2),
                url: "https://b.example.com".to_string(),
                title: Some("Headline B".to_string()),
                snippet: Some("Summary B".to_string()),
                domain: Some("b.example.com".to_string()),
            },
            WebSource {
                source_id: "a".to_string(),
                rank: Some(1),
                url: "https://a.example.com".to_string(),
                title: Some("Headline A".to_string()),
                snippet: Some("Summary A".to_string()),
                domain: Some("a.example.com".to_string()),
            },
        ],
        documents: vec![],
    };

    let hints = candidate_source_hints_from_bundle(&bundle);
    assert_eq!(hints.len(), 2);
    assert_eq!(hints[0].url, "https://a.example.com");
    assert_eq!(hints[0].title.as_deref(), Some("Headline A"));
    assert_eq!(hints[1].url, "https://b.example.com");
    assert_eq!(hints[1].title.as_deref(), Some("Headline B"));
}

#[test]
fn web_pipeline_source_hints_prioritize_primary_status_surfaces_over_secondary_aggregation() {
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:ddg".to_string(),
        query: Some("active cloud incidents".to_string()),
        url: Some("https://duckduckgo.com/?q=active+cloud+incidents".to_string()),
        sources: vec![
            WebSource {
                source_id: "agg".to_string(),
                rank: Some(1),
                url: "https://example-monitor.com/cloud/incidents".to_string(),
                title: Some("Cloud status page aggregator".to_string()),
                snippet: Some(
                    "Track incidents across providers with community outage reports.".to_string(),
                ),
                domain: Some("example-monitor.com".to_string()),
            },
            WebSource {
                source_id: "primary".to_string(),
                rank: Some(5),
                url: "https://status.vendor-a.com/incidents/123".to_string(),
                title: Some("API outage impacting U.S. region".to_string()),
                snippet: Some(
                    "Status page shows investigating with mitigation underway.".to_string(),
                ),
                domain: Some("status.vendor-a.com".to_string()),
            },
        ],
        documents: vec![],
    };

    let hints = candidate_source_hints_from_bundle(&bundle);
    assert_eq!(hints.len(), 2);
    assert_eq!(hints[0].url, "https://status.vendor-a.com/incidents/123");
    assert_eq!(hints[1].url, "https://example-monitor.com/cloud/incidents");
}

#[test]
fn web_pipeline_source_hints_prioritize_operational_status_hosts_over_documentation_surfaces() {
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:ddg".to_string(),
        query: Some("service health incidents".to_string()),
        url: Some("https://duckduckgo.com/?q=service+health+incidents".to_string()),
        sources: vec![
            WebSource {
                source_id: "docs".to_string(),
                rank: Some(1),
                url: "https://learn.vendor-a.com/service-health/overview".to_string(),
                title: Some("Service health overview".to_string()),
                snippet: Some(
                    "Documentation overview for service health capabilities and guidance."
                        .to_string(),
                ),
                domain: Some("learn.vendor-a.com".to_string()),
            },
            WebSource {
                source_id: "status-a".to_string(),
                rank: Some(5),
                url: "https://status.vendor-a.com/incidents/123".to_string(),
                title: Some("API outage impacting U.S. region".to_string()),
                snippet: Some(
                    "Status page shows investigating with mitigation underway.".to_string(),
                ),
                domain: Some("status.vendor-a.com".to_string()),
            },
            WebSource {
                source_id: "status-b".to_string(),
                rank: Some(6),
                url: "https://status.vendor-b.com/incidents/456".to_string(),
                title: Some("Authentication degradation for North America".to_string()),
                snippet: Some("Users may see login errors; next update expected soon.".to_string()),
                domain: Some("status.vendor-b.com".to_string()),
            },
        ],
        documents: vec![],
    };

    let hints = candidate_source_hints_from_bundle(&bundle);
    assert_eq!(hints.len(), 3);
    assert_eq!(hints[0].url, "https://status.vendor-a.com/incidents/123");
    assert_eq!(hints[1].url, "https://status.vendor-b.com/incidents/456");
    assert_eq!(
        hints[2].url,
        "https://learn.vendor-a.com/service-health/overview"
    );
}

#[test]
fn web_pipeline_uses_source_hints_when_read_output_is_low_signal() {
    let mut pending = PendingSearchCompletion {
        query: "latest breaking news".to_string(),
        query_contract: "latest breaking news".to_string(),
        url: "https://news.google.com/rss/search?q=latest+breaking+news".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec!["https://news.google.com/rss/articles/abc".to_string()],
        candidate_source_hints: vec![crate::agentic::desktop::types::PendingSearchReadSummary {
            url: "https://news.google.com/rss/articles/abc".to_string(),
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
        "https://news.google.com/rss/articles/abc",
        Some("Google News"),
    );
    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    assert!(reply.contains("Major storm causes widespread flight delays"));
    assert!(reply.contains("Airports across the U.S."));
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
        "expected primary status citations to be preferred when sufficient inventory exists"
    );
    assert!(
        !reply.contains("https://ops-tracker.example.net/status"),
        "expected primary status citations to be preferred when sufficient inventory exists"
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
fn queue_maps_browser_click_element_from_browser_interact_target() {
    let request = build_request(
        ActionTarget::BrowserInteract,
        21,
        serde_json::json!({
            "id": "btn_submit"
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::BrowserClickElement { id } => {
            assert_eq!(id, "btn_submit");
        }
        other => panic!("expected BrowserClickElement, got {:?}", other),
    }
}

#[test]
fn queue_maps_net_fetch_target_to_typed_net_fetch_tool() {
    let request = build_request(
        ActionTarget::NetFetch,
        25,
        serde_json::json!({
            "url": "https://example.com",
            "max_chars": 123
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::NetFetch { url, max_chars } => {
            assert_eq!(url, "https://example.com");
            assert_eq!(max_chars, Some(123));
        }
        other => panic!("expected NetFetch, got {:?}", other),
    }
}

#[test]
fn queue_preserves_filesystem_search_from_fsread_target() {
    let request = build_fs_read_request(serde_json::json!({
        "path": "/tmp/workspace",
        "regex": "TODO",
        "file_pattern": "*.rs"
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsSearch {
            path,
            regex,
            file_pattern,
        } => {
            assert_eq!(path, "/tmp/workspace");
            assert_eq!(regex, "TODO");
            assert_eq!(file_pattern.as_deref(), Some("*.rs"));
        }
        other => panic!("expected FsSearch, got {:?}", other),
    }
}

#[test]
fn queue_infers_list_directory_for_existing_directory_path() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ioi_queue_fs_list_{}", unique));
    fs::create_dir_all(&dir).expect("temp directory should be created");
    let request = build_fs_read_request(serde_json::json!({
        "path": dir.to_string_lossy()
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsList { path } => {
            assert_eq!(path, dir.to_string_lossy());
        }
        other => panic!("expected FsList, got {:?}", other),
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn queue_uses_explicit_fsread_tool_name_override() {
    let request = build_fs_read_request(serde_json::json!({
        "path": "/tmp/not-a-real-directory",
        "__ioi_tool_name": "filesystem__list_directory"
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsList { path } => {
            assert_eq!(path, "/tmp/not-a-real-directory");
        }
        other => panic!("expected FsList, got {:?}", other),
    }
}

#[test]
fn queue_uses_explicit_fsread_tool_name_override_for_custom_alias_target() {
    let request = build_custom_request(
        "fs::read",
        8,
        serde_json::json!({
            "path": "/tmp/not-a-real-directory",
            "__ioi_tool_name": "filesystem__list_directory"
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsList { path } => {
            assert_eq!(path, "/tmp/not-a-real-directory");
        }
        other => panic!("expected FsList, got {:?}", other),
    }
}

#[test]
fn queue_rejects_incompatible_explicit_tool_name_for_target() {
    let request = build_fs_read_request(serde_json::json!({
        "path": "/tmp/demo.txt",
        "__ioi_tool_name": "filesystem__write_file"
    }));

    let err = queue_action_request_to_tool(&request)
        .expect_err("queue mapping should fail for incompatible explicit tool name");
    assert!(err.to_string().contains("incompatible"));
}

#[test]
fn queue_rejects_ambiguous_fswrite_transfer_without_explicit_tool_name() {
    let request = build_fs_write_request(serde_json::json!({
        "source_path": "/tmp/source.txt",
        "destination_path": "/tmp/destination.txt"
    }));

    let err = queue_action_request_to_tool(&request)
        .expect_err("queue mapping should fail for ambiguous transfer without explicit tool name");
    assert!(err.to_string().contains("__ioi_tool_name"));
    assert!(err.to_string().contains("filesystem__copy_path"));
}

#[test]
fn queue_rejects_ambiguous_fswrite_transfer_without_explicit_tool_name_for_custom_alias_target() {
    let request = build_custom_request(
        "fs::write",
        9,
        serde_json::json!({
            "source_path": "/tmp/source.txt",
            "destination_path": "/tmp/destination.txt"
        }),
    );

    let err = queue_action_request_to_tool(&request)
        .expect_err("queue mapping should fail for ambiguous transfer without explicit tool name");
    assert!(err.to_string().contains("__ioi_tool_name"));
    assert!(err.to_string().contains("filesystem__move_path"));
}

#[test]
fn queue_defaults_to_read_file_when_not_search_or_directory() {
    let request = build_fs_read_request(serde_json::json!({
        "path": "/tmp/not-a-real-file.txt"
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsRead { path } => {
            assert_eq!(path, "/tmp/not-a-real-file.txt");
        }
        other => panic!("expected FsRead, got {:?}", other),
    }
}

#[test]
fn queue_preserves_filesystem_patch_from_fswrite_target() {
    let request = build_fs_write_request(serde_json::json!({
        "path": "/tmp/demo.txt",
        "search": "alpha",
        "replace": "beta"
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsPatch {
            path,
            search,
            replace,
        } => {
            assert_eq!(path, "/tmp/demo.txt");
            assert_eq!(search, "alpha");
            assert_eq!(replace, "beta");
        }
        other => panic!("expected FsPatch, got {:?}", other),
    }
}

#[test]
fn queue_preserves_filesystem_delete_from_fswrite_target() {
    let request = build_fs_write_request(serde_json::json!({
        "path": "/tmp/demo.txt",
        "recursive": false,
        "ignore_missing": true
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsDelete {
            path,
            recursive,
            ignore_missing,
        } => {
            assert_eq!(path, "/tmp/demo.txt");
            assert!(!recursive);
            assert!(ignore_missing);
        }
        other => panic!("expected FsDelete, got {:?}", other),
    }
}

#[test]
fn queue_preserves_filesystem_delete_from_fswrite_target_when_recursive() {
    let request = build_fs_write_request(serde_json::json!({
        "path": "/tmp/demo-dir",
        "recursive": true,
        "ignore_missing": false
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsDelete {
            path,
            recursive,
            ignore_missing,
        } => {
            assert_eq!(path, "/tmp/demo-dir");
            assert!(recursive);
            assert!(!ignore_missing);
        }
        other => panic!("expected FsDelete, got {:?}", other),
    }
}

#[test]
fn queue_preserves_filesystem_create_directory_from_fswrite_target() {
    let request = build_fs_write_request(serde_json::json!({
        "path": "/tmp/new-dir",
        "recursive": true
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsCreateDirectory { path, recursive } => {
            assert_eq!(path, "/tmp/new-dir");
            assert!(recursive);
        }
        other => panic!("expected FsCreateDirectory, got {:?}", other),
    }
}

#[test]
fn queue_uses_explicit_fswrite_tool_name_override_for_copy_path() {
    let request = build_fs_write_request(serde_json::json!({
        "source_path": "/tmp/source.txt",
        "destination_path": "/tmp/destination.txt",
        "overwrite": true,
        "__ioi_tool_name": "filesystem__copy_path"
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsCopy {
            source_path,
            destination_path,
            overwrite,
        } => {
            assert_eq!(source_path, "/tmp/source.txt");
            assert_eq!(destination_path, "/tmp/destination.txt");
            assert!(overwrite);
        }
        other => panic!("expected FsCopy, got {:?}", other),
    }
}

#[test]
fn queue_uses_explicit_fswrite_tool_name_override_for_move_path() {
    let request = build_fs_write_request(serde_json::json!({
        "source_path": "/tmp/source.txt",
        "destination_path": "/tmp/destination.txt",
        "overwrite": false,
        "__ioi_tool_name": "filesystem__move_path"
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsMove {
            source_path,
            destination_path,
            overwrite,
        } => {
            assert_eq!(source_path, "/tmp/source.txt");
            assert_eq!(destination_path, "/tmp/destination.txt");
            assert!(!overwrite);
        }
        other => panic!("expected FsMove, got {:?}", other),
    }
}

#[test]
fn queue_uses_explicit_fswrite_tool_name_override_for_custom_alias_target() {
    let request = build_custom_request(
        "fs::write",
        17,
        serde_json::json!({
            "source_path": "/tmp/source.txt",
            "destination_path": "/tmp/destination.txt",
            "__ioi_tool_name": "filesystem__move_path"
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsMove {
            source_path,
            destination_path,
            overwrite,
        } => {
            assert_eq!(source_path, "/tmp/source.txt");
            assert_eq!(destination_path, "/tmp/destination.txt");
            assert!(!overwrite);
        }
        other => panic!("expected FsMove, got {:?}", other),
    }
}

#[test]
fn queue_preserves_launch_app_for_sys_exec_target_with_app_name() {
    let request = build_sys_exec_request(serde_json::json!({
        "app_name": "calculator"
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::OsLaunchApp { app_name } => {
            assert_eq!(app_name, "calculator");
        }
        other => panic!("expected OsLaunchApp, got {:?}", other),
    }
}

#[test]
fn queue_does_not_allow_metadata_override_for_sys_exec_target() {
    let request = build_sys_exec_request(serde_json::json!({
        "app_name": "calculator",
        "__ioi_tool_name": "os__launch_app"
    }));

    let err = queue_action_request_to_tool(&request).expect_err("expected schema error");
    assert!(err.to_string().contains("__ioi_tool_name"));
}

#[test]
fn queue_does_not_allow_metadata_to_override_non_fs_target_inference() {
    let request = build_sys_exec_request(serde_json::json!({
        "command": "echo",
        "args": ["ok"],
        "__ioi_tool_name": "os__launch_app"
    }));

    let err = queue_action_request_to_tool(&request).expect_err("expected schema error");
    assert!(err.to_string().contains("__ioi_tool_name"));
}

#[test]
fn queue_uses_explicit_sys_exec_tool_name_override_for_exec_session() {
    let request = build_sys_exec_request(serde_json::json!({
        "command": "echo",
        "args": ["ok"],
        "__ioi_tool_name": "sys__exec_session"
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::SysExecSession { command, args, .. } => {
            assert_eq!(command, "echo");
            assert_eq!(args, vec!["ok".to_string()]);
        }
        other => panic!("expected SysExecSession, got {:?}", other),
    }
}

#[test]
fn queue_maps_sys_exec_session_custom_alias() {
    let request = build_custom_request(
        "sys::exec_session",
        151,
        serde_json::json!({
            "command": "bash",
            "args": ["-lc", "echo ok"]
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::SysExecSession { command, args, .. } => {
            assert_eq!(command, "bash");
            assert_eq!(args, vec!["-lc".to_string(), "echo ok".to_string()]);
        }
        other => panic!("expected SysExecSession, got {:?}", other),
    }
}

#[test]
fn queue_maps_sys_exec_session_reset_custom_alias() {
    let request = build_custom_request("sys::exec_session_reset", 152, serde_json::json!({}));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::SysExecSessionReset {} => {}
        other => panic!("expected SysExecSessionReset, got {:?}", other),
    }
}

#[test]
fn queue_preserves_computer_left_click_payload_for_guiclick_target() {
    let request = build_request(
        ActionTarget::GuiClick,
        31,
        serde_json::json!({
            "action": "left_click",
            "coordinate": [120, 240]
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::Computer(ComputerAction::LeftClick { coordinate }) => {
            assert_eq!(coordinate, Some([120, 240]));
        }
        other => panic!("expected Computer LeftClick, got {:?}", other),
    }
}

#[test]
fn queue_uses_explicit_guiclick_tool_name_override_for_click_element() {
    let request = build_request(
        ActionTarget::GuiClick,
        32,
        serde_json::json!({
            "id": "btn_submit",
            "__ioi_tool_name": "gui__click_element"
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::GuiClickElement { id } => {
            assert_eq!(id, "btn_submit");
        }
        other => panic!("expected GuiClickElement, got {:?}", other),
    }
}

#[test]
fn queue_maps_guimousemove_target_to_computer_tool() {
    let request = build_request(
        ActionTarget::GuiMouseMove,
        33,
        serde_json::json!({
            "coordinate": [55, 89]
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::Computer(ComputerAction::MouseMove { coordinate }) => {
            assert_eq!(coordinate, [55, 89]);
        }
        other => panic!("expected Computer MouseMove, got {:?}", other),
    }
}

#[test]
fn queue_maps_guiscreenshot_target_to_computer_tool() {
    let request = build_request(ActionTarget::GuiScreenshot, 35, serde_json::json!({}));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::Computer(ComputerAction::Screenshot) => {}
        other => panic!("expected Computer Screenshot, got {:?}", other),
    }
}

#[test]
fn queue_maps_custom_computer_cursor_alias_to_computer_tool() {
    let request = build_custom_request(
        "computer::cursor",
        37,
        serde_json::json!({
            "action": "cursor_position"
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::Computer(ComputerAction::CursorPosition) => {}
        other => panic!("expected Computer CursorPosition, got {:?}", other),
    }
}
