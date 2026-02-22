use super::support::{
    append_pending_web_success_fallback, append_pending_web_success_from_bundle,
    candidate_source_hints_from_bundle, candidate_urls_from_bundle,
    constraint_grounded_probe_query_with_hints_and_locality_hint, constraint_grounded_search_limit,
    constraint_grounded_search_query, constraint_grounded_search_query_with_hints,
    constraint_grounded_search_query_with_hints_and_locality_hint, fallback_search_summary,
    merge_pending_search_completion, next_pending_web_candidate,
    pre_read_candidate_plan_from_bundle, pre_read_candidate_plan_from_bundle_with_locality_hint,
    queue_action_request_to_tool, select_web_pipeline_query_contract, summarize_search_results,
    synthesize_web_pipeline_reply, web_pipeline_can_queue_initial_read_latency_aware,
    web_pipeline_can_queue_probe_search_latency_aware, web_pipeline_completion_reason,
    web_pipeline_latency_pressure_label, web_pipeline_required_probe_budget_ms,
    web_pipeline_required_read_budget_ms, WebPipelineCompletionReason,
};
use crate::agentic::desktop::types::{PendingSearchCompletion, PendingSearchReadSummary};
use ioi_types::app::agentic::{AgentTool, ComputerAction};
use ioi_types::app::agentic::{WebDocument, WebEvidenceBundle, WebSource};
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
fn web_pipeline_pre_read_prunes_unresolvable_candidates_when_resolvable_inventory_exists() {
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:ddg".to_string(),
        query: Some("weather right now anderson sc".to_string()),
        url: Some("https://duckduckgo.com/?q=weather+right+now+anderson+sc".to_string()),
        sources: vec![
            WebSource {
                source_id: "tenday".to_string(),
                rank: Some(1),
                url: "https://weather.com/weather/tenday/l/Anderson%20SC".to_string(),
                title: Some("Anderson, SC 10-Day Weather Forecast".to_string()),
                snippet: Some(
                    "Be prepared with the most accurate 10-day forecast for Anderson.".to_string(),
                ),
                domain: Some("weather.com".to_string()),
            },
            WebSource {
                source_id: "current-a".to_string(),
                rank: Some(2),
                url: "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327"
                    .to_string(),
                title: Some("Anderson, SC Current Weather".to_string()),
                snippet: Some(
                    "Current conditions: temperature near 61 F, wind 4 mph, humidity 48%."
                        .to_string(),
                ),
                domain: Some("accuweather.com".to_string()),
            },
            WebSource {
                source_id: "current-b".to_string(),
                rank: Some(3),
                url: "https://forecast.weather.gov/MapClick.php?lat=34.5&lon=-82.65".to_string(),
                title: Some("Anderson SC Current Conditions".to_string()),
                snippet: Some(
                    "Observed at 2:00 AM: temperature 60 F, humidity 50%, calm wind.".to_string(),
                ),
                domain: Some("weather.gov".to_string()),
            },
        ],
        documents: vec![],
    };

    let plan = pre_read_candidate_plan_from_bundle("what's the weather right now", 2, &bundle);
    assert!(
        plan.total_candidates >= 2,
        "expected constraint-aware acquisition to keep at least the source floor, got {}",
        plan.total_candidates
    );
    assert!(
        plan.total_candidates <= 3,
        "constraint-aware acquisition should not expand candidate inventory: {:?}",
        plan
    );
    assert_eq!(plan.candidate_urls.len(), 2);
    assert!(
        plan.candidate_urls
            .iter()
            .all(|url| !url.contains("/tenday/")),
        "expected 10-day forecast candidate to be pruned: {:?}",
        plan.candidate_urls
    );
    assert!(!plan.requires_constraint_search_probe);
}

#[test]
fn web_pipeline_pre_read_prunes_irrelevant_candidates_when_compatible_inventory_exists() {
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:bing:http".to_string(),
        query: Some("current weather in anderson sc".to_string()),
        url: Some("https://www.bing.com/search?q=current+weather+anderson+sc".to_string()),
        sources: vec![
            WebSource {
                source_id: "irrelevant-1".to_string(),
                rank: Some(1),
                url: "https://forums.att.com/conversations/account-usage/compesation/5df024adbad5f2f60686b40b".to_string(),
                title: Some("AT&T Digital Resources & Answers - Community Forums".to_string()),
                snippet: Some("Apr 6, 2019 · I called customer service last night and paid my bill."
                    .to_string()),
                domain: Some("forums.att.com".to_string()),
            },
            WebSource {
                source_id: "weather-a".to_string(),
                rank: Some(2),
                url: "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327"
                    .to_string(),
                title: Some("Anderson, SC Current Weather".to_string()),
                snippet: Some(
                    "Current conditions: temperature near 61 F, wind 4 mph, humidity 48%."
                        .to_string(),
                ),
                domain: Some("accuweather.com".to_string()),
            },
            WebSource {
                source_id: "weather-b".to_string(),
                rank: Some(3),
                url: "https://forecast.weather.gov/MapClick.php?lat=34.5&lon=-82.65".to_string(),
                title: Some("Anderson SC Current Conditions".to_string()),
                snippet: Some(
                    "Observed at 2:00 AM: temperature 60 F, humidity 50%, calm wind.".to_string(),
                ),
                domain: Some("weather.gov".to_string()),
            },
        ],
        documents: vec![],
    };

    let plan = pre_read_candidate_plan_from_bundle(
        "what's the weather right now in anderson sc",
        2,
        &bundle,
    );
    assert!(
        plan.total_candidates <= 3,
        "constraint-aware acquisition should not expand candidate inventory: {:?}",
        plan
    );
    assert!(
        plan.candidate_urls
            .iter()
            .all(|url| !url.contains("forums.att.com")),
        "expected incompatible candidate to be pruned: {:?}",
        plan.candidate_urls
    );
    assert_eq!(plan.candidate_urls.len(), 2);
}

#[test]
fn web_pipeline_pre_read_acquisition_filters_incompatible_candidates_for_single_anchor_queries() {
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:bing:http".to_string(),
        query: Some("weather right now".to_string()),
        url: Some("https://www.bing.com/search?q=weather+right+now".to_string()),
        sources: vec![
            WebSource {
                source_id: "irrelevant".to_string(),
                rank: Some(1),
                url: "https://forums.att.com/conversations/account-usage/compesation/5df024adbad5f2f60686b40b".to_string(),
                title: Some("AT&T Digital Resources & Answers - Community Forums".to_string()),
                snippet: Some("Apr 6, 2019 · I called customer service last night and paid my bill."
                    .to_string()),
                domain: Some("forums.att.com".to_string()),
            },
            WebSource {
                source_id: "weather-a".to_string(),
                rank: Some(2),
                url: "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327"
                    .to_string(),
                title: Some("Anderson, SC Current Weather".to_string()),
                snippet: Some(
                    "Current conditions: temperature near 61 F, wind 4 mph, humidity 48%."
                        .to_string(),
                ),
                domain: Some("accuweather.com".to_string()),
            },
            WebSource {
                source_id: "weather-b".to_string(),
                rank: Some(3),
                url: "https://forecast.weather.gov/MapClick.php?lat=34.5&lon=-82.65".to_string(),
                title: Some("Anderson SC Current Conditions".to_string()),
                snippet: Some(
                    "Observed at 2:00 AM: temperature 60 F, humidity 50%, calm wind.".to_string(),
                ),
                domain: Some("weather.gov".to_string()),
            },
        ],
        documents: vec![],
    };

    let plan = pre_read_candidate_plan_from_bundle("what's the weather right now", 2, &bundle);
    assert_eq!(plan.total_candidates, 2, "plan={:?}", plan);
    assert!(
        plan.candidate_urls
            .iter()
            .all(|url| !url.contains("forums.att.com")),
        "expected incompatible candidate to be filtered during acquisition: {:?}",
        plan.candidate_urls
    );
    assert!(!plan.requires_constraint_search_probe);
}

#[test]
fn web_pipeline_pre_read_prunes_search_hub_urls_for_grounded_time_sensitive_queries() {
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:bing:http".to_string(),
        query: Some("what's the weather right now".to_string()),
        url: Some("https://www.bing.com/search?q=what%27s+the+weather+right+now".to_string()),
        sources: vec![
            WebSource {
                source_id: "serp".to_string(),
                rank: Some(1),
                url: "https://www.bing.com/search?q=what%27s+the+weather+right+now".to_string(),
                title: Some("Bing".to_string()),
                snippet: Some("Search results for weather right now".to_string()),
                domain: Some("bing.com".to_string()),
            },
            WebSource {
                source_id: "wx-a".to_string(),
                rank: Some(2),
                url: "https://www.accuweather.com/en/us/anderson/29624/current-weather/330677"
                    .to_string(),
                title: Some("Anderson, SC Current Weather".to_string()),
                snippet: Some(
                    "Current conditions: 62 F, feels like 64 F, wind 4 mph, humidity 42%."
                        .to_string(),
                ),
                domain: Some("accuweather.com".to_string()),
            },
            WebSource {
                source_id: "wx-b".to_string(),
                rank: Some(3),
                url: "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC".to_string(),
                title: Some("Current Conditions for Anderson, SC".to_string()),
                snippet: Some(
                    "Observed at 02:00 AM: temperature 60 F, humidity 50%, calm wind.".to_string(),
                ),
                domain: Some("weather.gov".to_string()),
            },
        ],
        documents: vec![],
    };

    let plan = pre_read_candidate_plan_from_bundle("what's the weather right now", 2, &bundle);
    assert!(
        plan.candidate_urls
            .iter()
            .all(|url| !url.contains("bing.com/search")),
        "search hub url should be pruned from evidence candidates: {:?}",
        plan.candidate_urls
    );
    assert!(plan
        .candidate_urls
        .iter()
        .any(|url| url.contains("accuweather.com")));
}

#[test]
fn web_pipeline_pre_read_requires_probe_when_time_sensitive_candidates_are_incompatible() {
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:bing:http".to_string(),
        query: Some("current weather in anderson sc".to_string()),
        url: Some("https://www.bing.com/search?q=current+weather+anderson+sc".to_string()),
        sources: vec![
            WebSource {
                source_id: "irrelevant-1".to_string(),
                rank: Some(1),
                url: "https://forums.att.com/conversations/account-usage/compesation/5df024adbad5f2f60686b40b".to_string(),
                title: Some("AT&T Digital Resources & Answers - Community Forums".to_string()),
                snippet: Some("Apr 6, 2019 · I called customer service last night and paid my bill."
                    .to_string()),
                domain: Some("forums.att.com".to_string()),
            },
            WebSource {
                source_id: "irrelevant-2".to_string(),
                rank: Some(2),
                url: "https://forums.att.com/conversations/apple/why-do-you-send-electronic-notifications-when-specifically-asked-not-to/5df00f54bad5f2f606253c6e".to_string(),
                title: Some("AT&T Community Forums".to_string()),
                snippet: Some("Dec 16, 2018 · Bought iPhone watch for spouse as Christmas present."
                    .to_string()),
                domain: Some("forums.att.com".to_string()),
            },
        ],
        documents: vec![],
    };

    let plan = pre_read_candidate_plan_from_bundle(
        "what's the weather right now in anderson sc",
        2,
        &bundle,
    );
    assert!(plan.requires_constraint_search_probe);
    assert_eq!(
        plan.candidate_urls.len(),
        0,
        "when strict compatibility prunes everything, pipeline should force a follow-up probe instead of admitting zero-compatibility exploratory reads"
    );
}

#[test]
fn web_pipeline_pre_read_requires_probe_when_resolvable_inventory_below_source_floor() {
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:bing:http".to_string(),
        query: Some("current weather in anderson sc".to_string()),
        url: Some("https://www.bing.com/search?q=current+weather+anderson+sc".to_string()),
        sources: vec![
            WebSource {
                source_id: "weather-a".to_string(),
                rank: Some(1),
                url: "https://www.weather-forecast.com/locations/Anderson/forecasts/latest"
                    .to_string(),
                title: Some("Anderson, South Carolina Weather Forecast".to_string()),
                snippet: Some(
                    "Providing a local hourly weather forecast with wind, humidity and temperature."
                        .to_string(),
                ),
                domain: Some("weather-forecast.com".to_string()),
            },
            WebSource {
                source_id: "weather-b".to_string(),
                rank: Some(2),
                url: "https://www.theweathernetwork.com/en/city/us/south-carolina/anderson/hourly"
                    .to_string(),
                title: Some("Anderson, SC Hourly Forecast - The Weather Network".to_string()),
                snippet: Some(
                    "Get Anderson current weather report with temperature, feels like, wind, humidity and pressure."
                        .to_string(),
                ),
                domain: Some("theweathernetwork.com".to_string()),
            },
        ],
        documents: vec![],
    };

    let plan = pre_read_candidate_plan_from_bundle(
        "what's the weather right now in anderson sc",
        2,
        &bundle,
    );
    assert_eq!(plan.candidate_urls.len(), 2, "plan={:?}", plan);
    assert!(
        plan.candidate_urls[0].contains("theweathernetwork.com"),
        "expected current-observation surface candidate to lead ranking: {:?}",
        plan.candidate_urls
    );
    assert!(
        plan.candidate_urls
            .iter()
            .any(|url| url.contains("weather-forecast.com")),
        "expected floor top-up to keep an additional non-hub weather candidate: {:?}",
        plan.candidate_urls
    );
    assert!(
        plan.requires_constraint_search_probe,
        "expected typed-facet probe when compatible candidates are not resolvable: {:?}",
        plan
    );
}

#[test]
fn web_pipeline_pre_read_does_not_learn_facets_from_incompatible_candidates() {
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:bing:http".to_string(),
        query: Some("current weather in anderson sc".to_string()),
        url: Some("https://www.bing.com/search?q=current+weather+anderson+sc".to_string()),
        sources: vec![
            WebSource {
                source_id: "shopping".to_string(),
                rank: Some(1),
                url: "https://www.bestbuy.com/trade-in".to_string(),
                title: Some("Trade-In - Best Buy".to_string()),
                snippet: Some(
                    "Save $50 or more on your next Windows 11 PC with in-store trade-in."
                        .to_string(),
                ),
                domain: Some("bestbuy.com".to_string()),
            },
            WebSource {
                source_id: "weather-a".to_string(),
                rank: Some(2),
                url: "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327"
                    .to_string(),
                title: Some("Anderson, SC Current Weather".to_string()),
                snippet: Some(
                    "Current conditions: temperature near 61 F, wind 4 mph, humidity 48%."
                        .to_string(),
                ),
                domain: Some("accuweather.com".to_string()),
            },
            WebSource {
                source_id: "weather-b".to_string(),
                rank: Some(3),
                url: "https://forecast.weather.gov/MapClick.php?lat=34.5&lon=-82.65".to_string(),
                title: Some("Anderson SC Current Conditions".to_string()),
                snippet: Some(
                    "Observed at 2:00 AM: temperature 60 F, humidity 50%, calm wind.".to_string(),
                ),
                domain: Some("weather.gov".to_string()),
            },
        ],
        documents: vec![],
    };

    let plan = pre_read_candidate_plan_from_bundle(
        "what's the weather right now in anderson sc",
        2,
        &bundle,
    );
    assert_eq!(plan.candidate_urls.len(), 2, "plan={:?}", plan);
    assert!(
        plan.candidate_urls
            .iter()
            .all(|url| !url.contains("bestbuy.com")),
        "expected incompatible shopping candidate to be excluded: {:?}",
        plan.candidate_urls
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_appends_typed_facets() {
    let query =
        constraint_grounded_search_query("what is the current price of bitcoin right now", 2);
    let normalized = query.to_ascii_lowercase();
    assert!(normalized.contains("latest measured data"));
    assert!(normalized.contains("as-of observation"));
    assert!(normalized.contains("price values"));
    assert!(normalized.contains("2 independent sources"));
    assert!(normalized.contains("\"bitcoin price\""));
}

#[test]
fn web_pipeline_constraint_grounded_search_query_with_hints_adds_anchor_phrase() {
    let hints = vec![
        PendingSearchReadSummary {
            url: "https://weather.com/weather/today/l/Anderson+SC".to_string(),
            title: Some("Current weather Anderson South Carolina".to_string()),
            excerpt:
                "Current conditions in Anderson South Carolina: temperature 62 F, humidity 44%."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC".to_string(),
            title: Some("Anderson South Carolina current conditions".to_string()),
            excerpt: "Observed weather for Anderson South Carolina: temperature 60 F, wind 3 mph."
                .to_string(),
        },
    ];

    let query =
        constraint_grounded_search_query_with_hints("what's the weather right now", 2, &hints);
    let normalized = query.to_ascii_lowercase();
    assert!(normalized.contains("anderson"));
    assert!(normalized.contains("\""));
}

#[test]
fn web_pipeline_constraint_grounded_search_query_anchor_phrase_ignores_output_contract_terms() {
    let hints = vec![
        PendingSearchReadSummary {
            url: "https://weather.com/weather/today/l/Anderson+SC".to_string(),
            title: Some("Current weather Anderson South Carolina".to_string()),
            excerpt:
                "Current conditions in Anderson South Carolina: temperature 62 F, humidity 44%."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC".to_string(),
            title: Some("Anderson South Carolina current conditions".to_string()),
            excerpt: "Observed weather for Anderson South Carolina: temperature 60 F, wind 3 mph."
                .to_string(),
        },
    ];

    let query = constraint_grounded_search_query_with_hints(
        "Current weather in Anderson, SC right now with sources and UTC timestamp.",
        2,
        &hints,
    );
    let normalized = query.to_ascii_lowercase();
    let utc_phrase_count = normalized.match_indices("utc timestamp").count();
    assert_eq!(
        utc_phrase_count, 1,
        "expected deduped output-contract term in query: {query}"
    );
    assert!(
        !normalized.contains("\"anderson sources"),
        "anchor phrase should be semantic-only: {query}"
    );
    assert!(
        !normalized.contains("\"sources utc"),
        "anchor phrase should be semantic-only: {query}"
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_projects_semantic_target_when_provenance_directives_present(
) {
    let query = constraint_grounded_search_query(
        "Current weather in Anderson, SC right now with sources and UTC timestamp.",
        2,
    );
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.starts_with("weather in anderson"),
        "expected semantic retrieval projection: {query}"
    );
    assert!(
        !normalized.starts_with("current weather in anderson, sc right now with sources"),
        "retrieval query should not be dominated by output-contract directives: {query}"
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_projects_semantic_target_for_locality_query() {
    let query =
        constraint_grounded_search_query("What's the weather right now in Anderson, SC?", 2);
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.starts_with("weather in anderson"),
        "expected locality-scoped semantic projection: {query}"
    );
    assert!(
        !normalized.starts_with("what's the weather right now"),
        "retrieval query should avoid conversational framing: {query}"
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_bootstrap_keeps_scoped_time_sensitive_query_concise(
) {
    let query = constraint_grounded_search_query(
        "Current weather in Anderson, SC right now with sources and UTC timestamp.",
        2,
    );
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.starts_with("weather in anderson"),
        "query={}",
        query
    );
    assert!(
        !normalized.contains("latest measured data"),
        "query={}",
        query
    );
    assert!(
        !normalized.contains("independent sources"),
        "query={}",
        query
    );
    assert!(!normalized.contains("utc timestamp"), "query={}", query);
}

#[test]
fn web_pipeline_constraint_grounded_search_query_infers_locality_scope_from_candidate_hints() {
    let hints = vec![PendingSearchReadSummary {
        url: "https://weather.com/weather/today/l/Anderson+SC".to_string(),
        title: Some("Anderson, SC current weather".to_string()),
        excerpt:
            "Current conditions in Anderson, South Carolina: temperature 62 F, humidity 42%, wind 4 mph."
                .to_string(),
    }];
    let query = constraint_grounded_search_query_with_hints_and_locality_hint(
        "what's the weather right now",
        2,
        &hints,
        None,
    );
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.contains("anderson"),
        "expected inferred locality token in grounded query: {}",
        query
    );
    assert!(
        normalized.contains("sc"),
        "expected inferred locality token in grounded query: {}",
        query
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_does_not_infer_scope_from_rss_proxy_tokens() {
    let hints = vec![PendingSearchReadSummary {
        url: "https://news.google.com/rss/articles/CBMimAFBVV95cUxNcVZDZVYtQXVXRFlLQmdCVnVuVlZjMlNZcTNGWm9WN0ZPb0pvMUpBMllJVFo0V3IxZ21RNUtQZTVkc3Joc0c2U2V6ZlA0OHEwdTlHNm8zanp5QmlUUERSVzBQTXJUMXlEVXctZkhUT085SVBvWmVjRWZPNFE4NFZ3LUpOemMyekVMVlRXejl6cHdjYUM2R3cxcw?oc=5".to_string(),
        title: None,
        excerpt: String::new(),
    }];

    let query =
        constraint_grounded_search_query_with_hints("what's the weather right now", 2, &hints);
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.starts_with("weather current conditions"),
        "scope should stay unresolved when hints are rss proxy links: {}",
        query
    );
    assert!(
        !normalized.contains("rss") && !normalized.contains("articles"),
        "rss proxy path tokens should not leak into inferred scope: {}",
        query
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_avoids_scope_inference_from_non_resolvable_hints()
{
    let hints = vec![PendingSearchReadSummary {
        url: "https://forums.x-plane.org/forums/topic/337131-weather-radar-not-working-for-me/"
            .to_string(),
        title: Some("Weather radar not working for me - X-Plane.Org Forum".to_string()),
        excerpt: "Despite updates to aircraft and sim builds, weather radar does not appear on ND."
            .to_string(),
    }];

    let query =
        constraint_grounded_search_query_with_hints("what's the weather right now", 2, &hints);
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.starts_with("weather current conditions"),
        "scope should stay unresolved for non-resolvable hints: {}",
        query
    );
    assert!(
        !normalized.contains("forum") && !normalized.contains("plane"),
        "non-resolvable hint tokens should not leak into query scope: {}",
        query
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_bootstrap_applies_trusted_locality_hint_without_hints(
) {
    let query = constraint_grounded_search_query_with_hints_and_locality_hint(
        "what's the weather right now",
        2,
        &[],
        Some("Anderson, SC"),
    );
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.starts_with("weather in anderson"),
        "query={}",
        query
    );
    assert!(
        normalized.contains("sc"),
        "query should preserve trusted locality tokens: {}",
        query
    );
    assert!(
        !normalized.contains("\"near me\""),
        "query should avoid locality placeholder terms when scope is resolved: {}",
        query
    );
    assert!(
        !normalized.contains("latest measured data"),
        "query={}",
        query
    );
    assert!(!normalized.contains("as-of observation"), "query={}", query);
}

#[test]
fn web_pipeline_constraint_grounded_search_query_prefers_explicit_locality_over_trusted_hint() {
    let query = constraint_grounded_search_query_with_hints_and_locality_hint(
        "what's the weather right now in Boise, ID",
        2,
        &[],
        Some("Anderson, SC"),
    );
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.contains("boise"),
        "query should preserve explicit query locality: {}",
        query
    );
    assert!(
        normalized.contains("id"),
        "query should preserve explicit query locality tokens: {}",
        query
    );
    assert!(
        !normalized.contains("anderson"),
        "trusted locality hint must not override explicit query locality: {}",
        query
    );
}

#[test]
fn web_pipeline_select_query_contract_prefers_scope_grounded_retrieval_query() {
    let selected = select_web_pipeline_query_contract(
        "what's the weather right now",
        "what's the weather right now in Anderson, SC",
    );
    let normalized = selected.to_ascii_lowercase();
    assert!(normalized.starts_with("what's the weather right now in"));
    assert!(normalized.contains("anderson"));
    assert!(normalized.contains("sc"));
}

#[test]
fn web_pipeline_select_query_contract_preserves_goal_when_it_has_scope_and_retrieval_does_not() {
    let selected = select_web_pipeline_query_contract(
        "what's the weather right now in Anderson, SC",
        "what's the weather right now",
    );
    assert_eq!(selected, "what's the weather right now in Anderson, SC");
}

#[test]
fn web_pipeline_select_query_contract_drops_probe_term_inflation_from_retrieval_query() {
    let selected = select_web_pipeline_query_contract(
        "what's the weather right now",
        "what's the weather right now in Anderson, SC \"anderson weather\" \"anderson weather\" \"anderson weather\"",
    );
    let normalized = selected.to_ascii_lowercase();
    assert!(normalized.starts_with("what's the weather right now in"));
    assert!(normalized.contains("anderson"));
    assert!(normalized.contains("sc"));
    assert!(!normalized.contains("\""));
    assert!(
        !normalized.contains("anderson weather"),
        "scope merge should not include probe-term inflation: {}",
        selected
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_avoids_locality_placeholder_when_scope_missing() {
    let query = constraint_grounded_search_query("what's the weather right now", 2);
    let normalized = query.to_ascii_lowercase();
    assert!(normalized.starts_with("weather current conditions"));
    assert!(!normalized.contains("\"near me\""), "query={}", query);
}

#[test]
fn web_pipeline_constraint_grounded_search_query_avoids_native_anchor_phrase_for_explicit_locality()
{
    let query =
        constraint_grounded_search_query("What's the weather right now in Anderson, SC?", 2);
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.starts_with("weather in anderson"),
        "query={}",
        query
    );
    assert!(
        !normalized.contains("\"anderson weather\""),
        "query should avoid quoted native-anchor inflation for explicit-locality lookups: {}",
        query
    );
}

#[test]
fn web_pipeline_constraint_grounded_probe_query_escalates_when_prior_equals_grounded() {
    let query = "what's the weather right now";
    let hints = vec![PendingSearchReadSummary {
        url: "https://www.weather-atlas.com/en/wyoming-usa/cheyenne".to_string(),
        title: Some("Weather today - Cheyenne, WY".to_string()),
        excerpt:
            "Current weather in Cheyenne, Wyoming: temperature 30 F, humidity 68%, wind 11 mph."
                .to_string(),
    }];
    let grounded = constraint_grounded_search_query_with_hints_and_locality_hint(
        query,
        2,
        &hints,
        Some("Anderson, SC"),
    );
    let probe = constraint_grounded_probe_query_with_hints_and_locality_hint(
        query,
        2,
        &hints,
        &grounded,
        Some("Anderson, SC"),
    )
    .expect("probe query should be generated");
    assert!(
        !probe.eq_ignore_ascii_case(&grounded),
        "probe should differ from prior grounded query"
    );
    let normalized = probe.to_ascii_lowercase();
    assert!(
        normalized.contains("cheyenne") || normalized.contains("wyoming"),
        "expected locality-aware escalation terms in probe query: {}",
        probe
    );
}

#[test]
fn web_pipeline_constraint_grounded_probe_query_adds_metric_probe_terms_when_locality_query_stalls()
{
    let query = "what's the weather right now";
    let grounded = constraint_grounded_search_query_with_hints_and_locality_hint(
        query,
        2,
        &[],
        Some("New York"),
    );
    let probe = constraint_grounded_probe_query_with_hints_and_locality_hint(
        query,
        2,
        &[],
        &grounded,
        Some("New York"),
    )
    .expect("probe query should be generated for stalled locality-sensitive query");
    let normalized = probe.to_ascii_lowercase();
    assert!(
        normalized.contains("temperature")
            && normalized.contains("humidity")
            && normalized.contains("wind"),
        "expected metric-oriented fallback probe terms: {}",
        probe
    );
    assert!(
        !probe.eq_ignore_ascii_case(&grounded),
        "fallback probe query should differ from grounded query"
    );
}

#[test]
fn web_pipeline_constraint_grounded_probe_query_excludes_low_signal_hosts_when_metric_gap_persists()
{
    let query = "what's the weather right now in anderson, sc";
    let hints = vec![
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
            excerpt:
                "Anderson, SC Weather Forecast, with current conditions and next 3 days."
                    .to_string(),
        },
    ];
    let grounded = constraint_grounded_search_query_with_hints(query, 2, &hints);
    let probe = constraint_grounded_probe_query_with_hints_and_locality_hint(
        query,
        2,
        &hints,
        &grounded,
        None,
    )
    .expect("probe query should be generated when metric grounding remains weak");
    let normalized = probe.to_ascii_lowercase();
    assert!(
        normalized.contains("-site:www.accuweather.com")
            || normalized.contains("-site:www.weather-forecast.com"),
        "expected probe to exclude at least one previously low-signal host: {}",
        probe
    );
    assert!(
        !probe.eq_ignore_ascii_case(&grounded),
        "host-exclusion probe should differ from grounded query"
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_preserves_non_locality_queries() {
    let query = constraint_grounded_search_query("summarize this local file", 2);
    assert_eq!(query, "summarize this local file");
}

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
                url: "https://weather-forecast.com/locations/Anderson/forecasts/latest"
                    .to_string(),
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

    base.attempted_urls.push(
        "https://www.bing.com/search?q=anderson+sc+weather+current+conditions".to_string(),
    );
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
                url: "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC"
                    .to_string(),
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
        reply.contains("Available observed details from cited source text:"),
        "expected partial-metric summary line, got:\n{}",
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
fn web_pipeline_single_snapshot_citation_fallback_prefers_evidence_urls_over_query_hubs_when_available()
{
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
