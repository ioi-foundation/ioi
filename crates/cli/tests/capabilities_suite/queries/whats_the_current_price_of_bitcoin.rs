use ioi_types::app::agentic::IntentScopeProfile;
use serde::Serialize;

use super::super::types::{
    contains_any, has_tool_with_token, truncate_chars, LocalCheck, LocalJudgeResult, QueryCase,
    RunObservation,
};

#[derive(Debug, Clone, Serialize)]
struct EnvironmentEvidenceReceipt {
    key: &'static str,
    observed_value: String,
    probe_source: &'static str,
    timestamp_ms: u64,
    satisfied: bool,
}

pub fn case() -> QueryCase {
    QueryCase {
        id: "whats_the_current_price_of_bitcoin",
        query: "What's the current price of Bitcoin?",
        success_definition: "Return the current Bitcoin price with runtime-grounded web retrieval evidence, independent citations, and no CEC contract failures.",
        seeded_intent_id: "web.research",
        intent_scope: IntentScopeProfile::WebResearch,
        seed_resolved_intent: true,
        expected_pass: true,
        sla_seconds: 90,
        max_steps: 18,
        min_local_score: 1.0,
        allow_retry_blocked_completion_with_local_evidence: false,
        local_sniff: evaluate,
    }
}

fn evaluate(obs: &RunObservation) -> LocalJudgeResult {
    let reply_lower = obs.final_reply.to_ascii_lowercase();

    let web_search_path_seen = has_tool_with_token(&obs.action_tools, "web__search")
        || has_tool_with_token(&obs.routing_tools, "web__search")
        || has_tool_with_token(&obs.workload_tools, "web__search");
    let web_read_path_seen = has_tool_with_token(&obs.action_tools, "web__read")
        || has_tool_with_token(&obs.routing_tools, "web__read")
        || has_tool_with_token(&obs.workload_tools, "web__read");
    let direct_fetch_path_seen = has_tool_with_token(&obs.action_tools, "net__fetch")
        || has_tool_with_token(&obs.routing_tools, "net__fetch")
        || has_tool_with_token(&obs.workload_tools, "net__fetch");
    let web_retrieval_path_present =
        web_search_path_seen && web_read_path_seen && !direct_fetch_path_seen;

    let citation_urls = extract_citation_urls(&obs.final_reply);
    let unique_citation_urls = citation_urls
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    let citation_domains = extract_domains(&unique_citation_urls);
    let unique_domain_count = citation_domains
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let search_hub_or_wrapper_citations = unique_citation_urls
        .iter()
        .filter(|url| is_search_hub_or_wrapper_url(url))
        .count();
    let citation_timestamps = extract_citation_timestamps(&obs.final_reply);
    let citation_iso_utc_count = citation_timestamps
        .iter()
        .filter(|value| looks_like_iso_utc_timestamp(value))
        .count();

    let has_bitcoin_anchor = contains_any(&reply_lower, &["bitcoin", "btc"]);
    let price_line_count = bitcoin_price_line_count(&obs.final_reply);
    let objective_specific_price_signal_present = has_bitcoin_anchor && price_line_count > 0;

    let web_min_sources = max_usize_verification_value(obs, "web_min_sources=");
    let web_sources_success = max_usize_verification_value(obs, "web_sources_success=");
    let web_source_floor_present = match (web_min_sources, web_sources_success) {
        (Some(min_sources), Some(success_sources)) => {
            min_sources >= 2 && success_sources >= min_sources
        }
        _ => false,
    };

    let run_timestamp_present = reply_lower.contains("run timestamp (utc):");
    let recency_heading_present =
        reply_lower.contains("right now") || reply_lower.contains("as of");
    let temporal_grounding_evidence_present =
        run_timestamp_present && (recency_heading_present || citation_iso_utc_count > 0);

    let source_quality_and_independence_present = unique_citation_urls.len() >= 2
        && unique_domain_count >= 2
        && search_hub_or_wrapper_citations == 0;
    let any_contract_failure_marker = observation_has_contract_failure_marker(obs);
    let completion_evidence_present = obs.completed && !obs.failed && !obs.final_reply.is_empty();

    let environment_receipts = build_environment_receipts(
        obs,
        price_line_count,
        has_bitcoin_anchor,
        web_min_sources,
        web_sources_success,
        unique_citation_urls.len(),
        unique_domain_count,
        search_hub_or_wrapper_citations,
        citation_iso_utc_count,
        run_timestamp_present,
        web_retrieval_path_present,
    );
    let environment_receipts_satisfied =
        environment_receipts.iter().all(|receipt| receipt.satisfied);

    let independent_channel_count = [
        objective_specific_price_signal_present,
        web_retrieval_path_present,
        web_source_floor_present,
        source_quality_and_independence_present,
        temporal_grounding_evidence_present,
    ]
    .into_iter()
    .filter(|flag| *flag)
    .count();
    let independent_runtime_evidence_channels_present =
        objective_specific_price_signal_present && independent_channel_count >= 4;

    let checks = vec![
        LocalCheck::new(
            "completion_evidence_present",
            completion_evidence_present,
            format!(
                "status={} completed={} failed={} reply_len={}",
                obs.final_status,
                obs.completed,
                obs.failed,
                obs.final_reply.chars().count()
            ),
        ),
        LocalCheck::new(
            "objective_specific_bitcoin_price_evidence_present",
            objective_specific_price_signal_present,
            format!(
                "price_line_count={} has_bitcoin_anchor={} reply_excerpt={}",
                price_line_count,
                has_bitcoin_anchor,
                truncate_chars(&obs.final_reply, 180)
            ),
        ),
        LocalCheck::new(
            "tool_and_route_path_evidence_present",
            web_retrieval_path_present,
            format!(
                "web_search_path_seen={} web_read_path_seen={} direct_fetch_path_seen={} action_tools={:?} routing_tools={:?} workload_tools={:?}",
                web_search_path_seen,
                web_read_path_seen,
                direct_fetch_path_seen,
                obs.action_tools,
                obs.routing_tools,
                obs.workload_tools
            ),
        ),
        LocalCheck::new(
            "web_pipeline_receipt_floor_present",
            web_source_floor_present,
            format!(
                "web_min_sources={:?} web_sources_success={:?} verification_checks={:?}",
                web_min_sources, web_sources_success, obs.verification_checks
            ),
        ),
        LocalCheck::new(
            "source_quality_and_independence_present",
            source_quality_and_independence_present,
            format!(
                "citation_url_count={} unique_domain_count={} search_hub_or_wrapper_citations={} citation_urls={:?}",
                unique_citation_urls.len(),
                unique_domain_count,
                search_hub_or_wrapper_citations,
                unique_citation_urls
            ),
        ),
        LocalCheck::new(
            "temporal_grounding_evidence_present",
            temporal_grounding_evidence_present,
            format!(
                "run_timestamp_present={} recency_heading_present={} citation_iso_utc_count={}",
                run_timestamp_present, recency_heading_present, citation_iso_utc_count
            ),
        ),
        LocalCheck::new(
            "contract_failure_markers_absent",
            !any_contract_failure_marker,
            truncate_chars(
                &format!(
                    "verification_checks={:?} final_reply={} event_excerpt={:?}",
                    obs.verification_checks, obs.final_reply, obs.event_excerpt
                ),
                220,
            ),
        ),
        LocalCheck::new(
            "environment_receipts_satisfied",
            environment_receipts_satisfied,
            serialize_environment_receipts(&environment_receipts),
        ),
        LocalCheck::new(
            "independent_runtime_evidence_channels_present",
            independent_runtime_evidence_channels_present,
            format!(
                "independent_channel_count={} objective_specific_price_signal_present={}",
                independent_channel_count, objective_specific_price_signal_present
            ),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
}

fn build_environment_receipts(
    obs: &RunObservation,
    price_line_count: usize,
    has_bitcoin_anchor: bool,
    web_min_sources: Option<usize>,
    web_sources_success: Option<usize>,
    citation_url_count: usize,
    unique_domain_count: usize,
    search_hub_or_wrapper_citations: usize,
    citation_iso_utc_count: usize,
    run_timestamp_present: bool,
    web_retrieval_path_present: bool,
) -> Vec<EnvironmentEvidenceReceipt> {
    let source_floor_satisfied = match (web_min_sources, web_sources_success) {
        (Some(min_sources), Some(success_sources)) => {
            min_sources >= 2 && success_sources >= min_sources
        }
        _ => false,
    };

    vec![
        EnvironmentEvidenceReceipt {
            key: "bitcoin_price_signal_observed",
            observed_value: format!(
                "price_line_count={} has_bitcoin_anchor={}",
                price_line_count, has_bitcoin_anchor
            ),
            probe_source: "KernelEvent::AgentActionResult(tool=chat__reply).output_excerpt",
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: has_bitcoin_anchor && price_line_count > 0,
        },
        EnvironmentEvidenceReceipt {
            key: "web_pipeline_source_floor_observed",
            observed_value: format!(
                "web_min_sources={:?} web_sources_success={:?}",
                web_min_sources, web_sources_success
            ),
            probe_source: "RoutingReceipt.post_state.verification_checks",
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: source_floor_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "citation_source_independence_observed",
            observed_value: format!(
                "citation_url_count={} unique_domain_count={} search_hub_or_wrapper_citations={}",
                citation_url_count, unique_domain_count, search_hub_or_wrapper_citations
            ),
            probe_source: "chat__reply citations block",
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: citation_url_count >= 2
                && unique_domain_count >= 2
                && search_hub_or_wrapper_citations == 0,
        },
        EnvironmentEvidenceReceipt {
            key: "temporal_grounding_observed",
            observed_value: format!(
                "run_timestamp_present={} citation_iso_utc_count={}",
                run_timestamp_present, citation_iso_utc_count
            ),
            probe_source: "chat__reply run timestamp + citation timestamp fields",
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: run_timestamp_present && citation_iso_utc_count >= 1,
        },
        EnvironmentEvidenceReceipt {
            key: "web_retrieval_contract_path_observed",
            observed_value: format!("web_retrieval_path_present={}", web_retrieval_path_present),
            probe_source: "KernelEvent::AgentActionResult + RoutingReceipt.tool_name",
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: web_retrieval_path_present,
        },
    ]
}

fn serialize_environment_receipts(receipts: &[EnvironmentEvidenceReceipt]) -> String {
    serde_json::to_string(receipts).unwrap_or_else(|_| "[]".to_string())
}

fn extract_citation_urls(reply: &str) -> Vec<String> {
    reply
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if !trimmed.starts_with("- ") || !trimmed.contains(" | http") {
                return None;
            }
            trimmed
                .split(" | ")
                .find(|segment| segment.starts_with("http://") || segment.starts_with("https://"))
                .map(|value| value.trim().to_string())
        })
        .collect()
}

fn extract_citation_timestamps(reply: &str) -> Vec<String> {
    reply
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if !trimmed.starts_with("- ") || !trimmed.contains(" | http") {
                return None;
            }
            let parts = trimmed.split(" | ").collect::<Vec<_>>();
            if parts.len() < 4 {
                return None;
            }
            parts
                .iter()
                .find(|part| looks_like_iso_utc_timestamp(part))
                .map(|value| value.trim().to_string())
        })
        .collect()
}

fn extract_domains(urls: &[String]) -> Vec<String> {
    urls.iter()
        .filter_map(|url| {
            let stripped = url
                .trim_start_matches("https://")
                .trim_start_matches("http://");
            let host = stripped.split('/').next()?.trim();
            if host.is_empty() {
                None
            } else {
                Some(host.trim_start_matches("www.").to_string())
            }
        })
        .collect::<Vec<_>>()
}

fn looks_like_iso_utc_timestamp(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() < 20 {
        return false;
    }
    let bytes = trimmed.as_bytes();
    bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-')
        && bytes.get(10) == Some(&b'T')
        && bytes.get(13) == Some(&b':')
        && bytes.get(16) == Some(&b':')
        && trimmed.ends_with('Z')
}

fn max_usize_verification_value(obs: &RunObservation, prefix: &str) -> Option<usize> {
    obs.verification_checks
        .iter()
        .filter_map(|check| check.strip_prefix(prefix))
        .filter_map(|value| value.trim().parse::<usize>().ok())
        .max()
}

fn bitcoin_price_line_count(reply: &str) -> usize {
    let has_global_bitcoin_anchor = reply
        .lines()
        .any(|line| contains_any(&line.to_ascii_lowercase(), &["bitcoin", "btc"]));

    reply
        .lines()
        .filter(|line| is_price_observation_line(line, has_global_bitcoin_anchor))
        .count()
}

fn is_price_observation_line(line: &str, has_global_bitcoin_anchor: bool) -> bool {
    let lower = line.to_ascii_lowercase();
    if lower.trim().is_empty() {
        return false;
    }
    if lower.contains("price unavailable")
        || lower.contains("did not expose numeric current-condition metrics")
    {
        return false;
    }

    let has_line_bitcoin_anchor = contains_any(&lower, &["bitcoin", "btc"]);
    let has_price_anchor = contains_any(
        &lower,
        &["price", "quote", "trading", "usd", "us$", "market", "$"],
    );
    let has_numeric_price = has_price_numeric_token(line);
    let structured_price_line = lower.trim_start().starts_with("- price:");

    has_numeric_price
        && has_price_anchor
        && (has_line_bitcoin_anchor || structured_price_line || has_global_bitcoin_anchor)
}

fn has_price_numeric_token(line: &str) -> bool {
    line.split_whitespace().any(|raw| {
        let token = raw.trim_matches(|ch: char| ",.;:!?()[]{}'\"".contains(ch));
        if token.is_empty() || token.contains(':') {
            return false;
        }
        let digit_count = token.chars().filter(|ch| ch.is_ascii_digit()).count();
        if digit_count < 3 {
            return false;
        }
        token.contains('$')
            || token.contains(',')
            || token.contains('.')
            || token.to_ascii_lowercase().contains("usd")
    })
}

fn is_search_hub_or_wrapper_url(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    lower.starts_with("https://news.google.com/rss/articles/")
        || lower.starts_with("https://news.google.com/rss/read/")
        || lower.starts_with("https://news.google.com/rss/topics/")
        || lower.contains("google.com/search?")
        || lower.contains("bing.com/search?")
        || lower.contains("duckduckgo.com/?q=")
        || lower.contains("/search?")
}

fn observation_has_contract_failure_marker(obs: &RunObservation) -> bool {
    let mut evidence_corpus = Vec::<String>::new();
    evidence_corpus.push(obs.final_reply.clone());
    evidence_corpus.extend(
        obs.action_evidence
            .iter()
            .map(|entry| format!("{} {}", entry.agent_status, entry.output_excerpt)),
    );
    evidence_corpus.extend(obs.verification_checks.iter().cloned());
    evidence_corpus.extend(obs.event_excerpt.iter().cloned());

    evidence_corpus
        .iter()
        .any(|segment| has_contract_failure_marker(segment))
}

fn has_contract_failure_marker(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "execution_contract_gate_blocked=true",
        "cec_terminal_error=true",
        "execution contract unmet",
        "base_error_class=executioncontractviolation",
        "error_class=executioncontractviolation",
        "error_class=discoverymissing",
        "error_class=synthesisfailed",
        "error_class=executionfailedterminal",
        "error_class=verificationmissing",
        "error_class=postconditionfailed",
        "failed_stage=",
        "missing_receipts=",
        "missing_postconditions=",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}
