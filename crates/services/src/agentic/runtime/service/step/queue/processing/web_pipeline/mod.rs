#![allow(dead_code)]

#[allow(unused_imports)]
use super::super::support::{
    append_final_web_completion_receipts,
    append_final_web_completion_receipts_with_rendered_summary,
    append_pending_web_success_fallback, append_pending_web_success_from_bundle,
    build_query_constraint_projection_with_locality_hint, candidate_constraint_compatibility,
    candidate_source_hints_from_bundle,
    collect_projection_candidate_urls_with_contract_and_locality_hint,
    collect_projection_candidate_urls_with_locality_hint, compact_whitespace,
    compatibility_passes_projection,
    constraint_grounded_probe_query_with_contract_and_hints_and_locality_hint,
    constraint_grounded_probe_query_with_hints_and_locality_hint, constraint_grounded_search_limit,
    constraint_grounded_search_query_with_contract_and_hints_and_locality_hint,
    constraint_grounded_search_query_with_hints_and_locality_hint, effective_locality_scope_hint,
    explicit_query_scope_hint, extract_json_object, fallback_search_summary,
    final_web_completion_facts, final_web_completion_facts_with_rendered_summary,
    has_primary_status_authority, is_citable_web_url, is_human_challenge_error,
    is_multi_item_listing_url, is_search_hub_url, local_business_detail_display_name,
    local_business_discovery_source_allowed_with_projection, local_business_entity_name_allowed,
    local_business_expansion_query, local_business_search_entity_anchor_tokens,
    local_business_search_entity_anchor_tokens_with_contract,
    local_business_target_name_from_source, local_business_target_names_from_attempted_urls,
    local_business_target_names_from_sources, mark_pending_web_attempted, mark_pending_web_blocked,
    merge_pending_search_completion, normalized_local_business_target_name,
    parse_web_evidence_bundle, pre_read_candidate_plan_from_bundle_with_contract_and_locality_hint,
    pre_read_candidate_plan_from_bundle_with_contract_and_locality_hint_and_recovery_mode,
    pre_read_candidate_plan_from_bundle_with_locality_hint,
    preferred_pre_read_action_count_with_contract_and_locality_hint,
    preferred_pre_read_action_count_with_locality_hint,
    projection_candidate_url_allowed_with_projection, query_is_generic_headline_collection,
    query_prefers_document_briefing_layout, query_requests_comparison,
    query_requires_runtime_locality_scope, queue_web_read_from_pipeline,
    queue_web_search_from_pipeline, remaining_pending_web_candidates,
    retrieval_affordances_with_contract_and_locality_hint,
    retrieval_affordances_with_locality_hint, retrieval_contract_entity_diversity_required,
    retrieval_contract_prefers_multi_item_cardinality, retrieval_contract_requests_comparison,
    retrieval_contract_required_distinct_domain_floor,
    retrieval_contract_requires_runtime_locality, select_final_web_summary_from_candidates,
    select_web_pipeline_query_contract, selected_local_business_target_sources,
    selected_source_quality_observation_with_contract_and_locality_hint,
    semantic_retrieval_query_contract_with_contract_and_locality_hint,
    semantic_retrieval_query_contract_with_locality_hint, source_anchor_tokens,
    source_has_terminal_error_signal, source_host,
    source_matches_local_business_search_entity_anchor, summarize_search_results,
    synthesize_web_pipeline_reply, synthesize_web_pipeline_reply_hybrid,
    url_structurally_equivalent, web_pipeline_can_queue_probe_search_latency_aware,
    web_pipeline_completion_reason, web_pipeline_grounded_probe_attempt_available,
    web_pipeline_min_sources, web_pipeline_now_ms, FinalWebSummaryCandidate,
    FinalWebSummarySelection, RetrievalAffordanceKind, WebPipelineCompletionReason,
    LOCAL_BUSINESS_EXPANSION_QUERY_MARKER_PREFIX, WEB_PIPELINE_BUDGET_MS,
};
use super::completion::complete_with_summary;
use super::routing::is_web_research_scope;
use crate::agentic::runtime::service::step::action::command_contract::execution_contract_violation_error;
use crate::agentic::runtime::service::step::action::{
    emit_completion_gate_status_event, emit_execution_contract_receipt_event_with_observation,
    resolved_intent_id,
};
use crate::agentic::runtime::service::step::signals::analyze_source_record_signals;
use crate::agentic::runtime::service::RuntimeAgentService;
use crate::agentic::runtime::types::{
    AgentState, AgentStatus, PendingSearchCompletion, PendingSearchReadSummary,
};
use ioi_types::app::agentic::{
    AgentTool, InferenceOptions, WebEvidenceBundle, WebRetrievalAffordance, WebRetrievalContract,
    WebSource, WebSourceExpansionAffordance, WebSourceObservation,
};
use ioi_types::app::ActionTarget;
use ioi_types::error::TransactionError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use tokio::time::Duration;
use url::Url;

const WEB_PIPELINE_DISCOVERY_SOURCE_LIMIT: usize = 15;
const WEB_PIPELINE_PRE_READ_SYNTHESIS_MAX_ATTEMPTS: usize = 3;
const WEB_PIPELINE_PRE_READ_SYNTHESIS_MAX_TOKENS: u32 = 700;
const WEB_PIPELINE_LOCAL_BUSINESS_EXPANSION_MAX_ATTEMPTS: usize = 2;
const WEB_PIPELINE_LOCAL_BUSINESS_EXPANSION_MAX_TOKENS: u32 = 400;
const WEB_PIPELINE_LOCAL_BUSINESS_EXPANSION_SOURCE_TEXT_CHARS: usize = 8_000;
const LOCAL_BUSINESS_EXPANSION_GENERIC_QUERY_TOKENS: &[&str] = &[
    "find",
    "three",
    "best",
    "top",
    "compare",
    "near",
    "nearby",
    "closest",
    "nearest",
    "restaurant",
    "restaurants",
    "menu",
    "menus",
    "review",
    "reviews",
    "reviewed",
    "rating",
    "ratings",
];
const ENTITY_EXPANSION_TARGET_MARKER_PREFIX: &str = "ioi://entity-expansion/target/";
const ENTITY_EXPANSION_QUERY_MARKER_PREFIX: &str = "ioi://entity-expansion/query/";

mod read;
mod search;
mod snapshot;

pub(super) use read::maybe_handle_web_read;
pub(crate) use search::maybe_handle_web_search;
pub(super) use snapshot::maybe_handle_browser_snapshot;

include!("pre_read_selection.rs");

include!("local_business_expansion.rs");

include!("entity_expansion.rs");

pub(crate) fn emit_web_contract_receipt(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    step_index: u32,
    intent_id: &str,
    stage: &str,
    key: &str,
    satisfied: bool,
    probe_source: &str,
    observed_value: &str,
    evidence_type: &str,
    provider_id: Option<String>,
) {
    let evidence_material = format!(
        "probe_source={};observed_value={};evidence_type={}",
        probe_source, observed_value, evidence_type
    );
    emit_execution_contract_receipt_event_with_observation(
        service,
        session_id,
        step_index,
        intent_id,
        stage,
        key,
        satisfied,
        &evidence_material,
        Some(probe_source),
        Some(observed_value),
        Some(evidence_type),
        None,
        provider_id,
        None,
    );
}

pub(crate) fn emit_web_string_receipts(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    step_index: u32,
    intent_id: &str,
    stage: &str,
    key: &str,
    probe_source: &str,
    evidence_type: &str,
    values: &[String],
) {
    let mut seen = BTreeSet::new();
    for value in values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        if !seen.insert(value.to_string()) {
            continue;
        }
        emit_web_contract_receipt(
            service,
            session_id,
            step_index,
            intent_id,
            stage,
            key,
            true,
            probe_source,
            value,
            evidence_type,
            None,
        );
    }
}

fn admitted_provider_ids_from_backend(backend: &str) -> Vec<String> {
    let trimmed = backend.trim();
    if trimmed.is_empty() || trimmed.starts_with("edge:search:empty") {
        return Vec::new();
    }
    let raw_values = if let Some(rest) = trimmed.strip_prefix("edge:search:aggregate:") {
        rest.split('+').collect::<Vec<_>>()
    } else {
        vec![trimmed]
    };
    raw_values
        .into_iter()
        .map(str::trim)
        .filter(|value| value.starts_with("edge:"))
        .map(str::to_string)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

async fn synthesize_summary(
    service: &RuntimeAgentService,
    pending: &PendingSearchCompletion,
    reason: WebPipelineCompletionReason,
) -> FinalWebSummarySelection {
    let mut candidates = Vec::new();
    if let Some(hybrid_summary) =
        synthesize_web_pipeline_reply_hybrid(service, pending, reason).await
    {
        candidates.push(FinalWebSummaryCandidate {
            provider: "hybrid",
            summary: hybrid_summary,
        });
    }
    candidates.push(FinalWebSummaryCandidate {
        provider: "deterministic",
        summary: synthesize_web_pipeline_reply(pending, reason),
    });
    select_final_web_summary_from_candidates(pending, reason, candidates)
        .expect("web summary selection requires at least one candidate")
}

fn append_summary_selection_checks(
    selection: &FinalWebSummarySelection,
    verification_checks: &mut Vec<String>,
) {
    verification_checks.push(format!("web_final_summary_provider={}", selection.provider));
    verification_checks.push(format!(
        "web_final_summary_contract_ready={}",
        selection.contract_ready
    ));
    for evaluation in &selection.evaluations {
        verification_checks.push(format!(
            "web_final_summary_candidate={}::contract_ready={}::rendered_layout={}::document_layout_met={}",
            evaluation.provider,
            evaluation.contract_ready,
            evaluation.facts.briefing_rendered_layout_profile,
            evaluation.facts.briefing_document_layout_met
        ));
    }
}

fn web_pipeline_completion_reason_label(reason: WebPipelineCompletionReason) -> &'static str {
    match reason {
        WebPipelineCompletionReason::MinSourcesReached => "min_sources_reached",
        WebPipelineCompletionReason::ExhaustedCandidates => "exhausted_candidates",
        WebPipelineCompletionReason::DeadlineReached => "deadline_reached",
    }
}

fn terminalized_web_pipeline_contract_error(
    pending: &PendingSearchCompletion,
    reason: WebPipelineCompletionReason,
    summary: &str,
) -> String {
    let summary_excerpt = compact_whitespace(summary);
    let summary_excerpt = if summary_excerpt.chars().count() > 280 {
        let mut truncated = summary_excerpt.chars().take(280).collect::<String>();
        truncated.push_str("...");
        truncated
    } else {
        summary_excerpt
    };

    format!(
        "{} cause_error_class=LowSignalReadInsufficient web_pipeline_reason={} successful_reads={} remaining_candidates={} summary_excerpt={}",
        execution_contract_violation_error("receipt::final_output_contract_ready=true"),
        web_pipeline_completion_reason_label(reason),
        pending.successful_reads.len(),
        remaining_pending_web_candidates(pending),
        summary_excerpt
    )
}

fn terminalize_failed_web_pipeline_completion(
    agent_state: &mut AgentState,
    pending: PendingSearchCompletion,
    reason: WebPipelineCompletionReason,
    summary: String,
    success: &mut bool,
    out: &mut Option<String>,
    err: &mut Option<String>,
    completion_summary: &mut Option<String>,
    verification_checks: &mut Vec<String>,
) {
    let error = terminalized_web_pipeline_contract_error(&pending, reason, &summary);
    *success = false;
    *out = Some(summary);
    *err = Some(error);
    *completion_summary = None;
    verification_checks.push("web_pipeline_terminalized_on_contract_failure=true".to_string());
    verification_checks.push(format!(
        "web_pipeline_terminal_failure_reason={}",
        web_pipeline_completion_reason_label(reason)
    ));
    verification_checks.push("web_pipeline_active=false".to_string());
    verification_checks.push("terminal_chat_reply_ready=false".to_string());
    agent_state.pending_search_completion = Some(pending);
    agent_state.execution_queue.clear();
    agent_state.recent_actions.clear();
}

fn normalized_domain_key(url: &str) -> Option<String> {
    source_host(url).map(|host| host.strip_prefix("www.").unwrap_or(&host).to_string())
}

fn payload_derived_source_hosts(
    discovery_sources: &[WebSource],
) -> std::collections::BTreeSet<String> {
    let mut hosts = std::collections::BTreeSet::new();
    for source in discovery_sources {
        if let Some(host) = normalized_domain_key(source.url.as_str()) {
            hosts.insert(host);
        }
        if let Some(host) = source
            .domain
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| {
                value
                    .strip_prefix("www.")
                    .unwrap_or(value)
                    .to_ascii_lowercase()
            })
        {
            hosts.insert(host);
        }
        if let Some(source_url) = source
            .snippet
            .as_deref()
            .and_then(source_url_from_metadata_excerpt)
        {
            if let Some(host) = normalized_domain_key(source_url.as_str()) {
                hosts.insert(host);
            }
        }
    }
    hosts
}

fn discovery_source_hints(discovery_sources: &[WebSource]) -> Vec<PendingSearchReadSummary> {
    let mut hints = Vec::new();
    let mut seen = std::collections::BTreeSet::new();

    for source in discovery_sources {
        let url = source.url.trim();
        if url.is_empty() {
            continue;
        }
        let base_url_allowed = is_citable_web_url(url)
            && !is_search_hub_url(url)
            && !is_multi_item_listing_url(url)
            && !crate::agentic::web::is_google_news_article_wrapper_url(url);
        let resolved_url = if base_url_allowed {
            url.to_string()
        } else {
            source
                .snippet
                .as_deref()
                .and_then(source_url_from_metadata_excerpt)
                .filter(|candidate| {
                    let trimmed = candidate.trim();
                    is_citable_web_url(trimmed)
                        && !is_search_hub_url(trimmed)
                        && !is_multi_item_listing_url(trimmed)
                })
                .unwrap_or_else(|| url.to_string())
        };
        let dedup_key = crate::agentic::web::normalize_url_for_id(&resolved_url);
        if !seen.insert(dedup_key) {
            continue;
        }
        hints.push(PendingSearchReadSummary {
            url: resolved_url,
            title: source
                .title
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.to_string()),
            excerpt: source
                .snippet
                .as_deref()
                .map(str::trim)
                .unwrap_or_default()
                .to_string(),
        });
    }

    hints
}

fn discovery_source_affordances(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    required_url_count: usize,
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
    url: &str,
    title: &str,
    excerpt: &str,
) -> Vec<RetrievalAffordanceKind> {
    retrieval_affordances_with_contract_and_locality_hint(
        retrieval_contract,
        query_contract,
        required_url_count.max(1) as u32,
        source_hints,
        locality_hint,
        url,
        title,
        excerpt,
    )
}

fn merged_entity_targets(existing_targets: &[String], new_targets: &[String]) -> Vec<String> {
    let mut merged = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for target in existing_targets.iter().chain(new_targets.iter()) {
        let Some(normalized) = normalized_entity_name(target) else {
            continue;
        };
        let key = normalized.to_ascii_lowercase();
        if !seen.insert(key) {
            continue;
        }
        merged.push(normalized);
    }
    merged
}

fn selected_source_structural_metrics(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    min_sources: u32,
    selected_urls: &[String],
    source_hints: &[PendingSearchReadSummary],
) -> (usize, usize, usize, usize, usize, bool, Vec<String>) {
    let locality_hint =
        if retrieval_contract_requires_runtime_locality(retrieval_contract, query_contract) {
            effective_locality_scope_hint(None)
        } else {
            None
        };
    let observation = selected_source_quality_observation_with_contract_and_locality_hint(
        retrieval_contract,
        query_contract,
        min_sources,
        selected_urls,
        source_hints,
        locality_hint.as_deref(),
    );
    (
        observation.total_sources,
        observation.compatible_sources,
        observation.locality_compatible_sources,
        observation.distinct_domains,
        observation.low_priority_sources,
        observation.quality_floor_met,
        observation.low_priority_urls,
    )
}

fn merged_local_business_targets(
    existing_targets: &[String],
    new_targets: &[String],
) -> Vec<String> {
    let mut merged = Vec::new();
    let mut seen = std::collections::BTreeSet::new();

    for target in existing_targets.iter().chain(new_targets.iter()) {
        let Some(normalized) = normalized_local_business_target_name(target) else {
            continue;
        };
        let dedup_key = normalized.to_ascii_lowercase();
        if !seen.insert(dedup_key) {
            continue;
        }
        merged.push(normalized);
    }

    merged
}

fn source_looks_like_multi_item_restaurant_guide(
    source_url: &str,
    title: Option<&str>,
    source_text: &str,
) -> bool {
    let observed = format!(
        "{} {} {}",
        source_url,
        title.unwrap_or_default(),
        source_text
    );
    let lower = format!(" {} ", observed.to_ascii_lowercase());
    if source_has_terminal_error_signal(source_url, title.unwrap_or_default(), source_text)
        || lower.contains(" please enable js ")
    {
        return false;
    }
    let source_tokens = source_anchor_tokens(source_url, title.unwrap_or_default(), source_text);
    let guide_marker_present = source_tokens.iter().any(|token| {
        matches!(
            token.as_str(),
            "best"
                | "top"
                | "guide"
                | "review"
                | "reviews"
                | "rating"
                | "ratings"
                | "ranked"
                | "ranking"
        )
    }) || lower.contains(" where to eat ")
        || lower.contains(" the spots ");
    let restaurant_collection_marker_present = source_tokens
        .iter()
        .any(|token| matches!(token.as_str(), "restaurants"))
        || lower.contains(" dining guide ")
        || lower.contains(" restaurant guide ");
    let strong_multi_item_markers = lower.matches("read the review").count() >= 2
        || lower.matches(" perfect for: ").count() >= 2
        || lower.matches(" $ $ $ ").count() >= 3
        || lower.matches(" 8.").count() >= 2
        || lower.matches(" 9.").count() >= 2;
    guide_marker_present
        && (restaurant_collection_marker_present
            || is_multi_item_listing_url(source_url.trim())
            || strong_multi_item_markers)
}

fn normalized_jsonish_source_text(source_text: &str) -> Option<String> {
    let normalized = source_text
        .replace("\\\\\"", "\"")
        .replace("\\\"", "\"")
        .replace("\\\\u", "\\u");
    let decoded = decode_jsonish_unicode_escapes(&normalized);
    (decoded != source_text).then_some(decoded)
}

fn queue_web_read_batch_from_pipeline(
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    urls: &[String],
    allow_browser_fallback: bool,
) -> Result<usize, TransactionError> {
    let mut queued = 0usize;
    for url in urls.iter().rev() {
        if queue_web_read_from_pipeline(agent_state, session_id, url, allow_browser_fallback)? {
            queued += 1;
        }
    }
    Ok(queued)
}

fn pending_web_read_allows_browser_fallback(pending: &PendingSearchCompletion) -> bool {
    pending
        .retrieval_contract
        .as_ref()
        .map(|contract| contract.browser_fallback_allowed)
        .unwrap_or_else(|| {
            !(query_prefers_document_briefing_layout(&pending.query_contract)
                && !query_requests_comparison(&pending.query_contract))
        })
}

fn queued_web_retrieve_count(agent_state: &AgentState) -> usize {
    agent_state
        .execution_queue
        .iter()
        .filter(|request| matches!(request.target, ActionTarget::WebRetrieve))
        .count()
}

fn queued_web_read_count(agent_state: &AgentState) -> usize {
    agent_state
        .execution_queue
        .iter()
        .filter(|request| {
            if !matches!(request.target, ActionTarget::WebRetrieve) {
                return false;
            }
            let Ok(args) = serde_json::from_slice::<serde_json::Value>(&request.params) else {
                return false;
            };
            args.get("url")
                .and_then(|value| value.as_str())
                .map(|url| !url.trim().is_empty())
                .unwrap_or(false)
        })
        .count()
}

fn grounded_probe_search_allowed(
    local_business_expansion_queued: bool,
    next_viable_candidate_available: bool,
    quality_floor_unmet: bool,
    probe_attempt_available: bool,
) -> bool {
    !local_business_expansion_queued
        && !next_viable_candidate_available
        && quality_floor_unmet
        && probe_attempt_available
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
