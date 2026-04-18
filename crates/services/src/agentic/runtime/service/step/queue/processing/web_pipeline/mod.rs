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
mod tests {
    use super::*;
    use ioi_types::app::{ActionContext, ActionRequest};
    use std::collections::{BTreeMap, VecDeque};

    fn test_agent_state() -> AgentState {
        AgentState {
            session_id: [7u8; 32],
            goal: "find restaurants".to_string(),
            transcript_root: [0u8; 32],
            status: AgentStatus::Running,
            step_count: 0,
            max_steps: 8,
            last_action_type: None,
            parent_session_id: None,
            child_session_ids: vec![],
            budget: 0,
            tokens_used: 0,
            consecutive_failures: 0,
            pending_approval: None,
            pending_tool_call: None,
            pending_tool_jcs: None,
            pending_tool_hash: None,
            pending_request_nonce: None,
            pending_visual_hash: None,
            recent_actions: vec![],
            mode: crate::agentic::runtime::types::AgentMode::default(),
            current_tier: crate::agentic::runtime::types::ExecutionTier::default(),
            last_screen_phash: None,
            execution_queue: vec![],
            pending_search_completion: None,
            planner_state: None,
            active_skill_hash: None,
            tool_execution_log: BTreeMap::new(),
            visual_som_map: None,
            visual_semantic_map: None,
            swarm_context: None,
            target: None,
            resolved_intent: None,
            awaiting_intent_clarification: false,
            working_directory: ".".to_string(),
            command_history: VecDeque::new(),
            active_lens: None,
        }
    }

    #[test]
    fn projection_candidate_url_rejects_placeholder_slug_segments() {
        assert!(!looks_like_deep_article_url(
            "https://www.cbsnews.com/news/article-title/"
        ));
        assert!(!looks_like_deep_article_url(
            "https://apnews.com/article/story-title"
        ));
        assert!(!looks_like_deep_article_url(
            "https://www.foxnews.com/shows/fox-news-live"
        ));
        assert!(!looks_like_deep_article_url(
            "https://example.com/world/news/article-title"
        ));
    }

    #[test]
    fn projection_candidate_url_accepts_real_article_paths() {
        let reuters = "https://www.reuters.com/world/europe/example-article-slug-2026-03-01/";
        assert!(is_citable_web_url(reuters));
        assert!(!is_search_hub_url(reuters));
        assert!(!is_multi_item_listing_url(reuters));
        assert!(looks_like_deep_article_url(reuters));
        assert!(looks_like_deep_article_url(
            "https://www.bbc.com/news/world-us-canada-12345678"
        ));
        assert!(looks_like_deep_article_url(
            "https://news.google.com/rss/articles/CBMiakFVX3lxTE1paDlDQVMzckpVZjltZkhUM3RSdFh4MGtVOHFGNll6NlRKNUpqOV9UVDl4ZlBXZldpcUtMNm9JLWtZZ0dSMHlORTBRVlZTNC1mZ1dCemkzaWRCcmFMN2E5VVlZallSYjI5MVE?oc=5"
        ));
    }

    #[test]
    fn queued_web_retrieve_count_includes_search_and_read_actions() {
        let session_id = [7u8; 32];
        let mut agent_state = test_agent_state();
        agent_state.execution_queue = vec![
            ActionRequest {
                target: ActionTarget::WebRetrieve,
                params: serde_jcs::to_vec(&serde_json::json!({
                    "query": "\"Brothers Italian Cuisine\" menus in Anderson, SC"
                }))
                .expect("params"),
                context: ActionContext {
                    agent_id: "desktop_agent".to_string(),
                    session_id: Some(session_id),
                    window_id: None,
                },
                nonce: 1,
            },
            ActionRequest {
                target: ActionTarget::WebRetrieve,
                params: serde_jcs::to_vec(&serde_json::json!({
                    "url": "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/"
                }))
                .expect("params"),
                context: ActionContext {
                    agent_id: "desktop_agent".to_string(),
                    session_id: Some(session_id),
                    window_id: None,
                },
                nonce: 2,
            },
        ];

        assert_eq!(queued_web_retrieve_count(&agent_state), 2);
        assert_eq!(queued_web_read_count(&agent_state), 1);
    }

    #[test]
    fn grounded_probe_search_is_blocked_when_local_business_expansion_is_already_queued() {
        assert!(!grounded_probe_search_allowed(true, false, true, true));
        assert!(grounded_probe_search_allowed(false, false, true, true));
    }

    #[test]
    fn terminalized_web_pipeline_contract_error_keeps_low_signal_cause_but_not_bare_success() {
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(
                crate::agentic::web::derive_web_retrieval_contract(
                    "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.",
                    None,
                )
                .expect("retrieval contract"),
            ),
            url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1,
            deadline_ms: 2,
            candidate_urls: vec!["https://research.ibm.com/blog/nist-pqc-standards".to_string()],
            candidate_source_hints: vec![],
            attempted_urls: vec![],
            blocked_urls: vec![],
            successful_reads: vec![PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "NIST IR 8413 Update 1 documents the post-quantum cryptography standardization process."
                        .to_string(),
            }],
            min_sources: 2,
        };

        let error = terminalized_web_pipeline_contract_error(
            &pending,
            WebPipelineCompletionReason::DeadlineReached,
            "Standards briefing\n\nSummary inventory\n- FIPS 203",
        );

        assert!(
            error.contains("ERROR_CLASS=ExecutionContractViolation"),
            "{error}"
        );
        assert!(
            error.contains("cause_error_class=LowSignalReadInsufficient"),
            "{error}"
        );
        assert!(
            error.contains("web_pipeline_reason=deadline_reached"),
            "{error}"
        );
    }

    #[test]
    fn terminalize_failed_web_pipeline_completion_marks_agent_for_terminal_contract_failure() {
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(
                crate::agentic::web::derive_web_retrieval_contract(
                    "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.",
                    None,
                )
                .expect("retrieval contract"),
            ),
            url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1,
            deadline_ms: 2,
            candidate_urls: vec![],
            candidate_source_hints: vec![],
            attempted_urls: vec![],
            blocked_urls: vec![],
            successful_reads: vec![PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "NIST IR 8413 Update 1 documents the post-quantum cryptography standardization process."
                        .to_string(),
            }],
            min_sources: 2,
        };
        let mut agent_state = test_agent_state();
        agent_state.execution_queue.push(ActionRequest {
            target: ActionTarget::WebRetrieve,
            params: serde_jcs::to_vec(&serde_json::json!({
                "url": "https://csrc.nist.gov/pubs/ir/8413/upd1/final"
            }))
            .expect("params"),
            context: ActionContext {
                agent_id: "desktop_agent".to_string(),
                session_id: Some(agent_state.session_id),
                window_id: None,
            },
            nonce: 1,
        });
        let mut success = true;
        let mut out = None;
        let mut err = None;
        let mut completion_summary = None;
        let mut verification_checks = Vec::new();

        terminalize_failed_web_pipeline_completion(
            &mut agent_state,
            pending.clone(),
            WebPipelineCompletionReason::ExhaustedCandidates,
            "Standards briefing\n\nSummary inventory\n- FIPS 203".to_string(),
            &mut success,
            &mut out,
            &mut err,
            &mut completion_summary,
            &mut verification_checks,
        );

        assert!(!success);
        assert_eq!(completion_summary, None);
        assert!(out
            .as_deref()
            .unwrap_or_default()
            .contains("Standards briefing"));
        assert!(err
            .as_deref()
            .unwrap_or_default()
            .contains("ERROR_CLASS=ExecutionContractViolation"));
        assert!(agent_state.execution_queue.is_empty());
        assert_eq!(
            agent_state
                .pending_search_completion
                .as_ref()
                .map(|value| value.query.as_str()),
            Some(pending.query.as_str())
        );
        assert!(verification_checks
            .iter()
            .any(|check| { check == "web_pipeline_terminalized_on_contract_failure=true" }));
    }

    #[test]
    fn payload_rejects_external_article_deep_links_without_discovery_receipts() {
        assert!(!payload_allows_external_article_url(
            None,
            "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus.",
            3,
            &[],
            "https://www.grubstreet.com/2023/10/best-italian-restaurants-nyc.html",
            &std::collections::BTreeSet::new()
        ));
    }

    #[test]
    fn payload_rejects_metadata_backed_external_deep_links() {
        let discovery_sources = vec![WebSource {
            source_id: "wrapper-1".to_string(),
            rank: Some(1),
            url: "https://news.google.com/rss/articles/CBMiUkFVX3lxTE0x?oc=5".to_string(),
            title: Some("Bitcoin price today".to_string()),
            snippet: Some(
                "CoinDesk | source_url=https://www.coindesk.com/price/bitcoin/ The price of Bitcoin (BTC) is $68,214.99 today as of Mar 6, 2026, 2:25 pm EST."
                    .to_string(),
            ),
            domain: Some("coindesk.com".to_string()),
        }];
        let allowed_hosts = payload_derived_source_hosts(&discovery_sources);

        assert!(!payload_allows_external_article_url(
            None,
            "What's the current price of Bitcoin?",
            2,
            &discovery_sources,
            "https://www.coindesk.com/price/bitcoin/",
            &allowed_hosts
        ));
    }

    #[test]
    fn pre_read_selection_payload_adds_local_business_detail_constraint() {
        let payload = build_pre_read_selection_payload(
            None,
            "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus.",
            3,
            &[],
            &[],
        );
        assert!(payload.constraints.iter().any(|constraint| {
            constraint.contains("official menu pages")
                || constraint.contains("business-detail pages")
        }));
    }

    #[test]
    fn discovery_source_hints_preserve_late_grounding_context_for_authority_expansion_sources() {
        let discovery_sources = vec![WebSource {
            source_id: "fips-203".to_string(),
            rank: Some(1),
            url: "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
            title: Some("Module-Lattice-Based Key-Encapsulation Mechanism Standard".to_string()),
            snippet: Some(format!(
                "{} post-quantum cryptography standards migration guidance from the NIST PQC program.",
                "context ".repeat(24)
            )),
            domain: Some("csrc.nist.gov".to_string()),
        }];

        let hints = discovery_source_hints(&discovery_sources);

        assert_eq!(hints.len(), 1);
        assert!(hints[0]
            .excerpt
            .contains("post-quantum cryptography standards"));
        assert!(hints[0].excerpt.len() > 180);
    }

    #[test]
    fn local_business_guide_detection_rejects_single_business_official_page() {
        let source_text = r#"Carbone New York is an Italian restaurant in New York, NY.
            Reserve a table for holidays and special events.
            "name":"Carbone","streetAddress":"181 Thompson St","postalCode":"10012""#;

        assert!(!source_looks_like_multi_item_restaurant_guide(
            "https://carbonenewyork.com",
            Some("Carbone New York"),
            source_text
        ));
    }

    #[test]
    fn local_business_guide_detection_accepts_ranked_restaurant_guide_surface() {
        let source_text = "Editors rank the best Italian restaurants in NYC with reviews, ratings and where to eat now.";

        assert!(source_looks_like_multi_item_restaurant_guide(
            "https://www.timeout.com/newyork/restaurants/best-italian-restaurants-in-nyc",
            Some("Best Italian Restaurants in NYC"),
            source_text
        ));
        assert!(source_looks_like_multi_item_restaurant_guide(
            "https://www.eater.com/nyc/italian-restaurant-reviews",
            Some("Italian restaurant reviews in NYC"),
            source_text
        ));
    }

    #[test]
    fn local_business_expansion_source_selection_skips_generic_citywide_restaurant_guides() {
        let bundle = WebEvidenceBundle {
            schema_version: 1,
            retrieved_at_ms: 0,
            tool: "web__read".to_string(),
            backend: "edge:read:http".to_string(),
            query: None,
            url: Some("https://ny.eater.com/maps/best-new-york-restaurants-38-map".to_string()),
            sources: vec![
                WebSource {
                    source_id: "generic-guide".to_string(),
                    rank: Some(1),
                    url: "https://ny.eater.com/maps/best-new-york-restaurants-38-map"
                        .to_string(),
                    title: Some("The 38 Best Restaurants in New York City".to_string()),
                    snippet: Some(
                        "Where to eat right now across New York City neighborhoods.".to_string(),
                    ),
                    domain: Some("ny.eater.com".to_string()),
                },
                WebSource {
                    source_id: "italian-guide".to_string(),
                    rank: Some(2),
                    url: "https://www.cntraveler.com/gallery/best-italian-restaurants-in-new-york"
                        .to_string(),
                    title: Some("The Very Best Italian Restaurants in New York City".to_string()),
                    snippet: Some(
                        "Menus, reviews and ratings for standout Italian restaurants in New York, NY."
                            .to_string(),
                    ),
                    domain: Some("www.cntraveler.com".to_string()),
                },
            ],
            source_observations: vec![],
            documents: vec![
                ioi_types::app::agentic::WebDocument {
                    source_id: "generic-guide".to_string(),
                    url: "https://ny.eater.com/maps/best-new-york-restaurants-38-map"
                        .to_string(),
                    title: Some("The 38 Best Restaurants in New York City".to_string()),
                    content_text:
                        "Where to eat right now in New York City. Charles Pan-Fried Chicken, Noz Market and Cafe Commerce are popular spots."
                            .to_string(),
                    content_hash: "hash-generic".to_string(),
                    quote_spans: vec![],
                },
                ioi_types::app::agentic::WebDocument {
                    source_id: "italian-guide".to_string(),
                    url: "https://www.cntraveler.com/gallery/best-italian-restaurants-in-new-york"
                        .to_string(),
                    title: Some("The Very Best Italian Restaurants in New York City".to_string()),
                    content_text:
                        "The best Italian restaurants in New York City include Torrisi Bar & Restaurant, L'Artusi and Via Carota."
                            .to_string(),
                    content_hash: "hash-italian".to_string(),
                    quote_spans: vec![],
                },
            ],
            provider_candidates: vec![],
            retrieval_contract: None,
        };

        let selected = select_local_business_expansion_source(
            "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus.",
            3,
            "New York, NY",
            &[],
            Some("New York, NY"),
            &bundle,
        )
        .expect("expected a query-compatible expansion source");

        assert_eq!(
            selected.0,
            "https://www.cntraveler.com/gallery/best-italian-restaurants-in-new-york"
        );
    }

    #[test]
    fn local_business_expansion_source_selection_rejects_off_topic_restaurant_guide() {
        let bundle = WebEvidenceBundle {
            schema_version: 1,
            retrieved_at_ms: 0,
            tool: "web__read".to_string(),
            backend: "edge:read:http".to_string(),
            query: None,
            url: Some("https://ny.eater.com/maps/best-new-york-restaurants-38-map".to_string()),
            sources: vec![WebSource {
                source_id: "generic-guide".to_string(),
                rank: Some(1),
                url: "https://ny.eater.com/maps/best-new-york-restaurants-38-map".to_string(),
                title: Some("The 38 Best Restaurants in New York City".to_string()),
                snippet: Some(
                    "Where to eat right now across New York City neighborhoods.".to_string(),
                ),
                domain: Some("ny.eater.com".to_string()),
            }],
            source_observations: vec![],
            documents: vec![ioi_types::app::agentic::WebDocument {
                source_id: "generic-guide".to_string(),
                url: "https://ny.eater.com/maps/best-new-york-restaurants-38-map".to_string(),
                title: Some("The 38 Best Restaurants in New York City".to_string()),
                content_text:
                    "Where to eat right now in New York City. Charles Pan-Fried Chicken, Noz Market and Cafe Commerce are popular spots."
                        .to_string(),
                content_hash: "hash-generic".to_string(),
                quote_spans: vec![],
            }],
            provider_candidates: vec![],
            retrieval_contract: None,
        };

        assert!(
            select_local_business_expansion_source(
                "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus.",
                3,
                "New York, NY",
                &[],
                Some("New York, NY"),
                &bundle,
            )
            .is_none()
        );
    }

    #[test]
    fn local_business_expansion_source_selection_rejects_single_restaurant_detail_page() {
        let bundle = WebEvidenceBundle {
            schema_version: 1,
            retrieved_at_ms: 0,
            tool: "web__read".to_string(),
            backend: "edge:read:http".to_string(),
            query: None,
            url: Some("https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/".to_string()),
            sources: vec![WebSource {
                source_id: "brothers-detail".to_string(),
                rank: Some(1),
                url: "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/".to_string(),
                title: Some(
                    "Brothers Italian Cuisine, Anderson - Menu, Reviews (226), Photos (25) - Restaurantji"
                        .to_string(),
                ),
                snippet: Some(
                    "Italian restaurant in Anderson, SC serving pizza, pasta and subs."
                        .to_string(),
                ),
                domain: Some("www.restaurantji.com".to_string()),
            }],
            source_observations: vec![],
            documents: vec![ioi_types::app::agentic::WebDocument {
                source_id: "brothers-detail".to_string(),
                url: "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/".to_string(),
                title: Some(
                    "Brothers Italian Cuisine, Anderson - Menu, Reviews (226), Photos (25) - Restaurantji"
                        .to_string(),
                ),
                content_text: "Brothers Italian Cuisine is an Italian restaurant in Anderson, SC with stromboli, manicotti and garlic knots on the menu."
                    .to_string(),
                content_hash: "hash-brothers".to_string(),
                quote_spans: vec![],
            }],
            provider_candidates: vec![],
            retrieval_contract: None,
        };

        assert!(
            select_local_business_expansion_source(
                "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.",
                3,
                "Anderson, SC",
                &[],
                Some("Anderson, SC"),
                &bundle,
            )
            .is_none()
        );
    }

    #[test]
    fn local_business_expansion_source_selection_accepts_structural_listing_seed() {
        let bundle = WebEvidenceBundle {
            schema_version: 1,
            retrieved_at_ms: 0,
            tool: "web__read".to_string(),
            backend: "edge:read:http".to_string(),
            query: None,
            url: Some(
                "https://www.tripadvisor.com/Restaurants-g30090-c26-Anderson_South_Carolina.html"
                    .to_string(),
            ),
            sources: vec![WebSource {
                source_id: "tripadvisor-list".to_string(),
                rank: Some(1),
                url: "https://www.tripadvisor.com/Restaurants-g30090-c26-Anderson_South_Carolina.html"
                    .to_string(),
                title: Some("Restaurants Anderson South Carolina".to_string()),
                snippet: Some(
                    "Browse Anderson dining results and traveler review rankings.".to_string(),
                ),
                domain: Some("www.tripadvisor.com".to_string()),
            }],
            source_observations: vec![],
            documents: vec![ioi_types::app::agentic::WebDocument {
                source_id: "tripadvisor-list".to_string(),
                url: "https://www.tripadvisor.com/Restaurants-g30090-c26-Anderson_South_Carolina.html"
                    .to_string(),
                title: Some("Restaurants Anderson South Carolina".to_string()),
                content_text: r#"{"@type":"Restaurant","name":"Dolce Vita Italian Bistro and Pizzeria","streetAddress":"3823 N Hwy 81","servesCuisine":"Italian"}
{"@type":"Restaurant","name":"Brothers Italian Cuisine","streetAddress":"725 N Murray Ave","servesCuisine":"Italian"}
{"@type":"Restaurant","name":"The Common House","streetAddress":"118 W Whitner St","servesCuisine":"Italian"}"#.to_string(),
                content_hash: "hash-tripadvisor-list".to_string(),
                quote_spans: vec![],
            }],
            provider_candidates: vec![],
            retrieval_contract: None,
        };

        let selected = select_local_business_expansion_source(
            "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.",
            3,
            "Anderson, SC",
            &[],
            Some("Anderson, SC"),
            &bundle,
        )
        .expect("expected a structural listing seed");

        assert_eq!(
            selected.0,
            "https://www.tripadvisor.com/Restaurants-g30090-c26-Anderson_South_Carolina.html"
        );
        assert_eq!(
            selected.3,
            vec![
                "Dolce Vita Italian Bistro and Pizzeria".to_string(),
                "Brothers Italian Cuisine".to_string(),
                "The Common House".to_string(),
            ]
        );
    }

    #[test]
    fn local_business_surface_filter_preserves_ranked_guide_sources_with_paths() {
        let bundle = WebEvidenceBundle {
            schema_version: 1,
            retrieved_at_ms: 0,
            tool: "web__search".to_string(),
            backend: "edge:bing:http".to_string(),
            query: Some(
                "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus."
                    .to_string(),
            ),
            url: Some("https://www.bing.com/search?q=italian+restaurants+new+york".to_string()),
            sources: vec![
                WebSource {
                    source_id: "eater".to_string(),
                    rank: Some(1),
                    url: "https://www.timeout.com/newyork/restaurants/best-italian-restaurants-in-nyc"
                        .to_string(),
                    title: Some("Best Italian Restaurants in NYC".to_string()),
                    snippet: Some(
                        "Restaurant reviews, ratings and menus for top Italian restaurants."
                            .to_string(),
                    ),
                    domain: Some("www.timeout.com".to_string()),
                },
                WebSource {
                    source_id: "zagat".to_string(),
                    rank: Some(2),
                    url: "https://www.zagat.com/best-italian-restaurants-in-new-york".to_string(),
                    title: Some("Best Italian Restaurants in New York".to_string()),
                    snippet: Some(
                        "Ratings and menus for the best Italian restaurants in New York, NY."
                            .to_string(),
                    ),
                    domain: Some("www.zagat.com".to_string()),
                },
                WebSource {
                    source_id: "tripadvisor-root".to_string(),
                    rank: Some(3),
                    url: "https://www.tripadvisor.com".to_string(),
                    title: Some("Tripadvisor: Best Italian Restaurants in New York".to_string()),
                    snippet: Some(
                        "Tripadvisor rankings and ratings for Italian restaurants in New York, NY."
                            .to_string(),
                    ),
                    domain: Some("www.tripadvisor.com".to_string()),
                },
                WebSource {
                    source_id: "lawless-root".to_string(),
                    rank: Some(4),
                    url: "https://www.lawlessitalian.com/".to_string(),
                    title: Some(
                        "Lawless Italian - Free Italian lessons and language tools".to_string(),
                    ),
                    snippet: Some(
                        "Learn Italian phrases, grammar and language basics for beginners."
                            .to_string(),
                    ),
                    domain: Some("www.lawlessitalian.com".to_string()),
                },
            ],
            source_observations: vec![],
            documents: vec![],
            provider_candidates: vec![],
            retrieval_contract: None,
        };
        let mut verification_checks = Vec::new();

        let filtered = filter_local_business_search_bundle_by_result_surface(
            &bundle,
            "Find the three best-reviewed Italian restaurants near me and compare their menus.",
            3,
            Some("New York, NY"),
            &mut verification_checks,
        );
        let kept_urls = filtered
            .sources
            .iter()
            .map(|source| source.url.clone())
            .collect::<Vec<_>>();

        assert!(
            kept_urls
                .iter()
                .any(|url| url.contains("timeout.com/newyork/restaurants")),
            "expected ranked guide article to survive: {:?}",
            kept_urls
        );
        assert!(
            kept_urls
                .iter()
                .any(|url| url.contains("zagat.com/best-italian-restaurants-in-new-york")),
            "expected ranked guide page to survive: {:?}",
            kept_urls
        );
        assert!(
            kept_urls
                .iter()
                .all(|url| url != "https://www.tripadvisor.com"),
            "expected bare root domain to be rejected: {:?}",
            kept_urls
        );
        assert!(
            kept_urls
                .iter()
                .all(|url| url != "https://www.lawlessitalian.com/"),
            "expected topical language-learning root to be rejected: {:?}",
            kept_urls
        );
        assert!(verification_checks
            .iter()
            .any(|check| { check == "web_local_business_surface_filter_required=true" }));
    }

    #[test]
    fn local_business_structured_metadata_extractor_returns_grounded_restaurants() {
        let source_text = r#"{"@type":"Restaurant","name":"Carbone","streetAddress":"181 Thompson St","postalCode":"10012"}
            {"@type":"Restaurant","name":"Via Carota","streetAddress":"51 Grove St","postalCode":"10014"}
            {"@type":"Restaurant","name":"L'Artusi","streetAddress":"228 W 10th St","postalCode":"10014"}"#;

        assert_eq!(
            extract_structured_local_business_names("New York, NY", source_text, 3),
            vec![
                "Carbone".to_string(),
                "Via Carota".to_string(),
                "L'Artusi".to_string()
            ]
        );
    }

    #[test]
    fn local_business_structured_metadata_extractor_handles_escaped_jsonish_restaurants() {
        let source_text = r#"Guide intro ... \"name\":\"Torrisi Bar \u0026 Restaurant\",\"postalCode\":\"10012\",\"street\":\"275 Mulberry St\" ...
            ... \"name\":\"L'Artusi\",\"postalCode\":\"10014\",\"street\":\"228 W 10th St\" ...
            ... \"name\":\"Via Carota\",\"postalCode\":\"10014\",\"street\":\"51 Grove St\" ..."#;

        assert_eq!(
            extract_structured_local_business_names("New York, NY", source_text, 3),
            vec![
                "Torrisi Bar & Restaurant".to_string(),
                "L'Artusi".to_string(),
                "Via Carota".to_string()
            ]
        );
    }

    #[test]
    fn local_business_expansion_source_selection_prefers_embedded_detail_pages_over_neighboring_categories(
    ) {
        let bundle = WebEvidenceBundle {
            schema_version: 1,
            retrieved_at_ms: 0,
            tool: "web__read".to_string(),
            backend: "edge:read:http".to_string(),
            query: None,
            url: Some("https://www.restaurantji.com/sc/anderson/italian/".to_string()),
            sources: vec![
                WebSource {
                    source_id: "italian-root".to_string(),
                    rank: Some(1),
                    url: "https://www.restaurantji.com/sc/anderson/italian/".to_string(),
                    title: Some(
                        "THE 10 BEST Italian Restaurants in Anderson, SC - 2026 Restaurantji"
                            .to_string(),
                    ),
                    snippet: Some(
                        "Best Italian restaurants in Anderson, SC with reviews, ratings and menus."
                            .to_string(),
                    ),
                    domain: Some("restaurantji.com".to_string()),
                },
                WebSource {
                    source_id: "brothers".to_string(),
                    rank: Some(2),
                    url: "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/"
                        .to_string(),
                    title: Some("Brothers Italian Cuisine".to_string()),
                    snippet: Some(
                        "Italian restaurant in Anderson, SC with pasta, pizza and subs."
                            .to_string(),
                    ),
                    domain: Some("restaurantji.com".to_string()),
                },
                WebSource {
                    source_id: "public-well".to_string(),
                    rank: Some(3),
                    url: "https://www.restaurantji.com/sc/anderson/public-well-cafe-and-pizza-/"
                        .to_string(),
                    title: Some("Public Well Cafe and Pizza".to_string()),
                    snippet: Some(
                        "Italian restaurant in Anderson, SC with pizza, pasta and menu specials."
                            .to_string(),
                    ),
                    domain: Some("restaurantji.com".to_string()),
                },
                WebSource {
                    source_id: "olive-garden".to_string(),
                    rank: Some(4),
                    url: "https://www.restaurantji.com/sc/anderson/olive-garden-/".to_string(),
                    title: Some("Olive Garden Italian Restaurant".to_string()),
                    snippet: Some(
                        "Italian restaurant in Anderson, SC with pasta, soup and breadsticks."
                            .to_string(),
                    ),
                    domain: Some("restaurantji.com".to_string()),
                },
                WebSource {
                    source_id: "burgers".to_string(),
                    rank: Some(5),
                    url: "https://www.restaurantji.com/sc/anderson/burgers/".to_string(),
                    title: Some("Where to Eat Burgers in Anderson".to_string()),
                    snippet: Some(
                        "Burger restaurants in Anderson, SC with reviews and ratings.".to_string(),
                    ),
                    domain: Some("restaurantji.com".to_string()),
                },
            ],
            source_observations: vec![],
            documents: vec![ioi_types::app::agentic::WebDocument {
                source_id: "italian-root".to_string(),
                url: "https://www.restaurantji.com/sc/anderson/italian/".to_string(),
                title: Some(
                    "THE 10 BEST Italian Restaurants in Anderson, SC - 2026 Restaurantji"
                        .to_string(),
                ),
                content_text: "Brothers Italian Cuisine, Public Well Cafe and Pizza, and Olive Garden Italian Restaurant are among the best Italian restaurants in Anderson. Italian Restaurants Nearby. Similar Cuisines In Anderson. Where to Eat Burgers in Anderson."
                    .to_string(),
                content_hash: "hash-italian-root".to_string(),
                quote_spans: vec![],
            }],
            provider_candidates: vec![],
            retrieval_contract: None,
        };

        let selected = select_local_business_expansion_source(
            "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.",
            3,
            "Anderson, SC",
            &[PendingSearchReadSummary {
                url: "https://www.restaurantji.com/sc/anderson/italian/".to_string(),
                title: Some(
                    "THE 10 BEST Italian Restaurants in Anderson, SC - 2026 Restaurantji"
                        .to_string(),
                ),
                excerpt:
                    "Best Italian restaurants in Anderson, SC with reviews, ratings and menus."
                        .to_string(),
            }],
            Some("Anderson, SC"),
            &bundle,
        )
        .expect("expected a query-compatible expansion source");

        assert_eq!(
            selected.0,
            "https://www.restaurantji.com/sc/anderson/italian/"
        );
        assert_eq!(
            selected.3,
            vec![
                "Brothers Italian Cuisine".to_string(),
                "Public Well Cafe and Pizza".to_string(),
                "Olive Garden Italian Restaurant".to_string(),
            ]
        );
    }

    #[test]
    fn local_business_expansion_target_floor_requires_distinct_restaurants() {
        assert!(!local_business_expansion_target_floor_met(
            &["Carbone".to_string()],
            &["Carbone".to_string()],
            3
        ));
        assert!(local_business_expansion_target_floor_met(
            &["Carbone".to_string()],
            &["Via Carota".to_string(), "L'Artusi".to_string()],
            3
        ));
    }

    #[test]
    fn local_business_expansion_contract_allows_current_comparison_queries() {
        let contract = WebRetrievalContract {
            entity_cardinality_min: 3,
            comparison_required: true,
            currentness_required: true,
            runtime_locality_required: true,
            source_independence_min: 2,
            citation_count_min: 1,
            structured_record_preferred: false,
            ordered_collection_preferred: false,
            link_collection_preferred: true,
            canonical_link_out_preferred: true,
            geo_scoped_detail_required: true,
            discovery_surface_required: true,
            entity_diversity_required: true,
            scalar_measure_required: false,
            browser_fallback_allowed: true,
            ..WebRetrievalContract::default()
        };

        assert!(local_business_expansion_query_contract(
            Some(&contract),
            "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.",
        ));
    }
}
