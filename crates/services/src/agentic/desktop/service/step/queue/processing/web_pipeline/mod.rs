use super::super::support::{
    append_final_web_completion_receipts, append_pending_web_success_fallback,
    append_pending_web_success_from_bundle, build_query_constraint_projection_with_locality_hint,
    candidate_source_hints_from_bundle,
    candidate_constraint_compatibility,
    collect_projection_candidate_urls_with_contract_and_locality_hint,
    collect_projection_candidate_urls_with_locality_hint, compact_whitespace,
    compatibility_passes_projection,
    constraint_grounded_probe_query_with_contract_and_hints_and_locality_hint,
    constraint_grounded_probe_query_with_hints_and_locality_hint, constraint_grounded_search_limit,
    constraint_grounded_search_query_with_contract_and_hints_and_locality_hint,
    constraint_grounded_search_query_with_hints_and_locality_hint, effective_locality_scope_hint,
    explicit_query_scope_hint, extract_json_object, fallback_search_summary,
    final_web_completion_facts, is_citable_web_url,
    is_human_challenge_error, is_multi_item_listing_url, is_search_hub_url,
    local_business_detail_display_name, local_business_discovery_source_allowed_with_projection,
    local_business_entity_name_allowed,
    local_business_expansion_query,
    local_business_search_entity_anchor_tokens,
    local_business_search_entity_anchor_tokens_with_contract,
    local_business_target_name_from_source, local_business_target_names_from_sources,
    local_business_target_names_from_attempted_urls, mark_pending_web_attempted,
    mark_pending_web_blocked, merge_pending_search_completion,
    normalized_local_business_target_name, parse_web_evidence_bundle,
    pre_read_candidate_plan_from_bundle_with_contract_and_locality_hint,
    pre_read_candidate_plan_from_bundle_with_contract_and_locality_hint_and_recovery_mode,
    pre_read_candidate_plan_from_bundle_with_locality_hint,
    preferred_pre_read_action_count_with_contract_and_locality_hint,
    preferred_pre_read_action_count_with_locality_hint,
    projection_candidate_url_allowed_with_projection, query_is_generic_headline_collection,
    query_requires_runtime_locality_scope, queue_web_read_from_pipeline,
    queue_web_search_from_pipeline, remaining_pending_web_candidates,
    retrieval_affordances_with_contract_and_locality_hint,
    retrieval_affordances_with_locality_hint, retrieval_contract_prefers_multi_item_cardinality,
    retrieval_contract_requests_comparison, retrieval_contract_requires_runtime_locality,
    retrieval_contract_entity_diversity_required,
    retrieval_contract_required_distinct_domain_floor,
    select_web_pipeline_query_contract, selected_local_business_target_sources,
    selected_source_quality_metrics_with_contract_and_locality_hint,
    selected_source_quality_metrics_with_locality_hint,
    semantic_retrieval_query_contract_with_contract_and_locality_hint,
    semantic_retrieval_query_contract_with_locality_hint, source_anchor_tokens,
    source_has_terminal_error_signal, source_host,
    source_matches_local_business_search_entity_anchor, summarize_search_results,
    synthesize_web_pipeline_reply, synthesize_web_pipeline_reply_hybrid,
    url_structurally_equivalent, web_pipeline_can_queue_probe_search_latency_aware,
    web_pipeline_completion_reason, web_pipeline_grounded_probe_attempt_available,
    web_pipeline_min_sources, web_pipeline_now_ms, RetrievalAffordanceKind,
    WebPipelineCompletionReason, LOCAL_BUSINESS_EXPANSION_QUERY_MARKER_PREFIX,
    WEB_PIPELINE_BUDGET_MS,
};
use super::completion::complete_with_summary;
use super::routing::is_web_research_scope;
use crate::agentic::desktop::service::step::action::{
    emit_completion_gate_status_event, emit_execution_contract_receipt_event_with_observation,
    resolved_intent_id,
};
use crate::agentic::desktop::service::step::signals::analyze_source_record_signals;
use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::{
    AgentState, AgentStatus, PendingSearchCompletion, PendingSearchReadSummary,
};
use ioi_types::app::agentic::{
    AgentTool, InferenceOptions, WebEvidenceBundle, WebRetrievalAffordance,
    WebRetrievalContract, WebSource, WebSourceExpansionAffordance, WebSourceObservation,
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

fn pre_read_synthesis_timeout() -> Duration {
    const DEFAULT_TIMEOUT_MS: u64 = 4_000;
    std::env::var("IOI_WEB_PRE_READ_SYNTHESIS_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_millis(DEFAULT_TIMEOUT_MS))
}

fn local_business_expansion_timeout() -> Duration {
    const DEFAULT_TIMEOUT_MS: u64 = 4_000;
    std::env::var("IOI_WEB_LOCAL_BUSINESS_EXPANSION_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_millis(DEFAULT_TIMEOUT_MS))
}

#[derive(Debug, Clone, Serialize)]
struct PreReadDiscoverySource {
    rank: Option<u32>,
    url: String,
    domain: Option<String>,
    title: Option<String>,
    snippet: Option<String>,
    affordances: Vec<WebRetrievalAffordance>,
    expansion_affordances: Vec<WebSourceExpansionAffordance>,
}

#[derive(Debug, Clone, Serialize)]
struct PreReadSelectionPayload {
    query_contract: String,
    retrieval_contract: WebRetrievalContract,
    required_url_count: usize,
    constraints: Vec<String>,
    sources: Vec<PreReadDiscoverySource>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum PreReadSelectionMode {
    DirectDetail,
    DiscoverySeed,
}

#[derive(Debug, Clone, Deserialize)]
struct PreReadSelectionResponse {
    selection_mode: PreReadSelectionMode,
    urls: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct GroundedEntityExpansionPayload {
    query_contract: String,
    locality_scope: String,
    required_entity_count: usize,
    source_url: String,
    source_title: Option<String>,
    source_text_excerpt: String,
}

#[derive(Debug, Clone, Deserialize)]
struct GroundedEntityExpansionResponse {
    entities: Vec<String>,
}

fn emit_web_contract_receipt(
    service: &DesktopAgentService,
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

fn emit_web_string_receipts(
    service: &DesktopAgentService,
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
    service: &DesktopAgentService,
    pending: &PendingSearchCompletion,
    reason: WebPipelineCompletionReason,
) -> String {
    if let Some(hybrid_summary) =
        synthesize_web_pipeline_reply_hybrid(service, pending, reason).await
    {
        hybrid_summary
    } else {
        synthesize_web_pipeline_reply(pending, reason)
    }
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
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "web_pipeline_pre_read_selection".to_string(),
        query: None,
        url: None,
        sources: discovery_sources.to_vec(),
        source_observations: vec![],
        documents: vec![],
        provider_candidates: vec![],
        retrieval_contract: None,
    };
    candidate_source_hints_from_bundle(&bundle)
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

fn pre_read_url_has_allowed_affordance(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    required_url_count: usize,
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
    url: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    !discovery_source_affordances(
        retrieval_contract,
        query_contract,
        required_url_count,
        source_hints,
        locality_hint,
        url,
        title,
        excerpt,
    )
    .is_empty()
}

fn pre_read_candidate_url_allowed_for_query(
    query_contract: &str,
    min_sources: u32,
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
    url: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    let projection = build_query_constraint_projection_with_locality_hint(
        query_contract,
        min_sources.max(1),
        source_hints,
        locality_hint,
    );
    projection_candidate_url_allowed_with_projection(
        query_contract,
        &projection,
        url,
        title,
        excerpt,
    )
}

fn selected_url_hint<'a>(
    source_hints: &'a [PendingSearchReadSummary],
    url: &str,
) -> Option<&'a PendingSearchReadSummary> {
    let trimmed = url.trim();
    source_hints.iter().find(|hint| {
        let hint_url = hint.url.trim();
        hint_url.eq_ignore_ascii_case(trimmed)
            || url_structurally_equivalent(hint_url, trimmed)
            || source_url_from_metadata_excerpt(&hint.excerpt)
                .map(|resolved| {
                    resolved.eq_ignore_ascii_case(trimmed)
                        || url_structurally_equivalent(&resolved, trimmed)
                })
                .unwrap_or(false)
    })
}

fn filter_local_business_search_bundle_by_entity_anchor(
    bundle: &WebEvidenceBundle,
    retrieval_contract: Option<&WebRetrievalContract>,
    search_query: &str,
    locality_hint: Option<&str>,
    verification_checks: &mut Vec<String>,
) -> WebEvidenceBundle {
    let anchor_preview = local_business_search_entity_anchor_tokens_with_contract(
        search_query,
        retrieval_contract,
        locality_hint,
    );
    if anchor_preview.is_empty() {
        return bundle.clone();
    }

    let mut filtered = bundle.clone();
    let kept_source_ids = filtered
        .sources
        .iter()
        .filter(|source| {
            source_matches_local_business_search_entity_anchor(
                search_query,
                retrieval_contract,
                locality_hint,
                &source.url,
                source.title.as_deref().unwrap_or_default(),
                source.snippet.as_deref().unwrap_or_default(),
            )
        })
        .map(|source| source.source_id.clone())
        .collect::<std::collections::BTreeSet<_>>();

    let before_sources = filtered.sources.len();
    let before_documents = filtered.documents.len();
    filtered
        .sources
        .retain(|source| kept_source_ids.contains(&source.source_id));
    filtered.documents.retain(|doc| {
        kept_source_ids.contains(&doc.source_id)
            || source_matches_local_business_search_entity_anchor(
                search_query,
                retrieval_contract,
                locality_hint,
                &doc.url,
                doc.title.as_deref().unwrap_or_default(),
                &doc.content_text,
            )
    });

    verification_checks.push("web_local_business_entity_filter_required=true".to_string());
    verification_checks.push(format!(
        "web_local_business_entity_filter_anchor={}",
        anchor_preview.join(" ")
    ));
    verification_checks.push(format!(
        "web_local_business_entity_filter_sources_before={}",
        before_sources
    ));
    verification_checks.push(format!(
        "web_local_business_entity_filter_sources_after={}",
        filtered.sources.len()
    ));
    verification_checks.push(format!(
        "web_local_business_entity_filter_documents_before={}",
        before_documents
    ));
    verification_checks.push(format!(
        "web_local_business_entity_filter_documents_after={}",
        filtered.documents.len()
    ));
    verification_checks.push(format!(
        "web_local_business_entity_filter_satisfied={}",
        !filtered.sources.is_empty() || !filtered.documents.is_empty()
    ));

    filtered
}

fn filter_local_business_search_bundle_by_result_surface(
    bundle: &WebEvidenceBundle,
    query_contract: &str,
    min_sources: u32,
    locality_hint: Option<&str>,
    verification_checks: &mut Vec<String>,
) -> WebEvidenceBundle {
    let retrieval_contract = bundle.retrieval_contract.as_ref();
    let projection = build_query_constraint_projection_with_locality_hint(
        query_contract,
        min_sources.max(1),
        &candidate_source_hints_from_bundle(bundle),
        locality_hint,
    );
    if !retrieval_contract_prefers_multi_item_cardinality(retrieval_contract, query_contract)
        || !retrieval_contract_requests_comparison(retrieval_contract, query_contract)
        || !projection.query_facets.locality_sensitive_public_fact
        || !projection.query_facets.grounded_external_required
    {
        return bundle.clone();
    }

    let mut filtered = bundle.clone();
    for source in &filtered.sources {
        let title = source.title.as_deref().unwrap_or_default();
        verification_checks.push(format!(
            "web_local_business_surface_filter_source_before={} | {}",
            source.url.trim(),
            compact_whitespace(title)
        ));
    }
    let kept_source_ids = filtered
        .sources
        .iter()
        .filter(|source| {
            local_business_discovery_source_allowed_with_projection(
                query_contract,
                &projection,
                &source.url,
                source.title.as_deref().unwrap_or_default(),
                source.snippet.as_deref().unwrap_or_default(),
            )
        })
        .map(|source| source.source_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let before_sources = filtered.sources.len();
    let before_documents = filtered.documents.len();

    filtered
        .sources
        .retain(|source| kept_source_ids.contains(&source.source_id));
    for source in &filtered.sources {
        verification_checks.push(format!(
            "web_local_business_surface_filter_source_kept={}",
            source.url.trim()
        ));
    }
    filtered.documents.retain(|doc| {
        kept_source_ids.contains(&doc.source_id)
            || local_business_discovery_source_allowed_with_projection(
                query_contract,
                &projection,
                &doc.url,
                doc.title.as_deref().unwrap_or_default(),
                &doc.content_text,
            )
    });

    verification_checks.push("web_local_business_surface_filter_required=true".to_string());
    verification_checks.push(format!(
        "web_local_business_surface_filter_sources_before={}",
        before_sources
    ));
    verification_checks.push(format!(
        "web_local_business_surface_filter_sources_after={}",
        filtered.sources.len()
    ));
    verification_checks.push(format!(
        "web_local_business_surface_filter_documents_before={}",
        before_documents
    ));
    verification_checks.push(format!(
        "web_local_business_surface_filter_documents_after={}",
        filtered.documents.len()
    ));
    verification_checks.push(format!(
        "web_local_business_surface_filter_satisfied={}",
        !filtered.sources.is_empty() || !filtered.documents.is_empty()
    ));

    filtered
}

fn normalize_grounding_text(input: &str) -> String {
    input
        .to_ascii_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { ' ' })
        .collect::<String>()
}

fn normalized_contains_phrase(haystack: &str, needle: &str) -> bool {
    let compact_haystack = normalize_grounding_text(haystack)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let compact_needle = normalize_grounding_text(needle)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    !compact_needle.is_empty() && compact_haystack.contains(&compact_needle)
}

fn normalized_entity_name(name: &str) -> Option<String> {
    let compact = compact_whitespace(name);
    (!compact.trim().is_empty()).then_some(compact)
}

fn entity_expansion_target_marker(entity_name: &str) -> Option<String> {
    normalized_entity_name(entity_name)
        .map(|normalized| format!("{}{}", ENTITY_EXPANSION_TARGET_MARKER_PREFIX, normalized))
}

fn entity_expansion_query_marker(query: &str) -> Option<String> {
    let compact = compact_whitespace(query);
    (!compact.trim().is_empty()).then_some(format!(
        "{}{}",
        ENTITY_EXPANSION_QUERY_MARKER_PREFIX, compact
    ))
}

fn entity_targets_from_attempted_urls(attempted_urls: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for attempted in attempted_urls {
        let Some(raw_target) = attempted
            .trim()
            .strip_prefix(ENTITY_EXPANSION_TARGET_MARKER_PREFIX)
        else {
            continue;
        };
        let Some(target) = normalized_entity_name(raw_target) else {
            continue;
        };
        let key = target.to_ascii_lowercase();
        if !seen.insert(key) {
            continue;
        }
        out.push(target);
    }
    out
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

fn entity_expansion_target_floor_met(
    existing_targets: &[String],
    new_targets: &[String],
    required_count: usize,
) -> bool {
    merged_entity_targets(existing_targets, new_targets).len() >= required_count.max(1)
}

fn source_matches_entity_name(source: &PendingSearchReadSummary, entity_name: &str) -> bool {
    let Some(entity) = normalized_entity_name(entity_name) else {
        return false;
    };
    let observed = format!(
        "{} {} {}",
        source.url,
        source.title.as_deref().unwrap_or_default(),
        source.excerpt
    );
    normalized_contains_phrase(&observed, &entity)
}

fn matched_entity_target_names(
    targets: &[String],
    sources: &[PendingSearchReadSummary],
) -> Vec<String> {
    let mut matched = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for target in targets {
        if !sources.iter().any(|source| source_matches_entity_name(source, target)) {
            continue;
        }
        let Some(normalized) = normalized_entity_name(target) else {
            continue;
        };
        let key = normalized.to_ascii_lowercase();
        if !seen.insert(key) {
            continue;
        }
        matched.push(normalized);
    }
    matched
}

fn selected_entity_target_sources(
    targets: &[String],
    sources: &[PendingSearchReadSummary],
    required_count: usize,
) -> Vec<PendingSearchReadSummary> {
    let mut selected = Vec::new();
    for target in targets {
        if selected.len() >= required_count.max(1) {
            break;
        }
        let Some(source) = sources
            .iter()
            .find(|source| source_matches_entity_name(source, target))
        else {
            continue;
        };
        let trimmed = source.url.trim();
        if trimmed.is_empty() {
            continue;
        }
        if selected.iter().any(|existing: &PendingSearchReadSummary| {
            existing.url.eq_ignore_ascii_case(trimmed)
                || url_structurally_equivalent(existing.url.as_str(), trimmed)
        }) {
            continue;
        }
        selected.push(PendingSearchReadSummary {
            url: trimmed.to_string(),
            title: source.title.clone(),
            excerpt: source.excerpt.trim().to_string(),
        });
    }
    selected
}

fn entity_detail_search_query(
    entity_name: &str,
    query_contract: &str,
    scope: Option<&str>,
) -> Option<String> {
    let entity_name = normalized_entity_name(entity_name)?;
    let mut parts = vec![format!("\"{}\"", entity_name)];
    let contract = compact_whitespace(query_contract);
    if !contract.trim().is_empty() {
        parts.push(contract);
    }
    if let Some(scope) = scope
        .map(compact_whitespace)
        .filter(|value| !value.trim().is_empty())
    {
        let has_scope = parts.iter().any(|part| normalized_contains_phrase(part, &scope));
        if !has_scope {
            parts.push(format!("\"{}\"", scope));
        }
    }
    Some(compact_whitespace(&parts.join(" ")))
}

fn selected_source_structural_metrics(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    min_sources: u32,
    selected_urls: &[String],
    source_hints: &[PendingSearchReadSummary],
) -> (usize, usize, usize, usize, usize, bool, Vec<String>) {
    let mut normalized = Vec::new();
    for selected in selected_urls {
        let _ = push_unique_selected_url(&mut normalized, selected);
    }

    let total_sources = normalized.len();
    let locality_floor_satisfied =
        !retrieval_contract_requires_runtime_locality(retrieval_contract, query_contract)
            || explicit_query_scope_hint(query_contract).is_some()
            || effective_locality_scope_hint(None).is_some();
    let locality_compatible_sources = if locality_floor_satisfied {
        total_sources
    } else {
        0
    };
    let distinct_domains = normalized
        .iter()
        .filter_map(|selected| selected_url_domain_key(source_hints, selected))
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let required_source_count = min_sources.max(1) as usize;
    let required_domain_floor =
        if retrieval_contract_entity_diversity_required(retrieval_contract, query_contract) {
            0
        } else {
            retrieval_contract_required_distinct_domain_floor(retrieval_contract, query_contract)
                .min(required_source_count)
                .max(usize::from(required_source_count > 1))
        };
    let quality_floor_met = total_sources >= required_source_count
        && locality_floor_satisfied
        && (required_domain_floor == 0 || distinct_domains >= required_domain_floor);

    (
        total_sources,
        total_sources,
        locality_compatible_sources,
        distinct_domains,
        0,
        quality_floor_met,
        Vec::new(),
    )
}

fn local_business_expansion_query_contract(
    retrieval_contract: Option<&WebRetrievalContract>,
    _query_contract: &str,
) -> bool {
    retrieval_contract
        .map(|contract| {
            crate::agentic::web::contract_requires_geo_scoped_entity_expansion(contract)
                && contract.comparison_required
                && contract.runtime_locality_required
        })
        .unwrap_or(false)
}

fn local_business_expansion_source_marker(source_url: &str) -> String {
    format!(
        "ioi://local-business-expansion/source/{}",
        source_url.trim()
    )
}

fn local_business_expansion_query_marker(query: &str) -> String {
    format!(
        "{}{}",
        LOCAL_BUSINESS_EXPANSION_QUERY_MARKER_PREFIX,
        query.trim()
    )
}

fn local_business_expansion_done_marker() -> &'static str {
    "ioi://local-business-expansion/done"
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

fn local_business_expansion_target_floor_met(
    existing_targets: &[String],
    new_targets: &[String],
    required_count: usize,
) -> bool {
    merged_local_business_targets(existing_targets, new_targets).len() >= required_count.max(1)
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

fn local_business_expansion_source_excerpt(
    bundle: &WebEvidenceBundle,
    source_id: &str,
    source_url: &str,
    source_text: &str,
) -> String {
    let hinted = bundle.sources.iter().find(|source| {
        source.source_id == source_id
            || source.url.eq_ignore_ascii_case(source_url)
            || url_structurally_equivalent(source.url.as_str(), source_url)
    });
    if let Some(snippet) = hinted
        .and_then(|source| source.snippet.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return snippet.to_string();
    }

    source_text.chars().take(320).collect()
}

fn structured_local_business_target_sources_from_bundle(
    query_contract: &str,
    scope: &str,
    bundle: &WebEvidenceBundle,
    required_count: usize,
) -> Vec<PendingSearchReadSummary> {
    let bundle_source_hints = candidate_source_hints_from_bundle(bundle);
    let bundle_targets = local_business_target_names_from_sources(
        &bundle_source_hints,
        Some(scope),
        required_count.saturating_mul(4),
    );
    if bundle_targets.is_empty() {
        return Vec::new();
    }

    selected_local_business_target_sources(
        query_contract,
        &bundle_targets,
        &bundle_source_hints,
        Some(scope),
        required_count,
    )
}

fn select_local_business_expansion_source(
    query_contract: &str,
    min_sources: u32,
    scope: &str,
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
    bundle: &WebEvidenceBundle,
) -> Option<(
    String,
    Option<String>,
    String,
    Vec<String>,
    Vec<PendingSearchReadSummary>,
)> {
    let projection = build_query_constraint_projection_with_locality_hint(
        query_contract,
        min_sources.max(1),
        source_hints,
        locality_hint,
    );
    let required_count = min_sources.max(1) as usize;

    for doc in &bundle.documents {
        let source_url = doc.url.trim();
        let source_text = doc.content_text.trim();
        if source_url.is_empty() || source_text.is_empty() {
            continue;
        }
        let source_title = doc.title.as_deref().or_else(|| {
            bundle
                .sources
                .iter()
                .find(|source| {
                    source.source_id == doc.source_id
                        || source.url.eq_ignore_ascii_case(source_url)
                        || url_structurally_equivalent(source.url.as_str(), source_url)
                })
                .and_then(|source| source.title.as_deref())
        });
        let source_excerpt = local_business_expansion_source_excerpt(
            bundle,
            &doc.source_id,
            source_url,
            source_text,
        );
        let structured_target_sources = structured_local_business_target_sources_from_bundle(
            query_contract,
            scope,
            bundle,
            required_count,
        );
        let mut structured_candidates = structured_target_sources
            .into_iter()
            .filter_map(|source| local_business_detail_display_name(&source, Some(scope)))
            .collect::<Vec<_>>();
        structured_candidates = merged_local_business_targets(
            &structured_candidates,
            &extract_structured_local_business_names(scope, source_text, required_count),
        );
        let guide_detected = structured_candidates.len() >= 2
            || is_multi_item_listing_url(source_url.trim())
            || source_looks_like_multi_item_restaurant_guide(source_url, source_title, source_text);
        if !guide_detected {
            continue;
        }

        if !is_citable_web_url(source_url) || is_search_hub_url(source_url) {
            continue;
        }
        let compatibility_observed_excerpt = compact_whitespace(
            format!(
                "{} {}",
                source_excerpt,
                source_text.chars().take(512).collect::<String>()
            )
            .trim(),
        );
        if source_has_terminal_error_signal(
            source_url,
            source_title.unwrap_or_default(),
            &compatibility_observed_excerpt,
        ) {
            continue;
        }
        let compatibility = candidate_constraint_compatibility(
            &projection.constraints,
            &projection.query_facets,
            &projection.query_native_tokens,
            &projection.query_tokens,
            &projection.locality_tokens,
            projection.locality_scope.is_some(),
            source_url,
            source_title.unwrap_or_default(),
            &compatibility_observed_excerpt,
        );
        if !compatibility_passes_projection(&projection, &compatibility) {
            continue;
        }
        let semantic_query_tokens = projection
            .query_native_tokens
            .iter()
            .filter(|token| !projection.locality_tokens.contains(*token))
            .filter(|token| {
                !LOCAL_BUSINESS_EXPANSION_GENERIC_QUERY_TOKENS.contains(&token.as_str())
            })
            .cloned()
            .collect::<BTreeSet<_>>();
        if !semantic_query_tokens.is_empty() {
            let source_tokens = source_anchor_tokens(
                source_url,
                source_title.unwrap_or_default(),
                &compatibility_observed_excerpt,
            );
            let semantic_overlap = semantic_query_tokens
                .iter()
                .filter(|token| source_tokens.contains(*token))
                .count();
            if semantic_overlap == 0 {
                continue;
            }
        }

        return Some((
            source_url.to_string(),
            source_title.map(str::to_string),
            source_text.to_string(),
            structured_candidates,
            structured_local_business_target_sources_from_bundle(
                query_contract,
                scope,
                bundle,
                required_count,
            ),
        ));
    }

    None
}

fn parse_jsonish_string_value(source_text: &str, start_idx: usize) -> Option<(String, usize)> {
    let bytes = source_text.as_bytes();
    if bytes.get(start_idx).copied() != Some(b'"') {
        return None;
    }

    let mut idx = start_idx + 1;
    let mut value = String::new();
    let mut escape = false;
    while idx < bytes.len() {
        let ch = bytes[idx] as char;
        idx += 1;
        if escape {
            match ch {
                '"' | '\\' | '/' => value.push(ch),
                'b' => value.push('\u{0008}'),
                'f' => value.push('\u{000C}'),
                'n' => value.push('\n'),
                'r' => value.push('\r'),
                't' => value.push('\t'),
                'u' => {
                    if idx + 4 <= bytes.len() {
                        if let Ok(raw) = std::str::from_utf8(&bytes[idx..idx + 4]) {
                            if let Ok(codepoint) = u16::from_str_radix(raw, 16) {
                                if let Some(decoded) = char::from_u32(codepoint as u32) {
                                    value.push(decoded);
                                }
                            }
                        }
                        idx += 4;
                    }
                }
                _ => value.push(ch),
            }
            escape = false;
            continue;
        }
        if ch == '\\' {
            escape = true;
            continue;
        }
        if ch == '"' {
            return Some((value, idx));
        }
        value.push(ch);
    }
    None
}

fn extract_jsonish_keyed_string_values(source_text: &str, key: &str) -> Vec<(usize, String)> {
    let pattern = format!("\"{}\"", key);
    let mut values = Vec::new();
    let mut cursor = 0usize;

    while let Some(relative_idx) = source_text[cursor..].find(&pattern) {
        let key_start = cursor + relative_idx;
        let after_key = key_start + pattern.len();
        let Some(colon_relative_idx) = source_text[after_key..].find(':') else {
            break;
        };
        let mut value_start = after_key + colon_relative_idx + 1;
        while let Some(ch) = source_text[value_start..].chars().next() {
            if ch.is_whitespace() {
                value_start += ch.len_utf8();
                continue;
            }
            break;
        }
        let Some((value, consumed_idx)) = parse_jsonish_string_value(source_text, value_start)
        else {
            cursor = after_key;
            continue;
        };
        values.push((key_start, value));
        cursor = consumed_idx;
    }

    values
}

fn decode_jsonish_unicode_escapes(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut decoded = String::with_capacity(input.len());
    let mut idx = 0usize;

    while idx < bytes.len() {
        if bytes[idx] == b'\\' && idx + 5 < bytes.len() && bytes[idx + 1] == b'u' {
            if let Ok(raw) = std::str::from_utf8(&bytes[idx + 2..idx + 6]) {
                if let Ok(codepoint) = u16::from_str_radix(raw, 16) {
                    if let Some(ch) = char::from_u32(codepoint as u32) {
                        decoded.push(ch);
                        idx += 6;
                        continue;
                    }
                }
            }
        }

        decoded.push(bytes[idx] as char);
        idx += 1;
    }

    decoded
}

fn normalized_jsonish_source_text(source_text: &str) -> Option<String> {
    let normalized = source_text
        .replace("\\\\\"", "\"")
        .replace("\\\"", "\"")
        .replace("\\\\u", "\\u");
    let decoded = decode_jsonish_unicode_escapes(&normalized);
    (decoded != source_text).then_some(decoded)
}

fn extract_structured_local_business_names(
    scope: &str,
    source_text: &str,
    required_count: usize,
) -> Vec<String> {
    let mut extracted = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut candidate_texts = vec![source_text.to_string()];
    if let Some(normalized) = normalized_jsonish_source_text(source_text) {
        candidate_texts.push(normalized);
    }

    for candidate_text in candidate_texts {
        let source_text_lower = candidate_text.to_ascii_lowercase();

        for (position, raw_name) in extract_jsonish_keyed_string_values(&candidate_text, "name") {
            let Some(name) = normalized_local_business_target_name(&raw_name) else {
                continue;
            };
            if name.eq_ignore_ascii_case(scope) {
                continue;
            }
            if !local_business_entity_name_allowed(&name, Some(scope)) {
                continue;
            }
            let token_count = name
                .split(|ch: char| !ch.is_ascii_alphanumeric())
                .filter(|token| !token.trim().is_empty())
                .count();
            if token_count == 0 || token_count > 6 {
                continue;
            }
            let lower_name = name.to_ascii_lowercase();
            if lower_name.contains("infatuation")
                || lower_name.contains("eater")
                || lower_name.contains("new york city")
                || lower_name.contains("restaurant guide")
            {
                continue;
            }
            let window_start = position.saturating_sub(128);
            let window_end = position.saturating_add(384).min(source_text_lower.len());
            let window = &source_text_lower[window_start..window_end];
            let structured_business_markers = window.contains("streetaddress")
                || window.contains("postalcode")
                || window.contains("servescuisine")
                || window.contains("@type\":\"restaurant")
                || window.contains("\"menu\"")
                || window.contains("\"telephone\"");
            if !structured_business_markers {
                continue;
            }
            if !normalized_contains_phrase(&candidate_text, &name) {
                continue;
            }
            let dedup_key = lower_name;
            if !seen.insert(dedup_key) {
                continue;
            }
            extracted.push(name);
            if extracted.len() >= required_count {
                return extracted;
            }
        }
    }

    extracted
}

fn lint_local_business_expansion_restaurants(
    scope: &str,
    source_text: &str,
    restaurants: &[String],
    required_count: usize,
) -> Result<Vec<String>, String> {
    let mut normalized = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for restaurant in restaurants {
        let trimmed = restaurant.trim();
        if trimmed.is_empty() {
            continue;
        }
        let key = trimmed.to_ascii_lowercase();
        if !seen.insert(key) {
            continue;
        }
        if trimmed.eq_ignore_ascii_case(scope) {
            continue;
        }
        let token_count = trimmed
            .split(|ch: char| !ch.is_ascii_alphanumeric())
            .filter(|token| !token.trim().is_empty())
            .count();
        if token_count == 0 {
            continue;
        }
        if !normalized_contains_phrase(source_text, trimmed) {
            return Err(format!(
                "restaurant '{}' was not grounded in the source text",
                trimmed
            ));
        }
        normalized.push(trimmed.to_string());
        if normalized.len() >= required_count {
            break;
        }
    }

    if normalized.is_empty() {
        return Err("no grounded restaurant names were returned".to_string());
    }
    Ok(normalized)
}

fn local_business_menu_queries(
    query_contract: &str,
    restaurants: &[String],
    scope: &str,
) -> Vec<String> {
    restaurants
        .iter()
        .filter_map(|restaurant| {
            local_business_expansion_query(restaurant, query_contract, Some(scope))
        })
        .collect()
}

async fn synthesize_local_business_expansion_restaurants(
    service: &DesktopAgentService,
    query_contract: &str,
    scope: &str,
    required_count: usize,
    source_url: &str,
    source_title: Option<&str>,
    source_text: &str,
) -> Result<Vec<String>, String> {
    synthesize_grounded_entity_targets(
        service,
        query_contract,
        scope,
        required_count,
        source_url,
        source_title,
        source_text,
    )
    .await
}

fn lint_grounded_entity_targets(
    scope: &str,
    source_text: &str,
    entities: &[String],
    required_count: usize,
) -> Result<Vec<String>, String> {
    let mut normalized = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for entity in entities {
        let Some(candidate) = normalized_entity_name(entity) else {
            continue;
        };
        if !local_business_entity_name_allowed(&candidate, Some(scope)) {
            return Err(format!(
                "entity '{}' did not satisfy structural local-business validation",
                candidate
            ));
        }
        let key = candidate.to_ascii_lowercase();
        if !seen.insert(key) {
            continue;
        }
        if !normalized_contains_phrase(source_text, &candidate) {
            return Err(format!(
                "entity '{}' was not explicitly grounded in the source text",
                candidate
            ));
        }
        normalized.push(candidate);
        if normalized.len() >= required_count {
            break;
        }
    }
    if normalized.is_empty() {
        return Err("no grounded entities were returned".to_string());
    }
    Ok(normalized)
}

async fn synthesize_grounded_entity_targets(
    service: &DesktopAgentService,
    query_contract: &str,
    scope: &str,
    required_count: usize,
    source_url: &str,
    source_title: Option<&str>,
    source_text: &str,
) -> Result<Vec<String>, String> {
    let payload = GroundedEntityExpansionPayload {
        query_contract: query_contract.trim().to_string(),
        locality_scope: scope.trim().to_string(),
        required_entity_count: required_count,
        source_url: source_url.trim().to_string(),
        source_title: source_title.map(str::to_string),
        source_text_excerpt: source_text
            .chars()
            .take(WEB_PIPELINE_LOCAL_BUSINESS_EXPANSION_SOURCE_TEXT_CHARS)
            .collect(),
    };
    let payload_json = serde_json::to_string_pretty(&payload)
        .map_err(|err| format!("failed to serialize grounded entity expansion payload: {}", err))?;
    let timeout = local_business_expansion_timeout();
    let mut feedback: Option<String> = None;
    let mut last_error = "grounded entity expansion failed".to_string();

    let structured = extract_structured_local_business_names(scope, source_text, required_count);
    if !structured.is_empty() {
        return lint_grounded_entity_targets(scope, source_text, &structured, required_count);
    }

    for attempt in 1..=WEB_PIPELINE_LOCAL_BUSINESS_EXPANSION_MAX_ATTEMPTS {
        let prompt = if let Some(previous_error) = feedback.as_deref() {
            format!(
                "Return JSON only with schema {{\"entities\":[string]}}.\n\
                 You are in CEC State 3 (Grounded Entity Expansion).\n\
                 Prior output failed lint: {}\n\
                 Re-extract only entities explicitly named in the source text that satisfy the query contract.\n\
                 Payload:\n{}",
                previous_error, payload_json
            )
        } else {
            format!(
                "Return JSON only with schema {{\"entities\":[string]}}.\n\
                 You are in CEC State 3 (Grounded Entity Expansion).\n\
                 Extract up to {} distinct entities explicitly named in the source text that satisfy the query contract.\n\
                 Requirements:\n\
                 - Use only entities explicitly named in the source text.\n\
                 - Respect the typed retrieval contract already encoded in the query contract.\n\
                 - Respect the locality scope already encoded in the query contract.\n\
                 - Return entity display names only, with no explanations.\n\
                 Payload:\n{}",
                required_count, payload_json
            )
        };
        let options = InferenceOptions {
            tools: vec![],
            temperature: 0.0,
            json_mode: true,
            max_tokens: WEB_PIPELINE_LOCAL_BUSINESS_EXPANSION_MAX_TOKENS,
        };
        let airlocked_prompt = match service
            .prepare_cloud_inference_input(
                None,
                "desktop_agent",
                "web_pipeline_grounded_entity_expansion",
                prompt.as_bytes(),
            )
            .await
        {
            Ok(bytes) => bytes,
            Err(err) => {
                last_error = format!("grounded entity expansion airlock failed: {}", err);
                feedback = Some(last_error.clone());
                if attempt == WEB_PIPELINE_LOCAL_BUSINESS_EXPANSION_MAX_ATTEMPTS {
                    break;
                }
                continue;
            }
        };
        let raw = match tokio::time::timeout(
            timeout,
            service
                .reasoning_inference
                .execute_inference([0u8; 32], &airlocked_prompt, options),
        )
        .await
        {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(err)) => {
                last_error = format!("grounded entity expansion inference failed: {}", err);
                feedback = Some(last_error.clone());
                if attempt == WEB_PIPELINE_LOCAL_BUSINESS_EXPANSION_MAX_ATTEMPTS {
                    break;
                }
                continue;
            }
            Err(_) => {
                last_error = format!(
                    "grounded entity expansion timed out after {}ms",
                    timeout.as_millis()
                );
                feedback = Some(last_error.clone());
                if attempt == WEB_PIPELINE_LOCAL_BUSINESS_EXPANSION_MAX_ATTEMPTS {
                    break;
                }
                continue;
            }
        };
        let text = match String::from_utf8(raw) {
            Ok(text) => text,
            Err(err) => {
                last_error = format!("grounded entity expansion response was not UTF-8: {}", err);
                feedback = Some(last_error.clone());
                if attempt == WEB_PIPELINE_LOCAL_BUSINESS_EXPANSION_MAX_ATTEMPTS {
                    break;
                }
                continue;
            }
        };
        let json_text = extract_json_object(&text).unwrap_or(text.as_str());
        let parsed: GroundedEntityExpansionResponse = match serde_json::from_str(json_text) {
            Ok(parsed) => parsed,
            Err(err) => {
                last_error = format!(
                    "grounded entity expansion returned invalid JSON schema: {}",
                    err
                );
                feedback = Some(last_error.clone());
                if attempt == WEB_PIPELINE_LOCAL_BUSINESS_EXPANSION_MAX_ATTEMPTS {
                    break;
                }
                continue;
            }
        };

        match lint_grounded_entity_targets(scope, source_text, &parsed.entities, required_count) {
            Ok(validated) => return Ok(validated),
            Err(err) => {
                last_error = err;
                feedback = Some(last_error.clone());
                if attempt == WEB_PIPELINE_LOCAL_BUSINESS_EXPANSION_MAX_ATTEMPTS {
                    break;
                }
            }
        }
    }

    Err(last_error)
}

pub(super) async fn maybe_queue_local_business_expansion_searches(
    service: &DesktopAgentService,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    pending: &mut PendingSearchCompletion,
    bundle: &WebEvidenceBundle,
    verification_checks: &mut Vec<String>,
) -> Result<bool, TransactionError> {
    let query_contract = if pending.query_contract.trim().is_empty() {
        pending.query.trim()
    } else {
        pending.query_contract.trim()
    };
    let retrieval_contract = pending.retrieval_contract.as_ref();
    if query_contract.is_empty()
        || !local_business_expansion_query_contract(retrieval_contract, query_contract)
    {
        return Ok(false);
    }

    let locality_hint =
        if retrieval_contract_requires_runtime_locality(retrieval_contract, query_contract) {
            effective_locality_scope_hint(None)
        } else {
            None
        };
    let required_count = pending.min_sources.max(1) as usize;
    let existing_targets = entity_targets_from_attempted_urls(&pending.attempted_urls);
    let existing_matched_targets =
        matched_entity_target_names(&existing_targets, &pending.successful_reads);
    if existing_matched_targets.len() >= required_count {
        return Ok(false);
    }

    let projection = build_query_constraint_projection_with_locality_hint(
        query_contract,
        pending.min_sources,
        &pending.successful_reads,
        locality_hint.as_deref(),
    );
    let Some(scope) = projection
        .locality_scope
        .clone()
        .or_else(|| locality_hint.clone())
    else {
        return Ok(false);
    };

    let mut selected_source: Option<(String, Option<String>, String, Vec<String>)> = None;
    for doc in &bundle.documents {
        let source_url = doc.url.trim();
        let source_text = doc.content_text.trim();
        if source_url.is_empty()
            || source_text.is_empty()
            || !is_citable_web_url(source_url)
            || is_search_hub_url(source_url)
        {
            continue;
        }
        let source_title = doc.title.clone().or_else(|| {
            bundle
                .sources
                .iter()
                .find(|source| {
                    source.source_id == doc.source_id
                        || source.url.eq_ignore_ascii_case(source_url)
                        || url_structurally_equivalent(source.url.as_str(), source_url)
                })
                .and_then(|source| source.title.clone())
        });
        if source_has_terminal_error_signal(
            source_url,
            source_title.as_deref().unwrap_or_default(),
            source_text,
        ) {
            continue;
        }
        let source_marker = local_business_expansion_source_marker(source_url);
        if pending
            .attempted_urls
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&source_marker))
        {
            continue;
        }
        let Ok(entities) = synthesize_grounded_entity_targets(
            service,
            query_contract,
            &scope,
            required_count,
            source_url,
            source_title.as_deref(),
            source_text,
        )
        .await
        else {
            continue;
        };
        if entities.is_empty() {
            continue;
        }
        pending.attempted_urls.push(source_marker);
        selected_source = Some((
            source_url.to_string(),
            source_title,
            source_text.to_string(),
            entities,
        ));
        break;
    }

    let Some((source_url, _source_title, _source_text, entities)) = selected_source else {
        verification_checks
            .push("web_local_business_expansion_query_compatible_source=false".to_string());
        return Ok(false);
    };

    verification_checks.push("web_local_business_expansion_required=true".to_string());
    verification_checks
        .push("web_local_business_expansion_query_compatible_source=true".to_string());
    verification_checks.push(format!(
        "web_local_business_expansion_source_url={}",
        source_url
    ));
    verification_checks.push(format!("web_local_business_expansion_scope={}", scope));
    verification_checks.push(format!(
        "web_local_business_expansion_guide_detected={}",
        entities.len() >= 2
    ));
    verification_checks.push(format!(
        "web_local_business_expansion_structured_candidate_count={}",
        entities.len()
    ));
    verification_checks.push(format!(
        "web_local_business_expansion_structured_target_floor_met={}",
        entity_expansion_target_floor_met(&existing_targets, &entities, required_count)
    ));
    let expansion_target_floor_met =
        entity_expansion_target_floor_met(&existing_targets, &entities, required_count);
    let total_targets = merged_entity_targets(&existing_targets, &entities);
    let mut queued = 0usize;
    let search_limit = constraint_grounded_search_limit(query_contract, pending.min_sources);
    for entity in &entities {
        let Some(target_marker) = entity_expansion_target_marker(entity) else {
            continue;
        };
        if pending
            .attempted_urls
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&target_marker))
        {
            continue;
        }
        let Some(search_query) = entity_detail_search_query(entity, query_contract, Some(&scope))
        else {
            continue;
        };
        let Some(query_marker) = entity_expansion_query_marker(&search_query) else {
            continue;
        };
        if pending
            .attempted_urls
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&query_marker))
        {
            continue;
        }
        pending.attempted_urls.push(target_marker);
        pending.attempted_urls.push(query_marker);
        if queue_web_search_from_pipeline(
            agent_state,
            session_id,
            &search_query,
            Some(query_contract),
            pending.retrieval_contract.as_ref(),
            search_limit,
        )? {
            queued = queued.saturating_add(1);
        }
    }
    verification_checks.push(format!(
        "web_local_business_expansion_candidates={}",
        entities.join(" | ")
    ));
    verification_checks.push(format!(
        "web_local_business_expansion_target_total={}",
        total_targets.len()
    ));
    verification_checks.push(format!(
        "web_local_business_expansion_target_floor_met={}",
        expansion_target_floor_met
    ));
    verification_checks.push(format!("web_local_business_expansion_queued={}", queued));
    verification_checks.push(format!(
        "web_local_business_expansion_satisfied={}",
        queued > 0 && expansion_target_floor_met
    ));
    if queued > 0 && expansion_target_floor_met {
        pending
            .attempted_urls
            .push(local_business_expansion_done_marker().to_string());
    }

    Ok(queued > 0)
}

fn payload_allows_external_article_url(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    required_url_count: usize,
    discovery_sources: &[WebSource],
    url: &str,
    allowed_hosts: &std::collections::BTreeSet<String>,
) -> bool {
    let trimmed = url.trim();
    let Some(host) = normalized_domain_key(trimmed) else {
        return false;
    };
    if !allowed_hosts.contains(&host) {
        return false;
    }
    let source_hints = discovery_source_hints(discovery_sources);
    let locality_hint =
        if retrieval_contract_requires_runtime_locality(retrieval_contract, query_contract) {
            effective_locality_scope_hint(None)
        } else {
            None
        };
    let Some(matched_hint) = selected_url_hint(&source_hints, trimmed) else {
        return false;
    };
    let hint_url = matched_hint.url.trim();
    if !hint_url.eq_ignore_ascii_case(trimmed) && !url_structurally_equivalent(hint_url, trimmed) {
        return false;
    }
    let title = matched_hint.title.as_deref().unwrap_or_default();
    let excerpt = matched_hint.excerpt.as_str();
    pre_read_candidate_url_allowed_for_query(
        query_contract,
        required_url_count as u32,
        &source_hints,
        locality_hint.as_deref(),
        trimmed,
        title,
        excerpt,
    )
}

fn pre_read_candidate_url_allowed(raw: &str) -> bool {
    let trimmed = raw.trim();
    !trimmed.is_empty()
        && is_citable_web_url(trimmed)
        && !is_search_hub_url(trimmed)
        && !is_multi_item_listing_url(trimmed)
        && looks_like_deep_article_url(trimmed)
}

fn looks_like_deep_article_url(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return false;
    }
    if is_search_hub_url(trimmed) {
        return false;
    }
    let Ok(parsed) = Url::parse(trimmed) else {
        return false;
    };
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return false;
    }
    let Some(host) = parsed.host_str() else {
        return false;
    };
    if host.trim().is_empty() {
        return false;
    }

    let normalized_path = parsed.path().trim_matches('/').to_ascii_lowercase();
    if normalized_path.is_empty() {
        return false;
    }
    let segments = normalized_path
        .split('/')
        .filter(|segment| !segment.trim().is_empty())
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return false;
    }
    if segments
        .iter()
        .any(|segment| segment.contains("menu") || segment.contains("menus"))
    {
        return true;
    }
    if segments.len() <= 2
        && segments
            .first()
            .copied()
            .map(|segment| {
                matches!(
                    segment,
                    "show" | "shows" | "watch" | "video" | "videos" | "live" | "tv"
                )
            })
            .unwrap_or(false)
    {
        return false;
    }

    let path_hub_markers = [
        "news",
        "latest",
        "home",
        "homepage",
        "index",
        "index.html",
        "video",
        "videos",
        "live",
        "world",
        "us",
        "top-stories",
        "top-news",
    ];
    let marker_segment = |segment: &str| {
        if segment.is_empty() {
            return false;
        }
        if path_hub_markers.contains(&segment) {
            return true;
        }
        segment
            .split('-')
            .all(|token| !token.is_empty() && path_hub_markers.contains(&token))
    };
    if path_hub_markers
        .iter()
        .any(|marker| normalized_path == *marker)
    {
        return false;
    }
    if segments
        .last()
        .map(|segment| marker_segment(segment))
        .unwrap_or(false)
    {
        return false;
    }
    if segments
        .last()
        .copied()
        .map(looks_like_placeholder_article_slug_segment)
        .unwrap_or(false)
    {
        return false;
    }
    if segments.len() <= 3
        && segments
            .first()
            .map(|segment| matches!(*segment, "c" | "channel" | "user"))
            .unwrap_or(false)
    {
        return false;
    }

    true
}

fn looks_like_placeholder_article_slug_segment(segment: &str) -> bool {
    let trimmed = segment.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return false;
    }
    let tokenized = trimmed
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    if tokenized.is_empty() {
        return false;
    }
    let role_tokens = [
        "article", "story", "news", "headline", "post", "report", "item",
    ];
    let placeholder_tokens = [
        "title",
        "slug",
        "name",
        "text",
        "content",
        "page",
        "link",
        "sample",
        "placeholder",
    ];
    let has_role = tokenized.iter().any(|token| role_tokens.contains(token));
    let has_placeholder = tokenized
        .iter()
        .any(|token| placeholder_tokens.contains(token));
    let all_generic = tokenized
        .iter()
        .all(|token| role_tokens.contains(token) || placeholder_tokens.contains(token));

    tokenized.len() >= 2 && has_role && has_placeholder && all_generic
}

fn lint_pre_read_payload_urls(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    discovery_sources: &[WebSource],
    source_observations: &[WebSourceObservation],
    selection_mode: &PreReadSelectionMode,
    urls: &[String],
    required_count: usize,
) -> Result<Vec<String>, String> {
    if !pre_read_selection_mode_permitted(retrieval_contract, query_contract, selection_mode) {
        return Err(format!(
            "selection mode {:?} is not permitted by the typed retrieval contract",
            selection_mode
        ));
    }

    let mut normalized = Vec::new();
    for url in urls {
        let trimmed = url.trim();
        if trimmed.is_empty()
            || normalized
                .iter()
                .any(|existing: &String| existing.eq_ignore_ascii_case(trimmed))
        {
            continue;
        }
        normalized.push(trimmed.to_string());
    }

    let expected_count = match selection_mode {
        PreReadSelectionMode::DirectDetail => required_count,
        PreReadSelectionMode::DiscoverySeed => 1,
    };
    if normalized.len() != expected_count {
        return Err(format!(
            "expected exactly {} URLs but received {}",
            expected_count,
            normalized.len()
        ));
    }

    let source_hints = discovery_source_hints(discovery_sources);
    let entity_diversity_required =
        retrieval_contract_entity_diversity_required(retrieval_contract, query_contract);
    let required_domain_floor = if entity_diversity_required {
        0
    } else {
        retrieval_contract_required_distinct_domain_floor(retrieval_contract, query_contract)
            .min(expected_count)
            .max(usize::from(expected_count > 1))
    };
    let mut distinct_targets = std::collections::BTreeSet::new();
    let mut distinct_domains = std::collections::BTreeSet::new();
    for url in &normalized {
        let trimmed = url.trim();
        let Some(_matched_hint) = selected_url_hint(&source_hints, trimmed) else {
            return Err(format!(
                "selected URL was not present in the discovery payload: {}",
                url
            ));
        };
        if !is_citable_web_url(trimmed) || is_search_hub_url(trimmed) {
            return Err(format!("selected URL is not a citable source candidate: {}", url));
        }
        if *selection_mode == PreReadSelectionMode::DiscoverySeed {
            let Some(observation) = source_observation_for_url(source_observations, trimmed) else {
                return Err(format!(
                    "selected discovery seed was missing typed source observations: {}",
                    url
                ));
            };
            let seed_admitted = source_observation_supports_discovery_seed(observation);
            if !seed_admitted {
                return Err(format!(
                    "selected discovery seed did not satisfy typed expansion affordances: {}",
                    url
                ));
            }
        }
        distinct_targets.insert(trimmed.to_ascii_lowercase());
        if let Some(domain) = selected_url_domain_key(&source_hints, trimmed) {
            distinct_domains.insert(domain);
        }
    }

    if distinct_targets.len() != normalized.len() {
        return Err(format!(
            "expected {} distinct retrieval targets but received {}",
            normalized.len(),
            distinct_targets.len()
        ));
    }

    if *selection_mode == PreReadSelectionMode::DirectDetail
        && required_domain_floor > 0
        && distinct_domains.len() < required_domain_floor
    {
        return Err(format!(
            "expected at least {} distinct domains but received {}",
            required_domain_floor,
            distinct_domains.len()
        ));
    }

    Ok(normalized)
}

fn ranked_discovery_sources_with_limit(
    bundle: &WebEvidenceBundle,
    limit: usize,
) -> Vec<WebSource> {
    let mut indexed = bundle
        .sources
        .iter()
        .cloned()
        .enumerate()
        .collect::<Vec<_>>();
    indexed.sort_by(|(left_idx, left), (right_idx, right)| {
        left.rank
            .unwrap_or(u32::MAX)
            .cmp(&right.rank.unwrap_or(u32::MAX))
            .then_with(|| left_idx.cmp(right_idx))
            .then_with(|| left.url.cmp(&right.url))
    });

    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (_, source) in indexed {
        let trimmed = source.url.trim();
        if trimmed.is_empty() || !seen.insert(trimmed.to_string()) {
            continue;
        }
        out.push(WebSource {
            url: trimmed.to_string(),
            ..source
        });
        if out.len() >= limit {
            break;
        }
    }

    out
}

fn ranked_discovery_sources(bundle: &WebEvidenceBundle) -> Vec<WebSource> {
    ranked_discovery_sources_with_limit(bundle, WEB_PIPELINE_DISCOVERY_SOURCE_LIMIT)
}

fn ordered_discovery_sources(bundle: &WebEvidenceBundle) -> Vec<WebSource> {
    ranked_discovery_sources_with_limit(bundle, usize::MAX)
}

fn source_observation_for_url<'a>(
    source_observations: &'a [WebSourceObservation],
    url: &str,
) -> Option<&'a WebSourceObservation> {
    let trimmed = url.trim();
    source_observations.iter().find(|observation| {
        observation.url.eq_ignore_ascii_case(trimmed)
            || url_structurally_equivalent(&observation.url, trimmed)
    })
}

fn source_observation_supports_discovery_seed(observation: &WebSourceObservation) -> bool {
    observation
        .affordances
        .contains(&WebRetrievalAffordance::LinkCollection)
        && observation
            .affordances
            .contains(&WebRetrievalAffordance::CanonicalLinkOut)
        && observation.expansion_affordances.iter().any(|affordance| {
            matches!(
                affordance,
                WebSourceExpansionAffordance::JsonLdItemList
                    | WebSourceExpansionAffordance::ChildLinkCollection
            )
        })
}

fn build_pre_read_selection_payload(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    required_url_count: usize,
    discovery_sources: &[WebSource],
    source_observations: &[WebSourceObservation],
) -> PreReadSelectionPayload {
    let retrieval_contract = retrieval_contract.cloned().unwrap_or_default();
    let discovery_seed_permitted = pre_read_selection_mode_permitted(
        Some(&retrieval_contract),
        query_contract,
        &PreReadSelectionMode::DiscoverySeed,
    );
    let payload_sources = discovery_sources
        .iter()
        .map(|source| {
            PreReadDiscoverySource {
                rank: source.rank,
                url: source.url.trim().to_string(),
                domain: source.domain.clone(),
                title: source.title.clone(),
                snippet: source.snippet.clone(),
                affordances: source_observation_for_url(source_observations, &source.url)
                    .map(|observation| observation.affordances.clone())
                    .unwrap_or_default(),
                expansion_affordances: source_observation_for_url(source_observations, &source.url)
                    .map(|observation| observation.expansion_affordances.clone())
                    .unwrap_or_default(),
            }
        })
        .collect::<Vec<_>>();
    let mut constraints = vec![
        "Use only the typed retrieval contract and payload source metadata.".to_string(),
        "Return only URLs present in payload.sources; do not synthesize substitute URLs."
            .to_string(),
        "Use selection_mode=direct_detail when the selected URLs can be read directly as final evidence sources."
            .to_string(),
    ];
    if discovery_seed_permitted {
        constraints.push(
            "Use selection_mode=discovery_seed only when the payload lacks enough direct detail sources but one stronger source can support grounded follow-up expansion."
                .to_string(),
        );
        constraints.push(
            "Return exactly required_url_count URLs for direct_detail or exactly one URL for discovery_seed."
                .to_string(),
        );
    } else {
        constraints.push(
            "Return exactly required_url_count URLs using selection_mode=direct_detail."
                .to_string(),
        );
    }
    if retrieval_contract.source_independence_min > 1 && !retrieval_contract.entity_diversity_required
    {
        constraints.push(
            "When direct_detail is used, prefer independent sources from distinct domains when the payload permits."
                .to_string(),
        );
    }
    if retrieval_contract.entity_diversity_required {
        constraints.push(
            "For multi-entity comparison queries, prefer URLs about distinct answer entities even when domains repeat."
                .to_string(),
        );
    }
    if retrieval_contract.runtime_locality_required {
        constraints.push(
            "Select only sources aligned to the runtime locality already expressed in the query contract."
                .to_string(),
        );
    }
    if discovery_seed_permitted {
        constraints.push(
            "discovery_seed is admissible only for sources whose payload metadata includes link_collection, canonical_link_out, and at least one structural expansion affordance."
                .to_string(),
        );
    } else {
        constraints.push(
            "discovery_seed is not permitted for this payload; selection_mode must be direct_detail."
                .to_string(),
        );
    }
    PreReadSelectionPayload {
        query_contract: query_contract.trim().to_string(),
        retrieval_contract,
        required_url_count,
        constraints,
        sources: payload_sources,
    }
}

fn pre_read_selection_mode_permitted(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    selection_mode: &PreReadSelectionMode,
) -> bool {
    match selection_mode {
        PreReadSelectionMode::DirectDetail => true,
        PreReadSelectionMode::DiscoverySeed => {
            retrieval_contract_entity_diversity_required(retrieval_contract, query_contract)
                || crate::agentic::web::contract_requires_geo_scoped_entity_expansion(
                    retrieval_contract.unwrap_or(&WebRetrievalContract::default()),
                )
        }
    }
}

async fn synthesize_pre_read_selection(
    service: &DesktopAgentService,
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    required_url_count: usize,
    discovery_sources: &[WebSource],
    source_observations: &[WebSourceObservation],
) -> Result<PreReadSelectionResponse, String> {
    let payload = build_pre_read_selection_payload(
        retrieval_contract,
        query_contract,
        required_url_count,
        discovery_sources,
        source_observations,
    );
    let discovery_seed_permitted = pre_read_selection_mode_permitted(
        retrieval_contract,
        query_contract,
        &PreReadSelectionMode::DiscoverySeed,
    );
    let selection_schema = if discovery_seed_permitted {
        "{\"selection_mode\":\"direct_detail|discovery_seed\",\"urls\":[string]}"
    } else {
        "{\"selection_mode\":\"direct_detail\",\"urls\":[string]}"
    };
    let selection_mode_requirement = if discovery_seed_permitted {
        "- `discovery_seed` means the payload lacks enough direct final sources, so exactly one stronger source should be selected for grounded follow-up expansion."
    } else {
        "- `discovery_seed` is not permitted for this payload; `selection_mode` must be `direct_detail`."
    };
    if payload.sources.is_empty() {
        return Err("pre-read selection requires at least one discovered source".to_string());
    }
    let payload_json = serde_json::to_string_pretty(&payload)
        .map_err(|err| format!("failed to serialize pre-read selection payload: {}", err))?;
    let timeout = pre_read_synthesis_timeout();
    let mut feedback: Option<String> = None;
    let mut last_error = "pre-read selection failed".to_string();

    for attempt in 1..=WEB_PIPELINE_PRE_READ_SYNTHESIS_MAX_ATTEMPTS {
        let prompt = if let Some(previous_error) = feedback.as_deref() {
            format!(
                "Return JSON only with schema {}.\n\
                 You are in CEC State 3 (Typed Web Source Selection).\n\
                 Prior output failed lint: {}\n\
                 Re-select URLs using only the typed retrieval contract and payload source metadata.\n\
                 Payload:\n{}",
                selection_schema, previous_error, payload_json
            )
        } else {
            format!(
                "Return JSON only with schema {}.\n\
                 You are in CEC State 3 (Typed Web Source Selection).\n\
                 Select URLs from the payload that best satisfy the typed retrieval contract.\n\
                 Requirements:\n\
                 - Use only payload URLs.\n\
                 - Use only the typed retrieval contract and payload source metadata.\n\
                 - `direct_detail` means the returned URLs can be read directly as final evidence sources.\n\
                 {}\n\
                 - Prefer semantically aligned sources that satisfy locality/currentness constraints already encoded in the query contract.\n\
                 - For multi-entity comparison queries, prefer sources about distinct answer entities.\n\
                 - When source independence matters and entity diversity is not sufficient, prefer distinct domains.\n\
                 - If unclear, exclude the URL.\n\
                 Payload:\n{}",
                selection_schema,
                selection_mode_requirement,
                payload_json
            )
        };
        let options = InferenceOptions {
            tools: vec![],
            temperature: 0.0,
            json_mode: true,
            max_tokens: WEB_PIPELINE_PRE_READ_SYNTHESIS_MAX_TOKENS,
        };
        let airlocked_prompt = match service
            .prepare_cloud_inference_input(
                None,
                "desktop_agent",
                "web_pipeline_pre_read_selection",
                prompt.as_bytes(),
            )
            .await
        {
            Ok(bytes) => bytes,
            Err(err) => {
                last_error = format!("pre-read selection airlock failed: {}", err);
                feedback = Some(last_error.clone());
                if attempt == WEB_PIPELINE_PRE_READ_SYNTHESIS_MAX_ATTEMPTS {
                    break;
                }
                continue;
            }
        };
        let raw = match tokio::time::timeout(
            timeout,
            service
                .reasoning_inference
                .execute_inference([0u8; 32], &airlocked_prompt, options),
        )
        .await
        {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(err)) => {
                last_error = format!("pre-read selection inference failed: {}", err);
                feedback = Some(last_error.clone());
                if attempt == WEB_PIPELINE_PRE_READ_SYNTHESIS_MAX_ATTEMPTS {
                    break;
                }
                continue;
            }
            Err(_) => {
                last_error = format!(
                    "pre-read selection timed out after {}ms",
                    timeout.as_millis()
                );
                feedback = Some(last_error.clone());
                if attempt == WEB_PIPELINE_PRE_READ_SYNTHESIS_MAX_ATTEMPTS {
                    break;
                }
                continue;
            }
        };
        let text = match String::from_utf8(raw) {
            Ok(text) => text,
            Err(err) => {
                last_error = format!("pre-read selection response was not UTF-8: {}", err);
                feedback = Some(last_error.clone());
                if attempt == WEB_PIPELINE_PRE_READ_SYNTHESIS_MAX_ATTEMPTS {
                    break;
                }
                continue;
            }
        };
        let json_text = extract_json_object(&text).unwrap_or(text.as_str());
        let parsed: PreReadSelectionResponse = match serde_json::from_str(json_text) {
            Ok(parsed) => parsed,
            Err(err) => {
                last_error = format!("pre-read selection returned invalid JSON schema: {}", err);
                feedback = Some(last_error.clone());
                if attempt == WEB_PIPELINE_PRE_READ_SYNTHESIS_MAX_ATTEMPTS {
                    break;
                }
                continue;
            }
        };

        match lint_pre_read_payload_urls(
            retrieval_contract,
            query_contract,
            discovery_sources,
            source_observations,
            &parsed.selection_mode,
            &parsed.urls,
            payload.required_url_count,
        ) {
            Ok(validated) => {
                return Ok(PreReadSelectionResponse {
                    selection_mode: parsed.selection_mode,
                    urls: validated,
                });
            }
            Err(err) => {
                last_error = err;
                feedback = Some(last_error.clone());
                if attempt == WEB_PIPELINE_PRE_READ_SYNTHESIS_MAX_ATTEMPTS {
                    break;
                }
            }
        }
    }

    Err(last_error)
}

fn selected_source_hints_for_urls(
    bundle: &WebEvidenceBundle,
    selected_urls: &[String],
) -> Vec<PendingSearchReadSummary> {
    let source_hints = candidate_source_hints_from_bundle(bundle);
    selected_urls
        .iter()
        .map(|selected| {
            let selected_trimmed = selected.trim();
            if selected_trimmed.is_empty() {
                return PendingSearchReadSummary::default();
            }
            if let Some(source) = selected_url_hint(&source_hints, selected_trimmed) {
                return PendingSearchReadSummary {
                    url: selected_trimmed.to_string(),
                    title: source.title.clone(),
                    excerpt: source.excerpt.clone(),
                };
            }

            let fallback_source = bundle.sources.iter().find(|source| {
                let source_url = source.url.trim();
                source_url.eq_ignore_ascii_case(selected_trimmed)
                    || url_structurally_equivalent(source_url, selected_trimmed)
            });
            PendingSearchReadSummary {
                url: selected_trimmed.to_string(),
                title: fallback_source.and_then(|source| source.title.clone()),
                excerpt: fallback_source
                    .and_then(|source| source.snippet.clone())
                    .unwrap_or_default(),
            }
        })
        .collect()
}

fn source_url_from_metadata_excerpt(excerpt: &str) -> Option<String> {
    let marker = "source_url=";
    let lower = excerpt.to_ascii_lowercase();
    let start = lower.find(marker)? + marker.len();
    let candidate = excerpt
        .get(start..)?
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_matches(|ch: char| "|,;:!?)]}\"'".contains(ch))
        .trim();
    if candidate.starts_with("http://") || candidate.starts_with("https://") {
        Some(candidate.to_string())
    } else {
        None
    }
}

fn selected_url_domain_key(source_hints: &[PendingSearchReadSummary], url: &str) -> Option<String> {
    let trimmed = url.trim();
    let url_domain = normalized_domain_key(trimmed);
    let hinted_domain = selected_url_hint(source_hints, trimmed)
        .and_then(|hint| source_url_from_metadata_excerpt(&hint.excerpt))
        .and_then(|resolved| normalized_domain_key(&resolved));
    match (url_domain, hinted_domain) {
        (Some(url_domain), Some(hinted_domain)) if url_domain != hinted_domain => {
            Some(hinted_domain)
        }
        (Some(url_domain), _) => Some(url_domain),
        (None, Some(hinted_domain)) => Some(hinted_domain),
        (None, None) => None,
    }
}

fn headline_source_low_priority(url: &str, title: &str, excerpt: &str) -> bool {
    let signals = analyze_source_record_signals(url, title, excerpt);
    signals.low_priority_hits > 0 || signals.low_priority_dominates()
}

pub(super) fn headline_selection_quality_metrics(
    selected_urls: &[String],
    source_hints: &[PendingSearchReadSummary],
) -> (usize, usize, usize, Vec<String>) {
    let mut total_sources = 0usize;
    let mut low_priority_sources = 0usize;
    let mut distinct_domains = std::collections::BTreeSet::new();
    let mut low_priority_urls = Vec::new();
    let mut seen_urls = std::collections::BTreeSet::new();

    for selected in selected_urls {
        let selected_trimmed = selected.trim();
        if selected_trimmed.is_empty() {
            continue;
        }
        let dedup_key = selected_trimmed.to_ascii_lowercase();
        if !seen_urls.insert(dedup_key) {
            continue;
        }

        let (title, excerpt) = source_hints
            .iter()
            .find(|hint| {
                let hint_url = hint.url.trim();
                hint_url.eq_ignore_ascii_case(selected_trimmed)
                    || url_structurally_equivalent(hint_url, selected_trimmed)
            })
            .map(|hint| {
                (
                    hint.title.as_deref().unwrap_or_default(),
                    hint.excerpt.as_str(),
                )
            })
            .unwrap_or(("", ""));
        total_sources = total_sources.saturating_add(1);
        if let Some(domain) = selected_url_domain_key(source_hints, selected_trimmed) {
            distinct_domains.insert(domain);
        }
        if headline_source_low_priority(selected_trimmed, title, excerpt) {
            low_priority_sources = low_priority_sources.saturating_add(1);
            low_priority_urls.push(selected_trimmed.to_string());
        }
    }

    (
        total_sources,
        low_priority_sources,
        distinct_domains.len(),
        low_priority_urls,
    )
}

fn resolve_selected_urls_from_hints(
    selected_urls: &mut Vec<String>,
    source_hints: &[PendingSearchReadSummary],
) {
    for selected in selected_urls.iter_mut() {
        let selected_trimmed = selected.trim().to_string();
        if selected_trimmed.is_empty() {
            continue;
        }
        let resolved = source_hints
            .iter()
            .find(|hint| {
                let hint_url = hint.url.trim();
                hint_url.eq_ignore_ascii_case(&selected_trimmed)
                    || url_structurally_equivalent(hint_url, &selected_trimmed)
            })
            .and_then(|hint| source_url_from_metadata_excerpt(&hint.excerpt))
            .filter(|resolved_url| is_citable_web_url(resolved_url) && !is_search_hub_url(resolved_url));
        if let Some(resolved_url) = resolved {
            *selected = resolved_url;
        }
    }

    let mut deduped = Vec::new();
    for selected in selected_urls.iter() {
        let _ = push_unique_selected_url(&mut deduped, selected);
    }
    *selected_urls = deduped;
}

fn merge_source_hints(
    primary: Vec<PendingSearchReadSummary>,
    additional: &[PendingSearchReadSummary],
) -> Vec<PendingSearchReadSummary> {
    let mut merged = Vec::new();

    for source in primary {
        let trimmed = source.url.trim();
        if trimmed.is_empty() {
            continue;
        }
        if merged.iter().any(|existing: &PendingSearchReadSummary| {
            let existing_url = existing.url.trim();
            existing_url.eq_ignore_ascii_case(trimmed)
                || url_structurally_equivalent(existing_url, trimmed)
        }) {
            continue;
        }
        merged.push(PendingSearchReadSummary {
            url: trimmed.to_string(),
            title: source.title,
            excerpt: source.excerpt.trim().to_string(),
        });
    }

    for source in additional {
        let trimmed = source.url.trim();
        if trimmed.is_empty() {
            continue;
        }
        if merged.iter().any(|existing: &PendingSearchReadSummary| {
            let existing_url = existing.url.trim();
            existing_url.eq_ignore_ascii_case(trimmed)
                || url_structurally_equivalent(existing_url, trimmed)
        }) {
            continue;
        }
        merged.push(PendingSearchReadSummary {
            url: trimmed.to_string(),
            title: source.title.clone(),
            excerpt: source.excerpt.trim().to_string(),
        });
    }

    merged
}

fn push_unique_selected_url(selected_urls: &mut Vec<String>, candidate_url: &str) -> bool {
    let trimmed = candidate_url.trim();
    if trimmed.is_empty() {
        return false;
    }
    if selected_urls.iter().any(|existing| {
        existing.eq_ignore_ascii_case(trimmed) || url_structurally_equivalent(existing, trimmed)
    }) {
        return false;
    }
    selected_urls.push(trimmed.to_string());
    true
}

fn queue_web_read_batch_from_pipeline(
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    urls: &[String],
) -> Result<usize, TransactionError> {
    let mut queued = 0usize;
    for url in urls.iter().rev() {
        if queue_web_read_from_pipeline(agent_state, session_id, url)? {
            queued += 1;
        }
    }
    Ok(queued)
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn local_business_expansion_source_selection_prefers_embedded_detail_pages_over_neighboring_categories() {
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

        assert_eq!(selected.0, "https://www.restaurantji.com/sc/anderson/italian/");
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
