use super::envelope::ResolutionPolicy;
use super::support::{
    append_final_web_completion_receipts, append_pending_web_success_fallback,
    append_pending_web_success_from_bundle, append_pending_web_success_from_hint,
    build_query_constraint_projection_with_locality_hint, candidate_constraint_compatibility,
    candidate_source_hints_from_bundle, candidate_urls_from_bundle, citation_ids_for_story,
    collect_projection_candidate_urls_with_locality_hint,
    constraint_grounded_probe_query_with_hints_and_locality_hint, constraint_grounded_search_limit,
    constraint_grounded_search_query, constraint_grounded_search_query_with_hints,
    constraint_grounded_search_query_with_hints_and_locality_hint,
    excerpt_has_query_grounding_signal, excerpt_has_query_grounding_signal_with_contract,
    explicit_query_scope_hint, fallback_search_summary, is_search_hub_url,
    local_business_expansion_query, local_business_search_entity_anchor_tokens,
    local_business_target_names_from_attempted_urls, local_business_target_names_from_sources,
    looks_like_structured_metadata_noise, matched_local_business_target_names,
    merge_pending_search_completion, next_pending_web_candidate,
    pre_read_candidate_plan_from_bundle,
    pre_read_candidate_plan_from_bundle_with_contract_and_locality_hint_and_recovery_mode,
    pre_read_candidate_plan_from_bundle_with_locality_hint,
    preferred_pre_read_action_count_with_locality_hint, prefers_single_fact_snapshot,
    projection_candidate_url_allowed, projection_probe_hint_anchor_phrase,
    query_is_generic_headline_collection, query_prefers_multi_item_cardinality,
    query_requests_comparison, query_requires_local_business_entity_diversity,
    query_requires_runtime_locality_scope, query_requires_structured_synthesis,
    queue_action_request_to_tool, remaining_pending_web_candidates, render_synthesis_draft,
    required_citations_per_story, required_story_count, resolved_query_contract_with_locality_hint,
    retrieval_affordances_with_locality_hint, retrieval_contract_min_sources,
    select_web_pipeline_query_contract, selected_local_business_target_sources,
    selected_source_quality_metrics_with_locality_hint, single_snapshot_constraint_set_with_hints,
    source_anchor_tokens, source_locality_tokens,
    source_matches_local_business_search_entity_anchor, summarize_search_results,
    synthesize_web_pipeline_reply, web_pipeline_can_queue_initial_read_latency_aware,
    web_pipeline_can_queue_probe_search_latency_aware, web_pipeline_completion_reason,
    web_pipeline_grounded_probe_attempt_available, web_pipeline_latency_pressure_label,
    web_pipeline_min_sources, web_pipeline_required_probe_budget_ms,
    web_pipeline_required_read_budget_ms, CitationCandidate, RetrievalAffordanceKind, StoryDraft,
    SynthesisDraft, WebPipelineCompletionReason, WEB_PIPELINE_REQUIRED_STORIES,
    WEIGHTED_INSIGHT_SIGNAL_VERSION,
};
use crate::agentic::desktop::types::{PendingSearchCompletion, PendingSearchReadSummary};
use ioi_types::app::agentic::{AgentTool, ComputerAction};
use ioi_types::app::agentic::{WebDocument, WebEvidenceBundle, WebRetrievalContract, WebSource};
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget};
use std::collections::{BTreeMap, BTreeSet};
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

const ANDERSON_WEATHER_QUERY: &str = "current weather in anderson sc";
const ANDERSON_BING_SEARCH_URL: &str = "https://www.bing.com/search?q=current+weather+anderson+sc";
const ATT_FORUM_ACCOUNT_USAGE_URL: &str =
    "https://forums.att.com/conversations/account-usage/compesation/5df024adbad5f2f60686b40b";
const ATT_FORUM_APPLE_URL: &str =
    "https://forums.att.com/conversations/apple/why-do-you-send-electronic-notifications-when-specifically-asked-not-to/5df00f54bad5f2f606253c6e";
const ACCUWEATHER_ANDERSON_CURRENT_URL: &str =
    "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327";
const WEATHER_GOV_ANDERSON_CURRENT_URL: &str =
    "https://forecast.weather.gov/MapClick.php?lat=34.5&lon=-82.65";

fn anderson_weather_search_bundle(query: &str, sources: Vec<WebSource>) -> WebEvidenceBundle {
    WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:bing:http".to_string(),
        query: Some(query.to_string()),
        url: Some(ANDERSON_BING_SEARCH_URL.to_string()),
        sources,
        source_observations: vec![],
        documents: vec![],
        provider_candidates: vec![],
        retrieval_contract: None,
    }
}

fn source_att_forum_account_usage(rank: u32) -> WebSource {
    WebSource {
        source_id: "irrelevant-1".to_string(),
        rank: Some(rank),
        url: ATT_FORUM_ACCOUNT_USAGE_URL.to_string(),
        title: Some("AT&T Digital Resources & Answers - Community Forums".to_string()),
        snippet: Some(
            "Apr 6, 2019 · I called customer service last night and paid my bill.".to_string(),
        ),
        domain: Some("forums.att.com".to_string()),
    }
}

fn source_att_forum_apple(rank: u32) -> WebSource {
    WebSource {
        source_id: "irrelevant-2".to_string(),
        rank: Some(rank),
        url: ATT_FORUM_APPLE_URL.to_string(),
        title: Some("AT&T Community Forums".to_string()),
        snippet: Some(
            "Dec 16, 2018 · Bought iPhone watch for spouse as Christmas present.".to_string(),
        ),
        domain: Some("forums.att.com".to_string()),
    }
}

fn source_accuweather_anderson(rank: u32) -> WebSource {
    WebSource {
        source_id: "weather-a".to_string(),
        rank: Some(rank),
        url: ACCUWEATHER_ANDERSON_CURRENT_URL.to_string(),
        title: Some("Anderson, SC Current Weather".to_string()),
        snippet: Some(
            "Current conditions: temperature near 61 F, wind 4 mph, humidity 48%.".to_string(),
        ),
        domain: Some("accuweather.com".to_string()),
    }
}

fn source_weather_gov_anderson(rank: u32) -> WebSource {
    WebSource {
        source_id: "weather-b".to_string(),
        rank: Some(rank),
        url: WEATHER_GOV_ANDERSON_CURRENT_URL.to_string(),
        title: Some("Anderson SC Current Conditions".to_string()),
        snippet: Some(
            "Observed at 2:00 AM: temperature 60 F, humidity 50%, calm wind.".to_string(),
        ),
        domain: Some("weather.gov".to_string()),
    }
}

mod queue_tool_mapping;
mod web_pipeline_citations;
mod web_pipeline_inputs;
mod web_pipeline_outputs;
