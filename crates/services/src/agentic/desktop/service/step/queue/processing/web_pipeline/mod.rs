use super::super::support::{
    append_final_web_completion_receipts, append_pending_web_success_fallback,
    append_pending_web_success_from_bundle, build_query_constraint_projection_with_locality_hint,
    candidate_constraint_compatibility, candidate_source_hints_from_bundle,
    collect_projection_candidate_urls_with_contract_and_locality_hint,
    collect_projection_candidate_urls_with_locality_hint, compact_whitespace,
    compatibility_passes_projection,
    constraint_grounded_probe_query_with_contract_and_hints_and_locality_hint,
    constraint_grounded_probe_query_with_hints_and_locality_hint, constraint_grounded_search_limit,
    constraint_grounded_search_query_with_contract_and_hints_and_locality_hint,
    constraint_grounded_search_query_with_hints_and_locality_hint, effective_locality_scope_hint,
    explicit_query_scope_hint, extract_json_object, fallback_search_summary,
    final_web_completion_facts, is_citable_web_url, is_human_challenge_error,
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
    query_requires_runtime_locality_scope, queue_web_read_from_pipeline,
    queue_web_search_from_pipeline, remaining_pending_web_candidates,
    retrieval_affordances_with_contract_and_locality_hint,
    retrieval_affordances_with_locality_hint, retrieval_contract_entity_diversity_required,
    retrieval_contract_prefers_multi_item_cardinality, retrieval_contract_requests_comparison,
    retrieval_contract_required_distinct_domain_floor,
    retrieval_contract_requires_runtime_locality, select_web_pipeline_query_contract,
    selected_local_business_target_sources,
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
