use super::super::support::{
    append_pending_web_success_fallback, append_pending_web_success_from_bundle,
    candidate_source_hints_from_bundle,
    constraint_grounded_probe_query_with_hints_and_locality_hint, constraint_grounded_search_limit,
    effective_locality_scope_hint, extract_json_object, fallback_search_summary,
    has_primary_status_authority, is_citable_web_url, is_human_challenge_error,
    is_multi_item_listing_url, is_news_feed_wrapper_url, is_search_hub_url, iso_date_from_unix_ms,
    mark_pending_web_attempted, mark_pending_web_blocked, merge_pending_search_completion,
    parse_web_evidence_bundle, pre_read_candidate_plan_from_bundle_with_locality_hint,
    query_is_generic_headline_collection, query_requires_runtime_locality_scope,
    queue_web_read_from_pipeline, queue_web_search_from_pipeline, remaining_pending_web_candidates,
    select_web_pipeline_query_contract, source_host, summarize_search_results,
    synthesize_web_pipeline_reply, synthesize_web_pipeline_reply_hybrid,
    url_structurally_equivalent, web_pipeline_can_queue_probe_search_latency_aware,
    web_pipeline_min_sources, web_pipeline_now_ms, WebPipelineCompletionReason,
    WEB_PIPELINE_BUDGET_MS,
};
use super::completion::complete_with_summary;
use super::routing::is_web_research_scope;
use crate::agentic::desktop::service::step::signals::analyze_source_record_signals;
use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::{
    AgentState, AgentStatus, PendingSearchCompletion, PendingSearchReadSummary,
};
use ioi_types::app::agentic::{AgentTool, InferenceOptions, WebEvidenceBundle, WebSource};
use ioi_types::app::ActionTarget;
use ioi_types::error::TransactionError;
use serde::{Deserialize, Serialize};
use tokio::time::Duration;
use url::Url;

const WEB_PIPELINE_DISCOVERY_SOURCE_LIMIT: usize = 15;
const WEB_PIPELINE_PRE_READ_SYNTHESIS_MAX_ATTEMPTS: usize = 3;
const WEB_PIPELINE_PRE_READ_SYNTHESIS_MAX_TOKENS: u32 = 700;

fn pre_read_synthesis_timeout() -> Duration {
    const DEFAULT_TIMEOUT_MS: u64 = 4_000;
    std::env::var("IOI_WEB_PRE_READ_SYNTHESIS_TIMEOUT_MS")
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
}

#[derive(Debug, Clone, Serialize)]
struct PreReadSelectionPayload {
    query: String,
    required_url_count: usize,
    constraints: Vec<String>,
    sources: Vec<PreReadDiscoverySource>,
}

#[derive(Debug, Clone, Deserialize)]
struct PreReadSelectionResponse {
    urls: Vec<String>,
}

async fn synthesize_summary(
    service: &DesktopAgentService,
    pending: &PendingSearchCompletion,
    reason: WebPipelineCompletionReason,
) -> String {
    if let Some(hybrid_summary) =
        synthesize_web_pipeline_reply_hybrid(service.reasoning_inference.clone(), pending, reason)
            .await
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

fn payload_allows_external_article_url(
    url: &str,
    allowed_hosts: &std::collections::BTreeSet<String>,
) -> bool {
    let trimmed = url.trim();
    if trimmed.is_empty()
        || !is_citable_web_url(trimmed)
        || is_news_feed_wrapper_url(trimmed)
        || !looks_like_deep_article_url(trimmed)
        || is_search_hub_url(trimmed)
        || is_multi_item_listing_url(trimmed)
    {
        return false;
    }
    let Some(host) = normalized_domain_key(trimmed) else {
        return false;
    };
    allowed_hosts.contains(&host)
}

fn looks_like_deep_article_url(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return false;
    }
    if is_news_feed_wrapper_url(trimmed) {
        return true;
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
    if path_hub_markers
        .iter()
        .any(|marker| normalized_path == *marker)
    {
        return false;
    }

    true
}

fn is_headline_citable_page_url(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || !is_citable_web_url(trimmed)
        || is_news_feed_wrapper_url(trimmed)
        || is_search_hub_url(trimmed)
        || is_multi_item_listing_url(trimmed)
    {
        return false;
    }
    let Ok(parsed) = Url::parse(trimmed) else {
        return false;
    };
    if parsed.path().trim_matches('/').is_empty() {
        return false;
    }
    headline_url_recency_acceptable(trimmed)
}

fn headline_url_explicit_year(url: &str) -> Option<i32> {
    let parsed = Url::parse(url.trim()).ok()?;
    for token in parsed.path().split(|ch: char| !ch.is_ascii_digit()) {
        if token.len() != 4 {
            continue;
        }
        let Ok(year) = token.parse::<i32>() else {
            continue;
        };
        if (1900..=2100).contains(&year) {
            return Some(year);
        }
    }
    None
}

fn current_utc_year() -> i32 {
    iso_date_from_unix_ms(web_pipeline_now_ms())
        .split('-')
        .next()
        .and_then(|value| value.parse::<i32>().ok())
        .unwrap_or(1970)
}

fn headline_url_recency_acceptable(url: &str) -> bool {
    let Some(year) = headline_url_explicit_year(url) else {
        return true;
    };
    year >= current_utc_year().saturating_sub(1)
}

fn lint_pre_read_payload_urls(
    urls: &[String],
    required_count: usize,
    allow_feed_wrappers: bool,
    headline_lookup_mode: bool,
) -> Result<Vec<String>, String> {
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

    if normalized.len() != required_count {
        return Err(format!(
            "expected exactly {} URLs but received {}",
            required_count,
            normalized.len()
        ));
    }

    let mut distinct_source_keys = std::collections::BTreeSet::new();
    for url in &normalized {
        if is_news_feed_wrapper_url(url) {
            if !allow_feed_wrappers {
                return Err(format!("feed-wrapper URL selected: {}", url));
            }
            distinct_source_keys.insert(format!("wrapper::{}", url.trim().to_ascii_lowercase()));
            continue;
        }
        if headline_lookup_mode {
            if !is_headline_citable_page_url(url) {
                return Err(format!("non-headline-citable URL selected: {}", url));
            }
        } else if !looks_like_deep_article_url(url) {
            return Err(format!("non-deep-link URL selected: {}", url));
        }
        let Some(domain) = normalized_domain_key(url) else {
            return Err(format!("failed to resolve domain for URL: {}", url));
        };
        distinct_source_keys.insert(format!("domain::{}", domain));
    }

    if distinct_source_keys.len() != required_count {
        return Err(format!(
            "expected {} distinct domains but received {}",
            required_count,
            distinct_source_keys.len()
        ));
    }

    Ok(normalized)
}

fn ranked_discovery_sources(bundle: &WebEvidenceBundle) -> Vec<WebSource> {
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
        if out.len() >= WEB_PIPELINE_DISCOVERY_SOURCE_LIMIT {
            break;
        }
    }

    out
}

fn build_pre_read_selection_payload(
    query_contract: &str,
    required_url_count: usize,
    discovery_sources: &[WebSource],
) -> PreReadSelectionPayload {
    let headline_lookup_mode = query_is_generic_headline_collection(query_contract);
    let mut constraints = vec![
        "Select only URLs that are direct article pages, not homepages, hubs, or section fronts."
            .to_string(),
        "Return exactly the required URL count.".to_string(),
        "Each URL must come from a distinct domain.".to_string(),
        "Prefer URLs present in payload sources; direct article substitutions are allowed only when their host matches payload source metadata."
            .to_string(),
    ];
    if headline_lookup_mode {
        constraints.push(
            "For headline aggregation, do not return feed-wrapper URLs; use direct article links."
                .to_string(),
        );
    } else {
        constraints.push(
            "Feed-wrapper article URLs are allowed when they identify article records.".to_string(),
        );
    }

    PreReadSelectionPayload {
        query: query_contract.trim().to_string(),
        required_url_count,
        constraints,
        sources: discovery_sources
            .iter()
            .map(|source| PreReadDiscoverySource {
                rank: source.rank,
                url: source.url.trim().to_string(),
                domain: source.domain.clone(),
                title: source.title.clone(),
                snippet: source.snippet.clone(),
            })
            .collect(),
    }
}

async fn synthesize_pre_read_payload_urls(
    service: &DesktopAgentService,
    query_contract: &str,
    required_url_count: usize,
    discovery_sources: &[WebSource],
) -> Result<Vec<String>, String> {
    if discovery_sources.len() < required_url_count {
        return Err(format!(
            "insufficient discovery inventory: have {} sources but require {}",
            discovery_sources.len(),
            required_url_count
        ));
    }

    let payload =
        build_pre_read_selection_payload(query_contract, required_url_count, discovery_sources);
    let headline_lookup_mode = query_is_generic_headline_collection(query_contract);
    let allow_feed_wrappers = !headline_lookup_mode;
    let deep_link_requirement = if allow_feed_wrappers {
        "Deep links only (not homepage/hub URLs), except feed-wrapper article URLs."
    } else {
        "Headline pages only (not search hubs/homepages); feed-wrapper URLs are not allowed."
    };
    let payload_json = serde_json::to_string_pretty(&payload)
        .map_err(|err| format!("failed to serialize pre-read payload: {}", err))?;

    let mut feedback: Option<String> = None;
    let mut last_error = "pre-read payload synthesis failed".to_string();
    let inference_timeout = pre_read_synthesis_timeout();

    for attempt in 1..=WEB_PIPELINE_PRE_READ_SYNTHESIS_MAX_ATTEMPTS {
        let prompt = if let Some(previous_error) = feedback.as_deref() {
            format!(
                "Return JSON only with schema {{\"urls\":[string]}}.\n\
                 You are in CEC State 3 (Payload Synthesis).\n\
                 Prior output failed lint: {}\n\
                 Re-select URLs using payload evidence and satisfy all constraints.\n\
                 Payload:\n{}",
                previous_error, payload_json
            )
        } else {
            format!(
                "Return JSON only with schema {{\"urls\":[string]}}.\n\
                 You are in CEC State 3 (Payload Synthesis).\n\
                 Select exact article URLs from payload.sources.\n\
                 Requirements:\n\
                 - Exactly {} URLs.\n\
                 - Distinct domains only.\n\
                 - {}.\n\
                 - Prefer URLs in payload.sources; direct substitutions must match payload source metadata hosts.\n\
                 Payload:\n{}",
                required_url_count, deep_link_requirement, payload_json
            )
        };

        let options = InferenceOptions {
            tools: vec![],
            temperature: 0.0,
            json_mode: true,
            max_tokens: WEB_PIPELINE_PRE_READ_SYNTHESIS_MAX_TOKENS,
        };
        let raw = match tokio::time::timeout(
            inference_timeout,
            service
                .reasoning_inference
                .execute_inference([0u8; 32], prompt.as_bytes(), options),
        )
        .await
        {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(err)) => {
                last_error = format!("pre-read synthesis inference failed: {}", err);
                feedback = Some(last_error.clone());
                if attempt == WEB_PIPELINE_PRE_READ_SYNTHESIS_MAX_ATTEMPTS {
                    break;
                }
                continue;
            }
            Err(_) => {
                last_error = format!(
                    "pre-read synthesis timed out after {}ms",
                    inference_timeout.as_millis()
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
                last_error = format!("pre-read synthesis response was not UTF-8: {}", err);
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
                last_error = format!("pre-read synthesis returned invalid JSON schema: {}", err);
                feedback = Some(last_error.clone());
                if attempt == WEB_PIPELINE_PRE_READ_SYNTHESIS_MAX_ATTEMPTS {
                    break;
                }
                continue;
            }
        };

        let source_inventory = discovery_sources
            .iter()
            .map(|source| source.url.trim().to_ascii_lowercase())
            .collect::<std::collections::BTreeSet<_>>();
        let allowed_external_hosts = payload_derived_source_hosts(discovery_sources);
        let selected_inventory = parsed
            .urls
            .iter()
            .map(|url| url.trim().to_ascii_lowercase())
            .collect::<std::collections::BTreeSet<_>>();
        let outside_payload = selected_inventory
            .iter()
            .filter(|url| !source_inventory.contains(*url))
            .cloned()
            .collect::<Vec<_>>();
        if !outside_payload.is_empty() {
            if headline_lookup_mode {
                last_error = format!(
                    "headline pre-read selection included URLs outside discovery payload: {:?}",
                    outside_payload
                );
                feedback = Some(last_error.clone());
                if attempt == WEB_PIPELINE_PRE_READ_SYNTHESIS_MAX_ATTEMPTS {
                    break;
                }
                continue;
            }
            let disallowed = outside_payload
                .iter()
                .filter(|url| !payload_allows_external_article_url(url, &allowed_external_hosts))
                .cloned()
                .collect::<Vec<_>>();
            if !disallowed.is_empty() {
                last_error = format!(
                    "response included URLs outside discovery payload: {:?}",
                    disallowed
                );
                feedback = Some(last_error.clone());
                if attempt == WEB_PIPELINE_PRE_READ_SYNTHESIS_MAX_ATTEMPTS {
                    break;
                }
                continue;
            }
        }

        match lint_pre_read_payload_urls(
            &parsed.urls,
            required_url_count,
            allow_feed_wrappers,
            headline_lookup_mode,
        ) {
            Ok(validated) => return Ok(validated),
            Err(lint_error) => {
                last_error = lint_error;
                feedback = Some(last_error.clone());
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
            if let Some(source) = source_hints.iter().find(|source| {
                let source_url = source.url.trim();
                source_url.eq_ignore_ascii_case(selected_trimmed)
                    || url_structurally_equivalent(source_url, selected_trimmed)
            }) {
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

fn headline_resolved_hint_url(hint: &PendingSearchReadSummary) -> Option<String> {
    let trimmed = hint.url.trim();
    if trimmed.is_empty() {
        return None;
    }
    let candidate = if is_news_feed_wrapper_url(trimmed) {
        source_url_from_metadata_excerpt(&hint.excerpt)?
    } else {
        trimmed.to_string()
    };
    let resolved = candidate.trim();
    if resolved.is_empty()
        || !is_citable_web_url(resolved)
        || is_news_feed_wrapper_url(resolved)
        || !is_headline_citable_page_url(resolved)
    {
        return None;
    }
    Some(resolved.to_string())
}

fn normalize_headline_source_hints(
    hints: Vec<PendingSearchReadSummary>,
) -> Vec<PendingSearchReadSummary> {
    let mut normalized = Vec::new();
    for hint in hints {
        let Some(url) = headline_resolved_hint_url(&hint) else {
            continue;
        };
        if normalized
            .iter()
            .any(|existing: &PendingSearchReadSummary| {
                let existing_url = existing.url.trim();
                existing_url.eq_ignore_ascii_case(&url)
                    || url_structurally_equivalent(existing_url, &url)
            })
        {
            continue;
        }
        normalized.push(PendingSearchReadSummary {
            url,
            title: hint.title,
            excerpt: hint.excerpt.trim().to_string(),
        });
    }
    normalized
}

fn resolve_selected_urls_from_hints(
    selected_urls: &mut Vec<String>,
    source_hints: &[PendingSearchReadSummary],
) {
    for selected in selected_urls.iter_mut() {
        let selected_trimmed = selected.trim().to_string();
        if selected_trimmed.is_empty() || !is_news_feed_wrapper_url(&selected_trimmed) {
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
            .filter(|resolved_url| {
                is_citable_web_url(resolved_url)
                    && !is_news_feed_wrapper_url(resolved_url)
                    && is_headline_citable_page_url(resolved_url)
            });
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

fn headline_source_hint_allowed(hint: &PendingSearchReadSummary) -> bool {
    let Some(url) = headline_resolved_hint_url(hint) else {
        return false;
    };

    let title = hint.title.as_deref().unwrap_or_default();
    let excerpt = hint.excerpt.as_str();
    let signals = analyze_source_record_signals(&url, title, excerpt);
    has_primary_status_authority(signals) || !signals.low_priority_dominates()
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

pub(super) async fn maybe_handle_web_search(
    service: &DesktopAgentService,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    pre_state_step_index: u32,
    tool_name: &str,
    tool_wrapper: &AgentTool,
    is_gated: bool,
    success: &mut bool,
    out: &mut Option<String>,
    err: &mut Option<String>,
    completion_summary: &mut Option<String>,
    verification_checks: &mut Vec<String>,
) -> Result<(), TransactionError> {
    let parsed_bundle = out.as_deref().and_then(parse_web_evidence_bundle);
    let promoted_memory_search = tool_name == "memory__search"
        && parsed_bundle
            .as_ref()
            .map(|bundle| bundle.tool == "web__search")
            .unwrap_or(false);
    let effective_web_search = tool_name == "web__search" || promoted_memory_search;
    if promoted_memory_search {
        verification_checks.push("memory_search_promoted_to_web_search=true".to_string());
    }
    if !effective_web_search || is_gated || !is_web_research_scope(agent_state) || !*success {
        return Ok(());
    }
    let Some(bundle) = parsed_bundle.as_ref() else {
        return Ok(());
    };

    let query_value = bundle
        .query
        .clone()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| match tool_wrapper {
            AgentTool::WebSearch { query, .. } => {
                let trimmed = query.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            }
            AgentTool::MemorySearch { query } => {
                let trimmed = query.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            }
            _ => None,
        })
        .unwrap_or_else(|| agent_state.goal.clone());
    let query_contract =
        select_web_pipeline_query_contract(agent_state.goal.as_str(), &query_value);
    let min_sources = web_pipeline_min_sources(&query_contract).max(1);
    let headline_lookup_mode = query_is_generic_headline_collection(&query_contract);
    let required_url_count = if headline_lookup_mode {
        (min_sources as usize).saturating_add(1).min(6)
    } else {
        min_sources as usize
    };
    let started_at_ms = web_pipeline_now_ms();
    let locality_hint = if query_requires_runtime_locality_scope(&query_contract) {
        effective_locality_scope_hint(None)
    } else {
        None
    };

    let discovery_sources = ranked_discovery_sources(bundle);
    let deterministic_plan = pre_read_candidate_plan_from_bundle_with_locality_hint(
        &query_contract,
        min_sources,
        bundle,
        locality_hint.as_deref(),
    );
    let target_url_count = if headline_lookup_mode {
        required_url_count.saturating_add(2).min(6)
    } else {
        required_url_count
    };
    let probe_source_hints = if headline_lookup_mode {
        let normalized =
            normalize_headline_source_hints(deterministic_plan.probe_source_hints.clone());
        let filtered = normalized
            .iter()
            .filter(|source| headline_source_hint_allowed(source))
            .cloned()
            .collect::<Vec<_>>();
        if filtered.is_empty() {
            normalized
        } else {
            filtered
        }
    } else {
        deterministic_plan.probe_source_hints.clone()
    };
    let selection = synthesize_pre_read_payload_urls(
        service,
        &query_contract,
        required_url_count,
        &discovery_sources,
    )
    .await;
    let (selected_urls, payload_error) = match selection {
        Ok(urls) => (urls, None),
        Err(error) => (Vec::new(), Some(error)),
    };
    let mut selected_urls = selected_urls;
    let mut selected_hints = selected_source_hints_for_urls(bundle, &selected_urls);
    if headline_lookup_mode {
        selected_hints = normalize_headline_source_hints(selected_hints);
    }
    let locality_scope_required = query_requires_runtime_locality_scope(&query_contract);
    if locality_scope_required {
        if deterministic_plan.candidate_urls.is_empty() {
            // When locality scope is required, avoid committing non-local synthesized URLs.
            selected_urls.clear();
            selected_hints.clear();
        } else {
            selected_urls.retain(|selected| {
                let selected_trimmed = selected.trim();
                deterministic_plan.candidate_urls.iter().any(|allowed| {
                    let allowed_trimmed = allowed.trim();
                    allowed_trimmed.eq_ignore_ascii_case(selected_trimmed)
                        || url_structurally_equivalent(allowed_trimmed, selected_trimmed)
                })
            });
            selected_hints = selected_source_hints_for_urls(bundle, &selected_urls);
            if headline_lookup_mode {
                selected_hints = normalize_headline_source_hints(selected_hints);
            }
        }
    }
    let deterministic_fallback_used = (payload_error.is_some() || selected_urls.is_empty())
        && !deterministic_plan.candidate_urls.is_empty();
    if deterministic_fallback_used {
        selected_urls = deterministic_plan.candidate_urls.clone();
        selected_hints = deterministic_plan.candidate_source_hints.clone();
    }
    let mut deterministic_top_up_used = false;
    if selected_urls.len() < required_url_count {
        for candidate in &deterministic_plan.candidate_urls {
            if selected_urls.len() >= required_url_count {
                break;
            }
            if push_unique_selected_url(&mut selected_urls, candidate) {
                deterministic_top_up_used = true;
            }
        }
        if selected_urls.len() < required_url_count {
            for source in &probe_source_hints {
                if selected_urls.len() >= required_url_count {
                    break;
                }
                if push_unique_selected_url(&mut selected_urls, &source.url) {
                    deterministic_top_up_used = true;
                }
            }
        }
        if deterministic_top_up_used {
            selected_hints = selected_source_hints_for_urls(bundle, &selected_urls);
        }
    }
    let mut merged_hints = merge_source_hints(
        merge_source_hints(
            selected_hints,
            deterministic_plan.candidate_source_hints.as_slice(),
        ),
        probe_source_hints.as_slice(),
    );
    if headline_lookup_mode {
        let discovery_hints =
            normalize_headline_source_hints(candidate_source_hints_from_bundle(bundle));
        merged_hints = merge_source_hints(merged_hints, discovery_hints.as_slice());
        merged_hints = merged_hints
            .into_iter()
            .filter(headline_source_hint_allowed)
            .collect::<Vec<_>>();
        merged_hints = normalize_headline_source_hints(merged_hints);

        if !merged_hints.is_empty() {
            selected_urls.retain(|selected| {
                let selected_trimmed = selected.trim();
                !selected_trimmed.is_empty()
                    && merged_hints.iter().any(|hint| {
                        let hint_url = hint.url.trim();
                        hint_url.eq_ignore_ascii_case(selected_trimmed)
                            || url_structurally_equivalent(hint_url, selected_trimmed)
                    })
            });
        }
        if selected_urls.len() < required_url_count {
            for hint in &merged_hints {
                if selected_urls.len() >= required_url_count {
                    break;
                }
                let _ = push_unique_selected_url(&mut selected_urls, &hint.url);
            }
        }
    }
    resolve_selected_urls_from_hints(&mut selected_urls, &merged_hints);
    if headline_lookup_mode {
        selected_urls.retain(|selected| {
            let trimmed = selected.trim();
            !trimmed.is_empty()
                && !is_news_feed_wrapper_url(trimmed)
                && is_headline_citable_page_url(trimmed)
        });
        if selected_urls.len() < target_url_count {
            for hint in &merged_hints {
                if selected_urls.len() >= target_url_count {
                    break;
                }
                let hint_url = hint.url.trim();
                if hint_url.is_empty() {
                    continue;
                }
                if is_news_feed_wrapper_url(hint_url) || !is_headline_citable_page_url(hint_url) {
                    continue;
                }
                let _ = push_unique_selected_url(&mut selected_urls, hint_url);
            }
        }
    }

    let search_url_attempt = bundle
        .url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
        .into_iter()
        .collect::<Vec<_>>();

    let had_pending_pipeline = agent_state.pending_search_completion.is_some();
    let incoming_pending = PendingSearchCompletion {
        query: query_value,
        query_contract,
        url: bundle.url.clone().unwrap_or_default(),
        started_step: pre_state_step_index,
        started_at_ms,
        deadline_ms: started_at_ms.saturating_add(WEB_PIPELINE_BUDGET_MS),
        candidate_urls: selected_urls.clone(),
        candidate_source_hints: merged_hints,
        attempted_urls: search_url_attempt,
        blocked_urls: Vec::new(),
        successful_reads: Vec::new(),
        min_sources,
    };
    let mut pending = if let Some(existing) = agent_state.pending_search_completion.clone() {
        merge_pending_search_completion(existing, incoming_pending)
    } else {
        incoming_pending
    };

    let preexisting_queued_reads = queued_web_read_count(agent_state);
    let queued_reads = if !selected_urls.is_empty() {
        queue_web_read_batch_from_pipeline(agent_state, session_id, &selected_urls)?
    } else {
        0
    };
    let total_queued_reads = preexisting_queued_reads.saturating_add(queued_reads);
    let mut probe_queued = false;
    let mut probe_budget_ok = true;
    let probe_allowed =
        deterministic_plan.requires_constraint_search_probe && !had_pending_pipeline;
    if probe_allowed {
        let now_ms = web_pipeline_now_ms();
        probe_budget_ok = web_pipeline_can_queue_probe_search_latency_aware(&pending, now_ms);
        if probe_budget_ok {
            let prior_query = bundle
                .query
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| pending.query.trim());
            if let Some(probe_query) = constraint_grounded_probe_query_with_hints_and_locality_hint(
                pending.query_contract.as_str(),
                pending.min_sources,
                &probe_source_hints,
                prior_query,
                locality_hint.as_deref(),
            ) {
                let probe_limit = constraint_grounded_search_limit(
                    pending.query_contract.as_str(),
                    pending.min_sources,
                );
                probe_queued = queue_web_search_from_pipeline(
                    agent_state,
                    session_id,
                    probe_query.as_str(),
                    probe_limit,
                )?;
                if probe_queued {
                    verification_checks
                        .push(format!("web_constraint_search_probe_query={}", probe_query));
                    verification_checks
                        .push(format!("web_constraint_search_probe_limit={}", probe_limit));
                }
            }
        }
    }

    verification_checks.push(format!(
        "web_pre_read_discovery_sources={}",
        discovery_sources.len()
    ));
    verification_checks.push(format!("web_pre_read_required_urls={}", required_url_count));
    verification_checks.push(format!(
        "web_pre_read_selected_urls={}",
        selected_urls.len()
    ));
    if !selected_urls.is_empty() {
        verification_checks.push(format!(
            "web_pre_read_selected_url_values={}",
            selected_urls.join(" | ")
        ));
    }
    if !discovery_sources.is_empty() {
        let discovery_urls = discovery_sources
            .iter()
            .map(|source| source.url.trim())
            .filter(|url| !url.is_empty())
            .take(10)
            .collect::<Vec<_>>();
        if !discovery_urls.is_empty() {
            verification_checks.push(format!(
                "web_pre_read_discovery_url_values={}",
                discovery_urls.join(" | ")
            ));
        }
    }
    verification_checks.push(format!(
        "web_pre_read_existing_reads_queued={}",
        preexisting_queued_reads
    ));
    verification_checks.push(format!("web_pre_read_batch_reads_queued={}", queued_reads));
    verification_checks.push(format!(
        "web_pre_read_total_reads_queued={}",
        total_queued_reads
    ));
    verification_checks.push(format!(
        "web_pre_read_deterministic_fallback_used={}",
        deterministic_fallback_used
    ));
    verification_checks.push(format!(
        "web_pre_read_deterministic_top_up_used={}",
        deterministic_top_up_used
    ));
    verification_checks.push(format!("web_min_sources={}", min_sources));
    verification_checks.push(format!("web_headline_lookup_mode={}", headline_lookup_mode));
    verification_checks.push(format!(
        "web_query_contract={}",
        pending.query_contract.trim()
    ));
    verification_checks.push(format!("web_pending_query={}", pending.query.trim()));
    verification_checks.push(format!(
        "web_constraint_search_probe_required={}",
        deterministic_plan.requires_constraint_search_probe
    ));
    verification_checks.push(format!(
        "web_constraint_search_probe_allowed={}",
        probe_allowed
    ));
    verification_checks.push(format!(
        "web_constraint_search_probe_budget_ok={}",
        probe_budget_ok
    ));
    verification_checks.push(format!(
        "web_constraint_search_probe_queued={}",
        probe_queued
    ));
    verification_checks.push(format!(
        "web_pre_read_payload_valid={}",
        payload_error.is_none()
    ));
    if let Some(error) = payload_error.as_deref() {
        verification_checks.push(format!("web_pre_read_payload_error={}", error));
    }

    if total_queued_reads == 0 && !probe_queued {
        if let Some(error) = payload_error {
            // Preserve synthesis diagnostics while carrying the explicit state-3 failure signal.
            pending
                .blocked_urls
                .push(format!("ioi://state3-synthesis-error/{}", error));
        }
        let summary = synthesize_summary(
            service,
            &pending,
            WebPipelineCompletionReason::ExhaustedCandidates,
        )
        .await;
        complete_with_summary(
            agent_state,
            summary,
            success,
            out,
            err,
            completion_summary,
            true,
        );
        verification_checks.push("web_pipeline_active=false".to_string());
        verification_checks.push("terminal_chat_reply_ready=true".to_string());
        return Ok(());
    }

    verification_checks.push("web_pipeline_active=true".to_string());
    verification_checks.push("web_sources_success=0".to_string());
    verification_checks.push("web_sources_blocked=0".to_string());
    verification_checks.push("web_budget_ms=0".to_string());
    agent_state.pending_search_completion = Some(pending);
    agent_state.status = AgentStatus::Running;
    Ok(())
}

pub(super) async fn maybe_handle_web_read(
    service: &DesktopAgentService,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    tool_name: &str,
    tool_wrapper: &AgentTool,
    is_gated: bool,
    success: &mut bool,
    out: &mut Option<String>,
    err: &mut Option<String>,
    completion_summary: &mut Option<String>,
    verification_checks: &mut Vec<String>,
) -> Result<(), TransactionError> {
    if is_gated || tool_name != "web__read" {
        return Ok(());
    }
    let Some(mut pending) = agent_state.pending_search_completion.clone() else {
        return Ok(());
    };

    let current_url = match tool_wrapper {
        AgentTool::WebRead { url, .. } => url.trim().to_string(),
        _ => String::new(),
    };

    if !current_url.is_empty() {
        mark_pending_web_attempted(&mut pending, &current_url);
    }

    if *success {
        if let Some(bundle) = out.as_deref().and_then(parse_web_evidence_bundle) {
            append_pending_web_success_from_bundle(&mut pending, &bundle, &current_url);
        } else {
            append_pending_web_success_fallback(&mut pending, &current_url, out.as_deref());
        }
    } else if !current_url.is_empty() && is_human_challenge_error(err.as_deref().unwrap_or("")) {
        mark_pending_web_blocked(&mut pending, &current_url);
    }

    let now_ms = web_pipeline_now_ms();
    let elapsed_ms = now_ms.saturating_sub(pending.started_at_ms);
    let remaining_candidates = remaining_pending_web_candidates(&pending);
    let min_sources_required = pending.min_sources.max(1) as usize;
    let floor_unmet = pending.successful_reads.len() < min_sources_required;
    let probe_marker_prefix = "ioi://constraint-probe/";
    let probe_already_attempted = pending
        .attempted_urls
        .iter()
        .any(|url| url.starts_with(probe_marker_prefix));
    let probe_allowed = remaining_candidates == 0 && floor_unmet && !probe_already_attempted;
    let mut probe_budget_ok = true;
    let mut probe_queued = false;
    if probe_allowed {
        probe_budget_ok = web_pipeline_can_queue_probe_search_latency_aware(&pending, now_ms);
        if probe_budget_ok {
            let query_contract = if pending.query_contract.trim().is_empty() {
                pending.query.as_str()
            } else {
                pending.query_contract.as_str()
            };
            let locality_hint = if query_requires_runtime_locality_scope(query_contract) {
                effective_locality_scope_hint(None)
            } else {
                None
            };
            let prior_query = if pending.query.trim().is_empty() {
                query_contract.trim()
            } else {
                pending.query.trim()
            };
            if let Some(probe_query) = constraint_grounded_probe_query_with_hints_and_locality_hint(
                query_contract,
                pending.min_sources,
                &pending.candidate_source_hints,
                prior_query,
                locality_hint.as_deref(),
            ) {
                let probe_limit =
                    constraint_grounded_search_limit(query_contract, pending.min_sources);
                probe_queued = queue_web_search_from_pipeline(
                    agent_state,
                    session_id,
                    probe_query.as_str(),
                    probe_limit,
                )?;
                if probe_queued {
                    pending
                        .attempted_urls
                        .push(format!("{}{}", probe_marker_prefix, probe_query));
                    verification_checks
                        .push(format!("web_constraint_search_probe_query={}", probe_query));
                    verification_checks
                        .push(format!("web_constraint_search_probe_limit={}", probe_limit));
                }
            }
        }
    }

    let completion_reason = if probe_queued {
        None
    } else if pending.deadline_ms > 0 && now_ms >= pending.deadline_ms {
        Some(WebPipelineCompletionReason::DeadlineReached)
    } else if remaining_candidates == 0 {
        if pending.successful_reads.len() >= min_sources_required {
            Some(WebPipelineCompletionReason::MinSourcesReached)
        } else {
            Some(WebPipelineCompletionReason::ExhaustedCandidates)
        }
    } else {
        None
    };

    verification_checks.push(format!(
        "web_sources_success={}",
        pending.successful_reads.len()
    ));
    verification_checks.push(format!(
        "web_sources_blocked={}",
        pending.blocked_urls.len()
    ));
    verification_checks.push(format!("web_budget_ms={}", elapsed_ms));
    verification_checks.push(format!("web_remaining_candidates={}", remaining_candidates));
    verification_checks.push(format!(
        "web_constraint_search_probe_allowed={}",
        probe_allowed
    ));
    verification_checks.push(format!(
        "web_constraint_search_probe_budget_ok={}",
        probe_budget_ok
    ));
    verification_checks.push(format!(
        "web_constraint_search_probe_queued={}",
        probe_queued
    ));

    if let Some(reason) = completion_reason {
        let summary = synthesize_summary(service, &pending, reason).await;
        complete_with_summary(
            agent_state,
            summary,
            success,
            out,
            err,
            completion_summary,
            true,
        );
        verification_checks.push("web_pipeline_active=false".to_string());
        verification_checks.push("terminal_chat_reply_ready=true".to_string());
        return Ok(());
    }

    let challenge = is_human_challenge_error(err.as_deref().unwrap_or(""));
    verification_checks.push("web_pipeline_active=true".to_string());
    agent_state.pending_search_completion = Some(pending);
    if !*success {
        let note = if challenge {
            format!(
                "Recorded challenged source in fixed payload (no fallback retries): {}",
                current_url
            )
        } else {
            format!(
                "Source read failed in fixed payload (no fallback retries): {}",
                current_url
            )
        };
        *success = true;
        *out = Some(note);
        *err = None;
        agent_state.status = AgentStatus::Running;
    }

    Ok(())
}

pub(super) fn maybe_handle_browser_snapshot(
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    tool_name: &str,
    is_gated: bool,
    success: &mut bool,
    out: &mut Option<String>,
    err: &mut Option<String>,
    completion_summary: &mut Option<String>,
) {
    if is_gated || tool_name != "browser__snapshot" {
        return;
    }
    let Some(pending) = agent_state.pending_search_completion.clone() else {
        return;
    };
    let summary = if *success {
        summarize_search_results(&pending.query, &pending.url, out.as_deref().unwrap_or(""))
    } else {
        fallback_search_summary(&pending.query, &pending.url)
    };
    complete_with_summary(
        agent_state,
        summary,
        success,
        out,
        err,
        completion_summary,
        true,
    );
    log::info!(
        "Search flow completed after browser__snapshot for session {}.",
        hex::encode(&session_id[..4])
    );
}
