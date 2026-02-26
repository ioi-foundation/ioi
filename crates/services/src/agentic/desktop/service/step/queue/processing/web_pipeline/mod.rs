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

mod read;
mod search;
mod snapshot;

pub(super) use read::maybe_handle_web_read;
pub(super) use search::maybe_handle_web_search;
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
