use super::super::support::{
    append_pending_web_success_fallback, append_pending_web_success_from_bundle,
    candidate_source_hints_from_bundle,
    constraint_grounded_probe_query_with_hints_and_locality_hint, constraint_grounded_search_limit,
    effective_locality_scope_hint, extract_json_object, fallback_search_summary,
    is_citable_web_url, is_google_news_rss_wrapper_url, is_human_challenge_error,
    is_search_hub_url, mark_pending_web_attempted, mark_pending_web_blocked,
    merge_pending_search_completion, parse_web_evidence_bundle,
    pre_read_candidate_plan_from_bundle_with_locality_hint, query_is_generic_headline_collection,
    query_requires_runtime_locality_scope, queue_web_read_from_pipeline,
    queue_web_search_from_pipeline, remaining_pending_web_candidates,
    select_web_pipeline_query_contract, source_host, summarize_search_results,
    synthesize_web_pipeline_reply, synthesize_web_pipeline_reply_hybrid,
    url_structurally_equivalent, web_pipeline_can_queue_probe_search_latency_aware,
    web_pipeline_min_sources, web_pipeline_now_ms, WebPipelineCompletionReason,
    WEB_PIPELINE_BUDGET_MS,
};
use super::completion::complete_with_summary;
use super::routing::is_web_research_scope;
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

fn looks_like_deep_article_url(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() || is_search_hub_url(trimmed) {
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

fn lint_pre_read_payload_urls(
    urls: &[String],
    required_count: usize,
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

    let mut domains = std::collections::BTreeSet::new();
    for url in &normalized {
        if !looks_like_deep_article_url(url) {
            return Err(format!("non-deep-link URL selected: {}", url));
        }
        let Some(domain) = normalized_domain_key(url) else {
            return Err(format!("failed to resolve domain for URL: {}", url));
        };
        domains.insert(domain);
    }

    if domains.len() != required_count {
        return Err(format!(
            "expected {} distinct domains but received {}",
            required_count,
            domains.len()
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
    PreReadSelectionPayload {
        query: query_contract.trim().to_string(),
        required_url_count,
        constraints: vec![
            "Select only URLs that are direct article pages, not homepages, hubs, or section fronts."
                .to_string(),
            "Return exactly the required URL count.".to_string(),
            "Each URL must come from a distinct domain.".to_string(),
            "Do not invent or modify URLs; only choose from provided sources.".to_string(),
        ],
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
                 Re-select URLs from payload.sources only and satisfy all constraints.\n\
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
                 - Deep links only (not homepage/hub URLs).\n\
                 - Use ONLY URLs present in payload.sources.\n\
                 Payload:\n{}",
                required_url_count, payload_json
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
        let selected_inventory = parsed
            .urls
            .iter()
            .map(|url| url.trim().to_ascii_lowercase())
            .collect::<std::collections::BTreeSet<_>>();
        if !selected_inventory
            .iter()
            .all(|url| source_inventory.contains(url))
        {
            let missing = selected_inventory
                .iter()
                .filter(|url| !source_inventory.contains(*url))
                .cloned()
                .collect::<Vec<_>>();
            last_error = format!(
                "response included URLs outside discovery payload: {:?}",
                missing
            );
            feedback = Some(last_error.clone());
            if attempt == WEB_PIPELINE_PRE_READ_SYNTHESIS_MAX_ATTEMPTS {
                break;
            }
            continue;
        }

        match lint_pre_read_payload_urls(&parsed.urls, required_url_count) {
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
    let url = hint.url.trim();
    if url.is_empty() || !is_citable_web_url(url) {
        return false;
    }
    if is_search_hub_url(url) && !is_google_news_rss_wrapper_url(url) {
        return false;
    }

    let lower_url = url.to_ascii_lowercase();
    let blocked_domains = [
        "stackexchange.com",
        "stackoverflow.com",
        "wikipedia.org",
        "reddit.com",
        "quora.com",
        "facebook.com",
        "instagram.com",
        "tiktok.com",
        "youtube.com",
    ];
    if blocked_domains
        .iter()
        .any(|domain| lower_url.contains(domain))
    {
        return false;
    }

    if is_google_news_rss_wrapper_url(url) {
        return true;
    }

    let title = hint
        .title
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let excerpt = hint.excerpt.to_ascii_lowercase();
    let signal_text = format!(" {} {} ", title, excerpt);
    let low_priority_markers = [
        " news websites ",
        " fact sheet ",
        " trust in media ",
        " which news sources ",
        " schedules and results ",
        " watch live ",
        " horoscope ",
        " horoscopes ",
        " how to watch ",
    ];
    if low_priority_markers
        .iter()
        .any(|marker| signal_text.contains(marker))
        || lower_url.contains("/horoscope")
        || lower_url.contains("/horoscopes")
    {
        return false;
    }
    let has_news_signal = [
        " news ",
        " headline ",
        " headlines ",
        " breaking ",
        " update ",
        " updates ",
        " report ",
        " reports ",
        " world ",
        " politics ",
        " business ",
        " market ",
        " economy ",
        " election ",
        " court ",
        " war ",
    ]
    .iter()
    .any(|marker| signal_text.contains(marker));
    if has_news_signal {
        return true;
    }

    [
        "/news",
        "/world",
        "/politics",
        "/business",
        "/us/",
        "/article",
    ]
    .iter()
    .any(|marker| lower_url.contains(marker))
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
    let required_url_count = min_sources as usize;
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
    let headline_lookup_mode = query_is_generic_headline_collection(&query_contract);
    let probe_source_hints = if headline_lookup_mode {
        let filtered = deterministic_plan
            .probe_source_hints
            .iter()
            .filter(|source| headline_source_hint_allowed(source))
            .cloned()
            .collect::<Vec<_>>();
        if filtered.is_empty() {
            deterministic_plan.probe_source_hints.clone()
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
        let discovery_hints = candidate_source_hints_from_bundle(bundle)
            .into_iter()
            .filter(headline_source_hint_allowed)
            .collect::<Vec<_>>();
        merged_hints = merge_source_hints(merged_hints, discovery_hints.as_slice());
        merged_hints = merged_hints
            .into_iter()
            .filter(headline_source_hint_allowed)
            .collect::<Vec<_>>();

        selected_urls.retain(|selected| {
            let selected_trimmed = selected.trim();
            !selected_trimmed.is_empty()
                && merged_hints.iter().any(|hint| {
                    let hint_url = hint.url.trim();
                    hint_url.eq_ignore_ascii_case(selected_trimmed)
                        || url_structurally_equivalent(hint_url, selected_trimmed)
                })
        });
        if selected_urls.len() < required_url_count {
            for hint in &merged_hints {
                if selected_urls.len() >= required_url_count {
                    break;
                }
                let _ = push_unique_selected_url(&mut selected_urls, &hint.url);
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
