use crate::agentic::desktop::service::step::action::{
    emit_completion_gate_status_event, resolved_intent_id,
};
use crate::agentic::desktop::service::step::queue::web_pipeline::{
    candidate_source_hints_from_bundle,
    constraint_grounded_probe_query_with_hints_and_locality_hint, constraint_grounded_search_limit,
    effective_locality_scope_hint, is_citable_web_url, is_multi_item_listing_url,
    is_search_hub_url, merge_pending_search_completion,
    pre_read_candidate_plan_from_bundle_with_locality_hint, query_is_generic_headline_collection,
    query_requires_runtime_locality_scope, queue_web_read_from_pipeline,
    queue_web_search_from_pipeline, select_web_pipeline_query_contract, source_host,
    synthesize_web_pipeline_reply, synthesize_web_pipeline_reply_hybrid,
    url_structurally_equivalent, web_pipeline_can_queue_probe_search_latency_aware,
    web_pipeline_grounded_probe_attempt_available, web_pipeline_min_sources, web_pipeline_now_ms,
    WebPipelineCompletionReason, WEB_PIPELINE_BUDGET_MS,
};
use crate::agentic::desktop::service::step::signals::analyze_source_record_signals;
use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::{
    AgentState, AgentStatus, PendingSearchCompletion, PendingSearchReadSummary,
};
use ioi_types::app::agentic::{InferenceOptions, WebEvidenceBundle, WebSource};
use ioi_types::app::ActionTarget;
use ioi_types::error::TransactionError;
use serde::{Deserialize, Serialize};
use url::Url;

const WEB_PIPELINE_DISCOVERY_SOURCE_LIMIT: usize = 15;
const WEB_PIPELINE_PRE_READ_SYNTHESIS_MAX_ATTEMPTS: usize = 3;
const WEB_PIPELINE_PRE_READ_SYNTHESIS_MAX_TOKENS: u32 = 700;

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

fn extract_json_object(raw: &str) -> Option<&str> {
    let start = raw.find('{')?;
    let end = raw.rfind('}')?;
    (end >= start).then_some(&raw[start..=end])
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
    let segments = normalized_path
        .split('/')
        .filter(|segment| !segment.trim().is_empty())
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return false;
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
        let airlocked_prompt = service
            .prepare_cloud_inference_input(
                None,
                "desktop_agent",
                "web_pre_read_payload_synthesis",
                prompt.as_bytes(),
            )
            .await
            .map_err(|err| format!("pre-read synthesis airlock failed: {}", err))?;
        let raw = service
            .reasoning_inference
            .execute_inference([0u8; 32], &airlocked_prompt, options)
            .await
            .map_err(|err| format!("pre-read synthesis inference failed: {}", err))?;
        let text = String::from_utf8(raw)
            .map_err(|err| format!("pre-read synthesis response was not UTF-8: {}", err))?;
        let json_text = extract_json_object(&text).unwrap_or(text.as_str());
        let parsed: PreReadSelectionResponse = serde_json::from_str(json_text)
            .map_err(|err| format!("pre-read synthesis returned invalid JSON schema: {}", err))?;

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

fn projection_candidate_url_allowed(raw: &str) -> bool {
    let trimmed = raw.trim();
    !trimmed.is_empty()
        && is_citable_web_url(trimmed)
        && !is_search_hub_url(trimmed)
        && !is_multi_item_listing_url(trimmed)
        && looks_like_deep_article_url(trimmed)
}

fn resolved_hint_candidate_url(hint: &PendingSearchReadSummary) -> Option<String> {
    let trimmed = hint.url.trim();
    if trimmed.is_empty() {
        return None;
    }
    if projection_candidate_url_allowed(trimmed) {
        return Some(trimmed.to_string());
    }
    let candidate = source_url_from_metadata_excerpt(&hint.excerpt)?;
    projection_candidate_url_allowed(&candidate).then_some(candidate)
}

fn headline_source_low_priority(url: &str, title: &str, excerpt: &str) -> bool {
    let signals = analyze_source_record_signals(url, title, excerpt);
    signals.low_priority_hits > 0 || signals.low_priority_dominates()
}

fn headline_selection_quality_metrics(
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

        total_sources = total_sources.saturating_add(1);
        if let Some(domain) = normalized_domain_key(selected_trimmed) {
            distinct_domains.insert(domain);
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
            .filter(|resolved_url| projection_candidate_url_allowed(resolved_url));
        if let Some(resolved_url) = resolved {
            if !projection_candidate_url_allowed(&selected_trimmed) {
                *selected = resolved_url;
            }
        }
    }

    let mut deduped = Vec::new();
    for selected in selected_urls.iter() {
        let _ = push_unique_selected_url(&mut deduped, selected);
    }
    *selected_urls = deduped;
}

fn collect_projection_candidate_urls(
    selected_urls: &[String],
    source_hints: &[PendingSearchReadSummary],
    target_count: usize,
    distinct_domain_floor: usize,
    blocked_domains: &std::collections::BTreeSet<String>,
) -> Vec<String> {
    let mut ordered_candidates = Vec::new();
    for url in selected_urls {
        let trimmed = url.trim();
        if !projection_candidate_url_allowed(trimmed) {
            continue;
        }
        if normalized_domain_key(trimmed)
            .map(|domain| blocked_domains.contains(&domain))
            .unwrap_or(false)
        {
            continue;
        }
        let _ = push_unique_selected_url(&mut ordered_candidates, trimmed);
    }
    for hint in source_hints {
        let Some(candidate) = resolved_hint_candidate_url(hint) else {
            continue;
        };
        if normalized_domain_key(&candidate)
            .map(|domain| blocked_domains.contains(&domain))
            .unwrap_or(false)
        {
            continue;
        }
        let _ = push_unique_selected_url(&mut ordered_candidates, &candidate);
    }

    let target = target_count.max(1);
    let domain_floor = distinct_domain_floor.min(target);
    let mut output = Vec::new();
    let mut seen_domains = std::collections::BTreeSet::new();

    if domain_floor > 1 {
        for candidate in &ordered_candidates {
            if output.len() >= target || seen_domains.len() >= domain_floor {
                break;
            }
            let domain_key = normalized_domain_key(candidate)
                .unwrap_or_else(|| candidate.trim().to_ascii_lowercase());
            if !seen_domains.insert(domain_key) {
                continue;
            }
            let _ = push_unique_selected_url(&mut output, candidate);
        }
    }

    for candidate in &ordered_candidates {
        if output.len() >= target {
            break;
        }
        let _ = push_unique_selected_url(&mut output, candidate);
    }

    output
}

fn pre_read_batch_target(query_contract: &str, min_sources: u32) -> usize {
    constraint_grounded_search_limit(query_contract, min_sources.max(1)) as usize
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

pub(super) async fn apply_pre_read_bundle(
    service: &DesktopAgentService,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    started_step: u32,
    bundle: &WebEvidenceBundle,
    query_fallback: &str,
    verification_checks: &mut Vec<String>,
    history_entry: &mut Option<String>,
    action_output: &mut Option<String>,
    terminal_chat_reply_output: &mut Option<String>,
    is_lifecycle_action: &mut bool,
) -> Result<(), TransactionError> {
    let query_value = bundle
        .query
        .clone()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            let trimmed = query_fallback.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        })
        .unwrap_or_else(|| agent_state.goal.clone());
    let query_contract =
        select_web_pipeline_query_contract(agent_state.goal.as_str(), &query_value);

    let min_sources = web_pipeline_min_sources(&query_contract).max(1);
    let headline_lookup_mode = query_is_generic_headline_collection(&query_contract);
    let required_url_count = min_sources as usize;
    let pre_read_target = pre_read_batch_target(&query_contract, min_sources);
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
    let probe_source_hints = deterministic_plan.probe_source_hints.clone();
    let selection = synthesize_pre_read_payload_urls(
        service,
        &query_contract,
        required_url_count,
        &discovery_sources,
    )
    .await;
    let (selected_urls, payload_error, payload_synthesis_skipped) = match selection {
        Ok(urls) => (urls, None, false),
        Err(error) => (Vec::new(), Some(error), false),
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
    let discovery_hints = candidate_source_hints_from_bundle(bundle);
    merged_hints = merge_source_hints(merged_hints, discovery_hints.as_slice());
    resolve_selected_urls_from_hints(&mut selected_urls, &merged_hints);
    let blocked_domains = agent_state
        .pending_search_completion
        .as_ref()
        .map(|pending| {
            pending
                .blocked_urls
                .iter()
                .filter_map(|url| normalized_domain_key(url))
                .collect::<std::collections::BTreeSet<_>>()
        })
        .unwrap_or_default();
    selected_urls = collect_projection_candidate_urls(
        &selected_urls,
        &merged_hints,
        pre_read_target,
        required_url_count,
        &blocked_domains,
    );

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
        started_step,
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
    let constraint_probe_attempt_count = pending
        .attempted_urls
        .iter()
        .filter(|entry| entry.trim().starts_with("ioi://constraint-probe/"))
        .count();
    let pending_search_recovery_probe_allowed = had_pending_pipeline
        && deterministic_plan.requires_constraint_search_probe
        && queued_reads == 0
        && preexisting_queued_reads > 0
        && pending.successful_reads.is_empty()
        && selected_urls.is_empty()
        && (payload_error.is_some() || payload_synthesis_skipped)
        && constraint_probe_attempt_count < 2
        && web_pipeline_grounded_probe_attempt_available(&pending);
    let probe_allowed = deterministic_plan.requires_constraint_search_probe
        && (!had_pending_pipeline || pending_search_recovery_probe_allowed);
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
                    let probe_attempt_marker = format!("ioi://constraint-probe/{}", probe_query);
                    if !pending
                        .attempted_urls
                        .iter()
                        .any(|entry| entry == &probe_attempt_marker)
                    {
                        pending.attempted_urls.push(probe_attempt_marker);
                    }
                    verification_checks
                        .push(format!("web_constraint_search_probe_query={}", probe_query));
                    verification_checks
                        .push(format!("web_constraint_search_probe_limit={}", probe_limit));
                }
            }
        }
    }

    if headline_lookup_mode {
        let (
            headline_total_sources,
            headline_low_priority_sources,
            headline_distinct_domains,
            headline_low_priority_urls,
        ) = headline_selection_quality_metrics(&selected_urls, &pending.candidate_source_hints);
        let headline_quality_floor_met = headline_total_sources >= required_url_count
            && headline_low_priority_sources == 0
            && headline_distinct_domains >= required_url_count;
        verification_checks.push(format!(
            "web_headline_selected_sources_total={}",
            headline_total_sources
        ));
        verification_checks.push(format!(
            "web_headline_selected_sources_low_priority={}",
            headline_low_priority_sources
        ));
        verification_checks.push(format!(
            "web_headline_selected_sources_distinct_domains={}",
            headline_distinct_domains
        ));
        verification_checks.push(format!(
            "web_headline_selected_sources_quality_floor_met={}",
            headline_quality_floor_met
        ));
        if !headline_low_priority_urls.is_empty() {
            verification_checks.push(format!(
                "web_headline_selected_sources_low_priority_urls={}",
                headline_low_priority_urls.join(" | ")
            ));
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
    verification_checks.push(format!("web_pre_read_batch_target={}", pre_read_target));
    if headline_lookup_mode {
        verification_checks.push(format!(
            "web_headline_read_batch_target={}",
            pre_read_target
        ));
    }
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
        "web_constraint_search_probe_recovery_allowed={}",
        pending_search_recovery_probe_allowed
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
    verification_checks.push(format!(
        "web_pre_read_payload_synthesis_skipped={}",
        payload_synthesis_skipped
    ));
    if let Some(error) = payload_error.as_deref() {
        verification_checks.push(format!("web_pre_read_payload_error={}", error));
    }

    if total_queued_reads == 0 && !probe_queued {
        if let Some(error) = payload_error {
            pending
                .blocked_urls
                .push(format!("ioi://state3-synthesis-error/{}", error));
        }
        let reason = WebPipelineCompletionReason::ExhaustedCandidates;
        let summary = if let Some(hybrid_summary) =
            synthesize_web_pipeline_reply_hybrid(service, &pending, reason).await
        {
            hybrid_summary
        } else {
            synthesize_web_pipeline_reply(&pending, reason)
        };
        *action_output = Some(summary.clone());
        *history_entry = Some(summary.clone());
        *terminal_chat_reply_output = Some(summary.clone());
        *is_lifecycle_action = true;
        agent_state.status = AgentStatus::Completed(Some(summary));
        agent_state.pending_search_completion = None;
        agent_state.execution_queue.clear();
        agent_state.recent_actions.clear();
        let intent_id = resolved_intent_id(agent_state);
        emit_completion_gate_status_event(
            service,
            session_id,
            started_step,
            intent_id.as_str(),
            true,
            "web_pre_read_completion_gate_passed",
        );
        verification_checks.push("cec_completion_gate_emitted=true".to_string());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projection_candidate_url_rejects_placeholder_slug_segments() {
        assert!(!projection_candidate_url_allowed(
            "https://www.cbsnews.com/news/article-title/"
        ));
        assert!(!projection_candidate_url_allowed(
            "https://apnews.com/article/story-title"
        ));
        assert!(!projection_candidate_url_allowed(
            "https://www.foxnews.com/shows/fox-news-live"
        ));
    }

    #[test]
    fn projection_candidate_url_accepts_real_article_paths() {
        assert!(projection_candidate_url_allowed(
            "https://www.reuters.com/world/europe/example-article-slug-2026-03-01/"
        ));
    }
}
