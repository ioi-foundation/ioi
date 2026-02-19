use crate::agentic::desktop::middleware;
use crate::agentic::desktop::types::{
    AgentState, PendingSearchCompletion, PendingSearchReadSummary,
};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_types::app::agentic::{AgentTool, InferenceOptions, WebEvidenceBundle};
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget};
use ioi_types::error::TransactionError;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_SEARCH_EXTRACT_CHARS: usize = 8_000;
const QUEUE_TOOL_NAME_KEY: &str = "__ioi_tool_name";
const WEB_PIPELINE_EXCERPT_CHARS: usize = 220;
pub(crate) const WEB_PIPELINE_BUDGET_MS: u64 = 60_000;
pub(crate) const WEB_PIPELINE_DEFAULT_MIN_SOURCES: u32 = 2;
pub(crate) const WEB_PIPELINE_SEARCH_LIMIT: u32 = 10;
pub(crate) const WEB_PIPELINE_REQUIRED_STORIES: usize = 3;
pub(crate) const WEB_PIPELINE_CITATIONS_PER_STORY: usize = 2;
pub(crate) const WEB_PIPELINE_REQUIRED_DISTINCT_CITATIONS: usize =
    WEB_PIPELINE_REQUIRED_STORIES * WEB_PIPELINE_CITATIONS_PER_STORY;

const WEB_PIPELINE_STORY_TITLE_CHARS: usize = 140;
const WEB_PIPELINE_HYBRID_MAX_TOKENS: u32 = 1_200;
const WEB_PIPELINE_HYBRID_BUDGET_GUARD_MS: u64 = 8_000;
const SOURCE_QUALITY_META_MARKERS: [&str; 10] = [
    "news websites",
    "fact sheet",
    "trust in media",
    "news sources americans use",
    "which news sources",
    "breaking headlines",
    "headlines and video reports",
    "news, schedules, results",
    "schedules and results",
    "schedules, results",
];
const SOURCE_QUALITY_EVENT_SIGNAL_MARKERS: [&str; 18] = [
    "breaking",
    "storm",
    "wildfire",
    "flood",
    "earthquake",
    "evacuation",
    "court",
    "doj",
    "congress",
    "senate",
    "house",
    "policy",
    "attack",
    "shooting",
    "charges",
    "investigation",
    "market",
    "inflation",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WebPipelineCompletionReason {
    MinSourcesReached,
    ExhaustedCandidates,
    DeadlineReached,
}

pub(super) fn fallback_search_summary(query: &str, url: &str) -> String {
    format!(
        "Searched '{}' at {}, but structured extraction failed. Retry refinement if needed.",
        query, url
    )
}

fn strip_markup(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_tag = false;
    for ch in input.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                out.push(' ');
            }
            _ if in_tag => {}
            _ => out.push(ch),
        }
    }
    out
}

fn compact_whitespace(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn extract_urls(input: &str, limit: usize) -> Vec<String> {
    let mut urls = Vec::new();
    for raw in input.split_whitespace() {
        let trimmed = raw
            .trim_matches(|ch: char| ",.;:!?)]}\"'".contains(ch))
            .trim();
        if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
            continue;
        }
        if urls.iter().any(|existing| existing == trimmed) {
            continue;
        }
        urls.push(trimmed.to_string());
        if urls.len() >= limit {
            break;
        }
    }
    urls
}

fn extract_finding_lines(input: &str, limit: usize) -> Vec<String> {
    let mut findings = Vec::new();
    for line in input.lines() {
        let normalized = compact_whitespace(line).trim().to_string();
        if normalized.len() < 24 || normalized.len() > 200 {
            continue;
        }
        if normalized.starts_with("http://") || normalized.starts_with("https://") {
            continue;
        }
        if normalized.to_ascii_lowercase().contains("cookie")
            || normalized.to_ascii_lowercase().contains("javascript")
        {
            continue;
        }
        if findings.iter().any(|existing| existing == &normalized) {
            continue;
        }
        findings.push(normalized);
        if findings.len() >= limit {
            break;
        }
    }
    findings
}

pub(super) fn summarize_search_results(query: &str, url: &str, extract_text: &str) -> String {
    let capped = extract_text
        .chars()
        .take(MAX_SEARCH_EXTRACT_CHARS)
        .collect::<String>();
    let stripped = strip_markup(&capped);
    let findings = extract_finding_lines(&stripped, 3);
    let urls = extract_urls(&capped, 2);

    let mut bullets: Vec<String> = Vec::new();
    for finding in findings {
        bullets.push(finding);
        if bullets.len() >= 3 {
            break;
        }
    }
    for link in urls.iter() {
        if bullets.len() >= 3 {
            break;
        }
        bullets.push(format!("Top link: {}", link));
    }

    if bullets.is_empty() {
        let snippet = compact_whitespace(&stripped)
            .chars()
            .take(180)
            .collect::<String>();
        if snippet.is_empty() {
            bullets.push("No high-signal snippets were extracted.".to_string());
        } else {
            bullets.push(format!("Extracted snippet: {}", snippet));
        }
    }

    let refinement_hint = if let Some(link) = urls.first() {
        format!(
            "Open '{}' or refine with more specific keywords (site:, date range, exact phrase).",
            link
        )
    } else {
        "Refine with more specific keywords (site:, date range, exact phrase).".to_string()
    };

    let mut summary = format!("Search summary for '{}':\n", query);
    for bullet in bullets.into_iter().take(3) {
        summary.push_str(&format!("- {}\n", bullet));
    }
    summary.push_str(&format!("- Source URL: {}\n", url));
    summary.push_str(&format!("Next refinement: {}", refinement_hint));
    summary
}

pub(crate) fn web_pipeline_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn civil_date_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    // Howard Hinnant civil-from-days algorithm, converted to Rust.
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

fn iso_date_from_unix_ms(unix_ms: u64) -> String {
    let days_since_epoch = (unix_ms / 86_400_000) as i64;
    let (year, month, day) = civil_date_from_days(days_since_epoch);
    format!("{:04}-{:02}-{:02}", year, month, day)
}

fn iso_datetime_from_unix_ms(unix_ms: u64) -> String {
    let days_since_epoch = (unix_ms / 86_400_000) as i64;
    let (year, month, day) = civil_date_from_days(days_since_epoch);
    let ms_of_day = unix_ms % 86_400_000;
    let hour = ms_of_day / 3_600_000;
    let minute = (ms_of_day % 3_600_000) / 60_000;
    let second = (ms_of_day % 60_000) / 1_000;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

fn normalize_confidence_label(label: &str) -> String {
    let normalized = label.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "high" | "medium" | "low" => normalized,
        _ => "low".to_string(),
    }
}

pub(crate) fn parse_web_evidence_bundle(raw: &str) -> Option<WebEvidenceBundle> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    serde_json::from_str::<WebEvidenceBundle>(trimmed).ok()
}

pub(crate) fn candidate_urls_from_bundle(bundle: &WebEvidenceBundle) -> Vec<String> {
    let mut urls = Vec::new();
    let mut seen = BTreeSet::new();

    for hint in candidate_source_hints_from_bundle(bundle) {
        let url = hint.url.trim();
        if !url.is_empty() && seen.insert(url.to_string()) {
            urls.push(url.to_string());
        }
    }

    for doc in &bundle.documents {
        let url = doc.url.trim();
        if url.is_empty() {
            continue;
        }
        if seen.insert(url.to_string()) {
            urls.push(url.to_string());
        }
    }

    urls
}

pub(crate) fn candidate_source_hints_from_bundle(
    bundle: &WebEvidenceBundle,
) -> Vec<PendingSearchReadSummary> {
    let mut hints = Vec::new();
    let mut seen = BTreeSet::new();
    let mut sources = bundle.sources.clone();
    sources.sort_by_key(|source| source.rank.unwrap_or(u32::MAX));
    for source in sources {
        let url = source.url.trim();
        if url.is_empty() || !seen.insert(url.to_string()) {
            continue;
        }
        hints.push(PendingSearchReadSummary {
            url: url.to_string(),
            title: source
                .title
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.to_string()),
            excerpt: compact_excerpt(source.snippet.as_deref().unwrap_or_default(), 180),
        });
    }
    hints
}

pub(crate) fn next_pending_web_candidate(pending: &PendingSearchCompletion) -> Option<String> {
    let mut attempted = BTreeSet::new();
    for url in &pending.attempted_urls {
        let trimmed = url.trim();
        if !trimmed.is_empty() {
            attempted.insert(trimmed.to_string());
        }
    }
    for url in &pending.blocked_urls {
        let trimmed = url.trim();
        if !trimmed.is_empty() {
            attempted.insert(trimmed.to_string());
        }
    }

    for candidate in &pending.candidate_urls {
        let trimmed = candidate.trim();
        if trimmed.is_empty() {
            continue;
        }
        if attempted.contains(trimmed) {
            continue;
        }
        return Some(trimmed.to_string());
    }

    None
}

pub(crate) fn mark_pending_web_attempted(pending: &mut PendingSearchCompletion, url: &str) {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return;
    }
    if pending
        .attempted_urls
        .iter()
        .any(|existing| existing.trim() == trimmed)
    {
        return;
    }
    pending.attempted_urls.push(trimmed.to_string());
}

pub(crate) fn mark_pending_web_blocked(pending: &mut PendingSearchCompletion, url: &str) {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return;
    }
    if pending
        .blocked_urls
        .iter()
        .any(|existing| existing.trim() == trimmed)
    {
        return;
    }
    pending.blocked_urls.push(trimmed.to_string());
}

fn compact_excerpt(input: &str, max_chars: usize) -> String {
    compact_whitespace(input)
        .chars()
        .take(max_chars)
        .collect::<String>()
}

fn marker_hits(text: &str, markers: &[&str]) -> usize {
    let lower = text.to_ascii_lowercase();
    markers
        .iter()
        .filter(|marker| lower.contains(**marker))
        .count()
}

fn is_meta_news_text(text: &str) -> bool {
    let meta_hits = marker_hits(text, &SOURCE_QUALITY_META_MARKERS);
    if meta_hits == 0 {
        return false;
    }
    let event_hits = marker_hits(text, &SOURCE_QUALITY_EVENT_SIGNAL_MARKERS);
    meta_hits > event_hits
}

fn is_meta_news_story(source: &PendingSearchReadSummary) -> bool {
    let title = source.title.as_deref().unwrap_or_default();
    let combined = format!("{} {}", title, source.excerpt);
    is_meta_news_text(&combined)
}

fn is_low_signal_title(title: &str) -> bool {
    let trimmed = title.trim();
    if trimmed.is_empty() {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "google news" | "news" | "home" | "homepage" | "untitled"
    ) || lower.starts_with("google news -")
}

fn is_low_signal_excerpt(excerpt: &str) -> bool {
    let trimmed = excerpt.trim();
    if trimmed.is_empty() {
        return true;
    }
    if trimmed.chars().count() < 28 {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    lower.contains("enable javascript")
        || lower.contains("cookie")
        || lower.contains("recaptcha")
        || lower.contains("human verification")
}

fn hint_for_url<'a>(
    pending: &'a PendingSearchCompletion,
    url: &str,
) -> Option<&'a PendingSearchReadSummary> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return None;
    }
    pending
        .candidate_source_hints
        .iter()
        .find(|hint| hint.url.trim() == trimmed)
}

fn push_pending_web_success(
    pending: &mut PendingSearchCompletion,
    url: &str,
    title: Option<String>,
    excerpt: String,
) {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return;
    }
    if pending
        .successful_reads
        .iter()
        .any(|existing| existing.url.trim() == trimmed)
    {
        return;
    }

    let hint = hint_for_url(pending, trimmed);
    let mut resolved_title = title
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());
    if resolved_title
        .as_deref()
        .map(is_low_signal_title)
        .unwrap_or(true)
    {
        if let Some(hint_title) = hint
            .and_then(|value| value.title.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            resolved_title = Some(hint_title.to_string());
        }
    }

    let mut resolved_excerpt = excerpt.trim().to_string();
    if is_low_signal_excerpt(&resolved_excerpt) {
        if let Some(hint_excerpt) = hint
            .map(|value| value.excerpt.trim())
            .filter(|value| !value.is_empty())
        {
            resolved_excerpt = hint_excerpt.to_string();
        }
    }

    pending.successful_reads.push(PendingSearchReadSummary {
        url: trimmed.to_string(),
        title: resolved_title,
        excerpt: resolved_excerpt,
    });
}

pub(crate) fn append_pending_web_success_fallback(
    pending: &mut PendingSearchCompletion,
    url: &str,
    raw_output: Option<&str>,
) {
    let excerpt = compact_excerpt(raw_output.unwrap_or_default(), WEB_PIPELINE_EXCERPT_CHARS);
    push_pending_web_success(pending, url, None, excerpt);
}

pub(crate) fn append_pending_web_success_from_bundle(
    pending: &mut PendingSearchCompletion,
    bundle: &WebEvidenceBundle,
    fallback_url: &str,
) {
    if let Some(doc) = bundle.documents.first() {
        let title = doc
            .title
            .clone()
            .or_else(|| {
                bundle
                    .sources
                    .iter()
                    .find(|source| source.source_id == doc.source_id)
                    .and_then(|source| source.title.clone())
            })
            .filter(|value| !value.trim().is_empty());
        let excerpt = compact_excerpt(&doc.content_text, WEB_PIPELINE_EXCERPT_CHARS);
        push_pending_web_success(pending, &doc.url, title, excerpt);
        return;
    }

    if let Some(source) = bundle.sources.first() {
        let excerpt = compact_excerpt(source.snippet.as_deref().unwrap_or_default(), 180);
        push_pending_web_success(pending, &source.url, source.title.clone(), excerpt);
        return;
    }

    append_pending_web_success_fallback(pending, fallback_url, None);
}

pub(crate) fn remaining_pending_web_candidates(pending: &PendingSearchCompletion) -> usize {
    let attempted: BTreeSet<String> = pending
        .attempted_urls
        .iter()
        .chain(pending.blocked_urls.iter())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect();
    pending
        .candidate_urls
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty() && !attempted.contains(*value))
        .count()
}

pub(crate) fn web_pipeline_completion_reason(
    pending: &PendingSearchCompletion,
    now_ms: u64,
) -> Option<WebPipelineCompletionReason> {
    let min_sources = pending.min_sources.max(1) as usize;
    if pending.successful_reads.len() >= min_sources {
        return Some(WebPipelineCompletionReason::MinSourcesReached);
    }
    if pending.deadline_ms > 0 && now_ms >= pending.deadline_ms {
        return Some(WebPipelineCompletionReason::DeadlineReached);
    }
    if remaining_pending_web_candidates(pending) == 0 {
        return Some(WebPipelineCompletionReason::ExhaustedCandidates);
    }
    None
}

pub(crate) fn queue_web_read_from_pipeline(
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    url: &str,
) -> Result<bool, TransactionError> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Ok(false);
    }
    let params = serde_jcs::to_vec(&json!({ "url": trimmed }))
        .or_else(|_| serde_json::to_vec(&json!({ "url": trimmed })))
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let request = ActionRequest {
        target: ActionTarget::WebRetrieve,
        params,
        context: ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: Some(session_id),
            window_id: None,
        },
        nonce: agent_state.step_count as u64 + agent_state.execution_queue.len() as u64 + 1,
    };

    let duplicate = agent_state
        .execution_queue
        .iter()
        .any(|queued| queued.target == request.target && queued.params == request.params);
    if duplicate {
        return Ok(false);
    }

    agent_state.execution_queue.insert(0, request);
    Ok(true)
}

pub(crate) fn is_human_challenge_error(error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    lower.contains("error_class=humanchallengerequired")
        || lower.contains("recaptcha")
        || lower.contains("human verification")
        || lower.contains("verify you are human")
        || lower.contains("i'm not a robot")
        || lower.contains("i am not a robot")
}

fn confidence_tier(
    pending: &PendingSearchCompletion,
    reason: WebPipelineCompletionReason,
) -> &'static str {
    let success = pending.successful_reads.len();
    let min_sources = pending.min_sources.max(1) as usize;
    if success >= min_sources && matches!(reason, WebPipelineCompletionReason::MinSourcesReached) {
        return "high";
    }
    if success >= min_sources {
        return "medium";
    }
    if success >= 1 {
        return "low";
    }
    "low"
}

fn completion_reason_line(reason: WebPipelineCompletionReason) -> &'static str {
    match reason {
        WebPipelineCompletionReason::MinSourcesReached => {
            "Completed after meeting the source floor."
        }
        WebPipelineCompletionReason::ExhaustedCandidates => {
            "Completed because no additional candidate sources remained."
        }
        WebPipelineCompletionReason::DeadlineReached => "Completed at the 60-second budget limit.",
    }
}

fn excerpt_headline(excerpt: &str) -> Option<String> {
    let compact = compact_whitespace(excerpt);
    let trimmed = compact.trim();
    if trimmed.is_empty() {
        return None;
    }
    let candidate = trimmed
        .split(['.', ';', '\n'])
        .next()
        .map(str::trim)
        .unwrap_or_default();
    if candidate.chars().count() < 20 {
        return None;
    }
    Some(candidate.chars().take(120).collect())
}

fn source_bullet(source: &PendingSearchReadSummary) -> String {
    let title = source.title.as_deref().map(str::trim).unwrap_or_default();
    let excerpt = source.excerpt.trim();
    let headline = if !title.is_empty() && !is_low_signal_title(title) {
        title.to_string()
    } else if let Some(from_excerpt) = excerpt_headline(excerpt) {
        from_excerpt
    } else {
        format!("Update from {}", source.url)
    };

    if excerpt.is_empty() || is_low_signal_excerpt(excerpt) {
        return headline;
    }

    let detail = compact_excerpt(excerpt, 160);
    if detail.eq_ignore_ascii_case(&headline) {
        headline
    } else {
        format!("{}: {}", headline, detail)
    }
}

#[derive(Debug, Clone)]
struct CitationCandidate {
    id: String,
    url: String,
    source_label: String,
    excerpt: String,
    timestamp_utc: String,
    note: String,
    from_successful_read: bool,
}

#[derive(Debug, Clone)]
struct StoryDraft {
    title: String,
    what_happened: String,
    changed_last_hour: String,
    why_it_matters: String,
    citation_ids: Vec<String>,
    confidence: String,
    caveat: String,
}

#[derive(Debug, Clone)]
struct SynthesisDraft {
    query: String,
    run_date: String,
    run_timestamp_ms: u64,
    run_timestamp_iso_utc: String,
    completion_reason: String,
    overall_confidence: String,
    overall_caveat: String,
    stories: Vec<StoryDraft>,
    citations_by_id: BTreeMap<String, CitationCandidate>,
    blocked_urls: Vec<String>,
    partial_note: Option<String>,
}

#[derive(Debug, Serialize)]
struct HybridSynthesisPayload {
    query: String,
    run_timestamp_ms: u64,
    run_timestamp_iso_utc: String,
    completion_reason: String,
    citation_candidates: Vec<HybridCitationCandidate>,
    deterministic_story_drafts: Vec<HybridStoryDraft>,
}

#[derive(Debug, Serialize)]
struct HybridCitationCandidate {
    id: String,
    url: String,
    source_label: String,
    excerpt: String,
    timestamp_utc: String,
    note: String,
}

#[derive(Debug, Serialize)]
struct HybridStoryDraft {
    title: String,
    what_happened: String,
    changed_last_hour: String,
    why_it_matters: String,
    citation_ids: Vec<String>,
    confidence: String,
    caveat: String,
}

#[derive(Debug, Deserialize)]
struct HybridSynthesisResponse {
    stories: Vec<HybridStoryResponse>,
    #[serde(default)]
    overall_confidence: String,
    #[serde(default)]
    overall_caveat: String,
}

#[derive(Debug, Deserialize)]
struct HybridStoryResponse {
    title: String,
    what_happened: String,
    changed_last_hour: String,
    why_it_matters: String,
    citation_ids: Vec<String>,
    confidence: String,
    caveat: String,
}

fn title_tokens(input: &str) -> BTreeSet<String> {
    input
        .to_ascii_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .filter(|token| token.len() > 2)
        .map(|token| token.to_string())
        .collect()
}

fn titles_similar(a: &str, b: &str) -> bool {
    let a_trim = a.trim();
    let b_trim = b.trim();
    if a_trim.is_empty() || b_trim.is_empty() {
        return false;
    }
    if a_trim.eq_ignore_ascii_case(b_trim) {
        return true;
    }
    let a_tokens = title_tokens(a_trim);
    let b_tokens = title_tokens(b_trim);
    if a_tokens.is_empty() || b_tokens.is_empty() {
        return false;
    }
    let overlap = a_tokens.intersection(&b_tokens).count();
    let largest = a_tokens.len().max(b_tokens.len());
    overlap * 2 >= largest
}

fn canonical_source_title(source: &PendingSearchReadSummary) -> String {
    let title = source.title.as_deref().map(str::trim).unwrap_or_default();
    if !title.is_empty() && !is_low_signal_title(title) {
        return title.chars().take(WEB_PIPELINE_STORY_TITLE_CHARS).collect();
    }
    if let Some(from_excerpt) = excerpt_headline(source.excerpt.trim()) {
        return from_excerpt
            .chars()
            .take(WEB_PIPELINE_STORY_TITLE_CHARS)
            .collect();
    }
    format!("Update from {}", source.url)
}

fn merged_story_sources(pending: &PendingSearchCompletion) -> Vec<PendingSearchReadSummary> {
    let mut merged: Vec<PendingSearchReadSummary> = Vec::new();
    let mut seen = BTreeSet::new();

    for source in &pending.successful_reads {
        let trimmed = source.url.trim();
        if trimmed.is_empty() || !seen.insert(trimmed.to_string()) {
            continue;
        }
        merged.push(source.clone());
    }

    for source in &pending.candidate_source_hints {
        let trimmed = source.url.trim();
        if trimmed.is_empty() || !seen.insert(trimmed.to_string()) {
            continue;
        }
        merged.push(source.clone());
    }

    for url in &pending.candidate_urls {
        let trimmed = url.trim();
        if trimmed.is_empty() || !seen.insert(trimmed.to_string()) {
            continue;
        }
        merged.push(PendingSearchReadSummary {
            url: trimmed.to_string(),
            title: None,
            excerpt: String::new(),
        });
    }

    // Keep deterministic source order, but prefer event-driven stories over
    // "news-about-news" meta coverage when enough alternatives exist.
    let mut prioritized = Vec::new();
    let mut deprioritized = Vec::new();
    for source in merged {
        if is_meta_news_story(&source) {
            deprioritized.push(source);
        } else {
            prioritized.push(source);
        }
    }
    prioritized.extend(deprioritized);
    prioritized
}

fn why_it_matters_from_story(source: &PendingSearchReadSummary) -> String {
    let text = format!(
        "{} {}",
        source.title.as_deref().unwrap_or_default(),
        source.excerpt
    )
    .to_ascii_lowercase();
    if text.contains("court")
        || text.contains("doj")
        || text.contains("congress")
        || text.contains("capitol")
    {
        return "This could alter U.S. legal, regulatory, or federal policy decisions in the near term."
            .to_string();
    }
    if text.contains("storm")
        || text.contains("weather")
        || text.contains("flood")
        || text.contains("wildfire")
    {
        return "This has immediate public-safety and infrastructure implications across affected U.S. regions."
            .to_string();
    }
    if text.contains("market")
        || text.contains("inflation")
        || text.contains("jobs")
        || text.contains("rate")
    {
        return "This may influence U.S. economic expectations, market pricing, and household decision-making."
            .to_string();
    }
    "This matters because it may affect public safety, policy, or economic conditions in the U.S. as the story develops."
        .to_string()
}

fn changed_last_hour_line(run_timestamp_iso_utc: &str) -> String {
    format!(
        "As of {}, the latest retrieved reporting indicates ongoing movement, but explicit hour-over-hour deltas were not consistently published by every source.",
        run_timestamp_iso_utc
    )
}

fn build_citation_candidates(
    pending: &PendingSearchCompletion,
    run_timestamp_iso_utc: &str,
) -> Vec<CitationCandidate> {
    let merged = merged_story_sources(pending);
    let successful_urls: BTreeSet<String> = pending
        .successful_reads
        .iter()
        .map(|source| source.url.trim().to_string())
        .filter(|url| !url.is_empty())
        .collect();

    merged
        .into_iter()
        .enumerate()
        .map(|(idx, source)| {
            let url = source.url.trim().to_string();
            let source_label = canonical_source_title(&source);
            let excerpt = compact_excerpt(source.excerpt.as_str(), 180);
            CitationCandidate {
                id: format!("C{}", idx + 1),
                url: url.clone(),
                source_label,
                excerpt,
                timestamp_utc: run_timestamp_iso_utc.to_string(),
                note: "retrieved_utc; source publish/update timestamp unavailable".to_string(),
                from_successful_read: successful_urls.contains(&url),
            }
        })
        .collect()
}

fn title_overlap_score(a: &str, b: &str) -> usize {
    let a_tokens = title_tokens(a);
    let b_tokens = title_tokens(b);
    if a_tokens.is_empty() || b_tokens.is_empty() {
        return 0;
    }
    a_tokens.intersection(&b_tokens).count()
}

fn citation_relevance_score(
    source: &PendingSearchReadSummary,
    candidate: &CitationCandidate,
) -> usize {
    let story_title = canonical_source_title(source);
    let story_context = format!("{} {}", story_title, source.excerpt);
    let candidate_context = format!("{} {}", candidate.source_label, candidate.excerpt);
    let mut score = title_overlap_score(&story_context, &candidate_context);
    if source.url.trim() == candidate.url.trim() {
        score += 1_000;
    }
    score
}

fn is_meta_news_candidate(candidate: &CitationCandidate) -> bool {
    let combined = format!("{} {}", candidate.source_label, candidate.excerpt);
    is_meta_news_text(&combined)
}

fn citation_ids_for_story(
    source: &PendingSearchReadSummary,
    candidates: &[CitationCandidate],
    used_urls: &mut BTreeSet<String>,
) -> Vec<String> {
    if candidates.is_empty() {
        return Vec::new();
    }

    let mut ranked_indices = (0..candidates.len()).collect::<Vec<_>>();
    ranked_indices.sort_by(|left_idx, right_idx| {
        let left = &candidates[*left_idx];
        let right = &candidates[*right_idx];
        let left_key = (
            citation_relevance_score(source, left),
            !is_meta_news_candidate(left),
            left.from_successful_read,
            !used_urls.contains(&left.url),
        );
        let right_key = (
            citation_relevance_score(source, right),
            !is_meta_news_candidate(right),
            right.from_successful_read,
            !used_urls.contains(&right.url),
        );
        right_key.cmp(&left_key)
    });

    let mut selected_ids = Vec::new();
    let mut selected_urls = BTreeSet::new();

    for idx in &ranked_indices {
        if selected_ids.len() >= WEB_PIPELINE_CITATIONS_PER_STORY {
            break;
        }
        let candidate = &candidates[*idx];
        if used_urls.contains(&candidate.url) || selected_urls.contains(&candidate.url) {
            continue;
        }
        selected_ids.push(candidate.id.clone());
        selected_urls.insert(candidate.url.clone());
        used_urls.insert(candidate.url.clone());
    }

    if selected_ids.len() < WEB_PIPELINE_CITATIONS_PER_STORY {
        for idx in &ranked_indices {
            if selected_ids.len() >= WEB_PIPELINE_CITATIONS_PER_STORY {
                break;
            }
            let candidate = &candidates[*idx];
            if selected_urls.contains(&candidate.url)
                || selected_ids.iter().any(|id| id == &candidate.id)
            {
                continue;
            }
            selected_ids.push(candidate.id.clone());
            selected_urls.insert(candidate.url.clone());
        }
    }

    selected_ids
}

fn build_deterministic_story_draft(
    pending: &PendingSearchCompletion,
    reason: WebPipelineCompletionReason,
) -> SynthesisDraft {
    let run_timestamp_ms = if pending.started_at_ms > 0 {
        pending.started_at_ms
    } else {
        web_pipeline_now_ms()
    };
    let run_timestamp_iso_utc = iso_datetime_from_unix_ms(run_timestamp_ms);
    let run_date = iso_date_from_unix_ms(run_timestamp_ms);
    let query = pending.query.trim().to_string();
    let completion_reason = completion_reason_line(reason).to_string();
    let partial_note = {
        let min_sources = pending.min_sources.max(1) as usize;
        (pending.successful_reads.len() < min_sources).then(|| {
            format!(
                "Partial evidence: confirmed readable sources={} while floor={}.",
                pending.successful_reads.len(),
                min_sources
            )
        })
    };

    let candidates = build_citation_candidates(pending, &run_timestamp_iso_utc);
    let mut citations_by_id = BTreeMap::new();
    for candidate in &candidates {
        citations_by_id.insert(candidate.id.clone(), candidate.clone());
    }

    let mut stories = Vec::new();
    let merged_sources = merged_story_sources(pending);
    let mut selected_sources = Vec::new();
    for source in &merged_sources {
        let title = canonical_source_title(source);
        if selected_sources
            .iter()
            .any(|existing: &PendingSearchReadSummary| {
                titles_similar(&title, &canonical_source_title(existing))
            })
        {
            continue;
        }
        selected_sources.push(source.clone());
        if selected_sources.len() >= WEB_PIPELINE_REQUIRED_STORIES {
            break;
        }
    }
    while selected_sources.len() < WEB_PIPELINE_REQUIRED_STORIES && !merged_sources.is_empty() {
        selected_sources
            .push(merged_sources[selected_sources.len() % merged_sources.len()].clone());
    }

    let mut used_urls = BTreeSet::new();
    for source in selected_sources.iter().take(WEB_PIPELINE_REQUIRED_STORIES) {
        let title = canonical_source_title(source);
        let what_happened = source_bullet(source);
        let why_it_matters = why_it_matters_from_story(source);
        let changed_last_hour = changed_last_hour_line(&run_timestamp_iso_utc);
        let citation_ids = citation_ids_for_story(source, &candidates, &mut used_urls);
        let confident_reads = citation_ids
            .iter()
            .filter_map(|id| citations_by_id.get(id))
            .filter(|candidate| candidate.from_successful_read)
            .count();
        let confidence = if confident_reads >= WEB_PIPELINE_CITATIONS_PER_STORY {
            "high".to_string()
        } else if citation_ids.len() >= WEB_PIPELINE_CITATIONS_PER_STORY {
            "medium".to_string()
        } else {
            "low".to_string()
        };
        let caveat = "Timestamps are anchored to UTC retrieval time when source publish/update metadata was unavailable.".to_string();

        stories.push(StoryDraft {
            title,
            what_happened,
            changed_last_hour,
            why_it_matters,
            citation_ids,
            confidence,
            caveat,
        });
    }

    while stories.len() < WEB_PIPELINE_REQUIRED_STORIES {
        let fallback_source = if merged_sources.is_empty() {
            PendingSearchReadSummary {
                url: String::new(),
                title: None,
                excerpt: String::new(),
            }
        } else {
            merged_sources[stories.len() % merged_sources.len()].clone()
        };
        let fallback_ids = citation_ids_for_story(&fallback_source, &candidates, &mut used_urls);
        stories.push(StoryDraft {
            title: format!("Story {}", stories.len() + 1),
            what_happened: "Insufficient high-signal extraction for a richer deterministic summary."
                .to_string(),
            changed_last_hour: changed_last_hour_line(&run_timestamp_iso_utc),
            why_it_matters:
                "This still matters because it contributes to the current U.S. breaking-news picture."
                    .to_string(),
            citation_ids: fallback_ids,
            confidence: "low".to_string(),
            caveat: "Evidence quality was limited for this slot.".to_string(),
        });
    }

    SynthesisDraft {
        query,
        run_date,
        run_timestamp_ms,
        run_timestamp_iso_utc,
        completion_reason,
        overall_confidence: confidence_tier(pending, reason).to_string(),
        overall_caveat: "Ranking and recency are based on retrieved evidence and may lag when sources do not publish explicit update timestamps.".to_string(),
        stories,
        citations_by_id,
        blocked_urls: pending.blocked_urls.clone(),
        partial_note,
    }
}

fn render_synthesis_draft(draft: &SynthesisDraft) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "Top 3 U.S. breaking stories (as of {} UTC)",
        draft.run_timestamp_iso_utc
    ));

    for (idx, story) in draft
        .stories
        .iter()
        .take(WEB_PIPELINE_REQUIRED_STORIES)
        .enumerate()
    {
        lines.push(String::new());
        lines.push(format!("Story {}: {}", idx + 1, story.title));
        lines.push(format!("What happened: {}", story.what_happened));
        lines.push(format!(
            "What changed in the last hour: {}",
            story.changed_last_hour
        ));
        lines.push(format!("Why it matters: {}", story.why_it_matters));
        lines.push("Citations:".to_string());
        for citation_id in story
            .citation_ids
            .iter()
            .take(WEB_PIPELINE_CITATIONS_PER_STORY)
        {
            if let Some(citation) = draft.citations_by_id.get(citation_id) {
                lines.push(format!(
                    "- {} | {} | {} | {}",
                    citation.source_label, citation.url, citation.timestamp_utc, citation.note
                ));
            }
        }
        lines.push(format!("Confidence: {}", story.confidence));
        lines.push(format!("Caveat: {}", story.caveat));
    }

    lines.push(String::new());
    if let Some(partial_note) = draft.partial_note.as_deref() {
        lines.push(partial_note.to_string());
    }
    if !draft.blocked_urls.is_empty() {
        lines.push(format!(
            "Blocked sources requiring human challenge: {}",
            draft.blocked_urls.join(", ")
        ));
    }
    lines.push(format!("Completion reason: {}", draft.completion_reason));
    lines.push(format!("Run date (UTC): {}", draft.run_date));
    lines.push(format!(
        "Run timestamp (UTC): {}",
        draft.run_timestamp_iso_utc
    ));
    lines.push(format!("Overall confidence: {}", draft.overall_confidence));
    lines.push(format!("Overall caveat: {}", draft.overall_caveat));
    if !draft.query.is_empty() {
        lines.push(format!("Query: {}", draft.query));
    }

    lines.join("\n")
}

fn extract_json_object(raw: &str) -> Option<&str> {
    let start = raw.find('{')?;
    let end = raw.rfind('}')?;
    (end >= start).then_some(&raw[start..=end])
}

fn is_iso_utc_datetime(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20 {
        return false;
    }
    bytes[0].is_ascii_digit()
        && bytes[1].is_ascii_digit()
        && bytes[2].is_ascii_digit()
        && bytes[3].is_ascii_digit()
        && bytes[4] == b'-'
        && bytes[5].is_ascii_digit()
        && bytes[6].is_ascii_digit()
        && bytes[7] == b'-'
        && bytes[8].is_ascii_digit()
        && bytes[9].is_ascii_digit()
        && bytes[10] == b'T'
        && bytes[11].is_ascii_digit()
        && bytes[12].is_ascii_digit()
        && bytes[13] == b':'
        && bytes[14].is_ascii_digit()
        && bytes[15].is_ascii_digit()
        && bytes[16] == b':'
        && bytes[17].is_ascii_digit()
        && bytes[18].is_ascii_digit()
        && bytes[19] == b'Z'
}

fn apply_hybrid_synthesis_response(
    base: &SynthesisDraft,
    response: HybridSynthesisResponse,
) -> Option<SynthesisDraft> {
    if response.stories.len() < WEB_PIPELINE_REQUIRED_STORIES {
        return None;
    }

    let mut used_urls = BTreeSet::new();
    let mut stories = Vec::new();
    for story in response
        .stories
        .into_iter()
        .take(WEB_PIPELINE_REQUIRED_STORIES)
    {
        let title = story.title.trim();
        let happened = story.what_happened.trim();
        let changed = story.changed_last_hour.trim();
        let matters = story.why_it_matters.trim();
        if title.is_empty() || happened.is_empty() || changed.is_empty() || matters.is_empty() {
            return None;
        }

        let mut citation_ids = Vec::new();
        for id in story.citation_ids {
            let trimmed = id.trim();
            if trimmed.is_empty() || citation_ids.iter().any(|existing| existing == trimmed) {
                continue;
            }
            let Some(citation) = base.citations_by_id.get(trimmed) else {
                continue;
            };
            citation_ids.push(trimmed.to_string());
            used_urls.insert(citation.url.clone());
            if citation_ids.len() >= WEB_PIPELINE_CITATIONS_PER_STORY {
                break;
            }
        }
        if citation_ids.len() < WEB_PIPELINE_CITATIONS_PER_STORY {
            return None;
        }

        let mut normalized_confidence = normalize_confidence_label(&story.confidence);
        if normalized_confidence == "low" && citation_ids.len() >= WEB_PIPELINE_CITATIONS_PER_STORY
        {
            normalized_confidence = "medium".to_string();
        }

        stories.push(StoryDraft {
            title: title.to_string(),
            what_happened: happened.to_string(),
            changed_last_hour: changed.to_string(),
            why_it_matters: matters.to_string(),
            citation_ids,
            confidence: normalized_confidence,
            caveat: if story.caveat.trim().is_empty() {
                "Model omitted caveat; fallback caveat applied.".to_string()
            } else {
                story.caveat.trim().to_string()
            },
        });
    }

    if used_urls.len() < WEB_PIPELINE_REQUIRED_DISTINCT_CITATIONS {
        return None;
    }

    let mut overall_confidence = normalize_confidence_label(&response.overall_confidence);
    if overall_confidence == "low" && used_urls.len() >= WEB_PIPELINE_REQUIRED_DISTINCT_CITATIONS {
        overall_confidence = "medium".to_string();
    }

    Some(SynthesisDraft {
        query: base.query.clone(),
        run_date: base.run_date.clone(),
        run_timestamp_ms: base.run_timestamp_ms,
        run_timestamp_iso_utc: base.run_timestamp_iso_utc.clone(),
        completion_reason: base.completion_reason.clone(),
        overall_confidence,
        overall_caveat: if response.overall_caveat.trim().is_empty() {
            base.overall_caveat.clone()
        } else {
            response.overall_caveat.trim().to_string()
        },
        stories,
        citations_by_id: base.citations_by_id.clone(),
        blocked_urls: base.blocked_urls.clone(),
        partial_note: base.partial_note.clone(),
    })
}

pub(crate) async fn synthesize_web_pipeline_reply_hybrid(
    runtime: Arc<dyn InferenceRuntime>,
    pending: &PendingSearchCompletion,
    reason: WebPipelineCompletionReason,
) -> Option<String> {
    let draft = build_deterministic_story_draft(pending, reason);
    let now_ms = web_pipeline_now_ms();
    if pending.deadline_ms > 0
        && now_ms.saturating_add(WEB_PIPELINE_HYBRID_BUDGET_GUARD_MS) >= pending.deadline_ms
    {
        return None;
    }

    let candidates = draft
        .citations_by_id
        .values()
        .map(|citation| HybridCitationCandidate {
            id: citation.id.clone(),
            url: citation.url.clone(),
            source_label: citation.source_label.clone(),
            excerpt: citation.excerpt.clone(),
            timestamp_utc: citation.timestamp_utc.clone(),
            note: citation.note.clone(),
        })
        .collect::<Vec<_>>();
    if candidates.len() < WEB_PIPELINE_REQUIRED_DISTINCT_CITATIONS {
        return None;
    }

    let deterministic_story_drafts = draft
        .stories
        .iter()
        .take(WEB_PIPELINE_REQUIRED_STORIES)
        .map(|story| HybridStoryDraft {
            title: story.title.clone(),
            what_happened: story.what_happened.clone(),
            changed_last_hour: story.changed_last_hour.clone(),
            why_it_matters: story.why_it_matters.clone(),
            citation_ids: story.citation_ids.clone(),
            confidence: story.confidence.clone(),
            caveat: story.caveat.clone(),
        })
        .collect::<Vec<_>>();

    let payload = HybridSynthesisPayload {
        query: draft.query.clone(),
        run_timestamp_ms: draft.run_timestamp_ms,
        run_timestamp_iso_utc: draft.run_timestamp_iso_utc.clone(),
        completion_reason: draft.completion_reason.clone(),
        citation_candidates: candidates,
        deterministic_story_drafts,
    };
    let prompt = format!(
        "Return JSON only with schema: \
{{\"stories\":[{{\"title\":string,\"what_happened\":string,\"changed_last_hour\":string,\"why_it_matters\":string,\"citation_ids\":[string,string],\"confidence\":\"high|medium|low\",\"caveat\":string}}],\"overall_confidence\":\"high|medium|low\",\"overall_caveat\":string}}.\n\
Requirements:\n\
- Exactly 3 stories.\n\
- Use ONLY citation_ids from payload.\n\
- Each story must include exactly 2 citation_ids.\n\
- Keep text concise, factual, and U.S.-focused.\n\
- Treat run_timestamp_ms and run_timestamp_iso_utc as authoritative UTC clock for recency.\n\
Payload:\n{}",
        serde_json::to_string_pretty(&payload).ok()?
    );
    let options = InferenceOptions {
        tools: vec![],
        temperature: 0.0,
        json_mode: true,
        max_tokens: WEB_PIPELINE_HYBRID_MAX_TOKENS,
    };
    let raw = runtime
        .execute_inference([0u8; 32], prompt.as_bytes(), options)
        .await
        .ok()?;
    let text = String::from_utf8(raw).ok()?;
    let json_text = extract_json_object(&text).unwrap_or(text.as_str());
    let response: HybridSynthesisResponse = serde_json::from_str(json_text).ok()?;
    let updated = apply_hybrid_synthesis_response(&draft, response)?;

    // Ensure rendered citations still carry absolute UTC datetimes.
    let has_timestamps = updated
        .citations_by_id
        .values()
        .all(|citation| is_iso_utc_datetime(&citation.timestamp_utc));
    if !has_timestamps {
        return None;
    }
    Some(render_synthesis_draft(&updated))
}

pub(crate) fn synthesize_web_pipeline_reply(
    pending: &PendingSearchCompletion,
    reason: WebPipelineCompletionReason,
) -> String {
    let draft = build_deterministic_story_draft(pending, reason);
    render_synthesis_draft(&draft)
}

fn infer_sys_tool_name(args: &serde_json::Value) -> &'static str {
    if let Some(obj) = args.as_object() {
        if obj.get("command").is_none() && obj.get("app_name").is_some() {
            return "os__launch_app";
        }
        if obj.get("command").is_none() && obj.get("path").is_some() {
            return "sys__change_directory";
        }
    }
    "sys__exec"
}

fn infer_fs_read_tool_name(args: &serde_json::Value) -> &'static str {
    let Some(obj) = args.as_object() else {
        return "filesystem__read_file";
    };

    // Preserve deterministic filesystem search queued via ActionTarget::FsRead.
    if obj.contains_key("regex") || obj.contains_key("file_pattern") {
        return "filesystem__search";
    }

    if let Some(path) = obj
        .get("path")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if Path::new(path).is_dir() {
            return "filesystem__list_directory";
        }
    }

    "filesystem__read_file"
}

fn infer_fs_write_tool_name(args: &serde_json::Value) -> &'static str {
    let Some(obj) = args.as_object() else {
        return "filesystem__write_file";
    };

    // Preserve deterministic patch requests queued under ActionTarget::FsWrite.
    if obj.contains_key("search") && obj.contains_key("replace") {
        return "filesystem__patch";
    }

    // Preserve deterministic delete/create-directory requests queued under
    // ActionTarget::FsWrite for backward compatibility.
    if obj.contains_key("path")
        && !obj.contains_key("content")
        && !obj.contains_key("line")
        && !obj.contains_key("line_number")
    {
        // Delete payloads include `ignore_missing`; prefer delete whenever it is present.
        if obj.contains_key("ignore_missing") {
            return "filesystem__delete_path";
        }

        // Recursive-without-delete markers maps to create_directory to avoid destructive
        // misclassification of legacy deterministic directory creation requests.
        if obj.contains_key("recursive") {
            return "filesystem__create_directory";
        }
    }

    "filesystem__write_file"
}

fn has_non_empty_string_field(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> bool {
    obj.get(key)
        .and_then(|value| value.as_str())
        .map(str::trim)
        .is_some_and(|value| !value.is_empty())
}

fn is_ambiguous_fs_write_transfer_payload(args: &serde_json::Value) -> bool {
    let Some(obj) = args.as_object() else {
        return false;
    };
    has_non_empty_string_field(obj, "source_path")
        && has_non_empty_string_field(obj, "destination_path")
}

fn infer_custom_tool_name(name: &str, args: &serde_json::Value) -> String {
    match name {
        "ui::find" => "ui__find".to_string(),
        "os::focus" => "os__focus_window".to_string(),
        "clipboard::write" => "os__copy".to_string(),
        "clipboard::read" => "os__paste".to_string(),
        "computer::cursor" => "computer".to_string(),
        "fs::read" => infer_fs_read_tool_name(args).to_string(),
        "fs::write" => infer_fs_write_tool_name(args).to_string(),
        "sys::exec" => infer_sys_tool_name(args).to_string(),
        "sys::exec_session" => "sys__exec_session".to_string(),
        "sys::exec_session_reset" => "sys__exec_session_reset".to_string(),
        "sys::install_package" => "sys__install_package".to_string(),
        _ => name.to_string(),
    }
}

fn infer_web_retrieve_tool_name(
    args: &serde_json::Value,
) -> Result<&'static str, TransactionError> {
    let Some(obj) = args.as_object() else {
        return Err(TransactionError::Invalid(
            "Queued web::retrieve args must be a JSON object.".into(),
        ));
    };

    if obj.contains_key("query") {
        return Ok("web__search");
    }
    if obj.contains_key("url") {
        return Ok("web__read");
    }

    Err(TransactionError::Invalid(
        "Queued web::retrieve must include either 'query' (web__search) or 'url' (web__read)."
            .into(),
    ))
}

fn infer_browser_interact_tool_name(
    args: &serde_json::Value,
) -> Result<&'static str, TransactionError> {
    let Some(obj) = args.as_object() else {
        return Err(TransactionError::Invalid(
            "Queued browser::interact args must be a JSON object.".into(),
        ));
    };

    if obj.contains_key("url") {
        return Ok("browser__navigate");
    }
    if obj.contains_key("text") {
        return Ok("browser__type");
    }
    if obj.contains_key("id") {
        return Ok("browser__click_element");
    }
    if obj.contains_key("selector") {
        return Ok("browser__click");
    }
    if obj.contains_key("key") {
        return Ok("browser__key");
    }
    if obj.contains_key("x") && obj.contains_key("y") {
        return Ok("browser__synthetic_click");
    }
    if obj.contains_key("delta_x") || obj.contains_key("delta_y") {
        return Ok("browser__scroll");
    }

    Err(TransactionError::Invalid(
        "Queued browser::interact args did not match any known browser__* tool signature.".into(),
    ))
}

fn looks_like_computer_action_payload(args: &serde_json::Value) -> bool {
    args.as_object()
        .and_then(|obj| obj.get("action"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .is_some_and(|value| !value.is_empty())
}

fn ensure_computer_action(raw_args: serde_json::Value, action: &str) -> serde_json::Value {
    match raw_args {
        serde_json::Value::Object(mut obj) => {
            obj.entry("action".to_string())
                .or_insert_with(|| json!(action));
            serde_json::Value::Object(obj)
        }
        other => other,
    }
}

#[derive(Clone, Copy)]
enum QueueToolNameScope {
    Read,
    Write,
    GuiClick,
    SysExec,
}

fn explicit_queue_tool_name_scope(target: &ActionTarget) -> Option<QueueToolNameScope> {
    match target {
        ActionTarget::FsRead => Some(QueueToolNameScope::Read),
        ActionTarget::FsWrite => Some(QueueToolNameScope::Write),
        ActionTarget::Custom(name) if name == "fs::read" => Some(QueueToolNameScope::Read),
        ActionTarget::Custom(name) if name == "fs::write" => Some(QueueToolNameScope::Write),
        ActionTarget::GuiClick | ActionTarget::UiClick => Some(QueueToolNameScope::GuiClick),
        ActionTarget::SysExec => Some(QueueToolNameScope::SysExec),
        _ => None,
    }
}

fn is_explicit_tool_name_allowed_for_scope(scope: QueueToolNameScope, tool_name: &str) -> bool {
    match scope {
        QueueToolNameScope::Read => matches!(
            tool_name,
            "filesystem__read_file" | "filesystem__list_directory" | "filesystem__search"
        ),
        QueueToolNameScope::Write => matches!(
            tool_name,
            "filesystem__write_file"
                | "filesystem__patch"
                | "filesystem__delete_path"
                | "filesystem__create_directory"
                | "filesystem__copy_path"
                | "filesystem__move_path"
        ),
        QueueToolNameScope::GuiClick => {
            matches!(tool_name, "gui__click" | "gui__click_element" | "computer")
        }
        QueueToolNameScope::SysExec => {
            matches!(tool_name, "sys__exec_session" | "sys__exec_session_reset")
        }
    }
}

fn extract_explicit_tool_name(
    target: &ActionTarget,
    raw_args: &serde_json::Value,
) -> Result<Option<String>, TransactionError> {
    // Explicit queue metadata is used for targets where ActionTarget-level replay can collapse
    // distinct tool variants into ambiguous defaults.
    let Some(scope) = explicit_queue_tool_name_scope(target) else {
        return Ok(None);
    };

    let Some(obj) = raw_args.as_object() else {
        return Ok(None);
    };

    let Some(name) = obj.get(QUEUE_TOOL_NAME_KEY) else {
        return Ok(None);
    };

    let tool_name = name.as_str().map(str::trim).ok_or_else(|| {
        TransactionError::Invalid(format!(
            "Queued {} must be a non-empty string when present.",
            QUEUE_TOOL_NAME_KEY
        ))
    })?;

    if tool_name.is_empty() {
        return Err(TransactionError::Invalid(format!(
            "Queued {} cannot be empty.",
            QUEUE_TOOL_NAME_KEY
        )));
    }

    if !is_explicit_tool_name_allowed_for_scope(scope, tool_name) {
        return Err(TransactionError::Invalid(format!(
            "Queued {} '{}' is incompatible with target {:?}.",
            QUEUE_TOOL_NAME_KEY, tool_name, target
        )));
    }

    Ok(Some(tool_name.to_string()))
}

fn strip_internal_queue_metadata(raw_args: serde_json::Value) -> serde_json::Value {
    match raw_args {
        serde_json::Value::Object(mut obj) => {
            obj.remove(QUEUE_TOOL_NAME_KEY);
            serde_json::Value::Object(obj)
        }
        other => other,
    }
}

fn queue_target_to_tool_name_and_args(
    target: &ActionTarget,
    raw_args: serde_json::Value,
) -> Result<(String, serde_json::Value), TransactionError> {
    let explicit_tool_name = extract_explicit_tool_name(target, &raw_args)?;
    let raw_args = strip_internal_queue_metadata(raw_args);

    if let Some(tool_name) = explicit_tool_name {
        return Ok((tool_name, raw_args));
    }

    if matches!(
        explicit_queue_tool_name_scope(target),
        Some(QueueToolNameScope::Write)
    ) && is_ambiguous_fs_write_transfer_payload(&raw_args)
    {
        return Err(TransactionError::Invalid(format!(
            "Queued fs::write transfer payloads must include {} set to filesystem__copy_path or filesystem__move_path.",
            QUEUE_TOOL_NAME_KEY
        )));
    }

    match target {
        ActionTarget::Custom(name) => Ok((infer_custom_tool_name(name, &raw_args), raw_args)),
        ActionTarget::FsRead => Ok((infer_fs_read_tool_name(&raw_args).to_string(), raw_args)),
        ActionTarget::FsWrite => Ok((infer_fs_write_tool_name(&raw_args).to_string(), raw_args)),
        ActionTarget::WebRetrieve => Ok((
            infer_web_retrieve_tool_name(&raw_args)?.to_string(),
            raw_args,
        )),
        ActionTarget::NetFetch => Ok(("net__fetch".to_string(), raw_args)),
        ActionTarget::BrowserInteract => Ok((
            infer_browser_interact_tool_name(&raw_args)?.to_string(),
            raw_args,
        )),
        ActionTarget::BrowserInspect => Ok(("browser__snapshot".to_string(), raw_args)),
        ActionTarget::GuiType | ActionTarget::UiType => {
            if looks_like_computer_action_payload(&raw_args) {
                Ok(("computer".to_string(), raw_args))
            } else {
                Ok(("gui__type".to_string(), raw_args))
            }
        }
        ActionTarget::GuiClick | ActionTarget::UiClick => {
            if looks_like_computer_action_payload(&raw_args) {
                Ok(("computer".to_string(), raw_args))
            } else {
                Ok(("gui__click".to_string(), raw_args))
            }
        }
        ActionTarget::GuiScroll => {
            if looks_like_computer_action_payload(&raw_args) {
                Ok(("computer".to_string(), raw_args))
            } else {
                Ok(("gui__scroll".to_string(), raw_args))
            }
        }
        ActionTarget::GuiMouseMove => Ok((
            "computer".to_string(),
            ensure_computer_action(raw_args, "mouse_move"),
        )),
        ActionTarget::GuiScreenshot => Ok((
            "computer".to_string(),
            ensure_computer_action(raw_args, "screenshot"),
        )),
        ActionTarget::GuiInspect => Ok(("gui__snapshot".to_string(), raw_args)),
        ActionTarget::GuiSequence => Ok(("computer".to_string(), raw_args)),
        ActionTarget::SysExec => Ok((infer_sys_tool_name(&raw_args).to_string(), raw_args)),
        ActionTarget::SysInstallPackage => Ok(("sys__install_package".to_string(), raw_args)),
        ActionTarget::WindowFocus => Ok(("os__focus_window".to_string(), raw_args)),
        ActionTarget::ClipboardWrite => Ok(("os__copy".to_string(), raw_args)),
        ActionTarget::ClipboardRead => Ok(("os__paste".to_string(), raw_args)),
        unsupported => Err(TransactionError::Invalid(format!(
            "Queue execution for target {:?} is not yet mapped to AgentTool",
            unsupported
        ))),
    }
}

pub fn queue_action_request_to_tool(
    action_request: &ActionRequest,
) -> Result<AgentTool, TransactionError> {
    let raw_args: serde_json::Value =
        serde_json::from_slice(&action_request.params).map_err(|e| {
            TransactionError::Serialization(format!("Invalid queued action params JSON: {}", e))
        })?;

    let (tool_name, args) = queue_target_to_tool_name_and_args(&action_request.target, raw_args)?;

    let wrapper = json!({
        "name": tool_name,
        "arguments": args,
    });
    let wrapper_json = serde_json::to_string(&wrapper)
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;

    middleware::normalize_tool_call(&wrapper_json)
        .map_err(|e| TransactionError::Invalid(format!("Queue tool normalization failed: {}", e)))
}
