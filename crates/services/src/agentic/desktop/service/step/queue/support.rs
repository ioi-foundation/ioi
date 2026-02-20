use crate::agentic::desktop::middleware;
use crate::agentic::desktop::service::step::signals::{
    analyze_source_record_signals, infer_report_sections, is_mailbox_connector_intent,
    report_section_aliases, report_section_key, report_section_label, ReportSectionKind,
    SourceSignalProfile, WEB_EVIDENCE_SIGNAL_VERSION,
};
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
pub(crate) const WEB_PIPELINE_DEFAULT_MIN_SOURCES: u32 = 1;
pub(crate) const WEB_PIPELINE_SEARCH_LIMIT: u32 = 10;
pub(crate) const WEB_PIPELINE_REQUIRED_STORIES: usize = 3;
pub(crate) const WEB_PIPELINE_CITATIONS_PER_STORY: usize = 2;

const WEB_PIPELINE_STORY_TITLE_CHARS: usize = 140;
const WEB_PIPELINE_HYBRID_MAX_TOKENS: u32 = 1_200;
const WEB_PIPELINE_HYBRID_BUDGET_GUARD_MS: u64 = 45_000;
const WEB_PIPELINE_ACTIONABLE_EXCERPT_CHARS: usize = 140;
const CITATION_SOURCE_URL_MATCH_BONUS: usize = 1_000;
const CITATION_PRIMARY_STATUS_BONUS: usize = 16;
const CITATION_OFFICIAL_STATUS_HOST_BONUS: usize = 24;
const CITATION_SECONDARY_COVERAGE_PENALTY: usize = 8;
const CITATION_DOCUMENTATION_SURFACE_PENALTY: usize = 10;
const NON_ACTIONABLE_EXCERPT_MARKERS: [&str; 8] = [
    "requires authorization",
    "you can try signing in",
    "use personalized service health",
    "for incidents related",
    "learn more",
    "high-profile breaches",
    "annual report",
    "state of",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WebPipelineCompletionReason {
    MinSourcesReached,
    ExhaustedCandidates,
    DeadlineReached,
}

fn parse_small_count_token(token: &str) -> Option<usize> {
    let normalized = token
        .trim()
        .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
        .to_ascii_lowercase();
    match normalized.as_str() {
        "1" | "one" => Some(1),
        "2" | "two" => Some(2),
        "3" | "three" => Some(3),
        "4" | "four" => Some(4),
        "5" | "five" => Some(5),
        "6" | "six" => Some(6),
        _ => None,
    }
}

fn required_story_count(query: &str) -> usize {
    let tokens = query.split_whitespace().collect::<Vec<_>>();
    for idx in 0..tokens.len() {
        let token = tokens[idx].to_ascii_lowercase();
        if token == "top" {
            if let Some(value) = tokens
                .get(idx + 1)
                .and_then(|value| parse_small_count_token(value))
            {
                return value.clamp(1, 6);
            }
        }

        let Some(value) = parse_small_count_token(tokens[idx]) else {
            continue;
        };
        let next = tokens
            .get(idx + 1)
            .map(|value| {
                value
                    .trim()
                    .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
                    .to_ascii_lowercase()
            })
            .unwrap_or_default();
        if matches!(
            next.as_str(),
            "stories"
                | "story"
                | "items"
                | "results"
                | "findings"
                | "incidents"
                | "events"
                | "updates"
        ) {
            return value.clamp(1, 6);
        }
    }

    WEB_PIPELINE_REQUIRED_STORIES
}

fn required_citations_per_story(query: &str) -> usize {
    let tokens = query.split_whitespace().collect::<Vec<_>>();
    for idx in 0..tokens.len() {
        let Some(value) = parse_small_count_token(tokens[idx]) else {
            continue;
        };
        let next = tokens
            .get(idx + 1)
            .map(|value| {
                value
                    .trim()
                    .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
                    .to_ascii_lowercase()
            })
            .unwrap_or_default();
        if matches!(
            next.as_str(),
            "citation" | "citations" | "source" | "sources"
        ) && tokens
            .get(idx + 2)
            .map(|value| {
                value
                    .trim()
                    .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
                    .eq_ignore_ascii_case("each")
            })
            .unwrap_or(false)
        {
            return value.clamp(1, 6);
        }
    }

    WEB_PIPELINE_CITATIONS_PER_STORY
}

fn required_distinct_citations(query: &str) -> usize {
    required_story_count(query).saturating_mul(required_citations_per_story(query))
}

fn requires_mailbox_access_notice(query: &str) -> bool {
    is_mailbox_connector_intent(query)
}

fn render_mailbox_access_limited_draft(draft: &SynthesisDraft) -> String {
    let citations_per_story = required_citations_per_story(&draft.query).max(1);
    let mut lines = Vec::new();
    lines.push(format!(
        "Mailbox retrieval request (as of {} UTC)",
        draft.run_timestamp_iso_utc
    ));
    lines.push(
        "Access limitation: I cannot access your mailbox directly from public web evidence."
            .to_string(),
    );
    lines.push(
        "Next step: You can connect mailbox access or provide the latest email headers/body, and I will read it."
            .to_string(),
    );
    lines.push("Citations:".to_string());

    let mut emitted = 0usize;
    let mut emitted_ids = BTreeSet::new();
    for story in &draft.stories {
        for citation_id in &story.citation_ids {
            if emitted >= citations_per_story {
                break;
            }
            if !emitted_ids.insert(citation_id.clone()) {
                continue;
            }
            if let Some(citation) = draft.citations_by_id.get(citation_id) {
                lines.push(format!(
                    "- {} | {} | {} | {}",
                    citation.source_label, citation.url, citation.timestamp_utc, citation.note
                ));
                emitted += 1;
            }
        }
        if emitted >= citations_per_story {
            break;
        }
    }

    if emitted == 0 {
        for citation in draft.citations_by_id.values().take(citations_per_story) {
            lines.push(format!(
                "- {} | {} | {} | {}",
                citation.source_label, citation.url, citation.timestamp_utc, citation.note
            ));
            emitted += 1;
        }
    }

    if emitted == 0 {
        lines.push(format!(
            "- Mailbox connector policy | imap://mailbox/access-policy | {} | Direct mailbox connector access is required for personal inbox reads.",
            draft.run_timestamp_iso_utc
        ));
        emitted += 1;
    }

    while emitted < citations_per_story {
        lines.push(format!(
            "- Mailbox connector policy | imap://mailbox/access-policy | {} | Direct mailbox connector access is required for personal inbox reads.",
            draft.run_timestamp_iso_utc
        ));
        emitted += 1;
    }

    lines.push("Confidence: medium".to_string());
    lines.push(
        "Caveat: Mailbox content cannot be verified without direct mailbox access.".to_string(),
    );
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

pub(crate) fn render_mailbox_access_limited_reply(query: &str, run_timestamp_ms: u64) -> String {
    let run_timestamp_iso_utc = iso_datetime_from_unix_ms(run_timestamp_ms);
    let draft = SynthesisDraft {
        query: query.to_string(),
        run_date: iso_date_from_unix_ms(run_timestamp_ms),
        run_timestamp_ms,
        run_timestamp_iso_utc: run_timestamp_iso_utc.clone(),
        completion_reason: "MailboxConnectorRequired".to_string(),
        overall_confidence: "medium".to_string(),
        overall_caveat:
            "Mailbox content requires connector-backed access and cannot be inferred from public web sources."
                .to_string(),
        stories: Vec::new(),
        citations_by_id: BTreeMap::new(),
        blocked_urls: Vec::new(),
        partial_note: None,
    };
    render_mailbox_access_limited_draft(&draft)
}

fn synthesis_query_contract(pending: &PendingSearchCompletion) -> String {
    let contract = pending.query_contract.trim();
    if !contract.is_empty() {
        return contract.to_string();
    }
    pending.query.trim().to_string()
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
    sources.sort_by(|left, right| {
        let left_title = left.title.as_deref().unwrap_or_default();
        let right_title = right.title.as_deref().unwrap_or_default();
        let left_excerpt = left.snippet.as_deref().unwrap_or_default();
        let right_excerpt = right.snippet.as_deref().unwrap_or_default();
        let left_signals = analyze_source_record_signals(&left.url, left_title, left_excerpt);
        let right_signals = analyze_source_record_signals(&right.url, right_title, right_excerpt);

        let left_key = (
            left_signals.official_status_host_hits > 0,
            left_signals.official_status_host_hits,
            left_signals.primary_status_surface_hits > 0,
            left_signals.primary_status_surface_hits,
            left_signals.secondary_coverage_hits == 0,
            left_signals.documentation_surface_hits == 0,
            left_signals.relevance_score(false),
            left_signals.provenance_hits,
            left_signals.primary_event_hits,
        );
        let right_key = (
            right_signals.official_status_host_hits > 0,
            right_signals.official_status_host_hits,
            right_signals.primary_status_surface_hits > 0,
            right_signals.primary_status_surface_hits,
            right_signals.secondary_coverage_hits == 0,
            right_signals.documentation_surface_hits == 0,
            right_signals.relevance_score(false),
            right_signals.provenance_hits,
            right_signals.primary_event_hits,
        );

        right_key
            .cmp(&left_key)
            .then_with(|| {
                left.rank
                    .unwrap_or(u32::MAX)
                    .cmp(&right.rank.unwrap_or(u32::MAX))
            })
            .then_with(|| left.url.cmp(&right.url))
    });
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

fn source_evidence_signals(source: &PendingSearchReadSummary) -> SourceSignalProfile {
    let title = source.title.as_deref().unwrap_or_default();
    analyze_source_record_signals(&source.url, title, &source.excerpt)
}

fn has_primary_status_authority(signals: SourceSignalProfile) -> bool {
    signals.official_status_host_hits > 0 || signals.primary_status_surface_hits > 0
}

fn is_low_priority_coverage_story(source: &PendingSearchReadSummary) -> bool {
    source_evidence_signals(source).low_priority_dominates()
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
        || NON_ACTIONABLE_EXCERPT_MARKERS
            .iter()
            .any(|marker| lower.contains(marker))
}

fn actionable_excerpt(excerpt: &str) -> Option<String> {
    let trimmed = excerpt.trim();
    if trimmed.is_empty() {
        return None;
    }
    let compact = compact_whitespace(trimmed);
    if compact.is_empty() {
        return None;
    }

    let mut cutoff = compact.len();
    let lower = compact.to_ascii_lowercase();
    for marker in [
        " use personalized service health",
        " for incidents related",
        " learn more",
        " note access to this page requires authorization",
    ] {
        if let Some(idx) = lower.find(marker) {
            cutoff = cutoff.min(idx);
        }
    }

    let condensed = compact[..cutoff].trim().to_string();
    if condensed.chars().count() < 28 {
        return None;
    }
    let condensed_lc = condensed.to_ascii_lowercase();
    if NON_ACTIONABLE_EXCERPT_MARKERS
        .iter()
        .any(|marker| condensed_lc.contains(marker))
    {
        return None;
    }

    Some(
        condensed
            .chars()
            .take(WEB_PIPELINE_ACTIONABLE_EXCERPT_CHARS)
            .collect(),
    )
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
    // Ontology-level fallback: if live reads are blocked but ranked source hints already
    // satisfy citation diversity, synthesize from captured evidence instead of churning.
    if pending.successful_reads.is_empty()
        && !pending.blocked_urls.is_empty()
        && pending.candidate_source_hints.len()
            >= required_distinct_citations(&synthesis_query_contract(pending))
    {
        return Some(WebPipelineCompletionReason::ExhaustedCandidates);
    }

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

    let detail = actionable_excerpt(excerpt).unwrap_or_else(|| compact_excerpt(excerpt, 160));
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
    user_impact: String,
    workaround: String,
    eta_confidence: String,
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
    required_sections: Vec<HybridSectionSpec>,
    citation_candidates: Vec<HybridCitationCandidate>,
    deterministic_story_drafts: Vec<HybridStoryDraft>,
}

#[derive(Debug, Clone, Serialize)]
struct HybridSectionSpec {
    key: String,
    label: String,
    required: bool,
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
    sections: Vec<HybridSectionDraft>,
    citation_ids: Vec<String>,
    confidence: String,
    caveat: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct HybridSectionDraft {
    key: String,
    label: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct HybridSynthesisResponse {
    #[serde(default)]
    heading: String,
    items: Vec<HybridItemResponse>,
    #[serde(default)]
    overall_confidence: String,
    #[serde(default)]
    overall_caveat: String,
}

#[derive(Debug, Deserialize)]
struct HybridItemResponse {
    title: String,
    #[serde(default)]
    sections: Vec<HybridSectionResponse>,
    #[serde(default)]
    citation_ids: Vec<String>,
    #[serde(default)]
    confidence: String,
    #[serde(default)]
    caveat: String,
}

#[derive(Debug, Deserialize)]
struct HybridSectionResponse {
    #[serde(default)]
    key: String,
    label: String,
    #[serde(default)]
    content: String,
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

    let successful_urls: BTreeSet<String> = pending
        .successful_reads
        .iter()
        .map(|source| source.url.trim().to_string())
        .filter(|url| !url.is_empty())
        .collect();

    merged.sort_by(|left, right| {
        let left_signals = source_evidence_signals(left);
        let right_signals = source_evidence_signals(right);
        let left_success = successful_urls.contains(left.url.trim());
        let right_success = successful_urls.contains(right.url.trim());
        let left_key = (
            !is_low_priority_coverage_story(left),
            left_signals.official_status_host_hits > 0,
            left_signals.official_status_host_hits,
            left_signals.primary_status_surface_hits > 0,
            left_signals.primary_status_surface_hits,
            left_signals.secondary_coverage_hits == 0,
            left_signals.documentation_surface_hits == 0,
            left_signals.relevance_score(left_success),
            left_signals.provenance_hits,
            left_signals.primary_event_hits,
            left_success,
        );
        let right_key = (
            !is_low_priority_coverage_story(right),
            right_signals.official_status_host_hits > 0,
            right_signals.official_status_host_hits,
            right_signals.primary_status_surface_hits > 0,
            right_signals.primary_status_surface_hits,
            right_signals.secondary_coverage_hits == 0,
            right_signals.documentation_surface_hits == 0,
            right_signals.relevance_score(right_success),
            right_signals.provenance_hits,
            right_signals.primary_event_hits,
            right_success,
        );
        right_key
            .cmp(&left_key)
            .then_with(|| left.url.cmp(&right.url))
    });

    merged
}

fn is_primary_status_surface_source(source: &PendingSearchReadSummary) -> bool {
    let signals = source_evidence_signals(source);
    has_primary_status_authority(signals) && !signals.low_priority_dominates()
}

fn why_it_matters_from_story(source: &PendingSearchReadSummary) -> String {
    let text = format!(
        "{} {}",
        source.title.as_deref().unwrap_or_default(),
        source.excerpt
    )
    .to_ascii_lowercase();
    if text.contains("authentication")
        || text.contains("login")
        || text.contains("identity")
        || text.contains("sso")
    {
        return "User sign-in and account access may fail or degrade for affected tenants."
            .to_string();
    }
    if text.contains("api")
        || text.contains("endpoint")
        || text.contains("request")
        || text.contains("latency")
    {
        return "API-driven workflows may see elevated errors, latency, or timeouts for affected traffic."
            .to_string();
    }
    if text.contains("dashboard")
        || text.contains("console")
        || text.contains("admin")
        || text.contains("portal")
    {
        return "Operator visibility and control-plane actions may be delayed for affected users."
            .to_string();
    }
    "Customer-facing functionality may remain degraded until source updates confirm recovery."
        .to_string()
}

fn user_impact_from_story(source: &PendingSearchReadSummary) -> String {
    why_it_matters_from_story(source)
}

fn workaround_from_story(source: &PendingSearchReadSummary) -> String {
    let signals = source_evidence_signals(source);
    if signals.mitigation_hits > 0 {
        return "Follow mitigation guidance published by the source (retry/failover/alternate path where available).".to_string();
    }
    if signals.primary_event_hits > 0
        || signals.provenance_hits > 0
        || has_primary_status_authority(signals)
    {
        return "No explicit workaround confirmed; monitor official updates and defer non-critical writes until status changes.".to_string();
    }
    "Workaround not explicitly published in retrieved evidence; use standard resilience fallback patterns and continue monitoring updates.".to_string()
}

fn eta_confidence_from_story(
    source: &PendingSearchReadSummary,
    confident_reads: usize,
    citation_count: usize,
    required_citations_per_story: usize,
) -> String {
    let signals = source_evidence_signals(source);
    let explicit_eta = signals.timeline_hits > 0;
    let status_provenance = signals.provenance_hits > 0 || has_primary_status_authority(signals);

    if explicit_eta && confident_reads >= required_citations_per_story {
        return "high".to_string();
    }
    if status_provenance || confident_reads >= 1 || citation_count >= required_citations_per_story {
        return "medium".to_string();
    }
    "low".to_string()
}

fn changed_last_hour_line(
    source: &PendingSearchReadSummary,
    run_timestamp_iso_utc: &str,
) -> String {
    if let Some(excerpt) = actionable_excerpt(source.excerpt.trim()) {
        return format!(
            "As of {}, latest provider update signal: {}",
            run_timestamp_iso_utc, excerpt
        );
    }
    format!(
        "As of {}, the event remains active in retrieved evidence; explicit hour-over-hour deltas were not consistently published.",
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
    let candidate_signals =
        analyze_source_record_signals(&candidate.url, &candidate.source_label, &candidate.excerpt);
    let mut score = title_overlap_score(&story_context, &candidate_context)
        + candidate_signals.primary_status_surface_hits * CITATION_PRIMARY_STATUS_BONUS
        + candidate_signals.official_status_host_hits * CITATION_OFFICIAL_STATUS_HOST_BONUS;
    score = score.saturating_sub(
        candidate_signals.secondary_coverage_hits * CITATION_SECONDARY_COVERAGE_PENALTY,
    );
    score = score.saturating_sub(
        candidate_signals.documentation_surface_hits * CITATION_DOCUMENTATION_SURFACE_PENALTY,
    );
    if source.url.trim() == candidate.url.trim() {
        score += CITATION_SOURCE_URL_MATCH_BONUS;
    }
    score
}

fn citation_source_signals(candidate: &CitationCandidate) -> SourceSignalProfile {
    analyze_source_record_signals(&candidate.url, &candidate.source_label, &candidate.excerpt)
}

fn is_low_priority_coverage_candidate(candidate: &CitationCandidate) -> bool {
    citation_source_signals(candidate).low_priority_dominates()
}

fn citation_ids_for_story(
    source: &PendingSearchReadSummary,
    candidates: &[CitationCandidate],
    used_urls: &mut BTreeSet<String>,
    citations_per_story: usize,
) -> Vec<String> {
    if candidates.is_empty() {
        return Vec::new();
    }

    let mut ranked = candidates
        .iter()
        .enumerate()
        .map(|(idx, candidate)| {
            let signals = citation_source_signals(candidate);
            (idx, signals)
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|(left_idx, left_signals), (right_idx, right_signals)| {
        let left = &candidates[*left_idx];
        let right = &candidates[*right_idx];
        let left_key = (
            left_signals.official_status_host_hits > 0,
            left_signals.official_status_host_hits,
            left_signals.primary_status_surface_hits > 0,
            left_signals.primary_status_surface_hits,
            left_signals.secondary_coverage_hits == 0,
            left_signals.documentation_surface_hits == 0,
            citation_relevance_score(source, left),
            !is_low_priority_coverage_candidate(left),
            left.from_successful_read,
            !used_urls.contains(&left.url),
        );
        let right_key = (
            right_signals.official_status_host_hits > 0,
            right_signals.official_status_host_hits,
            right_signals.primary_status_surface_hits > 0,
            right_signals.primary_status_surface_hits,
            right_signals.secondary_coverage_hits == 0,
            right_signals.documentation_surface_hits == 0,
            citation_relevance_score(source, right),
            !is_low_priority_coverage_candidate(right),
            right.from_successful_read,
            !used_urls.contains(&right.url),
        );
        right_key.cmp(&left_key)
    });

    let primary_status_candidates = ranked
        .iter()
        .filter(|(idx, signals)| {
            has_primary_status_authority(*signals) && !used_urls.contains(&candidates[*idx].url)
        })
        .count();
    let require_primary_status = primary_status_candidates >= citations_per_story;

    let mut selected_ids = Vec::new();
    let mut selected_urls = BTreeSet::new();

    for (idx, signals) in &ranked {
        if selected_ids.len() >= citations_per_story {
            break;
        }
        if require_primary_status && !has_primary_status_authority(*signals) {
            continue;
        }
        let candidate = &candidates[*idx];
        if used_urls.contains(&candidate.url) || selected_urls.contains(&candidate.url) {
            continue;
        }
        selected_ids.push(candidate.id.clone());
        selected_urls.insert(candidate.url.clone());
        used_urls.insert(candidate.url.clone());
    }

    if selected_ids.len() < citations_per_story {
        for (idx, _) in &ranked {
            if selected_ids.len() >= citations_per_story {
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
    let query = synthesis_query_contract(pending);
    let required_story_count = required_story_count(&query);
    let citations_per_story = required_citations_per_story(&query);
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
    let primary_status_sources = merged_sources
        .iter()
        .filter(|source| is_primary_status_surface_source(source))
        .cloned()
        .collect::<Vec<_>>();
    let source_pool = if primary_status_sources.len() >= required_story_count {
        &primary_status_sources
    } else {
        &merged_sources
    };
    let mut selected_sources = Vec::new();
    for source in source_pool {
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
        if selected_sources.len() >= required_story_count {
            break;
        }
    }
    while selected_sources.len() < required_story_count && !source_pool.is_empty() {
        selected_sources.push(source_pool[selected_sources.len() % source_pool.len()].clone());
    }

    let mut used_urls = BTreeSet::new();
    for source in selected_sources.iter().take(required_story_count) {
        let title = canonical_source_title(source);
        let what_happened = source_bullet(source);
        let why_it_matters = why_it_matters_from_story(source);
        let user_impact = user_impact_from_story(source);
        let workaround = workaround_from_story(source);
        let changed_last_hour = changed_last_hour_line(source, &run_timestamp_iso_utc);
        let citation_ids =
            citation_ids_for_story(source, &candidates, &mut used_urls, citations_per_story);
        let confident_reads = citation_ids
            .iter()
            .filter_map(|id| citations_by_id.get(id))
            .filter(|candidate| candidate.from_successful_read)
            .count();
        let confidence = if confident_reads >= citations_per_story {
            "high".to_string()
        } else if citation_ids.len() >= citations_per_story {
            "medium".to_string()
        } else {
            "low".to_string()
        };
        let eta_confidence = eta_confidence_from_story(
            source,
            confident_reads,
            citation_ids.len(),
            citations_per_story,
        );
        let caveat = "Timestamps are anchored to UTC retrieval time when source publish/update metadata was unavailable.".to_string();

        stories.push(StoryDraft {
            title,
            what_happened,
            changed_last_hour,
            why_it_matters,
            user_impact,
            workaround,
            eta_confidence,
            citation_ids,
            confidence,
            caveat,
        });
    }

    while stories.len() < required_story_count {
        let fallback_source = if merged_sources.is_empty() {
            PendingSearchReadSummary {
                url: String::new(),
                title: None,
                excerpt: String::new(),
            }
        } else {
            merged_sources[stories.len() % merged_sources.len()].clone()
        };
        let fallback_ids = citation_ids_for_story(
            &fallback_source,
            &candidates,
            &mut used_urls,
            citations_per_story,
        );
        stories.push(StoryDraft {
            title: format!("Story {}", stories.len() + 1),
            what_happened:
                "Insufficient high-signal extraction for a richer deterministic summary."
                    .to_string(),
            changed_last_hour: changed_last_hour_line(&fallback_source, &run_timestamp_iso_utc),
            why_it_matters:
                "This still matters because it contributes to active service health awareness."
                    .to_string(),
            user_impact: "Potential user-facing degradation remains plausible for affected users."
                .to_string(),
            workaround:
                "No explicit workaround confirmed in retrieved evidence; monitor source updates."
                    .to_string(),
            eta_confidence: "low".to_string(),
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
        overall_caveat: format!(
            "Ontology={} ranking uses content, provenance, and recency evidence; provider/source timestamps may lag or omit explicit update metadata.",
            WEB_EVIDENCE_SIGNAL_VERSION
        ),
        stories,
        citations_by_id,
        blocked_urls: pending.blocked_urls.clone(),
        partial_note,
    }
}

fn render_synthesis_draft(draft: &SynthesisDraft) -> String {
    if requires_mailbox_access_notice(&draft.query) {
        return render_mailbox_access_limited_draft(draft);
    }

    let mut lines = Vec::new();
    let required_sections = build_hybrid_required_sections(&draft.query);
    let story_count = required_story_count(&draft.query);
    let citations_per_story = required_citations_per_story(&draft.query);
    let heading = if draft.query.trim().is_empty() {
        format!(
            "Web retrieval summary (as of {} UTC)",
            draft.run_timestamp_iso_utc
        )
    } else {
        format!(
            "Web retrieval summary for '{}' (as of {} UTC)",
            draft.query.trim(),
            draft.run_timestamp_iso_utc
        )
    };
    lines.push(heading);

    for (idx, story) in draft.stories.iter().take(story_count).enumerate() {
        lines.push(String::new());
        lines.push(format!("Story {}: {}", idx + 1, story.title));
        if required_sections.is_empty() {
            lines.push(format!("What happened: {}", story.what_happened));
        } else {
            for section in &required_sections {
                if let Some(content) = section_content_for_story(story, section) {
                    lines.push(format!("{}: {}", content.label, content.content));
                }
            }
        }
        lines.push("Citations:".to_string());
        for citation_id in story.citation_ids.iter().take(citations_per_story) {
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

fn normalize_section_key(label: &str) -> String {
    let mut out = String::new();
    let mut last_was_underscore = false;
    for ch in label.chars() {
        let normalized = ch.to_ascii_lowercase();
        if normalized.is_ascii_alphanumeric() {
            out.push(normalized);
            last_was_underscore = false;
            continue;
        }
        if !last_was_underscore {
            out.push('_');
            last_was_underscore = true;
        }
    }
    out.trim_matches('_').to_string()
}

fn dedupe_labels(labels: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for label in labels {
        let key = normalize_section_key(&label);
        if key.is_empty() || !seen.insert(key) {
            continue;
        }
        out.push(label);
    }
    out
}

fn required_section_labels_for_query(query: &str) -> Vec<String> {
    dedupe_labels(
        infer_report_sections(query)
            .into_iter()
            .map(|kind| report_section_label(kind, query))
            .collect(),
    )
}

fn build_hybrid_required_sections(query: &str) -> Vec<HybridSectionSpec> {
    required_section_labels_for_query(query)
        .into_iter()
        .map(|label| HybridSectionSpec {
            key: normalize_section_key(&label),
            label,
            required: true,
        })
        .collect()
}

fn section_kind_from_key(key: &str) -> Option<ReportSectionKind> {
    let normalized = normalize_section_key(key);
    [
        ReportSectionKind::Summary,
        ReportSectionKind::RecentChange,
        ReportSectionKind::Significance,
        ReportSectionKind::UserImpact,
        ReportSectionKind::Mitigation,
        ReportSectionKind::EtaConfidence,
        ReportSectionKind::Caveat,
        ReportSectionKind::Evidence,
    ]
    .into_iter()
    .find(|kind| {
        normalized == report_section_key(*kind)
            || report_section_aliases(*kind)
                .iter()
                .any(|alias| normalize_section_key(alias) == normalized)
    })
}

fn section_content_for_story(
    story: &StoryDraft,
    section: &HybridSectionSpec,
) -> Option<HybridSectionDraft> {
    let kind = section_kind_from_key(&section.key)
        .or_else(|| section_kind_from_key(&section.label))
        .unwrap_or(ReportSectionKind::Summary);
    let content = match kind {
        ReportSectionKind::Summary => story.what_happened.clone(),
        ReportSectionKind::RecentChange => story.changed_last_hour.clone(),
        ReportSectionKind::Significance => story.why_it_matters.clone(),
        ReportSectionKind::UserImpact => story.user_impact.clone(),
        ReportSectionKind::Mitigation => story.workaround.clone(),
        ReportSectionKind::EtaConfidence => story.eta_confidence.clone(),
        ReportSectionKind::Caveat => story.caveat.clone(),
        ReportSectionKind::Evidence => story.what_happened.clone(),
    };

    let normalized = compact_whitespace(content.trim());
    if normalized.is_empty() {
        return None;
    }
    Some(HybridSectionDraft {
        key: section.key.clone(),
        label: section.label.clone(),
        content: normalized,
    })
}

fn section_content_from_map(sections: &BTreeMap<String, String>, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(value) = sections.get(*key) {
            let trimmed = compact_whitespace(value.trim());
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
    }
    None
}

fn section_content_from_map_for_kind(
    sections: &BTreeMap<String, String>,
    kind: ReportSectionKind,
) -> Option<String> {
    section_content_from_map(sections, report_section_aliases(kind))
}

fn apply_hybrid_synthesis_response(
    base: &SynthesisDraft,
    required_sections: &[HybridSectionSpec],
    response: HybridSynthesisResponse,
) -> Option<SynthesisDraft> {
    let required_story_count = required_story_count(&base.query);
    let citations_per_story = required_citations_per_story(&base.query);
    let required_distinct_citations = required_distinct_citations(&base.query);
    if response.items.len() < required_story_count {
        return None;
    }

    let mut used_urls = BTreeSet::new();
    let mut stories = Vec::new();
    let required_keys = required_sections
        .iter()
        .map(|section| section.key.clone())
        .collect::<BTreeSet<_>>();

    for (idx, item) in response
        .items
        .into_iter()
        .take(required_story_count)
        .enumerate()
    {
        let base_story = base.stories.get(idx)?;
        let title = item.title.trim();
        if title.is_empty() {
            return None;
        }

        let mut sections_by_key = BTreeMap::<String, String>::new();
        for section in item.sections {
            let key = {
                let from_key = normalize_section_key(&section.key);
                if from_key.is_empty() {
                    normalize_section_key(&section.label)
                } else {
                    from_key
                }
            };
            if key.is_empty() {
                continue;
            }
            let content = compact_whitespace(section.content.trim());
            if content.is_empty() {
                continue;
            }
            sections_by_key.entry(key).or_insert(content);
        }
        if required_keys
            .iter()
            .any(|required| !sections_by_key.contains_key(required))
        {
            return None;
        }

        let happened =
            section_content_from_map_for_kind(&sections_by_key, ReportSectionKind::Summary)
                .unwrap_or_else(|| base_story.what_happened.clone());
        let changed =
            section_content_from_map_for_kind(&sections_by_key, ReportSectionKind::RecentChange)
                .unwrap_or_else(|| base_story.changed_last_hour.clone());
        let matters =
            section_content_from_map_for_kind(&sections_by_key, ReportSectionKind::Significance)
                .unwrap_or_else(|| base_story.why_it_matters.clone());
        let user_impact =
            section_content_from_map_for_kind(&sections_by_key, ReportSectionKind::UserImpact)
                .unwrap_or_else(|| base_story.user_impact.clone());
        let workaround =
            section_content_from_map_for_kind(&sections_by_key, ReportSectionKind::Mitigation)
                .unwrap_or_else(|| base_story.workaround.clone());
        let eta_label =
            section_content_from_map_for_kind(&sections_by_key, ReportSectionKind::EtaConfidence)
                .unwrap_or_else(|| base_story.eta_confidence.clone());

        let mut citation_ids = Vec::new();
        for id in item.citation_ids {
            let trimmed = id.trim();
            if trimmed.is_empty() || citation_ids.iter().any(|existing| existing == trimmed) {
                continue;
            }
            let Some(citation) = base.citations_by_id.get(trimmed) else {
                continue;
            };
            citation_ids.push(trimmed.to_string());
            used_urls.insert(citation.url.clone());
            if citation_ids.len() >= citations_per_story {
                break;
            }
        }
        if citation_ids.len() < citations_per_story {
            return None;
        }

        let mut normalized_confidence = normalize_confidence_label(&item.confidence);
        if normalized_confidence == "low" && citation_ids.len() >= citations_per_story {
            normalized_confidence = "medium".to_string();
        }

        stories.push(StoryDraft {
            title: title.to_string(),
            what_happened: happened.to_string(),
            changed_last_hour: changed.to_string(),
            why_it_matters: matters.to_string(),
            user_impact,
            workaround,
            eta_confidence: normalize_confidence_label(&eta_label),
            citation_ids,
            confidence: normalized_confidence,
            caveat: if item.caveat.trim().is_empty() {
                "Model omitted caveat; fallback caveat applied.".to_string()
            } else {
                item.caveat.trim().to_string()
            },
        });
    }

    if used_urls.len() < required_distinct_citations {
        return None;
    }

    let mut overall_confidence = normalize_confidence_label(&response.overall_confidence);
    if overall_confidence == "low" && used_urls.len() >= required_distinct_citations {
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
            let heading = response.heading.trim();
            if heading.is_empty() {
                response.overall_caveat.trim().to_string()
            } else {
                format!(
                    "{} | heading: {}",
                    response.overall_caveat.trim(),
                    compact_whitespace(heading)
                )
            }
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
    let required_story_count = required_story_count(&draft.query);
    let citations_per_story = required_citations_per_story(&draft.query);
    let required_distinct_citations = required_distinct_citations(&draft.query);
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
    if candidates.len() < required_distinct_citations {
        return None;
    }

    let required_sections = build_hybrid_required_sections(&draft.query);
    if required_sections.is_empty() {
        return None;
    }

    let deterministic_story_drafts = draft
        .stories
        .iter()
        .take(required_story_count)
        .map(|story| HybridStoryDraft {
            title: story.title.clone(),
            sections: required_sections
                .iter()
                .filter_map(|section| section_content_for_story(story, section))
                .collect::<Vec<_>>(),
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
        required_sections: required_sections.clone(),
        citation_candidates: candidates,
        deterministic_story_drafts,
    };
    let prompt = format!(
        "Return JSON only with schema: \
{{\"heading\":string,\"items\":[{{\"title\":string,\"sections\":[{{\"label\":string,\"content\":string}}],\"citation_ids\":[string],\"confidence\":\"high|medium|low\",\"caveat\":string}}],\"overall_confidence\":\"high|medium|low\",\"overall_caveat\":string}}.\n\
Requirements:\n\
- Exactly {} items.\n\
- For each item, include all payload.required_sections labels exactly once in `sections`.\n\
- Use ONLY citation_ids from payload.\n\
- Each item must include exactly {} citation_ids.\n\
- Keep text concise, factual, and query-aligned.\n\
- Treat run_timestamp_ms and run_timestamp_iso_utc as authoritative UTC clock for recency.\n\
Payload:\n{}",
        required_story_count,
        citations_per_story,
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
    let updated = apply_hybrid_synthesis_response(&draft, &required_sections, response)?;

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
