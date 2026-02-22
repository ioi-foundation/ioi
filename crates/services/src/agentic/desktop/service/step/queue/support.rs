use super::envelope::{
    compile_constraint_set, score_evidence_candidate, verify_claim_envelope,
    CandidateEvidenceScore, ConstraintScope, ConstraintSet, EnvelopeStatus, ResolutionPolicy,
};
use crate::agentic::desktop::middleware;
use crate::agentic::desktop::service::step::signals::{
    analyze_metric_schema, analyze_query_facets, analyze_source_record_signals,
    infer_report_sections, is_mailbox_connector_intent, query_semantic_anchor_tokens,
    query_structural_directive_tokens, report_section_aliases, report_section_key,
    report_section_label, MetricAxis, MetricSchemaProfile, QueryFacetProfile, ReportSectionKind,
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
use url::Url;

const MAX_SEARCH_EXTRACT_CHARS: usize = 8_000;
const QUEUE_TOOL_NAME_KEY: &str = "__ioi_tool_name";
const WEB_PIPELINE_EXCERPT_CHARS: usize = 220;
pub(crate) const WEB_PIPELINE_BUDGET_MS: u64 = 50_000;
pub(crate) const WEB_PIPELINE_DEFAULT_MIN_SOURCES: u32 = 1;
pub(crate) const WEB_PIPELINE_SEARCH_LIMIT: u32 = 10;
pub(crate) const WEB_PIPELINE_REQUIRED_STORIES: usize = 3;
pub(crate) const WEB_PIPELINE_CITATIONS_PER_STORY: usize = 2;
const WEB_PIPELINE_CONSTRAINT_SEARCH_LIMIT_MIN: u32 = 4;
const WEB_PIPELINE_CONSTRAINT_SEARCH_LIMIT_MAX: u32 = 8;
const WEB_PIPELINE_CONSTRAINT_SEARCH_LIMIT_MULTIPLIER: u32 = 3;

const WEB_PIPELINE_STORY_TITLE_CHARS: usize = 140;
const WEB_PIPELINE_HYBRID_MAX_TOKENS: u32 = 1_200;
const WEB_PIPELINE_HYBRID_BUDGET_GUARD_MS: u64 = 45_000;
const WEB_PIPELINE_ACTIONABLE_EXCERPT_CHARS: usize = 140;
const WEB_PIPELINE_MIN_REMAINING_BUDGET_MS_FOR_INITIAL_READ: u64 = 20_000;
const WEB_PIPELINE_MIN_REMAINING_BUDGET_MS_FOR_SEARCH_PROBE: u64 = 20_000;
const WEB_PIPELINE_LATENCY_ELEVATED_BUFFER_MS: u64 = 6_000;
const WEB_PIPELINE_LATENCY_READ_GUARD_MS: u64 = 8_000;
const WEB_PIPELINE_LATENCY_PROBE_GUARD_MS: u64 = 10_000;
const CITATION_SOURCE_URL_MATCH_BONUS: usize = 1_000;
const CITATION_PRIMARY_STATUS_BONUS: usize = 16;
const CITATION_OFFICIAL_STATUS_HOST_BONUS: usize = 24;
const CITATION_SECONDARY_COVERAGE_PENALTY: usize = 8;
const CITATION_DOCUMENTATION_SURFACE_PENALTY: usize = 10;
const SINGLE_SNAPSHOT_MAX_ADDITIONAL_PROBE_SOURCES: usize = 1;
const SINGLE_SNAPSHOT_MAX_EXPLORATORY_READS_WITHOUT_COMPATIBILITY: usize = 2;
const SINGLE_SNAPSHOT_MIN_REMAINING_BUDGET_MS_FOR_PROBE: u64 = 35_000;
const QUERY_COMPATIBILITY_MIN_TOKEN_CHARS: usize = 3;
const QUERY_COMPATIBILITY_MIN_ANCHOR_OVERLAP: usize = 1;
const QUERY_COMPATIBILITY_MIN_GROUNDED_MULTI_ANCHOR_OVERLAP: usize = 2;
const QUERY_COMPATIBILITY_STRONG_COVERAGE_NUMERATOR: usize = 1;
const QUERY_COMPATIBILITY_STRONG_COVERAGE_DENOMINATOR: usize = 3;
const QUERY_COMPATIBILITY_ANCHOR_WEIGHT: usize = 8;
const QUERY_COMPATIBILITY_NATIVE_ANCHOR_WEIGHT: usize = 12;
const QUERY_COMPATIBILITY_STRONG_COVERAGE_BONUS: usize = 10;
const QUERY_COMPATIBILITY_AXIS_OVERLAP_WEIGHT: usize = 10;
const QUERY_COMPATIBILITY_CURRENT_OBSERVATION_BONUS: usize = 8;
const QUERY_COMPATIBILITY_GROUNDED_EXTERNAL_BONUS: usize = 6;
const QUERY_COMPATIBILITY_SEARCH_HUB_PENALTY: usize = 24;
const QUERY_COMPATIBILITY_NO_RESOLVABLE_PAYLOAD_PENALTY: usize = 6;
const QUERY_COMPATIBILITY_LOCALITY_OVERLAP_WEIGHT: usize = 14;
const QUERY_COMPATIBILITY_MIN_LOCALITY_OVERLAP: usize = 1;
const TIME_SENSITIVE_RESOLVABLE_SURFACE_MIN_AXIS: usize = 2;
const QUERY_PROBE_HINT_MAX_CANDIDATES: usize = 4;
const QUERY_PROBE_HINT_MAX_TOKENS: usize = 3;
const QUERY_PROBE_HINT_MIN_SHARED_TOKEN_HITS: usize = 2;
const QUERY_PROBE_ESCALATION_MAX_CONFLICT_TERMS: usize = 3;
const QUERY_PROBE_ESCALATION_MIN_CONFLICT_HITS: usize = 1;
const QUERY_PROBE_ESCALATION_MAX_HOST_EXCLUSION_TERMS: usize = 2;
const QUERY_PROBE_LOCALITY_METRIC_ESCALATION_PHRASE: &str = "current conditions";
const ACTIONABLE_EXCERPT_MIN_SCORE: usize = 4;
const ACTIONABLE_EXCERPT_SEGMENT_MIN_CHARS: usize = 28;
const ACTIONABLE_EXCERPT_CLAIM_BASE_BONUS: usize = 3;
const INFERRED_SCOPE_FALLBACK_CANDIDATE_COUNT: usize = 2;
const TIME_SENSITIVE_RESOLUTION_MIN_FACET_NUMERATOR: usize = 1;
const TIME_SENSITIVE_RESOLUTION_MIN_FACET_DENOMINATOR: usize = 2;
const LOCALITY_SCOPE_MAX_CHARS: usize = 96;
const LOCALITY_SCOPE_TOKEN_MAX_CHARS: usize = 24;
const LOCALITY_INFERENCE_MIN_SUPPORT: usize = 2;
const LOCALITY_INFERENCE_MAX_TOKENS: usize = 4;
const QUERY_COMPATIBILITY_STOPWORDS: [&str; 28] = [
    "a", "an", "the", "and", "or", "to", "of", "for", "with", "in", "on", "at", "by", "from",
    "into", "over", "under", "what", "whats", "is", "are", "was", "were", "right", "now",
    "current", "latest", "today",
];
const LOCALITY_SCOPE_NOISE_TOKENS: [&str; 21] = [
    "http", "https", "www", "com", "org", "net", "news", "google", "search", "query", "update",
    "source", "sources", "rss", "article", "articles", "read", "feed", "story", "stories", "oc",
];
const TRUSTED_LOCALITY_ENV_KEYS: [&str; 8] = [
    "IOI_SESSION_LOCALITY",
    "IOI_DEVICE_LOCALITY",
    "IOI_USER_LOCALITY",
    "IOI_LOCALITY",
    "SESSION_LOCALITY",
    "DEVICE_LOCALITY",
    "USER_LOCALITY",
    "LOCALITY",
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PreReadCandidatePlan {
    pub candidate_urls: Vec<String>,
    pub candidate_source_hints: Vec<PendingSearchReadSummary>,
    pub probe_source_hints: Vec<PendingSearchReadSummary>,
    pub total_candidates: usize,
    pub pruned_candidates: usize,
    pub resolvable_candidates: usize,
    pub scoreable_candidates: usize,
    pub requires_constraint_search_probe: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WebPipelineCompletionReason {
    MinSourcesReached,
    ExhaustedCandidates,
    DeadlineReached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WebPipelineLatencyPressure {
    Nominal,
    Elevated,
    Critical,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CandidateConstraintCompatibility {
    compatibility_score: usize,
    is_compatible: bool,
    locality_compatible: bool,
}

#[derive(Debug, Clone)]
struct QueryConstraintProjection {
    constraints: ConstraintSet,
    query_facets: QueryFacetProfile,
    query_native_tokens: BTreeSet<String>,
    query_tokens: BTreeSet<String>,
    locality_scope: Option<String>,
    locality_scope_inferred: bool,
    locality_tokens: BTreeSet<String>,
}

impl QueryConstraintProjection {
    fn enforce_grounded_compatibility(&self) -> bool {
        self.constraints
            .scopes
            .contains(&ConstraintScope::TimeSensitive)
            || (self.query_facets.grounded_external_required
                && !self.query_native_tokens.is_empty())
    }

    fn strict_grounded_compatibility(&self) -> bool {
        self.constraints
            .scopes
            .contains(&ConstraintScope::TimeSensitive)
            && self.enforce_grounded_compatibility()
            && !self.locality_scope_inferred
            && self.query_native_tokens.len()
                >= QUERY_COMPATIBILITY_MIN_GROUNDED_MULTI_ANCHOR_OVERLAP
    }

    fn has_constraint_objective(&self) -> bool {
        self.constraints
            .scopes
            .contains(&ConstraintScope::TimeSensitive)
            || self.query_facets.grounded_external_required
            || !self.constraints.required_facets.is_empty()
            || !self.query_tokens.is_empty()
    }

    fn reject_search_hub_candidates(&self) -> bool {
        self.constraints
            .scopes
            .contains(&ConstraintScope::TimeSensitive)
            || self.query_facets.grounded_external_required
    }
}

#[derive(Debug, Clone)]
struct RankedAcquisitionCandidate {
    idx: usize,
    hint: PendingSearchReadSummary,
    envelope_score: CandidateEvidenceScore,
    resolves_constraint: bool,
    time_sensitive_resolvable_payload: bool,
    compatibility: CandidateConstraintCompatibility,
    source_relevance_score: usize,
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

fn explicit_story_count_hint(query: &str) -> Option<usize> {
    let tokens = query.split_whitespace().collect::<Vec<_>>();
    for idx in 0..tokens.len() {
        let token = tokens[idx].to_ascii_lowercase();
        if token == "top" {
            if let Some(value) = tokens
                .get(idx + 1)
                .and_then(|value| parse_small_count_token(value))
            {
                return Some(value.clamp(1, 6));
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
            return Some(value.clamp(1, 6));
        }
    }
    None
}

fn required_story_count(query: &str) -> usize {
    if let Some(explicit) = explicit_story_count_hint(query) {
        return explicit;
    }
    if prefers_single_fact_snapshot(query) {
        return 1;
    }

    WEB_PIPELINE_REQUIRED_STORIES
}

fn prefers_single_fact_snapshot(query: &str) -> bool {
    if query.trim().is_empty() {
        return false;
    }

    let facets = analyze_query_facets(query);
    if !facets.time_sensitive_public_fact {
        return false;
    }
    if facets.workspace_constrained {
        return false;
    }
    if explicit_story_count_hint(query).is_some() {
        return false;
    }
    true
}

fn query_metric_axes_with_hints(
    query: &str,
    candidate_hints: &[PendingSearchReadSummary],
) -> BTreeSet<MetricAxis> {
    let query_facets = analyze_query_facets(query);
    let query_native_tokens = query_native_anchor_tokens(query);
    let mut required_facets = query_facets.metric_schema.axis_hits;
    if required_facets.is_empty() {
        let mut inferred_counts = BTreeMap::<MetricAxis, usize>::new();
        for hint in candidate_hints {
            let title = hint.title.as_deref().unwrap_or_default();
            let hint_tokens = source_anchor_tokens(&hint.url, title, &hint.excerpt);
            let has_query_anchor_overlap = query_native_tokens.is_empty()
                || query_native_tokens
                    .intersection(&hint_tokens)
                    .next()
                    .is_some();
            if !has_query_anchor_overlap {
                continue;
            }
            let combined = format!("{} {}", title, hint.excerpt);
            let schema = analyze_metric_schema(&combined);
            for axis in schema.axis_hits {
                *inferred_counts.entry(axis).or_insert(0) += 1;
            }
        }
        let mut inferred_ranked = inferred_counts.into_iter().collect::<Vec<_>>();
        inferred_ranked
            .sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        required_facets.extend(inferred_ranked.into_iter().take(4).map(|(axis, _)| axis));
    }
    compile_constraint_set(
        query,
        required_facets,
        WEB_PIPELINE_DEFAULT_MIN_SOURCES as usize,
    )
    .required_facets
}

fn query_metric_axes(query: &str) -> BTreeSet<MetricAxis> {
    query_metric_axes_with_hints(query, &[])
}

fn single_snapshot_constraint_set_with_hints(
    query: &str,
    min_independent_sources: usize,
    candidate_hints: &[PendingSearchReadSummary],
) -> ConstraintSet {
    let required_facets = query_metric_axes_with_hints(query, candidate_hints);
    compile_constraint_set(query, required_facets, min_independent_sources)
}

fn single_snapshot_candidate_envelope_score(
    constraints: &ConstraintSet,
    policy: ResolutionPolicy,
    url: &str,
    title: &str,
    excerpt: &str,
) -> CandidateEvidenceScore {
    let source = PendingSearchReadSummary {
        url: url.trim().to_string(),
        title: {
            let trimmed = title.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        },
        excerpt: excerpt.trim().to_string(),
    };
    score_evidence_candidate(constraints, &source, "", policy)
}

fn envelope_score_has_resolvable_signal(score: &CandidateEvidenceScore) -> bool {
    score.has_numeric_observation()
        || score.present_without_numeric_facets > 0
        || (score.required_facets == 0 && score.total_score > 0)
}

fn envelope_score_resolves_constraint(
    constraints: &ConstraintSet,
    score: &CandidateEvidenceScore,
) -> bool {
    let minimum_numeric_facets = if constraints.required_facets.is_empty() {
        1
    } else if constraints.scopes.contains(&ConstraintScope::TimeSensitive) {
        constraints
            .required_facets
            .len()
            .saturating_mul(TIME_SENSITIVE_RESOLUTION_MIN_FACET_NUMERATOR)
            .saturating_add(TIME_SENSITIVE_RESOLUTION_MIN_FACET_DENOMINATOR.saturating_sub(1))
            / TIME_SENSITIVE_RESOLUTION_MIN_FACET_DENOMINATOR
    } else {
        1
    }
    .max(1);

    if constraints.scopes.contains(&ConstraintScope::TimeSensitive) {
        return score.numeric_observed_facets >= minimum_numeric_facets;
    }

    if constraints.required_facets.is_empty() {
        return envelope_score_has_resolvable_signal(score);
    }

    // Metric facets are quantitative in this ontology, so pre-read resolvability
    // requires at least one numeric observation claim before we spend a read.
    score.numeric_observed_facets > 0
}

fn compare_candidate_evidence_scores_desc(
    left: &CandidateEvidenceScore,
    right: &CandidateEvidenceScore,
) -> std::cmp::Ordering {
    right
        .has_numeric_observation()
        .cmp(&left.has_numeric_observation())
        .then_with(|| {
            right
                .numeric_observed_facets
                .cmp(&left.numeric_observed_facets)
        })
        .then_with(|| {
            right
                .present_without_numeric_facets
                .cmp(&left.present_without_numeric_facets)
        })
        .then_with(|| left.missing_facets.cmp(&right.missing_facets))
        .then_with(|| left.unavailable_facets.cmp(&right.unavailable_facets))
        .then_with(|| {
            right
                .observed_timestamp_facets
                .cmp(&left.observed_timestamp_facets)
        })
        .then_with(|| right.total_score.cmp(&left.total_score))
}

fn metric_axis_search_phrase(axis: MetricAxis) -> &'static str {
    match axis {
        MetricAxis::Temperature => "temperature",
        MetricAxis::Humidity => "humidity",
        MetricAxis::Wind => "wind",
        MetricAxis::Pressure => "pressure",
        MetricAxis::Visibility => "visibility",
        MetricAxis::AirQuality => "air quality",
        MetricAxis::Precipitation => "precipitation",
        MetricAxis::Price => "price",
        MetricAxis::Rate => "rate",
        MetricAxis::Score => "score",
        MetricAxis::Duration => "duration",
    }
}

fn is_query_stopword(token: &str) -> bool {
    QUERY_COMPATIBILITY_STOPWORDS.contains(&token)
}

fn is_locality_scope_noise_token(token: &str) -> bool {
    LOCALITY_SCOPE_NOISE_TOKENS.contains(&token)
}

fn normalized_anchor_tokens(text: &str) -> BTreeSet<String> {
    text.split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter_map(|token| {
            let normalized = token.trim().to_ascii_lowercase();
            if normalized.len() < QUERY_COMPATIBILITY_MIN_TOKEN_CHARS {
                return None;
            }
            if normalized.chars().all(|ch| ch.is_ascii_digit()) {
                return None;
            }
            if is_query_stopword(&normalized) {
                return None;
            }
            Some(normalized)
        })
        .collect()
}

fn normalized_locality_tokens(text: &str) -> BTreeSet<String> {
    text.split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter_map(|token| {
            let normalized = token.trim().to_ascii_lowercase();
            if normalized.len() < 2 {
                return None;
            }
            if normalized.chars().all(|ch| ch.is_ascii_digit()) {
                return None;
            }
            if is_query_stopword(&normalized) {
                return None;
            }
            Some(normalized)
        })
        .collect()
}

fn source_locality_tokens(url: &str, title: &str, excerpt: &str) -> BTreeSet<String> {
    let mut tokens = normalized_locality_tokens(title);
    tokens.extend(normalized_locality_tokens(excerpt));

    if let Ok(parsed) = Url::parse(url.trim()) {
        if let Some(host) = parsed.host_str() {
            tokens.extend(normalized_locality_tokens(host));
        }
        tokens.extend(normalized_locality_tokens(parsed.path()));
        if let Some(query) = parsed.query() {
            tokens.extend(normalized_locality_tokens(query));
        }
    } else {
        tokens.extend(normalized_locality_tokens(url));
    }

    tokens
}

fn ordered_normalized_locality_tokens(text: &str) -> Vec<String> {
    let mut ordered = Vec::new();
    let mut seen = BTreeSet::new();
    for token in text.split(|ch: char| !ch.is_ascii_alphanumeric()) {
        let normalized = token.trim().to_ascii_lowercase();
        if normalized.len() < 2 {
            continue;
        }
        if normalized.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }
        if is_query_stopword(&normalized) {
            continue;
        }
        if !seen.insert(normalized.clone()) {
            continue;
        }
        ordered.push(normalized);
    }
    ordered
}

fn source_structural_locality_tokens(url: &str, title: &str) -> Vec<String> {
    let mut tokens = ordered_normalized_locality_tokens(title);
    let mut seen = tokens.iter().cloned().collect::<BTreeSet<_>>();
    if let Ok(parsed) = Url::parse(url.trim()) {
        if !is_locality_scope_inference_hub_url(url) {
            for token in ordered_normalized_locality_tokens(parsed.path()) {
                if seen.insert(token.clone()) {
                    tokens.push(token);
                }
            }
            if let Some(query) = parsed.query() {
                for token in ordered_normalized_locality_tokens(query) {
                    if seen.insert(token.clone()) {
                        tokens.push(token);
                    }
                }
            }
        }
    } else {
        for token in ordered_normalized_locality_tokens(url) {
            if seen.insert(token.clone()) {
                tokens.push(token);
            }
        }
    }
    tokens
}

fn is_locality_scope_inference_hub_url(url: &str) -> bool {
    if is_search_hub_url(url) {
        return true;
    }
    let Ok(parsed) = Url::parse(url.trim()) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    let path = parsed.path().to_ascii_lowercase();
    host == "news.google.com"
        && (path.starts_with("/rss/articles")
            || path.starts_with("/rss/read")
            || path.starts_with("/rss/topics"))
}

fn sanitize_locality_scope(raw: &str) -> Option<String> {
    let mut out = String::new();
    let mut last_was_space = true;
    for ch in raw.trim().chars() {
        let allowed = ch.is_ascii_alphanumeric() || matches!(ch, ' ' | ',' | '-' | '/');
        if allowed {
            let normalized = if ch.is_ascii_whitespace() { ' ' } else { ch };
            if normalized == ' ' {
                if last_was_space {
                    continue;
                }
                last_was_space = true;
            } else {
                last_was_space = false;
            }
            out.push(normalized);
        } else if !last_was_space {
            out.push(' ');
            last_was_space = true;
        }
        if out.chars().count() >= LOCALITY_SCOPE_MAX_CHARS {
            break;
        }
    }
    let compact = compact_whitespace(&out);
    (!compact.is_empty()).then_some(compact)
}

fn inferred_locality_scope_from_candidate_hints(
    query: &str,
    candidate_hints: &[PendingSearchReadSummary],
) -> Option<String> {
    if candidate_hints.is_empty() {
        return None;
    }

    let query_facets = analyze_query_facets(query);
    let locality_scope_required = query_requires_locality_scope(query, &query_facets);
    let semantic_query_tokens = query_semantic_anchor_tokens(query)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let structural_query_tokens = query_structural_directive_tokens(query);
    let mut token_support: BTreeMap<String, usize> = BTreeMap::new();
    let mut structural_token_support: BTreeMap<String, usize> = BTreeMap::new();
    let mut hint_tokens = Vec::new();

    for (rank, hint) in candidate_hints.iter().enumerate() {
        let title = hint.title.as_deref().unwrap_or_default();
        if locality_scope_required
            && !candidate_time_sensitive_resolvable_payload(title, &hint.excerpt)
        {
            continue;
        }
        let locality_hub_hint = is_locality_scope_inference_hub_url(&hint.url);
        let mut tokens = if locality_hub_hint {
            ordered_normalized_locality_tokens(title)
        } else {
            source_structural_locality_tokens(&hint.url, title)
        };
        if tokens.is_empty() {
            tokens = if locality_hub_hint {
                ordered_normalized_locality_tokens(&hint.excerpt)
            } else {
                source_locality_tokens(&hint.url, title, &hint.excerpt)
                    .into_iter()
                    .collect::<Vec<_>>()
            };
        }
        let mut filtered_tokens = Vec::new();
        let mut seen_tokens = BTreeSet::new();
        for token in tokens.into_iter() {
            if token.len() < 2 {
                continue;
            }
            if token.len() > LOCALITY_SCOPE_TOKEN_MAX_CHARS {
                continue;
            }
            if is_query_stopword(&token) {
                continue;
            }
            if is_locality_scope_noise_token(&token) {
                continue;
            }
            if semantic_query_tokens.contains(&token) || structural_query_tokens.contains(&token) {
                continue;
            }
            if analyze_metric_schema(&token).has_metric_payload() {
                continue;
            }
            if !seen_tokens.insert(token.clone()) {
                continue;
            }
            filtered_tokens.push(token);
        }
        if filtered_tokens.is_empty() {
            continue;
        }

        let mut structural_tokens = Vec::new();
        if let Ok(parsed) = Url::parse(hint.url.trim()) {
            structural_tokens.extend(ordered_normalized_locality_tokens(parsed.path()));
            if let Some(query) = parsed.query() {
                structural_tokens.extend(ordered_normalized_locality_tokens(query));
            }
        }
        let mut seen_structural_tokens = BTreeSet::new();
        for token in structural_tokens {
            if token.len() < 2 {
                continue;
            }
            if token.len() > LOCALITY_SCOPE_TOKEN_MAX_CHARS {
                continue;
            }
            if is_query_stopword(&token) || is_locality_scope_noise_token(&token) {
                continue;
            }
            if semantic_query_tokens.contains(&token) || structural_query_tokens.contains(&token) {
                continue;
            }
            if analyze_metric_schema(&token).has_metric_payload() {
                continue;
            }
            if !seen_structural_tokens.insert(token.clone()) {
                continue;
            }
            *structural_token_support.entry(token).or_insert(0) += 1;
        }

        for token in &filtered_tokens {
            *token_support.entry(token.clone()).or_insert(0) += 1;
        }
        hint_tokens.push((rank, filtered_tokens));
    }

    if token_support.is_empty() || hint_tokens.is_empty() {
        return None;
    }

    let mut ranked_hints = hint_tokens
        .into_iter()
        .map(|(rank, tokens)| {
            let consensus_score = tokens
                .iter()
                .map(|token| {
                    token_support
                        .get(token)
                        .copied()
                        .unwrap_or_default()
                        .saturating_sub(1)
                })
                .sum::<usize>();
            let aggregate_support = tokens
                .iter()
                .map(|token| token_support.get(token).copied().unwrap_or_default())
                .sum::<usize>();
            (rank, tokens, consensus_score, aggregate_support)
        })
        .collect::<Vec<_>>();
    ranked_hints.sort_by(
        |(left_rank, _, left_consensus, left_aggregate),
         (right_rank, _, right_consensus, right_aggregate)| {
            right_consensus
                .cmp(left_consensus)
                .then_with(|| left_rank.cmp(right_rank))
                .then_with(|| right_aggregate.cmp(left_aggregate))
        },
    );

    let Some((_, selected_tokens, _, _)) = ranked_hints.first() else {
        return None;
    };
    let has_consensus_tokens = selected_tokens.iter().any(|token| {
        token_support.get(token).copied().unwrap_or_default() >= LOCALITY_INFERENCE_MIN_SUPPORT
    });
    let selection_support_floor = if has_consensus_tokens {
        LOCALITY_INFERENCE_MIN_SUPPORT
    } else {
        1
    };
    let token_order = selected_tokens
        .iter()
        .enumerate()
        .map(|(idx, token)| (token.clone(), idx))
        .collect::<BTreeMap<_, _>>();
    let mut ranked_tokens = selected_tokens
        .iter()
        .filter_map(|token| {
            let support = token_support.get(token).copied().unwrap_or_default();
            (support >= selection_support_floor).then(|| {
                (
                    token.clone(),
                    support,
                    *token_order.get(token).unwrap_or(&usize::MAX),
                )
            })
        })
        .collect::<Vec<_>>();
    if ranked_tokens.is_empty() {
        ranked_tokens = selected_tokens
            .iter()
            .map(|token| {
                (
                    token.clone(),
                    token_support.get(token).copied().unwrap_or_default(),
                    *token_order.get(token).unwrap_or(&usize::MAX),
                )
            })
            .collect::<Vec<_>>();
    }
    ranked_tokens.sort_by(
        |(left_token, left_support, left_order), (right_token, right_support, right_order)| {
            right_support
                .cmp(left_support)
                .then_with(|| left_order.cmp(right_order))
                .then_with(|| left_token.cmp(right_token))
        },
    );

    let scope_tokens = ranked_tokens
        .into_iter()
        .take(LOCALITY_INFERENCE_MAX_TOKENS)
        .map(|(token, _, _)| token)
        .collect::<Vec<_>>();
    if scope_tokens.is_empty() {
        return None;
    }
    let has_structural_locality_anchor = scope_tokens.iter().any(|token| {
        structural_token_support
            .get(token)
            .copied()
            .unwrap_or_default()
            >= selection_support_floor
    });
    if !has_structural_locality_anchor {
        return None;
    }
    sanitize_locality_scope(&scope_tokens.join(" "))
}

fn scope_anchor_start(query_lower: &str) -> Option<usize> {
    for marker in [" in ", " near ", " around ", " at "] {
        if let Some(idx) = query_lower.find(marker) {
            return Some(idx + marker.len());
        }
    }
    None
}

fn explicit_query_scope_hint(query: &str) -> Option<String> {
    let compact = compact_whitespace(query);
    if compact.is_empty() {
        return None;
    }
    let lower = compact.to_ascii_lowercase();
    let start = scope_anchor_start(&lower)?;
    let end = compact[start..]
        .char_indices()
        .find_map(|(idx, ch)| matches!(ch, '?' | '!' | '.').then_some(start + idx))
        .unwrap_or(compact.len());
    let raw_scope = compact[start..end]
        .trim_matches(|ch: char| matches!(ch, '.' | ',' | ';' | ':' | '?' | '!'))
        .trim()
        .to_string();
    if raw_scope.is_empty() {
        return None;
    }

    let structural_tokens = query_structural_directive_tokens(&compact);
    let mut scope_tokens = raw_scope.split_whitespace().collect::<Vec<_>>();
    while let Some(last) = scope_tokens.last() {
        let normalized = last
            .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
            .to_ascii_lowercase();
        if normalized.is_empty()
            || is_query_stopword(&normalized)
            || structural_tokens.contains(&normalized)
        {
            scope_tokens.pop();
            continue;
        }
        break;
    }
    if scope_tokens.is_empty() {
        return None;
    }
    sanitize_locality_scope(&scope_tokens.join(" "))
}

fn query_requires_locality_scope(query: &str, facets: &QueryFacetProfile) -> bool {
    facets.time_sensitive_public_fact
        && facets.locality_sensitive_public_fact
        && !facets.workspace_constrained
        && explicit_query_scope_hint(query).is_none()
}

pub(crate) fn query_requires_runtime_locality_scope(query: &str) -> bool {
    let compact = compact_whitespace(query);
    if compact.trim().is_empty() {
        return false;
    }
    let facets = analyze_query_facets(&compact);
    query_requires_locality_scope(&compact, &facets)
}

fn trusted_runtime_locality_scope_from_env() -> Option<String> {
    TRUSTED_LOCALITY_ENV_KEYS.iter().find_map(|key| {
        std::env::var(key)
            .ok()
            .and_then(|raw| sanitize_locality_scope(&raw))
    })
}

fn effective_locality_scope_hint(locality_hint: Option<&str>) -> Option<String> {
    locality_hint
        .and_then(sanitize_locality_scope)
        .or_else(trusted_runtime_locality_scope_from_env)
}

fn append_scope_to_query(query: &str, scope: &str) -> String {
    let trimmed = compact_whitespace(query);
    if trimmed.is_empty() {
        return trimmed;
    }
    let trimmed = trimmed.trim();
    let (base, suffix) = match trimmed
        .chars()
        .last()
        .filter(|ch| matches!(ch, '?' | '!' | '.'))
    {
        Some(punct) => (
            trimmed[..trimmed.len().saturating_sub(1)].trim(),
            punct.to_string(),
        ),
        None => (trimmed, String::new()),
    };
    if base.is_empty() {
        return trimmed.to_string();
    }
    format!("{base} in {scope}{suffix}")
}

fn resolved_query_contract_with_locality_hint(query: &str, locality_hint: Option<&str>) -> String {
    let base = compact_whitespace(query);
    if base.trim().is_empty() {
        return String::new();
    }
    if explicit_query_scope_hint(&base).is_some() {
        return base;
    }
    let facets = analyze_query_facets(&base);
    if !query_requires_locality_scope(&base, &facets) {
        return base;
    }
    let Some(scope) = effective_locality_scope_hint(locality_hint) else {
        return base;
    };
    compact_whitespace(&append_scope_to_query(&base, &scope))
}

fn resolved_query_contract(query: &str) -> String {
    resolved_query_contract_with_locality_hint(query, None)
}

fn semantic_retrieval_query_contract_with_locality_hint(
    query: &str,
    locality_hint: Option<&str>,
) -> String {
    let resolved = resolved_query_contract_with_locality_hint(query, locality_hint);
    if resolved.trim().is_empty() {
        return resolved;
    }

    let facets = analyze_query_facets(&resolved);
    if facets.goal.provenance_hits == 0
        && !facets.time_sensitive_public_fact
        && !facets.grounded_external_required
    {
        return resolved;
    }

    let semantic_tokens = query_semantic_anchor_tokens(&resolved)
        .into_iter()
        .filter(|token| token.len() >= QUERY_COMPATIBILITY_MIN_TOKEN_CHARS)
        .filter(|token| !is_query_stopword(token))
        .collect::<Vec<_>>();

    let scope = explicit_query_scope_hint(&resolved);
    if scope.is_none() && semantic_tokens.len() < 2 {
        if facets.time_sensitive_public_fact && facets.locality_sensitive_public_fact {
            if let Some(token) = semantic_tokens.first() {
                return format!("{token} current conditions temperature humidity wind");
            }
        }
        return resolved;
    }

    let Some(scope) = scope else {
        return semantic_tokens.join(" ");
    };
    let scope_tokens = normalized_locality_tokens(&scope);
    let mut semantic_non_scope = semantic_tokens
        .iter()
        .filter(|token| !scope_tokens.contains(*token))
        .cloned()
        .collect::<Vec<_>>();
    if semantic_non_scope.is_empty() {
        if let Some(first) = semantic_tokens.first() {
            semantic_non_scope.push(first.clone());
        } else {
            return resolved;
        }
    }
    format!("{} in {}", semantic_non_scope.join(" "), scope)
}

pub(crate) fn select_web_pipeline_query_contract(goal: &str, retrieval_query: &str) -> String {
    let goal_compact = compact_whitespace(goal);
    let retrieval_compact = compact_whitespace(retrieval_query);
    let goal_trimmed = goal_compact.trim();
    let retrieval_trimmed = retrieval_compact.trim();

    if goal_trimmed.is_empty() {
        return resolved_query_contract(retrieval_trimmed);
    }

    let mut contract = resolved_query_contract(goal_trimmed);
    if contract.trim().is_empty() {
        contract = goal_trimmed.to_string();
    }

    if retrieval_trimmed.is_empty() {
        return contract;
    }
    if explicit_query_scope_hint(&contract).is_some() {
        return contract;
    }

    if let Some(scope) = explicit_query_scope_hint(retrieval_trimmed).and_then(|value| {
        let goal_anchor_tokens = query_native_anchor_tokens(goal_trimmed);
        let mut seen = BTreeSet::new();
        let filtered_tokens = value
            .split_whitespace()
            .filter_map(|token| {
                let normalized = token
                    .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
                    .to_ascii_lowercase();
                if normalized.is_empty() || goal_anchor_tokens.contains(&normalized) {
                    return None;
                }
                if !seen.insert(normalized.clone()) {
                    return None;
                }
                Some(normalized)
            })
            .collect::<Vec<_>>();
        if filtered_tokens.is_empty() {
            None
        } else {
            sanitize_locality_scope(&filtered_tokens.join(" "))
        }
    }) {
        let merged = append_scope_to_query(&contract, &scope);
        return compact_whitespace(&merged);
    }

    contract
}

fn query_anchor_tokens(query_contract: &str, constraints: &ConstraintSet) -> BTreeSet<String> {
    let mut tokens = query_native_anchor_tokens(query_contract);
    for axis in &constraints.required_facets {
        for token in metric_axis_search_phrase(*axis).split_whitespace() {
            let normalized = token.trim().to_ascii_lowercase();
            if normalized.len() < QUERY_COMPATIBILITY_MIN_TOKEN_CHARS {
                continue;
            }
            if is_query_stopword(&normalized) {
                continue;
            }
            tokens.insert(normalized);
        }
    }
    tokens
}

fn query_native_anchor_tokens(query_contract: &str) -> BTreeSet<String> {
    let semantic_tokens = query_semantic_anchor_tokens(query_contract)
        .into_iter()
        .filter(|token| token.len() >= QUERY_COMPATIBILITY_MIN_TOKEN_CHARS)
        .filter(|token| !is_query_stopword(token))
        .collect::<BTreeSet<_>>();
    if semantic_tokens.is_empty() {
        normalized_anchor_tokens(query_contract)
    } else {
        semantic_tokens
    }
}

fn build_query_constraint_projection_with_locality_hint(
    query_contract: &str,
    min_sources: u32,
    candidate_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
) -> QueryConstraintProjection {
    let base_query_contract =
        resolved_query_contract_with_locality_hint(query_contract, locality_hint);
    let original_locality_scope = explicit_query_scope_hint(query_contract);
    let trusted_locality_scope = if original_locality_scope.is_none() {
        effective_locality_scope_hint(locality_hint)
    } else {
        None
    };
    let inferred_locality_scope =
        if original_locality_scope.is_none() && trusted_locality_scope.is_none() {
            inferred_locality_scope_from_candidate_hints(&base_query_contract, candidate_hints)
        } else {
            None
        };
    let projection_query_contract = inferred_locality_scope
        .as_deref()
        .map(|scope| append_scope_to_query(&base_query_contract, scope))
        .unwrap_or(base_query_contract);
    let constraints = single_snapshot_constraint_set_with_hints(
        &projection_query_contract,
        min_sources.max(1) as usize,
        candidate_hints,
    );
    let query_facets = analyze_query_facets(&projection_query_contract);
    let query_native_tokens = query_native_anchor_tokens(&projection_query_contract);
    let query_tokens = query_anchor_tokens(&projection_query_contract, &constraints);
    let locality_scope = explicit_query_scope_hint(&projection_query_contract);
    let locality_scope_inferred = original_locality_scope.is_none()
        && trusted_locality_scope.is_none()
        && inferred_locality_scope.is_some();
    let locality_tokens = locality_scope
        .as_deref()
        .map(normalized_locality_tokens)
        .unwrap_or_default();

    QueryConstraintProjection {
        constraints,
        query_facets,
        query_native_tokens,
        query_tokens,
        locality_scope,
        locality_scope_inferred,
        locality_tokens,
    }
}

fn build_query_constraint_projection(
    query_contract: &str,
    min_sources: u32,
    candidate_hints: &[PendingSearchReadSummary],
) -> QueryConstraintProjection {
    build_query_constraint_projection_with_locality_hint(
        query_contract,
        min_sources,
        candidate_hints,
        None,
    )
}

fn projection_constraint_search_terms(projection: &QueryConstraintProjection) -> Vec<String> {
    let mut terms = Vec::new();
    let has_explicit_metric_objective = !projection.constraints.required_facets.is_empty()
        || !projection.query_facets.metric_schema.axis_hits.is_empty();
    if projection
        .constraints
        .scopes
        .contains(&ConstraintScope::TimeSensitive)
        && has_explicit_metric_objective
    {
        terms.push("latest measured data".to_string());
        terms.push("as-of observation".to_string());
    }
    if !projection.constraints.required_facets.is_empty() {
        let axes = projection
            .constraints
            .required_facets
            .iter()
            .copied()
            .map(metric_axis_search_phrase)
            .collect::<Vec<_>>()
            .join(", ");
        if !axes.is_empty() {
            terms.push(format!("{} values", axes));
        }
    }
    if projection.constraints.output_contract.requires_absolute_utc
        && projection.query_facets.goal.provenance_hits > 0
    {
        terms.push("UTC timestamp".to_string());
    }
    if projection
        .constraints
        .provenance_policy
        .min_independent_sources
        > 1
        && has_explicit_metric_objective
    {
        terms.push(format!(
            "{} independent sources",
            projection
                .constraints
                .provenance_policy
                .min_independent_sources
        ));
    }
    terms
}

pub(crate) fn constraint_grounded_search_limit(query: &str, min_sources: u32) -> u32 {
    let projection = build_query_constraint_projection(query, min_sources, &[]);
    if !projection.has_constraint_objective() {
        return WEB_PIPELINE_SEARCH_LIMIT;
    }
    if !projection
        .constraints
        .scopes
        .contains(&ConstraintScope::TimeSensitive)
    {
        return WEB_PIPELINE_SEARCH_LIMIT;
    }

    let objective_floor = min_sources
        .max(1)
        .saturating_mul(WEB_PIPELINE_CONSTRAINT_SEARCH_LIMIT_MULTIPLIER);
    objective_floor.clamp(
        WEB_PIPELINE_CONSTRAINT_SEARCH_LIMIT_MIN,
        WEB_PIPELINE_CONSTRAINT_SEARCH_LIMIT_MAX,
    )
}

fn source_anchor_tokens(url: &str, title: &str, excerpt: &str) -> BTreeSet<String> {
    let mut tokens = normalized_anchor_tokens(title);
    tokens.extend(normalized_anchor_tokens(excerpt));

    if let Ok(parsed) = Url::parse(url.trim()) {
        if let Some(host) = parsed.host_str() {
            tokens.extend(
                host.split(|ch: char| !ch.is_ascii_alphanumeric())
                    .filter_map(|token| {
                        let normalized = token.trim().to_ascii_lowercase();
                        if normalized.len() < QUERY_COMPATIBILITY_MIN_TOKEN_CHARS {
                            return None;
                        }
                        if is_query_stopword(&normalized) {
                            return None;
                        }
                        Some(normalized)
                    }),
            );
        }

        tokens.extend(
            parsed
                .path()
                .split(|ch: char| !ch.is_ascii_alphanumeric())
                .filter_map(|token| {
                    let normalized = token.trim().to_ascii_lowercase();
                    if normalized.len() < QUERY_COMPATIBILITY_MIN_TOKEN_CHARS {
                        return None;
                    }
                    if is_query_stopword(&normalized) {
                        return None;
                    }
                    Some(normalized)
                }),
        );
        if let Some(query) = parsed.query() {
            tokens.extend(
                query
                    .split(|ch: char| !ch.is_ascii_alphanumeric())
                    .filter_map(|token| {
                        let normalized = token.trim().to_ascii_lowercase();
                        if normalized.len() < QUERY_COMPATIBILITY_MIN_TOKEN_CHARS {
                            return None;
                        }
                        if is_query_stopword(&normalized) {
                            return None;
                        }
                        Some(normalized)
                    }),
            );
        }
    }

    tokens
}

fn is_search_hub_url(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url.trim()) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    let path = parsed.path().to_ascii_lowercase();
    let has_query = parsed
        .query_pairs()
        .any(|(key, _)| key == "q" || key == "query" || key == "text");

    let is_ddg_hub = host.contains("duckduckgo.")
        && (path == "/" || path.starts_with("/html") || path.starts_with("/lite"));
    let is_bing_hub = host.ends_with("bing.com") && (path == "/" || path.starts_with("/search"));
    let is_google_hub = host.contains("google.")
        && (path == "/"
            || path.starts_with("/search")
            || path == "/url"
            || path.starts_with("/rss/search"));
    let is_generic_query_search_hub = path.contains("/search")
        || path.ends_with("/search")
        || path.starts_with("/find")
        || path.contains("/results");

    (is_ddg_hub || is_bing_hub || is_google_hub || is_generic_query_search_hub) && has_query
}

fn candidate_time_sensitive_resolvable_payload(title: &str, excerpt: &str) -> bool {
    fn observation_surface_signal(schema: &MetricSchemaProfile) -> bool {
        let observation_strength = schema
            .observation_hits
            .saturating_add(schema.timestamp_hits);
        if observation_strength == 0 {
            return false;
        }
        let horizon_pressure = schema.horizon_hits.saturating_add(schema.range_hits);
        if observation_strength <= horizon_pressure {
            return false;
        }
        schema.axis_hits.len() >= TIME_SENSITIVE_RESOLVABLE_SURFACE_MIN_AXIS
    }

    let source_schema = analyze_metric_schema(&format!("{} {}", title, excerpt));
    if source_schema.has_current_observation_payload()
        || (source_schema.numeric_token_hits > 0 && source_schema.unit_hits > 0)
    {
        return true;
    }

    let excerpt_schema = analyze_metric_schema(excerpt);
    if observation_surface_signal(&excerpt_schema) {
        return true;
    }

    excerpt.trim().is_empty() && observation_surface_signal(&analyze_metric_schema(title))
}

fn compatibility_passes_projection(
    projection: &QueryConstraintProjection,
    compatibility: &CandidateConstraintCompatibility,
) -> bool {
    if !compatibility.is_compatible {
        return false;
    }
    if projection
        .constraints
        .scopes
        .contains(&ConstraintScope::TimeSensitive)
        && projection.locality_scope.is_some()
        && !compatibility.locality_compatible
    {
        return false;
    }
    true
}

fn candidate_constraint_compatibility(
    constraints: &ConstraintSet,
    query_facets: &QueryFacetProfile,
    query_native_tokens: &BTreeSet<String>,
    query_tokens: &BTreeSet<String>,
    query_locality_tokens: &BTreeSet<String>,
    has_query_locality_scope: bool,
    url: &str,
    title: &str,
    excerpt: &str,
) -> CandidateConstraintCompatibility {
    let source_tokens = source_anchor_tokens(url, title, excerpt);
    let source_locality = source_locality_tokens(url, title, excerpt);
    let anchor_overlap_count = query_tokens.intersection(&source_tokens).count();
    let native_anchor_overlap_count = query_native_tokens.intersection(&source_tokens).count();
    let locality_overlap_count = query_locality_tokens.intersection(&source_locality).count();
    let query_anchor_count = query_tokens.len();

    let source_schema = analyze_metric_schema(&format!("{} {}", title, excerpt));
    let axis_overlap_count = source_schema.axis_overlap_score(&constraints.required_facets);
    let has_current_observation_payload = source_schema.has_current_observation_payload();
    let has_time_sensitive_resolvable_payload =
        candidate_time_sensitive_resolvable_payload(title, excerpt);
    let semantic_anchor_overlap_count = query_native_tokens
        .iter()
        .filter(|token| !query_locality_tokens.contains(*token))
        .filter(|token| source_tokens.contains(*token))
        .count();
    let semantic_anchor_token_count = query_native_tokens
        .iter()
        .filter(|token| !query_locality_tokens.contains(*token))
        .count();
    let has_semantic_anchor_overlap =
        semantic_anchor_overlap_count >= QUERY_COMPATIBILITY_MIN_ANCHOR_OVERLAP;
    let search_hub = is_search_hub_url(url);
    let reject_search_hub = constraints.scopes.contains(&ConstraintScope::TimeSensitive)
        || query_facets.grounded_external_required;
    let has_facet_constraints = !constraints.required_facets.is_empty();
    let typed_match = if has_facet_constraints {
        // Typed-facet matching for time-sensitive requests requires a resolvable
        // current-observation surface, not just lexical facet overlap.
        if constraints.scopes.contains(&ConstraintScope::TimeSensitive) {
            axis_overlap_count > 0 && has_time_sensitive_resolvable_payload
        } else {
            axis_overlap_count > 0
        }
    } else if constraints.scopes.contains(&ConstraintScope::TimeSensitive) {
        let anchor_match = has_current_observation_payload
            || native_anchor_overlap_count >= QUERY_COMPATIBILITY_MIN_ANCHOR_OVERLAP;
        if has_query_locality_scope && !query_locality_tokens.is_empty() {
            anchor_match && (has_time_sensitive_resolvable_payload || has_semantic_anchor_overlap)
        } else {
            anchor_match
        }
    } else {
        axis_overlap_count > 0 || has_current_observation_payload
    };
    let has_anchor_overlap = anchor_overlap_count >= QUERY_COMPATIBILITY_MIN_ANCHOR_OVERLAP;
    let has_locality_overlap = locality_overlap_count >= QUERY_COMPATIBILITY_MIN_LOCALITY_OVERLAP;
    let locality_scope_active = has_query_locality_scope
        && !query_locality_tokens.is_empty()
        && constraints.scopes.contains(&ConstraintScope::TimeSensitive);
    let requires_semantic_anchor_overlap = locality_scope_active && semantic_anchor_token_count > 0;
    let min_native_overlap_required = if query_facets.grounded_external_required
        && query_native_tokens.len() >= QUERY_COMPATIBILITY_MIN_GROUNDED_MULTI_ANCHOR_OVERLAP
    {
        if constraints.scopes.contains(&ConstraintScope::TimeSensitive) {
            QUERY_COMPATIBILITY_MIN_ANCHOR_OVERLAP
        } else {
            QUERY_COMPATIBILITY_MIN_GROUNDED_MULTI_ANCHOR_OVERLAP
        }
    } else if !query_native_tokens.is_empty() {
        QUERY_COMPATIBILITY_MIN_ANCHOR_OVERLAP
    } else {
        0
    };
    let has_native_anchor_overlap = native_anchor_overlap_count >= min_native_overlap_required;
    let strong_anchor_coverage = query_anchor_count > 0
        && anchor_overlap_count * QUERY_COMPATIBILITY_STRONG_COVERAGE_DENOMINATOR
            >= query_anchor_count * QUERY_COMPATIBILITY_STRONG_COVERAGE_NUMERATOR;

    let mut is_compatible = if constraints.scopes.contains(&ConstraintScope::TimeSensitive) {
        let anchor_requirement =
            if query_facets.grounded_external_required && query_anchor_count > 0 {
                has_native_anchor_overlap
            } else if query_anchor_count > 0 {
                has_anchor_overlap || has_native_anchor_overlap
            } else {
                true
            };
        typed_match
            && anchor_requirement
            && (!requires_semantic_anchor_overlap || has_semantic_anchor_overlap)
    } else if query_facets.grounded_external_required && query_anchor_count > 0 {
        has_native_anchor_overlap && (has_anchor_overlap || typed_match)
    } else if query_anchor_count > 0 {
        has_anchor_overlap || typed_match
    } else {
        typed_match || source_tokens.len() >= QUERY_COMPATIBILITY_MIN_ANCHOR_OVERLAP
    };
    if reject_search_hub && search_hub {
        // Search-hub URLs are intermediary navigation surfaces, not evidence pages.
        is_compatible = false;
    }
    let mut compatibility_score = anchor_overlap_count * QUERY_COMPATIBILITY_ANCHOR_WEIGHT;
    compatibility_score = compatibility_score
        .saturating_add(native_anchor_overlap_count * QUERY_COMPATIBILITY_NATIVE_ANCHOR_WEIGHT);
    if strong_anchor_coverage {
        compatibility_score =
            compatibility_score.saturating_add(QUERY_COMPATIBILITY_STRONG_COVERAGE_BONUS);
    }
    compatibility_score = compatibility_score
        .saturating_add(axis_overlap_count * QUERY_COMPATIBILITY_AXIS_OVERLAP_WEIGHT);
    if has_current_observation_payload {
        compatibility_score =
            compatibility_score.saturating_add(QUERY_COMPATIBILITY_CURRENT_OBSERVATION_BONUS);
    }
    if query_facets.grounded_external_required && is_compatible {
        compatibility_score =
            compatibility_score.saturating_add(QUERY_COMPATIBILITY_GROUNDED_EXTERNAL_BONUS);
    }
    if search_hub {
        compatibility_score =
            compatibility_score.saturating_sub(QUERY_COMPATIBILITY_SEARCH_HUB_PENALTY);
    }
    if constraints.scopes.contains(&ConstraintScope::TimeSensitive)
        && !has_time_sensitive_resolvable_payload
    {
        compatibility_score =
            compatibility_score.saturating_sub(QUERY_COMPATIBILITY_NO_RESOLVABLE_PAYLOAD_PENALTY);
    }
    if locality_scope_active && has_locality_overlap {
        compatibility_score = compatibility_score
            .saturating_add(locality_overlap_count * QUERY_COMPATIBILITY_LOCALITY_OVERLAP_WEIGHT);
    }
    let locality_compatible = !locality_scope_active || has_locality_overlap;

    CandidateConstraintCompatibility {
        compatibility_score,
        is_compatible,
        locality_compatible,
    }
}

fn probe_hint_anchor_tokens(title: &str, excerpt: &str) -> BTreeSet<String> {
    let mut out = normalized_anchor_tokens(title);
    out.extend(normalized_anchor_tokens(excerpt));
    out
}

fn projection_probe_hint_anchor_phrase(
    projection: &QueryConstraintProjection,
    candidate_hints: &[PendingSearchReadSummary],
) -> Option<String> {
    if candidate_hints.is_empty() {
        return None;
    }

    let policy = ResolutionPolicy::default();
    let mut ranked = candidate_hints
        .iter()
        .enumerate()
        .map(|(idx, hint)| {
            let title = hint.title.as_deref().unwrap_or_default();
            let compatibility = candidate_constraint_compatibility(
                &projection.constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                &hint.url,
                title,
                &hint.excerpt,
            );
            let envelope = single_snapshot_candidate_envelope_score(
                &projection.constraints,
                policy,
                &hint.url,
                title,
                &hint.excerpt,
            );
            (idx, hint, compatibility, envelope)
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        right
            .2
            .is_compatible
            .cmp(&left.2.is_compatible)
            .then_with(|| right.2.compatibility_score.cmp(&left.2.compatibility_score))
            .then_with(|| compare_candidate_evidence_scores_desc(&left.3, &right.3))
            .then_with(|| left.0.cmp(&right.0))
            .then_with(|| left.1.url.cmp(&right.1.url))
    });

    let mut token_hits = BTreeMap::<String, usize>::new();
    let enforce_grounded = projection.enforce_grounded_compatibility();
    let time_sensitive_scope = projection
        .constraints
        .scopes
        .contains(&ConstraintScope::TimeSensitive);
    for (_, hint, compatibility, _) in ranked.iter().take(QUERY_PROBE_HINT_MAX_CANDIDATES) {
        if enforce_grounded && !compatibility_passes_projection(projection, compatibility) {
            continue;
        }
        let title = hint.title.as_deref().unwrap_or_default();
        if time_sensitive_scope
            && !candidate_time_sensitive_resolvable_payload(title, &hint.excerpt)
        {
            continue;
        }
        let tokens = probe_hint_anchor_tokens(title, &hint.excerpt);
        for token in tokens {
            if projection.query_tokens.contains(&token)
                || projection.query_native_tokens.contains(&token)
            {
                continue;
            }
            *token_hits.entry(token).or_insert(0) += 1;
        }
    }

    if token_hits.is_empty() {
        return None;
    }

    let mut ranked_tokens = token_hits.into_iter().collect::<Vec<_>>();
    ranked_tokens.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));

    let mut anchor_tokens = ranked_tokens
        .iter()
        .filter_map(|(token, hits)| {
            (*hits >= QUERY_PROBE_HINT_MIN_SHARED_TOKEN_HITS).then(|| token.clone())
        })
        .take(QUERY_PROBE_HINT_MAX_TOKENS)
        .collect::<Vec<_>>();
    if anchor_tokens.len() < 2 {
        anchor_tokens = ranked_tokens
            .into_iter()
            .map(|(token, _)| token)
            .take(QUERY_PROBE_HINT_MAX_TOKENS)
            .collect();
    }

    (anchor_tokens.len() >= 2).then(|| format!("\"{}\"", anchor_tokens.join(" ")))
}

fn projection_native_anchor_phrase(projection: &QueryConstraintProjection) -> Option<String> {
    if projection.locality_scope.is_some()
        && projection
            .constraints
            .scopes
            .contains(&ConstraintScope::TimeSensitive)
    {
        // Explicit locality already grounds scope for time-sensitive lookups.
        // Adding a quoted native-anchor phrase can over-constrain SERP recall.
        return None;
    }
    let anchor_phrase_tokens = projection
        .query_native_tokens
        .iter()
        .take(4)
        .cloned()
        .collect::<Vec<_>>();
    (anchor_phrase_tokens.len() >= 2).then(|| format!("\"{}\"", anchor_phrase_tokens.join(" ")))
}

fn projection_locality_semantic_anchor_phrase(
    projection: &QueryConstraintProjection,
) -> Option<String> {
    if projection.locality_tokens.is_empty() {
        return None;
    }
    let mut tokens = projection
        .locality_tokens
        .iter()
        .take(3)
        .cloned()
        .collect::<Vec<_>>();
    tokens.extend(
        projection
            .query_native_tokens
            .iter()
            .filter(|token| !projection.locality_tokens.contains(*token))
            .take(2)
            .cloned(),
    );
    tokens.dedup();
    (tokens.len() >= 2).then(|| format!("\"{}\"", tokens.join(" ")))
}

fn projection_probe_conflict_exclusion_terms(
    projection: &QueryConstraintProjection,
    candidate_hints: &[PendingSearchReadSummary],
) -> Vec<String> {
    if candidate_hints.is_empty() || !projection.enforce_grounded_compatibility() {
        return Vec::new();
    }

    let mut token_hits = BTreeMap::<String, usize>::new();
    for hint in candidate_hints {
        let compatibility = candidate_constraint_compatibility(
            &projection.constraints,
            &projection.query_facets,
            &projection.query_native_tokens,
            &projection.query_tokens,
            &projection.locality_tokens,
            projection.locality_scope.is_some(),
            &hint.url,
            hint.title.as_deref().unwrap_or_default(),
            &hint.excerpt,
        );
        if compatibility_passes_projection(projection, &compatibility) {
            continue;
        }

        let source_tokens = source_anchor_tokens(
            &hint.url,
            hint.title.as_deref().unwrap_or_default(),
            &hint.excerpt,
        );
        for token in source_tokens {
            if token.len() < QUERY_COMPATIBILITY_MIN_TOKEN_CHARS || is_query_stopword(&token) {
                continue;
            }
            if projection.query_tokens.contains(&token)
                || projection.query_native_tokens.contains(&token)
                || projection.locality_tokens.contains(&token)
            {
                continue;
            }
            *token_hits.entry(token).or_insert(0) += 1;
        }
    }

    let mut ranked_tokens = token_hits.into_iter().collect::<Vec<_>>();
    ranked_tokens.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    ranked_tokens
        .into_iter()
        .filter(|(_, hits)| *hits >= QUERY_PROBE_ESCALATION_MIN_CONFLICT_HITS)
        .take(QUERY_PROBE_ESCALATION_MAX_CONFLICT_TERMS)
        .map(|(token, _)| format!("-{}", token))
        .collect()
}

fn projection_probe_host_exclusion_terms(
    projection: &QueryConstraintProjection,
    candidate_hints: &[PendingSearchReadSummary],
) -> Vec<String> {
    if candidate_hints.is_empty() {
        return Vec::new();
    }
    if !projection
        .constraints
        .scopes
        .contains(&ConstraintScope::TimeSensitive)
    {
        return Vec::new();
    }

    let mut host_hits = BTreeMap::<String, usize>::new();
    for hint in candidate_hints {
        let title = hint.title.as_deref().unwrap_or_default();
        let observed = format!("{} {}", title, hint.excerpt);
        if contains_current_condition_metric_signal(&observed) {
            continue;
        }
        let Some(host) = source_host(&hint.url) else {
            continue;
        };
        if host.trim().is_empty() {
            continue;
        }
        *host_hits.entry(host).or_insert(0) += 1;
    }

    let mut ranked_hosts = host_hits.into_iter().collect::<Vec<_>>();
    ranked_hosts.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    ranked_hosts
        .into_iter()
        .take(QUERY_PROBE_ESCALATION_MAX_HOST_EXCLUSION_TERMS)
        .map(|(host, _)| format!("-site:{host}"))
        .collect()
}

fn projection_probe_structural_terms(projection: &QueryConstraintProjection) -> Vec<String> {
    let mut terms = Vec::new();
    if let Some(scope) = projection.locality_scope.as_ref() {
        terms.push(format!("\"{}\"", scope));
    }
    let facet_terms = projection
        .constraints
        .required_facets
        .iter()
        .copied()
        .map(metric_axis_search_phrase)
        .collect::<Vec<_>>();
    if !facet_terms.is_empty() {
        terms.push(format!("\"{} observed\"", facet_terms.join(" ")));
    }
    if projection
        .constraints
        .scopes
        .contains(&ConstraintScope::TimeSensitive)
    {
        terms.push("\"observed now\"".to_string());
    }
    terms
}

fn append_unique_query_terms(base_query: &str, terms: &[String]) -> String {
    let mut appended = base_query.trim().to_string();
    let lower = base_query.to_ascii_lowercase();
    for term in terms {
        let trimmed = term.trim();
        if trimmed.is_empty() {
            continue;
        }
        if lower.contains(&trimmed.to_ascii_lowercase()) {
            continue;
        }
        if !appended.is_empty() {
            appended.push(' ');
        }
        appended.push_str(trimmed);
    }
    appended
}

pub(crate) fn constraint_grounded_search_query_with_hints_and_locality_hint(
    query: &str,
    min_sources: u32,
    candidate_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
) -> String {
    let base = semantic_retrieval_query_contract_with_locality_hint(query, locality_hint);
    if base.trim().is_empty() {
        return String::new();
    }
    let projection = build_query_constraint_projection_with_locality_hint(
        query,
        min_sources,
        candidate_hints,
        locality_hint,
    );
    let mut constraint_terms = projection_constraint_search_terms(&projection);
    let bootstrap_without_hints = candidate_hints.is_empty();
    let bootstrap_time_sensitive_locality_scope = bootstrap_without_hints
        && projection
            .constraints
            .scopes
            .contains(&ConstraintScope::TimeSensitive)
        && projection.locality_scope.is_some();
    if bootstrap_time_sensitive_locality_scope {
        return base;
    }
    let native_anchor_phrase = projection_native_anchor_phrase(&projection);
    if projection.strict_grounded_compatibility() {
        if let Some(anchor_phrase) = native_anchor_phrase.as_ref() {
            constraint_terms.push(anchor_phrase.clone());
        }
    }
    if let Some(anchor_phrase) = projection_probe_hint_anchor_phrase(&projection, candidate_hints) {
        if !constraint_terms.iter().any(|term| term == &anchor_phrase) {
            constraint_terms.push(anchor_phrase);
        }
    }
    let inferred_locality_grounding = projection.locality_scope_inferred
        && projection
            .constraints
            .scopes
            .contains(&ConstraintScope::TimeSensitive);
    if inferred_locality_grounding && !bootstrap_without_hints {
        for term in ["latest measured data", "as-of observation"] {
            if !constraint_terms.iter().any(|existing| existing == term) {
                constraint_terms.push(term.to_string());
            }
        }
        if let Some(scope) = projection.locality_scope.as_ref() {
            let scoped_phrase = format!("\"{}\"", scope);
            if !constraint_terms.iter().any(|term| term == &scoped_phrase) {
                constraint_terms.insert(0, scoped_phrase);
            }
        }
        if let Some(anchor_phrase) = projection_locality_semantic_anchor_phrase(&projection) {
            if !constraint_terms.iter().any(|term| term == &anchor_phrase) {
                constraint_terms.insert(0, anchor_phrase);
            }
        } else if let Some(anchor_phrase) = native_anchor_phrase {
            if !constraint_terms.iter().any(|term| term == &anchor_phrase) {
                constraint_terms.insert(0, anchor_phrase);
            }
        }
    }
    if constraint_terms.is_empty() {
        return base;
    }
    if inferred_locality_grounding && !bootstrap_without_hints {
        return append_unique_query_terms(&constraint_terms.join(" "), &[base]);
    }
    append_unique_query_terms(&base, &constraint_terms)
}

pub(crate) fn constraint_grounded_probe_query_with_hints_and_locality_hint(
    query: &str,
    min_sources: u32,
    candidate_hints: &[PendingSearchReadSummary],
    prior_query: &str,
    locality_hint: Option<&str>,
) -> Option<String> {
    let grounded_query = constraint_grounded_search_query_with_hints_and_locality_hint(
        query,
        min_sources,
        candidate_hints,
        locality_hint,
    );
    if grounded_query.trim().is_empty() {
        return None;
    }

    let prior_trimmed = prior_query.trim();
    if prior_trimmed.is_empty() || !grounded_query.eq_ignore_ascii_case(prior_trimmed) {
        return Some(grounded_query);
    }

    let projection = build_query_constraint_projection_with_locality_hint(
        query,
        min_sources,
        candidate_hints,
        locality_hint,
    );
    let mut escalation_terms =
        projection_probe_conflict_exclusion_terms(&projection, candidate_hints);
    let host_exclusion_terms = projection_probe_host_exclusion_terms(&projection, candidate_hints);
    for term in host_exclusion_terms {
        if escalation_terms.iter().any(|existing| existing == &term) {
            continue;
        }
        escalation_terms.push(term);
    }
    if escalation_terms.is_empty() {
        escalation_terms = projection_probe_structural_terms(&projection);
    }
    let requires_locality_metric_escalation = projection
        .constraints
        .scopes
        .contains(&ConstraintScope::TimeSensitive)
        && projection.query_facets.locality_sensitive_public_fact;
    let metric_probe_terms = [
        QUERY_PROBE_LOCALITY_METRIC_ESCALATION_PHRASE.to_string(),
        metric_axis_search_phrase(MetricAxis::Temperature).to_string(),
        metric_axis_search_phrase(MetricAxis::Humidity).to_string(),
        metric_axis_search_phrase(MetricAxis::Wind).to_string(),
    ];
    let escalated_query = append_unique_query_terms(&grounded_query, &escalation_terms);
    if !escalated_query.trim().is_empty() && !escalated_query.eq_ignore_ascii_case(prior_trimmed) {
        let locality_escalated_query = if requires_locality_metric_escalation {
            append_unique_query_terms(&escalated_query, &metric_probe_terms)
        } else {
            escalated_query.clone()
        };
        if locality_escalated_query.trim().is_empty()
            || locality_escalated_query.eq_ignore_ascii_case(prior_trimmed)
        {
            Some(escalated_query)
        } else {
            Some(locality_escalated_query)
        }
    } else if requires_locality_metric_escalation {
        let fallback_query = append_unique_query_terms(&grounded_query, &metric_probe_terms);
        if fallback_query.trim().is_empty() || fallback_query.eq_ignore_ascii_case(prior_trimmed) {
            None
        } else {
            Some(fallback_query)
        }
    } else {
        None
    }
}

pub(crate) fn constraint_grounded_probe_query_with_hints(
    query: &str,
    min_sources: u32,
    candidate_hints: &[PendingSearchReadSummary],
    prior_query: &str,
) -> Option<String> {
    constraint_grounded_probe_query_with_hints_and_locality_hint(
        query,
        min_sources,
        candidate_hints,
        prior_query,
        None,
    )
}

pub(crate) fn constraint_grounded_search_query_with_hints(
    query: &str,
    min_sources: u32,
    candidate_hints: &[PendingSearchReadSummary],
) -> String {
    constraint_grounded_search_query_with_hints_and_locality_hint(
        query,
        min_sources,
        candidate_hints,
        None,
    )
}

pub(crate) fn constraint_grounded_search_query(query: &str, min_sources: u32) -> String {
    constraint_grounded_search_query_with_hints(query, min_sources, &[])
}

fn pre_read_candidate_plan(
    query_contract: &str,
    min_sources: u32,
    candidate_urls: Vec<String>,
    candidate_source_hints: Vec<PendingSearchReadSummary>,
    locality_hint: Option<&str>,
    allow_floor_recovery_exploration: bool,
) -> PreReadCandidatePlan {
    let total_candidates = candidate_urls.len();
    if total_candidates == 0 {
        return PreReadCandidatePlan {
            candidate_urls,
            probe_source_hints: candidate_source_hints.clone(),
            candidate_source_hints,
            total_candidates: 0,
            pruned_candidates: 0,
            resolvable_candidates: 0,
            scoreable_candidates: 0,
            requires_constraint_search_probe: false,
        };
    }

    let projection = build_query_constraint_projection_with_locality_hint(
        query_contract,
        min_sources,
        &candidate_source_hints,
        locality_hint,
    );
    let probe_source_hints = candidate_source_hints.clone();
    let constraints = &projection.constraints;
    let policy = ResolutionPolicy::default();
    let hints_by_url = candidate_source_hints
        .iter()
        .filter_map(|hint| {
            let trimmed = hint.url.trim();
            (!trimmed.is_empty()).then(|| (trimmed.to_string(), hint.clone()))
        })
        .collect::<BTreeMap<_, _>>();

    let mut ranked = candidate_urls
        .iter()
        .enumerate()
        .map(|(idx, url)| {
            let trimmed = url.trim();
            let hint = hints_by_url.get(trimmed);
            let title = hint
                .and_then(|entry| entry.title.as_deref())
                .unwrap_or_default();
            let excerpt = hint.map(|entry| entry.excerpt.as_str()).unwrap_or_default();
            let score = single_snapshot_candidate_envelope_score(
                constraints,
                policy,
                trimmed,
                title,
                excerpt,
            );
            let scoreable = !title.trim().is_empty() || !excerpt.trim().is_empty();
            let compatibility = candidate_constraint_compatibility(
                constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                trimmed,
                title,
                excerpt,
            );
            let resolvable_payload = candidate_time_sensitive_resolvable_payload(title, excerpt);
            (
                idx,
                trimmed.to_string(),
                score,
                scoreable,
                compatibility,
                resolvable_payload,
            )
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        let right_passes = compatibility_passes_projection(&projection, &right.4);
        let left_passes = compatibility_passes_projection(&projection, &left.4);
        right
            .5
            .cmp(&left.5)
            .then_with(|| right_passes.cmp(&left_passes))
            .then_with(|| right.4.compatibility_score.cmp(&left.4.compatibility_score))
            .then_with(|| compare_candidate_evidence_scores_desc(&left.2, &right.2))
            .then_with(|| right.4.is_compatible.cmp(&left.4.is_compatible))
            .then_with(|| right.3.cmp(&left.3))
            .then_with(|| left.0.cmp(&right.0))
            .then_with(|| left.1.cmp(&right.1))
    });

    let min_required = min_sources.max(1) as usize;
    let resolvable_candidates = ranked
        .iter()
        .filter(|(_, _, score, _, _, _)| envelope_score_resolves_constraint(constraints, score))
        .count();
    let scoreable_candidates = ranked
        .iter()
        .filter(|(_, _, _, scoreable, _, _)| *scoreable)
        .count();
    let compatible_candidates = ranked
        .iter()
        .filter(|(_, _, _, _, compatibility, _)| {
            compatibility_passes_projection(&projection, compatibility)
        })
        .count();
    let positive_compatibility_candidates = ranked
        .iter()
        .filter(|(_, _, _, _, compatibility, _)| {
            compatibility_passes_projection(&projection, compatibility)
                && compatibility.compatibility_score > 0
        })
        .count();
    let locality_compatible_candidates = ranked
        .iter()
        .filter(|(_, _, _, _, compatibility, _)| compatibility.locality_compatible)
        .count();
    let can_prune = resolvable_candidates >= min_required;
    let enforce_grounded_compatibility = projection.enforce_grounded_compatibility();
    let strict_grounded_compatibility = projection.strict_grounded_compatibility();
    let can_prune_by_compatibility = if strict_grounded_compatibility {
        !(allow_floor_recovery_exploration
            && compatible_candidates > 0
            && compatible_candidates < min_required)
    } else {
        enforce_grounded_compatibility
            && (compatible_candidates >= min_required
                || positive_compatibility_candidates >= min_required)
    };
    let can_prune_by_locality = projection.locality_scope.is_some()
        && constraints.scopes.contains(&ConstraintScope::TimeSensitive)
        && (locality_compatible_candidates >= min_required
            || (allow_floor_recovery_exploration && locality_compatible_candidates > 0));
    let can_prune_by_positive_compatibility =
        constraints.scopes.contains(&ConstraintScope::TimeSensitive)
            && positive_compatibility_candidates >= min_required;
    let has_constraint_objective = projection.has_constraint_objective();
    let time_sensitive_scope = constraints.scopes.contains(&ConstraintScope::TimeSensitive);
    let reject_search_hub = projection.reject_search_hub_candidates();
    let mut requires_constraint_search_probe =
        if !has_constraint_objective || scoreable_candidates == 0 {
            false
        } else {
            let compatibility_gap = compatible_candidates < min_required;
            let resolvability_gap = resolvable_candidates < min_required;
            if strict_grounded_compatibility {
                compatibility_gap || resolvability_gap
            } else {
                constraints.scopes.contains(&ConstraintScope::TimeSensitive)
                    && (compatibility_gap || resolvability_gap)
            }
        };

    let mut candidate_urls = ranked
        .iter()
        .filter_map(|(_, url, score, _, compatibility, _)| {
            if reject_search_hub && is_search_hub_url(url) {
                return None;
            }
            if can_prune && !envelope_score_resolves_constraint(constraints, score) {
                return None;
            }
            if can_prune_by_compatibility
                && !compatibility_passes_projection(&projection, compatibility)
            {
                return None;
            }
            if can_prune_by_locality && !compatibility.locality_compatible {
                return None;
            }
            if can_prune_by_positive_compatibility && compatibility.compatibility_score == 0 {
                return None;
            }
            Some(url.to_string())
        })
        .collect::<Vec<_>>();
    if candidate_urls.is_empty() && projection.locality_scope_inferred {
        let fallback_limit = min_required
            .min(INFERRED_SCOPE_FALLBACK_CANDIDATE_COUNT)
            .max(1);
        let positive_fallback = ranked
            .iter()
            .filter(|(_, _, _, _, compatibility, _)| {
                compatibility_passes_projection(&projection, compatibility)
                    && compatibility.compatibility_score > 0
            })
            .take(fallback_limit)
            .map(|(_, url, _, _, _, _)| url.to_string())
            .collect::<Vec<_>>();
        candidate_urls = positive_fallback;
    }
    if candidate_urls.len() < min_required && has_constraint_objective && scoreable_candidates > 0 {
        let candidate_count_before_top_up = candidate_urls.len();
        let mut seen_candidate_urls = candidate_urls
            .iter()
            .map(|url| url.trim().to_string())
            .collect::<BTreeSet<_>>();
        for (_, url, _, _, compatibility, resolvable_payload) in ranked.iter() {
            if candidate_urls.len() >= min_required {
                break;
            }
            if seen_candidate_urls.contains(url) || is_search_hub_url(url) {
                continue;
            }
            if !compatibility.locality_compatible {
                continue;
            }
            let compatibility_relevant = compatibility.compatibility_score > 0
                || compatibility_passes_projection(&projection, compatibility)
                || (allow_floor_recovery_exploration && compatible_candidates == 0);
            if !compatibility_relevant {
                continue;
            }
            let payload_relevant = !time_sensitive_scope
                || *resolvable_payload
                || candidate_urls.len() < min_required
                || (allow_floor_recovery_exploration && compatible_candidates == 0);
            if !payload_relevant {
                continue;
            }
            if seen_candidate_urls.insert(url.to_string()) {
                candidate_urls.push(url.to_string());
            }
        }
        if candidate_urls.len() > candidate_count_before_top_up {
            requires_constraint_search_probe = true;
        }
    }
    if candidate_urls.is_empty()
        && has_constraint_objective
        && constraints.scopes.contains(&ConstraintScope::TimeSensitive)
    {
        requires_constraint_search_probe = true;
    }
    let kept_urls = candidate_urls.iter().cloned().collect::<BTreeSet<_>>();
    let mut candidate_source_hints = Vec::new();
    let mut seen_hint_urls = BTreeSet::new();
    for url in &candidate_urls {
        if let Some(hint) = hints_by_url.get(url) {
            let trimmed = hint.url.trim();
            if !trimmed.is_empty() && seen_hint_urls.insert(trimmed.to_string()) {
                candidate_source_hints.push(hint.clone());
            }
        }
    }
    // Preserve additional ranked, non-hub compatible hints for citation quality and
    // bounded floor-recovery reads when selected URL inventory is sparse.
    for (_, url, _, _, compatibility, resolvable_payload) in &ranked {
        if seen_hint_urls.contains(url) {
            continue;
        }
        if reject_search_hub && is_search_hub_url(url) {
            continue;
        }
        if can_prune_by_locality && !compatibility.locality_compatible {
            continue;
        }
        let include_hint = compatibility_passes_projection(&projection, compatibility)
            || compatibility.compatibility_score > 0
            || *resolvable_payload;
        if !include_hint {
            continue;
        }
        if let Some(hint) = hints_by_url.get(url) {
            let trimmed = hint.url.trim();
            if !trimmed.is_empty() && seen_hint_urls.insert(trimmed.to_string()) {
                candidate_source_hints.push(hint.clone());
            }
        }
    }

    PreReadCandidatePlan {
        candidate_urls,
        candidate_source_hints,
        probe_source_hints,
        total_candidates,
        pruned_candidates: total_candidates.saturating_sub(kept_urls.len()),
        resolvable_candidates,
        scoreable_candidates,
        requires_constraint_search_probe,
    }
}

pub(crate) fn pre_read_candidate_plan_from_bundle_with_locality_hint(
    query_contract: &str,
    min_sources: u32,
    bundle: &WebEvidenceBundle,
    locality_hint: Option<&str>,
) -> PreReadCandidatePlan {
    pre_read_candidate_plan_from_bundle_with_locality_hint_and_recovery_mode(
        query_contract,
        min_sources,
        bundle,
        locality_hint,
        false,
    )
}

pub(crate) fn pre_read_candidate_plan_from_bundle_with_locality_hint_and_recovery_mode(
    query_contract: &str,
    min_sources: u32,
    bundle: &WebEvidenceBundle,
    locality_hint: Option<&str>,
    allow_floor_recovery_exploration: bool,
) -> PreReadCandidatePlan {
    let (candidate_urls, candidate_source_hints) =
        constrained_candidate_inventory_from_bundle_with_locality_hint(
            query_contract,
            min_sources,
            bundle,
            locality_hint,
        );
    pre_read_candidate_plan(
        query_contract,
        min_sources,
        candidate_urls,
        candidate_source_hints,
        locality_hint,
        allow_floor_recovery_exploration,
    )
}

pub(crate) fn pre_read_candidate_plan_from_bundle(
    query_contract: &str,
    min_sources: u32,
    bundle: &WebEvidenceBundle,
) -> PreReadCandidatePlan {
    pre_read_candidate_plan_from_bundle_with_locality_hint_and_recovery_mode(
        query_contract,
        min_sources,
        bundle,
        None,
        false,
    )
}

pub(crate) fn pre_read_candidate_plan_from_bundle_with_recovery_mode(
    query_contract: &str,
    min_sources: u32,
    bundle: &WebEvidenceBundle,
    allow_floor_recovery_exploration: bool,
) -> PreReadCandidatePlan {
    pre_read_candidate_plan_from_bundle_with_locality_hint_and_recovery_mode(
        query_contract,
        min_sources,
        bundle,
        None,
        allow_floor_recovery_exploration,
    )
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

pub(crate) fn web_pipeline_min_sources(query: &str) -> u32 {
    if prefers_single_fact_snapshot(query) {
        return 2;
    }
    WEB_PIPELINE_DEFAULT_MIN_SOURCES
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

pub(crate) fn web_pipeline_remaining_budget_ms(deadline_ms: u64, now_ms: u64) -> u64 {
    if deadline_ms == 0 {
        return u64::MAX;
    }
    deadline_ms.saturating_sub(now_ms)
}

pub(crate) fn web_pipeline_can_queue_initial_read(deadline_ms: u64, now_ms: u64) -> bool {
    if deadline_ms == 0 {
        return true;
    }
    web_pipeline_remaining_budget_ms(deadline_ms, now_ms)
        >= WEB_PIPELINE_MIN_REMAINING_BUDGET_MS_FOR_INITIAL_READ
}

pub(crate) fn web_pipeline_can_queue_probe_search(deadline_ms: u64, now_ms: u64) -> bool {
    if deadline_ms == 0 {
        return true;
    }
    web_pipeline_remaining_budget_ms(deadline_ms, now_ms)
        >= WEB_PIPELINE_MIN_REMAINING_BUDGET_MS_FOR_SEARCH_PROBE
}

fn web_pipeline_observed_attempt_count(pending: &PendingSearchCompletion) -> u64 {
    pending
        .attempted_urls
        .len()
        .max(pending.successful_reads.len() + pending.blocked_urls.len())
        .max(1) as u64
}

fn web_pipeline_observed_attempt_latency_ms(pending: &PendingSearchCompletion, now_ms: u64) -> u64 {
    if pending.started_at_ms == 0 || now_ms <= pending.started_at_ms {
        return 0;
    }
    let elapsed_ms = now_ms.saturating_sub(pending.started_at_ms);
    elapsed_ms / web_pipeline_observed_attempt_count(pending)
}

fn web_pipeline_constraint_guard_ms(
    pending: &PendingSearchCompletion,
    read_guard_ms: u64,
    non_constraint_guard_ms: u64,
) -> u64 {
    let query_contract = synthesis_query_contract(pending);
    let projection = build_query_constraint_projection(
        &query_contract,
        pending.min_sources,
        &pending.candidate_source_hints,
    );
    if projection.has_constraint_objective() {
        read_guard_ms
    } else {
        non_constraint_guard_ms
    }
}

pub(crate) fn web_pipeline_required_read_budget_ms(
    pending: &PendingSearchCompletion,
    now_ms: u64,
) -> u64 {
    if pending.deadline_ms == 0 {
        return 0;
    }
    let observed_latency = web_pipeline_observed_attempt_latency_ms(pending, now_ms);
    let constraint_guard = web_pipeline_constraint_guard_ms(
        pending,
        WEB_PIPELINE_LATENCY_READ_GUARD_MS,
        WEB_PIPELINE_LATENCY_READ_GUARD_MS / 2,
    );
    WEB_PIPELINE_MIN_REMAINING_BUDGET_MS_FOR_INITIAL_READ
        .max(observed_latency.saturating_add(constraint_guard))
}

pub(crate) fn web_pipeline_required_probe_budget_ms(
    pending: &PendingSearchCompletion,
    now_ms: u64,
) -> u64 {
    if pending.deadline_ms == 0 {
        return 0;
    }
    let query_contract = synthesis_query_contract(pending);
    let projection = build_query_constraint_projection(
        &query_contract,
        pending.min_sources,
        &pending.candidate_source_hints,
    );
    let observed_latency = web_pipeline_observed_attempt_latency_ms(pending, now_ms);
    let strict_grounding_guard = if projection.strict_grounded_compatibility() {
        WEB_PIPELINE_LATENCY_PROBE_GUARD_MS / 2
    } else {
        0
    };
    let constraint_guard = web_pipeline_constraint_guard_ms(
        pending,
        WEB_PIPELINE_LATENCY_PROBE_GUARD_MS,
        WEB_PIPELINE_LATENCY_PROBE_GUARD_MS / 2,
    );
    WEB_PIPELINE_MIN_REMAINING_BUDGET_MS_FOR_SEARCH_PROBE.max(
        observed_latency
            .saturating_add(constraint_guard)
            .saturating_add(strict_grounding_guard),
    )
}

pub(crate) fn web_pipeline_can_queue_initial_read_latency_aware(
    pending: &PendingSearchCompletion,
    now_ms: u64,
) -> bool {
    if pending.deadline_ms == 0 {
        return true;
    }
    let remaining = web_pipeline_remaining_budget_ms(pending.deadline_ms, now_ms);
    remaining >= web_pipeline_required_read_budget_ms(pending, now_ms)
}

pub(crate) fn web_pipeline_can_queue_probe_search_latency_aware(
    pending: &PendingSearchCompletion,
    now_ms: u64,
) -> bool {
    if pending.deadline_ms == 0 {
        return true;
    }
    let remaining = web_pipeline_remaining_budget_ms(pending.deadline_ms, now_ms);
    remaining >= web_pipeline_required_probe_budget_ms(pending, now_ms)
}

pub(crate) fn web_pipeline_latency_pressure(
    pending: &PendingSearchCompletion,
    now_ms: u64,
) -> WebPipelineLatencyPressure {
    if pending.deadline_ms == 0 {
        return WebPipelineLatencyPressure::Nominal;
    }
    let remaining = web_pipeline_remaining_budget_ms(pending.deadline_ms, now_ms);
    let required_read_budget = web_pipeline_required_read_budget_ms(pending, now_ms);
    if remaining < required_read_budget {
        return WebPipelineLatencyPressure::Critical;
    }
    if remaining < required_read_budget.saturating_add(WEB_PIPELINE_LATENCY_ELEVATED_BUFFER_MS) {
        return WebPipelineLatencyPressure::Elevated;
    }
    WebPipelineLatencyPressure::Nominal
}

pub(crate) fn web_pipeline_latency_pressure_label(
    pending: &PendingSearchCompletion,
    now_ms: u64,
) -> &'static str {
    match web_pipeline_latency_pressure(pending, now_ms) {
        WebPipelineLatencyPressure::Nominal => "nominal",
        WebPipelineLatencyPressure::Elevated => "elevated",
        WebPipelineLatencyPressure::Critical => "critical",
    }
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

fn candidate_source_hints_from_bundle_ranked(
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

fn document_source_hints_from_bundle(bundle: &WebEvidenceBundle) -> Vec<PendingSearchReadSummary> {
    let mut hints = Vec::new();
    let mut seen = BTreeSet::new();
    for doc in &bundle.documents {
        let url = doc.url.trim();
        if url.is_empty() || !seen.insert(url.to_string()) {
            continue;
        }
        hints.push(PendingSearchReadSummary {
            url: url.to_string(),
            title: doc
                .title
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.to_string()),
            excerpt: compact_excerpt(&doc.content_text, WEB_PIPELINE_EXCERPT_CHARS),
        });
    }
    hints
}

pub(crate) fn candidate_source_hints_from_bundle(
    bundle: &WebEvidenceBundle,
) -> Vec<PendingSearchReadSummary> {
    candidate_source_hints_from_bundle_ranked(bundle)
}

pub(crate) fn candidate_urls_from_bundle(bundle: &WebEvidenceBundle) -> Vec<String> {
    let mut urls = Vec::new();
    let mut seen = BTreeSet::new();

    for hint in candidate_source_hints_from_bundle_ranked(bundle) {
        let url = hint.url.trim();
        if !url.is_empty() && seen.insert(url.to_string()) {
            urls.push(url.to_string());
        }
    }

    for hint in document_source_hints_from_bundle(bundle) {
        let url = hint.url.trim();
        if !url.is_empty() && seen.insert(url.to_string()) {
            urls.push(url.to_string());
        }
    }

    urls
}

fn constrained_candidate_inventory_from_bundle_with_locality_hint(
    query_contract: &str,
    min_sources: u32,
    bundle: &WebEvidenceBundle,
    locality_hint: Option<&str>,
) -> (Vec<String>, Vec<PendingSearchReadSummary>) {
    let mut candidate_hints = candidate_source_hints_from_bundle_ranked(bundle);
    let mut seen_urls = candidate_hints
        .iter()
        .map(|hint| hint.url.trim().to_string())
        .filter(|url| !url.is_empty())
        .collect::<BTreeSet<_>>();
    for hint in document_source_hints_from_bundle(bundle) {
        let trimmed = hint.url.trim();
        if trimmed.is_empty() || !seen_urls.insert(trimmed.to_string()) {
            continue;
        }
        candidate_hints.push(hint);
    }

    if candidate_hints.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let projection = build_query_constraint_projection_with_locality_hint(
        query_contract,
        min_sources,
        &candidate_hints,
        locality_hint,
    );
    let constraints = &projection.constraints;
    let policy = ResolutionPolicy::default();
    let min_required = min_sources.max(1) as usize;

    let mut ranked = candidate_hints
        .into_iter()
        .enumerate()
        .map(|(idx, hint)| {
            let title = hint.title.as_deref().unwrap_or_default();
            let envelope_score = single_snapshot_candidate_envelope_score(
                constraints,
                policy,
                &hint.url,
                title,
                &hint.excerpt,
            );
            let resolves_constraint =
                envelope_score_resolves_constraint(constraints, &envelope_score);
            let compatibility = candidate_constraint_compatibility(
                constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                &hint.url,
                title,
                &hint.excerpt,
            );
            let source_signals = analyze_source_record_signals(&hint.url, title, &hint.excerpt);
            let time_sensitive_resolvable_payload =
                candidate_time_sensitive_resolvable_payload(title, &hint.excerpt);
            RankedAcquisitionCandidate {
                idx,
                hint,
                envelope_score,
                resolves_constraint,
                time_sensitive_resolvable_payload,
                compatibility,
                source_relevance_score: source_signals.relevance_score(false),
            }
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        let right_passes = compatibility_passes_projection(&projection, &right.compatibility);
        let left_passes = compatibility_passes_projection(&projection, &left.compatibility);
        right
            .time_sensitive_resolvable_payload
            .cmp(&left.time_sensitive_resolvable_payload)
            .then_with(|| right_passes.cmp(&left_passes))
            .then_with(|| right.resolves_constraint.cmp(&left.resolves_constraint))
            .then_with(|| {
                right
                    .compatibility
                    .compatibility_score
                    .cmp(&left.compatibility.compatibility_score)
            })
            .then_with(|| {
                compare_candidate_evidence_scores_desc(&left.envelope_score, &right.envelope_score)
            })
            .then_with(|| {
                right
                    .source_relevance_score
                    .cmp(&left.source_relevance_score)
            })
            .then_with(|| left.idx.cmp(&right.idx))
            .then_with(|| left.hint.url.cmp(&right.hint.url))
    });

    let has_constraint_objective = projection.has_constraint_objective();
    let compatible_candidates = ranked
        .iter()
        .filter(|candidate| compatibility_passes_projection(&projection, &candidate.compatibility))
        .count();
    let should_filter_by_compatibility =
        has_constraint_objective && compatible_candidates >= min_required;

    let mut filtered = ranked.iter().collect::<Vec<_>>();
    if should_filter_by_compatibility {
        filtered.retain(|candidate| {
            compatibility_passes_projection(&projection, &candidate.compatibility)
        });
    }

    let resolvable_candidates = filtered
        .iter()
        .filter(|candidate| candidate.resolves_constraint)
        .count();
    if has_constraint_objective && resolvable_candidates >= min_required {
        filtered.retain(|candidate| candidate.resolves_constraint);
    }

    let selected = if filtered.is_empty() {
        if projection.strict_grounded_compatibility() {
            Vec::new()
        } else {
            ranked.iter().collect::<Vec<_>>()
        }
    } else {
        filtered
    };
    let mut selected_urls = Vec::new();
    let mut selected_hints = Vec::new();
    let mut selected_seen = BTreeSet::new();
    for candidate in selected {
        let url = candidate.hint.url.trim();
        if url.is_empty() || !selected_seen.insert(url.to_string()) {
            continue;
        }
        selected_urls.push(url.to_string());
        selected_hints.push(candidate.hint.clone());
    }

    (selected_urls, selected_hints)
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

    let query_contract = synthesis_query_contract(pending);
    let prefer_host_diversity = prefers_single_fact_snapshot(&query_contract);
    if prefer_host_diversity {
        let projection =
            build_query_constraint_projection(&query_contract, 1, &pending.candidate_source_hints);
        let envelope_constraints = &projection.constraints;
        let grounded_anchor_constrained = projection.strict_grounded_compatibility();
        let envelope_policy = ResolutionPolicy::default();
        let mut ranked_candidates = pending
            .candidate_urls
            .iter()
            .enumerate()
            .filter_map(|(idx, candidate)| {
                let trimmed = candidate.trim();
                if trimmed.is_empty() || attempted.contains(trimmed) {
                    return None;
                }
                let hint = hint_for_url(pending, trimmed);
                let title = hint
                    .and_then(|entry| entry.title.as_deref())
                    .unwrap_or_default();
                let excerpt = hint.map(|entry| entry.excerpt.as_str()).unwrap_or_default();
                let envelope_score = single_snapshot_candidate_envelope_score(
                    envelope_constraints,
                    envelope_policy,
                    trimmed,
                    title,
                    excerpt,
                );
                let compatibility = candidate_constraint_compatibility(
                    envelope_constraints,
                    &projection.query_facets,
                    &projection.query_native_tokens,
                    &projection.query_tokens,
                    &projection.locality_tokens,
                    projection.locality_scope.is_some(),
                    trimmed,
                    title,
                    excerpt,
                );
                let resolvable_payload =
                    candidate_time_sensitive_resolvable_payload(title, excerpt);
                let source_relevance_score =
                    analyze_source_record_signals(trimmed, title, excerpt).relevance_score(false);
                Some((
                    idx,
                    trimmed.to_string(),
                    envelope_score,
                    compatibility,
                    resolvable_payload,
                    source_relevance_score,
                ))
            })
            .collect::<Vec<_>>();
        ranked_candidates.sort_by(|left, right| {
            right
                .4
                .cmp(&left.4)
                .then_with(|| {
                    let right_passes = compatibility_passes_projection(&projection, &right.3);
                    let left_passes = compatibility_passes_projection(&projection, &left.3);
                    right_passes.cmp(&left_passes)
                })
                .then_with(|| right.3.compatibility_score.cmp(&left.3.compatibility_score))
                .then_with(|| compare_candidate_evidence_scores_desc(&left.2, &right.2))
                .then_with(|| right.5.cmp(&left.5))
                .then_with(|| left.0.cmp(&right.0))
                .then_with(|| left.1.cmp(&right.1))
        });
        let has_compatible_candidates =
            ranked_candidates
                .iter()
                .any(|(_, _, _, compatibility, _, _)| {
                    compatibility_passes_projection(&projection, compatibility)
                });
        let requires_semantic_locality_alignment = projection
            .constraints
            .scopes
            .contains(&ConstraintScope::TimeSensitive)
            && projection.locality_scope.is_some()
            && projection
                .query_native_tokens
                .iter()
                .any(|token| !projection.locality_tokens.contains(token));
        let exploratory_attempts_without_compatibility = pending
            .attempted_urls
            .iter()
            .chain(pending.blocked_urls.iter())
            .chain(pending.successful_reads.iter().map(|source| &source.url))
            .map(|url| url.trim().to_string())
            .filter(|url| !url.is_empty() && !is_search_hub_url(url))
            .collect::<BTreeSet<_>>()
            .len();
        let exploratory_read_cap = SINGLE_SNAPSHOT_MAX_EXPLORATORY_READS_WITHOUT_COMPATIBILITY
            .saturating_add(
                single_snapshot_additional_probe_attempt_count(pending)
                    .min(SINGLE_SNAPSHOT_MAX_ADDITIONAL_PROBE_SOURCES),
            );
        let can_issue_exploratory_read =
            exploratory_attempts_without_compatibility < exploratory_read_cap;
        if requires_semantic_locality_alignment
            && !has_compatible_candidates
            && !can_issue_exploratory_read
        {
            return None;
        }

        let mut attempted_hosts = BTreeSet::new();
        for url in pending
            .attempted_urls
            .iter()
            .chain(pending.blocked_urls.iter())
            .chain(pending.successful_reads.iter().map(|source| &source.url))
        {
            let trimmed = url.trim();
            if trimmed.is_empty() || is_search_hub_url(trimmed) {
                continue;
            }
            if let Some(host) = source_host(trimmed) {
                attempted_hosts.insert(host);
            }
        }

        for (_, candidate, _, compatibility, _, _) in &ranked_candidates {
            if has_compatible_candidates
                && !compatibility_passes_projection(&projection, compatibility)
            {
                continue;
            }
            if let Some(host) = source_host(candidate) {
                if attempted_hosts.contains(&host) {
                    continue;
                }
            }
            return Some(candidate.clone());
        }

        if has_compatible_candidates {
            if let Some((_, candidate, _, _, _, _)) =
                ranked_candidates
                    .iter()
                    .find(|(_, _, _, compatibility, _, _)| {
                        compatibility_passes_projection(&projection, compatibility)
                    })
            {
                return Some(candidate.clone());
            }
        }

        if grounded_anchor_constrained {
            if !has_compatible_candidates && can_issue_exploratory_read {
                if let Some((_, candidate, _, _, _, _)) = ranked_candidates.first() {
                    return Some(candidate.clone());
                }
            }
            return None;
        }

        if let Some((_, candidate, _, _, _, _)) = ranked_candidates.first() {
            return Some(candidate.clone());
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

fn normalize_optional_title(value: Option<String>) -> Option<String> {
    value.and_then(|title| {
        let trimmed = title.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

fn prefer_title(existing: Option<String>, incoming: Option<String>) -> Option<String> {
    let existing = normalize_optional_title(existing);
    let incoming = normalize_optional_title(incoming);
    match (existing, incoming) {
        (None, None) => None,
        (Some(value), None) | (None, Some(value)) => Some(value),
        (Some(left), Some(right)) => {
            let left_low = is_low_signal_title(&left);
            let right_low = is_low_signal_title(&right);
            if left_low != right_low {
                return if right_low { Some(left) } else { Some(right) };
            }
            if right.chars().count() > left.chars().count() {
                Some(right)
            } else {
                Some(left)
            }
        }
    }
}

fn prefer_excerpt(existing: String, incoming: String) -> String {
    let left = existing.trim().to_string();
    let right = incoming.trim().to_string();
    if left.is_empty() {
        return right;
    }
    if right.is_empty() {
        return left;
    }

    let left_current = contains_current_condition_metric_signal(&left);
    let right_current = contains_current_condition_metric_signal(&right);
    if right_current != left_current {
        return if right_current { right } else { left };
    }

    let left_metric = contains_metric_signal(&left);
    let right_metric = contains_metric_signal(&right);
    if right_metric != left_metric {
        return if right_metric { right } else { left };
    }

    let left_low = is_low_signal_excerpt(&left);
    let right_low = is_low_signal_excerpt(&right);
    if right_low != left_low {
        return if right_low { left } else { right };
    }

    if right.chars().count() > left.chars().count() {
        right
    } else {
        left
    }
}

fn merge_pending_source_record(
    existing: PendingSearchReadSummary,
    incoming: PendingSearchReadSummary,
) -> PendingSearchReadSummary {
    let url = if existing.url.trim().is_empty() {
        incoming.url.trim().to_string()
    } else {
        existing.url.trim().to_string()
    };
    PendingSearchReadSummary {
        url,
        title: prefer_title(existing.title, incoming.title),
        excerpt: prefer_excerpt(existing.excerpt, incoming.excerpt),
    }
}

fn merge_url_sequence(existing: Vec<String>, incoming: Vec<String>) -> Vec<String> {
    let mut merged = Vec::new();
    let mut seen = BTreeSet::new();
    for url in existing.into_iter().chain(incoming.into_iter()) {
        let trimmed = url.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !seen.insert(trimmed.to_string()) {
            continue;
        }
        merged.push(trimmed.to_string());
    }
    merged
}

pub(crate) fn merge_pending_search_completion(
    existing: PendingSearchCompletion,
    incoming: PendingSearchCompletion,
) -> PendingSearchCompletion {
    let existing_contract = existing.query_contract.trim();
    let incoming_contract = incoming.query_contract.trim();
    if !existing_contract.is_empty()
        && !incoming_contract.is_empty()
        && !existing_contract.eq_ignore_ascii_case(incoming_contract)
    {
        return incoming;
    }

    let existing_query = existing.query.trim();
    let incoming_query = incoming.query.trim();
    if existing_contract.is_empty()
        && incoming_contract.is_empty()
        && !existing_query.is_empty()
        && !incoming_query.is_empty()
        && !existing_query.eq_ignore_ascii_case(incoming_query)
    {
        return incoming;
    }

    let successful_reads = {
        let mut merged_by_url: BTreeMap<String, PendingSearchReadSummary> = BTreeMap::new();
        for source in existing
            .successful_reads
            .into_iter()
            .chain(incoming.successful_reads.into_iter())
        {
            let trimmed = source.url.trim();
            if trimmed.is_empty() {
                continue;
            }
            let normalized = PendingSearchReadSummary {
                url: trimmed.to_string(),
                title: normalize_optional_title(source.title),
                excerpt: source.excerpt.trim().to_string(),
            };
            if let Some(current) = merged_by_url.get(trimmed) {
                let merged = merge_pending_source_record(current.clone(), normalized);
                merged_by_url.insert(trimmed.to_string(), merged);
            } else {
                merged_by_url.insert(trimmed.to_string(), normalized);
            }
        }
        merged_by_url.into_values().collect::<Vec<_>>()
    };

    let attempted_urls = merge_url_sequence(existing.attempted_urls, incoming.attempted_urls);
    let blocked_urls = merge_url_sequence(existing.blocked_urls, incoming.blocked_urls);

    let mut attempted_or_resolved = BTreeSet::new();
    for url in attempted_urls.iter().chain(blocked_urls.iter()) {
        attempted_or_resolved.insert(url.trim().to_string());
    }
    for source in &successful_reads {
        let trimmed = source.url.trim();
        if !trimmed.is_empty() {
            attempted_or_resolved.insert(trimmed.to_string());
        }
    }

    let candidate_urls = merge_url_sequence(existing.candidate_urls, incoming.candidate_urls)
        .into_iter()
        .filter(|url| !attempted_or_resolved.contains(url))
        .collect::<Vec<_>>();

    let candidate_source_hints = {
        let mut merged_by_url: BTreeMap<String, PendingSearchReadSummary> = BTreeMap::new();
        for source in existing
            .candidate_source_hints
            .into_iter()
            .chain(incoming.candidate_source_hints.into_iter())
        {
            let trimmed = source.url.trim();
            if trimmed.is_empty() {
                continue;
            }
            let normalized = PendingSearchReadSummary {
                url: trimmed.to_string(),
                title: normalize_optional_title(source.title),
                excerpt: source.excerpt.trim().to_string(),
            };
            if let Some(current) = merged_by_url.get(trimmed) {
                let merged = merge_pending_source_record(current.clone(), normalized);
                merged_by_url.insert(trimmed.to_string(), merged);
            } else {
                merged_by_url.insert(trimmed.to_string(), normalized);
            }
        }

        let mut ordered = Vec::new();
        let mut seen = BTreeSet::new();
        for url in &candidate_urls {
            if let Some(source) = merged_by_url.get(url) {
                ordered.push(source.clone());
                seen.insert(url.clone());
            }
        }
        for (url, source) in merged_by_url {
            if seen.insert(url) {
                ordered.push(source);
            }
        }
        ordered
    };

    PendingSearchCompletion {
        query: if incoming_query.is_empty() {
            existing.query
        } else if existing_query.is_empty() || !existing_query.eq_ignore_ascii_case(incoming_query)
        {
            incoming.query
        } else {
            existing.query
        },
        query_contract: if existing_contract.is_empty() {
            incoming.query_contract
        } else {
            existing.query_contract
        },
        url: if existing.url.trim().is_empty() {
            incoming.url
        } else {
            existing.url
        },
        started_step: if existing.started_at_ms > 0 || existing.started_step > 0 {
            existing.started_step
        } else {
            incoming.started_step
        },
        started_at_ms: if existing.started_at_ms > 0 {
            existing.started_at_ms
        } else {
            incoming.started_at_ms
        },
        deadline_ms: if existing.deadline_ms > 0 {
            existing.deadline_ms
        } else {
            incoming.deadline_ms
        },
        candidate_urls,
        candidate_source_hints,
        attempted_urls,
        blocked_urls,
        successful_reads,
        min_sources: existing.min_sources.max(incoming.min_sources),
    }
}

fn compact_excerpt(input: &str, max_chars: usize) -> String {
    compact_whitespace(input)
        .chars()
        .take(max_chars)
        .collect::<String>()
}

fn prioritized_signal_excerpt(input: &str, max_chars: usize) -> String {
    let compact = compact_whitespace(input);
    if compact.is_empty() {
        return String::new();
    }

    if let Some(metric) = first_metric_sentence(&compact) {
        return metric.chars().take(max_chars).collect();
    }

    if let Some(actionable) = actionable_excerpt(&compact) {
        return actionable.chars().take(max_chars).collect();
    }

    if is_low_signal_excerpt(&compact) {
        return String::new();
    }

    compact.chars().take(max_chars).collect()
}

fn source_host(url: &str) -> Option<String> {
    let parsed = Url::parse(url.trim()).ok()?;
    let host = parsed
        .host_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    Some(host.to_ascii_lowercase())
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

fn actionable_source_signal_strength(signals: SourceSignalProfile) -> usize {
    effective_primary_event_hits(signals) + signals.impact_hits + signals.mitigation_hits
}

fn low_priority_source_signal_strength(signals: SourceSignalProfile) -> usize {
    signals.low_priority_hits + signals.secondary_coverage_hits + signals.documentation_surface_hits
}

fn effective_primary_event_hits(signals: SourceSignalProfile) -> usize {
    let surface_bias = signals
        .provenance_hits
        .max(signals.primary_status_surface_hits);
    signals
        .primary_event_hits
        .saturating_sub(surface_bias.min(signals.primary_event_hits))
}

fn excerpt_has_claim_signal(excerpt: &str) -> bool {
    let trimmed = excerpt.trim();
    if trimmed.is_empty() {
        return false;
    }
    let metric_schema = analyze_metric_schema(trimmed);
    if metric_schema.has_metric_payload() || metric_schema.has_current_observation_payload() {
        return true;
    }
    let signals = analyze_source_record_signals("", "", trimmed);
    let has_timeline_claim = signals.timeline_hits > 0
        && (metric_schema.timestamp_hits > 0
            || (metric_schema.observation_hits > 0
                && trimmed.chars().any(|ch| ch.is_ascii_digit())));
    effective_primary_event_hits(signals) > 0
        || signals.impact_hits > 0
        || signals.mitigation_hits > 0
        || has_timeline_claim
}

fn excerpt_actionability_score(excerpt: &str) -> usize {
    let trimmed = excerpt.trim();
    if trimmed.is_empty() {
        return 0;
    }

    let metric_schema = analyze_metric_schema(trimmed);
    let signals = analyze_source_record_signals("", "", trimmed);
    let has_claim_signal = excerpt_has_claim_signal(trimmed);
    let digit_hits = trimmed
        .chars()
        .filter(|ch| ch.is_ascii_digit())
        .count()
        .min(6);
    let actionability_signal = actionable_source_signal_strength(signals).min(8);
    let low_priority_signal = low_priority_source_signal_strength(signals).min(8);

    let mut score = 0usize;
    if metric_schema.has_current_observation_payload() {
        score = score.saturating_add(6);
    }
    if metric_schema.has_metric_payload() {
        score = score.saturating_add(4);
    }
    score = score
        .saturating_add(metric_schema.axis_hits.len().min(4).saturating_mul(2))
        .saturating_add(metric_schema.numeric_token_hits.min(4))
        .saturating_add(metric_schema.unit_hits.min(4))
        .saturating_add(metric_schema.observation_hits.min(3))
        .saturating_add(metric_schema.timestamp_hits.min(3));
    if has_claim_signal {
        let provenance_context = signals
            .provenance_hits
            .saturating_add(signals.primary_status_surface_hits)
            .saturating_add(signals.official_status_host_hits)
            .min(4);
        score = score
            .saturating_add(ACTIONABLE_EXCERPT_CLAIM_BASE_BONUS)
            .saturating_add(actionability_signal)
            .saturating_add(provenance_context);
    }
    score = score.saturating_add(digit_hits);
    score.saturating_sub(low_priority_signal)
}

fn is_low_signal_excerpt(excerpt: &str) -> bool {
    let trimmed = excerpt.trim();
    if trimmed.is_empty() {
        return true;
    }
    if trimmed.chars().count() < ACTIONABLE_EXCERPT_SEGMENT_MIN_CHARS {
        return true;
    }
    let has_numeric_hint = trimmed.chars().any(|ch| ch.is_ascii_digit());
    if !excerpt_has_claim_signal(trimmed) && !has_numeric_hint {
        return true;
    }

    let actionability_score = excerpt_actionability_score(trimmed);
    if actionability_score >= ACTIONABLE_EXCERPT_MIN_SCORE {
        return false;
    }

    let anchor_token_count = normalized_anchor_tokens(trimmed).len();
    if !has_numeric_hint {
        return true;
    }
    anchor_token_count < 3
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

    let mut best_segment: Option<(usize, String)> = None;
    for segment in compact
        .split(['.', '!', '?', ';'])
        .map(compact_whitespace)
        .filter(|value| !value.is_empty())
    {
        if segment.chars().count() < ACTIONABLE_EXCERPT_SEGMENT_MIN_CHARS {
            continue;
        }
        if !excerpt_has_claim_signal(&segment) {
            continue;
        }
        let score = excerpt_actionability_score(&segment);
        if score < ACTIONABLE_EXCERPT_MIN_SCORE {
            continue;
        }
        let replace = best_segment
            .as_ref()
            .map(|(best_score, best_text)| {
                score > *best_score || (score == *best_score && segment.len() < best_text.len())
            })
            .unwrap_or(true);
        if replace {
            best_segment = Some((score, segment));
        }
    }

    if let Some((_, selected)) = best_segment {
        return Some(
            selected
                .chars()
                .take(WEB_PIPELINE_ACTIONABLE_EXCERPT_CHARS)
                .collect(),
        );
    }

    if excerpt_actionability_score(&compact) < ACTIONABLE_EXCERPT_MIN_SCORE
        || is_low_signal_excerpt(&compact)
    {
        return None;
    }

    Some(
        compact
            .chars()
            .take(WEB_PIPELINE_ACTIONABLE_EXCERPT_CHARS)
            .collect(),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UrlStructuralKey {
    host: String,
    path: String,
    query_tokens: BTreeSet<String>,
}

fn normalized_url_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return "/".to_string();
    }
    let lowered = trimmed.to_ascii_lowercase();
    let stripped = lowered.trim_end_matches('/');
    if stripped.is_empty() {
        "/".to_string()
    } else {
        stripped.to_string()
    }
}

fn url_structural_key(url: &str) -> Option<UrlStructuralKey> {
    let parsed = Url::parse(url.trim()).ok()?;
    let host = parsed.host_str()?.trim().to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    let path = normalized_url_path(parsed.path());
    let mut query_tokens = BTreeSet::new();
    if let Some(query) = parsed.query() {
        query_tokens.extend(normalized_locality_tokens(query));
        query_tokens.extend(normalized_anchor_tokens(query));
    }

    Some(UrlStructuralKey {
        host,
        path,
        query_tokens,
    })
}

fn normalized_url_literal(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if let Some(key) = url_structural_key(trimmed) {
        let mut normalized = format!("{}{}", key.host, key.path);
        if !key.query_tokens.is_empty() {
            normalized.push('?');
            normalized.push_str(
                &key.query_tokens
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("&"),
            );
        }
        return normalized;
    }
    trimmed
        .trim_end_matches('/')
        .split_whitespace()
        .collect::<String>()
        .to_ascii_lowercase()
}

fn url_structural_query_overlap(left: &UrlStructuralKey, right: &UrlStructuralKey) -> usize {
    left.query_tokens.intersection(&right.query_tokens).count()
}

fn url_structurally_equivalent(left: &str, right: &str) -> bool {
    let left_trimmed = left.trim();
    let right_trimmed = right.trim();
    if left_trimmed.is_empty() || right_trimmed.is_empty() {
        return false;
    }
    if left_trimmed.eq_ignore_ascii_case(right_trimmed) {
        return true;
    }

    match (
        url_structural_key(left_trimmed),
        url_structural_key(right_trimmed),
    ) {
        (Some(left_key), Some(right_key)) => {
            if left_key.host != right_key.host || left_key.path != right_key.path {
                return false;
            }
            if left_key.query_tokens.is_empty() || right_key.query_tokens.is_empty() {
                return true;
            }
            url_structural_query_overlap(&left_key, &right_key) > 0
        }
        _ => normalized_url_literal(left_trimmed) == normalized_url_literal(right_trimmed),
    }
}

fn hint_for_url<'a>(
    pending: &'a PendingSearchCompletion,
    url: &str,
) -> Option<&'a PendingSearchReadSummary> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(exact) = pending
        .candidate_source_hints
        .iter()
        .find(|hint| hint.url.trim().eq_ignore_ascii_case(trimmed))
    {
        return Some(exact);
    }

    let target_key = url_structural_key(trimmed)?;
    let mut best_hint: Option<&PendingSearchReadSummary> = None;
    let mut best_overlap = 0usize;
    for hint in &pending.candidate_source_hints {
        let hint_trimmed = hint.url.trim();
        if hint_trimmed.is_empty() {
            continue;
        }
        let Some(hint_key) = url_structural_key(hint_trimmed) else {
            continue;
        };
        if hint_key.host != target_key.host || hint_key.path != target_key.path {
            continue;
        }
        if !hint_key.query_tokens.is_empty()
            && !target_key.query_tokens.is_empty()
            && url_structural_query_overlap(&hint_key, &target_key) == 0
        {
            continue;
        }
        let overlap = url_structural_query_overlap(&hint_key, &target_key);
        let should_replace = best_hint.is_none() || overlap > best_overlap;
        if should_replace {
            best_overlap = overlap;
            best_hint = Some(hint);
        }
    }

    best_hint
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
        .any(|existing| url_structurally_equivalent(existing.url.trim(), trimmed))
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
    if let Some(hint_excerpt) = hint
        .map(|value| value.excerpt.trim())
        .filter(|value| !value.is_empty())
    {
        let resolved_has_current = contains_current_condition_metric_signal(&resolved_excerpt);
        let hint_has_current = contains_current_condition_metric_signal(hint_excerpt);
        let resolved_has_metric = contains_metric_signal(&resolved_excerpt);
        let hint_has_metric = contains_metric_signal(hint_excerpt);
        let should_use_hint = is_low_signal_excerpt(&resolved_excerpt)
            || (hint_has_current && !resolved_has_current)
            || (!resolved_has_metric && hint_has_metric);
        if should_use_hint {
            resolved_excerpt = hint_excerpt.to_string();
        }
    }

    let query_contract = synthesis_query_contract(pending);
    let projection = build_query_constraint_projection(
        &query_contract,
        pending.min_sources,
        &pending.candidate_source_hints,
    );
    let min_sources_required = pending.min_sources.max(1) as usize;
    let source_floor_unmet = pending.successful_reads.len() < min_sources_required;
    let time_sensitive = projection
        .constraints
        .scopes
        .contains(&ConstraintScope::TimeSensitive);
    let reject_search_hub = projection.reject_search_hub_candidates();
    if reject_search_hub && is_search_hub_url(trimmed) {
        return;
    }
    if projection.query_facets.grounded_external_required || time_sensitive {
        let compatibility = candidate_constraint_compatibility(
            &projection.constraints,
            &projection.query_facets,
            &projection.query_native_tokens,
            &projection.query_tokens,
            &projection.locality_tokens,
            projection.locality_scope.is_some(),
            trimmed,
            resolved_title.as_deref().unwrap_or_default(),
            &resolved_excerpt,
        );
        let mut compatibility_passes = compatibility_passes_projection(&projection, &compatibility);
        if !compatibility_passes {
            if let Some(hint_entry) = hint {
                let hint_title = hint_entry.title.as_deref().unwrap_or_default().trim();
                let hint_excerpt = hint_entry.excerpt.trim();
                let hint_compatibility = candidate_constraint_compatibility(
                    &projection.constraints,
                    &projection.query_facets,
                    &projection.query_native_tokens,
                    &projection.query_tokens,
                    &projection.locality_tokens,
                    projection.locality_scope.is_some(),
                    trimmed,
                    hint_title,
                    hint_excerpt,
                );
                if compatibility_passes_projection(&projection, &hint_compatibility) {
                    compatibility_passes = true;
                    if resolved_title
                        .as_deref()
                        .map(is_low_signal_title)
                        .unwrap_or(true)
                        && !hint_title.is_empty()
                    {
                        resolved_title = Some(hint_title.to_string());
                    }
                    if !hint_excerpt.is_empty() {
                        resolved_excerpt = hint_excerpt.to_string();
                    }
                }
            }
        }
        if !compatibility_passes {
            let has_compatible_alternative =
                pending.candidate_source_hints.iter().any(|candidate| {
                    let candidate_url = candidate.url.trim();
                    if candidate_url.is_empty() || candidate_url.eq_ignore_ascii_case(trimmed) {
                        return false;
                    }
                    if is_search_hub_url(candidate_url) {
                        return false;
                    }
                    let candidate_title = candidate.title.as_deref().unwrap_or_default();
                    let candidate_excerpt = candidate.excerpt.as_str();
                    let candidate_compatibility = candidate_constraint_compatibility(
                        &projection.constraints,
                        &projection.query_facets,
                        &projection.query_native_tokens,
                        &projection.query_tokens,
                        &projection.locality_tokens,
                        projection.locality_scope.is_some(),
                        candidate_url,
                        candidate_title,
                        candidate_excerpt,
                    );
                    compatibility_passes_projection(&projection, &candidate_compatibility)
                });
            let allow_exploratory_first_capture =
                projection.locality_scope_inferred && !projection.locality_tokens.is_empty();
            let allow_exploratory_floor_capture = source_floor_unmet
                && time_sensitive
                && compatibility.locality_compatible
                && !is_search_hub_url(trimmed);
            if (!source_floor_unmet && has_compatible_alternative)
                || (!source_floor_unmet && !pending.successful_reads.is_empty())
                || (!allow_exploratory_first_capture && !allow_exploratory_floor_capture)
            {
                return;
            }
        }

        if time_sensitive {
            let mut resolved_payload = candidate_time_sensitive_resolvable_payload(
                resolved_title.as_deref().unwrap_or_default(),
                &resolved_excerpt,
            );
            if !resolved_payload {
                if let Some(hint_entry) = hint {
                    let hint_title = hint_entry.title.as_deref().unwrap_or_default().trim();
                    let hint_excerpt = hint_entry.excerpt.trim();
                    if !hint_excerpt.is_empty()
                        && candidate_time_sensitive_resolvable_payload(hint_title, hint_excerpt)
                    {
                        let hint_compatibility = candidate_constraint_compatibility(
                            &projection.constraints,
                            &projection.query_facets,
                            &projection.query_native_tokens,
                            &projection.query_tokens,
                            &projection.locality_tokens,
                            projection.locality_scope.is_some(),
                            trimmed,
                            hint_title,
                            hint_excerpt,
                        );
                        if compatibility_passes_projection(&projection, &hint_compatibility) {
                            if !hint_title.is_empty() {
                                resolved_title = Some(hint_title.to_string());
                            }
                            resolved_excerpt = hint_excerpt.to_string();
                            resolved_payload = true;
                        }
                    }
                }
            }
            if !resolved_payload {
                let has_resolvable_alternative = pending
                    .candidate_source_hints
                    .iter()
                    .chain(pending.successful_reads.iter())
                    .any(|candidate| {
                        let candidate_url = candidate.url.trim();
                        if candidate_url.is_empty() || is_search_hub_url(candidate_url) {
                            return false;
                        }
                        if candidate_url.eq_ignore_ascii_case(trimmed) {
                            return false;
                        }
                        let candidate_title = candidate.title.as_deref().unwrap_or_default().trim();
                        let candidate_excerpt = candidate.excerpt.trim();
                        if !candidate_time_sensitive_resolvable_payload(
                            candidate_title,
                            candidate_excerpt,
                        ) {
                            return false;
                        }
                        let candidate_compatibility = candidate_constraint_compatibility(
                            &projection.constraints,
                            &projection.query_facets,
                            &projection.query_native_tokens,
                            &projection.query_tokens,
                            &projection.locality_tokens,
                            projection.locality_scope.is_some(),
                            candidate_url,
                            candidate_title,
                            candidate_excerpt,
                        );
                        compatibility_passes_projection(&projection, &candidate_compatibility)
                    });
                if has_resolvable_alternative {
                    if source_floor_unmet {
                        // Floor-recovery mode: retain additional locality-compatible reads even
                        // when stronger resolvable alternatives already exist.
                    } else {
                        return;
                    }
                }
            }
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
    let excerpt =
        prioritized_signal_excerpt(raw_output.unwrap_or_default(), WEB_PIPELINE_EXCERPT_CHARS);
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
        let excerpt = prioritized_signal_excerpt(&doc.content_text, WEB_PIPELINE_EXCERPT_CHARS);
        let before = pending.successful_reads.len();
        push_pending_web_success(pending, &doc.url, title.clone(), excerpt.clone());
        if pending.successful_reads.len() > before {
            return;
        }
        let fallback_trimmed = fallback_url.trim();
        if !fallback_trimmed.is_empty() && !url_structurally_equivalent(&doc.url, fallback_trimmed)
        {
            push_pending_web_success(pending, fallback_trimmed, title, excerpt);
            if pending.successful_reads.len() > before {
                return;
            }
        } else if pending.successful_reads.len() > before {
            return;
        }
    }

    if let Some(source) = bundle.sources.first() {
        let excerpt =
            prioritized_signal_excerpt(source.snippet.as_deref().unwrap_or_default(), 180);
        let before = pending.successful_reads.len();
        push_pending_web_success(pending, &source.url, source.title.clone(), excerpt.clone());
        if pending.successful_reads.len() > before {
            return;
        }
        let fallback_trimmed = fallback_url.trim();
        if !fallback_trimmed.is_empty()
            && !url_structurally_equivalent(&source.url, fallback_trimmed)
        {
            push_pending_web_success(pending, fallback_trimmed, source.title.clone(), excerpt);
            if pending.successful_reads.len() > before {
                return;
            }
        } else if pending.successful_reads.len() > before {
            return;
        }
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

fn single_snapshot_has_metric_grounding(pending: &PendingSearchCompletion) -> bool {
    pending.successful_reads.iter().any(|source| {
        let observed_text = format!(
            "{} {}",
            source.title.as_deref().unwrap_or_default(),
            source.excerpt
        );
        contains_current_condition_metric_signal(&observed_text)
    })
}

fn single_snapshot_has_viable_followup_candidate(
    pending: &PendingSearchCompletion,
    query_contract: &str,
) -> bool {
    let projection =
        build_query_constraint_projection(query_contract, 1, &pending.candidate_source_hints);
    let envelope_constraints = &projection.constraints;
    let envelope_policy = ResolutionPolicy::default();
    let attempted_urls = pending
        .attempted_urls
        .iter()
        .chain(pending.blocked_urls.iter())
        .chain(pending.successful_reads.iter().map(|source| &source.url))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>();

    pending.candidate_urls.iter().any(|candidate| {
        let trimmed = candidate.trim();
        if trimmed.is_empty() || attempted_urls.contains(trimmed) {
            return false;
        }
        let hint = hint_for_url(pending, trimmed);
        let title = hint
            .and_then(|entry| entry.title.as_deref())
            .unwrap_or_default();
        let excerpt = hint.map(|entry| entry.excerpt.as_str()).unwrap_or_default();
        let compatibility = candidate_constraint_compatibility(
            envelope_constraints,
            &projection.query_facets,
            &projection.query_native_tokens,
            &projection.query_tokens,
            &projection.locality_tokens,
            projection.locality_scope.is_some(),
            trimmed,
            title,
            excerpt,
        );
        if projection.enforce_grounded_compatibility()
            && !compatibility_passes_projection(&projection, &compatibility)
        {
            return false;
        }
        if title.trim().is_empty() && excerpt.trim().is_empty() {
            return false;
        }
        let envelope_score = single_snapshot_candidate_envelope_score(
            envelope_constraints,
            envelope_policy,
            trimmed,
            title,
            excerpt,
        );
        let resolves_constraint =
            envelope_score_resolves_constraint(envelope_constraints, &envelope_score);
        if projection.has_constraint_objective() {
            resolves_constraint
        } else {
            resolves_constraint || compatibility_passes_projection(&projection, &compatibility)
        }
    })
}

fn single_snapshot_probe_budget_allows_followup(
    pending: &PendingSearchCompletion,
    now_ms: u64,
) -> bool {
    if pending.deadline_ms == 0 {
        return true;
    }
    pending.deadline_ms.saturating_sub(now_ms) >= SINGLE_SNAPSHOT_MIN_REMAINING_BUDGET_MS_FOR_PROBE
}

fn single_snapshot_additional_probe_attempt_count(pending: &PendingSearchCompletion) -> usize {
    let observed_search_attempts = pending
        .attempted_urls
        .iter()
        .filter(|url| {
            let trimmed = url.trim();
            !trimmed.is_empty() && is_search_hub_url(trimmed)
        })
        .count();
    let baseline_search_attempt_missing_from_attempts = if is_search_hub_url(&pending.url) {
        let pending_search_url = pending.url.trim();
        !pending_search_url.is_empty()
            && !pending.attempted_urls.iter().any(|url| {
                let trimmed = url.trim();
                !trimmed.is_empty() && url_structurally_equivalent(trimmed, pending_search_url)
            })
    } else {
        false
    };
    let total_search_attempts = observed_search_attempts
        .saturating_add(usize::from(baseline_search_attempt_missing_from_attempts));
    let probe_query_delta = usize::from({
        let query = pending.query.trim();
        let query_contract = pending.query_contract.trim();
        total_search_attempts == 0
            && !query.is_empty()
            && !query_contract.is_empty()
            && !query.eq_ignore_ascii_case(query_contract)
    });
    total_search_attempts
        .saturating_sub(1)
        .saturating_add(probe_query_delta)
}

fn single_snapshot_requires_current_metric_observation_contract(
    pending: &PendingSearchCompletion,
) -> bool {
    let query_contract = synthesis_query_contract(pending);
    if !prefers_single_fact_snapshot(&query_contract) {
        return false;
    }
    let projection = build_query_constraint_projection(
        &query_contract,
        pending.min_sources.max(1),
        &pending.candidate_source_hints,
    );
    let has_metric_objective = !projection.constraints.required_facets.is_empty()
        || !projection.query_facets.metric_schema.axis_hits.is_empty()
        || (projection.query_facets.time_sensitive_public_fact
            && projection.query_facets.locality_sensitive_public_fact);
    let requires_current_observation = projection
        .constraints
        .scopes
        .contains(&ConstraintScope::TimeSensitive)
        || projection.query_facets.time_sensitive_public_fact;
    has_metric_objective && requires_current_observation
}

pub(crate) fn web_pipeline_requires_metric_probe_followup(
    pending: &PendingSearchCompletion,
    now_ms: u64,
) -> bool {
    if !single_snapshot_requires_current_metric_observation_contract(pending) {
        return false;
    }
    let query_contract = synthesis_query_contract(pending);
    let min_sources = pending.min_sources.max(1) as usize;
    if pending.successful_reads.len() < min_sources {
        return false;
    }
    if single_snapshot_has_metric_grounding(pending) {
        return false;
    }
    let snapshot_probe_limit =
        min_sources.saturating_add(SINGLE_SNAPSHOT_MAX_ADDITIONAL_PROBE_SOURCES);
    if pending.successful_reads.len() >= snapshot_probe_limit {
        return false;
    }
    if single_snapshot_additional_probe_attempt_count(pending)
        >= SINGLE_SNAPSHOT_MAX_ADDITIONAL_PROBE_SOURCES
    {
        return false;
    }
    if !single_snapshot_probe_budget_allows_followup(pending, now_ms) {
        return false;
    }
    if single_snapshot_has_viable_followup_candidate(pending, &query_contract) {
        return true;
    }
    // Pre-emit quality gate: allow one deterministic recovery probe even when
    // candidate inventory is exhausted, so the pipeline can self-correct
    // missing current-observation metrics before final reply emission.
    true
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

    let query_contract = synthesis_query_contract(pending);
    let single_snapshot_mode = prefers_single_fact_snapshot(&query_contract);
    let remaining_candidates = remaining_pending_web_candidates(pending);
    let has_viable_followup_candidate =
        single_snapshot_has_viable_followup_candidate(pending, &query_contract);
    let min_sources = pending.min_sources.max(1) as usize;
    let grounded_sources = grounded_source_evidence_count(pending);

    if single_snapshot_mode
        && pending.successful_reads.len() >= 1
        && pending.successful_reads.len() < min_sources
        && grounded_sources >= min_sources
        && !single_snapshot_has_metric_grounding(pending)
        && !has_viable_followup_candidate
    {
        return Some(WebPipelineCompletionReason::ExhaustedCandidates);
    }

    if pending.successful_reads.len() >= min_sources {
        if single_snapshot_mode && web_pipeline_requires_metric_probe_followup(pending, now_ms) {
            return None;
        }
        if single_snapshot_mode && !single_snapshot_has_metric_grounding(pending) {
            let post_probe_attempt_available =
                single_snapshot_additional_probe_attempt_count(pending) > 0;
            if post_probe_attempt_available
                && remaining_candidates > 0
                && next_pending_web_candidate(pending).is_some()
            {
                return None;
            }
            return Some(WebPipelineCompletionReason::ExhaustedCandidates);
        }
        return Some(WebPipelineCompletionReason::MinSourcesReached);
    }
    if pending.deadline_ms > 0 && now_ms >= pending.deadline_ms {
        return Some(WebPipelineCompletionReason::DeadlineReached);
    }
    if remaining_candidates == 0 {
        // Keep the loop alive for one bounded probe when the citation/source floor
        // is still unmet in single-snapshot mode and budget allows recovery.
        if single_snapshot_mode
            && pending.successful_reads.len() < min_sources
            && single_snapshot_additional_probe_attempt_count(pending)
                < SINGLE_SNAPSHOT_MAX_ADDITIONAL_PROBE_SOURCES
            && single_snapshot_probe_budget_allows_followup(pending, now_ms)
        {
            return None;
        }
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

pub(crate) fn queue_web_search_from_pipeline(
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    query: &str,
    limit: u32,
) -> Result<bool, TransactionError> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Ok(false);
    }
    let params = serde_jcs::to_vec(&json!({
        "query": trimmed,
        "limit": limit.max(1),
    }))
    .or_else(|_| {
        serde_json::to_vec(&json!({
            "query": trimmed,
            "limit": limit.max(1),
        }))
    })
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

fn single_snapshot_source_score(
    source: &PendingSearchReadSummary,
    envelope_constraints: &ConstraintSet,
    envelope_policy: ResolutionPolicy,
) -> CandidateEvidenceScore {
    let title = source.title.as_deref().unwrap_or_default();
    let excerpt = source.excerpt.trim();
    single_snapshot_candidate_envelope_score(
        envelope_constraints,
        envelope_policy,
        source.url.as_str(),
        title,
        excerpt,
    )
}

fn has_quantitative_metric_payload(text: &str, require_current_observation: bool) -> bool {
    let schema = analyze_metric_schema(text);
    if schema.numeric_token_hits == 0 {
        return false;
    }
    if require_current_observation && schema.axis_hits.is_empty() {
        return false;
    }
    let has_explicit_measurement = has_numeric_measurement_signal(text);
    if has_explicit_measurement {
        if require_current_observation {
            return schema.has_current_observation_payload()
                || (schema.observation_hits > 0 && schema.unit_hits > 0);
        }
        return true;
    }
    if schema.axis_hits.is_empty() {
        return false;
    }
    if require_current_observation && !schema.has_current_observation_payload() {
        return false;
    }
    let timestamp_dominates_without_units = schema.timestamp_hits > 0
        && schema.unit_hits == 0
        && schema.currency_hits == 0
        && schema.timestamp_hits >= schema.numeric_token_hits;
    if timestamp_dominates_without_units {
        return false;
    }
    let horizon_dominates =
        schema.horizon_hits > schema.observation_hits + schema.timestamp_hits + schema.range_hits;
    if horizon_dominates {
        return false;
    }
    let has_multi_axis_observed_numeric = schema.has_current_observation_payload()
        && schema.observation_hits > 0
        && schema.axis_hits.len() >= 2
        && schema.numeric_token_hits >= 2
        && schema.timestamp_hits < schema.numeric_token_hits;
    let has_ranged_observation = schema.range_hits > 0 && schema.observation_hits > 0;
    has_multi_axis_observed_numeric || has_ranged_observation
}

fn contains_current_condition_metric_signal(text: &str) -> bool {
    if !has_quantitative_metric_payload(text, true) {
        return false;
    }
    let schema = analyze_metric_schema(text);
    let has_observable_axis = schema.axis_hits.iter().any(|axis| {
        matches!(
            axis,
            MetricAxis::Temperature
                | MetricAxis::Humidity
                | MetricAxis::Wind
                | MetricAxis::Pressure
                | MetricAxis::Visibility
                | MetricAxis::AirQuality
                | MetricAxis::Price
                | MetricAxis::Rate
        )
    });
    has_observable_axis
}

fn metric_axis_unavailable_label(axis: MetricAxis) -> &'static str {
    match axis {
        MetricAxis::Temperature => "temperature (\u{00b0}F) unavailable",
        MetricAxis::Humidity => "humidity unavailable",
        MetricAxis::Wind => "wind unavailable",
        MetricAxis::Pressure => "pressure unavailable",
        MetricAxis::Visibility => "visibility unavailable",
        MetricAxis::AirQuality => "air quality unavailable",
        MetricAxis::Precipitation => "precipitation unavailable",
        MetricAxis::Price => "price unavailable",
        MetricAxis::Rate => "rate unavailable",
        MetricAxis::Score => "score unavailable",
        MetricAxis::Duration => "duration unavailable",
    }
}

fn single_snapshot_metric_status_line(required_axes: &BTreeSet<MetricAxis>) -> String {
    if required_axes.is_empty() {
        return "- Current metric status: live current-observation values were unavailable in retrieved source text at this UTC timestamp.".to_string();
    }
    let mut axis_labels = required_axes
        .iter()
        .copied()
        .map(metric_axis_unavailable_label)
        .collect::<Vec<_>>();
    axis_labels.truncate(4);
    format!(
        "- Current metric status: {} in retrieved source text at this UTC timestamp.",
        axis_labels.join("; ")
    )
}

fn compact_metric_focus(text: &str) -> String {
    let compact = compact_whitespace(text);
    if compact.is_empty() {
        return compact;
    }

    let focused = best_metric_segment(&compact).unwrap_or(compact);
    let focused = focused
        .trim()
        .trim_matches(|ch: char| ch == ',' || ch == ';' || ch == ':' || ch == '-' || ch == '|');
    focused
        .chars()
        .take(WEB_PIPELINE_ACTIONABLE_EXCERPT_CHARS)
        .collect()
}

fn contains_metric_signal(text: &str) -> bool {
    analyze_metric_schema(text).has_metric_payload()
}

fn metric_segment_signal_score(text: &str) -> usize {
    let schema = analyze_metric_schema(text);
    let axis_score = schema.axis_hits.len().saturating_mul(3);
    let numeric_score = schema.numeric_token_hits.min(6).saturating_mul(2);
    let unit_score = schema.unit_hits.min(4).saturating_mul(2);
    let currency_score = schema.currency_hits.min(2).saturating_mul(2);
    let observation_score = schema.observation_hits.min(3).saturating_mul(2);
    let timestamp_score = schema.timestamp_hits.min(3).saturating_mul(2);
    let horizon_penalty = schema.horizon_hits.min(3);
    let range_penalty = schema.range_hits.min(2);
    axis_score
        .saturating_add(numeric_score)
        .saturating_add(unit_score)
        .saturating_add(currency_score)
        .saturating_add(observation_score)
        .saturating_add(timestamp_score)
        .saturating_sub(horizon_penalty)
        .saturating_sub(range_penalty)
}

fn best_metric_segment(text: &str) -> Option<String> {
    let compact = compact_whitespace(text);
    if compact.is_empty() {
        return None;
    }

    let mut best: Option<(usize, usize, String)> = None;
    for segment in compact
        .split(['.', '!', '?', ';', '\n'])
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
    {
        let schema = analyze_metric_schema(segment);
        if !schema.has_metric_payload() {
            continue;
        }
        let score = metric_segment_signal_score(segment);
        let candidate = compact_whitespace(segment);
        let candidate_len = candidate.len();
        match &best {
            Some((best_score, best_len, _))
                if score < *best_score || (score == *best_score && candidate_len <= *best_len) => {}
            _ => {
                best = Some((score, candidate_len, candidate));
            }
        }
    }

    best.map(|(_, _, segment)| segment)
}

fn first_metric_sentence(text: &str) -> Option<String> {
    let compact = compact_whitespace(text);
    let mut fallback = None;
    for sentence in compact
        .split(['.', '!', '?', ';', '\n'])
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
    {
        let focused = compact_metric_focus(sentence);
        if focused.is_empty() {
            continue;
        }
        if has_quantitative_metric_payload(&focused, false) {
            return Some(focused);
        }
        if fallback.is_none() && contains_metric_signal(sentence) {
            fallback = Some(focused);
        }
    }
    fallback
}

fn looks_like_clock_time(token: &str) -> bool {
    let normalized = token.trim_matches(|ch: char| !ch.is_ascii_digit() && ch != ':');
    if normalized.is_empty() {
        return false;
    }
    let mut parts = normalized.split(':');
    let Some(hours) = parts.next() else {
        return false;
    };
    let Some(minutes) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    if hours.is_empty() || minutes.len() != 2 {
        return false;
    }
    hours.chars().all(|ch| ch.is_ascii_digit()) && minutes.chars().all(|ch| ch.is_ascii_digit())
}

fn token_is_numeric_literal(token: &str) -> bool {
    let normalized = token.trim_matches(|ch: char| {
        !ch.is_ascii_alphanumeric() && ch != '.' && ch != '-' && ch != '+'
    });
    if normalized.is_empty() || looks_like_clock_time(normalized) {
        return false;
    }
    normalized.replace(',', "").parse::<f64>().is_ok()
}

fn token_is_measurement_unit(token: &str) -> bool {
    let normalized = token.trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '/');
    if normalized.is_empty() {
        return false;
    }
    if looks_like_clock_time(normalized) {
        return false;
    }
    let schema = analyze_metric_schema(normalized);
    schema.unit_hits > 0 || schema.currency_hits > 0
}

fn token_has_inline_numeric_measurement(token: &str) -> bool {
    let normalized = token.trim_matches(|ch: char| ",.;:!?()[]{}'\"".contains(ch));
    if normalized.is_empty() || looks_like_clock_time(normalized) {
        return false;
    }
    let has_digit = normalized.chars().any(|ch| ch.is_ascii_digit());
    if !has_digit {
        return false;
    }
    if normalized.contains('\u{00b0}')
        || normalized.contains('%')
        || normalized.contains('$')
        || normalized.contains('\u{20ac}')
        || normalized.contains('\u{00a3}')
    {
        return true;
    }
    let has_alpha = normalized.chars().any(|ch| ch.is_ascii_alphabetic());
    has_alpha
}

fn has_numeric_measurement_signal(text: &str) -> bool {
    let tokens = compact_whitespace(text)
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();
    for (idx, token) in tokens.iter().enumerate() {
        if token_has_inline_numeric_measurement(token) {
            return true;
        }
        if token_is_numeric_literal(token)
            && tokens
                .get(idx + 1)
                .is_some_and(|next| token_is_measurement_unit(next))
        {
            return true;
        }
    }
    false
}

fn concise_metric_snapshot_line(metric_excerpt: &str) -> String {
    let focused = compact_metric_focus(metric_excerpt);
    if focused.is_empty() {
        return focused;
    }

    let mut tokens = Vec::new();
    for token in focused.split_whitespace() {
        let trimmed = token.trim_matches(|ch: char| matches!(ch, ',' | ';' | '|'));
        if trimmed.is_empty() {
            continue;
        }
        if looks_like_clock_time(trimmed) || trimmed.contains('/') {
            break;
        }
        tokens.push(trimmed.to_string());
        if tokens.len() >= 22 {
            break;
        }
    }

    let concise = if tokens.is_empty() {
        focused
    } else {
        tokens.join(" ")
    };
    concise
        .trim()
        .trim_matches(|ch: char| ch == ':' || ch == '-' || ch == '|')
        .to_string()
}

fn single_snapshot_metric_limitation_line(source: &PendingSearchReadSummary) -> String {
    format!(
        "Current-condition metrics were not exposed in readable source text from {} at retrieval time.",
        canonical_source_title(source)
    )
}

fn single_snapshot_best_available_with_limitation(
    source: &PendingSearchReadSummary,
    metric_excerpt: &str,
) -> String {
    if !has_quantitative_metric_payload(metric_excerpt, false) {
        return single_snapshot_metric_limitation_line(source);
    }
    let concise = concise_metric_snapshot_line(metric_excerpt);
    format!(
        "Available observed details from retrieved source text: {}. Live numeric current-condition metrics were not exposed from {} at retrieval time.",
        concise,
        canonical_source_title(source)
    )
}

fn single_snapshot_summary_line(source: &PendingSearchReadSummary) -> String {
    if let Some(metric) = first_metric_sentence(source.excerpt.as_str()) {
        if contains_current_condition_metric_signal(&metric) {
            return format!(
                "Current conditions from retrieved source text: {}",
                concise_metric_snapshot_line(&metric)
            );
        }
        if has_quantitative_metric_payload(&metric, false) {
            return single_snapshot_best_available_with_limitation(source, &metric);
        }
        return single_snapshot_metric_limitation_line(source);
    }
    let fallback =
        actionable_excerpt(source.excerpt.as_str()).unwrap_or_else(|| source_bullet(source));
    if contains_current_condition_metric_signal(&fallback) {
        return format!(
            "Current conditions from retrieved source text: {}",
            concise_metric_snapshot_line(&fallback)
        );
    }
    if has_quantitative_metric_payload(&fallback, false) {
        return single_snapshot_best_available_with_limitation(source, &fallback);
    }
    single_snapshot_metric_limitation_line(source)
}

fn metric_axis_display_label(axis: MetricAxis) -> &'static str {
    match axis {
        MetricAxis::Temperature => "Temperature",
        MetricAxis::Humidity => "Humidity",
        MetricAxis::Wind => "Wind",
        MetricAxis::Pressure => "Pressure",
        MetricAxis::Visibility => "Visibility",
        MetricAxis::AirQuality => "Air quality",
        MetricAxis::Precipitation => "Precipitation",
        MetricAxis::Price => "Price",
        MetricAxis::Rate => "Rate",
        MetricAxis::Score => "Score",
        MetricAxis::Duration => "Duration",
    }
}

fn metric_axis_display_priority(axis: MetricAxis) -> usize {
    match axis {
        MetricAxis::Temperature => 0,
        MetricAxis::Humidity => 1,
        MetricAxis::Wind => 2,
        MetricAxis::Pressure => 3,
        MetricAxis::Visibility => 4,
        MetricAxis::AirQuality => 5,
        MetricAxis::Precipitation => 6,
        MetricAxis::Price => 7,
        MetricAxis::Rate => 8,
        MetricAxis::Score => 9,
        MetricAxis::Duration => 10,
    }
}

fn axis_specific_metric_line(axis: MetricAxis, text: &str) -> Option<String> {
    let schema = analyze_metric_schema(text);
    if !schema.axis_hits.contains(&axis) || !has_quantitative_metric_payload(text, true) {
        return None;
    }
    let focused = compact_metric_focus(text);
    if focused.is_empty() || !focused.chars().any(|ch| ch.is_ascii_digit()) {
        return None;
    }
    let concise = concise_metric_snapshot_line(&focused);
    if concise.is_empty() || !concise.chars().any(|ch| ch.is_ascii_digit()) {
        return None;
    }
    Some(concise)
}

fn single_snapshot_structured_metric_lines(
    story: &StoryDraft,
    draft: &SynthesisDraft,
    required_axes: &BTreeSet<MetricAxis>,
) -> Vec<(MetricAxis, String)> {
    let mut axes = required_axes.clone();
    if axes.is_empty() {
        let mut inferred = BTreeSet::new();
        inferred.extend(analyze_metric_schema(&story.what_happened).axis_hits);
        for citation_id in &story.citation_ids {
            if let Some(citation) = draft.citations_by_id.get(citation_id) {
                let combined = format!("{} {}", citation.source_label, citation.excerpt);
                inferred.extend(analyze_metric_schema(&combined).axis_hits);
            }
        }
        axes = inferred;
    }

    let mut axis_list = axes.into_iter().collect::<Vec<_>>();
    axis_list.sort_by(|left, right| {
        metric_axis_display_priority(*left)
            .cmp(&metric_axis_display_priority(*right))
            .then_with(|| left.cmp(right))
    });

    let mut lines = Vec::new();
    let mut seen = BTreeSet::new();
    for axis in axis_list {
        let mut candidate = axis_specific_metric_line(axis, &story.what_happened);
        if candidate.is_none() {
            for citation_id in &story.citation_ids {
                let Some(citation) = draft.citations_by_id.get(citation_id) else {
                    continue;
                };
                candidate = axis_specific_metric_line(axis, &citation.excerpt);
                if candidate.is_none() {
                    let combined = format!("{} {}", citation.source_label, citation.excerpt);
                    candidate = axis_specific_metric_line(axis, &combined);
                }
                if candidate.is_some() {
                    break;
                }
            }
        }
        let Some(value) = candidate else {
            continue;
        };
        if !seen.insert(value.to_ascii_lowercase()) {
            continue;
        }
        lines.push((axis, value));
        if lines.len() >= 5 {
            break;
        }
    }

    lines
}

fn query_scope_hint(query: &str, candidate_hints: &[PendingSearchReadSummary]) -> Option<String> {
    if let Some(explicit_scope) = explicit_query_scope_hint(query) {
        return Some(explicit_scope);
    }
    let facets = analyze_query_facets(query);
    if !query_requires_locality_scope(query, &facets) {
        return None;
    }
    if let Some(scope) = effective_locality_scope_hint(None) {
        return Some(scope);
    }
    inferred_locality_scope_from_candidate_hints(query, candidate_hints)
}

fn extract_temperature_phrase(text: &str) -> Option<String> {
    let compact = compact_whitespace(text);
    if compact.is_empty() || !has_quantitative_metric_payload(&compact, true) {
        return None;
    }
    for segment in compact.split([',', ';']).map(str::trim) {
        if segment.is_empty() {
            continue;
        }
        let schema = analyze_metric_schema(segment);
        let has_numeric = segment.chars().any(|ch| ch.is_ascii_digit());
        if has_numeric && schema.axis_hits.contains(&MetricAxis::Temperature) {
            return Some(compact_whitespace(segment));
        }
    }
    for token in compact.split_whitespace() {
        let normalized = token.trim_matches(|ch: char| ",.;:!?()[]{}'\"".contains(ch));
        if normalized.is_empty() || !normalized.chars().any(|ch| ch.is_ascii_digit()) {
            continue;
        }
        let lower = normalized.to_ascii_lowercase();
        if normalized.contains('\u{00b0}') || lower.ends_with('f') || lower.ends_with('c') {
            return Some(normalized.to_string());
        }
    }
    None
}

fn compact_source_label(source_label: &str) -> String {
    let trimmed = source_label.trim();
    for separator in [" | ", " - "] {
        if let Some((head, _)) = trimmed.split_once(separator) {
            let compact = head.trim();
            if !compact.is_empty() {
                return compact.to_string();
            }
        }
    }
    trimmed.to_string()
}

fn source_consistency_note(story: &StoryDraft, draft: &SynthesisDraft) -> Option<String> {
    let labels = story
        .citation_ids
        .iter()
        .filter_map(|id| draft.citations_by_id.get(id))
        .map(|citation| compact_source_label(&citation.source_label))
        .filter(|label| !label.is_empty())
        .collect::<Vec<_>>();

    if labels.is_empty() {
        return None;
    }
    if labels.len() == 1 {
        return Some(format!(
            "(From {} — structured against available observed facets.)",
            labels[0]
        ));
    }
    Some(format!(
        "(From {} + {} — consistent on available observed facets.)",
        labels[0], labels[1]
    ))
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
    let query_contract = synthesis_query_contract(pending);
    let projection = build_query_constraint_projection(
        &query_contract,
        pending.min_sources,
        &pending.candidate_source_hints,
    );
    let enforce_grounded_compatibility = projection.enforce_grounded_compatibility();
    let reject_search_hub = projection.reject_search_hub_candidates();

    let mut merged: Vec<PendingSearchReadSummary> = Vec::new();
    let mut seen = BTreeSet::new();

    for source in &pending.successful_reads {
        let trimmed = source.url.trim();
        if trimmed.is_empty() {
            continue;
        }
        if reject_search_hub && is_search_hub_url(trimmed) {
            continue;
        }
        if enforce_grounded_compatibility {
            let compatibility = candidate_constraint_compatibility(
                &projection.constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                trimmed,
                source.title.as_deref().unwrap_or_default(),
                &source.excerpt,
            );
            if !compatibility_passes_projection(&projection, &compatibility) {
                continue;
            }
        }
        if !seen.insert(trimmed.to_string()) {
            continue;
        }
        merged.push(source.clone());
    }

    for source in &pending.candidate_source_hints {
        let trimmed = source.url.trim();
        if trimmed.is_empty() {
            continue;
        }
        if reject_search_hub && is_search_hub_url(trimmed) {
            continue;
        }
        if enforce_grounded_compatibility {
            let compatibility = candidate_constraint_compatibility(
                &projection.constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                trimmed,
                source.title.as_deref().unwrap_or_default(),
                &source.excerpt,
            );
            if !compatibility_passes_projection(&projection, &compatibility) {
                continue;
            }
        }
        if !seen.insert(trimmed.to_string()) {
            continue;
        }
        merged.push(source.clone());
    }

    for url in &pending.candidate_urls {
        let trimmed = url.trim();
        if trimmed.is_empty() {
            continue;
        }
        if reject_search_hub && is_search_hub_url(trimmed) {
            continue;
        }
        if enforce_grounded_compatibility {
            let compatibility = candidate_constraint_compatibility(
                &projection.constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                trimmed,
                "",
                "",
            );
            if !compatibility_passes_projection(&projection, &compatibility) {
                continue;
            }
        }
        if !seen.insert(trimmed.to_string()) {
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

fn grounded_source_evidence_count(pending: &PendingSearchCompletion) -> usize {
    let query_contract = synthesis_query_contract(pending);
    let projection = build_query_constraint_projection(
        &query_contract,
        pending.min_sources,
        &pending.candidate_source_hints,
    );
    let enforce_grounded_compatibility = projection.enforce_grounded_compatibility();
    let reject_search_hub = projection.reject_search_hub_candidates();
    let has_constraint_objective = projection.has_constraint_objective();
    let envelope_constraints = &projection.constraints;
    let envelope_policy = ResolutionPolicy::default();

    let mut grounded_urls: BTreeSet<String> = BTreeSet::new();

    for source in &pending.successful_reads {
        let trimmed = source.url.trim();
        if trimmed.is_empty() {
            continue;
        }
        if reject_search_hub && is_search_hub_url(trimmed) {
            continue;
        }
        if enforce_grounded_compatibility {
            let compatibility = candidate_constraint_compatibility(
                &projection.constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                trimmed,
                source.title.as_deref().unwrap_or_default(),
                &source.excerpt,
            );
            if !compatibility_passes_projection(&projection, &compatibility) {
                continue;
            }
        }
        if has_constraint_objective {
            let title = source.title.as_deref().unwrap_or_default();
            let score = single_snapshot_candidate_envelope_score(
                envelope_constraints,
                envelope_policy,
                trimmed,
                title,
                &source.excerpt,
            );
            if !envelope_score_resolves_constraint(envelope_constraints, &score) {
                continue;
            }
        }
        grounded_urls.insert(trimmed.to_string());
    }

    for source in &pending.candidate_source_hints {
        let trimmed = source.url.trim();
        if trimmed.is_empty() {
            continue;
        }
        if reject_search_hub && is_search_hub_url(trimmed) {
            continue;
        }
        if enforce_grounded_compatibility {
            let compatibility = candidate_constraint_compatibility(
                &projection.constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                trimmed,
                source.title.as_deref().unwrap_or_default(),
                &source.excerpt,
            );
            if !compatibility_passes_projection(&projection, &compatibility) {
                continue;
            }
        }
        if has_constraint_objective {
            let title = source.title.as_deref().unwrap_or_default();
            let score = single_snapshot_candidate_envelope_score(
                envelope_constraints,
                envelope_policy,
                trimmed,
                title,
                &source.excerpt,
            );
            if !envelope_score_resolves_constraint(envelope_constraints, &score) {
                continue;
            }
        } else {
            let has_signal = !source.excerpt.trim().is_empty()
                || source
                    .title
                    .as_deref()
                    .map(|value| !value.trim().is_empty())
                    .unwrap_or(false);
            if !has_signal {
                continue;
            }
        }
        grounded_urls.insert(trimmed.to_string());
    }

    grounded_urls.len()
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
    let query_contract = synthesis_query_contract(pending);
    let mut merged = merged_story_sources(pending);
    let minimum_candidate_floor =
        (pending.min_sources.max(1) as usize).max(required_citations_per_story(&query_contract));
    if merged.len() < minimum_candidate_floor {
        let projection = build_query_constraint_projection(
            &query_contract,
            pending.min_sources,
            &pending.candidate_source_hints,
        );
        let reject_search_hub = projection.reject_search_hub_candidates();
        let has_non_search_hub_inventory = pending
            .successful_reads
            .iter()
            .map(|source| source.url.as_str())
            .chain(
                pending
                    .candidate_source_hints
                    .iter()
                    .map(|source| source.url.as_str()),
            )
            .chain(pending.candidate_urls.iter().map(|url| url.as_str()))
            .chain(pending.attempted_urls.iter().map(|url| url.as_str()))
            .chain(std::iter::once(pending.url.as_str()))
            .map(str::trim)
            .any(|url| !url.is_empty() && !is_search_hub_url(url));
        let allow_query_search_hub_provenance = reject_search_hub
            && pending.successful_reads.is_empty()
            && !has_non_search_hub_inventory;
        let mut seen_urls = merged
            .iter()
            .map(|source| source.url.trim().to_string())
            .filter(|url| !url.is_empty())
            .collect::<BTreeSet<_>>();
        let mut fallback_pool = Vec::new();
        fn push_fallback_source(
            seen_urls: &mut BTreeSet<String>,
            fallback_pool: &mut Vec<PendingSearchReadSummary>,
            source: PendingSearchReadSummary,
            reject_search_hub: bool,
            allow_search_hub: bool,
        ) {
            let trimmed = source.url.trim();
            if trimmed.is_empty()
                || (!allow_search_hub && reject_search_hub && is_search_hub_url(trimmed))
                || !seen_urls.insert(trimmed.to_string())
            {
                return;
            }
            fallback_pool.push(source);
        }

        for source in pending
            .successful_reads
            .iter()
            .chain(pending.candidate_source_hints.iter())
        {
            push_fallback_source(
                &mut seen_urls,
                &mut fallback_pool,
                source.clone(),
                reject_search_hub,
                false,
            );
        }
        for url in pending
            .attempted_urls
            .iter()
            .chain(pending.candidate_urls.iter())
            .chain(std::iter::once(&pending.url))
        {
            let trimmed = url.trim();
            if trimmed.is_empty() {
                continue;
            }
            let allow_search_hub = allow_query_search_hub_provenance
                && pending.url.trim().eq_ignore_ascii_case(trimmed);
            push_fallback_source(
                &mut seen_urls,
                &mut fallback_pool,
                PendingSearchReadSummary {
                    url: trimmed.to_string(),
                    title: None,
                    excerpt: String::new(),
                },
                reject_search_hub,
                allow_search_hub,
            );
        }

        if reject_search_hub && merged.len().saturating_add(fallback_pool.len()) < minimum_candidate_floor
        {
            let query_provenance_url = std::iter::once(pending.url.as_str())
                .chain(pending.attempted_urls.iter().map(|url| url.as_str()))
                .map(str::trim)
                .find(|url| !url.is_empty() && is_search_hub_url(url));
            if let Some(query_provenance_url) = query_provenance_url {
                if seen_urls.insert(query_provenance_url.to_string()) {
                    fallback_pool.push(PendingSearchReadSummary {
                        url: query_provenance_url.to_string(),
                        title: None,
                        excerpt: String::new(),
                    });
                }
            }
        }

        if fallback_pool.is_empty() && merged.is_empty() {
            for source in pending
                .successful_reads
                .iter()
                .chain(pending.candidate_source_hints.iter())
            {
                push_fallback_source(
                    &mut seen_urls,
                    &mut fallback_pool,
                    source.clone(),
                    reject_search_hub,
                    true,
                );
            }
            for url in pending
                .attempted_urls
                .iter()
                .chain(pending.candidate_urls.iter())
                .chain(std::iter::once(&pending.url))
            {
                let trimmed = url.trim();
                if trimmed.is_empty() {
                    continue;
                }
                push_fallback_source(
                    &mut seen_urls,
                    &mut fallback_pool,
                    PendingSearchReadSummary {
                        url: trimmed.to_string(),
                        title: None,
                        excerpt: String::new(),
                    },
                    reject_search_hub,
                    true,
                );
            }
        }

        let mut ranked_fallback = fallback_pool
            .into_iter()
            .enumerate()
            .map(|(idx, source)| {
                let title = source.title.as_deref().unwrap_or_default();
                let source_tokens = source_anchor_tokens(&source.url, title, &source.excerpt);
                let native_overlap_count = projection
                    .query_native_tokens
                    .intersection(&source_tokens)
                    .count();
                let compatibility = candidate_constraint_compatibility(
                    &projection.constraints,
                    &projection.query_facets,
                    &projection.query_native_tokens,
                    &projection.query_tokens,
                    &projection.locality_tokens,
                    projection.locality_scope.is_some(),
                    &source.url,
                    title,
                    &source.excerpt,
                );
                let resolvable_payload =
                    candidate_time_sensitive_resolvable_payload(title, &source.excerpt);
                (
                    idx,
                    source,
                    compatibility,
                    native_overlap_count,
                    resolvable_payload,
                )
            })
            .collect::<Vec<_>>();
        ranked_fallback.sort_by(|left, right| {
            right
                .4
                .cmp(&left.4)
                .then_with(|| right.3.cmp(&left.3))
                .then_with(|| {
                    let right_passes = compatibility_passes_projection(&projection, &right.2);
                    let left_passes = compatibility_passes_projection(&projection, &left.2);
                    right_passes.cmp(&left_passes)
                })
                .then_with(|| right.2.compatibility_score.cmp(&left.2.compatibility_score))
                .then_with(|| left.0.cmp(&right.0))
        });
        let enforce_grounded_compatibility = projection.enforce_grounded_compatibility();
        let strict_grounded_compatibility = projection.strict_grounded_compatibility();
        let has_compatible_fallback = ranked_fallback.iter().any(|(_, _, compatibility, _, _)| {
            compatibility_passes_projection(&projection, compatibility)
        });
        let require_native_overlap = !projection.query_native_tokens.is_empty()
            && ranked_fallback
                .iter()
                .any(|(_, _, _, native_overlap, _)| *native_overlap > 0);
        for pass in 0..2 {
            for (_, source, compatibility, native_overlap_count, _) in ranked_fallback.iter() {
                if merged.len() >= minimum_candidate_floor {
                    break;
                }
                if strict_grounded_compatibility
                    && has_compatible_fallback
                    && !compatibility_passes_projection(&projection, compatibility)
                {
                    continue;
                }
                if enforce_grounded_compatibility
                    && has_compatible_fallback
                    && !compatibility_passes_projection(&projection, compatibility)
                {
                    continue;
                }
                if pass == 0 && require_native_overlap && *native_overlap_count == 0 {
                    continue;
                }
                if pass == 1 && (!require_native_overlap || *native_overlap_count > 0) {
                    continue;
                }
                let url = source.url.trim();
                if url.is_empty()
                    || merged
                        .iter()
                        .any(|existing| existing.url.trim().eq_ignore_ascii_case(url))
                {
                    continue;
                }
                merged.push(source.clone());
            }
            if merged.len() >= minimum_candidate_floor {
                break;
            }
        }
    }

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
            let excerpt = {
                let prioritized = prioritized_signal_excerpt(source.excerpt.as_str(), 180);
                if prioritized.is_empty() || !excerpt_has_claim_signal(&prioritized) {
                    String::new()
                } else {
                    prioritized
                }
            };
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

fn citation_metric_signal(candidate: &CitationCandidate) -> bool {
    contains_metric_signal(&candidate.excerpt)
        || contains_metric_signal(&format!(
            "{} {} {}",
            candidate.source_label, candidate.excerpt, candidate.url
        ))
}

fn citation_current_condition_metric_signal(candidate: &CitationCandidate) -> bool {
    contains_current_condition_metric_signal(&candidate.excerpt)
        || contains_current_condition_metric_signal(&format!(
            "{} {} {}",
            candidate.source_label, candidate.excerpt, candidate.url
        ))
}

fn citation_single_snapshot_evidence_score(
    candidate: &CitationCandidate,
    envelope_constraints: &ConstraintSet,
    envelope_policy: ResolutionPolicy,
) -> CandidateEvidenceScore {
    single_snapshot_candidate_envelope_score(
        envelope_constraints,
        envelope_policy,
        &candidate.url,
        &candidate.source_label,
        &candidate.excerpt,
    )
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
    prefer_host_diversity: bool,
    envelope_constraints: &ConstraintSet,
    envelope_policy: ResolutionPolicy,
) -> Vec<String> {
    if candidates.is_empty() {
        return Vec::new();
    }

    let mut ranked = candidates
        .iter()
        .enumerate()
        .map(|(idx, candidate)| {
            let signals = citation_source_signals(candidate);
            let envelope_score = if prefer_host_diversity {
                citation_single_snapshot_evidence_score(
                    candidate,
                    envelope_constraints,
                    envelope_policy,
                )
            } else {
                CandidateEvidenceScore::default()
            };
            (idx, signals, envelope_score)
        })
        .collect::<Vec<_>>();
    ranked.sort_by(
        |(left_idx, left_signals, left_envelope), (right_idx, right_signals, right_envelope)| {
            let left = &candidates[*left_idx];
            let right = &candidates[*right_idx];
            let envelope_order = if prefer_host_diversity {
                compare_candidate_evidence_scores_desc(left_envelope, right_envelope)
            } else {
                std::cmp::Ordering::Equal
            };
            let left_key = (
                prefer_host_diversity
                    && envelope_score_resolves_constraint(envelope_constraints, left_envelope),
                citation_metric_signal(left),
                left_signals.official_status_host_hits > 0,
                left_signals.official_status_host_hits,
                left_signals.primary_status_surface_hits > 0,
                left_signals.primary_status_surface_hits,
                left_signals.secondary_coverage_hits == 0,
                left_signals.documentation_surface_hits == 0,
                citation_relevance_score(source, left),
                !is_low_priority_coverage_candidate(left),
                left.from_successful_read,
            );
            let right_key = (
                prefer_host_diversity
                    && envelope_score_resolves_constraint(envelope_constraints, right_envelope),
                citation_metric_signal(right),
                right_signals.official_status_host_hits > 0,
                right_signals.official_status_host_hits,
                right_signals.primary_status_surface_hits > 0,
                right_signals.primary_status_surface_hits,
                right_signals.secondary_coverage_hits == 0,
                right_signals.documentation_surface_hits == 0,
                citation_relevance_score(source, right),
                !is_low_priority_coverage_candidate(right),
                right.from_successful_read,
            );
            envelope_order.then_with(|| right_key.cmp(&left_key))
        },
    );

    let primary_status_candidates = ranked
        .iter()
        .filter(|(idx, signals, _)| {
            has_primary_status_authority(*signals) && !used_urls.contains(&candidates[*idx].url)
        })
        .count();
    let require_primary_status = primary_status_candidates >= citations_per_story;

    let host_inventory = ranked
        .iter()
        .filter_map(|(idx, signals, envelope_score)| {
            if require_primary_status && !has_primary_status_authority(*signals) {
                return None;
            }
            let candidate = &candidates[*idx];
            if used_urls.contains(&candidate.url) {
                return None;
            }
            if prefer_host_diversity
                && !envelope_score_resolves_constraint(envelope_constraints, envelope_score)
            {
                return None;
            }
            source_host(&candidate.url)
        })
        .collect::<BTreeSet<_>>();
    let require_host_diversity =
        prefer_host_diversity && host_inventory.len() >= citations_per_story;

    let mut selected_ids = Vec::new();
    let mut selected_urls = BTreeSet::new();
    let mut selected_hosts = BTreeSet::new();

    for (idx, signals, _) in &ranked {
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
        if require_host_diversity {
            if let Some(host) = source_host(&candidate.url) {
                if selected_hosts.contains(&host) {
                    continue;
                }
                selected_hosts.insert(host);
            }
        }
        selected_ids.push(candidate.id.clone());
        selected_urls.insert(candidate.url.clone());
        used_urls.insert(candidate.url.clone());
    }

    if selected_ids.len() < citations_per_story {
        for (idx, _, _) in &ranked {
            if selected_ids.len() >= citations_per_story {
                break;
            }
            let candidate = &candidates[*idx];
            if selected_urls.contains(&candidate.url)
                || selected_ids.iter().any(|id| id == &candidate.id)
            {
                continue;
            }
            if require_host_diversity {
                if let Some(host) = source_host(&candidate.url) {
                    if selected_hosts.contains(&host) {
                        continue;
                    }
                    selected_hosts.insert(host);
                }
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
    let single_snapshot_mode = prefers_single_fact_snapshot(&query);
    let required_story_count = required_story_count(&query);
    let citations_per_story = required_citations_per_story(&query);
    let single_snapshot_policy = ResolutionPolicy::default();
    let completion_reason = completion_reason_line(reason).to_string();
    let partial_note = {
        let min_sources = pending.min_sources.max(1) as usize;
        let grounded_sources = grounded_source_evidence_count(pending);
        (pending.successful_reads.len() < min_sources && grounded_sources < min_sources).then(
            || {
                format!(
                    "Partial evidence: confirmed readable sources={} while floor={}.",
                    pending.successful_reads.len(),
                    min_sources
                )
            },
        )
    };

    let candidates = build_citation_candidates(pending, &run_timestamp_iso_utc);
    let mut citations_by_id = BTreeMap::new();
    for candidate in &candidates {
        citations_by_id.insert(candidate.id.clone(), candidate.clone());
    }

    let mut stories = Vec::new();
    let merged_sources = merged_story_sources(pending);
    let single_snapshot_constraints = single_snapshot_constraint_set_with_hints(
        &query,
        citations_per_story.max(1),
        &merged_sources,
    );
    let primary_status_sources = merged_sources
        .iter()
        .filter(|source| is_primary_status_surface_source(source))
        .cloned()
        .collect::<Vec<_>>();
    let source_pool = if single_snapshot_mode {
        let mut ranked = merged_sources.clone();
        ranked.sort_by(|left, right| {
            compare_candidate_evidence_scores_desc(
                &single_snapshot_source_score(
                    left,
                    &single_snapshot_constraints,
                    single_snapshot_policy,
                ),
                &single_snapshot_source_score(
                    right,
                    &single_snapshot_constraints,
                    single_snapshot_policy,
                ),
            )
            .then_with(|| left.url.cmp(&right.url))
        });
        ranked
    } else if primary_status_sources.len() >= required_story_count {
        primary_status_sources
    } else {
        merged_sources.clone()
    };
    let mut selected_sources = Vec::new();
    for source in &source_pool {
        if single_snapshot_mode && is_low_signal_excerpt(source.excerpt.as_str()) {
            continue;
        }
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
        let what_happened = if single_snapshot_mode {
            single_snapshot_summary_line(source)
        } else {
            source_bullet(source)
        };
        let why_it_matters = why_it_matters_from_story(source);
        let user_impact = user_impact_from_story(source);
        let workaround = workaround_from_story(source);
        let changed_last_hour = changed_last_hour_line(source, &run_timestamp_iso_utc);
        let citation_ids = citation_ids_for_story(
            source,
            &candidates,
            &mut used_urls,
            citations_per_story,
            single_snapshot_mode,
            &single_snapshot_constraints,
            single_snapshot_policy,
        );
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
            single_snapshot_mode,
            &single_snapshot_constraints,
            single_snapshot_policy,
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
    let use_single_snapshot_layout = story_count == 1 && prefers_single_fact_snapshot(&draft.query);
    let single_snapshot_query_axes = query_metric_axes(&draft.query);

    if use_single_snapshot_layout {
        let scope_candidate_hints = draft
            .citations_by_id
            .values()
            .map(|citation| PendingSearchReadSummary {
                url: citation.url.clone(),
                title: Some(citation.source_label.clone()),
                excerpt: citation.excerpt.clone(),
            })
            .collect::<Vec<_>>();
        let heading = if let Some(scope) = query_scope_hint(&draft.query, &scope_candidate_hints) {
            format!(
                "Right now in {} (as of {} UTC):",
                scope, draft.run_timestamp_iso_utc
            )
        } else {
            format!("Right now (as of {} UTC):", draft.run_timestamp_iso_utc)
        };
        lines.push(heading);

        if let Some(story) = draft.stories.first() {
            lines.push(String::new());
            let metric_lines =
                single_snapshot_structured_metric_lines(story, draft, &single_snapshot_query_axes);
            let citation_current_metric = story
                .citation_ids
                .iter()
                .filter_map(|id| draft.citations_by_id.get(id))
                .find_map(|citation| {
                    let citation_text =
                        format!("{} {}", citation.source_label, citation.excerpt.trim());
                    first_metric_sentence(&citation_text).filter(|metric| {
                        contains_current_condition_metric_signal(metric)
                    })
                });
            let citation_partial_metric = story
                .citation_ids
                .iter()
                .filter_map(|id| draft.citations_by_id.get(id))
                .find_map(|citation| {
                    let citation_text =
                        format!("{} {}", citation.source_label, citation.excerpt.trim());
                    first_metric_sentence(&citation_text)
                        .filter(|metric| has_quantitative_metric_payload(metric, false))
                });
            let temperature_phrase = metric_lines.iter().find_map(|(axis, value)| {
                (*axis == MetricAxis::Temperature)
                    .then(|| extract_temperature_phrase(value))
                    .flatten()
            });
            let first_metric_value = metric_lines
                .first()
                .map(|(_, value)| concise_metric_snapshot_line(value));
            let story_has_quantitative_metric_signal = !metric_lines.is_empty()
                || has_quantitative_metric_payload(&story.what_happened, false)
                || citation_current_metric
                    .as_deref()
                    .map(|metric| has_quantitative_metric_payload(metric, false))
                    .unwrap_or(false)
                || citation_partial_metric
                    .as_deref()
                    .map(|metric| has_quantitative_metric_payload(metric, false))
                    .unwrap_or(false);
            let summary_line = if let Some(temp) = temperature_phrase {
                format!("Current conditions: It's **{}**.", temp)
            } else if contains_current_condition_metric_signal(&story.what_happened) {
                format!(
                    "Current conditions from retrieved source text: {}",
                    concise_metric_snapshot_line(&story.what_happened)
                )
            } else if let Some(value) = first_metric_value {
                format!("Current conditions from retrieved source text: {}", value)
            } else if let Some(metric) = citation_current_metric.as_deref() {
                format!(
                    "Current conditions from cited source text: {}",
                    concise_metric_snapshot_line(metric)
                )
            } else if let Some(metric) = citation_partial_metric.as_deref() {
                format!(
                    "Available observed details from cited source text: {}",
                    concise_metric_snapshot_line(metric)
                )
            } else {
                "Current conditions: Current-condition metrics were not exposed in retrieved source text at this UTC timestamp.".to_string()
            };
            let summary_line_lower = summary_line.to_ascii_lowercase();
            let summary_line_has_metric_limitation =
                summary_line_lower.contains("current-condition metrics were not exposed");
            lines.push(summary_line);

            if !metric_lines.is_empty() {
                lines.push(String::new());
                for (axis, value) in metric_lines {
                    lines.push(format!("- {}: {}", metric_axis_display_label(axis), value));
                }
            }

            if let Some(note) = source_consistency_note(story, draft) {
                lines.push(String::new());
                lines.push(note);
            }

            let citation_current_condition_signal = story
                .citation_ids
                .iter()
                .filter_map(|id| draft.citations_by_id.get(id))
                .any(citation_current_condition_metric_signal);
            let envelope_sources = story
                .citation_ids
                .iter()
                .filter_map(|id| draft.citations_by_id.get(id))
                .map(|citation| PendingSearchReadSummary {
                    url: citation.url.clone(),
                    title: Some(citation.source_label.clone()),
                    excerpt: citation.excerpt.clone(),
                })
                .collect::<Vec<_>>();
            let envelope_constraints = compile_constraint_set(
                &draft.query,
                single_snapshot_query_axes.clone(),
                citations_per_story.max(1),
            );
            let envelope_verification = verify_claim_envelope(
                &envelope_constraints,
                &envelope_sources,
                &draft.run_timestamp_iso_utc,
                ResolutionPolicy::default(),
            );
            let unresolved_axes = if envelope_verification.unresolved_facets.is_empty() {
                single_snapshot_query_axes.clone()
            } else {
                envelope_verification.unresolved_facets.clone()
            };
            let envelope_requires_caveat = matches!(
                envelope_verification.status,
                Some(EnvelopeStatus::ValidWithCaveats | EnvelopeStatus::Invalid)
            );
            let summary_has_current_metric_signal =
                contains_current_condition_metric_signal(&story.what_happened);
            let summary_has_metric_limitation = story
                .what_happened
                .to_ascii_lowercase()
                .contains("current-condition metrics were not exposed");
            let needs_followup_guidance = envelope_requires_caveat
                || summary_line_has_metric_limitation
                || summary_has_metric_limitation
                || draft.partial_note.is_some()
                || (!summary_has_current_metric_signal
                    && !citation_current_condition_signal
                    && !story_has_quantitative_metric_signal);
            if needs_followup_guidance {
                lines.push(
                    "- Estimated-right-now: derived from cited forecast range was unavailable in retrieved source text."
                        .to_string(),
                );
                if unresolved_axes.is_empty() && story_has_quantitative_metric_signal {
                    lines.push("- Current metric status: partial live current-observation values were available in retrieved source text at this UTC timestamp.".to_string());
                } else {
                    lines.push(single_snapshot_metric_status_line(&unresolved_axes));
                }
                if story_has_quantitative_metric_signal {
                    lines.push("- Data caveat: Retrieved source snippets exposed partial numeric current-condition metrics; complete live fields may still be unavailable at this UTC timestamp.".to_string());
                } else {
                    lines.push("- Data caveat: Retrieved source snippets did not expose numeric current-condition metrics at this UTC timestamp.".to_string());
                }
                if let Some(primary_citation) = story
                    .citation_ids
                    .iter()
                    .filter_map(|id| draft.citations_by_id.get(id))
                    .next()
                {
                    lines.push(format!(
                        "- Next step: Open {} for live current-condition metrics (temperature, feels-like, humidity, wind).",
                        primary_citation.url
                    ));
                } else {
                    lines.push(
                        "- Next step: Open the cited sources for live current-condition metrics."
                            .to_string(),
                    );
                }
            }

            lines.push(String::new());
            lines.push("Citations:".to_string());
            let mut emitted = 0usize;
            let mut seen_urls = BTreeSet::new();
            for citation_id in story.citation_ids.iter().take(citations_per_story) {
                if let Some(citation) = draft.citations_by_id.get(citation_id) {
                    if !seen_urls.insert(citation.url.clone()) {
                        continue;
                    }
                    let note = if citation.excerpt.trim().is_empty() {
                        citation.note.clone()
                    } else {
                        format!("{} | excerpt: {}", citation.note, citation.excerpt)
                    };
                    lines.push(format!(
                        "- {} | {} | {} | {}",
                        citation.source_label, citation.url, citation.timestamp_utc, note
                    ));
                    emitted += 1;
                }
            }
            if emitted < citations_per_story {
                for citation in draft.citations_by_id.values() {
                    if emitted >= citations_per_story {
                        break;
                    }
                    if !seen_urls.insert(citation.url.clone()) {
                        continue;
                    }
                    let note = if citation.excerpt.trim().is_empty() {
                        citation.note.clone()
                    } else {
                        format!("{} | excerpt: {}", citation.note, citation.excerpt)
                    };
                    lines.push(format!(
                        "- {} | {} | {} | {}",
                        citation.source_label, citation.url, citation.timestamp_utc, note
                    ));
                    emitted += 1;
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
        return lines.join("\n");
    }

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
