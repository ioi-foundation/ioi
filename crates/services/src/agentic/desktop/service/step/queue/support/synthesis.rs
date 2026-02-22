use super::*;

pub(crate) fn confidence_tier(
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

pub(crate) fn completion_reason_line(reason: WebPipelineCompletionReason) -> &'static str {
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

pub(crate) fn excerpt_headline(excerpt: &str) -> Option<String> {
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

pub(crate) fn source_bullet(source: &PendingSearchReadSummary) -> String {
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

pub(crate) fn single_snapshot_source_score(
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

pub(crate) fn has_quantitative_metric_payload(
    text: &str,
    require_current_observation: bool,
) -> bool {
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

pub(crate) fn contains_current_condition_metric_signal(text: &str) -> bool {
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

pub(crate) fn metric_axis_unavailable_label(axis: MetricAxis) -> &'static str {
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

pub(crate) fn single_snapshot_metric_status_line(required_axes: &BTreeSet<MetricAxis>) -> String {
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

pub(crate) fn compact_metric_focus(text: &str) -> String {
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

pub(crate) fn contains_metric_signal(text: &str) -> bool {
    analyze_metric_schema(text).has_metric_payload()
}

pub(crate) fn metric_segment_signal_score(text: &str) -> usize {
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

pub(crate) fn best_metric_segment(text: &str) -> Option<String> {
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

pub(crate) fn first_metric_sentence(text: &str) -> Option<String> {
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

pub(crate) fn looks_like_clock_time(token: &str) -> bool {
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

pub(crate) fn token_is_numeric_literal(token: &str) -> bool {
    let normalized = token.trim_matches(|ch: char| {
        !ch.is_ascii_alphanumeric() && ch != '.' && ch != '-' && ch != '+'
    });
    if normalized.is_empty() || looks_like_clock_time(normalized) {
        return false;
    }
    normalized.replace(',', "").parse::<f64>().is_ok()
}

pub(crate) fn token_is_measurement_unit(token: &str) -> bool {
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

pub(crate) fn token_has_inline_numeric_measurement(token: &str) -> bool {
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

pub(crate) fn has_numeric_measurement_signal(text: &str) -> bool {
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

pub(crate) fn concise_metric_snapshot_line(metric_excerpt: &str) -> String {
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

pub(crate) fn single_snapshot_metric_limitation_line(source: &PendingSearchReadSummary) -> String {
    format!(
        "Current-condition metrics were not exposed in readable source text from {} at retrieval time.",
        canonical_source_title(source)
    )
}

pub(crate) fn single_snapshot_best_available_with_limitation(
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

pub(crate) fn single_snapshot_summary_line(source: &PendingSearchReadSummary) -> String {
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

pub(crate) fn metric_axis_display_label(axis: MetricAxis) -> &'static str {
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

pub(crate) fn metric_axis_display_priority(axis: MetricAxis) -> usize {
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

pub(crate) fn axis_specific_metric_line(axis: MetricAxis, text: &str) -> Option<String> {
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

pub(crate) fn single_snapshot_structured_metric_lines(
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

pub(crate) fn query_scope_hint(
    query: &str,
    candidate_hints: &[PendingSearchReadSummary],
) -> Option<String> {
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

pub(crate) fn extract_temperature_phrase(text: &str) -> Option<String> {
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

pub(crate) fn compact_source_label(source_label: &str) -> String {
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

pub(crate) fn source_consistency_note(
    story: &StoryDraft,
    draft: &SynthesisDraft,
) -> Option<String> {
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
pub(crate) struct CitationCandidate {
    pub(crate) id: String,
    pub(crate) url: String,
    pub(crate) source_label: String,
    pub(crate) excerpt: String,
    pub(crate) timestamp_utc: String,
    pub(crate) note: String,
    pub(crate) from_successful_read: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct StoryDraft {
    pub(crate) title: String,
    pub(crate) what_happened: String,
    pub(crate) changed_last_hour: String,
    pub(crate) why_it_matters: String,
    pub(crate) user_impact: String,
    pub(crate) workaround: String,
    pub(crate) eta_confidence: String,
    pub(crate) citation_ids: Vec<String>,
    pub(crate) confidence: String,
    pub(crate) caveat: String,
}

#[derive(Debug, Clone)]
pub(crate) struct SynthesisDraft {
    pub(crate) query: String,
    pub(crate) run_date: String,
    pub(crate) run_timestamp_ms: u64,
    pub(crate) run_timestamp_iso_utc: String,
    pub(crate) completion_reason: String,
    pub(crate) overall_confidence: String,
    pub(crate) overall_caveat: String,
    pub(crate) stories: Vec<StoryDraft>,
    pub(crate) citations_by_id: BTreeMap<String, CitationCandidate>,
    pub(crate) blocked_urls: Vec<String>,
    pub(crate) partial_note: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct HybridSynthesisPayload {
    query: String,
    run_timestamp_ms: u64,
    run_timestamp_iso_utc: String,
    completion_reason: String,
    required_sections: Vec<HybridSectionSpec>,
    citation_candidates: Vec<HybridCitationCandidate>,
    deterministic_story_drafts: Vec<HybridStoryDraft>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct HybridSectionSpec {
    key: String,
    label: String,
    required: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct HybridCitationCandidate {
    id: String,
    url: String,
    source_label: String,
    excerpt: String,
    timestamp_utc: String,
    note: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct HybridStoryDraft {
    title: String,
    sections: Vec<HybridSectionDraft>,
    citation_ids: Vec<String>,
    confidence: String,
    caveat: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct HybridSectionDraft {
    key: String,
    label: String,
    content: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct HybridSynthesisResponse {
    #[serde(default)]
    heading: String,
    items: Vec<HybridItemResponse>,
    #[serde(default)]
    overall_confidence: String,
    #[serde(default)]
    overall_caveat: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct HybridItemResponse {
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
pub(crate) struct HybridSectionResponse {
    #[serde(default)]
    key: String,
    label: String,
    #[serde(default)]
    content: String,
}

pub(crate) fn title_tokens(input: &str) -> BTreeSet<String> {
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

pub(crate) fn titles_similar(a: &str, b: &str) -> bool {
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

pub(crate) fn canonical_source_title(source: &PendingSearchReadSummary) -> String {
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

pub(crate) fn merged_story_sources(
    pending: &PendingSearchCompletion,
) -> Vec<PendingSearchReadSummary> {
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

pub(crate) fn grounded_source_evidence_count(pending: &PendingSearchCompletion) -> usize {
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

pub(crate) fn is_primary_status_surface_source(source: &PendingSearchReadSummary) -> bool {
    let signals = source_evidence_signals(source);
    has_primary_status_authority(signals) && !signals.low_priority_dominates()
}

pub(crate) fn why_it_matters_from_story(source: &PendingSearchReadSummary) -> String {
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

pub(crate) fn user_impact_from_story(source: &PendingSearchReadSummary) -> String {
    why_it_matters_from_story(source)
}

pub(crate) fn workaround_from_story(source: &PendingSearchReadSummary) -> String {
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

pub(crate) fn eta_confidence_from_story(
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

pub(crate) fn changed_last_hour_line(
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

pub(crate) fn build_citation_candidates(
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

        if reject_search_hub
            && merged.len().saturating_add(fallback_pool.len()) < minimum_candidate_floor
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

pub(crate) fn title_overlap_score(a: &str, b: &str) -> usize {
    let a_tokens = title_tokens(a);
    let b_tokens = title_tokens(b);
    if a_tokens.is_empty() || b_tokens.is_empty() {
        return 0;
    }
    a_tokens.intersection(&b_tokens).count()
}

pub(crate) fn citation_relevance_score(
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

pub(crate) fn citation_metric_signal(candidate: &CitationCandidate) -> bool {
    contains_metric_signal(&candidate.excerpt)
        || contains_metric_signal(&format!(
            "{} {} {}",
            candidate.source_label, candidate.excerpt, candidate.url
        ))
}

pub(crate) fn citation_current_condition_metric_signal(candidate: &CitationCandidate) -> bool {
    contains_current_condition_metric_signal(&candidate.excerpt)
        || contains_current_condition_metric_signal(&format!(
            "{} {} {}",
            candidate.source_label, candidate.excerpt, candidate.url
        ))
}

pub(crate) fn citation_single_snapshot_evidence_score(
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

pub(crate) fn citation_source_signals(candidate: &CitationCandidate) -> SourceSignalProfile {
    analyze_source_record_signals(&candidate.url, &candidate.source_label, &candidate.excerpt)
}

pub(crate) fn is_low_priority_coverage_candidate(candidate: &CitationCandidate) -> bool {
    citation_source_signals(candidate).low_priority_dominates()
}

pub(crate) fn citation_ids_for_story(
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

pub(crate) fn build_deterministic_story_draft(
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

pub(crate) fn render_synthesis_draft(draft: &SynthesisDraft) -> String {
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
                    first_metric_sentence(&citation_text)
                        .filter(|metric| contains_current_condition_metric_signal(metric))
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

pub(crate) fn extract_json_object(raw: &str) -> Option<&str> {
    let start = raw.find('{')?;
    let end = raw.rfind('}')?;
    (end >= start).then_some(&raw[start..=end])
}

pub(crate) fn is_iso_utc_datetime(value: &str) -> bool {
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

pub(crate) fn normalize_section_key(label: &str) -> String {
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

pub(crate) fn dedupe_labels(labels: Vec<String>) -> Vec<String> {
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

pub(crate) fn required_section_labels_for_query(query: &str) -> Vec<String> {
    dedupe_labels(
        infer_report_sections(query)
            .into_iter()
            .map(|kind| report_section_label(kind, query))
            .collect(),
    )
}

pub(crate) fn build_hybrid_required_sections(query: &str) -> Vec<HybridSectionSpec> {
    required_section_labels_for_query(query)
        .into_iter()
        .map(|label| HybridSectionSpec {
            key: normalize_section_key(&label),
            label,
            required: true,
        })
        .collect()
}

pub(crate) fn section_kind_from_key(key: &str) -> Option<ReportSectionKind> {
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

pub(crate) fn section_content_for_story(
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

pub(crate) fn section_content_from_map(
    sections: &BTreeMap<String, String>,
    keys: &[&str],
) -> Option<String> {
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

pub(crate) fn section_content_from_map_for_kind(
    sections: &BTreeMap<String, String>,
    kind: ReportSectionKind,
) -> Option<String> {
    section_content_from_map(sections, report_section_aliases(kind))
}

pub(crate) fn apply_hybrid_synthesis_response(
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
