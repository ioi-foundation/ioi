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
