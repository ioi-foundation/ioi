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
    if looks_like_structured_metadata_noise(trimmed) {
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
    } else if let Some(display_name) = local_business_detail_display_name(source, None) {
        display_name
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

pub(crate) fn source_bullet_for_query(
    query_contract: &str,
    min_sources: usize,
    source: &PendingSearchReadSummary,
) -> String {
    source_bullet_for_query_with_contract(None, query_contract, min_sources, source)
}

pub(crate) fn source_bullet_for_query_with_contract(
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    query_contract: &str,
    min_sources: usize,
    source: &PendingSearchReadSummary,
) -> String {
    let headline = canonical_source_title_for_query(query_contract, source);
    let title = source.title.as_deref().map(str::trim).unwrap_or_default();
    let excerpt = source.excerpt.trim();

    if excerpt.is_empty()
        || excerpt.to_ascii_lowercase().contains("source_url=")
        || looks_like_structured_metadata_noise(excerpt)
    {
        return headline;
    }

    if excerpt_has_query_grounding_signal_with_contract(
        retrieval_contract,
        query_contract,
        min_sources,
        &source.url,
        title,
        excerpt,
    ) {
        let detail = compact_excerpt(excerpt, 160);
        if detail.eq_ignore_ascii_case(&headline) {
            return headline;
        }
        return format!("{}: {}", headline, detail);
    }

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
    if require_current_observation && has_stale_relative_age_signal(text) {
        return false;
    }
    let schema = analyze_metric_schema(text);
    if schema.numeric_token_hits == 0 {
        return false;
    }
    let has_explicit_measurement = has_numeric_measurement_signal(text);
    if has_explicit_measurement {
        if require_current_observation {
            return schema.has_current_observation_payload()
                || (schema.observation_hits > 0 && schema.unit_hits > 0)
                || (schema.axis_hits.is_empty() && has_temperature_observation_signal(text));
        }
        return true;
    }
    if require_current_observation && schema.axis_hits.is_empty() {
        return has_temperature_observation_signal(text);
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

fn has_temperature_observation_signal(text: &str) -> bool {
    let schema = analyze_metric_schema(text);
    if schema.numeric_token_hits == 0 || schema.unit_hits == 0 {
        return false;
    }

    let compact = compact_whitespace(text);
    if compact.is_empty() {
        return false;
    }
    let has_temperature_unit_signal = compact.contains('\u{00b0}')
        || compact.split_whitespace().any(|raw_token| {
            let token = raw_token
                .trim_matches(|ch: char| ",.;:!?()[]{}'\"".contains(ch))
                .to_ascii_lowercase();
            if token.is_empty() {
                return false;
            }
            if matches!(token.as_str(), "fahrenheit" | "celsius" | "f" | "c") {
                return true;
            }
            let has_digit = token.chars().any(|ch| ch.is_ascii_digit());
            has_digit
                && (token.ends_with('f') || token.ends_with('c') || token.contains('\u{00b0}'))
        });
    if !has_temperature_unit_signal {
        return false;
    }

    let horizon_dominates = schema.horizon_hits > schema.observation_hits + schema.timestamp_hits;
    if horizon_dominates {
        return false;
    }
    if schema.range_hits > 0 && schema.observation_hits == 0 && schema.timestamp_hits == 0 {
        return false;
    }

    true
}

fn has_stale_relative_age_signal(text: &str) -> bool {
    let lowered = format!(" {} ", compact_whitespace(text).to_ascii_lowercase());
    [
        " yesterday ",
        " day ago ",
        " days ago ",
        " week ago ",
        " weeks ago ",
        " month ago ",
        " months ago ",
        " year ago ",
        " years ago ",
    ]
    .iter()
    .any(|marker| lowered.contains(marker))
}

pub(crate) fn contains_current_condition_metric_signal(text: &str) -> bool {
    if has_stale_relative_age_signal(text) {
        return false;
    }
    let lowered = text.to_ascii_lowercase();
    let current_metric_payload = has_quantitative_metric_payload(text, true);
    let temperature_observation = has_temperature_observation_signal(text);
    let price_quote_observation = has_price_quote_payload(text);
    let explicit_price_context = (lowered.contains("pricing")
        || lowered.contains(" price ")
        || lowered.contains(" prices ")
        || lowered.contains("cost")
        || lowered.contains("rate card")
        || lowered.contains("rates"))
        && text.chars().any(|ch| ch.is_ascii_digit())
        && (text.contains('$') || lowered.contains("usd"));
    if !current_metric_payload && !temperature_observation && !price_quote_observation {
        return explicit_price_context;
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
    if schema.axis_hits.contains(&MetricAxis::Price) && !price_quote_observation {
        return false;
    }
    has_observable_axis
        || temperature_observation
        || price_quote_observation
        || explicit_price_context
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

pub(crate) fn metric_sentence_like_segments(text: &str) -> Vec<String> {
    let compact = compact_whitespace(text);
    if compact.is_empty() {
        return Vec::new();
    }

    let chars = compact.char_indices().collect::<Vec<_>>();
    let mut segments = Vec::new();
    let mut start = 0usize;
    for (idx, ch) in chars.iter().copied() {
        let split_here = match ch {
            '!' | '?' | ';' | '\n' => true,
            '.' => {
                let prev_digit = compact[..idx]
                    .chars()
                    .next_back()
                    .map(|value| value.is_ascii_digit())
                    .unwrap_or(false);
                let next_digit = compact[idx + ch.len_utf8()..]
                    .chars()
                    .next()
                    .map(|value| value.is_ascii_digit())
                    .unwrap_or(false);
                !(prev_digit && next_digit)
            }
            _ => false,
        };
        if !split_here {
            continue;
        }
        let segment = compact[start..idx].trim();
        if !segment.is_empty() {
            segments.push(segment.to_string());
        }
        start = idx + ch.len_utf8();
    }

    let trailing = compact[start..].trim();
    if !trailing.is_empty() {
        segments.push(trailing.to_string());
    }

    if segments.is_empty() {
        vec![compact]
    } else {
        segments
    }
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
    let price_quote_bonus =
        usize::from(schema.axis_hits.contains(&MetricAxis::Price) && has_price_quote_payload(text))
            .saturating_mul(12);
    let price_without_quote_penalty = usize::from(
        schema.axis_hits.contains(&MetricAxis::Price) && !has_price_quote_payload(text),
    )
    .saturating_mul(8);
    axis_score
        .saturating_add(numeric_score)
        .saturating_add(unit_score)
        .saturating_add(currency_score)
        .saturating_add(observation_score)
        .saturating_add(timestamp_score)
        .saturating_add(price_quote_bonus)
        .saturating_sub(horizon_penalty)
        .saturating_sub(range_penalty)
        .saturating_sub(price_without_quote_penalty)
}

pub(crate) fn best_metric_segment(text: &str) -> Option<String> {
    let compact = compact_whitespace(text);
    if compact.is_empty() {
        return None;
    }

    let mut best: Option<(usize, usize, String)> = None;
    for segment in metric_sentence_like_segments(&compact) {
        let schema = analyze_metric_schema(&segment);
        if !schema.has_metric_payload() {
            continue;
        }
        let score = metric_segment_signal_score(&segment);
        let candidate = compact_whitespace(&segment);
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
    let mut best_metric: Option<(i32, usize, String)> = None;
    let mut fallback: Option<(usize, String)> = None;
    for sentence in metric_sentence_like_segments(&compact) {
        let focused = compact_metric_focus(&sentence);
        if focused.is_empty() {
            continue;
        }
        if has_quantitative_metric_payload(&focused, false) {
            let schema = analyze_metric_schema(&focused);
            let mut score = metric_segment_signal_score(&focused) as i32;
            if contains_current_condition_metric_signal(&focused) {
                score += 12;
            } else if has_temperature_observation_signal(&focused) {
                score += 8;
            }
            if schema.has_current_observation_payload() {
                score += 6;
            }
            if schema.range_hits > 0 && schema.observation_hits == 0 && schema.timestamp_hits == 0 {
                score -= 6;
            }
            let candidate_len = focused.len();
            match &best_metric {
                Some((best_score, best_len, _))
                    if score < *best_score
                        || (score == *best_score && candidate_len >= *best_len) => {}
                _ => {
                    best_metric = Some((score, candidate_len, focused));
                }
            }
            continue;
        }
        if contains_metric_signal(&sentence) {
            let candidate_len = focused.len();
            let replace = fallback
                .as_ref()
                .map(|(best_len, _)| candidate_len < *best_len)
                .unwrap_or(true);
            if replace {
                fallback = Some((candidate_len, focused));
            }
        }
    }
    best_metric
        .map(|(_, _, segment)| segment)
        .or_else(|| fallback.map(|(_, segment)| segment))
}

pub(crate) fn looks_like_clock_time(token: &str) -> bool {
    crate::agentic::runtime::service::output::text_tokens::looks_like_clock_time(token)
}

pub(crate) fn token_is_numeric_literal(token: &str) -> bool {
    crate::agentic::runtime::service::output::text_tokens::token_is_numeric_literal(token)
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

const PRICE_SNAPSHOT_CATEGORY_MARKERS: &[&str] = &[
    "audio:",
    "text:",
    "image:",
    "video:",
    "realtime:",
    "transcription:",
    "speech:",
    "tts:",
];

fn price_only_snapshot_query(query_contract: &str) -> bool {
    let normalized = format!(
        " {} ",
        query_contract
            .to_ascii_lowercase()
            .chars()
            .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { ' ' })
            .collect::<String>()
    );
    (normalized.contains(" pricing ")
        || normalized.contains(" price ")
        || normalized.contains(" prices ")
        || normalized.contains(" rates ")
        || normalized.contains(" rate card ")
        || normalized.contains(" billing "))
        && !normalized.contains(" exchange rate ")
        && !normalized.contains(" interest rate ")
}

pub(crate) fn single_snapshot_prefers_price_summary_label(
    query_contract: &str,
    metric_excerpt: &str,
) -> bool {
    price_only_snapshot_query(query_contract)
        && (has_price_quote_payload(metric_excerpt) || metric_excerpt.contains('$'))
}

pub(crate) fn single_snapshot_current_metric_prefix(
    query_contract: &str,
    metric_excerpt: &str,
    cited: bool,
) -> &'static str {
    if single_snapshot_prefers_price_summary_label(query_contract, metric_excerpt) {
        if cited {
            "Current pricing from cited source text:"
        } else {
            "Current pricing from retrieved source text:"
        }
    } else if cited {
        "Current conditions from cited source text:"
    } else {
        "Current conditions from retrieved source text:"
    }
}

fn normalize_price_clause_text(text: &str) -> String {
    let compact = compact_whitespace(text);
    let trimmed = compact
        .trim()
        .trim_matches(|ch: char| matches!(ch, ':' | ';' | '|' | ','))
        .trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let stripped = trimmed
        .strip_prefix("Pricing:")
        .map(str::trim)
        .unwrap_or(trimmed);
    let mut normalized = stripped.to_string();
    for (from, to) in [
        (" for cached inputs", " cached input"),
        (" for inputs", " input"),
        (" for outputs", " output"),
        (" for output", " output"),
        (" for outpu", " output"),
        (" cached inputs", " cached input"),
        (" inputs", " input"),
        (" outputs", " output"),
    ] {
        normalized = normalized.replace(from, to);
    }
    normalized = compact_whitespace(&normalized);

    let mut tokens: Vec<String> = Vec::new();
    let mut seen_currency = 0usize;
    for token in normalized.split_whitespace() {
        let trimmed = token.trim_matches(|ch: char| matches!(ch, ';' | '|'));
        if trimmed.is_empty() || trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            break;
        }
        if trimmed.contains('$') && seen_currency > 0 {
            if let Some(last) = tokens.last_mut() {
                if !last.ends_with(',') {
                    last.push(',');
                }
            }
        }
        if trimmed.contains('$') {
            seen_currency += 1;
        }
        tokens.push(trimmed.to_string());
        if tokens.len() >= 32 {
            break;
        }
    }

    let mut concise = tokens.join(" ");
    while concise.ends_with(" for") {
        concise.truncate(concise.len().saturating_sub(4));
        concise = concise.trim_end().to_string();
    }
    concise
        .trim()
        .trim_matches(|ch: char| matches!(ch, ':' | ';' | '|' | '-' | ','))
        .to_string()
}

fn concise_price_quote_snapshot_line(metric_excerpt: &str) -> Option<String> {
    let focused = compact_whitespace(strip_metric_summary_prefix(metric_excerpt));
    if focused.is_empty() || !focused.contains('$') {
        return None;
    }

    let lowered = focused.to_ascii_lowercase();
    let mut category_positions = PRICE_SNAPSHOT_CATEGORY_MARKERS
        .iter()
        .filter_map(|marker| lowered.find(marker).map(|idx| (idx, *marker)))
        .collect::<Vec<_>>();
    category_positions.sort_by_key(|(idx, _)| *idx);
    category_positions.dedup_by_key(|(idx, _)| *idx);

    let mut clauses = Vec::new();
    if category_positions.len() >= 2 {
        for (idx, (start, _)) in category_positions.iter().enumerate().take(3) {
            let end = category_positions
                .get(idx + 1)
                .map(|(next, _)| *next)
                .unwrap_or_else(|| focused.len());
            let clause = normalize_price_clause_text(focused[*start..end].trim());
            if clause.is_empty() {
                continue;
            }
            clauses.push(clause);
        }
    }

    if !clauses.is_empty() {
        return Some(clauses.join("; "));
    }

    let normalized = normalize_price_clause_text(&focused);
    (!normalized.is_empty()).then_some(normalized)
}

pub(crate) fn concise_metric_snapshot_line(metric_excerpt: &str) -> String {
    let focused = compact_metric_focus(strip_metric_summary_prefix(metric_excerpt));
    if focused.is_empty() {
        return focused;
    }
    if let Some(price_snapshot) = concise_price_quote_snapshot_line(metric_excerpt) {
        return price_snapshot;
    }
    let schema = analyze_metric_schema(&focused);
    let allow_slash_delimiter = schema.axis_hits.contains(&MetricAxis::Price)
        || schema.axis_hits.contains(&MetricAxis::Rate);

    let mut tokens = Vec::new();
    for token in focused.split_whitespace() {
        let trimmed = token.trim_matches(|ch: char| matches!(ch, ',' | ';' | '|'));
        if trimmed.is_empty() {
            continue;
        }
        if looks_like_clock_time(trimmed)
            || (trimmed.contains('/') && !allow_slash_delimiter)
            || trimmed.starts_with("http://")
            || trimmed.starts_with("https://")
        {
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

fn strip_metric_summary_prefix(text: &str) -> &str {
    let trimmed = text.trim();
    for prefix in [
        "Current conditions from retrieved source text:",
        "Current conditions from cited source text:",
        "Current pricing from retrieved source text:",
        "Current pricing from cited source text:",
        "Available observed details from retrieved source text:",
        "Available observed details from cited source text:",
    ] {
        if trimmed
            .get(..prefix.len())
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
        {
            return trimmed[prefix.len()..].trim();
        }
    }
    trimmed
}

const SINGLE_SNAPSHOT_DIRECT_FACT_PREFIXES: &[&str] = &[
    "Current answer:",
    "Current answer from retrieved source text:",
    "Current answer from cited source text:",
    "Current status:",
    "Current status from retrieved source text:",
    "Current status from cited source text:",
];

const SUBJECT_CURRENTNESS_ROLE_MARKERS: &[&str] = &[
    "ceo",
    "chief executive officer",
    "president",
    "prime minister",
    "secretary-general",
    "secretary general",
    "governor",
    "mayor",
    "chair",
    "chairman",
    "chairwoman",
    "director",
    "executive director",
    "minister",
    "chancellor",
    "commissioner",
    "leader",
    "leadership",
    "incumbent",
];

const SUBJECT_CURRENTNESS_RELATION_MARKERS: &[&str] = &[
    " is led by ",
    " led by ",
    " is the current ",
    " is the ",
    " serves as ",
    " currently serves as ",
    " currently is ",
    " current ",
    " incumbent ",
    " appointed ",
    " elected ",
    " office holder ",
    " officeholder ",
];

const SUBJECT_CURRENTNESS_ROLE_NOISE_TOKENS: &[&str] = &[
    "a",
    "an",
    "and",
    "appointed",
    "as",
    "by",
    "ceo",
    "chair",
    "chairman",
    "chairwoman",
    "chancellor",
    "chief",
    "commissioner",
    "current",
    "currently",
    "director",
    "elected",
    "executive",
    "general",
    "governor",
    "head",
    "holder",
    "incumbent",
    "is",
    "leader",
    "leadership",
    "led",
    "mayor",
    "minister",
    "of",
    "office",
    "officeholder",
    "officer",
    "president",
    "prime",
    "secretary",
    "secretary-general",
    "serves",
    "serve",
    "the",
];

fn ensure_terminal_sentence(text: &str) -> String {
    let compact = compact_whitespace(text);
    let trimmed = compact
        .trim()
        .trim_matches(|ch: char| matches!(ch, ':' | ';' | '|' | '-'))
        .trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.ends_with(['.', '!', '?']) {
        trimmed.to_string()
    } else {
        format!("{trimmed}.")
    }
}

pub(crate) fn strip_single_snapshot_direct_fact_prefix(text: &str) -> &str {
    let trimmed = text.trim();
    for prefix in SINGLE_SNAPSHOT_DIRECT_FACT_PREFIXES {
        if trimmed
            .get(..prefix.len())
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
        {
            return trimmed[prefix.len()..].trim();
        }
    }
    trimmed
}

pub(crate) fn single_snapshot_has_direct_fact_line(text: &str) -> bool {
    SINGLE_SNAPSHOT_DIRECT_FACT_PREFIXES.iter().any(|prefix| {
        text.get(..prefix.len())
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
    })
}

fn subject_currentness_segment_has_role_marker(text: &str) -> bool {
    let normalized = format!(" {} ", compact_whitespace(text).to_ascii_lowercase());
    SUBJECT_CURRENTNESS_ROLE_MARKERS
        .iter()
        .any(|marker| normalized.contains(marker))
}

fn subject_currentness_capitalized_identity_streak(text: &str) -> usize {
    let mut best = 0usize;
    let mut streak = 0usize;

    for token in
        text.split(|ch: char| !(ch.is_alphanumeric() || ch == '\'' || ch == '-' || ch == '’'))
    {
        let trimmed = token.trim_matches(|ch: char| !ch.is_alphanumeric());
        if trimmed.is_empty() {
            streak = 0;
            continue;
        }

        let normalized = trimmed.to_ascii_lowercase();
        let first = trimmed.chars().next();
        let capitalized = trimmed.chars().any(|ch| ch.is_uppercase());
        let is_short_acronym = trimmed.chars().all(|ch| ch.is_uppercase()) && trimmed.len() <= 3;
        let is_noise = SUBJECT_CURRENTNESS_ROLE_NOISE_TOKENS.contains(&normalized.as_str());
        if first.is_none()
            || !capitalized
            || is_short_acronym
            || is_noise
            || normalized.chars().all(|ch| ch.is_ascii_digit())
        {
            streak = 0;
            continue;
        }

        streak += 1;
        best = best.max(streak);
    }

    best
}

fn subject_currentness_led_by_identity_payload(text: &str) -> bool {
    let compact = compact_whitespace(text);
    let normalized = format!(" {} ", compact.to_ascii_lowercase());

    for marker in [" is led by ", " led by "] {
        let Some(idx) = normalized.find(marker).map(|idx| idx.saturating_sub(1)) else {
            continue;
        };
        let Some((left, remainder)) = compact.get(..idx).zip(compact.get(idx + marker.len()..))
        else {
            continue;
        };
        if subject_currentness_segment_has_role_marker(left) {
            continue;
        }

        let right = remainder.trim();
        let right_head = right
            .split_once(" of ")
            .map(|(head, _)| head)
            .unwrap_or(right);
        if subject_currentness_capitalized_identity_streak(right_head) >= 2 {
            return true;
        }
    }

    false
}

fn subject_currentness_subject_identity_payload(text: &str) -> bool {
    let compact = compact_whitespace(text);
    let normalized = format!(" {} ", compact.to_ascii_lowercase());

    for marker in [
        " is the current ",
        " currently serves as ",
        " currently is ",
        " is the ",
        " appointed ",
        " elected ",
    ] {
        let Some(idx) = normalized.find(marker).map(|idx| idx.saturating_sub(1)) else {
            continue;
        };
        let Some((left, right)) = compact.get(..idx).zip(compact.get(idx + marker.len()..)) else {
            continue;
        };
        if subject_currentness_segment_has_role_marker(left) {
            continue;
        }
        if !subject_currentness_segment_has_role_marker(right) {
            continue;
        }
        if subject_currentness_capitalized_identity_streak(left) >= 1 {
            return true;
        }
    }

    false
}

pub(crate) fn has_subject_currentness_payload(text: &str) -> bool {
    let normalized = format!(" {} ", compact_whitespace(text).to_ascii_lowercase());
    SUBJECT_CURRENTNESS_ROLE_MARKERS
        .iter()
        .any(|marker| normalized.contains(marker))
        && SUBJECT_CURRENTNESS_RELATION_MARKERS
            .iter()
            .any(|marker| normalized.contains(marker))
        && (subject_currentness_subject_identity_payload(text)
            || subject_currentness_led_by_identity_payload(text))
}

pub(crate) fn query_requires_subject_currentness_identity(query_contract: &str) -> bool {
    let normalized = format!(
        " {} ",
        compact_whitespace(query_contract).to_ascii_lowercase()
    );
    normalized.contains(" who ")
        && SUBJECT_CURRENTNESS_ROLE_MARKERS
            .iter()
            .any(|marker| normalized.contains(marker))
}

fn has_explicit_current_holder_marker(text: &str) -> bool {
    let normalized = format!(" {} ", compact_whitespace(text).to_ascii_lowercase());
    normalized.contains(" is the current ")
        || normalized.contains(" is current ")
        || normalized.contains(" currently serves as ")
        || normalized.contains(" serves as ")
        || normalized.contains(" currently is ")
        || normalized.contains(" incumbent ")
}

pub(crate) fn first_subject_currentness_sentence(text: &str) -> Option<String> {
    let compact = compact_whitespace(text);
    let trimmed = compact.trim();
    if trimmed.is_empty() {
        return None;
    }

    for candidate in trimmed.split(['.', '!', '?', '\n', ';']) {
        let normalized = ensure_terminal_sentence(candidate);
        if normalized.len() >= 20 && has_subject_currentness_payload(&normalized) {
            return Some(normalized);
        }
    }

    has_subject_currentness_payload(trimmed).then(|| ensure_terminal_sentence(trimmed))
}

pub(crate) fn first_current_role_holder_sentence(text: &str) -> Option<String> {
    first_subject_currentness_sentence(text)
        .filter(|sentence| has_explicit_current_holder_marker(sentence))
}

#[cfg(test)]
#[path = "basics/currentness_tests.rs"]
mod currentness_tests;

pub(crate) fn single_snapshot_fact_grounding_signal_with_contract(
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    query_contract: &str,
    min_sources: usize,
    source: &PendingSearchReadSummary,
) -> bool {
    let title = source.title.as_deref().unwrap_or_default();
    excerpt_has_query_grounding_signal_with_contract(
        retrieval_contract,
        query_contract,
        min_sources,
        &source.url,
        title,
        &source.excerpt,
    ) || first_subject_currentness_sentence(&format!("{} {}", title, source.excerpt)).is_some()
}

pub(crate) fn single_snapshot_summary_line_with_contract(
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    query_contract: &str,
    min_sources: usize,
    source: &PendingSearchReadSummary,
) -> String {
    let title = source.title.as_deref().unwrap_or_default();
    let excerpt = source.excerpt.as_str();
    let query_facets = analyze_query_facets(query_contract);
    let metric_snapshot_query = !query_metric_axes(query_contract).is_empty()
        || (query_facets.time_sensitive_public_fact && query_facets.locality_sensitive_public_fact);
    if let Some(metric) = first_metric_sentence(excerpt) {
        if contains_current_condition_metric_signal(&metric) {
            return format!(
                "{} {}",
                single_snapshot_current_metric_prefix(query_contract, &metric, false),
                concise_metric_snapshot_line(&metric)
            );
        }
        if has_quantitative_metric_payload(&metric, false) {
            return single_snapshot_best_available_with_limitation(source, &metric);
        }
    }
    if metric_snapshot_query {
        let fallback = actionable_excerpt(excerpt).unwrap_or_else(|| source_bullet(source));
        if contains_current_condition_metric_signal(&fallback) {
            return format!(
                "{} {}",
                single_snapshot_current_metric_prefix(query_contract, &fallback, false),
                concise_metric_snapshot_line(&fallback)
            );
        }
        if has_quantitative_metric_payload(&fallback, false) {
            return single_snapshot_best_available_with_limitation(source, &fallback);
        }
        return single_snapshot_metric_limitation_line(source);
    }
    if let Some(subject_currentness) =
        first_subject_currentness_sentence(&format!("{} {}", title, excerpt))
    {
        return format!(
            "Current answer from retrieved source text: {}",
            subject_currentness
        );
    }
    if single_snapshot_fact_grounding_signal_with_contract(
        retrieval_contract,
        query_contract,
        min_sources,
        source,
    ) {
        let fact = actionable_excerpt(excerpt)
            .or_else(|| excerpt_headline(excerpt))
            .unwrap_or_else(|| {
                source_bullet_for_query_with_contract(
                    retrieval_contract,
                    query_contract,
                    min_sources,
                    source,
                )
            });
        return format!(
            "Current answer from retrieved source text: {}",
            ensure_terminal_sentence(&fact)
        );
    }
    let fallback = actionable_excerpt(excerpt).unwrap_or_else(|| source_bullet(source));
    if contains_current_condition_metric_signal(&fallback) {
        return format!(
            "{} {}",
            single_snapshot_current_metric_prefix(query_contract, &fallback, false),
            concise_metric_snapshot_line(&fallback)
        );
    }
    if has_quantitative_metric_payload(&fallback, false) {
        return single_snapshot_best_available_with_limitation(source, &fallback);
    }
    single_snapshot_metric_limitation_line(source)
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
    single_snapshot_summary_line_with_contract(None, "", 1, source)
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
    fn axis_keyword_markers(axis: MetricAxis) -> &'static [&'static str] {
        match axis {
            MetricAxis::Temperature => &["temperature", "feels like"],
            MetricAxis::Humidity => &["humidity"],
            MetricAxis::Wind => &["wind speed", "wind"],
            MetricAxis::Pressure => &["pressure", "barometer"],
            MetricAxis::Visibility => &["visibility"],
            MetricAxis::AirQuality => &["air quality", "aqi"],
            MetricAxis::Price => &["price", "quote", "rate"],
            MetricAxis::Rate => &["rate"],
            MetricAxis::Precipitation => &["precipitation"],
            MetricAxis::Score => &["score"],
            MetricAxis::Duration => &["duration"],
        }
    }

    fn axis_keyword_metric_excerpt(axis: MetricAxis, text: &str) -> Option<String> {
        const STOP_MARKERS: &[&str] = &[
            "temperature",
            "feels like",
            "humidity",
            "wind speed",
            "wind",
            "pressure",
            "barometer",
            "visibility",
            "air quality",
            "aqi",
            "price",
            "quote",
            "rate",
        ];

        let compact = compact_whitespace(text);
        if compact.is_empty() {
            return None;
        }
        let lowered = compact.to_ascii_lowercase();
        for marker in axis_keyword_markers(axis) {
            let Some(start) = lowered.find(marker) else {
                continue;
            };
            let after = start + marker.len();
            let next_marker = STOP_MARKERS
                .iter()
                .filter_map(|candidate| {
                    lowered[after..]
                        .find(candidate)
                        .map(|offset| after + offset)
                })
                .min();
            let punctuation_end = compact[after..]
                .find(['.', ';', ','])
                .map(|offset| after + offset);
            let end = next_marker
                .into_iter()
                .chain(punctuation_end)
                .min()
                .unwrap_or(compact.len());
            let segment = compact_whitespace(&compact[start..end]);
            if segment.is_empty() || !segment.chars().any(|ch| ch.is_ascii_digit()) {
                continue;
            }
            let concise = concise_metric_snapshot_line(&segment);
            if !concise.is_empty() && concise.chars().any(|ch| ch.is_ascii_digit()) {
                return Some(concise);
            }
        }
        None
    }

    let schema = analyze_metric_schema(text);
    if !schema.axis_hits.contains(&axis) || !has_quantitative_metric_payload(text, true) {
        return None;
    }
    if axis == MetricAxis::Price && !has_price_quote_payload(text) {
        return None;
    }
    if let Some(keyword_excerpt) = axis_keyword_metric_excerpt(axis, text) {
        return Some(keyword_excerpt);
    }
    for sentence in metric_sentence_like_segments(text) {
        for segment in sentence
            .split([',', ';'])
            .map(compact_whitespace)
            .filter(|segment| !segment.is_empty())
        {
            let segment_schema = analyze_metric_schema(&segment);
            if !segment_schema.axis_hits.contains(&axis) {
                continue;
            }
            if axis == MetricAxis::Price && !has_price_quote_payload(&segment) {
                continue;
            }
            if axis != MetricAxis::Price && !has_quantitative_metric_payload(&segment, true) {
                continue;
            }
            let concise = concise_metric_snapshot_line(&segment);
            if !concise.is_empty() && concise.chars().any(|ch| ch.is_ascii_digit()) {
                return Some(concise);
            }
        }
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
