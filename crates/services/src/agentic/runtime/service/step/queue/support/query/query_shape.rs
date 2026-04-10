use super::*;

const EXPLICIT_COUNT_COLLECTION_NOUNS: &[&str] = &[
    "stories",
    "story",
    "items",
    "results",
    "findings",
    "incidents",
    "events",
    "updates",
    "options",
    "records",
    "entries",
];

const MULTI_ITEM_COMPARISON_DIRECTIVES: &[&str] = &[
    " compare ",
    " comparison ",
    " versus ",
    " vs ",
    " across ",
    " between ",
    " among ",
];

const MULTI_ITEM_RANKING_DIRECTIVES: &[&str] =
    &[" roundup ", " round-up ", " list ", " ranking ", " ranked "];

const MULTI_ITEM_BRIEFING_DIRECTIVES: &[&str] = &[
    " briefing ",
    " overview ",
    " survey ",
    " landscape ",
    " digest ",
];

const DOCUMENT_BRIEFING_DIRECTIVES: &[&str] = &[
    " briefing ",
    " brief ",
    " memo ",
    " report ",
    " one-page ",
    " one page ",
];

fn marker_lexeme_tokens(markers: &[&str]) -> BTreeSet<String> {
    markers
        .iter()
        .flat_map(|marker| marker.split_whitespace())
        .filter_map(|token| {
            let normalized = token
                .trim()
                .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
                .to_ascii_lowercase();
            if normalized.len() < QUERY_COMPATIBILITY_MIN_TOKEN_CHARS {
                return None;
            }
            if normalized.chars().all(|ch| ch.is_ascii_digit()) {
                return None;
            }
            Some(normalized)
        })
        .collect()
}

pub(crate) fn query_shape_boundary_tokens(query: &str) -> BTreeSet<String> {
    if query.trim().is_empty() {
        return BTreeSet::new();
    }

    let mut tokens = BTreeSet::new();
    tokens.extend(marker_lexeme_tokens(MULTI_ITEM_COMPARISON_DIRECTIVES));
    tokens.extend(marker_lexeme_tokens(MULTI_ITEM_RANKING_DIRECTIVES));
    tokens.extend(marker_lexeme_tokens(MULTI_ITEM_BRIEFING_DIRECTIVES));
    tokens.extend(marker_lexeme_tokens(DOCUMENT_BRIEFING_DIRECTIVES));

    let padded = normalized_phrase_query(query);
    if padded.contains(" top ") {
        tokens.insert("top".to_string());
    }

    tokens
}

pub(crate) fn parse_small_count_token(token: &str) -> Option<usize> {
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

fn normalize_count_hint_token(token: &str) -> String {
    token
        .trim()
        .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
        .to_ascii_lowercase()
}

fn token_is_semantic_count_target(token: &str, structural_tokens: &BTreeSet<String>) -> bool {
    let normalized = normalize_count_hint_token(token);
    if normalized.len() < QUERY_COMPATIBILITY_MIN_TOKEN_CHARS {
        return false;
    }
    if normalized.chars().all(|ch| ch.is_ascii_digit()) || is_query_stopword(&normalized) {
        return false;
    }
    !structural_tokens.contains(&normalized)
}

fn token_looks_plural(token: &str) -> bool {
    let normalized = token.trim().to_ascii_lowercase();
    normalized.len() >= QUERY_COMPATIBILITY_MIN_TOKEN_CHARS
        && normalized.ends_with('s')
        && !normalized.ends_with("ss")
}

fn semantic_surface_is_plural(semantic_tokens: &BTreeSet<String>) -> bool {
    semantic_tokens
        .iter()
        .any(|token| token_looks_plural(token))
}

fn query_requests_multi_item_briefing(padded_query: &str) -> bool {
    MULTI_ITEM_BRIEFING_DIRECTIVES
        .iter()
        .any(|marker| padded_query.contains(marker))
}

fn query_requests_document_briefing(padded_query: &str) -> bool {
    DOCUMENT_BRIEFING_DIRECTIVES
        .iter()
        .any(|marker| padded_query.contains(marker))
}

pub(crate) fn explicit_story_count_hint(query: &str) -> Option<usize> {
    let tokens = query.split_whitespace().collect::<Vec<_>>();
    let structural_tokens = query_structural_directive_tokens(query);
    for idx in 0..tokens.len() {
        let token = normalize_count_hint_token(tokens[idx]);
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
            .map(|value| normalize_count_hint_token(value))
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

        let lookahead_contains_collection_noun = tokens
            .iter()
            .skip(idx + 1)
            .take(4)
            .map(|value| normalize_count_hint_token(value))
            .any(|value| EXPLICIT_COUNT_COLLECTION_NOUNS.contains(&value.as_str()));
        if lookahead_contains_collection_noun {
            return Some(value.clamp(1, 6));
        }

        let lookahead_contains_semantic_target = tokens
            .iter()
            .skip(idx + 1)
            .take(4)
            .any(|value| token_is_semantic_count_target(value, &structural_tokens));
        if lookahead_contains_semantic_target {
            return Some(value.clamp(1, 6));
        }
    }
    None
}

pub(crate) fn required_story_count(query: &str) -> usize {
    if let Some(explicit) = explicit_story_count_hint(query) {
        return explicit;
    }
    if prefers_single_fact_snapshot(query) {
        return 1;
    }
    if query_prefers_multi_item_cardinality(query) {
        WEB_PIPELINE_REQUIRED_STORIES
    } else {
        1
    }
}

pub(super) fn normalized_phrase_query(query: &str) -> String {
    let normalized = query
        .to_ascii_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { ' ' })
        .collect::<String>();
    format!(
        " {} ",
        normalized.split_whitespace().collect::<Vec<_>>().join(" ")
    )
}

pub(super) fn canonical_domain_key(url: &str) -> Option<String> {
    let parsed = Url::parse(url.trim()).ok()?;
    let host = parsed.host_str()?.trim();
    if host.is_empty() {
        return None;
    }
    let normalized = host.to_ascii_lowercase();
    Some(
        normalized
            .strip_prefix("www.")
            .unwrap_or(&normalized)
            .to_string(),
    )
}

pub(crate) fn required_distinct_domain_floor(query_contract: &str) -> usize {
    if query_requires_local_business_entity_diversity(query_contract) {
        return 0;
    }
    if query_prefers_multi_item_cardinality(query_contract) {
        required_story_count(query_contract).max(1)
    } else {
        0
    }
}

pub(crate) fn prefers_single_fact_snapshot(query: &str) -> bool {
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
    let padded = normalized_phrase_query(query);
    let semantic_tokens = query_semantic_anchor_tokens(query);
    let plural_semantic_surface = semantic_surface_is_plural(&semantic_tokens);
    let ranked_plural_collection = plural_semantic_surface
        && MULTI_ITEM_RANKING_DIRECTIVES
            .iter()
            .chain([" top "].iter())
            .chain(MULTI_ITEM_COMPARISON_DIRECTIVES.iter())
            .any(|marker| padded.contains(marker));
    let plural_briefing_surface =
        plural_semantic_surface && query_requests_multi_item_briefing(&padded);
    if ranked_plural_collection || plural_briefing_surface {
        return false;
    }
    true
}

pub(crate) fn query_prefers_multi_item_cardinality(query: &str) -> bool {
    if query.trim().is_empty() {
        return false;
    }
    if explicit_story_count_hint(query).is_some() {
        return true;
    }
    if prefers_single_fact_snapshot(query) {
        return false;
    }
    if query_prefers_document_briefing_layout(query) {
        return false;
    }

    let padded = normalized_phrase_query(query);
    let has_collection_directive = MULTI_ITEM_RANKING_DIRECTIVES
        .iter()
        .chain(MULTI_ITEM_COMPARISON_DIRECTIVES.iter())
        .any(|marker| padded.contains(marker));
    let has_ranked_collection = padded.contains(" top ");
    let semantic_tokens = query_semantic_anchor_tokens(query);
    let plural_semantic_surface = semantic_surface_is_plural(&semantic_tokens);
    let has_plural_briefing_surface =
        plural_semantic_surface && query_requests_multi_item_briefing(&padded);

    query_requests_comparison(query)
        || ((has_ranked_collection || has_collection_directive || has_plural_briefing_surface)
            && plural_semantic_surface)
}

pub(crate) fn query_requests_comparison(query: &str) -> bool {
    if query.trim().is_empty() {
        return false;
    }
    let padded = normalized_phrase_query(query);
    MULTI_ITEM_COMPARISON_DIRECTIVES
        .iter()
        .any(|marker| padded.contains(marker))
}

pub(crate) fn query_prefers_document_briefing_layout(query: &str) -> bool {
    if query.trim().is_empty() {
        return false;
    }
    if prefers_single_fact_snapshot(query) {
        return false;
    }
    let padded = normalized_phrase_query(query);
    if !query_requests_document_briefing(&padded) {
        return false;
    }
    let has_explicit_multi_item_shape = explicit_story_count_hint(query).is_some()
        || padded.contains(" top ")
        || MULTI_ITEM_RANKING_DIRECTIVES
            .iter()
            .chain(MULTI_ITEM_COMPARISON_DIRECTIVES.iter())
            .any(|marker| padded.contains(marker));
    !has_explicit_multi_item_shape
}

pub(crate) fn query_is_generic_headline_collection(query: &str) -> bool {
    if query.trim().is_empty() {
        return false;
    }
    if prefers_single_fact_snapshot(query) {
        return false;
    }
    if !query_prefers_multi_item_cardinality(query) {
        return false;
    }
    let padded = normalized_phrase_query(query);
    if query_requests_multi_item_briefing(&padded) {
        return false;
    }
    let facets = analyze_query_facets(query);
    facets.time_sensitive_public_fact
        && facets.grounded_external_required
        && !facets.workspace_constrained
        && !facets.locality_sensitive_public_fact
}

pub(crate) fn query_contains_structured_search_operators(query: &str) -> bool {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lowered = trimmed.to_ascii_lowercase();
    trimmed.contains('"')
        || lowered.contains("-site:")
        || lowered.contains(" site:")
        || lowered.contains("inurl:")
        || lowered.contains("intitle:")
}

pub(super) fn generic_headline_search_phrase(query: &str) -> String {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    if query_contains_structured_search_operators(trimmed) {
        return trimmed.to_string();
    }

    let mut tokens = Vec::new();
    let mut seen = BTreeSet::new();
    for raw in trimmed.split_whitespace() {
        let mut normalized = raw
            .trim()
            .trim_matches(|ch: char| matches!(ch, ',' | ';' | ':' | '.' | '!' | '?' | '(' | ')'))
            .trim_matches('"')
            .to_ascii_lowercase()
            .replace('\'', "");
        if normalized == "todays" {
            normalized = "today".to_string();
        }
        if normalized.len() < 2 {
            continue;
        }
        if matches!(
            normalized.as_str(),
            "tell"
                | "me"
                | "give"
                | "show"
                | "what"
                | "whats"
                | "please"
                | "could"
                | "would"
                | "can"
                | "you"
        ) {
            continue;
        }
        if seen.insert(normalized.clone()) {
            tokens.push(normalized);
        }
    }

    if tokens.is_empty() {
        trimmed.to_string()
    } else {
        tokens.join(" ")
    }
}

pub(crate) fn query_requires_structured_synthesis(query: &str) -> bool {
    if query_prefers_document_briefing_layout(query) {
        return true;
    }
    if query_prefers_multi_item_cardinality(query) {
        return true;
    }
    if prefers_single_fact_snapshot(query) {
        return false;
    }

    infer_report_sections(query).into_iter().any(|section| {
        matches!(
            section,
            ReportSectionKind::RecentChange
                | ReportSectionKind::Significance
                | ReportSectionKind::UserImpact
                | ReportSectionKind::Mitigation
                | ReportSectionKind::EtaConfidence
                | ReportSectionKind::Caveat
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_briefing_layout_wins_for_one_page_briefing_queries() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        assert!(query_prefers_document_briefing_layout(query));
        assert!(query_requires_structured_synthesis(query));
        assert!(!query_prefers_multi_item_cardinality(query));
    }

    #[test]
    fn explicit_multi_item_shape_overrides_document_briefing_layout() {
        let query = "Write a briefing comparing the top three post-quantum cryptography standards.";
        assert!(!query_prefers_document_briefing_layout(query));
        assert!(query_prefers_multi_item_cardinality(query));
    }
}

pub(crate) fn query_metric_axes_with_hints(
    query: &str,
    candidate_hints: &[PendingSearchReadSummary],
) -> BTreeSet<MetricAxis> {
    if query_is_generic_headline_collection(query) {
        return BTreeSet::new();
    }
    let query_facets = analyze_query_facets(query);
    let query_native_tokens = query_native_anchor_tokens(query);
    let mut required_facets = query_facets.metric_schema.axis_hits;
    if required_facets.is_empty() && prefers_single_fact_snapshot(query) {
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
            let likely_current_observation_surface = schema.has_current_observation_payload()
                || (schema.observation_hits > schema.horizon_hits
                    && schema.range_hits == 0
                    && !schema.axis_hits.is_empty());
            if !likely_current_observation_surface {
                continue;
            }
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

pub(crate) fn query_metric_axes(query: &str) -> BTreeSet<MetricAxis> {
    query_metric_axes_with_hints(query, &[])
}

pub(crate) fn single_snapshot_constraint_set_with_hints(
    query: &str,
    min_independent_sources: usize,
    candidate_hints: &[PendingSearchReadSummary],
) -> ConstraintSet {
    let required_facets = query_metric_axes_with_hints(query, candidate_hints);
    compile_constraint_set(query, required_facets, min_independent_sources)
}

pub(crate) fn single_snapshot_candidate_envelope_score(
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

pub(crate) fn envelope_score_has_resolvable_signal(score: &CandidateEvidenceScore) -> bool {
    score.has_numeric_observation()
        || score.present_without_numeric_facets > 0
        || (score.required_facets == 0 && score.total_score > 0)
}

pub(crate) fn envelope_score_resolves_constraint(
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

pub(crate) fn compare_candidate_evidence_scores_desc(
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

pub(crate) fn metric_axis_search_phrase(axis: MetricAxis) -> &'static str {
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
