use super::*;

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

pub(crate) fn explicit_story_count_hint(query: &str) -> Option<usize> {
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

pub(super) fn required_distinct_domain_floor(query_contract: &str) -> usize {
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
    let collection_topic = [
        " headlines ",
        " stories ",
        " incidents ",
        " outages ",
        " updates ",
        " events ",
        " findings ",
        " results ",
        " providers ",
        " services ",
        " news ",
    ]
    .iter()
    .any(|marker| padded.contains(marker));
    if collection_topic
        && [
            " top ",
            " roundup ",
            " round-up ",
            " list ",
            " ranking ",
            " ranked ",
            " across ",
            " between ",
            " among ",
        ]
        .iter()
        .any(|marker| padded.contains(marker))
    {
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

    let padded = normalized_phrase_query(query);
    let has_collection_topic = [
        " headlines ",
        " stories ",
        " incidents ",
        " outages ",
        " updates ",
        " events ",
        " findings ",
        " results ",
        " providers ",
        " services ",
    ]
    .iter()
    .any(|marker| padded.contains(marker));
    let has_collection_directive = [
        " roundup ",
        " round-up ",
        " list ",
        " ranking ",
        " ranked ",
        " compare ",
        " comparison ",
        " versus ",
        " vs ",
        " across ",
        " between ",
        " among ",
    ]
    .iter()
    .any(|marker| padded.contains(marker));
    let has_ranked_collection = padded.contains(" top ") && has_collection_topic;

    has_ranked_collection || (has_collection_directive && has_collection_topic)
}

pub(crate) fn query_is_generic_headline_collection(query: &str) -> bool {
    if !query_prefers_multi_item_cardinality(query) {
        return false;
    }
    let padded = normalized_phrase_query(query);
    let has_headline_anchor = [
        " headline ",
        " headlines ",
        " news ",
        " story ",
        " stories ",
        " breaking news ",
        " top stories ",
    ]
    .iter()
    .any(|marker| padded.contains(marker));
    if !has_headline_anchor {
        return false;
    }
    [
        " top ",
        " latest ",
        " today ",
        " breaking ",
        " recent ",
        " now ",
    ]
    .iter()
    .any(|marker| padded.contains(marker))
}

pub(super) fn generic_headline_search_phrase(query: &str) -> String {
    let mut tokens = Vec::new();
    let mut seen = BTreeSet::new();
    for raw in query.split(|ch: char| !ch.is_ascii_alphanumeric()) {
        let mut normalized = raw.trim().to_ascii_lowercase();
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
                | "today"
        ) {
            continue;
        }
        if seen.insert(normalized.clone()) {
            tokens.push(normalized);
        }
    }

    if !tokens.iter().any(|token| token == "news") {
        tokens.push("news".to_string());
    }
    if !tokens
        .iter()
        .any(|token| token == "headline" || token == "headlines")
    {
        tokens.push("headlines".to_string());
    }
    if !tokens
        .iter()
        .any(|token| matches!(token.as_str(), "latest" | "recent" | "breaking"))
    {
        tokens.push("latest".to_string());
    }
    if !tokens
        .iter()
        .any(|token| matches!(token.as_str(), "top" | "latest" | "breaking"))
    {
        tokens.push("top".to_string());
    }

    let priority = ["latest", "breaking", "top", "news", "headlines"];
    let mut ordered = Vec::new();
    let mut included = BTreeSet::new();
    for wanted in priority {
        if tokens.iter().any(|token| token == wanted) && included.insert(wanted.to_string()) {
            ordered.push(wanted.to_string());
        }
    }
    for token in tokens {
        if included.insert(token.clone()) {
            ordered.push(token);
        }
    }

    let mut query = ordered.join(" ").trim().to_string();
    if query.is_empty() {
        query = "latest top news headlines".to_string();
    }

    let quality_terms = ["world", "politics", "business"];
    query = append_unique_query_terms(
        &query,
        &quality_terms
            .iter()
            .map(|term| term.to_string())
            .collect::<Vec<_>>(),
    );

    query
}

pub(crate) fn query_requires_structured_synthesis(query: &str) -> bool {
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
