use super::*;

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
pub(crate) struct CandidateConstraintCompatibility {
    pub(crate) compatibility_score: usize,
    pub(crate) is_compatible: bool,
    pub(crate) locality_compatible: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct QueryConstraintProjection {
    pub(crate) constraints: ConstraintSet,
    pub(crate) query_facets: QueryFacetProfile,
    pub(crate) query_native_tokens: BTreeSet<String>,
    pub(crate) query_tokens: BTreeSet<String>,
    pub(crate) locality_scope: Option<String>,
    pub(crate) locality_scope_inferred: bool,
    pub(crate) locality_tokens: BTreeSet<String>,
}

impl QueryConstraintProjection {
    pub(crate) fn enforce_grounded_compatibility(&self) -> bool {
        self.constraints
            .scopes
            .contains(&ConstraintScope::TimeSensitive)
            || (self.query_facets.grounded_external_required
                && !self.query_native_tokens.is_empty())
    }

    pub(crate) fn strict_grounded_compatibility(&self) -> bool {
        self.constraints
            .scopes
            .contains(&ConstraintScope::TimeSensitive)
            && self.enforce_grounded_compatibility()
            && !self.locality_scope_inferred
            && self.query_native_tokens.len()
                >= QUERY_COMPATIBILITY_MIN_GROUNDED_MULTI_ANCHOR_OVERLAP
    }

    pub(crate) fn has_constraint_objective(&self) -> bool {
        self.constraints
            .scopes
            .contains(&ConstraintScope::TimeSensitive)
            || self.query_facets.grounded_external_required
            || !self.constraints.required_facets.is_empty()
            || !self.query_tokens.is_empty()
    }

    pub(crate) fn reject_search_hub_candidates(&self) -> bool {
        self.constraints
            .scopes
            .contains(&ConstraintScope::TimeSensitive)
            || self.query_facets.grounded_external_required
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RankedAcquisitionCandidate {
    pub(crate) idx: usize,
    pub(crate) hint: PendingSearchReadSummary,
    pub(crate) envelope_score: CandidateEvidenceScore,
    pub(crate) resolves_constraint: bool,
    pub(crate) time_sensitive_resolvable_payload: bool,
    pub(crate) compatibility: CandidateConstraintCompatibility,
    pub(crate) source_relevance_score: usize,
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

fn normalized_phrase_query(query: &str) -> String {
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

fn canonical_domain_key(url: &str) -> Option<String> {
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

fn required_distinct_domain_floor(query_contract: &str) -> usize {
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

fn generic_headline_search_phrase(query: &str) -> String {
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

pub(crate) fn is_query_stopword(token: &str) -> bool {
    QUERY_COMPATIBILITY_STOPWORDS.contains(&token)
}

fn is_tracking_noise_token(token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    if token.starts_with("utm") {
        return true;
    }
    if matches!(
        token,
        "msockid" | "fbclid" | "gclid" | "dclid" | "yclid" | "mcid" | "mkt_tok"
    ) {
        return true;
    }
    token.len() >= 16 && token.chars().all(|ch| ch.is_ascii_hexdigit())
}

pub(crate) fn is_locality_scope_noise_token(token: &str) -> bool {
    LOCALITY_SCOPE_NOISE_TOKENS.contains(&token)
}

pub(crate) fn normalized_anchor_tokens(text: &str) -> BTreeSet<String> {
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
            if is_tracking_noise_token(&normalized) {
                return None;
            }
            Some(normalized)
        })
        .collect()
}

pub(crate) fn normalized_locality_tokens(text: &str) -> BTreeSet<String> {
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
            if is_tracking_noise_token(&normalized) {
                return None;
            }
            Some(normalized)
        })
        .collect()
}

pub(crate) fn source_locality_tokens(url: &str, title: &str, excerpt: &str) -> BTreeSet<String> {
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

pub(crate) fn ordered_normalized_locality_tokens(text: &str) -> Vec<String> {
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
        if is_tracking_noise_token(&normalized) {
            continue;
        }
        if !seen.insert(normalized.clone()) {
            continue;
        }
        ordered.push(normalized);
    }
    ordered
}

pub(crate) fn source_structural_locality_tokens(url: &str, title: &str) -> Vec<String> {
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

pub(crate) fn is_locality_scope_inference_hub_url(url: &str) -> bool {
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

pub(crate) fn sanitize_locality_scope(raw: &str) -> Option<String> {
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

pub(crate) fn inferred_locality_scope_from_candidate_hints(
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

pub(crate) fn scope_anchor_start(query_lower: &str) -> Option<usize> {
    for marker in [" in ", " near ", " around ", " at "] {
        if let Some(idx) = query_lower.find(marker) {
            return Some(idx + marker.len());
        }
    }
    None
}

pub(crate) fn explicit_query_scope_hint(query: &str) -> Option<String> {
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

pub(crate) fn query_requires_locality_scope(query: &str, facets: &QueryFacetProfile) -> bool {
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

pub(crate) fn trusted_runtime_locality_scope_from_env() -> Option<String> {
    TRUSTED_LOCALITY_ENV_KEYS.iter().find_map(|key| {
        std::env::var(key)
            .ok()
            .and_then(|raw| sanitize_locality_scope(&raw))
    })
}

pub(crate) fn effective_locality_scope_hint(locality_hint: Option<&str>) -> Option<String> {
    locality_hint
        .and_then(sanitize_locality_scope)
        .or_else(trusted_runtime_locality_scope_from_env)
}

pub(crate) fn append_scope_to_query(query: &str, scope: &str) -> String {
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

pub(crate) fn resolved_query_contract_with_locality_hint(
    query: &str,
    locality_hint: Option<&str>,
) -> String {
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

pub(crate) fn resolved_query_contract(query: &str) -> String {
    resolved_query_contract_with_locality_hint(query, None)
}

pub(crate) fn semantic_retrieval_query_contract_with_locality_hint(
    query: &str,
    locality_hint: Option<&str>,
) -> String {
    let resolved = resolved_query_contract_with_locality_hint(query, locality_hint);
    if resolved.trim().is_empty() {
        return resolved;
    }
    if query_is_generic_headline_collection(&resolved) {
        return generic_headline_search_phrase(&resolved);
    }

    let facets = analyze_query_facets(&resolved);
    let weather_single_snapshot = prefers_single_fact_snapshot(&resolved) && {
        let padded = normalized_phrase_query(&resolved);
        padded.contains(" weather ") || padded.contains(" forecast ")
    };
    if weather_single_snapshot {
        if let Some(scope) = explicit_query_scope_hint(&resolved) {
            return format!(
                "weather current conditions temperature humidity wind in {}",
                scope
            );
        }
        return "weather current conditions temperature humidity wind".to_string();
    }

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

pub(crate) fn query_anchor_tokens(
    query_contract: &str,
    constraints: &ConstraintSet,
) -> BTreeSet<String> {
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

pub(crate) fn query_native_anchor_tokens(query_contract: &str) -> BTreeSet<String> {
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

pub(crate) fn build_query_constraint_projection_with_locality_hint(
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

pub(crate) fn build_query_constraint_projection(
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

pub(crate) fn projection_constraint_search_terms(
    projection: &QueryConstraintProjection,
) -> Vec<String> {
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
    if projection.query_facets.grounded_external_required
        && projection_prefers_service_status_surfaces(projection)
    {
        terms.push("official status page".to_string());
        terms.push("service health dashboard".to_string());
        terms.push("incident update".to_string());
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

pub(crate) fn projection_prefers_service_status_surfaces(
    projection: &QueryConstraintProjection,
) -> bool {
    let incident_tokens = [
        "incident",
        "incidents",
        "outage",
        "outages",
        "downtime",
        "availability",
        "degraded",
        "degradation",
    ];
    let status_tokens = ["status", "service", "health", "dashboard", "provider"];
    projection
        .query_tokens
        .iter()
        .any(|token| incident_tokens.contains(&token.as_str()))
        || (projection
            .query_tokens
            .iter()
            .any(|token| status_tokens.contains(&token.as_str()))
            && projection.query_facets.goal.external_hits > 0)
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

pub(crate) fn source_anchor_tokens(url: &str, title: &str, excerpt: &str) -> BTreeSet<String> {
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

pub(crate) fn is_search_hub_url(url: &str) -> bool {
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
    let is_google_news_hub = host == "news.google.com"
        && (path == "/"
            || path.starts_with("/topics")
            || path.starts_with("/topstories")
            || path.starts_with("/home")
            || path.starts_with("/news"));
    let is_news_feed_wrapper = is_news_feed_wrapper_url(url);
    let is_generic_query_search_hub = path.contains("/search")
        || path.ends_with("/search")
        || path.starts_with("/find")
        || path.contains("/results");

    is_google_news_hub
        || is_news_feed_wrapper
        || ((is_ddg_hub || is_bing_hub || is_google_hub || is_generic_query_search_hub)
            && has_query)
}

pub(crate) fn is_news_feed_wrapper_url(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url.trim()) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    if host.to_ascii_lowercase() != "news.google.com" {
        return false;
    }
    let path = parsed.path().to_ascii_lowercase();
    path.starts_with("/rss/articles")
        || path.starts_with("/rss/read")
        || path.starts_with("/rss/topics")
}

pub(crate) fn is_multi_item_listing_url(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url.trim()) else {
        return false;
    };
    let path = parsed.path().trim_matches('/').to_ascii_lowercase();
    if path.is_empty() {
        return true;
    }
    let segments = path
        .split('/')
        .filter(|segment| !segment.trim().is_empty())
        .map(|segment| segment.to_ascii_lowercase())
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return true;
    }

    const LISTING_MARKERS: &[&str] = &[
        "news",
        "latest",
        "headline",
        "headlines",
        "top",
        "story",
        "stories",
        "world",
        "us",
        "u-s",
        "politics",
        "business",
        "tech",
        "technology",
        "science",
        "health",
        "sports",
        "entertainment",
        "video",
        "videos",
        "category",
        "categories",
        "section",
        "sections",
        "topic",
        "topics",
        "home",
        "index",
        "live",
    ];

    let marker_segment = |segment: &str| {
        if segment.is_empty() {
            return false;
        }
        if LISTING_MARKERS.contains(&segment) {
            return true;
        }
        segment
            .split('-')
            .all(|token| !token.is_empty() && LISTING_MARKERS.contains(&token))
    };

    let short_listing = segments.len() <= 2
        && segments.iter().all(|segment| {
            if segment.chars().any(|ch| ch.is_ascii_digit()) {
                return false;
            }
            marker_segment(segment)
        });
    if short_listing {
        return true;
    }

    segments.len() <= 2
        && segments
            .last()
            .map(|segment| {
                segment.ends_with("-news")
                    || segment.ends_with("-headlines")
                    || segment.ends_with("-stories")
            })
            .unwrap_or(false)
}

pub(crate) fn is_citable_web_url(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url.trim()) else {
        return false;
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        return false;
    }
    parsed
        .host_str()
        .map(|host| !host.trim().is_empty())
        .unwrap_or(false)
}

pub(crate) fn candidate_time_sensitive_resolvable_payload(title: &str, excerpt: &str) -> bool {
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

pub(crate) fn compatibility_passes_projection(
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

pub(crate) fn candidate_constraint_compatibility(
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

pub(crate) fn probe_hint_anchor_tokens(title: &str, excerpt: &str) -> BTreeSet<String> {
    let mut out = normalized_anchor_tokens(title);
    out.extend(normalized_anchor_tokens(excerpt));
    out
}

pub(crate) fn projection_probe_hint_anchor_phrase(
    projection: &QueryConstraintProjection,
    candidate_hints: &[PendingSearchReadSummary],
) -> Option<String> {
    if candidate_hints.is_empty() {
        return None;
    }
    if projection.query_facets.grounded_external_required
        && projection_prefers_service_status_surfaces(projection)
    {
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

pub(crate) fn projection_native_anchor_phrase(
    projection: &QueryConstraintProjection,
) -> Option<String> {
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

pub(crate) fn projection_locality_semantic_anchor_phrase(
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

pub(crate) fn projection_probe_conflict_exclusion_terms(
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

pub(crate) fn projection_probe_host_exclusion_terms(
    projection: &QueryConstraintProjection,
    candidate_hints: &[PendingSearchReadSummary],
) -> Vec<String> {
    if candidate_hints.is_empty() {
        return Vec::new();
    }
    let time_sensitive_scope = projection
        .constraints
        .scopes
        .contains(&ConstraintScope::TimeSensitive);
    let host_exclusion_allowed = time_sensitive_scope
        || (projection.query_facets.grounded_external_required
            && projection_prefers_service_status_surfaces(projection));
    if !host_exclusion_allowed {
        return Vec::new();
    }

    let mut host_hits = BTreeMap::<String, usize>::new();
    for hint in candidate_hints {
        let title = hint.title.as_deref().unwrap_or_default();
        let observed = format!("{} {}", title, hint.excerpt);
        if time_sensitive_scope && contains_current_condition_metric_signal(&observed) {
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

pub(crate) fn projection_probe_structural_terms(
    projection: &QueryConstraintProjection,
) -> Vec<String> {
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
    if projection.query_facets.grounded_external_required
        && projection_prefers_service_status_surfaces(projection)
    {
        terms.push("\"official status page\"".to_string());
        terms.push("\"service health\"".to_string());
        terms.push("\"incident update\"".to_string());
    }
    terms
}

pub(crate) fn projection_probe_progressive_fallback_terms(
    projection: &QueryConstraintProjection,
) -> Vec<String> {
    let mut terms = Vec::new();
    if projection
        .constraints
        .scopes
        .contains(&ConstraintScope::TimeSensitive)
    {
        terms.push("\"latest update\"".to_string());
        terms.push("\"service advisory\"".to_string());
        terms.push("\"status dashboard\"".to_string());
        terms.push("\"incident report\"".to_string());
        terms.push("\"customer impact\"".to_string());
        terms.push("\"workaround\"".to_string());
    }
    if projection.query_facets.grounded_external_required {
        terms.push("\"official status page\"".to_string());
        terms.push("\"service health\"".to_string());
        terms.push("\"incident update\"".to_string());
        terms.push("\"statuspage\"".to_string());
    }
    terms.extend(projection_probe_structural_terms(projection));

    let mut deduped = Vec::new();
    let mut seen = BTreeSet::new();
    for term in terms {
        let key = term.trim().to_ascii_lowercase();
        if key.is_empty() || !seen.insert(key) {
            continue;
        }
        deduped.push(term);
    }
    deduped
}

pub(crate) fn append_unique_query_terms(base_query: &str, terms: &[String]) -> String {
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
    let resolved = resolved_query_contract_with_locality_hint(query, locality_hint);
    if resolved.trim().is_empty() {
        return String::new();
    }
    if query_is_generic_headline_collection(&resolved) {
        return generic_headline_search_phrase(&resolved);
    }

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
    let headline_collection_query = query_is_generic_headline_collection(query);
    let projection = headline_collection_query.then(|| {
        build_query_constraint_projection_with_locality_hint(
            query,
            min_sources,
            candidate_hints,
            locality_hint,
        )
    });
    if headline_collection_query {
        let mut diversification_terms = vec![
            "latest headlines".to_string(),
            "breaking news".to_string(),
            "multiple outlets".to_string(),
            "world".to_string(),
            "politics".to_string(),
            "business".to_string(),
        ];
        if let Some(projection_ref) = projection.as_ref() {
            let host_exclusion_terms =
                projection_probe_host_exclusion_terms(projection_ref, candidate_hints);
            for term in host_exclusion_terms.into_iter().take(1) {
                if diversification_terms
                    .iter()
                    .any(|existing| existing == &term)
                {
                    continue;
                }
                diversification_terms.push(term);
            }
        }
        let diversified_query = append_unique_query_terms(&grounded_query, &diversification_terms);
        if !diversified_query.trim().is_empty()
            && !diversified_query.eq_ignore_ascii_case(prior_trimmed)
        {
            return Some(diversified_query);
        }
    }
    if prior_trimmed.is_empty() || !grounded_query.eq_ignore_ascii_case(prior_trimmed) {
        return Some(grounded_query);
    }
    let projection = projection.unwrap_or_else(|| {
        build_query_constraint_projection_with_locality_hint(
            query,
            min_sources,
            candidate_hints,
            locality_hint,
        )
    });
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
        for fallback_term in projection_probe_progressive_fallback_terms(&projection) {
            let fallback_query = append_unique_query_terms(&grounded_query, &[fallback_term]);
            if fallback_query.trim().is_empty()
                || fallback_query.eq_ignore_ascii_case(prior_trimmed)
            {
                continue;
            }
            return Some(fallback_query);
        }
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

pub(crate) fn pre_read_candidate_plan(
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
    let mut probe_source_hints = candidate_source_hints.clone();
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
    let explicit_locality_scope =
        projection.locality_scope.is_some() && !projection.locality_scope_inferred;
    let can_prune_by_locality = projection.locality_scope.is_some()
        && constraints.scopes.contains(&ConstraintScope::TimeSensitive)
        && (locality_compatible_candidates >= min_required
            || (allow_floor_recovery_exploration && locality_compatible_candidates > 0)
            || (explicit_locality_scope && locality_compatible_candidates > 0));
    let can_prune_by_positive_compatibility =
        constraints.scopes.contains(&ConstraintScope::TimeSensitive)
            && positive_compatibility_candidates >= min_required;
    let has_constraint_objective = projection.has_constraint_objective();
    let time_sensitive_scope = constraints.scopes.contains(&ConstraintScope::TimeSensitive);
    let reject_search_hub = projection.reject_search_hub_candidates();
    let headline_lookup_mode = query_is_generic_headline_collection(query_contract);
    let prefer_non_listing_sources = query_prefers_multi_item_cardinality(query_contract);
    let mut requires_constraint_search_probe =
        if !has_constraint_objective || scoreable_candidates == 0 {
            false
        } else {
            let compatibility_gap = compatible_candidates < min_required;
            let resolvability_gap = resolvable_candidates < min_required;
            if strict_grounded_compatibility {
                compatibility_gap || resolvability_gap
            } else {
                (constraints.scopes.contains(&ConstraintScope::TimeSensitive)
                    && (compatibility_gap || resolvability_gap))
                    || (projection.query_facets.grounded_external_required && compatibility_gap)
            }
        };

    let mut candidate_urls = ranked
        .iter()
        .filter_map(|(_, url, score, _, compatibility, _)| {
            if reject_search_hub && is_search_hub_url(url) {
                return None;
            }
            if headline_lookup_mode && is_news_feed_wrapper_url(url) {
                return None;
            }
            if prefer_non_listing_sources && is_multi_item_listing_url(url) {
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
            if (can_prune_by_locality || explicit_locality_scope)
                && !compatibility.locality_compatible
            {
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
            .filter(|(_, url, _, _, _, _)| {
                !prefer_non_listing_sources || !is_multi_item_listing_url(url)
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
            if headline_lookup_mode && is_news_feed_wrapper_url(url) {
                continue;
            }
            if prefer_non_listing_sources && is_multi_item_listing_url(url) {
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
    let distinct_domain_floor = required_distinct_domain_floor(query_contract);
    if distinct_domain_floor > 1 && !candidate_urls.is_empty() {
        let mut seen_domains = BTreeSet::new();
        let mut distinct_domain_urls = Vec::new();
        for url in &candidate_urls {
            let trimmed = url.trim();
            if trimmed.is_empty() {
                continue;
            }
            let domain_key =
                canonical_domain_key(trimmed).unwrap_or_else(|| trimmed.to_ascii_lowercase());
            if seen_domains.insert(domain_key) {
                distinct_domain_urls.push(trimmed.to_string());
            }
        }
        if !distinct_domain_urls.is_empty() {
            candidate_urls = distinct_domain_urls;
        }
        if seen_domains.len() < distinct_domain_floor {
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
            if headline_lookup_mode && is_news_feed_wrapper_url(trimmed) {
                continue;
            }
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
        if headline_lookup_mode && is_news_feed_wrapper_url(url) {
            continue;
        }
        if prefer_non_listing_sources && is_multi_item_listing_url(url) {
            continue;
        }
        if (can_prune_by_locality || explicit_locality_scope) && !compatibility.locality_compatible
        {
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

    if explicit_locality_scope {
        probe_source_hints = candidate_source_hints.clone();
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

pub(crate) fn required_citations_per_story(query: &str) -> usize {
    let tokens = query.split_whitespace().collect::<Vec<_>>();
    let normalized_query = normalized_phrase_query(query);
    let has_for_each_directive = normalized_query.contains(" for each ");
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
        let third = tokens
            .get(idx + 2)
            .map(|value| {
                value
                    .trim()
                    .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
                    .to_ascii_lowercase()
            })
            .unwrap_or_default();
        let fourth = tokens
            .get(idx + 3)
            .map(|value| {
                value
                    .trim()
                    .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
                    .to_ascii_lowercase()
            })
            .unwrap_or_default();

        let looks_like_citation_directive = matches!(
            next.as_str(),
            "citation" | "citations" | "source" | "sources"
        ) || ((next == "source" || next == "sources")
            && matches!(third.as_str(), "citation" | "citations"));
        let explicit_each_directive = next == "each" || third == "each" || fourth == "each";
        let explicit_per_story_directive =
            third == "per" && matches!(fourth.as_str(), "story" | "stories" | "item" | "items");
        if looks_like_citation_directive
            && (explicit_each_directive || explicit_per_story_directive || has_for_each_directive)
        {
            return value.clamp(1, 6);
        }
    }

    if query_is_generic_headline_collection(query) {
        return 2;
    }

    if query_prefers_multi_item_cardinality(query) {
        // Multi-story web briefs cite the primary article URL per story by default.
        // Explicit "N citations/sources each" directives are handled above.
        return 1;
    }

    WEB_PIPELINE_CITATIONS_PER_STORY
}

pub(crate) fn required_distinct_citations(query: &str) -> usize {
    required_story_count(query).saturating_mul(required_citations_per_story(query))
}

pub(crate) fn web_pipeline_min_sources(query: &str) -> u32 {
    if query_prefers_multi_item_cardinality(query) {
        let target = required_story_count(query).max(1) as u32;
        return target.min(WEB_PIPELINE_CONSTRAINT_SEARCH_LIMIT_MAX).max(1);
    }
    if prefers_single_fact_snapshot(query) {
        return 2;
    }
    let lower = query.to_ascii_lowercase();
    let explicit_citation_floor =
        lower.contains("citation") || lower.contains("citations") || lower.contains("sources");
    if explicit_citation_floor {
        let target = required_distinct_citations(query) as u32;
        return target.clamp(
            WEB_PIPELINE_CONSTRAINT_SEARCH_LIMIT_MIN,
            WEB_PIPELINE_CONSTRAINT_SEARCH_LIMIT_MAX,
        );
    }
    WEB_PIPELINE_DEFAULT_MIN_SOURCES
}

pub(crate) fn requires_mailbox_access_notice(query: &str) -> bool {
    is_mailbox_connector_intent(query)
}

pub(crate) fn render_mailbox_access_limited_draft(draft: &SynthesisDraft) -> String {
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
