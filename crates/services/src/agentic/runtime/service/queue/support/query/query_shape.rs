use super::*;

const EXPLICIT_COUNT_COLLECTION_NOUNS: &[&str] = &[
    "citations",
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
    "sources",
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

const MULTI_ITEM_REPORT_DIRECTIVES: &[&str] = &[
    " briefing ",
    " overview ",
    " survey ",
    " landscape ",
    " digest ",
];

const DOCUMENT_REPORT_DIRECTIVES: &[&str] = &[
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
    tokens.extend(marker_lexeme_tokens(MULTI_ITEM_REPORT_DIRECTIVES));
    tokens.extend(marker_lexeme_tokens(DOCUMENT_REPORT_DIRECTIVES));

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

fn query_requests_multi_item_report(padded_query: &str) -> bool {
    MULTI_ITEM_REPORT_DIRECTIVES
        .iter()
        .any(|marker| padded_query.contains(marker))
}

fn query_requests_document_report(padded_query: &str) -> bool {
    DOCUMENT_REPORT_DIRECTIVES
        .iter()
        .any(|marker| padded_query.contains(marker))
}

pub(crate) fn explicit_source_cluster_count_hint(query: &str) -> Option<usize> {
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

pub(crate) fn required_source_cluster_count(query: &str) -> usize {
    if let Some(explicit) = explicit_source_cluster_count_hint(query) {
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
        required_source_cluster_count(query_contract).max(1)
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
    if explicit_source_cluster_count_hint(query).is_some() {
        return false;
    }
    let padded = normalized_phrase_query(query);
    let explicit_plural_collection_surface = EXPLICIT_COUNT_COLLECTION_NOUNS
        .iter()
        .any(|noun| padded.contains(&format!(" {noun} ")));
    let semantic_tokens = query_semantic_anchor_tokens(query);
    let plural_semantic_surface = semantic_surface_is_plural(&semantic_tokens);
    let ranked_plural_collection = plural_semantic_surface
        && MULTI_ITEM_RANKING_DIRECTIVES
            .iter()
            .chain([" top "].iter())
            .chain(MULTI_ITEM_COMPARISON_DIRECTIVES.iter())
            .any(|marker| padded.contains(marker));
    let plural_answer_surface =
        plural_semantic_surface && query_requests_multi_item_report(&padded);
    if ranked_plural_collection
        || plural_answer_surface
        || (explicit_plural_collection_surface && facets.goal.recency_hits > 0)
    {
        return false;
    }
    true
}

pub(crate) fn query_prefers_multi_item_cardinality(query: &str) -> bool {
    if query.trim().is_empty() {
        return false;
    }
    if explicit_source_cluster_count_hint(query).is_some() {
        return true;
    }
    if prefers_single_fact_snapshot(query) {
        return false;
    }
    if query_prefers_document_report_layout(query) {
        return false;
    }

    let padded = normalized_phrase_query(query);
    let has_collection_directive = MULTI_ITEM_RANKING_DIRECTIVES
        .iter()
        .chain(MULTI_ITEM_COMPARISON_DIRECTIVES.iter())
        .any(|marker| padded.contains(marker));
    let has_ranked_collection = padded.contains(" top ");
    let has_explicit_collection_noun = EXPLICIT_COUNT_COLLECTION_NOUNS
        .iter()
        .any(|noun| padded.contains(&format!(" {noun} ")));
    let semantic_tokens = query_semantic_anchor_tokens(query);
    let plural_semantic_surface = semantic_surface_is_plural(&semantic_tokens);
    let has_plural_answer_surface =
        plural_semantic_surface && query_requests_multi_item_report(&padded);
    let has_time_sensitive_collection_surface =
        has_explicit_collection_noun && analyze_query_facets(query).goal.recency_hits > 0;

    query_requests_comparison(query)
        || ((has_ranked_collection
            || has_collection_directive
            || has_plural_answer_surface
            || has_time_sensitive_collection_surface)
            && (plural_semantic_surface || has_explicit_collection_noun))
}

pub(crate) fn query_requests_comparison(query: &str) -> bool {
    if query.trim().is_empty() {
        return false;
    }
    let padded = normalized_phrase_query(query);
    if padded.contains(" better ") && padded.contains(" or ") {
        return true;
    }
    MULTI_ITEM_COMPARISON_DIRECTIVES
        .iter()
        .any(|marker| padded.contains(marker))
}

pub(crate) fn query_asks_to_find_sources(query: &str) -> bool {
    if query.trim().is_empty() {
        return false;
    }
    let padded = normalized_phrase_query(query);
    let has_find_verb = [
        " find ",
        " gather ",
        " look up ",
        " locate ",
        " collect ",
        " source ",
        " cite ",
        " citations ",
    ]
    .iter()
    .any(|marker| padded.contains(marker));
    let has_source_target = [
        " source ",
        " sources ",
        " citation ",
        " citations ",
        " references ",
        " links ",
    ]
    .iter()
    .any(|marker| padded.contains(marker));

    has_find_verb && has_source_target
}

pub(crate) fn query_requires_market_quote_grounding(query: &str) -> bool {
    if query.trim().is_empty() {
        return false;
    }

    let padded = normalized_phrase_query(query);
    let facets = analyze_query_facets(query);
    let explicitly_historical = [
        " historical ",
        " historically ",
        " last year ",
        " in 2020 ",
        " in 2021 ",
        " in 2022 ",
        " in 2023 ",
        " in 2024 ",
        " in 2025 ",
    ]
    .iter()
    .any(|marker| padded.contains(marker));
    let time_sensitive = facets.goal.recency_hits > 0
        || [
            " current ",
            " currently ",
            " right now ",
            " today ",
            " latest ",
            " live ",
            " now ",
        ]
        .iter()
        .any(|marker| padded.contains(marker));
    let finance_or_market_intent = [
        " investment ",
        " investments ",
        " invest ",
        " investing ",
        " investor ",
        " investors ",
        " crypto ",
        " cryptocurrency ",
        " token ",
        " tokens ",
        " coin ",
        " coins ",
        " trading ",
        " traded ",
        " trade ",
        " stock ",
        " stocks ",
        " etf ",
        " assets ",
        " asset ",
    ]
    .iter()
    .any(|marker| padded.contains(marker));

    let investment_comparison = finance_or_market_intent
        && (query_requests_comparison(query) || padded.contains(" better "));

    finance_or_market_intent
        && ((time_sensitive && (query_requests_comparison(query) || padded.contains(" better ")))
            || (investment_comparison && !explicitly_historical)
            || padded.contains(" versus ")
            || padded.contains(" vs "))
}

fn market_quote_anchor_noise_tokens() -> &'static [&'static str] {
    &[
        "asset",
        "assets",
        "better",
        "coin",
        "coins",
        "crypto",
        "cryptocurrency",
        "current",
        "currently",
        "investment",
        "investments",
        "invest",
        "investing",
        "investor",
        "investors",
        "latest",
        "live",
        "market",
        "now",
        "price",
        "quote",
        "right",
        "stock",
        "stocks",
        "today",
        "token",
        "tokens",
        "trade",
        "traded",
        "trading",
        "versus",
        "which",
    ]
}

fn market_quote_anchor_tokens(segment: &str) -> BTreeSet<String> {
    let noise = market_quote_anchor_noise_tokens();
    query_semantic_anchor_tokens(segment)
        .into_iter()
        .filter(|token| !noise.contains(&token.as_str()))
        .collect()
}

pub(crate) fn query_market_quote_entity_anchor_groups(query: &str) -> Vec<BTreeSet<String>> {
    if !query_requires_market_quote_grounding(query) {
        return Vec::new();
    }

    let normalized = normalized_phrase_query(query);
    let trimmed = normalized.trim();
    let separators = [" or ", " versus ", " vs ", " between ", " against "];
    let mut split_parts = vec![trimmed.to_string()];
    for separator in separators {
        if trimmed.contains(separator) {
            split_parts = trimmed
                .split(separator)
                .map(|part| part.trim().to_string())
                .filter(|part| !part.is_empty())
                .collect();
            break;
        }
    }

    let mut groups = Vec::new();
    for part in split_parts {
        let tokens = market_quote_anchor_tokens(&part);
        if !tokens.is_empty() {
            groups.push(tokens);
        }
    }

    if groups.len() >= 2 {
        return groups;
    }

    let fallback_tokens = market_quote_anchor_tokens(query);
    if fallback_tokens.is_empty() {
        Vec::new()
    } else {
        vec![fallback_tokens]
    }
}

pub(crate) fn market_quote_grounding_search_query(query: &str) -> Option<String> {
    if !query_requires_market_quote_grounding(query) {
        return None;
    }

    let mut anchor_terms = Vec::new();
    for group in query_market_quote_entity_anchor_groups(query) {
        for token in group {
            if !anchor_terms.iter().any(|existing| existing == &token) {
                anchor_terms.push(token);
            }
        }
    }
    if anchor_terms.is_empty() {
        return None;
    }

    let mut suffix = "crypto token live price quote market cap USD today".to_string();
    if query_requests_comparison(query) {
        suffix.push_str(" comparison investment use case performance risk investors");
    }
    Some(format!("{} {suffix}", anchor_terms.join(" ")))
}

fn market_quote_anchor_terms_in_order(segment: &str) -> Vec<String> {
    let noise = market_quote_anchor_noise_tokens();
    let mut out = Vec::new();
    for raw in segment.split_whitespace() {
        let normalized = raw
            .trim()
            .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
            .to_ascii_lowercase();
        if normalized.len() < QUERY_COMPATIBILITY_MIN_TOKEN_CHARS
            || normalized.chars().all(|ch| ch.is_ascii_digit())
            || is_query_stopword(&normalized)
            || noise.contains(&normalized.as_str())
            || out.iter().any(|existing| existing == &normalized)
        {
            continue;
        }
        out.push(normalized);
    }
    out
}

fn market_quote_anchor_segments(query: &str) -> Vec<String> {
    let normalized = normalized_phrase_query(query);
    let trimmed = normalized.trim();
    let separators = [" or ", " versus ", " vs ", " between ", " against "];
    for separator in separators {
        if trimmed.contains(separator) {
            return trimmed
                .split(separator)
                .map(|part| part.trim().to_string())
                .filter(|part| !part.is_empty())
                .collect();
        }
    }
    vec![trimmed.to_string()]
}

pub(crate) fn market_quote_grounding_direct_source_hints(
    query: &str,
) -> Vec<PendingSearchReadSummary> {
    if !query_requires_market_quote_grounding(query) {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for segment in market_quote_anchor_segments(query) {
        let terms = market_quote_anchor_terms_in_order(&segment);
        if terms.is_empty() {
            continue;
        }
        let slug = terms.join("-");
        if slug.is_empty() || !seen.insert(slug.clone()) {
            continue;
        }
        let label = terms
            .iter()
            .map(|term| {
                let mut chars = term.chars();
                match chars.next() {
                    Some(first) => format!("{}{}", first.to_ascii_uppercase(), chars.as_str()),
                    None => String::new(),
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        out.push(PendingSearchReadSummary {
            url: format!("https://www.coingecko.com/en/coins/{slug}"),
            title: Some(format!("{label} live price quote - CoinGecko")),
            excerpt: "Live crypto token price, market cap, and USD quote surface.".to_string(),
        });
    }
    out
}

fn generic_headline_subject_specificity(query: &str) -> usize {
    let generic_tokens = [
        "article",
        "articles",
        "best",
        "breaking",
        "current",
        "headline",
        "headlines",
        "latest",
        "news",
        "now",
        "recent",
        "report",
        "reports",
        "right",
        "source",
        "sources",
        "stories",
        "story",
        "today",
        "todays",
        "top",
    ];
    query_semantic_anchor_tokens(query)
        .into_iter()
        .filter(|token| !generic_tokens.contains(&token.as_str()))
        .count()
}

pub(crate) fn query_prefers_document_report_layout(query: &str) -> bool {
    if query.trim().is_empty() {
        return false;
    }
    if prefers_single_fact_snapshot(query) {
        return false;
    }
    let padded = normalized_phrase_query(query);
    if !query_requests_document_report(&padded) {
        return false;
    }
    let has_explicit_multi_item_shape = explicit_source_cluster_count_hint(query).is_some()
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
    if query_requests_comparison(query) {
        return false;
    }
    let padded = normalized_phrase_query(query);
    if query_requests_multi_item_report(&padded) {
        return false;
    }
    if generic_headline_subject_specificity(query) >= 3 {
        return false;
    }
    let facets = analyze_query_facets(query);
    facets.time_sensitive_public_fact
        && facets.grounded_external_required
        && !facets.service_status_lookup
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
    if query_prefers_document_report_layout(query) {
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
#[path = "query_shape/tests.rs"]
mod tests;

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
    if query_requires_market_quote_grounding(query) {
        required_facets.insert(MetricAxis::Price);
    }
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
