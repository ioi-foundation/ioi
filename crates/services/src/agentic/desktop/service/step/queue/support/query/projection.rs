use super::*;

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
    let locality_scope = explicit_query_scope_hint(&projection_query_contract);
    let locality_tokens = locality_scope
        .as_deref()
        .map(normalized_locality_tokens)
        .unwrap_or_default();
    let structural_tokens = query_structural_directive_tokens(&projection_query_contract);
    let query_native_tokens = query_native_anchor_tokens(&projection_query_contract);
    let query_native_tokens_ordered = ordered_anchor_phrase_tokens(
        &projection_query_contract,
        &locality_tokens,
        &structural_tokens,
    );
    let query_tokens = query_anchor_tokens(&projection_query_contract, &constraints);
    let locality_scope_inferred = original_locality_scope.is_none()
        && trusted_locality_scope.is_none()
        && inferred_locality_scope.is_some();

    QueryConstraintProjection {
        constraints,
        query_facets,
        query_native_tokens,
        query_native_tokens_ordered,
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

fn simple_anchor_variant(token: &str) -> Option<String> {
    let normalized = token.trim().to_ascii_lowercase();
    if normalized.len() <= 3 {
        return None;
    }
    if normalized == "menus" {
        return Some("menu".to_string());
    }
    if normalized == "news" || normalized.ends_with("ss") || normalized.ends_with("ous") {
        return None;
    }
    if let Some(stem) = normalized.strip_suffix("ies") {
        if stem.len() >= 2 {
            return Some(format!("{stem}y"));
        }
    }
    if normalized.ends_with("ches")
        || normalized.ends_with("shes")
        || normalized.ends_with("sses")
        || normalized.ends_with("xes")
        || normalized.ends_with("zes")
        || normalized.ends_with("oes")
    {
        return normalized
            .strip_suffix("es")
            .map(str::to_string)
            .filter(|value| !value.is_empty());
    }
    normalized
        .strip_suffix('s')
        .filter(|stem| stem.len() >= 3)
        .filter(|_| !normalized.ends_with("us") || normalized == "menus")
        .map(str::to_string)
}

fn expanded_query_anchor_tokens(tokens: &BTreeSet<String>) -> BTreeSet<String> {
    let mut expanded = tokens.clone();
    for token in tokens {
        if let Some(variant) = simple_anchor_variant(token) {
            expanded.insert(variant);
        }
    }
    expanded
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
    let is_google_news_article_wrapper =
        host == "news.google.com" && path.starts_with("/rss/articles/");
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
        && !is_google_news_article_wrapper
        && (path == "/"
            || path.starts_with("/topics")
            || path.starts_with("/topstories")
            || path.starts_with("/home")
            || path.starts_with("/news")
            || path.starts_with("/rss/"));
    let is_generic_query_search_hub = path.contains("/search")
        || path.ends_with("/search")
        || path.starts_with("/find")
        || path.contains("/results");

    is_google_news_hub
        || ((is_ddg_hub || is_bing_hub || is_google_hub || is_generic_query_search_hub)
            && has_query)
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

pub(crate) fn candidate_time_sensitive_resolvable_payload(
    url: &str,
    title: &str,
    excerpt: &str,
) -> bool {
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

    fn schema_has_price_without_quote(schema: &MetricSchemaProfile, text: &str) -> bool {
        schema.axis_hits.contains(&MetricAxis::Price) && !has_price_quote_payload(text)
    }

    if source_has_human_challenge_signal(url, title, excerpt) {
        return false;
    }
    let source_signals = analyze_source_record_signals(url, title, excerpt);
    if source_signals.low_priority_hits > 0 || source_signals.low_priority_dominates() {
        return false;
    }

    let source_text = format!("{} {}", title, excerpt);
    let source_schema = analyze_metric_schema(&source_text);
    let source_price_axis = source_schema.axis_hits.contains(&MetricAxis::Price);
    if source_price_axis {
        if has_price_quote_payload(&source_text) {
            return true;
        }
    } else if source_schema.has_current_observation_payload()
        || (source_schema.numeric_token_hits > 0 && source_schema.unit_hits > 0)
    {
        return true;
    }

    let excerpt_schema = analyze_metric_schema(excerpt);
    let excerpt_has_price_without_quote = schema_has_price_without_quote(&excerpt_schema, excerpt);
    if excerpt_schema.axis_hits.contains(&MetricAxis::Price) {
        if has_price_quote_payload(excerpt) {
            return true;
        }
    } else if observation_surface_signal(&excerpt_schema) && !excerpt_has_price_without_quote {
        return true;
    }

    if !excerpt.trim().is_empty() {
        return false;
    }

    let title_schema = analyze_metric_schema(title);
    if title_schema.axis_hits.contains(&MetricAxis::Price) {
        return has_price_quote_payload(title);
    }
    observation_surface_signal(&title_schema)
        && !schema_has_price_without_quote(&title_schema, title)
}

pub(crate) fn compatibility_passes_projection(
    projection: &QueryConstraintProjection,
    compatibility: &CandidateConstraintCompatibility,
) -> bool {
    if !compatibility.is_compatible {
        return false;
    }
    let locality_scope_enforced = projection
        .constraints
        .scopes
        .contains(&ConstraintScope::TimeSensitive)
        || projection.query_facets.grounded_external_required;
    if locality_scope_enforced
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
    let source_structural_locality = source_structural_locality_tokens(url, title)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let expanded_query_tokens = expanded_query_anchor_tokens(query_tokens);
    let expanded_query_native_tokens = expanded_query_anchor_tokens(query_native_tokens);
    let anchor_overlap_count = expanded_query_tokens.intersection(&source_tokens).count();
    let native_anchor_overlap_count = expanded_query_native_tokens
        .intersection(&source_tokens)
        .count();
    let locality_overlap_count = query_locality_tokens.intersection(&source_locality).count();
    let structural_locality_overlap_count = query_locality_tokens
        .intersection(&source_structural_locality)
        .count();
    let query_anchor_count = query_tokens.len();

    let source_schema = analyze_metric_schema(&format!("{} {}", title, excerpt));
    let axis_overlap_count = source_schema.axis_overlap_score(&constraints.required_facets);
    let has_current_observation_payload = source_schema.has_current_observation_payload();
    let has_time_sensitive_resolvable_payload =
        candidate_time_sensitive_resolvable_payload(url, title, excerpt);
    let semantic_anchor_overlap_count = expanded_query_native_tokens
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
    let has_structural_locality_overlap =
        structural_locality_overlap_count >= QUERY_COMPATIBILITY_MIN_LOCALITY_OVERLAP;
    let locality_scope_active = has_query_locality_scope
        && !query_locality_tokens.is_empty()
        && (constraints.scopes.contains(&ConstraintScope::TimeSensitive)
            || query_facets.grounded_external_required);
    let grounded_locality_scope_active =
        locality_scope_active && query_facets.grounded_external_required;
    let typed_structural_match = typed_match
        && (has_time_sensitive_resolvable_payload
            || has_current_observation_payload
            || axis_overlap_count > 0);
    let requires_semantic_anchor_overlap =
        locality_scope_active && semantic_anchor_token_count > 0 && !typed_structural_match;
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
    if grounded_locality_scope_active && has_structural_locality_overlap {
        compatibility_score = compatibility_score.saturating_add(
            structural_locality_overlap_count * QUERY_COMPATIBILITY_LOCALITY_OVERLAP_WEIGHT,
        );
    }
    let locality_compatible = if grounded_locality_scope_active {
        has_structural_locality_overlap
    } else if locality_scope_active {
        has_locality_overlap
    } else {
        true
    };

    CandidateConstraintCompatibility {
        compatibility_score,
        is_compatible,
        locality_compatible,
    }
}

pub(crate) fn probe_hint_anchor_tokens(title: &str, excerpt: &str) -> BTreeSet<String> {
    let observed = format!("{} {}", title, excerpt);
    let structural_tokens = query_structural_directive_tokens(&observed);
    let mut out = normalized_anchor_tokens(title);
    out.extend(normalized_anchor_tokens(excerpt));
    out.retain(|token| !structural_tokens.contains(token) && !is_locality_scope_noise_token(token));
    out
}

pub(crate) fn projection_probe_hint_anchor_phrase(
    projection: &QueryConstraintProjection,
    candidate_hints: &[PendingSearchReadSummary],
) -> Option<String> {
    if candidate_hints.is_empty() {
        return None;
    }

    if projection.enforce_grounded_compatibility() {
        // For grounded retrieval we only want the next query to carry the original
        // typed contract plus discovery-backed exclusions. Pulling novel anchor
        // tokens from noisy candidate titles turns drift into the next probe.
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
            && !candidate_time_sensitive_resolvable_payload(&hint.url, title, &hint.excerpt)
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

    let anchor_tokens = ranked_tokens
        .iter()
        .filter_map(|(token, hits)| {
            (*hits >= QUERY_PROBE_HINT_MIN_SHARED_TOKEN_HITS).then(|| token.clone())
        })
        .take(QUERY_PROBE_HINT_MAX_TOKENS)
        .collect::<Vec<_>>();

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
    let metric_tokens = projection
        .constraints
        .required_facets
        .iter()
        .copied()
        .flat_map(|axis| normalized_anchor_tokens(metric_axis_search_phrase(axis)))
        .collect::<BTreeSet<_>>();
    let mut anchor_phrase_tokens = if !metric_tokens.is_empty() {
        let mut tokens = projection
            .query_native_tokens_ordered
            .iter()
            .filter(|token| !metric_tokens.contains(*token))
            .take(3)
            .cloned()
            .collect::<Vec<_>>();
        tokens.extend(
            projection
                .query_native_tokens_ordered
                .iter()
                .filter(|token| metric_tokens.contains(*token))
                .take(2)
                .cloned(),
        );
        tokens
    } else {
        projection
            .query_native_tokens_ordered
            .iter()
            .take(4)
            .cloned()
            .collect::<Vec<_>>()
    };
    anchor_phrase_tokens.dedup();
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
            .query_native_tokens_ordered
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
    let host_exclusion_allowed =
        time_sensitive_scope || projection.enforce_grounded_compatibility();
    if !host_exclusion_allowed {
        return Vec::new();
    }

    fn collapsed_host_keys(host: &str) -> Vec<String> {
        let normalized = host.trim().trim_start_matches("www.").to_ascii_lowercase();
        if normalized.is_empty() {
            return Vec::new();
        }

        let mut out = BTreeSet::new();
        out.insert(normalized.clone());
        let labels = normalized.split('.').collect::<Vec<_>>();
        if labels.len() >= 2 {
            out.insert(format!(
                "{}.{}",
                labels[labels.len() - 2],
                labels[labels.len() - 1]
            ));
        }
        out.into_iter().collect()
    }

    let mut bad_host_hits = BTreeMap::<String, usize>::new();
    let mut good_host_hits = BTreeMap::<String, usize>::new();
    for hint in candidate_hints {
        let title = hint.title.as_deref().unwrap_or_default();
        let Some(host) = source_host(&hint.url) else {
            continue;
        };
        if host.trim().is_empty() {
            continue;
        }
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
        let payload_resolvable = !time_sensitive_scope
            || candidate_time_sensitive_resolvable_payload(&hint.url, title, &hint.excerpt);
        let compatible = compatibility_passes_projection(projection, &compatibility);
        let host_keys = collapsed_host_keys(&host);
        if compatible && payload_resolvable {
            for key in host_keys {
                *good_host_hits.entry(key).or_insert(0) += 1;
            }
            continue;
        }
        for key in host_keys {
            *bad_host_hits.entry(key).or_insert(0) += 1;
        }
    }

    let mut ranked_hosts = bad_host_hits
        .into_iter()
        .filter(|(host, hits)| {
            *hits >= QUERY_PROBE_ESCALATION_MIN_CONFLICT_HITS && !good_host_hits.contains_key(host)
        })
        .collect::<Vec<_>>();
    ranked_hosts.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    let mut selected_hosts = Vec::new();
    for (host, _) in ranked_hosts {
        if selected_hosts.iter().any(|selected: &String| {
            host == *selected
                || host.ends_with(&format!(".{selected}"))
                || selected.ends_with(&format!(".{host}"))
        }) {
            continue;
        }
        selected_hosts.push(host);
        if selected_hosts.len() >= QUERY_PROBE_ESCALATION_MAX_HOST_EXCLUSION_TERMS {
            break;
        }
    }
    selected_hosts
        .into_iter()
        .map(|host| format!("-site:{host}"))
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
    if projection.query_facets.grounded_external_required
        && projection_prefers_service_status_surfaces(projection)
    {
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

#[cfg(test)]
mod tests {
    use super::candidate_time_sensitive_resolvable_payload;

    #[test]
    fn time_sensitive_resolvable_payload_rejects_low_priority_forum_surface() {
        assert!(!candidate_time_sensitive_resolvable_payload(
            "https://www.reddit.com/r/CryptoCurrency/comments/14zq3b4/why_is_the_bitcoin_price_falling_what_is_the/",
            "Why is the Bitcoin price falling?",
            "Current BTC price is $68,123, but this thread is community speculation about where it goes next.",
        ));
    }

    #[test]
    fn time_sensitive_resolvable_payload_accepts_observation_surface() {
        assert!(candidate_time_sensitive_resolvable_payload(
            "https://www.example.com/markets/bitcoin-price",
            "Bitcoin price",
            "BTC price today is $68,123.45 as of 14:32 UTC.",
        ));
    }

    #[test]
    fn time_sensitive_resolvable_payload_rejects_marketing_percentages_on_price_pages() {
        assert!(!candidate_time_sensitive_resolvable_payload(
            "https://crypto.com/en/price/bitcoin",
            "Bitcoin (BTC) Price Today: BTC Live Price, Charts, News - Crypto.com International",
            "99% 0% fee first 30 days The purpose of this website is solely to display information regarding the products and services available",
        ));
    }
}
