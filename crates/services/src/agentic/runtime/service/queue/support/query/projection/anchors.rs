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
