use super::*;

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
