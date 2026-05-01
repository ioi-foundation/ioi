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
    if !locality_scope_required {
        return None;
    }
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
            && !candidate_time_sensitive_resolvable_payload(&hint.url, title, &hint.excerpt)
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

fn starts_with_unresolved_locality_scope(raw_scope: &str) -> bool {
    let normalized = normalized_phrase_query(raw_scope);
    UNRESOLVED_LOCALITY_SCOPE_PREFIXES
        .iter()
        .any(|prefix| normalized.starts_with(&format!(" {prefix} ")))
}

fn truncate_scope_at_structural_boundary(
    raw_scope: &str,
    structural_tokens: &BTreeSet<String>,
) -> String {
    let mut tokens = Vec::new();
    let mut search_from = 0;
    for token in raw_scope.split_whitespace() {
        let Some(relative_idx) = raw_scope[search_from..].find(token) else {
            continue;
        };
        let start = search_from + relative_idx;
        let end = start + token.len();
        search_from = end;
        let normalized = token
            .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
            .to_ascii_lowercase();
        if normalized.is_empty() {
            continue;
        }
        tokens.push((start, normalized));
    }

    for (idx, (start, token)) in tokens.iter().enumerate() {
        if idx > 0 && structural_tokens.contains(token) {
            return raw_scope[..*start].trim().to_string();
        }
        if SCOPE_STRUCTURAL_CONNECTORS.contains(&token.as_str())
            && tokens
                .iter()
                .skip(idx + 1)
                .take(3)
                .any(|(_, next)| structural_tokens.contains(next))
        {
            return raw_scope[..*start].trim().to_string();
        }
    }

    raw_scope.trim().to_string()
}

fn explicit_scope_candidate(
    compact: &str,
    start: usize,
    structural_tokens: &BTreeSet<String>,
) -> Option<String> {
    let end = compact[start..]
        .char_indices()
        .find_map(|(idx, ch)| matches!(ch, '?' | '!' | '.').then_some(start + idx))
        .unwrap_or(compact.len());
    let raw_scope = compact[start..end]
        .trim_matches(|ch: char| matches!(ch, '.' | ',' | ';' | ':' | '?' | '!'))
        .trim();
    if raw_scope.is_empty() {
        return None;
    }

    let truncated_scope = truncate_scope_at_structural_boundary(raw_scope, structural_tokens);
    if truncated_scope.is_empty() || starts_with_unresolved_locality_scope(&truncated_scope) {
        return None;
    }

    let mut scope_tokens = truncated_scope.split_whitespace().collect::<Vec<_>>();
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

    let scope = sanitize_locality_scope(&scope_tokens.join(" "))?;
    (!starts_with_unresolved_locality_scope(&scope)).then_some(scope)
}

fn truncate_retrieval_scope_at_goal_semantic_boundary(goal: &str, scope: &str) -> String {
    let goal_compact = compact_whitespace(goal);
    if goal_compact.trim().is_empty() {
        return scope.trim().to_string();
    }

    let goal_scope_tokens = explicit_query_scope_hint(&goal_compact)
        .map(|value| normalized_locality_tokens(&value))
        .unwrap_or_default();
    let goal_structural_tokens = query_structural_directive_tokens(&goal_compact);
    let goal_semantic_tokens = query_native_anchor_tokens(&goal_compact);
    if goal_semantic_tokens.is_empty() && goal_structural_tokens.is_empty() {
        return scope.trim().to_string();
    }

    let mut tokens = Vec::new();
    let mut search_from = 0;
    for token in scope.split_whitespace() {
        let Some(relative_idx) = scope[search_from..].find(token) else {
            continue;
        };
        let start = search_from + relative_idx;
        let end = start + token.len();
        search_from = end;
        let normalized = token
            .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
            .to_ascii_lowercase();
        if normalized.is_empty() {
            continue;
        }
        tokens.push((start, normalized));
    }

    for (idx, (start, token)) in tokens.iter().enumerate() {
        if idx == 0 {
            continue;
        }
        if !goal_scope_tokens.contains(token)
            && (goal_structural_tokens.contains(token) || goal_semantic_tokens.contains(token))
        {
            return scope[..*start].trim().to_string();
        }
    }

    scope.trim().to_string()
}

fn cleaned_retrieval_scope_for_goal(goal: &str, scope: &str) -> Option<String> {
    let truncated = truncate_retrieval_scope_at_goal_semantic_boundary(goal, scope);
    if truncated.is_empty() {
        return None;
    }

    let scope = sanitize_locality_scope(&truncated)?;
    (!starts_with_unresolved_locality_scope(&scope)).then_some(scope)
}

fn bounded_phrase_span(haystack: &str, phrase: &str) -> Option<(usize, usize)> {
    let bytes = haystack.as_bytes();
    let mut search_from = 0;
    while let Some(relative_idx) = haystack[search_from..].find(phrase) {
        let start = search_from + relative_idx;
        let end = start + phrase.len();
        let boundary_before = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
        let boundary_after = end == bytes.len() || !bytes[end].is_ascii_alphanumeric();
        if boundary_before && boundary_after {
            return Some((start, end));
        }
        search_from = start + 1;
    }
    None
}

fn replace_locality_placeholder_with_scope(query: &str, scope: &str) -> Option<String> {
    let compact = compact_whitespace(query);
    if compact.is_empty() {
        return None;
    }
    let lower = compact.to_ascii_lowercase();
    let (start, end) = REPLACEABLE_LOCALITY_PLACEHOLDER_PHRASES
        .iter()
        .filter_map(|phrase| bounded_phrase_span(&lower, phrase))
        .min_by_key(|(start, _)| *start)?;

    let prefix = compact[..start].trim();
    let suffix = compact[end..].trim();
    let replaced = match (prefix.is_empty(), suffix.is_empty()) {
        (true, true) => format!("in {scope}"),
        (true, false) => format!("in {scope} {suffix}"),
        (false, true) => format!("{prefix} in {scope}"),
        (false, false) => format!("{prefix} in {scope} {suffix}"),
    };
    Some(compact_whitespace(&replaced))
}

pub(crate) fn explicit_query_scope_hint(query: &str) -> Option<String> {
    let compact = compact_whitespace(query);
    if compact.is_empty() {
        return None;
    }
    let lower = compact.to_ascii_lowercase();
    let mut boundary_tokens = query_structural_directive_tokens(&compact);
    boundary_tokens.extend(query_shape_boundary_tokens(&compact));
    for start in scope_anchor_starts(&lower) {
        if let Some(scope) = explicit_scope_candidate(&compact, start, &boundary_tokens) {
            return Some(scope);
        }
    }
    None
}

pub(crate) fn query_requires_locality_scope(query: &str, facets: &QueryFacetProfile) -> bool {
    facets.locality_sensitive_public_fact
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
    if let Some(rewritten) = replace_locality_placeholder_with_scope(&base, &scope) {
        return rewritten;
    }
    compact_whitespace(&append_scope_to_query(&base, &scope))
}

pub(crate) fn resolved_query_contract(query: &str) -> String {
    resolved_query_contract_with_locality_hint(query, None)
}

fn strip_parent_playbook_context(goal: &str) -> &str {
    goal.split_once("[PARENT PLAYBOOK CONTEXT]")
        .map(|(head, _)| head)
        .unwrap_or(goal)
}

pub(crate) fn semantic_retrieval_query_contract_with_locality_hint(
    query: &str,
    locality_hint: Option<&str>,
) -> String {
    semantic_retrieval_query_contract_with_contract_and_locality_hint(query, None, locality_hint)
}

const DOCUMENT_BRIEFING_SEARCH_SCAFFOLD_TOKENS: &[&str] = &[
    "using",
    "local",
    "memory",
    "web",
    "utc",
    "timestamp",
    "evidence",
    "return",
    "then",
    "cited",
    "brief",
    "briefing",
    "memo",
    "report",
    "one",
    "page",
    "findings",
    "finding",
    "uncertainties",
    "uncertainty",
    "next",
    "check",
    "checks",
    "source",
    "sources",
    "citation",
    "citations",
];

fn semantic_search_structural_tokens(query: &str) -> BTreeSet<String> {
    let mut structural_tokens = query_structural_directive_tokens(query);
    if query_prefers_document_briefing_layout(query)
        && !query_requests_comparison(query)
        && analyze_query_facets(query).grounded_external_required
    {
        structural_tokens.extend(
            DOCUMENT_BRIEFING_SEARCH_SCAFFOLD_TOKENS
                .iter()
                .map(|token| token.to_string()),
        );
    }
    structural_tokens
}

pub(crate) fn semantic_retrieval_query_contract_with_contract_and_locality_hint(
    query: &str,
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    locality_hint: Option<&str>,
) -> String {
    let resolved = resolved_query_contract_with_locality_hint(query, locality_hint);
    if resolved.trim().is_empty() {
        return resolved;
    }
    if retrieval_or_query_is_generic_headline_collection(retrieval_contract, &resolved) {
        return generic_headline_search_phrase(&resolved);
    }

    let facets = analyze_query_facets(&resolved);
    let scope = explicit_query_scope_hint(&resolved);
    if facets.goal.provenance_hits == 0
        && !facets.time_sensitive_public_fact
        && !facets.grounded_external_required
    {
        return resolved;
    }

    let structural_tokens = semantic_search_structural_tokens(&resolved);
    let scope_tokens = scope
        .as_ref()
        .map(|scope| normalized_locality_tokens(scope))
        .unwrap_or_default();
    let semantic_tokens =
        ordered_anchor_phrase_tokens(&resolved, &scope_tokens, &structural_tokens)
            .into_iter()
            .filter(|token| token.len() >= QUERY_COMPATIBILITY_MIN_TOKEN_CHARS)
            .filter(|token| !is_query_stopword(token))
            .collect::<Vec<_>>();
    let metric_terms = facets
        .metric_schema
        .axis_hits
        .iter()
        .copied()
        .map(metric_axis_search_phrase)
        .collect::<Vec<_>>();
    let metric_tokens = metric_terms
        .iter()
        .flat_map(|term| normalized_anchor_tokens(term))
        .collect::<BTreeSet<_>>();
    let semantic_subject_tokens = semantic_tokens
        .iter()
        .filter(|token| !metric_tokens.contains(*token))
        .cloned()
        .collect::<Vec<_>>();
    let locality_snapshot_subject_tokens = semantic_subject_tokens
        .iter()
        .filter(|token| {
            !matches!(
                token.as_str(),
                "current" | "currently" | "latest" | "now" | "right" | "today"
            )
        })
        .cloned()
        .collect::<Vec<_>>();
    let weather_snapshot_query = semantic_tokens
        .iter()
        .any(|token| matches!(token.as_str(), "weather" | "forecast"));

    if retrieval_or_query_prefers_single_fact_snapshot(retrieval_contract, &resolved)
        && (weather_snapshot_query
            || (facets.time_sensitive_public_fact && facets.locality_sensitive_public_fact))
    {
        let subject_tokens = if locality_snapshot_subject_tokens.is_empty() {
            semantic_subject_tokens.clone()
        } else {
            locality_snapshot_subject_tokens
        };
        if !subject_tokens.is_empty() {
            let mut base = format!("{} current conditions", subject_tokens.join(" "));
            if !metric_terms.is_empty() {
                base = format!("{base} {}", metric_terms.join(" "));
            }
            if let Some(scope) = scope.as_ref() {
                return format!("{base} in {scope}");
            }
            return base;
        }
    }

    if scope.is_none() && semantic_tokens.len() < 2 {
        if facets.time_sensitive_public_fact && facets.locality_sensitive_public_fact {
            if let Some(token) = semantic_tokens.first() {
                return format!("{token} current conditions temperature humidity wind");
            }
        }
        return resolved;
    }

    if retrieval_or_query_prefers_single_fact_snapshot(retrieval_contract, &resolved)
        && !metric_terms.is_empty()
        && !semantic_subject_tokens.is_empty()
    {
        let base = if facets.time_sensitive_public_fact {
            format!(
                "current {} {}",
                semantic_subject_tokens.join(" "),
                metric_terms.join(" ")
            )
        } else {
            format!(
                "{} {}",
                semantic_subject_tokens.join(" "),
                metric_terms.join(" ")
            )
        };
        if let Some(scope) = scope.as_ref() {
            return format!("{base} in {scope}");
        }
        return base;
    }
    let Some(scope) = scope else {
        return semantic_tokens.join(" ");
    };
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

pub(crate) fn select_web_pipeline_query_contract_with_locality_hint(
    goal: &str,
    retrieval_query: &str,
    locality_hint: Option<&str>,
) -> String {
    let goal_compact = compact_whitespace(strip_parent_playbook_context(goal));
    let retrieval_compact = compact_whitespace(retrieval_query);
    let goal_trimmed = goal_compact.trim();
    let retrieval_trimmed = retrieval_compact.trim();

    if goal_trimmed.is_empty() {
        return resolved_query_contract(retrieval_trimmed);
    }

    let retrieval_scope = explicit_query_scope_hint(retrieval_trimmed)
        .and_then(|scope| cleaned_retrieval_scope_for_goal(goal_trimmed, &scope));
    let goal_requires_runtime_locality = query_requires_runtime_locality_scope(goal_trimmed);
    let runtime_scope = goal_requires_runtime_locality
        .then(|| effective_locality_scope_hint(locality_hint))
        .flatten();
    let mut contract = runtime_scope
        .as_deref()
        .or(retrieval_scope
            .as_deref()
            .filter(|_| goal_requires_runtime_locality))
        .map(|scope| resolved_query_contract_with_locality_hint(goal_trimmed, Some(scope)))
        .unwrap_or_else(|| resolved_query_contract(goal_trimmed));
    if contract.trim().is_empty() {
        contract = goal_trimmed.to_string();
    }

    if retrieval_trimmed.is_empty() {
        return contract;
    }
    if explicit_query_scope_hint(&contract).is_some() {
        return contract;
    }
    if let Some(scope) = retrieval_scope.as_deref() {
        let resolved_with_scope =
            resolved_query_contract_with_locality_hint(&contract, Some(scope));
        if !resolved_with_scope.trim().is_empty() {
            return compact_whitespace(&resolved_with_scope);
        }
    }

    contract
}

pub(crate) fn select_web_pipeline_query_contract(goal: &str, retrieval_query: &str) -> String {
    select_web_pipeline_query_contract_with_locality_hint(goal, retrieval_query, None)
}
