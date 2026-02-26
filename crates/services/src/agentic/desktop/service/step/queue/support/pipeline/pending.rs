use super::*;

pub(crate) fn next_pending_web_candidate(pending: &PendingSearchCompletion) -> Option<String> {
    let mut attempted = BTreeSet::new();
    for url in &pending.attempted_urls {
        let trimmed = url.trim();
        if !trimmed.is_empty() {
            attempted.insert(trimmed.to_string());
        }
    }
    for url in &pending.blocked_urls {
        let trimmed = url.trim();
        if !trimmed.is_empty() {
            attempted.insert(trimmed.to_string());
        }
    }

    let query_contract = synthesis_query_contract(pending);
    let prefer_host_diversity = prefers_single_fact_snapshot(&query_contract);
    if prefer_host_diversity {
        let projection =
            build_query_constraint_projection(&query_contract, 1, &pending.candidate_source_hints);
        let envelope_constraints = &projection.constraints;
        let grounded_anchor_constrained = projection.strict_grounded_compatibility();
        let envelope_policy = ResolutionPolicy::default();
        let mut ranked_candidates = pending
            .candidate_urls
            .iter()
            .enumerate()
            .filter_map(|(idx, candidate)| {
                let trimmed = candidate.trim();
                if trimmed.is_empty() || attempted.contains(trimmed) {
                    return None;
                }
                let hint = hint_for_url(pending, trimmed);
                let title = hint
                    .and_then(|entry| entry.title.as_deref())
                    .unwrap_or_default();
                let excerpt = hint.map(|entry| entry.excerpt.as_str()).unwrap_or_default();
                let envelope_score = single_snapshot_candidate_envelope_score(
                    envelope_constraints,
                    envelope_policy,
                    trimmed,
                    title,
                    excerpt,
                );
                let compatibility = candidate_constraint_compatibility(
                    envelope_constraints,
                    &projection.query_facets,
                    &projection.query_native_tokens,
                    &projection.query_tokens,
                    &projection.locality_tokens,
                    projection.locality_scope.is_some(),
                    trimmed,
                    title,
                    excerpt,
                );
                let resolvable_payload =
                    candidate_time_sensitive_resolvable_payload(title, excerpt);
                let source_relevance_score =
                    analyze_source_record_signals(trimmed, title, excerpt).relevance_score(false);
                Some((
                    idx,
                    trimmed.to_string(),
                    envelope_score,
                    compatibility,
                    resolvable_payload,
                    source_relevance_score,
                ))
            })
            .collect::<Vec<_>>();
        ranked_candidates.sort_by(|left, right| {
            right
                .4
                .cmp(&left.4)
                .then_with(|| {
                    let right_passes = compatibility_passes_projection(&projection, &right.3);
                    let left_passes = compatibility_passes_projection(&projection, &left.3);
                    right_passes.cmp(&left_passes)
                })
                .then_with(|| right.3.compatibility_score.cmp(&left.3.compatibility_score))
                .then_with(|| compare_candidate_evidence_scores_desc(&left.2, &right.2))
                .then_with(|| right.5.cmp(&left.5))
                .then_with(|| left.0.cmp(&right.0))
                .then_with(|| left.1.cmp(&right.1))
        });
        let has_compatible_candidates =
            ranked_candidates
                .iter()
                .any(|(_, _, _, compatibility, _, _)| {
                    compatibility_passes_projection(&projection, compatibility)
                });
        let requires_semantic_locality_alignment = projection
            .constraints
            .scopes
            .contains(&ConstraintScope::TimeSensitive)
            && projection.locality_scope.is_some()
            && projection
                .query_native_tokens
                .iter()
                .any(|token| !projection.locality_tokens.contains(token));
        let exploratory_attempts_without_compatibility = pending
            .attempted_urls
            .iter()
            .chain(pending.blocked_urls.iter())
            .chain(pending.successful_reads.iter().map(|source| &source.url))
            .map(|url| url.trim().to_string())
            .filter(|url| !url.is_empty() && !is_search_hub_url(url))
            .collect::<BTreeSet<_>>()
            .len();
        let exploratory_read_cap = SINGLE_SNAPSHOT_MAX_EXPLORATORY_READS_WITHOUT_COMPATIBILITY
            .saturating_add(
                single_snapshot_additional_probe_attempt_count(pending)
                    .min(SINGLE_SNAPSHOT_MAX_ADDITIONAL_PROBE_SOURCES),
            );
        let can_issue_exploratory_read =
            exploratory_attempts_without_compatibility < exploratory_read_cap;
        if requires_semantic_locality_alignment
            && !has_compatible_candidates
            && !can_issue_exploratory_read
        {
            return None;
        }

        let mut attempted_hosts = BTreeSet::new();
        for url in pending
            .attempted_urls
            .iter()
            .chain(pending.blocked_urls.iter())
            .chain(pending.successful_reads.iter().map(|source| &source.url))
        {
            let trimmed = url.trim();
            if trimmed.is_empty() || is_search_hub_url(trimmed) {
                continue;
            }
            if let Some(host) = source_host(trimmed) {
                attempted_hosts.insert(host);
            }
        }

        for (_, candidate, _, compatibility, _, _) in &ranked_candidates {
            if has_compatible_candidates
                && !compatibility_passes_projection(&projection, compatibility)
            {
                continue;
            }
            if let Some(host) = source_host(candidate) {
                if attempted_hosts.contains(&host) {
                    continue;
                }
            }
            return Some(candidate.clone());
        }

        if has_compatible_candidates {
            if let Some((_, candidate, _, _, _, _)) =
                ranked_candidates
                    .iter()
                    .find(|(_, _, _, compatibility, _, _)| {
                        compatibility_passes_projection(&projection, compatibility)
                    })
            {
                return Some(candidate.clone());
            }
        }

        if grounded_anchor_constrained {
            if !has_compatible_candidates && can_issue_exploratory_read {
                if let Some((_, candidate, _, _, _, _)) = ranked_candidates.first() {
                    return Some(candidate.clone());
                }
            }
            return None;
        }

        if let Some((_, candidate, _, _, _, _)) = ranked_candidates.first() {
            return Some(candidate.clone());
        }
    }

    if query_prefers_multi_item_cardinality(&query_contract) {
        let required_distinct_domains = required_story_count(&query_contract).max(1);
        let mut observed_domains = BTreeSet::new();
        for url in pending
            .attempted_urls
            .iter()
            .chain(pending.blocked_urls.iter())
            .chain(pending.successful_reads.iter().map(|source| &source.url))
        {
            let trimmed = url.trim();
            if trimmed.is_empty() || is_search_hub_url(trimmed) {
                continue;
            }
            if let Some(host) = source_host(trimmed) {
                let canonical_host = host.strip_prefix("www.").unwrap_or(&host).to_string();
                observed_domains.insert(canonical_host);
            }
        }

        for candidate in &pending.candidate_urls {
            let trimmed = candidate.trim();
            if trimmed.is_empty() || attempted.contains(trimmed) || is_search_hub_url(trimmed) {
                continue;
            }
            let domain_key = source_host(trimmed)
                .map(|host| host.strip_prefix("www.").unwrap_or(&host).to_string())
                .unwrap_or_else(|| trimmed.to_ascii_lowercase());
            if observed_domains.len() < required_distinct_domains
                && observed_domains.contains(&domain_key)
            {
                continue;
            }
            return Some(trimmed.to_string());
        }

        if observed_domains.len() < required_distinct_domains {
            return None;
        }
    }

    for candidate in &pending.candidate_urls {
        let trimmed = candidate.trim();
        if trimmed.is_empty() {
            continue;
        }
        if attempted.contains(trimmed) {
            continue;
        }
        return Some(trimmed.to_string());
    }

    None
}

pub(crate) fn mark_pending_web_attempted(pending: &mut PendingSearchCompletion, url: &str) {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return;
    }
    if pending
        .attempted_urls
        .iter()
        .any(|existing| existing.trim() == trimmed)
    {
        return;
    }
    pending.attempted_urls.push(trimmed.to_string());
}

pub(crate) fn mark_pending_web_blocked(pending: &mut PendingSearchCompletion, url: &str) {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return;
    }
    if pending
        .blocked_urls
        .iter()
        .any(|existing| existing.trim() == trimmed)
    {
        return;
    }
    pending.blocked_urls.push(trimmed.to_string());
}

pub(crate) fn normalize_optional_title(value: Option<String>) -> Option<String> {
    value.and_then(|title| {
        let trimmed = title.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

pub(crate) fn prefer_title(existing: Option<String>, incoming: Option<String>) -> Option<String> {
    let existing = normalize_optional_title(existing);
    let incoming = normalize_optional_title(incoming);
    match (existing, incoming) {
        (None, None) => None,
        (Some(value), None) | (None, Some(value)) => Some(value),
        (Some(left), Some(right)) => {
            let left_low = is_low_signal_title(&left);
            let right_low = is_low_signal_title(&right);
            if left_low != right_low {
                return if right_low { Some(left) } else { Some(right) };
            }
            if right.chars().count() > left.chars().count() {
                Some(right)
            } else {
                Some(left)
            }
        }
    }
}

pub(crate) fn prefer_excerpt(existing: String, incoming: String) -> String {
    let left = existing.trim().to_string();
    let right = incoming.trim().to_string();
    if left.is_empty() {
        return right;
    }
    if right.is_empty() {
        return left;
    }

    let left_current = contains_current_condition_metric_signal(&left);
    let right_current = contains_current_condition_metric_signal(&right);
    if right_current != left_current {
        return if right_current { right } else { left };
    }

    let left_metric = contains_metric_signal(&left);
    let right_metric = contains_metric_signal(&right);
    if right_metric != left_metric {
        return if right_metric { right } else { left };
    }

    let left_low = is_low_signal_excerpt(&left);
    let right_low = is_low_signal_excerpt(&right);
    if right_low != left_low {
        return if right_low { left } else { right };
    }

    if right.chars().count() > left.chars().count() {
        right
    } else {
        left
    }
}

pub(crate) fn merge_pending_source_record(
    existing: PendingSearchReadSummary,
    incoming: PendingSearchReadSummary,
) -> PendingSearchReadSummary {
    let url = if existing.url.trim().is_empty() {
        incoming.url.trim().to_string()
    } else {
        existing.url.trim().to_string()
    };
    PendingSearchReadSummary {
        url,
        title: prefer_title(existing.title, incoming.title),
        excerpt: prefer_excerpt(existing.excerpt, incoming.excerpt),
    }
}

pub(crate) fn merge_url_sequence(existing: Vec<String>, incoming: Vec<String>) -> Vec<String> {
    let mut merged = Vec::new();
    let mut seen = BTreeSet::new();
    for url in existing.into_iter().chain(incoming.into_iter()) {
        let trimmed = url.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !seen.insert(trimmed.to_string()) {
            continue;
        }
        merged.push(trimmed.to_string());
    }
    merged
}

pub(crate) fn merge_pending_search_completion(
    existing: PendingSearchCompletion,
    incoming: PendingSearchCompletion,
) -> PendingSearchCompletion {
    let existing_contract = existing.query_contract.trim();
    let incoming_contract = incoming.query_contract.trim();
    if !existing_contract.is_empty()
        && !incoming_contract.is_empty()
        && !existing_contract.eq_ignore_ascii_case(incoming_contract)
    {
        return incoming;
    }

    let existing_query = existing.query.trim();
    let incoming_query = incoming.query.trim();
    if existing_contract.is_empty()
        && incoming_contract.is_empty()
        && !existing_query.is_empty()
        && !incoming_query.is_empty()
        && !existing_query.eq_ignore_ascii_case(incoming_query)
    {
        return incoming;
    }

    let successful_reads = {
        let mut merged_by_url: BTreeMap<String, PendingSearchReadSummary> = BTreeMap::new();
        for source in existing
            .successful_reads
            .into_iter()
            .chain(incoming.successful_reads.into_iter())
        {
            let trimmed = source.url.trim();
            if trimmed.is_empty() {
                continue;
            }
            let normalized = PendingSearchReadSummary {
                url: trimmed.to_string(),
                title: normalize_optional_title(source.title),
                excerpt: source.excerpt.trim().to_string(),
            };
            if let Some(current) = merged_by_url.get(trimmed) {
                let merged = merge_pending_source_record(current.clone(), normalized);
                merged_by_url.insert(trimmed.to_string(), merged);
            } else {
                merged_by_url.insert(trimmed.to_string(), normalized);
            }
        }
        merged_by_url.into_values().collect::<Vec<_>>()
    };

    let attempted_urls = merge_url_sequence(existing.attempted_urls, incoming.attempted_urls);
    let blocked_urls = merge_url_sequence(existing.blocked_urls, incoming.blocked_urls);

    let mut attempted_or_resolved = BTreeSet::new();
    for url in attempted_urls.iter().chain(blocked_urls.iter()) {
        attempted_or_resolved.insert(url.trim().to_string());
    }
    for source in &successful_reads {
        let trimmed = source.url.trim();
        if !trimmed.is_empty() {
            attempted_or_resolved.insert(trimmed.to_string());
        }
    }

    let candidate_urls = merge_url_sequence(existing.candidate_urls, incoming.candidate_urls)
        .into_iter()
        .filter(|url| !attempted_or_resolved.contains(url))
        .collect::<Vec<_>>();

    let candidate_source_hints = {
        let mut merged_by_url: BTreeMap<String, PendingSearchReadSummary> = BTreeMap::new();
        for source in existing
            .candidate_source_hints
            .into_iter()
            .chain(incoming.candidate_source_hints.into_iter())
        {
            let trimmed = source.url.trim();
            if trimmed.is_empty() {
                continue;
            }
            let normalized = PendingSearchReadSummary {
                url: trimmed.to_string(),
                title: normalize_optional_title(source.title),
                excerpt: source.excerpt.trim().to_string(),
            };
            if let Some(current) = merged_by_url.get(trimmed) {
                let merged = merge_pending_source_record(current.clone(), normalized);
                merged_by_url.insert(trimmed.to_string(), merged);
            } else {
                merged_by_url.insert(trimmed.to_string(), normalized);
            }
        }

        let mut ordered = Vec::new();
        let mut seen = BTreeSet::new();
        for url in &candidate_urls {
            if let Some(source) = merged_by_url.get(url) {
                ordered.push(source.clone());
                seen.insert(url.clone());
            }
        }
        for (url, source) in merged_by_url {
            if seen.insert(url) {
                ordered.push(source);
            }
        }
        ordered
    };

    PendingSearchCompletion {
        query: if incoming_query.is_empty() {
            existing.query
        } else if existing_query.is_empty() || !existing_query.eq_ignore_ascii_case(incoming_query)
        {
            incoming.query
        } else {
            existing.query
        },
        query_contract: if existing_contract.is_empty() {
            incoming.query_contract
        } else {
            existing.query_contract
        },
        url: if existing.url.trim().is_empty() {
            incoming.url
        } else {
            existing.url
        },
        started_step: if existing.started_at_ms > 0 || existing.started_step > 0 {
            existing.started_step
        } else {
            incoming.started_step
        },
        started_at_ms: if existing.started_at_ms > 0 {
            existing.started_at_ms
        } else {
            incoming.started_at_ms
        },
        deadline_ms: if existing.deadline_ms > 0 {
            existing.deadline_ms
        } else {
            incoming.deadline_ms
        },
        candidate_urls,
        candidate_source_hints,
        attempted_urls,
        blocked_urls,
        successful_reads,
        min_sources: existing.min_sources.max(incoming.min_sources),
    }
}

