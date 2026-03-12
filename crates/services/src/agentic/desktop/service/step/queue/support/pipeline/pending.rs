use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingGroundedCandidateSelection {
    NotApplicable,
    Applicable,
}

#[derive(Debug, Clone)]
struct RankedGroundedPendingCandidate {
    idx: usize,
    url: String,
    domain_key: String,
    grounded_viable: bool,
    identifier_priority_viable: bool,
    resolvable_payload: bool,
    blocked_domain_repeat: bool,
    document_authority_score: usize,
    identifier_signal: bool,
    required_identifier_label_count: usize,
    adds_missing_required_identifier_coverage: bool,
    official_status_host_hits: usize,
    primary_status_surface_hits: usize,
    compatibility: CandidateConstraintCompatibility,
    envelope_score: CandidateEvidenceScore,
    relevance_score: usize,
}

pub(crate) fn pending_candidate_inventory(pending: &PendingSearchCompletion) -> Vec<String> {
    let mut ordered = Vec::new();
    let mut seen = BTreeSet::new();

    for url in &pending.candidate_urls {
        let trimmed = url.trim();
        if trimmed.is_empty() {
            continue;
        }
        if seen.insert(trimmed.to_string()) {
            ordered.push(trimmed.to_string());
        }
    }

    for hint in &pending.candidate_source_hints {
        let trimmed = hint.url.trim();
        if trimmed.is_empty() {
            continue;
        }
        if seen.insert(trimmed.to_string()) {
            ordered.push(trimmed.to_string());
        }
    }

    ordered
}

fn observed_pending_domain_keys(pending: &PendingSearchCompletion) -> BTreeSet<String> {
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
        let domain_key = source_host(trimmed)
            .map(|host| host.strip_prefix("www.").unwrap_or(&host).to_string())
            .unwrap_or_else(|| trimmed.to_ascii_lowercase());
        observed_domains.insert(domain_key);
    }
    observed_domains
}

fn pending_url_already_observed(pending: &PendingSearchCompletion, url: &str) -> bool {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return true;
    }

    pending
        .attempted_urls
        .iter()
        .chain(pending.blocked_urls.iter())
        .chain(pending.successful_reads.iter().map(|source| &source.url))
        .map(|existing| existing.trim())
        .filter(|existing| !existing.is_empty())
        .any(|existing| {
            existing.eq_ignore_ascii_case(trimmed) || url_structurally_equivalent(existing, trimmed)
        })
}

fn observed_source_surface_for_url<'a>(
    pending: &'a PendingSearchCompletion,
    url: &str,
) -> Option<(&'a str, &'a str)> {
    source_hint_for_url(&pending.successful_reads, url)
        .or_else(|| hint_for_url(pending, url))
        .map(|source| {
            (
                source.title.as_deref().unwrap_or_default(),
                source.excerpt.as_str(),
            )
        })
}

fn observed_single_snapshot_nonqualifying_count(
    pending: &PendingSearchCompletion,
    projection: &QueryConstraintProjection,
) -> usize {
    pending
        .attempted_urls
        .iter()
        .chain(pending.blocked_urls.iter())
        .chain(pending.successful_reads.iter().map(|source| &source.url))
        .map(|url| url.trim())
        .filter(|url| !url.is_empty() && !is_search_hub_url(url))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|url| {
            let Some((title, excerpt)) = observed_source_surface_for_url(pending, url) else {
                return true;
            };
            let compatibility = candidate_constraint_compatibility(
                &projection.constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                url,
                title,
                excerpt,
            );
            !compatibility_passes_projection(projection, &compatibility)
        })
        .count()
}

fn next_pending_grounded_candidate(
    pending: &PendingSearchCompletion,
    attempted: &BTreeSet<String>,
    query_contract: &str,
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
) -> (PendingGroundedCandidateSelection, Option<String>) {
    let projection = build_query_constraint_projection(
        query_contract,
        pending.min_sources,
        &pending.candidate_source_hints,
    );
    let time_sensitive = projection
        .constraints
        .scopes
        .contains(&ConstraintScope::TimeSensitive)
        || retrieval_contract
            .map(|contract| contract.currentness_required)
            .unwrap_or(false);
    if !projection.query_facets.grounded_external_required && !time_sensitive {
        return (PendingGroundedCandidateSelection::NotApplicable, None);
    }

    let reject_search_hub = projection.reject_search_hub_candidates();
    let enforce_grounded_compatibility = projection.enforce_grounded_compatibility();
    let has_constraint_objective = projection.has_constraint_objective();
    let envelope_constraints = &projection.constraints;
    let envelope_policy = ResolutionPolicy::default();
    let min_sources_required = pending.min_sources.max(1) as usize;
    let required_distinct_domains =
        retrieval_contract_required_distinct_domain_floor(retrieval_contract, query_contract);
    let required_identifier_labels = briefing_standard_identifier_groups_for_query(query_contract)
        .iter()
        .filter(|group| group.required)
        .map(|group| group.primary_label.to_string())
        .collect::<BTreeSet<_>>();
    let observed_required_identifier_labels = pending
        .successful_reads
        .iter()
        .flat_map(|source| {
            source_briefing_standard_identifier_labels(
                query_contract,
                &source.url,
                source.title.as_deref().unwrap_or_default(),
                &source.excerpt,
            )
            .into_iter()
        })
        .filter(|label| required_identifier_labels.contains(label))
        .collect::<BTreeSet<_>>();
    let missing_required_identifier_labels = required_identifier_labels
        .difference(&observed_required_identifier_labels)
        .cloned()
        .collect::<BTreeSet<_>>();
    let identifier_priority_required =
        retrieval_contract_requires_document_briefing_identifier_evidence(
            retrieval_contract,
            query_contract,
        ) && !missing_required_identifier_labels.is_empty();
    let blocked_domains = pending
        .blocked_urls
        .iter()
        .filter_map(|url| {
            let trimmed = url.trim();
            if trimmed.is_empty() || is_search_hub_url(trimmed) {
                return None;
            }
            source_host(trimmed)
                .map(|host| host.strip_prefix("www.").unwrap_or(&host).to_string())
                .or_else(|| Some(trimmed.to_ascii_lowercase()))
        })
        .collect::<BTreeSet<_>>();

    let mut ranked_candidates = pending_candidate_inventory(pending)
        .iter()
        .enumerate()
        .filter_map(|(idx, candidate)| {
            let trimmed = candidate.trim();
            if trimmed.is_empty()
                || attempted.contains(trimmed)
                || pending_url_already_observed(pending, trimmed)
                || !is_citable_web_url(trimmed)
            {
                return None;
            }
            if reject_search_hub && is_search_hub_url(trimmed) {
                return None;
            }

            let hint = hint_for_url(pending, trimmed);
            let title = hint
                .and_then(|entry| entry.title.as_deref())
                .unwrap_or_default();
            let excerpt = hint.map(|entry| entry.excerpt.as_str()).unwrap_or_default();
            let compatibility = candidate_constraint_compatibility(
                &projection.constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                trimmed,
                title,
                excerpt,
            );
            let compatibility_passes = compatibility_passes_projection(&projection, &compatibility);
            let envelope_score = single_snapshot_candidate_envelope_score(
                envelope_constraints,
                envelope_policy,
                trimmed,
                title,
                excerpt,
            );
            let has_signal = !title.trim().is_empty() || !excerpt.trim().is_empty();
            let resolves_constraint = if has_constraint_objective {
                envelope_score_resolves_constraint(envelope_constraints, &envelope_score)
            } else {
                has_signal
            };
            let grounded_viable =
                (!enforce_grounded_compatibility || compatibility_passes) && resolves_constraint;
            let signals = analyze_source_record_signals(trimmed, title, excerpt);
            let document_authority_score =
                source_document_authority_score(query_contract, trimmed, title, excerpt);
            let identifier_labels =
                source_briefing_standard_identifier_labels(query_contract, trimmed, title, excerpt);
            let required_identifier_label_count = identifier_labels
                .iter()
                .filter(|label| required_identifier_labels.contains(*label))
                .count();
            let adds_missing_required_identifier_coverage = identifier_labels
                .iter()
                .any(|label| missing_required_identifier_labels.contains(label));
            let identifier_signal = !identifier_labels.is_empty();
            let identifier_priority_viable = identifier_priority_required
                && (adds_missing_required_identifier_coverage
                    || (document_authority_score > 0 && identifier_signal));

            Some(RankedGroundedPendingCandidate {
                idx,
                url: trimmed.to_string(),
                domain_key: source_host(trimmed)
                    .map(|host| host.strip_prefix("www.").unwrap_or(&host).to_string())
                    .unwrap_or_else(|| trimmed.to_ascii_lowercase()),
                grounded_viable,
                identifier_priority_viable,
                resolvable_payload: candidate_time_sensitive_resolvable_payload(
                    trimmed, title, excerpt,
                ),
                blocked_domain_repeat: blocked_domains.contains(
                    &source_host(trimmed)
                        .map(|host| host.strip_prefix("www.").unwrap_or(&host).to_string())
                        .unwrap_or_else(|| trimmed.to_ascii_lowercase()),
                ),
                document_authority_score,
                identifier_signal,
                required_identifier_label_count,
                adds_missing_required_identifier_coverage,
                official_status_host_hits: signals.official_status_host_hits,
                primary_status_surface_hits: signals.primary_status_surface_hits,
                compatibility,
                envelope_score,
                relevance_score: signals.relevance_score(false),
            })
        })
        .collect::<Vec<_>>();

    if ranked_candidates.is_empty() {
        return (PendingGroundedCandidateSelection::Applicable, None);
    }

    ranked_candidates.sort_by(|left, right| {
        right
            .identifier_priority_viable
            .cmp(&left.identifier_priority_viable)
            .then_with(|| left.blocked_domain_repeat.cmp(&right.blocked_domain_repeat))
            .then_with(|| {
                right
                    .adds_missing_required_identifier_coverage
                    .cmp(&left.adds_missing_required_identifier_coverage)
            })
            .then_with(|| {
                right
                    .required_identifier_label_count
                    .cmp(&left.required_identifier_label_count)
            })
            .then_with(|| {
                (right.document_authority_score > 0).cmp(&(left.document_authority_score > 0))
            })
            .then_with(|| {
                right
                    .document_authority_score
                    .cmp(&left.document_authority_score)
            })
            .then_with(|| right.identifier_signal.cmp(&left.identifier_signal))
            .then_with(|| right.grounded_viable.cmp(&left.grounded_viable))
            .then_with(|| right.resolvable_payload.cmp(&left.resolvable_payload))
            .then_with(|| {
                (right.official_status_host_hits > 0).cmp(&(left.official_status_host_hits > 0))
            })
            .then_with(|| {
                right
                    .official_status_host_hits
                    .cmp(&left.official_status_host_hits)
            })
            .then_with(|| {
                (right.primary_status_surface_hits > 0).cmp(&(left.primary_status_surface_hits > 0))
            })
            .then_with(|| {
                right
                    .primary_status_surface_hits
                    .cmp(&left.primary_status_surface_hits)
            })
            .then_with(|| {
                right
                    .compatibility
                    .compatibility_score
                    .cmp(&left.compatibility.compatibility_score)
            })
            .then_with(|| {
                compare_candidate_evidence_scores_desc(&left.envelope_score, &right.envelope_score)
            })
            .then_with(|| right.relevance_score.cmp(&left.relevance_score))
            .then_with(|| left.idx.cmp(&right.idx))
            .then_with(|| left.url.cmp(&right.url))
    });

    let has_identifier_priority_viable = ranked_candidates
        .iter()
        .any(|entry| entry.identifier_priority_viable);
    let candidate_is_viable = |candidate: &RankedGroundedPendingCandidate| {
        if identifier_priority_required && has_identifier_priority_viable {
            candidate.identifier_priority_viable
        } else {
            candidate.grounded_viable
        }
    };

    let observed_domains = observed_pending_domain_keys(pending);
    let best_viable_unseen_domain = ranked_candidates.iter().find(|candidate| {
        candidate_is_viable(candidate)
            && observed_domains.len() < required_distinct_domains
            && !observed_domains.contains(&candidate.domain_key)
    });
    if let Some(candidate) = best_viable_unseen_domain {
        return (
            PendingGroundedCandidateSelection::Applicable,
            Some(candidate.url.clone()),
        );
    }

    if let Some(candidate) = ranked_candidates
        .iter()
        .find(|candidate| candidate_is_viable(candidate))
    {
        return (
            PendingGroundedCandidateSelection::Applicable,
            Some(candidate.url.clone()),
        );
    }

    let exploratory_allowed = pending.successful_reads.len() < min_sources_required;
    if exploratory_allowed {
        return (
            PendingGroundedCandidateSelection::Applicable,
            ranked_candidates
                .first()
                .map(|candidate| candidate.url.clone()),
        );
    }

    (PendingGroundedCandidateSelection::Applicable, None)
}

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
    let retrieval_contract = pending.retrieval_contract.as_ref();
    let prefer_host_diversity =
        retrieval_contract_prefers_single_fact_snapshot(retrieval_contract, &query_contract);
    if prefer_host_diversity {
        let projection =
            build_query_constraint_projection(&query_contract, 1, &pending.candidate_source_hints);
        let envelope_constraints = &projection.constraints;
        let grounded_anchor_constrained = projection.strict_grounded_compatibility();
        let envelope_policy = ResolutionPolicy::default();
        let candidate_inventory = pending_candidate_inventory(pending);
        let mut ranked_candidates = candidate_inventory
            .iter()
            .enumerate()
            .filter_map(|(idx, candidate)| {
                let trimmed = candidate.trim();
                if trimmed.is_empty()
                    || attempted.contains(trimmed)
                    || pending_url_already_observed(pending, trimmed)
                {
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
                    candidate_time_sensitive_resolvable_payload(trimmed, title, excerpt);
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
        let exploratory_attempts_without_compatibility =
            observed_single_snapshot_nonqualifying_count(pending, &projection);
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

    match next_pending_grounded_candidate(pending, &attempted, &query_contract, retrieval_contract)
    {
        (_, Some(candidate)) => return Some(candidate),
        (PendingGroundedCandidateSelection::Applicable, None) => return None,
        (PendingGroundedCandidateSelection::NotApplicable, None) => {}
    }

    let required_distinct_domains =
        retrieval_contract_required_distinct_domain_floor(retrieval_contract, &query_contract);
    let candidate_inventory = pending_candidate_inventory(pending);
    if required_distinct_domains > 1 {
        let observed_domains = observed_pending_domain_keys(pending);

        for candidate in &candidate_inventory {
            let trimmed = candidate.trim();
            if trimmed.is_empty()
                || attempted.contains(trimmed)
                || pending_url_already_observed(pending, trimmed)
                || is_search_hub_url(trimmed)
            {
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

    for candidate in &candidate_inventory {
        let trimmed = candidate.trim();
        if trimmed.is_empty() {
            continue;
        }
        if attempted.contains(trimmed) || pending_url_already_observed(pending, trimmed) {
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
    prefer_excerpt_for_query("", existing, incoming)
}

pub(crate) fn prefer_excerpt_for_query(
    query_contract: &str,
    existing: String,
    incoming: String,
) -> String {
    let left = existing.trim().to_string();
    let right = incoming.trim().to_string();
    if left.is_empty() {
        return right;
    }
    if right.is_empty() {
        return left;
    }

    let left_groups = observed_briefing_standard_identifier_groups(query_contract, &left);
    let right_groups = observed_briefing_standard_identifier_groups(query_contract, &right);
    let left_required = left_groups.iter().filter(|group| group.required).count();
    let right_required = right_groups.iter().filter(|group| group.required).count();
    if right_required != left_required {
        return if right_required > left_required {
            right
        } else {
            left
        };
    }
    if right_groups.len() != left_groups.len() {
        return if right_groups.len() > left_groups.len() {
            right
        } else {
            left
        };
    }

    let left_signals = analyze_source_record_signals("", "", &left);
    let right_signals = analyze_source_record_signals("", "", &right);
    let left_low_priority =
        left_signals.low_priority_hits > 0 || left_signals.low_priority_dominates();
    let right_low_priority =
        right_signals.low_priority_hits > 0 || right_signals.low_priority_dominates();
    if right_low_priority != left_low_priority {
        return if right_low_priority { left } else { right };
    }

    let left_actionability = excerpt_actionability_score(&left);
    let right_actionability = excerpt_actionability_score(&right);
    if right_actionability != left_actionability {
        return if right_actionability > left_actionability {
            right
        } else {
            left
        };
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
    merge_pending_source_record_for_query("", existing, incoming)
}

pub(crate) fn merge_pending_source_record_for_query(
    query_contract: &str,
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
        excerpt: prefer_excerpt_for_query(query_contract, existing.excerpt, incoming.excerpt),
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
        let merge_query_contract = if existing_contract.is_empty() {
            incoming_contract
        } else {
            existing_contract
        };
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
                let merged = merge_pending_source_record_for_query(
                    merge_query_contract,
                    current.clone(),
                    normalized,
                );
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
        let merge_query_contract = if existing_contract.is_empty() {
            incoming_contract
        } else {
            existing_contract
        };
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
                let merged = merge_pending_source_record_for_query(
                    merge_query_contract,
                    current.clone(),
                    normalized,
                );
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
        retrieval_contract: existing.retrieval_contract.or(incoming.retrieval_contract),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefer_excerpt_for_query_prefers_identifier_bearing_excerpt_over_longer_generic_excerpt() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let generic = "NIST maintains post-quantum cryptography resources and migration guidance for agencies planning the transition.";
        let identifiers = "The Federal Information Processing Standards FIPS 203, FIPS 204, and FIPS 205 standardize ML-KEM, ML-DSA, and SLH-DSA.";

        let preferred =
            prefer_excerpt_for_query(query, generic.to_string(), identifiers.to_string());

        assert_eq!(preferred, identifiers);
    }

    #[test]
    fn prefer_excerpt_for_query_prefers_clean_hint_over_script_heavy_menu_excerpt() {
        let query =
            "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
        let noisy = "3907 Clemson Blvd STE A, Anderson, SC 29621 return ([1e7] + -1e3 + -4e3 + -8e3 + -1e11).replace(/[018]/g, c => (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)); document.querySelector('.commentPopup').style.display = 'none'";
        let clean = "View the menu, hours, phone number, address and map for Red Tomato and Wine Restaurant in Anderson, SC.";

        let preferred = prefer_excerpt_for_query(query, noisy.to_string(), clean.to_string());

        assert_eq!(preferred, clean);
    }

    #[test]
    fn next_pending_web_candidate_prefers_discovered_official_authority_when_identifier_coverage_is_missing(
    ) {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).ok();
        let pending = PendingSearchCompletion {
            query: query.to_string(),
            query_contract: query.to_string(),
            retrieval_contract,
            url: String::new(),
            started_step: 0,
            started_at_ms: 0,
            deadline_ms: 0,
            candidate_urls: vec![
                "https://www.securityweek.com/nist-announces-hqc-as-fifth-standardized-post-quantum-algorithm/".to_string(),
                "https://www.ibm.com/think/topics/nist".to_string(),
                "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                "https://www.nist.gov/pqc".to_string(),
                "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
            ],
            candidate_source_hints: vec![
                PendingSearchReadSummary {
                    url: "https://www.securityweek.com/nist-announces-hqc-as-fifth-standardized-post-quantum-algorithm/".to_string(),
                    title: Some(
                        "NIST Announces HQC as Fifth Standardized Post-Quantum Algorithm"
                            .to_string(),
                    ),
                    excerpt:
                        "NIST selected HQC as a fifth post-quantum algorithm after prior standards."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.ibm.com/think/topics/nist".to_string(),
                    title: Some("NIST overview topic".to_string()),
                    excerpt: "IBM overview of NIST topics.".to_string(),
                },
            ],
            attempted_urls: vec![
                "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
            ],
            blocked_urls: Vec::new(),
            successful_reads: vec![PendingSearchReadSummary {
                url: "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
                title: Some(
                    "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption"
                        .to_string(),
                ),
                excerpt:
                    "March 11, 2025 - NIST selected HQC after finalizing FIPS 203, FIPS 204, and FIPS 205."
                        .to_string(),
            }],
            min_sources: 2,
        };

        assert_eq!(
            next_pending_web_candidate(&pending).as_deref(),
            Some(
                "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
            )
        );
    }
}
