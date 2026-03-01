use super::*;

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
    if headline_collection_query {
        if prior_trimmed.is_empty() || !grounded_query.eq_ignore_ascii_case(prior_trimmed) {
            return Some(grounded_query);
        }
        return None;
    }
    if prior_trimmed.is_empty() || !grounded_query.eq_ignore_ascii_case(prior_trimmed) {
        return Some(grounded_query);
    }
    let projection = build_query_constraint_projection_with_locality_hint(
        query,
        min_sources,
        candidate_hints,
        locality_hint,
    );
    let escalation_terms = projection_probe_structural_terms(&projection);
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
