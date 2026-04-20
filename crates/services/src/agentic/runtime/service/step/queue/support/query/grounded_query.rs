use super::*;

fn briefing_identifier_search_terms(query_contract: &str, include_optional: bool) -> Vec<String> {
    briefing_standard_identifier_groups_for_query(query_contract)
        .iter()
        .filter(|group| group.required || include_optional)
        .filter_map(|group| group.needles.first())
        .map(|needle| format!("\"{}\"", needle.to_ascii_uppercase()))
        .collect()
}

fn should_expand_optional_briefing_identifier_terms(
    query_contract: &str,
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
) -> bool {
    let facets = analyze_query_facets(query_contract);
    query_prefers_document_briefing_layout(query_contract)
        && !query_requests_comparison(query_contract)
        && facets.grounded_external_required
        && (retrieval_contract
            .map(|contract| contract.currentness_required)
            .unwrap_or(false)
            || facets.goal.recency_hits > 0)
}

fn inferred_briefing_identifier_probe_terms(
    query_contract: &str,
    candidate_hints: &[PendingSearchReadSummary],
) -> Vec<String> {
    if candidate_hints.is_empty() {
        return Vec::new();
    }

    let observations = candidate_hints
        .iter()
        .filter_map(|hint| {
            let trimmed = hint.url.trim();
            let title = hint.title.as_deref().unwrap_or_default();
            (!trimmed.is_empty()).then(|| BriefingIdentifierObservation {
                url: trimmed.to_string(),
                surface: preferred_source_briefing_identifier_surface(
                    query_contract,
                    &hint.url,
                    title,
                    &hint.excerpt,
                ),
                authoritative: source_has_document_authority(
                    query_contract,
                    trimmed,
                    title,
                    &hint.excerpt,
                ),
            })
        })
        .collect::<Vec<_>>();
    let mut labels = infer_briefing_required_identifier_labels(query_contract, &observations)
        .into_iter()
        .collect::<Vec<_>>();
    labels.sort();
    labels
        .into_iter()
        .take(3)
        .map(|label| format!("\"{}\"", label.to_ascii_uppercase()))
        .collect()
}

pub(crate) fn constraint_grounded_search_query_with_hints_and_locality_hint(
    query: &str,
    min_sources: u32,
    candidate_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
) -> String {
    constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
        query,
        None,
        min_sources,
        candidate_hints,
        locality_hint,
    )
}

pub(crate) fn constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
    query: &str,
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    min_sources: u32,
    candidate_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
) -> String {
    let resolved = resolved_query_contract_with_locality_hint(query, locality_hint);
    if resolved.trim().is_empty() {
        return String::new();
    }
    let local_business_discovery_query =
        local_business_discovery_query_contract(query, locality_hint);
    let local_business_entity_discovery_query =
        local_business_entity_discovery_query_contract(query, locality_hint);
    let local_business_entity_expansion = retrieval_contract
        .map(crate::agentic::web::contract_requires_geo_scoped_entity_expansion)
        .unwrap_or_else(|| query_requires_local_business_entity_diversity(&resolved));
    let grounded_query_basis = if local_business_entity_expansion {
        local_business_entity_discovery_query
            .trim()
            .is_empty()
            .then_some(local_business_discovery_query.as_str())
            .unwrap_or(local_business_entity_discovery_query.as_str())
    } else {
        resolved.as_str()
    };
    if retrieval_or_query_is_generic_headline_collection(retrieval_contract, &resolved) {
        return generic_headline_search_phrase(&resolved);
    }

    let base = semantic_retrieval_query_contract_with_contract_and_locality_hint(
        grounded_query_basis,
        retrieval_contract,
        locality_hint,
    );
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
    if projection.query_facets.grounded_external_required
        && projection.query_facets.service_status_lookup
    {
        for term in [
            "official status page",
            "service health dashboard",
            "incident update",
        ] {
            if !constraint_terms.iter().any(|existing| existing == term) {
                constraint_terms.push(term.to_string());
            }
        }
    }
    let bootstrap_without_hints = candidate_hints.is_empty();
    let authority_site_terms = if bootstrap_without_hints {
        query_document_authority_site_terms(&resolved, retrieval_contract, candidate_hints, false)
    } else {
        Vec::new()
    };
    constraint_terms.extend(briefing_identifier_search_terms(
        &resolved,
        should_expand_optional_briefing_identifier_terms(&resolved, retrieval_contract),
    ));
    if bootstrap_without_hints {
        constraint_terms.extend(authority_site_terms.clone());
    }
    if bootstrap_without_hints
        && retrieval_contract
            .map(crate::agentic::web::contract_requires_geo_scoped_entity_expansion)
            .unwrap_or(false)
    {
        return base;
    }
    if bootstrap_without_hints
        && retrieval_contract_prefers_single_fact_snapshot(retrieval_contract, &resolved)
    {
        return base;
    }
    let bootstrap_time_sensitive_locality_scope = bootstrap_without_hints
        && projection
            .constraints
            .scopes
            .contains(&ConstraintScope::TimeSensitive)
        && projection.locality_scope.is_some();
    if bootstrap_time_sensitive_locality_scope {
        return base;
    }
    let suppress_native_anchor_phrase = bootstrap_without_hints
        && projection.query_facets.grounded_external_required
        && !projection.query_facets.locality_sensitive_public_fact
        && (query_prefers_multi_item_cardinality(&resolved) || !authority_site_terms.is_empty());
    let native_anchor_phrase = if suppress_native_anchor_phrase {
        None
    } else {
        projection_native_anchor_phrase(&projection)
    };
    if projection.enforce_grounded_compatibility() {
        if let Some(anchor_phrase) = native_anchor_phrase.as_ref() {
            constraint_terms.push(anchor_phrase.clone());
        }
    }
    if projection.query_facets.grounded_external_required
        && !projection
            .constraints
            .scopes
            .contains(&ConstraintScope::TimeSensitive)
    {
        if let Some(scope) = projection.locality_scope.as_ref() {
            let scoped_phrase = format!("\"{}\"", scope);
            if !constraint_terms.iter().any(|term| term == &scoped_phrase) {
                constraint_terms.push(scoped_phrase);
            }
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
    constraint_grounded_probe_query_with_contract_and_hints_and_locality_hint(
        query,
        None,
        min_sources,
        candidate_hints,
        prior_query,
        locality_hint,
    )
}

pub(crate) fn constraint_grounded_probe_query_with_contract_and_hints_and_locality_hint(
    query: &str,
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    min_sources: u32,
    candidate_hints: &[PendingSearchReadSummary],
    prior_query: &str,
    locality_hint: Option<&str>,
) -> Option<String> {
    let grounded_query = constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
        query,
        retrieval_contract,
        min_sources,
        candidate_hints,
        locality_hint,
    );
    if grounded_query.trim().is_empty() {
        return None;
    }

    let prior_trimmed = prior_query.trim();
    let headline_collection_query =
        retrieval_or_query_is_generic_headline_collection(retrieval_contract, query);
    if headline_collection_query {
        return (prior_trimmed.is_empty() || !grounded_query.eq_ignore_ascii_case(prior_trimmed))
            .then_some(grounded_query);
    }
    let projection = build_query_constraint_projection_with_locality_hint(
        query,
        min_sources,
        candidate_hints,
        locality_hint,
    );
    let mut escalation_terms = projection_probe_structural_terms(&projection);
    escalation_terms.extend(projection_probe_locality_disambiguation_terms(
        &projection,
        candidate_hints,
    ));
    escalation_terms.extend(query_probe_document_authority_site_terms(
        query,
        retrieval_contract,
        candidate_hints,
    ));
    escalation_terms.extend(query_probe_grounded_authority_host_exclusion_terms(
        query,
        retrieval_contract,
        candidate_hints,
    ));
    escalation_terms.extend(inferred_briefing_identifier_probe_terms(
        query,
        candidate_hints,
    ));
    escalation_terms.extend(projection_probe_host_exclusion_terms(
        query,
        &projection,
        candidate_hints,
    ));
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
    if prior_trimmed.is_empty() || !grounded_query.eq_ignore_ascii_case(prior_trimmed) {
        let escalated_grounded_query =
            append_unique_query_terms(&grounded_query, &escalation_terms);
        if !escalated_grounded_query.trim().is_empty()
            && !escalated_grounded_query.eq_ignore_ascii_case(prior_trimmed)
            && !escalated_grounded_query.eq_ignore_ascii_case(&grounded_query)
        {
            return Some(if requires_locality_metric_escalation {
                append_unique_query_terms(&escalated_grounded_query, &metric_probe_terms)
            } else {
                escalated_grounded_query
            });
        }
        return Some(grounded_query);
    }
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

#[cfg(test)]
#[path = "grounded_query/tests.rs"]
mod tests;
