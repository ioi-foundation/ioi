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
    let source_signals = analyze_source_record_signals(url, title, excerpt);
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
    compatibility_score = compatibility_score.saturating_add(
        source_signals.primary_status_surface_hits * QUERY_COMPATIBILITY_PRIMARY_STATUS_BONUS,
    );
    compatibility_score = compatibility_score.saturating_add(
        source_signals.official_status_host_hits * QUERY_COMPATIBILITY_OFFICIAL_STATUS_HOST_BONUS,
    );
    if source_signals.low_priority_hits > 0 || source_signals.low_priority_dominates() {
        compatibility_score = compatibility_score
            .saturating_sub(QUERY_COMPATIBILITY_LOW_PRIORITY_PENALTY);
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
