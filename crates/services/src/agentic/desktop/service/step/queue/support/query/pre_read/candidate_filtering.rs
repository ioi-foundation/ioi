impl RetrievalAffordanceKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::DirectCitationRead => "direct_citation_read",
            Self::DiscoveryExpansionSeedRead => "discovery_expansion_seed_read",
        }
    }
}

pub(crate) fn projection_candidate_url_allowed(raw: &str) -> bool {
    let trimmed = raw.trim();
    !trimmed.is_empty()
        && is_citable_web_url(trimmed)
        && !is_search_hub_url(trimmed)
        && !is_multi_item_listing_url(trimmed)
        && looks_like_deep_article_url(trimmed)
}

fn single_snapshot_metric_detail_candidate_allowed_with_contract_and_projection(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    projection: &QueryConstraintProjection,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    if !retrieval_contract_prefers_single_fact_snapshot(retrieval_contract, query_contract) {
        return false;
    }

    let trimmed = raw.trim();
    if trimmed.is_empty()
        || !is_citable_web_url(trimmed)
        || is_search_hub_url(trimmed)
        || is_multi_item_listing_url(trimmed)
    {
        return false;
    }
    if title.trim().is_empty() && excerpt.trim().is_empty() {
        return false;
    }
    if source_has_human_challenge_signal(trimmed, title, excerpt) {
        return false;
    }

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
    let resolvable_payload = candidate_time_sensitive_resolvable_payload(raw, title, excerpt);
    let score = single_snapshot_candidate_envelope_score(
        &projection.constraints,
        ResolutionPolicy::default(),
        trimmed,
        title,
        excerpt,
    );

    compatibility_passes_projection(projection, &compatibility)
        && (resolvable_payload
            || envelope_score_resolves_constraint(&projection.constraints, &score))
}

fn single_snapshot_metric_detail_candidate_allowed_with_projection(
    query_contract: &str,
    projection: &QueryConstraintProjection,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    single_snapshot_metric_detail_candidate_allowed_with_contract_and_projection(
        None,
        query_contract,
        projection,
        raw,
        title,
        excerpt,
    )
}

fn local_business_detail_root_candidate_allowed_with_contract(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    projection: &QueryConstraintProjection,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    if !retrieval_contract_prefers_multi_item_cardinality(retrieval_contract, query_contract)
        || !retrieval_contract_requests_comparison(retrieval_contract, query_contract)
        || !projection.query_facets.locality_sensitive_public_fact
        || !projection.query_facets.grounded_external_required
        || projection.locality_scope.is_none()
    {
        return false;
    }

    let trimmed = raw.trim();
    if trimmed.is_empty() || !is_citable_web_url(trimmed) || is_search_hub_url(trimmed) {
        return false;
    }
    let Ok(parsed) = Url::parse(trimmed) else {
        return false;
    };
    if !parsed.path().trim_matches('/').is_empty() {
        return false;
    }
    if title.trim().is_empty() && excerpt.trim().is_empty() {
        return false;
    }
    if source_has_human_challenge_signal(trimmed, title, excerpt) {
        return false;
    }

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
    let discovery_compatible = compatibility_passes_projection(projection, &compatibility)
        || (projection.locality_scope.is_some()
            && projection.query_facets.locality_sensitive_public_fact
            && compatibility.is_compatible);
    if !discovery_compatible {
        return false;
    }

    let host_compact = parsed
        .host_str()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>();
    let source_tokens = normalized_anchor_tokens(&format!("{} {}", title, excerpt));
    let host_aligns_with_source = source_tokens.iter().any(|token| {
        token.len() >= 4
            && !projection.locality_tokens.contains(token)
            && host_compact.contains(token)
    });
    if !host_aligns_with_source {
        return false;
    }

    let signals = analyze_source_record_signals(trimmed, title, excerpt);
    !(signals.low_priority_hits > 0 || signals.low_priority_dominates())
}

fn local_business_detail_root_candidate_allowed(
    query_contract: &str,
    projection: &QueryConstraintProjection,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    local_business_detail_root_candidate_allowed_with_contract(
        None,
        query_contract,
        projection,
        raw,
        title,
        excerpt,
    )
}

fn local_business_discovery_seed_required_with_contract(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    projection: &QueryConstraintProjection,
) -> bool {
    retrieval_contract_entity_diversity_required(retrieval_contract, query_contract)
        && projection.query_facets.locality_sensitive_public_fact
        && projection.query_facets.grounded_external_required
        && projection.locality_scope.is_some()
        && projection.enforce_grounded_compatibility()
}

fn local_business_discovery_seed_required(
    query_contract: &str,
    projection: &QueryConstraintProjection,
) -> bool {
    local_business_discovery_seed_required_with_contract(None, query_contract, projection)
}

fn local_business_direct_citation_source_allowed_with_contract_and_projection(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    projection: &QueryConstraintProjection,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    if !retrieval_contract_entity_diversity_required(retrieval_contract, query_contract)
        || !retrieval_contract_prefers_multi_item_cardinality(retrieval_contract, query_contract)
        || !retrieval_contract_requests_comparison(retrieval_contract, query_contract)
        || !projection.query_facets.locality_sensitive_public_fact
        || !projection.query_facets.grounded_external_required
        || projection.locality_scope.is_none()
    {
        return true;
    }

    let source = PendingSearchReadSummary {
        url: raw.trim().to_string(),
        title: (!title.trim().is_empty()).then(|| title.trim().to_string()),
        excerpt: excerpt.trim().to_string(),
    };
    if local_business_target_name_from_source(&source, projection.locality_scope.as_deref())
        .is_some()
    {
        return true;
    }

    local_business_detail_root_candidate_allowed_with_contract(
        retrieval_contract,
        query_contract,
        projection,
        raw,
        title,
        excerpt,
    )
}

fn local_business_direct_citation_source_allowed_with_projection(
    query_contract: &str,
    projection: &QueryConstraintProjection,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    local_business_direct_citation_source_allowed_with_contract_and_projection(
        None,
        query_contract,
        projection,
        raw,
        title,
        excerpt,
    )
}

fn grounded_direct_citation_source_allowed_with_contract_and_projection(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    projection: &QueryConstraintProjection,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    if !projection.enforce_grounded_compatibility() {
        return true;
    }

    let trimmed = raw.trim();
    if trimmed.is_empty() || title.trim().is_empty() && excerpt.trim().is_empty() {
        return false;
    }
    if source_has_human_challenge_signal(trimmed, title, excerpt) {
        return false;
    }

    let signals = analyze_source_record_signals(trimmed, title, excerpt);
    if signals.low_priority_hits > 0 || signals.low_priority_dominates() {
        return false;
    }

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
    if !compatibility_passes_projection(projection, &compatibility) {
        return false;
    }

    if retrieval_contract_prefers_single_fact_snapshot(retrieval_contract, query_contract)
        && !candidate_time_sensitive_resolvable_payload(trimmed, title, excerpt)
    {
        return false;
    }

    true
}

fn grounded_direct_citation_source_allowed_with_projection(
    query_contract: &str,
    projection: &QueryConstraintProjection,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    grounded_direct_citation_source_allowed_with_contract_and_projection(
        None,
        query_contract,
        projection,
        raw,
        title,
        excerpt,
    )
}

pub(crate) fn projection_candidate_url_allowed_with_contract_and_projection(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    projection: &QueryConstraintProjection,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    if projection_candidate_listing_disallowed_with_contract_and_projection(
        retrieval_contract,
        query_contract,
        projection,
        raw,
        title,
        excerpt,
    ) {
        return false;
    }
    let candidate_allowed = projection_candidate_url_allowed(raw)
        || single_snapshot_metric_detail_candidate_allowed_with_contract_and_projection(
            retrieval_contract,
            query_contract,
            projection,
            raw,
            title,
            excerpt,
        )
        || local_business_detail_root_candidate_allowed_with_contract(
            retrieval_contract,
            query_contract,
            projection,
            raw,
            title,
            excerpt,
        );
    if !candidate_allowed {
        return false;
    }
    if !local_business_direct_citation_source_allowed_with_contract_and_projection(
        retrieval_contract,
        query_contract,
        projection,
        raw,
        title,
        excerpt,
    ) {
        return false;
    }
    if !grounded_direct_citation_source_allowed_with_contract_and_projection(
        retrieval_contract,
        query_contract,
        projection,
        raw,
        title,
        excerpt,
    ) {
        return false;
    }
    true
}

pub(crate) fn projection_candidate_url_allowed_with_projection(
    query_contract: &str,
    projection: &QueryConstraintProjection,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    projection_candidate_url_allowed_with_contract_and_projection(
        None,
        query_contract,
        projection,
        raw,
        title,
        excerpt,
    )
}

pub(crate) fn local_business_discovery_source_allowed_with_contract_and_projection(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    projection: &QueryConstraintProjection,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    if projection_candidate_url_allowed_with_contract_and_projection(
        retrieval_contract,
        query_contract,
        projection,
        raw,
        title,
        excerpt,
    ) {
        return true;
    }
    if !local_business_discovery_seed_required_with_contract(
        retrieval_contract,
        query_contract,
        projection,
    ) {
        return false;
    }

    let trimmed = raw.trim();
    if trimmed.is_empty() || !is_citable_web_url(trimmed) || is_search_hub_url(trimmed) {
        return false;
    }
    let Ok(parsed) = Url::parse(trimmed) else {
        return false;
    };
    if parsed.path().trim_matches('/').is_empty() {
        return false;
    }
    if title.trim().is_empty() && excerpt.trim().is_empty() {
        return false;
    }
    if source_has_human_challenge_signal(trimmed, title, excerpt) {
        return false;
    }
    if !is_multi_item_listing_url(trimmed)
        && !local_business_collection_surface_candidate(
            projection.locality_scope.as_deref(),
            trimmed,
            title,
            excerpt,
        )
    {
        return false;
    }

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
    if !compatibility_passes_projection(projection, &compatibility) {
        return false;
    }

    let signals = analyze_source_record_signals(trimmed, title, excerpt);
    !(signals.low_priority_hits > 0 || signals.low_priority_dominates())
}

pub(crate) fn local_business_discovery_source_allowed_with_projection(
    query_contract: &str,
    projection: &QueryConstraintProjection,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    local_business_discovery_source_allowed_with_contract_and_projection(
        None,
        query_contract,
        projection,
        raw,
        title,
        excerpt,
    )
}

pub(crate) fn retrieval_affordances_with_contract_and_locality_hint(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    min_sources: u32,
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> Vec<RetrievalAffordanceKind> {
    let projection = build_query_constraint_projection_with_locality_hint(
        query_contract,
        min_sources.max(1),
        source_hints,
        locality_hint,
    );
    let mut affordances = Vec::new();
    if projection_candidate_url_allowed_with_contract_and_projection(
        retrieval_contract,
        query_contract,
        &projection,
        raw,
        title,
        excerpt,
    ) {
        affordances.push(RetrievalAffordanceKind::DirectCitationRead);
    }
    if retrieval_contract_entity_diversity_required(retrieval_contract, query_contract)
        && local_business_discovery_source_allowed_with_contract_and_projection(
            retrieval_contract,
            query_contract,
            &projection,
            raw,
            title,
            excerpt,
        )
    {
        affordances.push(RetrievalAffordanceKind::DiscoveryExpansionSeedRead);
    }
    affordances
}

pub(crate) fn retrieval_affordances_with_locality_hint(
    query_contract: &str,
    min_sources: u32,
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> Vec<RetrievalAffordanceKind> {
    retrieval_affordances_with_contract_and_locality_hint(
        None,
        query_contract,
        min_sources,
        source_hints,
        locality_hint,
        raw,
        title,
        excerpt,
    )
}

pub(crate) fn preferred_pre_read_action_count_with_contract_and_locality_hint(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    min_sources: u32,
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
) -> usize {
    let required = min_sources.max(1) as usize;
    let mut direct_reads = 0usize;
    let mut discovery_seed_reads = 0usize;

    for hint in source_hints {
        let affordances = retrieval_affordances_with_contract_and_locality_hint(
            retrieval_contract,
            query_contract,
            min_sources,
            source_hints,
            locality_hint,
            &hint.url,
            hint.title.as_deref().unwrap_or_default(),
            &hint.excerpt,
        );
        if affordances.contains(&RetrievalAffordanceKind::DirectCitationRead) {
            direct_reads = direct_reads.saturating_add(1);
        }
        if affordances.contains(&RetrievalAffordanceKind::DiscoveryExpansionSeedRead) {
            discovery_seed_reads = discovery_seed_reads.saturating_add(1);
        }
    }

    if direct_reads >= required {
        required
    } else if discovery_seed_reads > 0
        && retrieval_contract_entity_diversity_required(retrieval_contract, query_contract)
    {
        1
    } else {
        required
    }
}

pub(crate) fn preferred_pre_read_action_count_with_locality_hint(
    query_contract: &str,
    min_sources: u32,
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
) -> usize {
    preferred_pre_read_action_count_with_contract_and_locality_hint(
        None,
        query_contract,
        min_sources,
        source_hints,
        locality_hint,
    )
}

pub(crate) fn projection_candidate_listing_disallowed_with_contract_and_projection(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    projection: &QueryConstraintProjection,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    is_multi_item_listing_url(raw)
        && !local_business_detail_root_candidate_allowed_with_contract(
            retrieval_contract,
            query_contract,
            projection,
            raw,
            title,
            excerpt,
        )
}

pub(crate) fn projection_candidate_listing_disallowed_with_projection(
    query_contract: &str,
    projection: &QueryConstraintProjection,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    projection_candidate_listing_disallowed_with_contract_and_projection(
        None,
        query_contract,
        projection,
        raw,
        title,
        excerpt,
    )
}
