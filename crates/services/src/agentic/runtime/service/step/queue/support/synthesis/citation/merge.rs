use super::shared::{
    blocked_unverified_url_set, headline_source_is_low_quality, is_blocked_unverified_url,
    successful_source_url_set,
};
use super::*;

pub(crate) fn merged_story_sources(
    pending: &PendingSearchCompletion,
) -> Vec<PendingSearchReadSummary> {
    let query_contract = synthesis_query_contract(pending);
    let retrieval_contract = pending.retrieval_contract.as_ref();
    let headline_lookup_mode =
        retrieval_contract_is_generic_headline_collection(retrieval_contract, &query_contract);
    let document_briefing_layout = query_prefers_document_briefing_layout(&query_contract)
        && !retrieval_contract_requests_comparison(retrieval_contract, &query_contract);
    let local_business_entity_diversity_required =
        retrieval_contract_entity_diversity_required(retrieval_contract, &query_contract);
    let projection = build_query_constraint_projection(
        &query_contract,
        pending.min_sources,
        &pending.candidate_source_hints,
    );
    let enforce_grounded_compatibility =
        projection.enforce_grounded_compatibility() && !headline_lookup_mode;
    let reject_search_hub = projection.reject_search_hub_candidates();
    let source_url_allowed = |url: &str| {
        let trimmed = url.trim();
        if trimmed.is_empty() || !is_citable_web_url(trimmed) {
            return false;
        }
        if reject_search_hub && is_search_hub_url(trimmed) {
            return false;
        }
        if headline_lookup_mode
            && (is_search_hub_url(trimmed) || is_multi_item_listing_url(trimmed))
        {
            return false;
        }
        true
    };
    let successful_urls = successful_source_url_set(pending);
    let blocked_unverified_urls = blocked_unverified_url_set(pending, &successful_urls);
    let preserve_successful_reads =
        (document_briefing_layout && !headline_lookup_mode)
            || local_business_entity_diversity_required;

    let mut merged: Vec<PendingSearchReadSummary> = Vec::new();
    let mut seen = BTreeSet::new();

    for source in &pending.successful_reads {
        let trimmed = source.url.trim();
        if !source_url_allowed(trimmed) {
            continue;
        }
        if enforce_grounded_compatibility && !preserve_successful_reads {
            let compatibility = candidate_constraint_compatibility(
                &projection.constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                trimmed,
                source.title.as_deref().unwrap_or_default(),
                &source.excerpt,
            );
            if !compatibility_passes_projection(&projection, &compatibility) {
                continue;
            }
        }
        // Deterministic document briefings should synthesize from read-backed evidence
        // that already cleared the web pipeline, then let briefing selection/finalization
        // prune weak or duplicative sources. Reapplying the grounded projection here can
        // drop all successful reads for execution-suffixed research contracts.
        if !seen.insert(trimmed.to_string()) {
            continue;
        }
        merged.push(source.clone());
    }

    for source in &pending.candidate_source_hints {
        let trimmed = source.url.trim();
        if trimmed.is_empty()
            || !source_url_allowed(trimmed)
            || is_blocked_unverified_url(trimmed, &blocked_unverified_urls)
        {
            continue;
        }
        if enforce_grounded_compatibility {
            let compatibility = candidate_constraint_compatibility(
                &projection.constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                trimmed,
                source.title.as_deref().unwrap_or_default(),
                &source.excerpt,
            );
            if !compatibility_passes_projection(&projection, &compatibility) {
                continue;
            }
        }
        if !seen.insert(trimmed.to_string()) {
            continue;
        }
        merged.push(source.clone());
    }

    for url in &pending.candidate_urls {
        let trimmed = url.trim();
        if trimmed.is_empty()
            || !source_url_allowed(trimmed)
            || is_blocked_unverified_url(trimmed, &blocked_unverified_urls)
        {
            continue;
        }
        if enforce_grounded_compatibility {
            let compatibility = candidate_constraint_compatibility(
                &projection.constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                trimmed,
                "",
                "",
            );
            if !compatibility_passes_projection(&projection, &compatibility) {
                continue;
            }
        }
        if !seen.insert(trimmed.to_string()) {
            continue;
        }
        merged.push(PendingSearchReadSummary {
            url: trimmed.to_string(),
            title: None,
            excerpt: String::new(),
        });
    }

    merged.sort_by(|left, right| {
        let left_signals = source_evidence_signals(left);
        let right_signals = source_evidence_signals(right);
        let left_success = successful_urls.contains(left.url.trim());
        let right_success = successful_urls.contains(right.url.trim());
        let left_document_authority_score = if document_briefing_layout {
            source_document_authority_score(
                &query_contract,
                &left.url,
                left.title.as_deref().unwrap_or_default(),
                &left.excerpt,
            )
        } else {
            0
        };
        let right_document_authority_score = if document_briefing_layout {
            source_document_authority_score(
                &query_contract,
                &right.url,
                right.title.as_deref().unwrap_or_default(),
                &right.excerpt,
            )
        } else {
            0
        };
        let left_key = (
            left_document_authority_score > 0,
            left_document_authority_score,
            !is_low_priority_coverage_story(left),
            left_signals.official_status_host_hits > 0,
            left_signals.official_status_host_hits,
            left_signals.primary_status_surface_hits > 0,
            left_signals.primary_status_surface_hits,
            left_signals.secondary_coverage_hits == 0,
            left_signals.documentation_surface_hits == 0,
            left_signals.relevance_score(left_success),
            (
                left_signals.provenance_hits,
                left_signals.primary_event_hits,
                left_success,
            ),
        );
        let right_key = (
            right_document_authority_score > 0,
            right_document_authority_score,
            !is_low_priority_coverage_story(right),
            right_signals.official_status_host_hits > 0,
            right_signals.official_status_host_hits,
            right_signals.primary_status_surface_hits > 0,
            right_signals.primary_status_surface_hits,
            right_signals.secondary_coverage_hits == 0,
            right_signals.documentation_surface_hits == 0,
            right_signals.relevance_score(right_success),
            (
                right_signals.provenance_hits,
                right_signals.primary_event_hits,
                right_success,
            ),
        );
        right_key
            .cmp(&left_key)
            .then_with(|| left.url.cmp(&right.url))
    });

    if headline_lookup_mode {
        let filtered = merged
            .iter()
            .filter(|source| !headline_source_is_low_quality(source))
            .cloned()
            .collect::<Vec<_>>();
        if !filtered.is_empty() {
            return filtered;
        }
    }

    merged
}

pub(crate) fn grounded_source_evidence_count(pending: &PendingSearchCompletion) -> usize {
    let query_contract = synthesis_query_contract(pending);
    let retrieval_contract = pending.retrieval_contract.as_ref();
    let headline_lookup_mode =
        retrieval_contract_is_generic_headline_collection(retrieval_contract, &query_contract);
    let document_briefing_layout = query_prefers_document_briefing_layout(&query_contract)
        && !retrieval_contract_requests_comparison(retrieval_contract, &query_contract);
    let locality_scope = explicit_query_scope_hint(&query_contract).or_else(|| {
        retrieval_contract_requires_runtime_locality(retrieval_contract, &query_contract)
            .then(|| effective_locality_scope_hint(None))
            .flatten()
    });
    let required_local_business_sources =
        retrieval_contract_required_story_count(retrieval_contract, &query_contract)
            .max(1)
            .max(pending.min_sources.max(1) as usize);
    let local_business_target_sources =
        if retrieval_contract_entity_diversity_required(retrieval_contract, &query_contract) {
            let target_names = merged_local_business_target_names(
                &pending.attempted_urls,
                &pending.successful_reads,
                locality_scope.as_deref(),
                required_local_business_sources,
            );
            if target_names.is_empty() {
                Vec::new()
            } else {
                selected_local_business_target_sources(
                    &query_contract,
                    &target_names,
                    &pending.successful_reads,
                    locality_scope.as_deref(),
                    required_local_business_sources,
                )
            }
        } else {
            Vec::new()
        };
    let projection = build_query_constraint_projection(
        &query_contract,
        pending.min_sources,
        &pending.candidate_source_hints,
    );
    let enforce_grounded_compatibility =
        projection.enforce_grounded_compatibility() && !headline_lookup_mode;
    let reject_search_hub = projection.reject_search_hub_candidates();
    let source_url_allowed = |url: &str| {
        let trimmed = url.trim();
        if trimmed.is_empty() || !is_citable_web_url(trimmed) {
            return false;
        }
        if reject_search_hub && is_search_hub_url(trimmed) {
            return false;
        }
        if headline_lookup_mode
            && (is_search_hub_url(trimmed) || is_multi_item_listing_url(trimmed))
        {
            return false;
        }
        true
    };
    let has_constraint_objective = projection.has_constraint_objective() && !headline_lookup_mode;
    let envelope_constraints = &projection.constraints;
    let envelope_policy = ResolutionPolicy::default();
    let successful_urls = successful_source_url_set(pending);
    let blocked_unverified_urls = blocked_unverified_url_set(pending, &successful_urls);
    let preserve_document_briefing_successful_reads =
        document_briefing_layout && !headline_lookup_mode;

    let mut grounded_urls: BTreeSet<String> = BTreeSet::new();

    for source in local_business_target_sources {
        let trimmed = source.url.trim();
        if source_url_allowed(trimmed) {
            grounded_urls.insert(trimmed.to_string());
        }
    }

    for source in &pending.successful_reads {
        let trimmed = source.url.trim();
        if !source_url_allowed(trimmed) {
            continue;
        }
        if enforce_grounded_compatibility && !preserve_document_briefing_successful_reads {
            let compatibility = candidate_constraint_compatibility(
                &projection.constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                trimmed,
                source.title.as_deref().unwrap_or_default(),
                &source.excerpt,
            );
            if !compatibility_passes_projection(&projection, &compatibility) {
                continue;
            }
        }
        if has_constraint_objective && !preserve_document_briefing_successful_reads {
            let title = source.title.as_deref().unwrap_or_default();
            let score = single_snapshot_candidate_envelope_score(
                envelope_constraints,
                envelope_policy,
                trimmed,
                title,
                &source.excerpt,
            );
            if !envelope_score_resolves_constraint(envelope_constraints, &score) {
                continue;
            }
        }
        grounded_urls.insert(trimmed.to_string());
    }

    for source in &pending.candidate_source_hints {
        let trimmed = source.url.trim();
        if trimmed.is_empty()
            || !source_url_allowed(trimmed)
            || is_blocked_unverified_url(trimmed, &blocked_unverified_urls)
        {
            continue;
        }
        if enforce_grounded_compatibility {
            let compatibility = candidate_constraint_compatibility(
                &projection.constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                trimmed,
                source.title.as_deref().unwrap_or_default(),
                &source.excerpt,
            );
            if !compatibility_passes_projection(&projection, &compatibility) {
                continue;
            }
        }
        if has_constraint_objective {
            let title = source.title.as_deref().unwrap_or_default();
            let score = single_snapshot_candidate_envelope_score(
                envelope_constraints,
                envelope_policy,
                trimmed,
                title,
                &source.excerpt,
            );
            if !envelope_score_resolves_constraint(envelope_constraints, &score) {
                continue;
            }
        } else {
            let has_signal = !source.excerpt.trim().is_empty()
                || source
                    .title
                    .as_deref()
                    .map(|value| !value.trim().is_empty())
                    .unwrap_or(false);
            if !has_signal {
                continue;
            }
        }
        grounded_urls.insert(trimmed.to_string());
    }

    grounded_urls.len()
}
