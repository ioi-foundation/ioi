use super::*;

pub(crate) fn pre_read_candidate_plan(
    query_contract: &str,
    min_sources: u32,
    candidate_urls: Vec<String>,
    candidate_source_hints: Vec<PendingSearchReadSummary>,
    locality_hint: Option<&str>,
    allow_floor_recovery_exploration: bool,
) -> PreReadCandidatePlan {
    let total_candidates = candidate_urls.len();
    if total_candidates == 0 {
        return PreReadCandidatePlan {
            candidate_urls,
            probe_source_hints: candidate_source_hints.clone(),
            candidate_source_hints,
            total_candidates: 0,
            pruned_candidates: 0,
            resolvable_candidates: 0,
            scoreable_candidates: 0,
            requires_constraint_search_probe: false,
        };
    }

    let projection = build_query_constraint_projection_with_locality_hint(
        query_contract,
        min_sources,
        &candidate_source_hints,
        locality_hint,
    );
    let mut probe_source_hints = candidate_source_hints.clone();
    let constraints = &projection.constraints;
    let policy = ResolutionPolicy::default();
    let hints_by_url = candidate_source_hints
        .iter()
        .filter_map(|hint| {
            let trimmed = hint.url.trim();
            (!trimmed.is_empty()).then(|| (trimmed.to_string(), hint.clone()))
        })
        .collect::<BTreeMap<_, _>>();

    let mut ranked = candidate_urls
        .iter()
        .enumerate()
        .map(|(idx, url)| {
            let trimmed = url.trim();
            let hint = hints_by_url.get(trimmed);
            let title = hint
                .and_then(|entry| entry.title.as_deref())
                .unwrap_or_default();
            let excerpt = hint.map(|entry| entry.excerpt.as_str()).unwrap_or_default();
            let score = single_snapshot_candidate_envelope_score(
                constraints,
                policy,
                trimmed,
                title,
                excerpt,
            );
            let scoreable = !title.trim().is_empty() || !excerpt.trim().is_empty();
            let compatibility = candidate_constraint_compatibility(
                constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                trimmed,
                title,
                excerpt,
            );
            let resolvable_payload = candidate_time_sensitive_resolvable_payload(title, excerpt);
            (
                idx,
                trimmed.to_string(),
                score,
                scoreable,
                compatibility,
                resolvable_payload,
            )
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        let right_passes = compatibility_passes_projection(&projection, &right.4);
        let left_passes = compatibility_passes_projection(&projection, &left.4);
        right
            .5
            .cmp(&left.5)
            .then_with(|| right_passes.cmp(&left_passes))
            .then_with(|| right.4.compatibility_score.cmp(&left.4.compatibility_score))
            .then_with(|| compare_candidate_evidence_scores_desc(&left.2, &right.2))
            .then_with(|| right.4.is_compatible.cmp(&left.4.is_compatible))
            .then_with(|| right.3.cmp(&left.3))
            .then_with(|| left.0.cmp(&right.0))
            .then_with(|| left.1.cmp(&right.1))
    });

    let min_required = min_sources.max(1) as usize;
    let resolvable_candidates = ranked
        .iter()
        .filter(|(_, _, score, _, _, _)| envelope_score_resolves_constraint(constraints, score))
        .count();
    let scoreable_candidates = ranked
        .iter()
        .filter(|(_, _, _, scoreable, _, _)| *scoreable)
        .count();
    let compatible_candidates = ranked
        .iter()
        .filter(|(_, _, _, _, compatibility, _)| {
            compatibility_passes_projection(&projection, compatibility)
        })
        .count();
    let positive_compatibility_candidates = ranked
        .iter()
        .filter(|(_, _, _, _, compatibility, _)| {
            compatibility_passes_projection(&projection, compatibility)
                && compatibility.compatibility_score > 0
        })
        .count();
    let locality_compatible_candidates = ranked
        .iter()
        .filter(|(_, _, _, _, compatibility, _)| compatibility.locality_compatible)
        .count();
    let can_prune = resolvable_candidates >= min_required;
    let enforce_grounded_compatibility = projection.enforce_grounded_compatibility();
    let strict_grounded_compatibility = projection.strict_grounded_compatibility();
    let can_prune_by_compatibility = if strict_grounded_compatibility {
        !(allow_floor_recovery_exploration
            && compatible_candidates > 0
            && compatible_candidates < min_required)
    } else {
        enforce_grounded_compatibility
            && (compatible_candidates >= min_required
                || positive_compatibility_candidates >= min_required)
    };
    let explicit_locality_scope =
        projection.locality_scope.is_some() && !projection.locality_scope_inferred;
    let can_prune_by_locality = projection.locality_scope.is_some()
        && constraints.scopes.contains(&ConstraintScope::TimeSensitive)
        && (locality_compatible_candidates >= min_required
            || (allow_floor_recovery_exploration && locality_compatible_candidates > 0)
            || (explicit_locality_scope && locality_compatible_candidates > 0));
    let can_prune_by_positive_compatibility =
        constraints.scopes.contains(&ConstraintScope::TimeSensitive)
            && positive_compatibility_candidates >= min_required;
    let has_constraint_objective = projection.has_constraint_objective();
    let time_sensitive_scope = constraints.scopes.contains(&ConstraintScope::TimeSensitive);
    let reject_search_hub = projection.reject_search_hub_candidates();
    let headline_lookup_mode = query_is_generic_headline_collection(query_contract);
    let prefer_non_listing_sources = query_prefers_multi_item_cardinality(query_contract);
    let mut requires_constraint_search_probe =
        if !has_constraint_objective || scoreable_candidates == 0 {
            false
        } else {
            let compatibility_gap = compatible_candidates < min_required;
            let resolvability_gap = resolvable_candidates < min_required;
            if strict_grounded_compatibility {
                compatibility_gap || resolvability_gap
            } else {
                (constraints.scopes.contains(&ConstraintScope::TimeSensitive)
                    && (compatibility_gap || resolvability_gap))
                    || (projection.query_facets.grounded_external_required && compatibility_gap)
            }
        };

    let mut candidate_urls = ranked
        .iter()
        .filter_map(|(_, url, score, _, compatibility, _)| {
            if reject_search_hub && is_search_hub_url(url) {
                return None;
            }
            if headline_lookup_mode && is_news_feed_wrapper_url(url) {
                return None;
            }
            if prefer_non_listing_sources && is_multi_item_listing_url(url) {
                return None;
            }
            if can_prune && !envelope_score_resolves_constraint(constraints, score) {
                return None;
            }
            if can_prune_by_compatibility
                && !compatibility_passes_projection(&projection, compatibility)
            {
                return None;
            }
            if (can_prune_by_locality || explicit_locality_scope)
                && !compatibility.locality_compatible
            {
                return None;
            }
            if can_prune_by_positive_compatibility && compatibility.compatibility_score == 0 {
                return None;
            }
            Some(url.to_string())
        })
        .collect::<Vec<_>>();
    if candidate_urls.is_empty() && projection.locality_scope_inferred {
        let fallback_limit = min_required
            .min(INFERRED_SCOPE_FALLBACK_CANDIDATE_COUNT)
            .max(1);
        let positive_fallback = ranked
            .iter()
            .filter(|(_, _, _, _, compatibility, _)| {
                compatibility_passes_projection(&projection, compatibility)
                    && compatibility.compatibility_score > 0
            })
            .filter(|(_, url, _, _, _, _)| {
                !prefer_non_listing_sources || !is_multi_item_listing_url(url)
            })
            .take(fallback_limit)
            .map(|(_, url, _, _, _, _)| url.to_string())
            .collect::<Vec<_>>();
        candidate_urls = positive_fallback;
    }
    if candidate_urls.len() < min_required && has_constraint_objective && scoreable_candidates > 0 {
        let candidate_count_before_top_up = candidate_urls.len();
        let mut seen_candidate_urls = candidate_urls
            .iter()
            .map(|url| url.trim().to_string())
            .collect::<BTreeSet<_>>();
        for (_, url, _, _, compatibility, resolvable_payload) in ranked.iter() {
            if candidate_urls.len() >= min_required {
                break;
            }
            if seen_candidate_urls.contains(url) || is_search_hub_url(url) {
                continue;
            }
            if headline_lookup_mode && is_news_feed_wrapper_url(url) {
                continue;
            }
            if prefer_non_listing_sources && is_multi_item_listing_url(url) {
                continue;
            }
            if !compatibility.locality_compatible {
                continue;
            }
            let compatibility_relevant = compatibility.compatibility_score > 0
                || compatibility_passes_projection(&projection, compatibility)
                || (allow_floor_recovery_exploration && compatible_candidates == 0);
            if !compatibility_relevant {
                continue;
            }
            let payload_relevant = !time_sensitive_scope
                || *resolvable_payload
                || candidate_urls.len() < min_required
                || (allow_floor_recovery_exploration && compatible_candidates == 0);
            if !payload_relevant {
                continue;
            }
            if seen_candidate_urls.insert(url.to_string()) {
                candidate_urls.push(url.to_string());
            }
        }
        if candidate_urls.len() > candidate_count_before_top_up {
            requires_constraint_search_probe = true;
        }
    }
    let distinct_domain_floor = required_distinct_domain_floor(query_contract);
    if distinct_domain_floor > 1 && !candidate_urls.is_empty() {
        let mut seen_domains = BTreeSet::new();
        let mut distinct_domain_urls = Vec::new();
        for url in &candidate_urls {
            let trimmed = url.trim();
            if trimmed.is_empty() {
                continue;
            }
            let domain_key =
                canonical_domain_key(trimmed).unwrap_or_else(|| trimmed.to_ascii_lowercase());
            if seen_domains.insert(domain_key) {
                distinct_domain_urls.push(trimmed.to_string());
            }
        }
        if !distinct_domain_urls.is_empty() {
            candidate_urls = distinct_domain_urls;
        }
        if seen_domains.len() < distinct_domain_floor {
            requires_constraint_search_probe = true;
        }
    }
    if candidate_urls.is_empty()
        && has_constraint_objective
        && constraints.scopes.contains(&ConstraintScope::TimeSensitive)
    {
        requires_constraint_search_probe = true;
    }
    let kept_urls = candidate_urls.iter().cloned().collect::<BTreeSet<_>>();
    let mut candidate_source_hints = Vec::new();
    let mut seen_hint_urls = BTreeSet::new();
    for url in &candidate_urls {
        if let Some(hint) = hints_by_url.get(url) {
            let trimmed = hint.url.trim();
            if headline_lookup_mode && is_news_feed_wrapper_url(trimmed) {
                continue;
            }
            if !trimmed.is_empty() && seen_hint_urls.insert(trimmed.to_string()) {
                candidate_source_hints.push(hint.clone());
            }
        }
    }
    // Preserve additional ranked, non-hub compatible hints for citation quality and
    // bounded floor-recovery reads when selected URL inventory is sparse.
    for (_, url, _, _, compatibility, resolvable_payload) in &ranked {
        if seen_hint_urls.contains(url) {
            continue;
        }
        if reject_search_hub && is_search_hub_url(url) {
            continue;
        }
        if headline_lookup_mode && is_news_feed_wrapper_url(url) {
            continue;
        }
        if prefer_non_listing_sources && is_multi_item_listing_url(url) {
            continue;
        }
        if (can_prune_by_locality || explicit_locality_scope) && !compatibility.locality_compatible
        {
            continue;
        }
        let include_hint = compatibility_passes_projection(&projection, compatibility)
            || compatibility.compatibility_score > 0
            || *resolvable_payload;
        if !include_hint {
            continue;
        }
        if let Some(hint) = hints_by_url.get(url) {
            let trimmed = hint.url.trim();
            if !trimmed.is_empty() && seen_hint_urls.insert(trimmed.to_string()) {
                candidate_source_hints.push(hint.clone());
            }
        }
    }

    if explicit_locality_scope {
        probe_source_hints = candidate_source_hints.clone();
    }

    PreReadCandidatePlan {
        candidate_urls,
        candidate_source_hints,
        probe_source_hints,
        total_candidates,
        pruned_candidates: total_candidates.saturating_sub(kept_urls.len()),
        resolvable_candidates,
        scoreable_candidates,
        requires_constraint_search_probe,
    }
}

pub(crate) fn pre_read_candidate_plan_from_bundle_with_locality_hint(
    query_contract: &str,
    min_sources: u32,
    bundle: &WebEvidenceBundle,
    locality_hint: Option<&str>,
) -> PreReadCandidatePlan {
    pre_read_candidate_plan_from_bundle_with_locality_hint_and_recovery_mode(
        query_contract,
        min_sources,
        bundle,
        locality_hint,
        false,
    )
}

pub(crate) fn pre_read_candidate_plan_from_bundle_with_locality_hint_and_recovery_mode(
    query_contract: &str,
    min_sources: u32,
    bundle: &WebEvidenceBundle,
    locality_hint: Option<&str>,
    allow_floor_recovery_exploration: bool,
) -> PreReadCandidatePlan {
    let (candidate_urls, candidate_source_hints) =
        constrained_candidate_inventory_from_bundle_with_locality_hint(
            query_contract,
            min_sources,
            bundle,
            locality_hint,
        );
    pre_read_candidate_plan(
        query_contract,
        min_sources,
        candidate_urls,
        candidate_source_hints,
        locality_hint,
        allow_floor_recovery_exploration,
    )
}

pub(crate) fn pre_read_candidate_plan_from_bundle(
    query_contract: &str,
    min_sources: u32,
    bundle: &WebEvidenceBundle,
) -> PreReadCandidatePlan {
    pre_read_candidate_plan_from_bundle_with_locality_hint_and_recovery_mode(
        query_contract,
        min_sources,
        bundle,
        None,
        false,
    )
}

pub(crate) fn pre_read_candidate_plan_from_bundle_with_recovery_mode(
    query_contract: &str,
    min_sources: u32,
    bundle: &WebEvidenceBundle,
    allow_floor_recovery_exploration: bool,
) -> PreReadCandidatePlan {
    pre_read_candidate_plan_from_bundle_with_locality_hint_and_recovery_mode(
        query_contract,
        min_sources,
        bundle,
        None,
        allow_floor_recovery_exploration,
    )
}
