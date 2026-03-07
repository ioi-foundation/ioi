pub(crate) fn pre_read_candidate_plan_with_contract(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    min_sources: u32,
    candidate_urls: Vec<String>,
    candidate_source_hints: Vec<PendingSearchReadSummary>,
    locality_hint: Option<&str>,
    allow_floor_recovery_exploration: bool,
) -> PreReadCandidatePlan {
    let total_candidates = candidate_urls.len();
    if total_candidates == 0 {
        let projection = build_query_constraint_projection_with_locality_hint(
            query_contract,
            min_sources,
            &candidate_source_hints,
            locality_hint,
        );
        let requires_constraint_search_probe = projection.has_constraint_objective()
            && (projection
                .constraints
                .scopes
                .contains(&ConstraintScope::TimeSensitive)
                || projection.enforce_grounded_compatibility());
        return PreReadCandidatePlan {
            candidate_urls,
            probe_source_hints: candidate_source_hints.clone(),
            candidate_source_hints,
            total_candidates: 0,
            pruned_candidates: 0,
            resolvable_candidates: 0,
            scoreable_candidates: 0,
            requires_constraint_search_probe,
        };
    }

    let projection = build_query_constraint_projection_with_locality_hint(
        query_contract,
        min_sources,
        &candidate_source_hints,
        locality_hint,
    );
    let headline_lookup_mode =
        retrieval_contract_is_generic_headline_collection(retrieval_contract, query_contract);
    let probe_source_hints = candidate_source_hints.clone();
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
            let resolvable_payload =
                candidate_time_sensitive_resolvable_payload(trimmed, title, excerpt);
            let affordances = retrieval_affordances_with_contract_and_locality_hint(
                retrieval_contract,
                query_contract,
                min_sources,
                &candidate_source_hints,
                locality_hint,
                trimmed,
                title,
                excerpt,
            );
            let listing_disallowed =
                projection_candidate_listing_disallowed_with_contract_and_projection(
                    retrieval_contract,
                    query_contract,
                    &projection,
                    trimmed,
                    title,
                    excerpt,
                );
            let headline_source = PendingSearchReadSummary {
                url: trimmed.to_string(),
                title: (!title.trim().is_empty()).then(|| title.trim().to_string()),
                excerpt: excerpt.trim().to_string(),
            };
            let headline_low_quality =
                headline_lookup_mode && headline_source_is_low_quality(trimmed, title, excerpt);
            let headline_actionable =
                headline_lookup_mode && headline_source_is_actionable(&headline_source);
            (
                idx,
                trimmed.to_string(),
                score,
                scoreable,
                compatibility,
                resolvable_payload,
                affordances,
                listing_disallowed,
                headline_low_quality,
                headline_actionable,
            )
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        let right_passes =
            !right.6.is_empty() && compatibility_passes_projection(&projection, &right.4);
        let left_passes =
            !left.6.is_empty() && compatibility_passes_projection(&projection, &left.4);
        right
            .9
            .cmp(&left.9)
            .then_with(|| right.8.cmp(&left.8))
            .then_with(|| right.5.cmp(&left.5))
            .then_with(|| right_passes.cmp(&left_passes))
            .then_with(|| right.4.compatibility_score.cmp(&left.4.compatibility_score))
            .then_with(|| right.6.len().cmp(&left.6.len()))
            .then_with(|| compare_candidate_evidence_scores_desc(&left.2, &right.2))
            .then_with(|| right.4.is_compatible.cmp(&left.4.is_compatible))
            .then_with(|| right.3.cmp(&left.3))
            .then_with(|| left.0.cmp(&right.0))
            .then_with(|| left.1.cmp(&right.1))
    });

    let min_required = min_sources.max(1) as usize;
    let resolvable_candidates = ranked
        .iter()
        .filter(|(_, _, score, _, _, _, affordances, _, _, _)| {
            !affordances.is_empty() && envelope_score_resolves_constraint(constraints, score)
        })
        .count();
    let scoreable_candidates = ranked
        .iter()
        .filter(|(_, _, _, scoreable, _, _, affordances, _, _, _)| {
            *scoreable && !affordances.is_empty()
        })
        .count();
    let compatible_candidates = ranked
        .iter()
        .filter(|(_, _, _, _, compatibility, _, affordances, _, _, _)| {
            !affordances.is_empty() && compatibility_passes_projection(&projection, compatibility)
        })
        .count();
    let positive_compatibility_candidates = ranked
        .iter()
        .filter(|(_, _, _, _, compatibility, _, affordances, _, _, _)| {
            !affordances.is_empty()
                && compatibility_passes_projection(&projection, compatibility)
                && compatibility.compatibility_score > 0
        })
        .count();
    let direct_read_candidates = ranked
        .iter()
        .filter(|(_, _, _, _, _, _, affordances, _, _, _)| {
            affordances.contains(&RetrievalAffordanceKind::DirectCitationRead)
        })
        .count();
    let headline_actionable_candidates = ranked
        .iter()
        .filter(|(_, _, _, _, _, _, affordances, _, _, actionable)| {
            !affordances.is_empty() && *actionable
        })
        .count();
    let headline_non_low_quality_candidates = ranked
        .iter()
        .filter(|(_, _, _, _, _, _, affordances, _, low_quality, _)| {
            !affordances.is_empty() && !*low_quality
        })
        .count();
    let locality_compatible_candidates = ranked
        .iter()
        .filter(|(_, _, _, _, compatibility, _, affordances, _, _, _)| {
            !affordances.is_empty() && compatibility.locality_compatible
        })
        .count();
    let can_prune = resolvable_candidates >= min_required && !headline_lookup_mode;
    let enforce_grounded_compatibility = projection.enforce_grounded_compatibility();
    let strict_grounded_compatibility = projection.strict_grounded_compatibility();
    let must_require_compatibility = enforce_grounded_compatibility && !headline_lookup_mode;
    let can_prune_by_compatibility = if strict_grounded_compatibility {
        !(allow_floor_recovery_exploration
            && compatible_candidates > 0
            && compatible_candidates < min_required)
    } else if headline_lookup_mode {
        false
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
    let can_prune_by_positive_compatibility = !headline_lookup_mode
        && constraints.scopes.contains(&ConstraintScope::TimeSensitive)
        && positive_compatibility_candidates >= min_required;
    let has_constraint_objective = projection.has_constraint_objective();
    let time_sensitive_scope = constraints.scopes.contains(&ConstraintScope::TimeSensitive);
    let reject_search_hub = projection.reject_search_hub_candidates();
    let prefer_direct_reads = direct_read_candidates >= min_required;
    let can_prune_headline_low_quality =
        headline_lookup_mode && headline_non_low_quality_candidates >= min_required;
    let mut requires_constraint_search_probe = if !has_constraint_objective {
        false
    } else {
        let compatibility_gap = compatible_candidates < min_required;
        let resolvability_gap = resolvable_candidates < min_required;
        let grounded_gap = projection.enforce_grounded_compatibility()
            && (scoreable_candidates == 0 || compatibility_gap || direct_read_candidates == 0);
        if strict_grounded_compatibility {
            grounded_gap || resolvability_gap
        } else {
            (constraints.scopes.contains(&ConstraintScope::TimeSensitive)
                && (compatibility_gap || resolvability_gap || scoreable_candidates == 0))
                || grounded_gap
        }
    };

    let mut candidate_urls = ranked
        .iter()
        .filter_map(
            |(_, url, score, _, compatibility, _, affordances, _, low_quality, _)| {
                if reject_search_hub && is_search_hub_url(url) {
                    return None;
                }
                if affordances.is_empty() {
                    return None;
                }
                if can_prune_headline_low_quality && *low_quality {
                    return None;
                }
                if prefer_direct_reads
                    && !affordances.contains(&RetrievalAffordanceKind::DirectCitationRead)
                {
                    return None;
                }
                if can_prune && !envelope_score_resolves_constraint(constraints, score) {
                    return None;
                }
                if must_require_compatibility
                    && !compatibility_passes_projection(&projection, compatibility)
                {
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
            },
        )
        .collect::<Vec<_>>();
    if candidate_urls.is_empty() && projection.locality_scope_inferred {
        let fallback_limit = min_required
            .min(INFERRED_SCOPE_FALLBACK_CANDIDATE_COUNT)
            .max(1);
        let positive_fallback = ranked
            .iter()
            .filter(|(_, _, _, _, compatibility, _, affordances, _, _, _)| {
                !affordances.is_empty()
                    && compatibility_passes_projection(&projection, compatibility)
                    && compatibility.compatibility_score > 0
            })
            .filter(|(_, _, _, _, _, _, affordances, _, _, _)| {
                !prefer_direct_reads
                    || affordances.contains(&RetrievalAffordanceKind::DirectCitationRead)
            })
            .take(fallback_limit)
            .map(|(_, url, _, _, _, _, _, _, _, _)| url.to_string())
            .collect::<Vec<_>>();
        candidate_urls = positive_fallback;
    }
    if candidate_urls.len() < min_required && has_constraint_objective && scoreable_candidates > 0 {
        let candidate_count_before_top_up = candidate_urls.len();
        let mut seen_candidate_urls = candidate_urls
            .iter()
            .map(|url| url.trim().to_string())
            .collect::<BTreeSet<_>>();
        for (_, url, _, _, compatibility, resolvable_payload, affordances, _, _, _) in ranked.iter()
        {
            if candidate_urls.len() >= min_required {
                break;
            }
            if seen_candidate_urls.contains(url) || is_search_hub_url(url) {
                continue;
            }
            if affordances.is_empty() {
                continue;
            }
            if prefer_direct_reads
                && !affordances.contains(&RetrievalAffordanceKind::DirectCitationRead)
            {
                continue;
            }
            if !compatibility.locality_compatible {
                continue;
            }
            let compatibility_relevant = if must_require_compatibility {
                compatibility_passes_projection(&projection, compatibility)
            } else {
                compatibility.compatibility_score > 0
                    || compatibility_passes_projection(&projection, compatibility)
                    || (allow_floor_recovery_exploration && compatible_candidates == 0)
            };
            if !compatibility_relevant {
                continue;
            }
            let payload_relevant = if must_require_compatibility && time_sensitive_scope {
                *resolvable_payload
            } else {
                headline_lookup_mode
                    || !time_sensitive_scope
                    || *resolvable_payload
                    || candidate_urls.len() < min_required
                    || (allow_floor_recovery_exploration && compatible_candidates == 0)
            };
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
    let distinct_domain_floor =
        retrieval_contract_required_distinct_domain_floor(retrieval_contract, query_contract);
    if distinct_domain_floor > 1 && !candidate_urls.is_empty() {
        let mut seen_domains = BTreeSet::new();
        let mut distinct_domain_urls = Vec::new();
        for url in &candidate_urls {
            let trimmed = url.trim();
            if trimmed.is_empty() {
                continue;
            }
            let domain_key = hints_by_url
                .get(url)
                .and_then(|hint| {
                    candidate_distinct_domain_key_from_excerpt(trimmed, hint.excerpt.as_str())
                })
                .unwrap_or_else(|| trimmed.to_ascii_lowercase());
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
    if headline_lookup_mode && headline_actionable_candidates < min_required {
        requires_constraint_search_probe = true;
    }
    let kept_urls = candidate_urls.iter().cloned().collect::<BTreeSet<_>>();
    let mut candidate_source_hints = Vec::new();
    let mut seen_hint_urls = BTreeSet::new();
    let mut seen_hint_domains = BTreeSet::new();
    for url in &candidate_urls {
        if let Some(hint) = hints_by_url.get(url) {
            let trimmed = hint.url.trim();
            if !trimmed.is_empty() && seen_hint_urls.insert(trimmed.to_string()) {
                if let Some(domain_key) =
                    candidate_distinct_domain_key_from_excerpt(trimmed, hint.excerpt.as_str())
                {
                    seen_hint_domains.insert(domain_key);
                }
                candidate_source_hints.push(hint.clone());
            }
        }
    }
    // Preserve additional ranked, non-hub compatible hints for citation quality and
    // bounded floor-recovery reads when selected URL inventory is sparse.
    for (_, url, _, _, compatibility, resolvable_payload, affordances, _, low_quality, _) in &ranked
    {
        if seen_hint_urls.contains(url) {
            continue;
        }
        if reject_search_hub && is_search_hub_url(url) {
            continue;
        }
        if affordances.is_empty() {
            continue;
        }
        if can_prune_headline_low_quality && *low_quality {
            continue;
        }
        if prefer_direct_reads
            && !affordances.contains(&RetrievalAffordanceKind::DirectCitationRead)
        {
            continue;
        }
        if must_require_compatibility
            && !compatibility_passes_projection(&projection, compatibility)
        {
            continue;
        }
        if (can_prune_by_locality || explicit_locality_scope) && !compatibility.locality_compatible
        {
            continue;
        }
        let domain_key = hints_by_url
            .get(url)
            .and_then(|hint| candidate_distinct_domain_key_from_excerpt(url, &hint.excerpt))
            .unwrap_or_else(|| url.trim().to_ascii_lowercase());
        let domain_floor_gap = seen_hint_domains.len() < distinct_domain_floor
            && !seen_hint_domains.contains(&domain_key);
        let include_hint = if must_require_compatibility {
            compatibility_passes_projection(&projection, compatibility)
                && (!time_sensitive_scope || *resolvable_payload || domain_floor_gap)
        } else {
            compatibility_passes_projection(&projection, compatibility)
                || compatibility.compatibility_score > 0
                || *resolvable_payload
                || domain_floor_gap
        };
        if !include_hint {
            continue;
        }
        if let Some(hint) = hints_by_url.get(url) {
            let trimmed = hint.url.trim();
            if !trimmed.is_empty() && seen_hint_urls.insert(trimmed.to_string()) {
                if let Some(hint_domain_key) =
                    candidate_distinct_domain_key_from_excerpt(trimmed, hint.excerpt.as_str())
                {
                    seen_hint_domains.insert(hint_domain_key);
                }
                candidate_source_hints.push(hint.clone());
            }
        }
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

pub(crate) fn pre_read_candidate_plan(
    query_contract: &str,
    min_sources: u32,
    candidate_urls: Vec<String>,
    candidate_source_hints: Vec<PendingSearchReadSummary>,
    locality_hint: Option<&str>,
    allow_floor_recovery_exploration: bool,
) -> PreReadCandidatePlan {
    pre_read_candidate_plan_with_contract(
        None,
        query_contract,
        min_sources,
        candidate_urls,
        candidate_source_hints,
        locality_hint,
        allow_floor_recovery_exploration,
    )
}

pub(crate) fn pre_read_candidate_plan_from_bundle_with_contract_and_locality_hint(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    min_sources: u32,
    bundle: &WebEvidenceBundle,
    locality_hint: Option<&str>,
) -> PreReadCandidatePlan {
    pre_read_candidate_plan_from_bundle_with_contract_and_locality_hint_and_recovery_mode(
        retrieval_contract,
        query_contract,
        min_sources,
        bundle,
        locality_hint,
        false,
    )
}

pub(crate) fn pre_read_candidate_plan_from_bundle_with_locality_hint(
    query_contract: &str,
    min_sources: u32,
    bundle: &WebEvidenceBundle,
    locality_hint: Option<&str>,
) -> PreReadCandidatePlan {
    pre_read_candidate_plan_from_bundle_with_contract_and_locality_hint(
        None,
        query_contract,
        min_sources,
        bundle,
        locality_hint,
    )
}

pub(crate) fn pre_read_candidate_plan_from_bundle_with_contract_and_locality_hint_and_recovery_mode(
    retrieval_contract: Option<&WebRetrievalContract>,
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
    pre_read_candidate_plan_with_contract(
        retrieval_contract,
        query_contract,
        min_sources,
        candidate_urls,
        candidate_source_hints,
        locality_hint,
        allow_floor_recovery_exploration,
    )
}

pub(crate) fn pre_read_candidate_plan_from_bundle_with_locality_hint_and_recovery_mode(
    query_contract: &str,
    min_sources: u32,
    bundle: &WebEvidenceBundle,
    locality_hint: Option<&str>,
    allow_floor_recovery_exploration: bool,
) -> PreReadCandidatePlan {
    pre_read_candidate_plan_from_bundle_with_contract_and_locality_hint_and_recovery_mode(
        None,
        query_contract,
        min_sources,
        bundle,
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
