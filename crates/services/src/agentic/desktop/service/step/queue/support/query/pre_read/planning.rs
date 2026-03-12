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
    let document_briefing_layout = query_prefers_document_briefing_layout(query_contract)
        && !query_requests_comparison(query_contract);
    let authority_source_required_for_briefing = document_briefing_layout
        && analyze_query_facets(query_contract).grounded_external_required
        && retrieval_contract
            .map(|contract| contract.currentness_required || contract.source_independence_min > 1)
            .unwrap_or(false);
    let probe_source_hints = candidate_source_hints.clone();
    let constraints = &projection.constraints;
    let policy = ResolutionPolicy::default();
    let required_briefing_identifier_labels =
        briefing_standard_identifier_groups_for_query(query_contract)
            .iter()
            .filter(|group| group.required)
            .map(|group| group.primary_label.to_string())
            .collect::<BTreeSet<_>>();
    let optional_briefing_identifier_labels =
        briefing_standard_identifier_groups_for_query(query_contract)
            .iter()
            .filter(|group| !group.required)
            .map(|group| group.primary_label.to_string())
            .collect::<BTreeSet<_>>();
    let hints_by_url = candidate_source_hints
        .iter()
        .filter_map(|hint| {
            let trimmed = hint.url.trim();
            (!trimmed.is_empty()).then(|| (trimmed.to_string(), hint.clone()))
        })
        .collect::<BTreeMap<_, _>>();

    #[derive(Clone)]
    struct RankedCandidate {
        idx: usize,
        url: String,
        score: CandidateEvidenceScore,
        scoreable: bool,
        compatibility: CandidateConstraintCompatibility,
        resolvable_payload: bool,
        affordances: Vec<RetrievalAffordanceKind>,
        listing_disallowed: bool,
        headline_low_quality: bool,
        headline_actionable: bool,
        source_relevance_score: usize,
        official_status_host_hits: usize,
        primary_status_surface_hits: usize,
        document_authority_score: usize,
        observed_identifier_label_count: usize,
        optional_identifier_label_count: usize,
        required_identifier_labels: BTreeSet<String>,
        query_grounding_signal: bool,
        intermediary_wrapper: bool,
    }

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
            let source_signals =
                crate::agentic::desktop::service::step::signals::analyze_source_record_signals(
                    trimmed, title, excerpt,
                );
            let document_authority_score =
                crate::agentic::desktop::service::step::queue::support::source_document_authority_score(
                    query_contract,
                    trimmed,
                    title,
                    excerpt,
                );
            let observed_identifier_labels = observed_briefing_standard_identifier_labels(
                query_contract,
                &format!("{trimmed} {title} {excerpt}"),
            )
            .into_iter()
            .collect::<BTreeSet<_>>();
            let required_identifier_labels = observed_identifier_labels
                .iter()
                .filter(|label| required_briefing_identifier_labels.contains(*label))
                .cloned()
                .collect::<BTreeSet<_>>();
            let optional_identifier_label_count = observed_identifier_labels
                .iter()
                .filter(|label| optional_briefing_identifier_labels.contains(*label))
                .count();
            let query_grounding_signal =
                crate::agentic::desktop::service::step::queue::support::excerpt_has_query_grounding_signal_with_contract(
                    retrieval_contract,
                    query_contract,
                    min_sources as usize,
                    trimmed,
                    title,
                    excerpt,
                );
            RankedCandidate {
                idx,
                url: trimmed.to_string(),
                score,
                scoreable,
                compatibility,
                resolvable_payload,
                affordances,
                listing_disallowed,
                headline_low_quality,
                headline_actionable,
                source_relevance_score: source_signals.relevance_score(false),
                official_status_host_hits: source_signals.official_status_host_hits,
                primary_status_surface_hits: source_signals.primary_status_surface_hits,
                document_authority_score,
                observed_identifier_label_count: observed_identifier_labels.len(),
                optional_identifier_label_count,
                required_identifier_labels,
                query_grounding_signal,
                intermediary_wrapper: crate::agentic::web::is_google_news_article_wrapper_url(
                    trimmed,
                ),
            }
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        let right_passes = !right.affordances.is_empty()
            && compatibility_passes_projection(&projection, &right.compatibility);
        let left_passes = !left.affordances.is_empty()
            && compatibility_passes_projection(&projection, &left.compatibility);
        let base_order = right
            .headline_actionable
            .cmp(&left.headline_actionable)
            .then_with(|| right.headline_low_quality.cmp(&left.headline_low_quality));
        let briefing_order = if document_briefing_layout {
            left.intermediary_wrapper
                .cmp(&right.intermediary_wrapper)
                .then_with(|| right_passes.cmp(&left_passes))
                .then_with(|| {
                    (right.document_authority_score > 0).cmp(&(left.document_authority_score > 0))
                })
                .then_with(|| {
                    right
                        .document_authority_score
                        .cmp(&left.document_authority_score)
                })
                .then_with(|| {
                    right
                        .optional_identifier_label_count
                        .cmp(&left.optional_identifier_label_count)
                })
                .then_with(|| {
                    right
                        .observed_identifier_label_count
                        .cmp(&left.observed_identifier_label_count)
                })
                .then_with(|| {
                    right
                        .required_identifier_labels
                        .len()
                        .cmp(&left.required_identifier_labels.len())
                })
                .then_with(|| {
                    right
                        .query_grounding_signal
                        .cmp(&left.query_grounding_signal)
                })
                .then_with(|| {
                    (right.official_status_host_hits > 0).cmp(&(left.official_status_host_hits > 0))
                })
                .then_with(|| {
                    right
                        .official_status_host_hits
                        .cmp(&left.official_status_host_hits)
                })
                .then_with(|| {
                    (right.primary_status_surface_hits > 0)
                        .cmp(&(left.primary_status_surface_hits > 0))
                })
                .then_with(|| {
                    right
                        .primary_status_surface_hits
                        .cmp(&left.primary_status_surface_hits)
                })
                .then_with(|| {
                    right
                        .source_relevance_score
                        .cmp(&left.source_relevance_score)
                })
        } else {
            std::cmp::Ordering::Equal
        };
        base_order
            .then_with(|| briefing_order)
            .then_with(|| right.resolvable_payload.cmp(&left.resolvable_payload))
            .then_with(|| right_passes.cmp(&left_passes))
            .then_with(|| {
                right
                    .compatibility
                    .compatibility_score
                    .cmp(&left.compatibility.compatibility_score)
            })
            .then_with(|| right.affordances.len().cmp(&left.affordances.len()))
            .then_with(|| compare_candidate_evidence_scores_desc(&left.score, &right.score))
            .then_with(|| {
                right
                    .compatibility
                    .is_compatible
                    .cmp(&left.compatibility.is_compatible)
            })
            .then_with(|| right.scoreable.cmp(&left.scoreable))
            .then_with(|| left.idx.cmp(&right.idx))
            .then_with(|| left.url.cmp(&right.url))
    });

    let min_required = min_sources.max(1) as usize;
    let resolvable_candidates = ranked
        .iter()
        .filter(|candidate| {
            !candidate.affordances.is_empty()
                && envelope_score_resolves_constraint(constraints, &candidate.score)
        })
        .count();
    let scoreable_candidates = ranked
        .iter()
        .filter(|candidate| candidate.scoreable && !candidate.affordances.is_empty())
        .count();
    let compatible_candidates = ranked
        .iter()
        .filter(|candidate| {
            !candidate.affordances.is_empty()
                && compatibility_passes_projection(&projection, &candidate.compatibility)
        })
        .count();
    let positive_compatibility_candidates = ranked
        .iter()
        .filter(|candidate| {
            !candidate.affordances.is_empty()
                && compatibility_passes_projection(&projection, &candidate.compatibility)
                && candidate.compatibility.compatibility_score > 0
        })
        .count();
    let direct_read_candidates = ranked
        .iter()
        .filter(|candidate| {
            candidate
                .affordances
                .contains(&RetrievalAffordanceKind::DirectCitationRead)
        })
        .count();
    let headline_actionable_candidates = ranked
        .iter()
        .filter(|candidate| !candidate.affordances.is_empty() && candidate.headline_actionable)
        .count();
    let headline_non_low_quality_candidates = ranked
        .iter()
        .filter(|candidate| !candidate.affordances.is_empty() && !candidate.headline_low_quality)
        .count();
    let locality_compatible_candidates = ranked
        .iter()
        .filter(|candidate| {
            !candidate.affordances.is_empty() && candidate.compatibility.locality_compatible
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
    let authority_candidate_for_briefing = |candidate: &RankedCandidate| {
        authority_source_required_for_briefing
            && candidate
                .affordances
                .contains(&RetrievalAffordanceKind::DirectCitationRead)
            && !candidate.listing_disallowed
            && candidate.document_authority_score > 0
            && (candidate.query_grounding_signal
                || candidate.compatibility.compatibility_score > 0
                || candidate.compatibility.is_compatible)
    };
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
        .filter_map(|candidate| {
            if reject_search_hub && is_search_hub_url(&candidate.url) {
                return None;
            }
            if candidate.affordances.is_empty() {
                return None;
            }
            if can_prune_headline_low_quality && candidate.headline_low_quality {
                return None;
            }
            if prefer_direct_reads
                && !candidate
                    .affordances
                    .contains(&RetrievalAffordanceKind::DirectCitationRead)
            {
                return None;
            }
            if can_prune
                && !envelope_score_resolves_constraint(constraints, &candidate.score)
                && !authority_candidate_for_briefing(candidate)
            {
                return None;
            }
            if must_require_compatibility
                && !compatibility_passes_projection(&projection, &candidate.compatibility)
                && !authority_candidate_for_briefing(candidate)
            {
                return None;
            }
            if can_prune_by_compatibility
                && !compatibility_passes_projection(&projection, &candidate.compatibility)
                && !authority_candidate_for_briefing(candidate)
            {
                return None;
            }
            if (can_prune_by_locality || explicit_locality_scope)
                && !candidate.compatibility.locality_compatible
                && !authority_candidate_for_briefing(candidate)
            {
                return None;
            }
            if can_prune_by_positive_compatibility
                && candidate.compatibility.compatibility_score == 0
                && !authority_candidate_for_briefing(candidate)
            {
                return None;
            }
            Some(candidate.url.to_string())
        })
        .collect::<Vec<_>>();
    if candidate_urls.is_empty() && projection.locality_scope_inferred {
        let fallback_limit = min_required
            .min(INFERRED_SCOPE_FALLBACK_CANDIDATE_COUNT)
            .max(1);
        let positive_fallback = ranked
            .iter()
            .filter(|candidate| {
                !candidate.affordances.is_empty()
                    && compatibility_passes_projection(&projection, &candidate.compatibility)
                    && candidate.compatibility.compatibility_score > 0
            })
            .filter(|candidate| {
                !prefer_direct_reads
                    || candidate
                        .affordances
                        .contains(&RetrievalAffordanceKind::DirectCitationRead)
            })
            .take(fallback_limit)
            .map(|candidate| candidate.url.to_string())
            .collect::<Vec<_>>();
        candidate_urls = positive_fallback;
    }
    if candidate_urls.len() < min_required && has_constraint_objective && scoreable_candidates > 0 {
        let candidate_count_before_top_up = candidate_urls.len();
        let mut seen_candidate_urls = candidate_urls
            .iter()
            .map(|url| url.trim().to_string())
            .collect::<BTreeSet<_>>();
        for candidate in ranked.iter() {
            if candidate_urls.len() >= min_required {
                break;
            }
            if seen_candidate_urls.contains(&candidate.url) || is_search_hub_url(&candidate.url) {
                continue;
            }
            if candidate.affordances.is_empty() {
                continue;
            }
            if prefer_direct_reads
                && !candidate
                    .affordances
                    .contains(&RetrievalAffordanceKind::DirectCitationRead)
            {
                continue;
            }
            if !candidate.compatibility.locality_compatible {
                continue;
            }
            let compatibility_relevant = if must_require_compatibility {
                compatibility_passes_projection(&projection, &candidate.compatibility)
                    || authority_candidate_for_briefing(candidate)
            } else {
                candidate.compatibility.compatibility_score > 0
                    || compatibility_passes_projection(&projection, &candidate.compatibility)
                    || authority_candidate_for_briefing(candidate)
                    || (allow_floor_recovery_exploration && compatible_candidates == 0)
            };
            if !compatibility_relevant {
                continue;
            }
            let payload_relevant = if must_require_compatibility && time_sensitive_scope {
                candidate.resolvable_payload || authority_candidate_for_briefing(candidate)
            } else {
                headline_lookup_mode
                    || !time_sensitive_scope
                    || candidate.resolvable_payload
                    || authority_candidate_for_briefing(candidate)
                    || candidate_urls.len() < min_required
                    || (allow_floor_recovery_exploration && compatible_candidates == 0)
            };
            if !payload_relevant {
                continue;
            }
            if seen_candidate_urls.insert(candidate.url.to_string()) {
                candidate_urls.push(candidate.url.to_string());
            }
        }
        if candidate_urls.len() > candidate_count_before_top_up {
            requires_constraint_search_probe = true;
        }
    }
    if authority_source_required_for_briefing {
        let authority_candidate = ranked
            .iter()
            .find(|candidate| authority_candidate_for_briefing(candidate));
        if let Some(authority_candidate) = authority_candidate {
            if let Some(existing_idx) = candidate_urls
                .iter()
                .position(|url| url.eq_ignore_ascii_case(authority_candidate.url.as_str()))
            {
                let authority_url = candidate_urls.remove(existing_idx);
                candidate_urls.insert(0, authority_url);
            } else {
                candidate_urls.insert(0, authority_candidate.url.clone());
            }
        }
    }
    let distinct_domain_floor =
        retrieval_contract_required_distinct_domain_floor(retrieval_contract, query_contract);
    if distinct_domain_floor > 1 && !candidate_urls.is_empty() {
        let ranked_by_url = ranked
            .iter()
            .map(|candidate| (candidate.url.to_ascii_lowercase(), candidate))
            .collect::<BTreeMap<_, _>>();
        let mut seen_domains = BTreeSet::new();
        let mut seen_required_identifier_labels = BTreeSet::new();
        let mut distinct_domain_urls = Vec::new();
        for url in &candidate_urls {
            let trimmed = url.trim();
            if trimmed.is_empty() {
                continue;
            }
            let candidate = ranked_by_url.get(&trimmed.to_ascii_lowercase());
            let domain_key = hints_by_url
                .get(url)
                .and_then(|hint| {
                    candidate_distinct_domain_key_from_excerpt(trimmed, hint.excerpt.as_str())
                })
                .unwrap_or_else(|| trimmed.to_ascii_lowercase());
            let adds_required_identifier_coverage = candidate.is_some_and(|candidate| {
                candidate.document_authority_score > 0
                    && candidate
                        .required_identifier_labels
                        .iter()
                        .any(|label| !seen_required_identifier_labels.contains(label))
            });
            if seen_domains.insert(domain_key) || adds_required_identifier_coverage {
                distinct_domain_urls.push(trimmed.to_string());
                if let Some(candidate) = candidate {
                    seen_required_identifier_labels
                        .extend(candidate.required_identifier_labels.iter().cloned());
                }
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
    for candidate in &ranked {
        if seen_hint_urls.contains(&candidate.url) {
            continue;
        }
        if reject_search_hub && is_search_hub_url(&candidate.url) {
            continue;
        }
        if candidate.affordances.is_empty() {
            continue;
        }
        if can_prune_headline_low_quality && candidate.headline_low_quality {
            continue;
        }
        if prefer_direct_reads
            && !candidate
                .affordances
                .contains(&RetrievalAffordanceKind::DirectCitationRead)
        {
            continue;
        }
        if must_require_compatibility
            && !compatibility_passes_projection(&projection, &candidate.compatibility)
        {
            continue;
        }
        if (can_prune_by_locality || explicit_locality_scope)
            && !candidate.compatibility.locality_compatible
        {
            continue;
        }
        let domain_key = hints_by_url
            .get(&candidate.url)
            .and_then(|hint| {
                candidate_distinct_domain_key_from_excerpt(&candidate.url, &hint.excerpt)
            })
            .unwrap_or_else(|| candidate.url.trim().to_ascii_lowercase());
        let domain_floor_gap = seen_hint_domains.len() < distinct_domain_floor
            && !seen_hint_domains.contains(&domain_key);
        let include_hint = if must_require_compatibility {
            compatibility_passes_projection(&projection, &candidate.compatibility)
                && (!time_sensitive_scope || candidate.resolvable_payload || domain_floor_gap)
        } else {
            compatibility_passes_projection(&projection, &candidate.compatibility)
                || candidate.compatibility.compatibility_score > 0
                || candidate.resolvable_payload
                || domain_floor_gap
        };
        if !include_hint {
            continue;
        }
        if let Some(hint) = hints_by_url.get(&candidate.url) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_briefing_plan_preserves_authority_candidate_while_enforcing_domain_diversity() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).ok();
        let nist_hqc_url =
            "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption";
        let nist_2024_url =
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards";
        let terra_url =
            "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/";

        let plan = pre_read_candidate_plan_with_contract(
            retrieval_contract.as_ref(),
            query,
            2,
            vec![
                nist_hqc_url.to_string(),
                nist_2024_url.to_string(),
                terra_url.to_string(),
            ],
            vec![
                PendingSearchReadSummary {
                    url: nist_hqc_url.to_string(),
                    title: Some(
                        "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption"
                            .to_string(),
                    ),
                    excerpt: "The other two finished standards, FIPS 204 and FIPS 205, contain digital signature algorithms."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: nist_2024_url.to_string(),
                    title: Some(
                        "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                            .to_string(),
                    ),
                    excerpt: "The finalized standards include FIPS 203 and ML-KEM.".to_string(),
                },
                PendingSearchReadSummary {
                    url: terra_url.to_string(),
                    title: Some("Diving Into NIST’s New Post-Quantum Standards".to_string()),
                    excerpt: "NIST has released FIPS 203, FIPS 204, and FIPS 205.".to_string(),
                },
            ],
            None,
            false,
        );

        assert_eq!(plan.candidate_urls.len(), 2, "{:?}", plan.candidate_urls);
        assert!(plan
            .candidate_urls
            .iter()
            .any(|url| url.contains("://www.nist.gov/")));
        assert!(plan
            .candidate_urls
            .iter()
            .any(|url| url.eq_ignore_ascii_case(terra_url)));
    }

    #[test]
    fn document_briefing_plan_prioritizes_current_authority_documents() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).ok();
        let nist_hqc_url =
            "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption";
        let nist_2024_url =
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards";

        let plan = pre_read_candidate_plan_with_contract(
            retrieval_contract.as_ref(),
            query,
            2,
            vec![nist_2024_url.to_string(), nist_hqc_url.to_string()],
            vec![
                PendingSearchReadSummary {
                    url: nist_2024_url.to_string(),
                    title: Some(
                        "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                            .to_string(),
                    ),
                    excerpt:
                        "NIST finalized FIPS 203, FIPS 204, and FIPS 205 for post-quantum cryptography."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: nist_hqc_url.to_string(),
                    title: Some(
                        "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption"
                            .to_string(),
                    ),
                    excerpt:
                        "NIST selected HQC in 2025 after finalizing FIPS 203, FIPS 204, and FIPS 205."
                            .to_string(),
                },
            ],
            None,
            false,
        );

        assert_eq!(
            plan.candidate_urls.first().map(String::as_str),
            Some(nist_hqc_url)
        );
    }

    #[test]
    fn document_briefing_plan_demotes_generic_authority_pages_without_query_grounding() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).ok();
        let nist_hqc_url =
            "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption";
        let nist_2024_url =
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards";
        let nist_cyber_url = "https://www.nist.gov/cybersecurity-and-privacy";
        let nist_webbook_url = "https://webbook.nist.gov/chemistry/";

        let plan = pre_read_candidate_plan_with_contract(
            retrieval_contract.as_ref(),
            query,
            2,
            vec![
                nist_cyber_url.to_string(),
                nist_webbook_url.to_string(),
                nist_hqc_url.to_string(),
                nist_2024_url.to_string(),
            ],
            vec![
                PendingSearchReadSummary {
                    url: nist_cyber_url.to_string(),
                    title: Some("Cybersecurity and Privacy | NIST".to_string()),
                    excerpt: "NIST advances standards, measurement science, and cybersecurity guidance."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: nist_webbook_url.to_string(),
                    title: Some("NIST Chemistry WebBook".to_string()),
                    excerpt: "Reference data and chemistry resources from NIST.".to_string(),
                },
                PendingSearchReadSummary {
                    url: nist_hqc_url.to_string(),
                    title: Some(
                        "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption"
                            .to_string(),
                    ),
                    excerpt:
                        "NIST selected HQC after finalizing FIPS 203, FIPS 204, and FIPS 205."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: nist_2024_url.to_string(),
                    title: Some(
                        "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                            .to_string(),
                    ),
                    excerpt:
                        "NIST finalized FIPS 203, FIPS 204, and FIPS 205 for post-quantum cryptography."
                            .to_string(),
                },
            ],
            None,
            false,
        );

        assert_eq!(
            plan.candidate_urls.iter().take(2).cloned().collect::<Vec<_>>(),
            vec![nist_hqc_url.to_string(), nist_2024_url.to_string()]
        );
    }

    #[test]
    fn document_briefing_plan_does_not_append_static_authority_seed_urls() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).ok();
        let external_url =
            "https://www.securityweek.com/nist-announces-hqc-as-fifth-standardized-post-quantum-algorithm/";

        let plan = pre_read_candidate_plan_with_contract(
            retrieval_contract.as_ref(),
            query,
            2,
            vec![external_url.to_string()],
            vec![PendingSearchReadSummary {
                url: external_url.to_string(),
                title: Some(
                    "NIST Announces HQC as Fifth Standardized Post-Quantum Algorithm"
                        .to_string(),
                ),
                excerpt:
                    "NIST selected HQC after releasing FIPS 203, FIPS 204, and FIPS 205."
                        .to_string(),
            }],
            None,
            false,
        );

        assert_eq!(plan.candidate_urls, vec![external_url.to_string()]);
    }
}
