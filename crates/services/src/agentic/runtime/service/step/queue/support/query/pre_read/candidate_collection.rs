pub(crate) fn resolved_hint_candidate_url(hint: &PendingSearchReadSummary) -> Option<String> {
    let trimmed = hint.url.trim();
    if trimmed.is_empty() {
        return None;
    }
    if projection_candidate_url_allowed(trimmed) {
        return Some(trimmed.to_string());
    }
    let candidate = source_url_from_metadata_excerpt(&hint.excerpt)?;
    projection_candidate_url_allowed(&candidate).then_some(candidate)
}

fn resolved_hint_candidate_url_with_projection(
    query_contract: &str,
    projection: &QueryConstraintProjection,
    hint: &PendingSearchReadSummary,
) -> Option<String> {
    let trimmed = hint.url.trim();
    let title = hint.title.as_deref().unwrap_or_default();
    let excerpt = hint.excerpt.as_str();
    if projection_candidate_url_allowed_with_projection(
        query_contract,
        projection,
        trimmed,
        title,
        excerpt,
    ) {
        return Some(trimmed.to_string());
    }
    let candidate = source_url_from_metadata_excerpt(excerpt)?;
    projection_candidate_url_allowed_with_projection(
        query_contract,
        projection,
        &candidate,
        title,
        excerpt,
    )
    .then_some(candidate)
}

fn resolved_hint_candidate_url_with_contract_and_affordance(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    projection: &QueryConstraintProjection,
    hint: &PendingSearchReadSummary,
) -> Option<String> {
    let trimmed = hint.url.trim();
    let title = hint.title.as_deref().unwrap_or_default();
    let excerpt = hint.excerpt.as_str();
    let affordances = retrieval_affordances_with_contract_and_locality_hint(
        retrieval_contract,
        query_contract,
        1,
        std::slice::from_ref(hint),
        projection.locality_scope.as_deref(),
        trimmed,
        title,
        excerpt,
    );
    if !affordances.is_empty() {
        return Some(trimmed.to_string());
    }

    let candidate = source_url_from_metadata_excerpt(excerpt)?;
    let affordances = retrieval_affordances_with_contract_and_locality_hint(
        retrieval_contract,
        query_contract,
        1,
        std::slice::from_ref(hint),
        projection.locality_scope.as_deref(),
        &candidate,
        title,
        excerpt,
    );
    (!affordances.is_empty()).then_some(candidate)
}

fn resolved_hint_candidate_url_with_affordance(
    query_contract: &str,
    projection: &QueryConstraintProjection,
    hint: &PendingSearchReadSummary,
) -> Option<String> {
    resolved_hint_candidate_url_with_contract_and_affordance(None, query_contract, projection, hint)
}

pub(crate) fn collect_projection_candidate_urls_with_contract_and_locality_hint(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    min_sources: u32,
    selected_urls: &[String],
    source_hints: &[PendingSearchReadSummary],
    target_count: usize,
    distinct_domain_floor: usize,
    blocked_domains: &BTreeSet<String>,
    locality_hint: Option<&str>,
) -> Vec<String> {
    #[derive(Clone)]
    struct CandidateRecord {
        url: String,
        title: String,
        excerpt: String,
        compatibility: CandidateConstraintCompatibility,
        affordances: Vec<RetrievalAffordanceKind>,
        low_priority: bool,
        headline_low_quality: bool,
        headline_actionable: bool,
        source_relevance_score: usize,
        original_idx: usize,
    }

    let projection = build_query_constraint_projection_with_locality_hint(
        query_contract,
        min_sources.max(1),
        source_hints,
        locality_hint,
    );
    let headline_lookup_mode =
        retrieval_contract_is_generic_headline_collection(retrieval_contract, query_contract);
    let mut ordered_candidates = Vec::<CandidateRecord>::new();
    let mut seen_urls = BTreeSet::new();
    let mut push_candidate = |candidate_url: &str, title: &str, excerpt: &str| {
        let trimmed = candidate_url.trim();
        let affordances = retrieval_affordances_with_contract_and_locality_hint(
            retrieval_contract,
            query_contract,
            min_sources.max(1),
            source_hints,
            locality_hint,
            trimmed,
            title,
            excerpt,
        );
        if affordances.is_empty() {
            return;
        }
        if source_has_human_challenge_signal(trimmed, title, excerpt) {
            return;
        }
        if canonical_domain_key(trimmed)
            .map(|domain| blocked_domains.contains(&domain))
            .unwrap_or(false)
        {
            return;
        }
        let dedup_key = trimmed.to_ascii_lowercase();
        if !seen_urls.insert(dedup_key) {
            return;
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
        let signals = analyze_source_record_signals(trimmed, title, excerpt);
        let headline_source = PendingSearchReadSummary {
            url: trimmed.to_string(),
            title: (!title.trim().is_empty()).then(|| title.trim().to_string()),
            excerpt: excerpt.trim().to_string(),
        };
        let headline_low_quality =
            headline_lookup_mode && headline_source_is_low_quality(trimmed, title, excerpt);
        let headline_actionable =
            headline_lookup_mode && headline_source_is_actionable(&headline_source);
        ordered_candidates.push(CandidateRecord {
            url: trimmed.to_string(),
            title: title.trim().to_string(),
            excerpt: excerpt.trim().to_string(),
            compatibility,
            affordances,
            low_priority: source_has_human_challenge_signal(trimmed, title, excerpt)
                || signals.low_priority_hits > 0
                || signals.low_priority_dominates(),
            headline_low_quality,
            headline_actionable,
            source_relevance_score: signals.relevance_score(false),
            original_idx: ordered_candidates.len(),
        });
    };

    for selected in selected_urls {
        let selected_trimmed = selected.trim();
        if selected_trimmed.is_empty() {
            continue;
        }
        let matched_hint = source_hint_for_url(source_hints, selected_trimmed).or_else(|| {
            source_hints.iter().find(|hint| {
                resolved_hint_candidate_url_with_contract_and_affordance(
                    retrieval_contract,
                    query_contract,
                    &projection,
                    hint,
                )
                .map(|resolved| {
                    resolved.eq_ignore_ascii_case(selected_trimmed)
                        || url_structurally_equivalent(&resolved, selected_trimmed)
                })
                .unwrap_or(false)
            })
        });
        let title = matched_hint
            .and_then(|hint| hint.title.as_deref())
            .unwrap_or_default();
        let excerpt = matched_hint
            .map(|hint| hint.excerpt.as_str())
            .unwrap_or_default();
        push_candidate(selected_trimmed, title, excerpt);
    }

    for hint in source_hints {
        let Some(candidate) = resolved_hint_candidate_url_with_contract_and_affordance(
            retrieval_contract,
            query_contract,
            &projection,
            hint,
        ) else {
            continue;
        };
        push_candidate(
            &candidate,
            hint.title.as_deref().unwrap_or_default(),
            &hint.excerpt,
        );
    }

    if headline_lookup_mode {
        ordered_candidates.sort_by(|left, right| {
            let right_direct = right
                .affordances
                .contains(&RetrievalAffordanceKind::DirectCitationRead);
            let left_direct = left
                .affordances
                .contains(&RetrievalAffordanceKind::DirectCitationRead);
            let right_passes = compatibility_passes_projection(&projection, &right.compatibility);
            let left_passes = compatibility_passes_projection(&projection, &left.compatibility);
            right
                .headline_actionable
                .cmp(&left.headline_actionable)
                .then_with(|| left.headline_low_quality.cmp(&right.headline_low_quality))
                .then_with(|| right_direct.cmp(&left_direct))
                .then_with(|| right_passes.cmp(&left_passes))
                .then_with(|| {
                    right
                        .compatibility
                        .compatibility_score
                        .cmp(&left.compatibility.compatibility_score)
                })
                .then_with(|| {
                    right
                        .source_relevance_score
                        .cmp(&left.source_relevance_score)
                })
                .then_with(|| right.affordances.len().cmp(&left.affordances.len()))
                .then_with(|| left.original_idx.cmp(&right.original_idx))
                .then_with(|| left.url.cmp(&right.url))
        });
    }

    let required_floor = distinct_domain_floor.max(1).min(target_count.max(1));
    let strict_grounded_retrieval = projection.enforce_grounded_compatibility();
    let strict_candidate_count = ordered_candidates
        .iter()
        .filter(|candidate| {
            compatibility_passes_projection(&projection, &candidate.compatibility)
                && !candidate.low_priority
        })
        .count();
    let headline_non_low_quality_count = ordered_candidates
        .iter()
        .filter(|candidate| {
            candidate
                .affordances
                .contains(&RetrievalAffordanceKind::DirectCitationRead)
                && !candidate.headline_low_quality
        })
        .count();
    let headline_actionable_count = ordered_candidates
        .iter()
        .filter(|candidate| {
            candidate
                .affordances
                .contains(&RetrievalAffordanceKind::DirectCitationRead)
                && candidate.headline_actionable
                && !candidate.headline_low_quality
        })
        .count();
    let headline_direct_candidate_count = ordered_candidates
        .iter()
        .filter(|candidate| {
            candidate
                .affordances
                .contains(&RetrievalAffordanceKind::DirectCitationRead)
        })
        .count();
    let compatible_candidate_count = ordered_candidates
        .iter()
        .filter(|candidate| compatibility_passes_projection(&projection, &candidate.compatibility))
        .count();

    let local_business_entity_diversity_flow =
        retrieval_contract_entity_diversity_required(retrieval_contract, query_contract);
    let preserve_local_business_seed = |candidate: &CandidateRecord| {
        local_business_entity_diversity_flow
            && !candidate.low_priority
            && candidate
                .affordances
                .contains(&RetrievalAffordanceKind::DiscoveryExpansionSeedRead)
    };
    let strict_quality_candidate = |candidate: &CandidateRecord| {
        compatibility_passes_projection(&projection, &candidate.compatibility) && !candidate.low_priority
    };
    let strict_or_seed_candidate =
        |candidate: &CandidateRecord| strict_quality_candidate(candidate) || preserve_local_business_seed(candidate);
    let compatible_or_seed_candidate = |candidate: &CandidateRecord| {
        compatibility_passes_projection(&projection, &candidate.compatibility)
            || preserve_local_business_seed(candidate)
    };

    let filtered_candidates = if headline_lookup_mode && headline_actionable_count >= required_floor
    {
        ordered_candidates
            .into_iter()
            .filter(|candidate| {
                candidate
                    .affordances
                    .contains(&RetrievalAffordanceKind::DirectCitationRead)
                    && candidate.headline_actionable
                    && !candidate.headline_low_quality
            })
            .collect::<Vec<_>>()
    } else if headline_lookup_mode && headline_non_low_quality_count >= required_floor {
        ordered_candidates
            .into_iter()
            .filter(|candidate| {
                candidate
                    .affordances
                    .contains(&RetrievalAffordanceKind::DirectCitationRead)
                    && !candidate.headline_low_quality
            })
            .collect::<Vec<_>>()
    } else if headline_lookup_mode && headline_direct_candidate_count > 0 {
        ordered_candidates
            .into_iter()
            .filter(|candidate| {
                candidate
                    .affordances
                    .contains(&RetrievalAffordanceKind::DirectCitationRead)
            })
            .collect::<Vec<_>>()
    } else if strict_grounded_retrieval && strict_candidate_count > 0 {
        ordered_candidates
            .into_iter()
            .filter(strict_or_seed_candidate)
            .collect::<Vec<_>>()
    } else if strict_candidate_count >= required_floor {
        ordered_candidates
            .into_iter()
            .filter(strict_or_seed_candidate)
            .collect::<Vec<_>>()
    } else if compatible_candidate_count > 0 && !strict_grounded_retrieval {
        ordered_candidates
            .into_iter()
            .filter(compatible_or_seed_candidate)
            .collect::<Vec<_>>()
    } else {
        ordered_candidates
    };

    let target = target_count.max(1);
    let domain_floor = distinct_domain_floor.min(target);
    let direct_candidate_count = filtered_candidates
        .iter()
        .filter(|candidate| {
            candidate
                .affordances
                .contains(&RetrievalAffordanceKind::DirectCitationRead)
        })
        .count();
    let direct_candidate_distinct_target_count = filtered_candidates
        .iter()
        .filter(|candidate| {
            candidate
                .affordances
                .contains(&RetrievalAffordanceKind::DirectCitationRead)
        })
        .filter_map(|candidate| {
            let source = PendingSearchReadSummary {
                url: candidate.url.clone(),
                title: (!candidate.title.trim().is_empty()).then(|| candidate.title.clone()),
                excerpt: candidate.excerpt.clone(),
            };
            local_business_target_name_from_source(&source, projection.locality_scope.as_deref())
        })
        .map(|target| target.to_ascii_lowercase())
        .collect::<BTreeSet<_>>()
        .len();
    let suppress_seed_only_candidates =
        if retrieval_contract_entity_diversity_required(retrieval_contract, query_contract) {
            direct_candidate_distinct_target_count >= required_floor
        } else {
            direct_candidate_count >= required_floor
        };
    let mut output = Vec::new();
    let mut seen_domains = BTreeSet::new();

    if domain_floor > 1 {
        for candidate in &filtered_candidates {
            if output.len() >= target || seen_domains.len() >= domain_floor {
                break;
            }
            if target > 1
                && candidate
                    .affordances
                    .contains(&RetrievalAffordanceKind::DiscoveryExpansionSeedRead)
                && !candidate
                    .affordances
                    .contains(&RetrievalAffordanceKind::DirectCitationRead)
                && suppress_seed_only_candidates
            {
                continue;
            }
            let domain_key =
                candidate_distinct_domain_key_from_excerpt(&candidate.url, &candidate.excerpt)
                    .unwrap_or_else(|| candidate.url.trim().to_ascii_lowercase());
            if !seen_domains.insert(domain_key) {
                continue;
            }
            output.push(candidate.url.clone());
        }
    }

    for candidate in &filtered_candidates {
        if output.len() >= target {
            break;
        }
        if output.iter().any(|existing| {
            existing.eq_ignore_ascii_case(candidate.url.as_str())
                || url_structurally_equivalent(existing, candidate.url.as_str())
        }) {
            continue;
        }
        if candidate.title.trim().is_empty()
            && candidate.excerpt.trim().is_empty()
            && compatible_candidate_count > 0
        {
            continue;
        }
        if target > 1
            && candidate
                .affordances
                .contains(&RetrievalAffordanceKind::DiscoveryExpansionSeedRead)
            && !candidate
                .affordances
                .contains(&RetrievalAffordanceKind::DirectCitationRead)
            && suppress_seed_only_candidates
        {
            continue;
        }
        output.push(candidate.url.clone());
    }

    output
}

pub(crate) fn collect_projection_candidate_urls_with_locality_hint(
    query_contract: &str,
    min_sources: u32,
    selected_urls: &[String],
    source_hints: &[PendingSearchReadSummary],
    target_count: usize,
    distinct_domain_floor: usize,
    blocked_domains: &BTreeSet<String>,
    locality_hint: Option<&str>,
) -> Vec<String> {
    collect_projection_candidate_urls_with_contract_and_locality_hint(
        None,
        query_contract,
        min_sources,
        selected_urls,
        source_hints,
        target_count,
        distinct_domain_floor,
        blocked_domains,
        locality_hint,
    )
}

#[cfg(test)]
mod candidate_collection_regression_tests {
    use super::*;

    fn restaurant_query_contract() -> String {
        "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus."
            .to_string()
    }

    #[test]
    fn retains_discovery_seed_when_direct_detail_candidates_do_not_cover_distinct_entities() {
        let query_contract = restaurant_query_contract();
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(&query_contract, None)
                .expect("retrieval contract");
        let source_hints = vec![
            PendingSearchReadSummary {
                url: "https://www.yelp.com/biz/dolce-vita-italian-bistro-and-pizzeria-anderson"
                    .to_string(),
                title: Some(
                    "Dolce Vita Italian Bistro and Pizzeria - Anderson, SC - Yelp".to_string(),
                ),
                excerpt: "Italian restaurant in Anderson, SC with pasta, pizza, and baked dishes."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.tripadvisor.com/Restaurant_Review-g30090-d15074041-Reviews-DolceVita_Italian_Bistro_Pizzeria-Anderson_South_Carolina.html".to_string(),
                title: Some(
                    "DolceVita Italian Bistro & Pizzeria - Tripadvisor".to_string(),
                ),
                excerpt:
                    "Italian restaurant in Anderson, South Carolina serving pizza and pasta."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://theredtomatorestaurant.com/".to_string(),
                title: Some("The Red Tomato and Wine Bar | Anderson, SC".to_string()),
                excerpt: "Italian dining in Anderson, SC with wine, pasta, and entrees."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.yelp.com/search?cflt=italian&find_loc=Anderson,+SC".to_string(),
                title: Some(
                    "Top 10 Best Italian Restaurants Near Anderson, South Carolina - Yelp"
                        .to_string(),
                ),
                excerpt:
                    "Best Italian in Anderson, SC: Dolce Vita Italian Bistro, The Red Tomato and Brothers Italian Cuisine."
                        .to_string(),
            },
        ];
        let candidate_urls = source_hints
            .iter()
            .map(|hint| hint.url.clone())
            .collect::<Vec<_>>();

        let output = collect_projection_candidate_urls_with_contract_and_locality_hint(
            Some(&retrieval_contract),
            &query_contract,
            3,
            &[],
            &source_hints,
            3,
            3,
            &BTreeSet::new(),
            Some("Anderson, SC"),
        );

        assert!(
            output.iter().any(|url| {
                url.eq_ignore_ascii_case(
                    "https://www.yelp.com/search?cflt=italian&find_loc=Anderson,+SC"
                )
            }),
            "{output:?}"
        );
        assert!(output.len() <= candidate_urls.len());
    }
}
