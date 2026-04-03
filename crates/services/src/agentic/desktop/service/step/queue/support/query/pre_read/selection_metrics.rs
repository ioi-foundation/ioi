#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SelectedSourceQualityObservation {
    pub(crate) total_sources: usize,
    pub(crate) compatible_sources: usize,
    pub(crate) locality_compatible_sources: usize,
    pub(crate) distinct_domains: usize,
    pub(crate) low_priority_sources: usize,
    pub(crate) quality_floor_met: bool,
    pub(crate) low_priority_urls: Vec<String>,
    pub(crate) entity_anchor_required: bool,
    pub(crate) entity_anchor_compatible_sources: usize,
    pub(crate) entity_anchor_floor_met: bool,
    pub(crate) entity_anchor_source_urls: Vec<String>,
    pub(crate) entity_anchor_mismatched_urls: Vec<String>,
    pub(crate) identifier_evidence_required: bool,
    pub(crate) identifier_bearing_sources: usize,
    pub(crate) authority_identifier_sources: usize,
    pub(crate) required_identifier_label_coverage: usize,
    pub(crate) optional_identifier_label_coverage: usize,
    pub(crate) required_identifier_group_floor: usize,
    pub(crate) identifier_coverage_floor_met: bool,
    pub(crate) missing_identifier_urls: Vec<String>,
}

pub(crate) fn selected_source_quality_observation_with_contract_and_locality_hint(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    min_sources: u32,
    selected_urls: &[String],
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
) -> SelectedSourceQualityObservation {
    let projection = build_query_constraint_projection_with_locality_hint(
        query_contract,
        min_sources.max(1),
        source_hints,
        locality_hint,
    );
    let headline_lookup_mode =
        retrieval_contract_is_generic_headline_collection(retrieval_contract, query_contract);
    let required_source_count = min_sources.max(1) as usize;
    let briefing_identifier_observations = source_hints
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
    let required_identifier_labels = infer_briefing_required_identifier_labels(
        query_contract,
        &briefing_identifier_observations,
    );
    let required_identifier_group_floor = required_identifier_labels.len();
    let optional_identifier_labels = BTreeSet::<String>::new();
    let identifier_evidence_required = !required_identifier_labels.is_empty()
        && retrieval_contract
            .is_some_and(|_| query_prefers_document_briefing_layout(query_contract));
    let local_business_entity_selection_flow =
        query_requires_local_business_entity_diversity(query_contract);
    let local_business_menu_surface_required = query_requires_local_business_menu_surface(
        query_contract,
        retrieval_contract,
        locality_hint,
    );
    let entity_anchor_required = !local_business_search_entity_anchor_tokens_with_contract(
        query_contract,
        retrieval_contract,
        locality_hint,
    )
    .is_empty();
    let mut total_sources = 0usize;
    let mut compatible_sources = 0usize;
    let mut locality_compatible_sources = 0usize;
    let mut low_priority_sources = 0usize;
    let mut distinct_domains = BTreeSet::new();
    let mut low_priority_urls = Vec::new();
    let mut entity_anchor_compatible_sources = 0usize;
    let mut entity_anchor_source_urls = Vec::new();
    let mut entity_anchor_mismatched_urls = Vec::new();
    let mut seen_urls = BTreeSet::new();
    let mut identifier_bearing_sources = 0usize;
    let mut authority_identifier_sources = 0usize;
    let mut authoritative_source_families = BTreeSet::new();
    let mut required_identifier_coverage = BTreeSet::new();
    let mut optional_identifier_coverage = BTreeSet::new();
    let mut missing_identifier_urls = Vec::new();
    let mut authority_backed_compatible_sources = 0usize;

    for selected in selected_urls {
        let selected_trimmed = selected.trim();
        if selected_trimmed.is_empty() {
            continue;
        }
        let dedup_key = selected_trimmed.to_ascii_lowercase();
        if !seen_urls.insert(dedup_key) {
            continue;
        }

        let (title, excerpt) = source_hint_for_url(source_hints, selected_trimmed)
            .map(|hint| {
                (
                    hint.title.as_deref().unwrap_or_default(),
                    hint.excerpt.as_str(),
                )
            })
            .unwrap_or(("", ""));
        total_sources = total_sources.saturating_add(1);
        if let Some(domain) = candidate_distinct_domain_key_from_excerpt(selected_trimmed, excerpt)
        {
            distinct_domains.insert(domain);
        }
        let selected_source_summary = PendingSearchReadSummary {
            url: selected_trimmed.to_string(),
            title: (!title.trim().is_empty()).then(|| title.trim().to_string()),
            excerpt: excerpt.trim().to_string(),
        };
        let entity_anchor_compatible = if !entity_anchor_required {
            true
        } else if local_business_entity_selection_flow {
            local_business_target_name_from_source(&selected_source_summary, locality_hint)
                .is_some()
        } else {
            source_matches_local_business_search_entity_anchor(
                query_contract,
                retrieval_contract,
                locality_hint,
                selected_trimmed,
                title,
                excerpt,
            )
        };
        if entity_anchor_compatible {
            entity_anchor_compatible_sources = entity_anchor_compatible_sources.saturating_add(1);
            entity_anchor_source_urls.push(selected_trimmed.to_string());
        } else {
            entity_anchor_mismatched_urls.push(selected_trimmed.to_string());
        }

        let identifier_labels = source_briefing_standard_identifier_labels(
            query_contract,
            selected_trimmed,
            title,
            excerpt,
        );
        let identifier_bearing = !identifier_labels.is_empty();
        let authoritative =
            source_has_document_authority(query_contract, selected_trimmed, title, excerpt);
        if authoritative {
            authoritative_source_families.insert(
                source_document_authority_family_key(
                    query_contract,
                    selected_trimmed,
                    title,
                    excerpt,
                )
                .unwrap_or_else(|| selected_trimmed.to_ascii_lowercase()),
            );
        }
        if identifier_bearing {
            identifier_bearing_sources = identifier_bearing_sources.saturating_add(1);
            if authoritative {
                authority_identifier_sources = authority_identifier_sources.saturating_add(1);
            }
            required_identifier_coverage.extend(
                identifier_labels
                    .iter()
                    .filter(|label| required_identifier_labels.contains(*label))
                    .cloned(),
            );
            optional_identifier_coverage.extend(
                identifier_labels
                    .iter()
                    .filter(|label| optional_identifier_labels.contains(*label))
                    .cloned(),
            );
        } else if identifier_evidence_required {
            missing_identifier_urls.push(selected_trimmed.to_string());
        }

        let admissible_for_document_briefing =
            !identifier_evidence_required || identifier_bearing || authoritative;
        let compatibility = if headline_lookup_mode {
            None
        } else {
            Some(candidate_constraint_compatibility(
                &projection.constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                selected_trimmed,
                title,
                excerpt,
            ))
        };
        let local_business_entity_compatible = admissible_for_document_briefing
            && entity_anchor_compatible
            && (!local_business_menu_surface_required
                || local_business_menu_surface_url(selected_trimmed));
        let local_business_locality_compatible = !projection.locality_scope.is_some()
            || compatibility
                .as_ref()
                .map(|value| value.locality_compatible)
                .unwrap_or(true);
        if headline_lookup_mode {
            let headline_source = PendingSearchReadSummary {
                url: selected_trimmed.to_string(),
                title: (!title.trim().is_empty()).then(|| title.trim().to_string()),
                excerpt: excerpt.trim().to_string(),
            };
            if headline_source_is_actionable(&headline_source)
                && admissible_for_document_briefing
                && entity_anchor_compatible
            {
                compatible_sources = compatible_sources.saturating_add(1);
            }
            if admissible_for_document_briefing && entity_anchor_compatible {
                locality_compatible_sources = locality_compatible_sources.saturating_add(1);
            }
        } else if local_business_entity_selection_flow {
            if local_business_entity_compatible {
                compatible_sources = compatible_sources.saturating_add(1);
            }
            if local_business_entity_compatible && local_business_locality_compatible {
                locality_compatible_sources = locality_compatible_sources.saturating_add(1);
            }
        } else {
            let compatibility = compatibility.expect("non-headline compatibility");
            let authority_aligned = source_has_document_briefing_authority_alignment_with_contract(
                retrieval_contract,
                query_contract,
                required_source_count,
                selected_trimmed,
                title,
                excerpt,
            );
            let grounded_external_publication_support =
                source_is_grounded_external_publication_support_artifact(
                    retrieval_contract,
                    query_contract,
                    selected_trimmed,
                    title,
                    excerpt,
                );
            let quality_compatible = (compatibility_passes_projection(&projection, &compatibility)
                || authority_aligned
                || grounded_external_publication_support)
                && admissible_for_document_briefing
                && entity_anchor_compatible;
            if quality_compatible {
                compatible_sources = compatible_sources.saturating_add(1);
            }
            if quality_compatible && (authority_aligned || authoritative) {
                authority_backed_compatible_sources =
                    authority_backed_compatible_sources.saturating_add(1);
            }
            if compatibility.locality_compatible
                && admissible_for_document_briefing
                && entity_anchor_compatible
            {
                locality_compatible_sources = locality_compatible_sources.saturating_add(1);
            }
        }

        let signals = analyze_source_record_signals(selected_trimmed, title, excerpt);
        if source_has_human_challenge_signal(selected_trimmed, title, excerpt)
            || signals.low_priority_hits > 0
            || signals.low_priority_dominates()
        {
            low_priority_sources = low_priority_sources.saturating_add(1);
            low_priority_urls.push(selected_trimmed.to_string());
        }
    }

    let required_domain_floor =
        retrieval_contract_required_distinct_domain_floor(retrieval_contract, query_contract)
            .min(required_source_count)
            .max(usize::from(required_source_count > 1));
    let locality_floor_met = !projection.locality_scope.is_some()
        || locality_compatible_sources >= required_source_count;
    let distinct_domain_floor_met =
        required_domain_floor == 0 || distinct_domains.len() >= required_domain_floor;
    let entity_anchor_floor_met =
        !entity_anchor_required || entity_anchor_compatible_sources >= required_source_count;
    let local_business_same_authority_override = local_business_entity_selection_flow
        && entity_anchor_floor_met
        && (!local_business_menu_surface_required || compatible_sources >= required_source_count);
    let distinct_domain_floor_met =
        distinct_domain_floor_met || local_business_same_authority_override;
    let identifier_coverage_floor_met = !identifier_evidence_required
        || (identifier_bearing_sources >= required_source_count
            && required_identifier_coverage.len() >= required_identifier_group_floor);
    let grounded_document_briefing_support_mode =
        query_prefers_document_briefing_layout(query_contract)
            && !query_requests_comparison(query_contract)
            && analyze_query_facets(query_contract).grounded_external_required
            && retrieval_contract
                .map(|contract| {
                    contract.currentness_required || contract.source_independence_min > 1
                })
                .unwrap_or(false);
    let quality_floor_met = total_sources >= required_source_count
        && compatible_sources >= required_source_count
        && locality_floor_met
        && distinct_domain_floor_met
        && low_priority_sources == 0
        && entity_anchor_floor_met
        && (!grounded_document_briefing_support_mode || authority_backed_compatible_sources > 0)
        && identifier_coverage_floor_met;

    SelectedSourceQualityObservation {
        total_sources,
        compatible_sources,
        locality_compatible_sources,
        distinct_domains: distinct_domains.len(),
        low_priority_sources,
        quality_floor_met,
        low_priority_urls,
        entity_anchor_required,
        entity_anchor_compatible_sources,
        entity_anchor_floor_met,
        entity_anchor_source_urls,
        entity_anchor_mismatched_urls,
        identifier_evidence_required,
        identifier_bearing_sources,
        authority_identifier_sources,
        required_identifier_label_coverage: required_identifier_coverage.len(),
        optional_identifier_label_coverage: optional_identifier_coverage.len(),
        required_identifier_group_floor,
        identifier_coverage_floor_met,
        missing_identifier_urls,
    }
}

pub(crate) fn selected_source_quality_metrics_with_contract_and_locality_hint(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    min_sources: u32,
    selected_urls: &[String],
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
) -> (usize, usize, usize, usize, usize, bool, Vec<String>) {
    let observation = selected_source_quality_observation_with_contract_and_locality_hint(
        retrieval_contract,
        query_contract,
        min_sources,
        selected_urls,
        source_hints,
        locality_hint,
    );
    (
        observation.total_sources,
        observation.compatible_sources,
        observation.locality_compatible_sources,
        observation.distinct_domains,
        observation.low_priority_sources,
        observation.quality_floor_met,
        observation.low_priority_urls,
    )
}

pub(crate) fn selected_source_quality_metrics_with_locality_hint(
    query_contract: &str,
    min_sources: u32,
    selected_urls: &[String],
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
) -> (usize, usize, usize, usize, usize, bool, Vec<String>) {
    selected_source_quality_metrics_with_contract_and_locality_hint(
        None,
        query_contract,
        min_sources,
        selected_urls,
        source_hints,
        locality_hint,
    )
}

#[cfg(test)]
#[path = "selection_metrics/tests.rs"]
mod selection_metrics_tests;
