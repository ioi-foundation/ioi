pub(crate) fn selected_source_quality_metrics_with_contract_and_locality_hint(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    min_sources: u32,
    selected_urls: &[String],
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
) -> (usize, usize, usize, usize, usize, bool, Vec<String>) {
    let projection = build_query_constraint_projection_with_locality_hint(
        query_contract,
        min_sources.max(1),
        source_hints,
        locality_hint,
    );
    let headline_lookup_mode =
        retrieval_contract_is_generic_headline_collection(retrieval_contract, query_contract);
    let mut total_sources = 0usize;
    let mut compatible_sources = 0usize;
    let mut locality_compatible_sources = 0usize;
    let mut low_priority_sources = 0usize;
    let mut distinct_domains = BTreeSet::new();
    let mut low_priority_urls = Vec::new();
    let mut seen_urls = BTreeSet::new();

    for selected in selected_urls {
        let selected_trimmed = selected.trim();
        if selected_trimmed.is_empty() {
            continue;
        }
        let dedup_key = selected_trimmed.to_ascii_lowercase();
        if !seen_urls.insert(dedup_key) {
            continue;
        }

        let (title, excerpt) = source_hints
            .iter()
            .find(|hint| {
                let hint_url = hint.url.trim();
                hint_url.eq_ignore_ascii_case(selected_trimmed)
                    || url_structurally_equivalent(hint_url, selected_trimmed)
            })
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

        if headline_lookup_mode {
            let headline_source = PendingSearchReadSummary {
                url: selected_trimmed.to_string(),
                title: (!title.trim().is_empty()).then(|| title.trim().to_string()),
                excerpt: excerpt.trim().to_string(),
            };
            if headline_source_is_actionable(&headline_source) {
                compatible_sources = compatible_sources.saturating_add(1);
            }
            locality_compatible_sources = locality_compatible_sources.saturating_add(1);
        } else {
            let compatibility = candidate_constraint_compatibility(
                &projection.constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                selected_trimmed,
                title,
                excerpt,
            );
            if compatibility_passes_projection(&projection, &compatibility) {
                compatible_sources = compatible_sources.saturating_add(1);
            }
            if compatibility.locality_compatible {
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

    let required_source_count = min_sources.max(1) as usize;
    let required_domain_floor =
        retrieval_contract_required_distinct_domain_floor(retrieval_contract, query_contract)
            .min(required_source_count)
            .max(usize::from(required_source_count > 1));
    let locality_floor_met = !projection.locality_scope.is_some()
        || locality_compatible_sources >= required_source_count;
    let distinct_domain_floor_met =
        required_domain_floor == 0 || distinct_domains.len() >= required_domain_floor;
    let quality_floor_met = total_sources >= required_source_count
        && compatible_sources >= required_source_count
        && locality_floor_met
        && distinct_domain_floor_met
        && low_priority_sources == 0;

    (
        total_sources,
        compatible_sources,
        locality_compatible_sources,
        distinct_domains.len(),
        low_priority_sources,
        quality_floor_met,
        low_priority_urls,
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
