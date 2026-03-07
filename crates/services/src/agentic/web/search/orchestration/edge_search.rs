pub async fn edge_web_search(
    browser: &BrowserDriver,
    query: &str,
    query_contract: Option<&str>,
    retrieval_contract: &WebRetrievalContract,
    limit: u32,
) -> Result<WebEvidenceBundle> {
    if let Some(fixture_urls) = reliability_fixture_sources() {
        let effective_limit = limit.max(1) as usize;
        let sources = fixture_urls
            .into_iter()
            .take(effective_limit)
            .enumerate()
            .map(|(idx, url)| WebSource {
                source_id: source_id_for_url(&url),
                rank: Some((idx + 1) as u32),
                domain: domain_for_url(&url),
                title: Some(format!("Reliability Fixture Source {}", idx + 1)),
                snippet: Some("Deterministic search fixture source".to_string()),
                url,
            })
            .collect::<Vec<_>>();

        let source_url = sources
            .first()
            .map(|source| source.url.clone())
            .unwrap_or_else(|| build_ddg_serp_url(query.trim()));

        return Ok(WebEvidenceBundle {
            schema_version: 1,
            retrieved_at_ms: now_ms(),
            tool: "web__search".to_string(),
            backend: "edge:search:fixture".to_string(),
            query: Some(query.trim().to_string()),
            url: Some(source_url),
            sources,
            source_observations: vec![],
            documents: vec![],
            provider_candidates: vec![WebProviderCandidate {
                provider_id: "edge:search:fixture".to_string(),
                affordances: vec![SearchStructuralAffordance::QueryableIndex],
                request_url: Some(build_ddg_serp_url(query.trim())),
                source_count: effective_limit as u32,
                success: true,
                selected: true,
                challenge_reason: None,
            }],
            retrieval_contract: Some(retrieval_contract.clone()),
        });
    }

    let selection_query_contract = query_contract
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| query.trim());
    let locality_hint = resolved_locality_scope(query, query_contract, retrieval_contract);
    let query_for_provider =
        provider_request_query(query, query_contract, retrieval_contract, locality_hint.as_deref());
    let default_serp_url = build_ddg_serp_url(&query_for_provider);
    let requirements =
        search_provider_requirements_from_contract(retrieval_contract, locality_hint.as_deref());
    let expansion_surface_preferred =
        contract_requires_geo_scoped_entity_expansion(retrieval_contract);
    let headline_lookup_mode = retrieval_contract.ordered_collection_preferred
        && retrieval_contract.entity_cardinality_min > 1
        && !retrieval_contract.link_collection_preferred
        && !crate::agentic::web::contract_requires_geo_scoped_entity_expansion(retrieval_contract);
    let excluded_hosts = excluded_hosts_from_query(&query_for_provider);
    let search_started_at_ms = now_ms();
    let mut candidate_observations = Vec::<ObservedSearchProviderCandidate>::new();
    let mut sources: Vec<WebSource> = Vec::new();
    let mut backend = "edge:search:empty".to_string();
    let mut source_url = default_serp_url.clone();
    let provider_result_limit = limit.max(1) as usize;
    let discovery_inventory_limit =
        if expansion_surface_preferred || contract_requires_semantic_source_alignment(retrieval_contract)
        {
            provider_result_limit.max(WEB_SOURCE_ALIGNMENT_MAX_SOURCES)
        } else {
            provider_result_limit
        };
    let mut contributing_backends: Vec<&str> = Vec::new();
    let mut fallback_notes: Vec<String> = Vec::new();

    let mut admitted_descriptors = search_provider_registry()
        .iter()
        .copied()
        .filter(|descriptor| provider_descriptor_is_admissible(&requirements, descriptor))
        .collect::<Vec<_>>();
    admitted_descriptors
        .sort_by_key(|descriptor| provider_probe_priority_key(&requirements, descriptor));

    for descriptor in admitted_descriptors {
        if search_budget_exhausted(search_started_at_ms) {
            fallback_notes.push(format!(
                "search_budget_exhausted_ms={}",
                EDGE_WEB_SEARCH_TOTAL_BUDGET_MS
            ));
            break;
        }
        let observation = probe_search_provider(
            browser,
            descriptor,
            &query_for_provider,
            selection_query_contract,
            retrieval_contract,
            locality_hint.as_deref(),
            headline_lookup_mode,
            discovery_inventory_limit,
            expansion_surface_preferred,
            &excluded_hosts,
        )
        .await;
        if let Some(note) = observation.fallback_note.clone() {
            fallback_notes.push(note);
        }
        candidate_observations.push(observation);
    }

    let mut selected_candidate_indexes = candidate_observations
        .iter()
        .enumerate()
        .filter(|(_, candidate)| {
            provider_candidate_is_usable(&requirements, candidate.selection_input())
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    selected_candidate_indexes.sort_by_key(|index| {
        provider_candidate_selection_key(
            &requirements,
            candidate_observations[*index].selection_input(),
        )
    });
    let preferred_ordered_collection_indexes = if requirements.ordered_collection_preferred {
        selected_candidate_indexes
            .iter()
            .copied()
            .filter(|index| {
                provider_supports_affordance(
                    &candidate_observations[*index].descriptor,
                    SearchStructuralAffordance::OrderedCollection,
                )
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let preferred_only_mode = requirements.ordered_collection_preferred
        && !preferred_ordered_collection_indexes.is_empty();
    let fallback_candidate_indexes = if preferred_only_mode {
        selected_candidate_indexes
            .iter()
            .copied()
            .filter(|index| !preferred_ordered_collection_indexes.contains(index))
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let aggregation_order = if preferred_only_mode {
        preferred_ordered_collection_indexes
            .iter()
            .chain(fallback_candidate_indexes.iter())
            .copied()
            .collect::<Vec<_>>()
    } else {
        selected_candidate_indexes.clone()
    };

    for index in aggregation_order {
        let candidate = &mut candidate_observations[index];
        let prior_count = sources.len();
        append_unique_sources(&mut sources, candidate.sources.clone());
        if sources.len() > prior_count {
            candidate.selected = true;
            if let Some(request_url) = candidate.request_url.as_ref() {
                if contributing_backends.is_empty() {
                    source_url = request_url.clone();
                }
            }
            contributing_backends.push(provider_backend_id(candidate.descriptor.stage));
        }
        if should_stop_provider_aggregation(
            retrieval_contract,
            selection_query_contract,
            locality_hint.as_deref(),
            discovery_inventory_limit,
            provider_result_limit,
            &sources,
            Some(&candidate.descriptor),
            preferred_only_mode,
        ) {
            break;
        }
    }

    if !sources.is_empty() {
        if headline_lookup_mode {
            sources = reorder_headline_sources_for_truncation(sources);
        }
        sources.truncate(discovery_inventory_limit);
        for (idx, source) in sources.iter_mut().enumerate() {
            source.rank = Some((idx + 1) as u32);
        }
        if let Some(first_backend) = contributing_backends.first() {
            backend = if contributing_backends
                .iter()
                .all(|candidate| candidate == first_backend)
            {
                (*first_backend).to_string()
            } else {
                let unique_backends = contributing_backends.into_iter().fold(
                    Vec::<&str>::new(),
                    |mut acc, backend_name| {
                        if !acc.contains(&backend_name) {
                            acc.push(backend_name);
                        }
                        acc
                    },
                );
                format!("edge:search:aggregate:{}", unique_backends.join("+"))
            };
        }
    }

    if sources.is_empty() {
        if let Some(challenged_candidate) = candidate_observations
            .iter()
            .find(|candidate| candidate.challenge_reason.is_some())
        {
            if let Some(reason) = challenged_candidate.challenge_reason.as_ref() {
                fallback_notes.push(format!("challenge_required={}", reason));
            }
            if let Some(url) = challenged_candidate.request_url.as_ref() {
                fallback_notes.push(format!("challenge_url={}", url));
                source_url = url.clone();
            }
        }
        if !fallback_notes.is_empty() {
            backend = format!("{}:{}", backend, fallback_notes.join("|"));
        }
    }

    let final_source_keys = sources
        .iter()
        .map(|source| normalize_url_for_id(&source.url))
        .collect::<HashSet<_>>();
    let mut source_observations = Vec::<WebSourceObservation>::new();
    for candidate in &candidate_observations {
        for observation in &candidate.source_observations {
            if final_source_keys.contains(&normalize_url_for_id(&observation.url)) {
                append_unique_source_observations(
                    &mut source_observations,
                    vec![observation.clone()],
                );
            }
        }
    }

    Ok(WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: now_ms(),
        tool: "web__search".to_string(),
        backend,
        query: Some(query_for_provider.clone()),
        url: Some(source_url),
        sources,
        source_observations,
        documents: vec![],
        provider_candidates: candidate_observations
            .iter()
            .map(ObservedSearchProviderCandidate::bundle_candidate)
            .collect(),
        retrieval_contract: Some(retrieval_contract.clone()),
    })
}
