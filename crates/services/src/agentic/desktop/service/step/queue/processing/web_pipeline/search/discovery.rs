fn structural_seed_expansion_from_html(
    seed_url: &str,
    page_url: &str,
    html: &str,
    limit: usize,
) -> Option<(
    ioi_types::app::agentic::WebSourceObservation,
    Vec<WebSource>,
)> {
    let expansion_limit = limit.max(1);
    let json_ld_sources = crate::agentic::web::parse_json_ld_item_list_sources_from_html(
        page_url,
        html,
        expansion_limit,
    );
    let child_link_sources = crate::agentic::web::parse_same_host_child_collection_sources_from_html(
        page_url,
        html,
        expansion_limit,
    );
    let mut expansion_affordances = Vec::new();
    let mut expanded_sources = Vec::new();
    let mut seen_urls = std::collections::BTreeSet::new();

    if !json_ld_sources.is_empty() {
        expansion_affordances
            .push(ioi_types::app::agentic::WebSourceExpansionAffordance::JsonLdItemList);
        for source in json_ld_sources {
            let trimmed = source.url.trim();
            if trimmed.is_empty() || !seen_urls.insert(trimmed.to_ascii_lowercase()) {
                continue;
            }
            expanded_sources.push(source);
        }
    }
    if !child_link_sources.is_empty() {
        expansion_affordances
            .push(ioi_types::app::agentic::WebSourceExpansionAffordance::ChildLinkCollection);
        for source in child_link_sources {
            let trimmed = source.url.trim();
            if trimmed.is_empty() || !seen_urls.insert(trimmed.to_ascii_lowercase()) {
                continue;
            }
            expanded_sources.push(source);
        }
    }
    if expansion_affordances.is_empty() {
        return None;
    }

    Some((
        ioi_types::app::agentic::WebSourceObservation {
            url: seed_url.trim().to_string(),
            affordances: vec![
                ioi_types::app::agentic::WebRetrievalAffordance::LinkCollection,
                ioi_types::app::agentic::WebRetrievalAffordance::CanonicalLinkOut,
            ],
            expansion_affordances,
        },
        expanded_sources,
    ))
}

fn deterministic_local_business_expansion_alignment_urls(
    query_contract: &str,
    locality_hint: Option<&str>,
    expanded_sources: &[WebSource],
    limit: usize,
) -> Vec<String> {
    let expanded_hints = expanded_sources
        .iter()
        .filter_map(|source| {
            let trimmed = source.url.trim();
            (!trimmed.is_empty()).then(|| PendingSearchReadSummary {
                url: trimmed.to_string(),
                title: source.title.clone().filter(|value| !value.trim().is_empty()),
                excerpt: source
                    .snippet
                    .as_deref()
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
            })
        })
        .collect::<Vec<_>>();
    if expanded_hints.is_empty() {
        return Vec::new();
    }

    let target_names = local_business_target_names_from_sources(
        &expanded_hints,
        locality_hint,
        expanded_hints.len(),
    );
    if target_names.is_empty() {
        return Vec::new();
    }

    selected_local_business_target_sources(
        query_contract,
        &target_names,
        &expanded_hints,
        locality_hint,
        limit.max(1),
    )
    .into_iter()
    .map(|source| source.url)
    .collect()
}

async fn observe_geo_scoped_discovery_sources(
    discovery_sources: &[WebSource],
    existing_observations: &[ioi_types::app::agentic::WebSourceObservation],
    required_url_count: usize,
    verification_checks: &mut Vec<String>,
) -> Vec<ioi_types::app::agentic::WebSourceObservation> {
    let mut observed = Vec::new();
    let probe_limit = discovery_sources
        .len()
        .min(required_url_count.saturating_mul(4).max(6));
    let expansion_limit = WEB_PIPELINE_DISCOVERY_SOURCE_LIMIT
        .max(required_url_count.saturating_mul(4))
        .max(6);
    let mut probed_urls = Vec::new();

    for source in discovery_sources.iter().take(probe_limit) {
        let seed_url = source.url.trim();
        if seed_url.is_empty() {
            continue;
        }
        let Ok((final_url, html)) =
            crate::agentic::web::fetch_structured_detail_http_fallback_browser_ua_with_final_url(
                seed_url,
            )
            .await
        else {
            continue;
        };
        if crate::agentic::web::detect_human_challenge(&final_url, &html).is_some() {
            continue;
        }
        let Some((observation, _)) =
            structural_seed_expansion_from_html(seed_url, &final_url, &html, expansion_limit)
        else {
            continue;
        };
        probed_urls.push(seed_url.to_string());
        observed.push(observation);
    }

    verification_checks.push(format!(
        "web_geo_scoped_seed_observation_attempted={}",
        probe_limit > 0
    ));
    verification_checks.push(format!(
        "web_geo_scoped_seed_observation_count={}",
        observed.len()
    ));
    if !probed_urls.is_empty() {
        verification_checks.push(format!(
            "web_geo_scoped_seed_observation_url_values={}",
            probed_urls.join(" | ")
        ));
    }

    merge_source_observations(existing_observations, observed)
}

async fn expand_geo_scoped_discovery_seed_sources(
    service: &DesktopAgentService,
    retrieval_contract: &ioi_types::app::agentic::WebRetrievalContract,
    query_contract: &str,
    discovery_sources: Vec<WebSource>,
    source_observations: &[ioi_types::app::agentic::WebSourceObservation],
    required_url_count: usize,
    verification_checks: &mut Vec<String>,
) -> Result<Vec<WebSource>, String> {
    if !crate::agentic::web::contract_requires_geo_scoped_entity_expansion(retrieval_contract) {
        return Ok(discovery_sources);
    }

    let mut expanded_sources = Vec::new();
    let mut seen_urls = std::collections::BTreeSet::new();
    let expansion_seed_limit = discovery_sources
        .len()
        .min(required_url_count.saturating_mul(4).max(6));
    let expansion_limit = WEB_PIPELINE_DISCOVERY_SOURCE_LIMIT
        .max(required_url_count.saturating_mul(4))
        .max(6);
    let mut expanded_seed_urls = Vec::new();
    let locality_hint = explicit_query_scope_hint(query_contract).or_else(|| {
        retrieval_contract_requires_runtime_locality(Some(retrieval_contract), query_contract)
            .then(|| effective_locality_scope_hint(None))
            .flatten()
    });

    for source in discovery_sources.iter().take(expansion_seed_limit) {
        let source_url = source.url.trim();
        if source_url.is_empty() {
            continue;
        }
        let Some(source_observation) = source_observations.iter().find(|observation| {
            observation.url.eq_ignore_ascii_case(source_url)
                || url_structurally_equivalent(&observation.url, source_url)
        }) else {
            continue;
        };
        let seed_admitted = source_observation.affordances.contains(
            &ioi_types::app::agentic::WebRetrievalAffordance::LinkCollection,
        ) && source_observation.affordances.contains(
            &ioi_types::app::agentic::WebRetrievalAffordance::CanonicalLinkOut,
        ) && source_observation.expansion_affordances.iter().any(|affordance| {
            matches!(
                affordance,
                ioi_types::app::agentic::WebSourceExpansionAffordance::JsonLdItemList
                    | ioi_types::app::agentic::WebSourceExpansionAffordance::ChildLinkCollection
            )
        });
        if !seed_admitted {
            continue;
        }
        let (final_url, html) = match crate::agentic::web::fetch_structured_detail_http_fallback_browser_ua_with_final_url(source_url).await {
            Ok(result) => result,
            Err(_) => continue,
        };
        if crate::agentic::web::detect_human_challenge(&final_url, &html).is_some() {
            continue;
        }
        let Some((_, item_sources)) =
            structural_seed_expansion_from_html(source_url, &final_url, &html, expansion_limit)
        else {
            continue;
        };
        expanded_seed_urls.push(source_url.to_string());
        for item_source in item_sources {
            let item_url = item_source.url.trim();
            if item_url.is_empty() {
                continue;
            }
            if !seen_urls.insert(item_url.to_ascii_lowercase()) {
                continue;
            }
            expanded_sources.push(item_source);
        }
    }

    verification_checks.push(format!(
        "web_geo_scoped_seed_expansion_attempted={}",
        expansion_seed_limit > 0
    ));
    verification_checks.push(format!(
        "web_geo_scoped_seed_expansion_seed_count={}",
        expanded_seed_urls.len()
    ));
    verification_checks.push(format!(
        "web_geo_scoped_seed_expansion_detail_count={}",
        expanded_sources.len()
    ));
    if !expanded_seed_urls.is_empty() {
        verification_checks.push(format!(
            "web_geo_scoped_seed_expansion_seed_url_values={}",
            expanded_seed_urls.join(" | ")
        ));
    }

    if expanded_sources.is_empty() {
        return Ok(discovery_sources);
    }

    let mut aligned_expanded_urls = crate::agentic::web::infer_query_matching_source_urls(
        service.fast_inference.clone(),
        query_contract,
        retrieval_contract,
        &expanded_sources,
    )
    .await?;
    let deterministic_expanded_urls = deterministic_local_business_expansion_alignment_urls(
        query_contract,
        locality_hint.as_deref(),
        &expanded_sources,
        expansion_limit,
    );
    verification_checks.push(format!(
        "web_geo_scoped_seed_expansion_alignment_deterministic_count={}",
        deterministic_expanded_urls.len()
    ));
    if !deterministic_expanded_urls.is_empty() {
        verification_checks.push(format!(
            "web_geo_scoped_seed_expansion_alignment_deterministic_url_values={}",
            deterministic_expanded_urls.join(" | ")
        ));
    }
    for url in deterministic_expanded_urls {
        if url_in_alignment_set(&url, &aligned_expanded_urls) {
            continue;
        }
        aligned_expanded_urls.push(url);
    }
    if aligned_expanded_urls.is_empty() {
        verification_checks.push("web_geo_scoped_seed_expansion_alignment_matched=0".to_string());
        return Ok(discovery_sources);
    }

    verification_checks.push(format!(
        "web_geo_scoped_seed_expansion_alignment_matched={}",
        aligned_expanded_urls.len()
    ));
    verification_checks.push(format!(
        "web_geo_scoped_seed_expansion_alignment_url_values={}",
        aligned_expanded_urls.join(" | ")
    ));

    let filtered = expanded_sources
        .into_iter()
        .filter(|source| url_in_alignment_set(&source.url, &aligned_expanded_urls))
        .collect::<Vec<_>>();
    if filtered.is_empty() {
        return Ok(discovery_sources);
    }

    let mut combined = filtered;
    for source in discovery_sources {
        let trimmed = source.url.trim();
        if trimmed.is_empty() || !seen_urls.insert(trimmed.to_ascii_lowercase()) {
            continue;
        }
        combined.push(source);
    }

    Ok(combined)
}
