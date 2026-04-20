fn pre_read_candidate_inventory_target(
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    query_contract: &str,
    min_sources: u32,
    batch_target: usize,
) -> usize {
    let required = batch_target.max(min_sources.max(1) as usize);
    let distinct_domain_floor =
        retrieval_contract_required_distinct_domain_floor(retrieval_contract, query_contract)
            .max(1);
    let extra_headroom = distinct_domain_floor
        .saturating_sub(1)
        .max(usize::from(required > 1));
    required.saturating_add(extra_headroom)
}

fn pre_read_batch_urls(candidate_urls: &[String], batch_target: usize) -> Vec<String> {
    candidate_urls
        .iter()
        .filter_map(|url| {
            let trimmed = url.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        })
        .take(batch_target.max(1))
        .collect()
}

fn url_in_alignment_set(url: &str, aligned_urls: &[String]) -> bool {
    let trimmed = url.trim();
    aligned_urls.iter().any(|aligned| {
        aligned.eq_ignore_ascii_case(trimmed) || url_structurally_equivalent(aligned, trimmed)
    })
}

fn source_url_from_metadata_excerpt(excerpt: &str) -> Option<String> {
    let marker = "source_url=";
    let lower = excerpt.to_ascii_lowercase();
    let start = lower.find(marker)? + marker.len();
    let candidate = excerpt
        .get(start..)?
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_matches(|ch: char| "|,;:!?)]}\"'".contains(ch))
        .trim();
    if candidate.starts_with("http://") || candidate.starts_with("https://") {
        Some(candidate.to_string())
    } else {
        None
    }
}

fn semantic_alignment_source_urls(source: &WebSource) -> Vec<String> {
    let mut urls = Vec::new();
    let mut seen = BTreeSet::new();
    let trimmed = source.url.trim();
    if !trimmed.is_empty() && seen.insert(trimmed.to_string()) {
        urls.push(trimmed.to_string());
    }

    let canonical = source
        .snippet
        .as_deref()
        .and_then(source_url_from_metadata_excerpt)
        .filter(|candidate| {
            let trimmed = candidate.trim();
            !trimmed.is_empty()
                && (is_search_hub_url(source.url.trim())
                    || crate::agentic::web::is_google_news_article_wrapper_url(source.url.trim()))
                && is_citable_web_url(trimmed)
        });
    if let Some(url) = canonical {
        if seen.insert(url.clone()) {
            urls.push(url);
        }
    }

    urls
}

fn source_in_alignment_set(source: &WebSource, aligned_urls: &[String]) -> bool {
    semantic_alignment_source_urls(source)
        .iter()
        .any(|url| url_in_alignment_set(url, aligned_urls))
}

fn semantic_alignment_subject_url(source: &WebSource) -> String {
    source
        .snippet
        .as_deref()
        .and_then(source_url_from_metadata_excerpt)
        .filter(|_| {
            is_search_hub_url(source.url.trim())
                || crate::agentic::web::is_google_news_article_wrapper_url(source.url.trim())
        })
        .unwrap_or_else(|| source.url.trim().to_string())
}

fn effective_semantic_alignment_urls(discovery_sources: &[WebSource]) -> Vec<String> {
    let mut urls = Vec::new();
    let mut seen = BTreeSet::new();
    for source in discovery_sources {
        for url in semantic_alignment_source_urls(source) {
            if seen.insert(url.clone()) {
                urls.push(url);
            }
        }
    }

    if discovery_sources.is_empty() {
        return urls;
    }

    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "web.pipeline.semantic_subject_alignment".to_string(),
        query: None,
        url: None,
        sources: discovery_sources.to_vec(),
        source_observations: Vec::new(),
        documents: Vec::new(),
        provider_candidates: Vec::new(),
        retrieval_contract: None,
    };
    for hint in candidate_source_hints_from_bundle(&bundle) {
        let trimmed = hint.url.trim();
        if !trimmed.is_empty() && seen.insert(trimmed.to_string()) {
            urls.push(trimmed.to_string());
        }
    }

    urls
}

fn semantically_aligned_discovery_source_priority(
    retrieval_contract: &ioi_types::app::agentic::WebRetrievalContract,
    query_contract: &str,
    source: &WebSource,
) -> (bool, bool, bool, u32) {
    let subject_url = semantic_alignment_subject_url(source);
    let url = subject_url.as_str();
    let title = source.title.as_deref().unwrap_or_default();
    let snippet = source.snippet.as_deref().unwrap_or_default();
    let authority_required =
        pre_read_authority_source_required(Some(retrieval_contract), query_contract);
    let primary_authority = authority_required
        && pre_read_source_has_primary_authority(query_contract, url, title, snippet);
    let authority_identifier = primary_authority
        && crate::agentic::runtime::service::step::queue::support::source_has_briefing_standard_identifier_signal(
            query_contract,
            url,
            title,
            snippet,
        );
    let direct_detail =
        is_citable_web_url(url) && !is_search_hub_url(url) && !is_multi_item_listing_url(url);

    (
        authority_identifier,
        primary_authority,
        direct_detail,
        source.rank.unwrap_or(u32::MAX),
    )
}

fn briefing_subject_overlap_guard_required(
    retrieval_contract: &ioi_types::app::agentic::WebRetrievalContract,
    query_contract: &str,
) -> bool {
    query_prefers_document_briefing_layout(query_contract)
        && !query_requests_comparison(query_contract)
        && crate::agentic::runtime::service::step::signals::analyze_query_facets(query_contract)
            .grounded_external_required
        && (retrieval_contract.currentness_required
            || retrieval_contract.source_independence_min > 1)
}

fn semantically_aligned_discovery_source_passes_briefing_subject_guard(
    retrieval_contract: &ioi_types::app::agentic::WebRetrievalContract,
    query_contract: &str,
    source: &WebSource,
) -> bool {
    if !briefing_subject_overlap_guard_required(retrieval_contract, query_contract) {
        return true;
    }

    let subject_url = semantic_alignment_subject_url(source);
    let trimmed_url = subject_url.as_str();
    if trimmed_url.is_empty() {
        return false;
    }

    let title = source.title.as_deref().unwrap_or_default();
    let snippet = source.snippet.as_deref().unwrap_or_default();
    let projection = crate::agentic::runtime::service::step::queue::web_pipeline::build_query_constraint_projection(
        query_contract,
        retrieval_contract
            .source_independence_min
            .max(retrieval_contract.entity_cardinality_min.max(1)),
        &[],
    );
    let overlap_floor = projection.query_native_tokens.len().min(2).max(1);
    let source_tokens = source_anchor_tokens(trimmed_url, title, snippet);
    let query_native_overlap = projection
        .query_native_tokens
        .intersection(&source_tokens)
        .count();

    query_native_overlap >= overlap_floor
        || crate::agentic::runtime::service::step::queue::support::source_has_briefing_standard_identifier_signal(
            query_contract,
            trimmed_url,
            title,
            snippet,
        )
}

fn rank_semantically_aligned_discovery_sources(
    retrieval_contract: &ioi_types::app::agentic::WebRetrievalContract,
    query_contract: &str,
    discovery_sources: Vec<WebSource>,
) -> Vec<WebSource> {
    let mut indexed = discovery_sources
        .into_iter()
        .enumerate()
        .collect::<Vec<_>>();
    indexed.sort_by(|(left_idx, left), (right_idx, right)| {
        let left_priority = semantically_aligned_discovery_source_priority(
            retrieval_contract,
            query_contract,
            left,
        );
        let right_priority = semantically_aligned_discovery_source_priority(
            retrieval_contract,
            query_contract,
            right,
        );
        right_priority
            .0
            .cmp(&left_priority.0)
            .then_with(|| right_priority.1.cmp(&left_priority.1))
            .then_with(|| right_priority.2.cmp(&left_priority.2))
            .then_with(|| left_priority.3.cmp(&right_priority.3))
            .then_with(|| left_idx.cmp(right_idx))
    });
    indexed.into_iter().map(|(_, source)| source).collect()
}

fn merge_source_observations(
    existing: &[ioi_types::app::agentic::WebSourceObservation],
    incoming: Vec<ioi_types::app::agentic::WebSourceObservation>,
) -> Vec<ioi_types::app::agentic::WebSourceObservation> {
    let mut merged = existing.to_vec();

    for observation in incoming {
        let observation_url = observation.url.trim();
        if observation_url.is_empty() {
            continue;
        }
        let Some(existing_idx) = merged.iter().position(|existing_observation| {
            existing_observation
                .url
                .eq_ignore_ascii_case(observation_url)
                || url_structurally_equivalent(&existing_observation.url, observation_url)
        }) else {
            merged.push(observation);
            continue;
        };

        let existing_observation = &mut merged[existing_idx];
        for affordance in observation.affordances {
            if !existing_observation.affordances.contains(&affordance) {
                existing_observation.affordances.push(affordance);
            }
        }
        for affordance in observation.expansion_affordances {
            if !existing_observation
                .expansion_affordances
                .contains(&affordance)
            {
                existing_observation.expansion_affordances.push(affordance);
            }
        }
    }

    merged
}

async fn filter_discovery_sources_by_semantic_alignment(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    step_index: u32,
    intent_id: &str,
    retrieval_contract: &ioi_types::app::agentic::WebRetrievalContract,
    query_contract: &str,
    discovery_sources: Vec<WebSource>,
    verification_checks: &mut Vec<String>,
) -> Result<(Vec<WebSource>, Vec<String>, bool), String> {
    let alignment_required =
        crate::agentic::web::contract_requires_semantic_source_alignment(retrieval_contract);
    emit_web_contract_receipt(
        service,
        session_id,
        step_index,
        intent_id,
        "discovery",
        "semantic_subject_alignment_required",
        true,
        "web.pipeline.semantic_subject_alignment_requirement.v1",
        if alignment_required { "true" } else { "false" },
        "bool",
        None,
    );
    verification_checks.push(format!(
        "web_semantic_subject_alignment_required={}",
        alignment_required
    ));
    if !alignment_required {
        return Ok((discovery_sources, Vec::new(), false));
    }

    let aligned_urls = crate::agentic::web::infer_query_matching_source_urls(
        service.fast_inference.clone(),
        query_contract,
        retrieval_contract,
        &discovery_sources,
    )
    .await?;
    let alignment_summary = format!(
        "matched_sources={};observed_sources={}",
        aligned_urls.len(),
        discovery_sources.len()
    );
    emit_web_contract_receipt(
        service,
        session_id,
        step_index,
        intent_id,
        "discovery",
        "semantic_subject_alignment_floor",
        !aligned_urls.is_empty(),
        "web.pipeline.semantic_subject_alignment.v1",
        alignment_summary.as_str(),
        "summary",
        None,
    );
    emit_web_string_receipts(
        service,
        session_id,
        step_index,
        intent_id,
        "discovery",
        "semantic_subject_alignment_url",
        "web.pipeline.semantic_subject_alignment.v1",
        "url",
        &aligned_urls,
    );
    verification_checks.push(format!(
        "web_semantic_subject_alignment_matched={}",
        aligned_urls.len()
    ));
    if !aligned_urls.is_empty() {
        verification_checks.push(format!(
            "web_semantic_subject_alignment_url_values={}",
            aligned_urls.join(" | ")
        ));
    }
    if aligned_urls.is_empty() {
        return Err("no semantically aligned discovery sources".to_string());
    }

    let aligned_sources = discovery_sources
        .into_iter()
        .filter(|source| source_in_alignment_set(source, &aligned_urls))
        .collect::<Vec<_>>();
    if aligned_sources.is_empty() {
        return Err("semantic source alignment removed all discovery sources".to_string());
    }
    let structural_guard_required =
        briefing_subject_overlap_guard_required(retrieval_contract, query_contract);
    let structural_filtered_sources = aligned_sources
        .into_iter()
        .filter(|source| {
            semantically_aligned_discovery_source_passes_briefing_subject_guard(
                retrieval_contract,
                query_contract,
                source,
            )
        })
        .collect::<Vec<_>>();
    let structural_rejected_count =
        aligned_urls.len().saturating_sub(structural_filtered_sources.len());
    emit_web_contract_receipt(
        service,
        session_id,
        step_index,
        intent_id,
        "discovery",
        "semantic_subject_alignment_structural_floor",
        !structural_guard_required || !structural_filtered_sources.is_empty(),
        "web.pipeline.semantic_subject_alignment.structural.v1",
        format!(
            "required={};kept_sources={};rejected_sources={}",
            structural_guard_required,
            structural_filtered_sources.len(),
            structural_rejected_count
        )
        .as_str(),
        "summary",
        None,
    );
    verification_checks.push(format!(
        "web_semantic_subject_alignment_structural_required={}",
        structural_guard_required
    ));
    verification_checks.push(format!(
        "web_semantic_subject_alignment_structural_kept={}",
        structural_filtered_sources.len()
    ));
    verification_checks.push(format!(
        "web_semantic_subject_alignment_structural_rejected={}",
        structural_rejected_count
    ));
    if structural_guard_required && structural_filtered_sources.is_empty() {
        return Err(
            "semantic source alignment removed all discovery sources after briefing subject guard"
                .to_string(),
        );
    }

    let filtered_sources = rank_semantically_aligned_discovery_sources(
        retrieval_contract,
        query_contract,
        structural_filtered_sources,
    );

    let effective_alignment_urls = effective_semantic_alignment_urls(&filtered_sources);
    emit_web_string_receipts(
        service,
        session_id,
        step_index,
        intent_id,
        "discovery",
        "semantic_subject_alignment_selection_url",
        "web.pipeline.semantic_subject_alignment.selection.v1",
        "url",
        &effective_alignment_urls,
    );
    if !effective_alignment_urls.is_empty() {
        verification_checks.push(format!(
            "web_semantic_subject_alignment_selection_url_values={}",
            effective_alignment_urls.join(" | ")
        ));
    }

    Ok((filtered_sources, effective_alignment_urls, true))
}

#[cfg(test)]
#[path = "alignment/semantic_alignment_tests.rs"]
mod semantic_alignment_tests;
