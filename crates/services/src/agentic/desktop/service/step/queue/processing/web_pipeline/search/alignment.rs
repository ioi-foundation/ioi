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

fn effective_semantic_alignment_urls(discovery_sources: &[WebSource]) -> Vec<String> {
    let mut urls = Vec::new();
    let mut seen = BTreeSet::new();
    for source in discovery_sources {
        let trimmed = source.url.trim();
        if !trimmed.is_empty() && seen.insert(trimmed.to_string()) {
            urls.push(trimmed.to_string());
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
            existing_observation.url.eq_ignore_ascii_case(observation_url)
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
            if !existing_observation.expansion_affordances.contains(&affordance) {
                existing_observation.expansion_affordances.push(affordance);
            }
        }
    }

    merged
}

async fn filter_discovery_sources_by_semantic_alignment(
    service: &DesktopAgentService,
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

    let filtered_sources = discovery_sources
        .into_iter()
        .filter(|source| url_in_alignment_set(&source.url, &aligned_urls))
        .collect::<Vec<_>>();
    if filtered_sources.is_empty() {
        return Err("semantic source alignment removed all discovery sources".to_string());
    }

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
