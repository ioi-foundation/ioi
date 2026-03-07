use super::*;
use crate::agentic::desktop::service::step::queue::support::{
    retrieval_contract_is_generic_headline_collection, retrieval_contract_min_sources,
    retrieval_contract_required_distinct_domain_floor,
};
use crate::agentic::desktop::service::step::queue::web_pipeline::resolved_query_contract_with_locality_hint;

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

    let aligned_expanded_urls = crate::agentic::web::infer_query_matching_source_urls(
        service.fast_inference.clone(),
        query_contract,
        retrieval_contract,
        &expanded_sources,
    )
    .await?;
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

    Ok((filtered_sources, aligned_urls, true))
}

fn planning_bundle_after_surface_filter(
    entity_filtered_bundle: &WebEvidenceBundle,
    surface_filtered_bundle: WebEvidenceBundle,
    verification_checks: &mut Vec<String>,
) -> WebEvidenceBundle {
    if surface_filtered_bundle.sources.is_empty()
        && surface_filtered_bundle.documents.is_empty()
        && !(entity_filtered_bundle.sources.is_empty()
            && entity_filtered_bundle.documents.is_empty())
    {
        verification_checks
            .push("web_discovery_surface_filter_preserved_empty_bundle=true".to_string());
    }
    surface_filtered_bundle
}

fn planning_bundle_from_discovery_sources(
    bundle: &WebEvidenceBundle,
    retrieval_contract: &ioi_types::app::agentic::WebRetrievalContract,
    discovery_sources: Vec<WebSource>,
    source_observations: &[ioi_types::app::agentic::WebSourceObservation],
    verification_checks: &mut Vec<String>,
) -> WebEvidenceBundle {
    let retained_source_urls = discovery_sources
        .iter()
        .map(|source| source.url.trim().to_string())
        .filter(|url| !url.is_empty())
        .collect::<Vec<_>>();
    let surface_filtered_bundle = WebEvidenceBundle {
        schema_version: bundle.schema_version,
        retrieved_at_ms: bundle.retrieved_at_ms,
        tool: bundle.tool.clone(),
        backend: bundle.backend.clone(),
        query: bundle.query.clone(),
        url: bundle.url.clone(),
        sources: discovery_sources,
        source_observations: source_observations
            .iter()
            .filter(|observation| {
                retained_source_urls.iter().any(|retained_url| {
                    observation.url.eq_ignore_ascii_case(retained_url)
                        || url_structurally_equivalent(&observation.url, retained_url)
                })
            })
            .cloned()
            .collect(),
        documents: vec![],
        provider_candidates: bundle.provider_candidates.clone(),
        retrieval_contract: Some(retrieval_contract.clone()),
    };
    planning_bundle_after_surface_filter(bundle, surface_filtered_bundle, verification_checks)
}

pub(crate) async fn maybe_handle_web_search(
    service: &DesktopAgentService,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    pre_state_step_index: u32,
    tool_name: &str,
    tool_wrapper: &AgentTool,
    is_gated: bool,
    success: &mut bool,
    out: &mut Option<String>,
    err: &mut Option<String>,
    completion_summary: &mut Option<String>,
    verification_checks: &mut Vec<String>,
) -> Result<(), TransactionError> {
    let parsed_bundle = out.as_deref().and_then(parse_web_evidence_bundle);
    let promoted_memory_search = tool_name == "memory__search"
        && parsed_bundle
            .as_ref()
            .map(|bundle| bundle.tool == "web__search")
            .unwrap_or(false);
    let effective_web_search = tool_name == "web__search" || promoted_memory_search;
    if promoted_memory_search {
        verification_checks.push("memory_search_promoted_to_web_search=true".to_string());
    }
    if !effective_web_search || is_gated || !is_web_research_scope(agent_state) || !*success {
        return Ok(());
    }
    let Some(bundle) = parsed_bundle.as_ref() else {
        return Ok(());
    };

    let query_value = bundle
        .query
        .clone()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| match tool_wrapper {
            AgentTool::WebSearch { query, .. } => {
                let trimmed = query.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            }
            AgentTool::MemorySearch { query } => {
                let trimmed = query.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            }
            _ => None,
        })
        .unwrap_or_else(|| agent_state.goal.clone());
    let query_contract = agent_state
        .pending_search_completion
        .as_ref()
        .map(|pending| pending.query_contract.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| {
            select_web_pipeline_query_contract(agent_state.goal.as_str(), &query_value)
        });
    let intent_id = resolved_intent_id(agent_state);
    let pending_contract = agent_state
        .pending_search_completion
        .as_ref()
        .and_then(|pending| pending.retrieval_contract.clone());
    let retrieval_contract = if let Some(contract) = pending_contract {
        contract
    } else if let Some(contract) = bundle.retrieval_contract.clone() {
        contract
    } else {
        let retrieval_goal = agent_state.goal.trim();
        match crate::agentic::web::infer_web_retrieval_contract(
            service.fast_inference.clone(),
            if retrieval_goal.is_empty() {
                &query_value
            } else {
                retrieval_goal
            },
            Some(query_contract.as_str()),
        )
        .await
        {
            Ok(contract) => contract,
            Err(inference_err) => {
                *success = false;
                *err = Some(format!(
                    "ERROR_CLASS=SynthesisFailed {}",
                    inference_err.to_string().trim()
                ));
                return Ok(());
            }
        }
    };
    let min_sources =
        retrieval_contract_min_sources(Some(&retrieval_contract), &query_contract).max(1);
    let headline_lookup_mode = retrieval_contract_is_generic_headline_collection(
        Some(&retrieval_contract),
        &query_contract,
    );
    let started_at_ms = web_pipeline_now_ms();
    let locality_scope_required = retrieval_contract.runtime_locality_required;
    let locality_hint = if locality_scope_required {
        effective_locality_scope_hint(None)
    } else {
        None
    };
    let locality_requirement_observed = locality_scope_required.to_string();
    let locality_alignment_satisfied = if locality_scope_required {
        let expected_query_contract = resolved_query_contract_with_locality_hint(
            agent_state.goal.as_str(),
            locality_hint.as_deref(),
        );
        !expected_query_contract.trim().is_empty()
            && expected_query_contract.eq_ignore_ascii_case(query_contract.trim())
    } else {
        true
    };
    let currentness_required = retrieval_contract.currentness_required;
    verification_checks.push(format!(
        "web_runtime_locality_scope_required={}",
        locality_scope_required
    ));
    verification_checks.push(format!(
        "web_runtime_locality_scope_satisfied={}",
        !locality_scope_required || locality_hint.is_some()
    ));
    if let Some(scope) = locality_hint.as_ref() {
        verification_checks.push(format!("web_runtime_locality_scope={}", scope));
    }
    emit_web_contract_receipt(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "execution",
        "query_contract",
        !query_contract.trim().is_empty(),
        "web.pipeline.query_contract.v1",
        query_contract.trim(),
        "string",
        None,
    );
    emit_web_contract_receipt(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "execution",
        "query_value",
        !query_value.trim().is_empty(),
        "web.pipeline.query_value.v1",
        query_value.trim(),
        "string",
        None,
    );
    emit_web_contract_receipt(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "discovery",
        "runtime_locality_required",
        true,
        "web.pipeline.locality_requirement.v1",
        locality_requirement_observed.as_str(),
        "bool",
        None,
    );
    if let Ok(observed_value) = serde_json::to_string(&retrieval_contract) {
        emit_web_contract_receipt(
            service,
            session_id,
            pre_state_step_index,
            intent_id.as_str(),
            "execution",
            "retrieval_contract",
            true,
            "web.pipeline.retrieval_contract.v1",
            observed_value.as_str(),
            "json",
            None,
        );
    }
    emit_web_contract_receipt(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "discovery",
        "runtime_locality_scope",
        !locality_scope_required || locality_hint.is_some(),
        "web.pipeline.locality_scope.v1",
        locality_hint.as_deref().unwrap_or("<unset>"),
        "scope",
        None,
    );
    emit_web_contract_receipt(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "discovery",
        "query_contract_locality_alignment",
        locality_alignment_satisfied,
        "web.pipeline.query_contract_locality_alignment.v1",
        query_contract.trim(),
        "string",
        None,
    );
    emit_web_contract_receipt(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "execution",
        "currentness_required",
        true,
        "web.pipeline.currentness_requirement.v1",
        if currentness_required {
            "true"
        } else {
            "false"
        },
        "bool",
        None,
    );
    emit_web_contract_receipt(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "execution",
        "min_sources_required",
        min_sources > 0,
        "web.pipeline.min_sources_required.v1",
        &min_sources.to_string(),
        "scalar",
        None,
    );
    for candidate in &bundle.provider_candidates {
        let observed_value = serde_json::json!({
            "provider_id": candidate.provider_id,
            "source_count": candidate.source_count,
            "selected": candidate.selected,
            "success": candidate.success,
            "request_url": candidate.request_url,
            "challenge_reason": candidate.challenge_reason,
            "affordances": candidate.affordances,
        })
        .to_string();
        emit_web_contract_receipt(
            service,
            session_id,
            pre_state_step_index,
            intent_id.as_str(),
            "discovery",
            "provider_candidate",
            candidate.success && candidate.source_count > 0,
            "web.search.provider_candidate.v2",
            observed_value.as_str(),
            "json",
            Some(candidate.provider_id.clone()),
        );
    }
    verification_checks.push("web_discovery_source_filters_bypassed=true".to_string());
    let bundle = bundle;
    for candidate in bundle
        .provider_candidates
        .iter()
        .filter(|candidate| candidate.selected)
    {
        let observed_value = serde_json::json!({
            "provider_id": candidate.provider_id,
            "source_count": candidate.source_count,
            "request_url": candidate.request_url,
        })
        .to_string();
        emit_web_contract_receipt(
            service,
            session_id,
            pre_state_step_index,
            intent_id.as_str(),
            "provider_selection",
            "provider_selected",
            !bundle.sources.is_empty() && candidate.source_count > 0,
            "web.search.provider_selection.v2",
            observed_value.as_str(),
            "json",
            Some(candidate.provider_id.clone()),
        );
    }
    let discovery_sources = ordered_discovery_sources(bundle);
    let required_url_count = min_sources.max(1) as usize;
    let (discovery_sources, semantic_aligned_discovery_urls, semantic_alignment_required) =
        match filter_discovery_sources_by_semantic_alignment(
            service,
            session_id,
            pre_state_step_index,
            intent_id.as_str(),
            &retrieval_contract,
            &query_contract,
            discovery_sources,
            verification_checks,
        )
        .await
        {
            Ok(result) => result,
            Err(error) => {
                verification_checks.push(format!("web_pre_read_payload_error={}", error));
                *success = false;
                *err = Some(format!("ERROR_CLASS=SynthesisFailed {}", error));
                return Ok(());
            }
        };
    let source_observations =
        if crate::agentic::web::contract_requires_geo_scoped_entity_expansion(&retrieval_contract)
        {
            observe_geo_scoped_discovery_sources(
                &discovery_sources,
                &bundle.source_observations,
                required_url_count,
                verification_checks,
            )
            .await
        } else {
            bundle.source_observations.clone()
        };
    let discovery_sources = match expand_geo_scoped_discovery_seed_sources(
        service,
        &retrieval_contract,
        &query_contract,
        discovery_sources,
        &source_observations,
        required_url_count,
        verification_checks,
    )
    .await
    {
        Ok(sources) => sources,
        Err(error) => {
            verification_checks.push(format!("web_pre_read_payload_error={}", error));
            *success = false;
            *err = Some(format!("ERROR_CLASS=SynthesisFailed {}", error));
            return Ok(());
        }
    };
    let discovery_sources = if semantic_alignment_required {
        discovery_sources
            .into_iter()
            .take(WEB_PIPELINE_DISCOVERY_SOURCE_LIMIT)
            .collect::<Vec<_>>()
    } else {
        discovery_sources
    };
    let semantic_aligned_discovery_urls = if semantic_alignment_required {
        discovery_sources
            .iter()
            .map(|source| source.url.clone())
            .collect::<Vec<_>>()
    } else {
        semantic_aligned_discovery_urls
    };
    let discovery_hints = merge_source_hints(
        candidate_source_hints_from_bundle(bundle),
        &discovery_source_hints(&discovery_sources),
    );
    let planning_bundle = planning_bundle_from_discovery_sources(
        bundle,
        &retrieval_contract,
        discovery_sources.clone(),
        &source_observations,
        verification_checks,
    );
    let pre_read_target = required_url_count;
    let selection = match synthesize_pre_read_selection(
        service,
        Some(&retrieval_contract),
        &query_contract,
        required_url_count,
        &planning_bundle.sources,
        &planning_bundle.source_observations,
    )
    .await
    {
        Ok(selection) => selection,
        Err(error) => {
            verification_checks.push(format!("web_pre_read_payload_error={}", error));
            *success = false;
            *err = Some(format!("ERROR_CLASS=SynthesisFailed {}", error));
            return Ok(());
        }
    };
    if selection.urls.is_empty() {
        let error = "typed pre-read selection returned no admissible URLs".to_string();
        verification_checks.push(format!("web_pre_read_payload_error={}", error));
        *success = false;
        *err = Some(format!("ERROR_CLASS=SynthesisFailed {}", error));
        return Ok(());
    }
    let payload_error: Option<String> = None;
    let payload_synthesis_skipped = false;
    let deterministic_fallback_used = false;
    let deterministic_top_up_used = false;
    let merged_hints = discovery_hints;
    let mut selected_urls = selection.urls;
    resolve_selected_urls_from_hints(&mut selected_urls, &merged_hints);
    let candidate_urls = selected_urls.clone();
    let selection_mode = match selection.selection_mode {
        PreReadSelectionMode::DirectDetail => "direct_detail",
        PreReadSelectionMode::DiscoverySeed => "discovery_seed",
    };
    emit_web_contract_receipt(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "verification",
        "pre_read_selection_mode",
        true,
        "web.pipeline.pre_read.selection_mode.v1",
        selection_mode,
        "enum",
        None,
    );
    verification_checks.push(format!("web_pre_read_selection_mode={}", selection_mode));
    let selected_subject_alignment_floor_met = if semantic_alignment_required {
        let minimum_aligned_selection = if crate::agentic::web::contract_requires_geo_scoped_entity_expansion(
            &retrieval_contract,
        ) {
            1
        } else {
            required_url_count
        };
        selected_urls.len() >= minimum_aligned_selection
            && selected_urls
                .iter()
                .all(|selected| url_in_alignment_set(selected, &semantic_aligned_discovery_urls))
    } else {
        true
    };
    let selected_subject_alignment_count = selected_urls
        .iter()
        .filter(|selected| url_in_alignment_set(selected, &semantic_aligned_discovery_urls))
        .count();
    let selected_subject_alignment_summary = format!(
        "required={};selected_sources={};aligned_selected_sources={}",
        semantic_alignment_required,
        selected_urls.len(),
        selected_subject_alignment_count
    );
    emit_web_contract_receipt(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "verification",
        "selected_source_subject_alignment_floor",
        selected_subject_alignment_floor_met,
        "web.pipeline.selected_source_subject_alignment.v1",
        selected_subject_alignment_summary.as_str(),
        "summary",
        None,
    );
    let aligned_selected_urls = selected_urls
        .iter()
        .filter(|selected| url_in_alignment_set(selected, &semantic_aligned_discovery_urls))
        .cloned()
        .collect::<Vec<_>>();
    emit_web_string_receipts(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "verification",
        "selected_source_subject_alignment_url",
        "web.pipeline.selected_source_subject_alignment.v1",
        "url",
        &aligned_selected_urls,
    );
    verification_checks.push(format!(
        "web_selected_source_subject_alignment_floor_met={}",
        selected_subject_alignment_floor_met
    ));
    if !aligned_selected_urls.is_empty() {
        verification_checks.push(format!(
            "web_selected_source_subject_alignment_url_values={}",
            aligned_selected_urls.join(" | ")
        ));
    }
    if semantic_alignment_required && !selected_subject_alignment_floor_met {
        let error =
            "selected sources failed semantic subject alignment against query contract".to_string();
        verification_checks.push(format!("web_pre_read_payload_error={}", error));
        *success = false;
        *err = Some(format!("ERROR_CLASS=SynthesisFailed {}", error));
        return Ok(());
    }
    let (
        selected_source_total,
        selected_source_compatible,
        selected_source_locality_compatible,
        selected_source_distinct_domains,
        selected_source_low_priority,
        selected_source_quality_floor_met,
        selected_source_low_priority_urls,
    ) = selected_source_structural_metrics(
        Some(&retrieval_contract),
        &query_contract,
        min_sources,
        &selected_urls,
        &merged_hints,
    );
    let raw_query_requires_runtime_scope = retrieval_contract.runtime_locality_required;
    let needs_locality_rebound_search = raw_query_requires_runtime_scope
        && locality_hint.is_some()
        && !selected_source_quality_floor_met
        && !query_contract
            .trim()
            .eq_ignore_ascii_case(query_value.trim());
    let mut rebound_queued = false;
    if needs_locality_rebound_search {
        let rebound_query =
            constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
                query_contract.as_str(),
                Some(&retrieval_contract),
                min_sources,
                &[],
                None,
            );
        let rebound_limit = constraint_grounded_search_limit(query_contract.as_str(), min_sources);
        rebound_queued = !rebound_query.trim().is_empty()
            && !rebound_query
                .trim()
                .eq_ignore_ascii_case(query_value.trim())
            && queue_web_search_from_pipeline(
                agent_state,
                session_id,
                rebound_query.as_str(),
                Some(query_contract.as_str()),
                Some(&retrieval_contract),
                rebound_limit,
            )?;
        verification_checks.push(format!(
            "web_runtime_locality_scope_rebound_search_required={}",
            true
        ));
        verification_checks.push(format!(
            "web_runtime_locality_scope_rebound_search_query={}",
            rebound_query
        ));
        verification_checks.push(format!(
            "web_runtime_locality_scope_rebound_search_queued={}",
            rebound_queued
        ));
    }

    let search_url_attempt = bundle
        .url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
        .into_iter()
        .collect::<Vec<_>>();

    let had_pending_pipeline = agent_state.pending_search_completion.is_some();
    let incoming_pending = PendingSearchCompletion {
        query: query_value,
        query_contract,
        retrieval_contract: Some(retrieval_contract),
        url: bundle.url.clone().unwrap_or_default(),
        started_step: pre_state_step_index,
        started_at_ms,
        deadline_ms: started_at_ms.saturating_add(WEB_PIPELINE_BUDGET_MS),
        candidate_urls: candidate_urls.clone(),
        candidate_source_hints: merged_hints,
        attempted_urls: search_url_attempt,
        blocked_urls: Vec::new(),
        successful_reads: Vec::new(),
        min_sources,
    };
    let mut pending = if let Some(existing) = agent_state.pending_search_completion.clone() {
        merge_pending_search_completion(existing, incoming_pending)
    } else {
        incoming_pending
    };

    let preexisting_queued_reads = queued_web_read_count(agent_state);
    let queued_reads = if !selected_urls.is_empty() {
        queue_web_read_batch_from_pipeline(agent_state, session_id, &selected_urls)?
    } else {
        0
    };
    let total_queued_reads = preexisting_queued_reads.saturating_add(queued_reads);
    let probe_queued = false;
    let probe_budget_ok = true;
    let pending_search_recovery_probe_allowed = false;
    let probe_allowed = false;

    if headline_lookup_mode {
        let (
            headline_total_sources,
            headline_low_priority_sources,
            headline_distinct_domains,
            headline_low_priority_urls,
        ) = headline_selection_quality_metrics(&selected_urls, &pending.candidate_source_hints);
        let headline_quality_floor_met = headline_total_sources >= required_url_count
            && headline_low_priority_sources == 0
            && headline_distinct_domains >= required_url_count;
        verification_checks.push(format!(
            "web_headline_selected_sources_total={}",
            headline_total_sources
        ));
        verification_checks.push(format!(
            "web_headline_selected_sources_low_priority={}",
            headline_low_priority_sources
        ));
        verification_checks.push(format!(
            "web_headline_selected_sources_distinct_domains={}",
            headline_distinct_domains
        ));
        verification_checks.push(format!(
            "web_headline_selected_sources_quality_floor_met={}",
            headline_quality_floor_met
        ));
        if !headline_low_priority_urls.is_empty() {
            verification_checks.push(format!(
                "web_headline_selected_sources_low_priority_urls={}",
                headline_low_priority_urls.join(" | ")
            ));
        }
    }
    verification_checks.push(format!(
        "web_selected_sources_total={}",
        selected_source_total
    ));
    verification_checks.push(format!(
        "web_selected_sources_compatible={}",
        selected_source_compatible
    ));
    verification_checks.push(format!(
        "web_selected_sources_locality_compatible={}",
        selected_source_locality_compatible
    ));
    verification_checks.push(format!(
        "web_selected_sources_distinct_domains={}",
        selected_source_distinct_domains
    ));
    verification_checks.push(format!(
        "web_selected_sources_low_priority={}",
        selected_source_low_priority
    ));
    verification_checks.push(format!(
        "web_selected_sources_quality_floor_met={}",
        selected_source_quality_floor_met
    ));
    if !selected_source_low_priority_urls.is_empty() {
        verification_checks.push(format!(
            "web_selected_sources_low_priority_urls={}",
            selected_source_low_priority_urls.join(" | ")
        ));
    }

    verification_checks.push(format!(
        "web_pre_read_discovery_sources={}",
        discovery_sources.len()
    ));
    verification_checks.push(format!("web_pre_read_required_urls={}", required_url_count));
    verification_checks.push(format!(
        "web_pre_read_selected_urls={}",
        selected_urls.len()
    ));
    verification_checks.push(format!(
        "web_pre_read_candidate_inventory_urls={}",
        candidate_urls.len()
    ));
    verification_checks.push(format!("web_pre_read_batch_target={}", pre_read_target));
    if headline_lookup_mode {
        verification_checks.push(format!(
            "web_headline_read_batch_target={}",
            pre_read_target
        ));
    }
    if !selected_urls.is_empty() {
        verification_checks.push(format!(
            "web_pre_read_selected_url_values={}",
            selected_urls.join(" | ")
        ));
    }
    if !candidate_urls.is_empty() {
        verification_checks.push(format!(
            "web_pre_read_candidate_inventory_url_values={}",
            candidate_urls
                .iter()
                .take(10)
                .cloned()
                .collect::<Vec<_>>()
                .join(" | ")
        ));
    }
    if !discovery_sources.is_empty() {
        let discovery_urls = discovery_sources
            .iter()
            .map(|source| source.url.trim())
            .filter(|url| !url.is_empty())
            .take(10)
            .collect::<Vec<_>>();
        if !discovery_urls.is_empty() {
            verification_checks.push(format!(
                "web_pre_read_discovery_url_values={}",
                discovery_urls.join(" | ")
            ));
        }
    }
    verification_checks.push(format!(
        "web_pre_read_existing_reads_queued={}",
        preexisting_queued_reads
    ));
    verification_checks.push(format!("web_pre_read_batch_reads_queued={}", queued_reads));
    verification_checks.push(format!(
        "web_pre_read_total_reads_queued={}",
        total_queued_reads
    ));
    verification_checks.push(format!(
        "web_pre_read_deterministic_fallback_used={}",
        deterministic_fallback_used
    ));
    verification_checks.push(format!(
        "web_pre_read_deterministic_top_up_used={}",
        deterministic_top_up_used
    ));
    verification_checks.push(format!("web_min_sources={}", min_sources));
    verification_checks.push(format!("web_headline_lookup_mode={}", headline_lookup_mode));
    verification_checks.push(format!(
        "web_query_contract={}",
        pending.query_contract.trim()
    ));
    verification_checks.push(format!("web_pending_query={}", pending.query.trim()));
    verification_checks.push(format!(
        "web_constraint_search_probe_required={}",
        false
    ));
    verification_checks.push(format!(
        "web_constraint_search_probe_allowed={}",
        probe_allowed
    ));
    verification_checks.push(format!(
        "web_constraint_search_probe_recovery_allowed={}",
        pending_search_recovery_probe_allowed
    ));
    verification_checks.push(format!(
        "web_constraint_search_probe_budget_ok={}",
        probe_budget_ok
    ));
    verification_checks.push(format!(
        "web_constraint_search_probe_queued={}",
        probe_queued
    ));
    verification_checks.push(format!(
        "web_pre_read_payload_valid={}",
        payload_error.is_none()
    ));
    verification_checks.push(format!(
        "web_pre_read_payload_synthesis_skipped={}",
        payload_synthesis_skipped
    ));
    if let Some(error) = payload_error.as_deref() {
        verification_checks.push(format!("web_pre_read_payload_error={}", error));
    }

    if total_queued_reads == 0 && !probe_queued && !rebound_queued {
        if let Some(error) = payload_error {
            // Preserve synthesis diagnostics while carrying the explicit state-3 failure signal.
            pending
                .blocked_urls
                .push(format!("ioi://state3-synthesis-error/{}", error));
        }
        let completion_reason = web_pipeline_completion_reason(&pending, web_pipeline_now_ms())
            .unwrap_or(WebPipelineCompletionReason::ExhaustedCandidates);
        append_final_web_completion_receipts(&pending, completion_reason, verification_checks);
        let summary = synthesize_summary(service, &pending, completion_reason).await;
        complete_with_summary(
            agent_state,
            summary,
            success,
            out,
            err,
            completion_summary,
            true,
        );
        emit_completion_gate_status_event(
            service,
            session_id,
            pre_state_step_index,
            intent_id.as_str(),
            true,
            "web_pipeline_search_completion_gate_passed",
        );
        verification_checks.push("cec_completion_gate_emitted=true".to_string());
        verification_checks.push("web_pipeline_active=false".to_string());
        verification_checks.push("terminal_chat_reply_ready=true".to_string());
        return Ok(());
    }

    verification_checks.push("web_pipeline_active=true".to_string());
    verification_checks.push("web_sources_success=0".to_string());
    verification_checks.push("web_sources_blocked=0".to_string());
    verification_checks.push("web_budget_ms=0".to_string());
    agent_state.pending_search_completion = Some(pending);
    agent_state.status = AgentStatus::Running;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        planning_bundle_after_surface_filter, pre_read_batch_urls,
        pre_read_candidate_inventory_target,
    };
    use ioi_types::app::agentic::{WebEvidenceBundle, WebSource};

    #[test]
    fn pre_read_candidate_inventory_target_preserves_multisource_headroom() {
        assert_eq!(
            pre_read_candidate_inventory_target(None, "Tell me today's top news headlines.", 3, 3),
            5
        );
        assert_eq!(
            pre_read_candidate_inventory_target(None, "What's the current price of Bitcoin?", 2, 2),
            3
        );
        assert_eq!(
            pre_read_candidate_inventory_target(None, "What's 247 × 38?", 1, 1),
            1
        );
    }

    #[test]
    fn pre_read_batch_urls_limits_execution_batch_without_discarding_order() {
        let batch = pre_read_batch_urls(
            &[
                "https://example.com/one".to_string(),
                " ".to_string(),
                "https://example.com/two".to_string(),
                "https://example.com/three".to_string(),
            ],
            2,
        );
        assert_eq!(
            batch,
            vec![
                "https://example.com/one".to_string(),
                "https://example.com/two".to_string()
            ]
        );
    }

    #[test]
    fn planning_bundle_preserves_empty_surface_filter_result() {
        let entity_filtered_bundle = WebEvidenceBundle {
            schema_version: 1,
            retrieved_at_ms: 0,
            tool: "web__search".to_string(),
            backend: "edge:bing:http".to_string(),
            query: Some("Find the three best-reviewed Italian restaurants near me.".to_string()),
            url: Some("https://example.com/search".to_string()),
            sources: vec![WebSource {
                source_id: "reddit".to_string(),
                rank: Some(1),
                url: "https://www.reddit.com/r/Italian/".to_string(),
                title: Some("Italian subreddit".to_string()),
                snippet: Some("Off-topic language discussion.".to_string()),
                domain: Some("www.reddit.com".to_string()),
            }],
            source_observations: vec![],
            documents: vec![],
            provider_candidates: vec![],
            retrieval_contract: None,
        };
        let surface_filtered_bundle = WebEvidenceBundle {
            schema_version: 1,
            retrieved_at_ms: 0,
            tool: "web__search".to_string(),
            backend: "edge:bing:http".to_string(),
            query: entity_filtered_bundle.query.clone(),
            url: entity_filtered_bundle.url.clone(),
            sources: vec![],
            source_observations: vec![],
            documents: vec![],
            provider_candidates: vec![],
            retrieval_contract: None,
        };
        let mut verification_checks = Vec::new();

        let planning_bundle = planning_bundle_after_surface_filter(
            &entity_filtered_bundle,
            surface_filtered_bundle,
            &mut verification_checks,
        );

        assert!(planning_bundle.sources.is_empty());
        assert!(planning_bundle.documents.is_empty());
        assert!(verification_checks
            .iter()
            .any(|check| { check == "web_discovery_surface_filter_preserved_empty_bundle=true" }));
        assert!(verification_checks
            .iter()
            .all(|check| { check != "web_discovery_probe_fallback_to_pre_surface_bundle=true" }));
    }
}
