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

fn defer_search_planning_failure_while_recovery_actions_remain(
    agent_state: &mut AgentState,
    verification_checks: &mut Vec<String>,
    success: &mut bool,
    err: &mut Option<String>,
    error: &str,
) -> bool {
    let queued_recovery_actions = queued_web_retrieve_count(agent_state);
    if queued_recovery_actions == 0 || agent_state.pending_search_completion.is_none() {
        return false;
    }

    verification_checks.push(format!("web_pre_read_payload_error={}", error));
    verification_checks.push("web_pre_read_payload_error_nonterminal=true".to_string());
    verification_checks.push(format!(
        "web_queued_web_recovery_actions_remaining={}",
        queued_recovery_actions
    ));
    verification_checks.push("web_pipeline_active=true".to_string());
    verification_checks.push("web_sources_success=0".to_string());
    verification_checks.push("web_sources_blocked=0".to_string());
    verification_checks.push("web_budget_ms=0".to_string());
    *success = true;
    *err = None;
    agent_state.status = AgentStatus::Running;
    true
}

fn local_business_alignment_target_name(
    url: &str,
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
) -> Option<String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return None;
    }
    let hint = selected_url_hint(source_hints, trimmed);
    let title = hint.and_then(|entry| entry.title.as_deref()).unwrap_or_default();
    let excerpt = hint.map(|entry| entry.excerpt.as_str()).unwrap_or_default();
    local_business_target_name_from_source(
        &PendingSearchReadSummary {
            url: trimmed.to_string(),
            title: (!title.trim().is_empty()).then(|| title.trim().to_string()),
            excerpt: excerpt.trim().to_string(),
        },
        locality_hint,
    )
}

fn local_business_selected_url_semantically_aligned(
    selected_url: &str,
    aligned_urls: &[String],
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
) -> bool {
    if url_in_alignment_set(selected_url, aligned_urls) {
        return true;
    }
    let Some(selected_target) =
        local_business_alignment_target_name(selected_url, source_hints, locality_hint)
    else {
        return false;
    };
    aligned_urls.iter().any(|aligned_url| {
        local_business_alignment_target_name(aligned_url, source_hints, locality_hint)
            .map(|aligned_target| aligned_target.eq_ignore_ascii_case(&selected_target))
            .unwrap_or(false)
    })
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

fn deterministic_local_business_direct_detail_urls(
    retrieval_contract: &ioi_types::app::agentic::WebRetrievalContract,
    query_contract: &str,
    min_sources: u32,
    candidate_urls: &[String],
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
    required_url_count: usize,
) -> Vec<String> {
    if !crate::agentic::web::contract_requires_geo_scoped_entity_expansion(retrieval_contract) {
        return candidate_urls
            .iter()
            .take(required_url_count)
            .cloned()
            .collect::<Vec<_>>();
    }

    let mut direct_detail_sources = Vec::new();
    let mut seen = BTreeSet::new();
    for candidate_url in candidate_urls {
        let trimmed = candidate_url.trim();
        if trimmed.is_empty() {
            continue;
        }
        let hint = selected_url_hint(source_hints, trimmed);
        let title = hint.and_then(|entry| entry.title.as_deref()).unwrap_or_default();
        let excerpt = hint.map(|entry| entry.excerpt.as_str()).unwrap_or_default();
        let affordances = retrieval_affordances_with_contract_and_locality_hint(
            Some(retrieval_contract),
            query_contract,
            min_sources.max(1),
            source_hints,
            locality_hint,
            trimmed,
            title,
            excerpt,
        );
        if !affordances.contains(&RetrievalAffordanceKind::DirectCitationRead) {
            continue;
        }
        if !seen.insert(trimmed.to_ascii_lowercase()) {
            continue;
        }
        direct_detail_sources.push(PendingSearchReadSummary {
            url: trimmed.to_string(),
            title: (!title.trim().is_empty()).then(|| title.trim().to_string()),
            excerpt: excerpt.trim().to_string(),
        });
    }

    let target_names = local_business_target_names_from_sources(
        &direct_detail_sources,
        locality_hint,
        required_url_count,
    );
    if target_names.len() < required_url_count {
        return Vec::new();
    }

    selected_local_business_target_sources(
        query_contract,
        &target_names,
        &direct_detail_sources,
        locality_hint,
        required_url_count,
    )
    .into_iter()
    .map(|source| source.url)
    .collect()
}

fn deterministic_local_business_discovery_seed_url(
    retrieval_contract: &ioi_types::app::agentic::WebRetrievalContract,
    query_contract: &str,
    min_sources: u32,
    discovery_sources: &[WebSource],
    source_observations: &[ioi_types::app::agentic::WebSourceObservation],
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
) -> Option<String> {
    if !crate::agentic::web::contract_requires_geo_scoped_entity_expansion(retrieval_contract) {
        return None;
    }

    let projection = build_query_constraint_projection_with_locality_hint(
        query_contract,
        min_sources.max(1),
        source_hints,
        locality_hint,
    );
    let mut ranked = Vec::new();
    for source in discovery_sources {
        let trimmed = source.url.trim();
        if trimmed.is_empty() {
            continue;
        }
        let title = source.title.as_deref().unwrap_or_default();
        let excerpt = source.snippet.as_deref().unwrap_or_default();
        let affordances = retrieval_affordances_with_contract_and_locality_hint(
            Some(retrieval_contract),
            query_contract,
            min_sources.max(1),
            source_hints,
            locality_hint,
            trimmed,
            title,
            excerpt,
        );
        let source_observation = source_observations.iter().find(|observation| {
            observation.url.eq_ignore_ascii_case(trimmed)
                || url_structurally_equivalent(&observation.url, trimmed)
        });
        let observed_seed_affordance = source_observation
            .map(|observation| {
                observation.affordances.contains(
                    &ioi_types::app::agentic::WebRetrievalAffordance::LinkCollection,
                ) && observation.affordances.contains(
                    &ioi_types::app::agentic::WebRetrievalAffordance::CanonicalLinkOut,
                ) && observation.expansion_affordances.iter().any(|affordance| {
                    matches!(
                        affordance,
                        ioi_types::app::agentic::WebSourceExpansionAffordance::JsonLdItemList
                            | ioi_types::app::agentic::WebSourceExpansionAffordance::ChildLinkCollection
                    )
                })
            })
            .unwrap_or(false);
        let collection_surface =
            crate::agentic::desktop::service::step::queue::support::local_business_collection_surface_candidate(
                locality_hint,
                trimmed,
                title,
                excerpt,
            );
        let detail_like_source = local_business_target_name_from_source(
            &PendingSearchReadSummary {
                url: trimmed.to_string(),
                title: (!title.trim().is_empty()).then(|| title.trim().to_string()),
                excerpt: excerpt.trim().to_string(),
            },
            locality_hint,
        )
        .is_some();
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
        if !(collection_surface
            || observed_seed_affordance
            || affordances.contains(&RetrievalAffordanceKind::DiscoveryExpansionSeedRead))
        {
            continue;
        }
        let signals = analyze_source_record_signals(trimmed, title, excerpt);
        ranked.push((
            collection_surface,
            !detail_like_source,
            observed_seed_affordance,
            compatibility.locality_compatible,
            compatibility.compatibility_score,
            signals.relevance_score(false),
            trimmed.to_string(),
        ));
    }

    ranked.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| right.1.cmp(&left.1))
            .then_with(|| right.2.cmp(&left.2))
            .then_with(|| right.3.cmp(&left.3))
            .then_with(|| right.4.cmp(&left.4))
            .then_with(|| right.5.cmp(&left.5))
            .then_with(|| left.6.cmp(&right.6))
    });

    ranked.into_iter().map(|(_, _, _, _, _, _, url)| url).next()
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
    let retrieval_goal = agent_state.goal.trim();
    let retrieval_query_basis = if retrieval_goal.is_empty() {
        query_value.as_str()
    } else {
        retrieval_goal
    };
    let retrieval_contract = if let Some(contract) = pending_contract
        .or_else(|| bundle.retrieval_contract.clone())
    {
        match crate::agentic::web::normalize_web_retrieval_contract(
            retrieval_query_basis,
            Some(query_contract.as_str()),
            contract,
        ) {
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
    } else {
        match crate::agentic::web::derive_web_retrieval_contract(
            retrieval_query_basis,
            Some(query_contract.as_str()),
        ) {
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
                let semantic_alignment_recovery_query = if crate::agentic::web::contract_requires_geo_scoped_entity_expansion(&retrieval_contract) {
                    crate::agentic::desktop::service::step::queue::web_pipeline::local_business_entity_discovery_query_contract(
                        query_contract.as_str(),
                        locality_hint.as_deref(),
                    )
                } else {
                    constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
                        query_contract.as_str(),
                        Some(&retrieval_contract),
                        min_sources,
                        &candidate_source_hints_from_bundle(bundle),
                        locality_hint.as_deref(),
                    )
                };
                let semantic_alignment_recovery_limit =
                    constraint_grounded_search_limit(query_contract.as_str(), min_sources);
                let semantic_alignment_recovery_queued =
                    !semantic_alignment_recovery_query.trim().is_empty()
                        && !semantic_alignment_recovery_query
                            .trim()
                            .eq_ignore_ascii_case(query_value.trim())
                        && queue_web_search_from_pipeline(
                            agent_state,
                            session_id,
                            semantic_alignment_recovery_query.as_str(),
                            Some(query_contract.as_str()),
                            Some(&retrieval_contract),
                            semantic_alignment_recovery_limit,
                        )?;
                verification_checks.push(format!(
                    "web_semantic_subject_alignment_recovery_query={}",
                    semantic_alignment_recovery_query
                ));
                verification_checks.push(format!(
                    "web_semantic_subject_alignment_recovery_limit={}",
                    semantic_alignment_recovery_limit
                ));
                verification_checks.push(format!(
                    "web_semantic_subject_alignment_recovery_queued={}",
                    semantic_alignment_recovery_queued
                ));
                if semantic_alignment_recovery_queued {
                    verification_checks.push("web_pipeline_active=true".to_string());
                    verification_checks.push("web_sources_success=0".to_string());
                    verification_checks.push("web_sources_blocked=0".to_string());
                    verification_checks.push("web_budget_ms=0".to_string());
                    *success = true;
                    *out = Some(format!(
                        "Queued grounded search recovery after discovery alignment failure: {}",
                        semantic_alignment_recovery_query
                    ));
                    *err = None;
                    agent_state.status = AgentStatus::Running;
                    return Ok(());
                }
                if defer_search_planning_failure_while_recovery_actions_remain(
                    agent_state,
                    verification_checks,
                    success,
                    err,
                    &error,
                ) {
                    return Ok(());
                }
                verification_checks.push(format!("web_pre_read_payload_error={}", error));
                *success = false;
                *err = Some(format!("ERROR_CLASS=SynthesisFailed {}", error));
                return Ok(());
            }
        };
    let source_observations = if crate::agentic::web::contract_requires_geo_scoped_entity_expansion(
        &retrieval_contract,
    ) {
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
            if defer_search_planning_failure_while_recovery_actions_remain(
                agent_state,
                verification_checks,
                success,
                err,
                &error,
            ) {
                return Ok(());
            }
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
        effective_semantic_alignment_urls(&discovery_sources)
    } else {
        semantic_aligned_discovery_urls
    };
    let filtered_discovery_hints = discovery_source_hints(&discovery_sources);
    let discovery_hints = if semantic_alignment_required {
        filtered_discovery_hints.clone()
    } else {
        merge_source_hints(
            candidate_source_hints_from_bundle(bundle),
            &filtered_discovery_hints,
        )
    };
    let planning_bundle = planning_bundle_from_discovery_sources(
        bundle,
        &retrieval_contract,
        discovery_sources.clone(),
        &source_observations,
        verification_checks,
    );
    let pre_read_target = required_url_count;
    let deterministic_plan =
        pre_read_candidate_plan_from_bundle_with_contract_and_locality_hint_and_recovery_mode(
            Some(&retrieval_contract),
            &query_contract,
            min_sources,
            &planning_bundle,
            locality_hint.as_deref(),
            true,
        );
    let deterministic_direct_selected_urls = deterministic_local_business_direct_detail_urls(
        &retrieval_contract,
        &query_contract,
        min_sources,
        &deterministic_plan.candidate_urls,
        &deterministic_plan.candidate_source_hints,
        locality_hint.as_deref(),
        required_url_count,
    );
    let deterministic_discovery_seed_url = deterministic_local_business_discovery_seed_url(
        &retrieval_contract,
        &query_contract,
        min_sources,
        &discovery_sources,
        &source_observations,
        &deterministic_plan.candidate_source_hints,
        locality_hint.as_deref(),
    );
    let deterministic_selection_mode = if crate::agentic::web::contract_requires_geo_scoped_entity_expansion(
        &retrieval_contract,
    ) && required_url_count > 1
        && deterministic_direct_selected_urls.len() < required_url_count
        && deterministic_discovery_seed_url.is_some()
    {
        PreReadSelectionMode::DiscoverySeed
    } else {
        PreReadSelectionMode::DirectDetail
    };
    let deterministic_selected_urls = match deterministic_selection_mode {
        PreReadSelectionMode::DirectDetail => {
            if crate::agentic::web::contract_requires_geo_scoped_entity_expansion(
                &retrieval_contract,
            ) {
                deterministic_direct_selected_urls.clone()
            } else {
                deterministic_plan
                    .candidate_urls
                    .iter()
                    .take(required_url_count)
                    .cloned()
                    .collect::<Vec<_>>()
            }
        }
        PreReadSelectionMode::DiscoverySeed => deterministic_discovery_seed_url
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
    };
    let deterministic_selection_available = match deterministic_selection_mode {
        PreReadSelectionMode::DirectDetail => {
            deterministic_selected_urls.len() == required_url_count
        }
        PreReadSelectionMode::DiscoverySeed => !deterministic_selected_urls.is_empty(),
    };
    let payload_error: Option<String> = None;
    let payload_synthesis_skipped: bool;
    let deterministic_fallback_used: bool;
    let deterministic_top_up_used =
        deterministic_plan.candidate_urls.len() > deterministic_selected_urls.len();
    let selection = if deterministic_selection_available {
        payload_synthesis_skipped = true;
        deterministic_fallback_used = false;
        PreReadSelectionResponse {
            selection_mode: deterministic_selection_mode,
            urls: deterministic_selected_urls.clone(),
        }
    } else {
        payload_synthesis_skipped = false;
        deterministic_fallback_used = false;
        match synthesize_pre_read_selection(
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
                if defer_search_planning_failure_while_recovery_actions_remain(
                    agent_state,
                    verification_checks,
                    success,
                    err,
                    &error,
                ) {
                    return Ok(());
                }
                verification_checks.push(format!("web_pre_read_payload_error={}", error));
                *success = false;
                *err = Some(format!("ERROR_CLASS=SynthesisFailed {}", error));
                return Ok(());
            }
        }
    };
    if selection.urls.is_empty() {
        let error = "typed pre-read selection returned no admissible URLs".to_string();
        if defer_search_planning_failure_while_recovery_actions_remain(
            agent_state,
            verification_checks,
            success,
            err,
            &error,
        ) {
            return Ok(());
        }
        verification_checks.push(format!("web_pre_read_payload_error={}", error));
        *success = false;
        *err = Some(format!("ERROR_CLASS=SynthesisFailed {}", error));
        return Ok(());
    }
    let merged_hints =
        merge_source_hints(discovery_hints, &deterministic_plan.candidate_source_hints);
    let mut selected_urls = selection.urls;
    let selected_urls_before_resolution = selected_urls.clone();
    let allowed_resolution_urls =
        semantic_alignment_required.then_some(semantic_aligned_discovery_urls.as_slice());
    resolve_selected_urls_from_hints(&mut selected_urls, &merged_hints, allowed_resolution_urls);
    let candidate_urls = if payload_synthesis_skipped {
        deterministic_plan.candidate_urls.clone()
    } else {
        selected_urls.clone()
    };
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
    emit_web_string_receipts(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "verification",
        "pre_read_selected_url_raw",
        "web.pipeline.pre_read.selection.v1",
        "url",
        &selected_urls_before_resolution,
    );
    emit_web_string_receipts(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "verification",
        "pre_read_selected_url",
        "web.pipeline.pre_read.selection.v1",
        "url",
        &selected_urls,
    );
    verification_checks.push(format!("web_pre_read_selection_mode={}", selection_mode));
    let geo_scoped_entity_expansion =
        crate::agentic::web::contract_requires_geo_scoped_entity_expansion(&retrieval_contract);
    let aligned_selected_urls = selected_urls
        .iter()
        .filter(|selected| {
            if geo_scoped_entity_expansion {
                local_business_selected_url_semantically_aligned(
                    selected,
                    &semantic_aligned_discovery_urls,
                    &merged_hints,
                    locality_hint.as_deref(),
                )
            } else {
                url_in_alignment_set(selected, &semantic_aligned_discovery_urls)
            }
        })
        .cloned()
        .collect::<Vec<_>>();
    let selected_subject_alignment_floor_met = if semantic_alignment_required {
        let minimum_aligned_selection =
            if geo_scoped_entity_expansion {
                1
            } else {
                required_url_count
            };
        selected_urls.len() >= minimum_aligned_selection
            && aligned_selected_urls.len() == selected_urls.len()
    } else {
        true
    };
    let selected_subject_alignment_count = aligned_selected_urls.len();
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
        if defer_search_planning_failure_while_recovery_actions_remain(
            agent_state,
            verification_checks,
            success,
            err,
            &error,
        ) {
            return Ok(());
        }
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
        let rebound_query = if crate::agentic::web::contract_requires_geo_scoped_entity_expansion(&retrieval_contract) {
            crate::agentic::desktop::service::step::queue::web_pipeline::local_business_entity_discovery_query_contract(
                query_contract.as_str(),
                locality_hint.as_deref(),
            )
        } else {
            constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
                query_contract.as_str(),
                Some(&retrieval_contract),
                min_sources,
                &[],
                None,
            )
        };
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
        queue_web_read_batch_from_pipeline(
            agent_state,
            session_id,
            &selected_urls,
            pending_web_read_allows_browser_fallback(&pending),
        )?
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
    if !selected_urls_before_resolution.is_empty() {
        verification_checks.push(format!(
            "web_pre_read_selected_url_raw_values={}",
            selected_urls_before_resolution.join(" | ")
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
    verification_checks.push(format!(
        "web_pre_read_local_business_direct_detail_selected={}",
        deterministic_direct_selected_urls.len()
    ));
    verification_checks.push(format!(
        "web_pre_read_local_business_discovery_seed_available={}",
        deterministic_discovery_seed_url.is_some()
    ));
    if let Some(seed_url) = deterministic_discovery_seed_url.as_deref() {
        verification_checks.push(format!(
            "web_pre_read_local_business_discovery_seed_url={}",
            seed_url
        ));
    }
    verification_checks.push(format!("web_min_sources={}", min_sources));
    verification_checks.push(format!("web_headline_lookup_mode={}", headline_lookup_mode));
    verification_checks.push(format!(
        "web_query_contract={}",
        pending.query_contract.trim()
    ));
    verification_checks.push(format!("web_pending_query={}", pending.query.trim()));
    verification_checks.push(format!("web_constraint_search_probe_required={}", false));
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
        let selection = synthesize_summary(service, &pending, completion_reason).await;
        append_summary_selection_checks(&selection, verification_checks);
        let summary = selection.summary;
        let final_facts = selection.facts;
        crate::agentic::desktop::service::step::queue::emit_final_web_completion_contract_receipts(
            service,
            session_id,
            pre_state_step_index,
            intent_id.as_str(),
            &final_facts,
        );
        append_final_web_completion_receipts_with_rendered_summary(
            &pending,
            completion_reason,
            &summary,
            verification_checks,
        );
        if !selection.contract_ready {
            emit_completion_gate_status_event(
                service,
                session_id,
                pre_state_step_index,
                intent_id.as_str(),
                false,
                "receipt::final_output_contract_ready=true",
            );
            verification_checks.push("cec_completion_gate_emitted=true".to_string());
            verification_checks.push("execution_contract_gate_blocked=true".to_string());
            verification_checks.push(
                "execution_contract_missing_keys=receipt::final_output_contract_ready=true"
                    .to_string(),
            );
            verification_checks
                .push("web_pipeline_terminalization_blocked_on_rendered_output=true".to_string());
            verification_checks.push("web_pipeline_active=true".to_string());
            verification_checks.push("terminal_chat_reply_ready=false".to_string());
            agent_state.pending_search_completion = Some(pending);
            agent_state.status = AgentStatus::Running;
            return Ok(());
        }
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
mod planning_regression_tests {
    use super::*;

    fn restaurant_query_contract() -> String {
        "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus."
            .to_string()
    }

    fn restaurant_retrieval_contract() -> ioi_types::app::agentic::WebRetrievalContract {
        crate::agentic::web::derive_web_retrieval_contract(&restaurant_query_contract(), None)
            .expect("retrieval contract")
    }

    fn restaurant_source_hints() -> Vec<PendingSearchReadSummary> {
        vec![
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
        ]
    }

    #[test]
    fn deterministic_local_business_direct_selection_requires_distinct_entities() {
        let query_contract = restaurant_query_contract();
        let retrieval_contract = restaurant_retrieval_contract();
        let source_hints = restaurant_source_hints();
        let candidate_urls = source_hints
            .iter()
            .map(|hint| hint.url.clone())
            .collect::<Vec<_>>();

        let selected = deterministic_local_business_direct_detail_urls(
            &retrieval_contract,
            &query_contract,
            3,
            &candidate_urls,
            &source_hints,
            Some("Anderson, SC"),
            3,
        );

        assert!(selected.is_empty(), "{selected:?}");
    }

    #[test]
    fn deterministic_local_business_seed_selection_finds_listing_surface() {
        let query_contract = restaurant_query_contract();
        let retrieval_contract = restaurant_retrieval_contract();
        let source_hints = restaurant_source_hints();

        let seed_url = deterministic_local_business_discovery_seed_url(
            &retrieval_contract,
            &query_contract,
            3,
            &vec![
                WebSource {
                    source_id: "1".to_string(),
                    rank: Some(1),
                    url: "https://www.yelp.com/biz/dolce-vita-italian-bistro-and-pizzeria-anderson"
                        .to_string(),
                    title: Some(
                        "Dolce Vita Italian Bistro and Pizzeria - Anderson, SC - Yelp"
                            .to_string(),
                    ),
                    snippet: Some(
                        "Italian restaurant in Anderson, SC with pasta, pizza, and baked dishes."
                            .to_string(),
                    ),
                    domain: Some("www.yelp.com".to_string()),
                },
                WebSource {
                    source_id: "2".to_string(),
                    rank: Some(2),
                    url: "https://www.tripadvisor.com/Restaurants-g30090-c26-Anderson_South_Carolina.html".to_string(),
                    title: Some("THE 10 BEST Italian Restaurants in Anderson (Updated 2026) - Tripadvisor".to_string()),
                    snippet: Some(
                        "Best Italian Restaurants in Anderson, South Carolina: find reviews for Dolce Vita, The Red Tomato, and Brothers Italian Cuisine."
                            .to_string(),
                    ),
                    domain: Some("www.tripadvisor.com".to_string()),
                },
            ],
            &[],
            &source_hints,
            Some("Anderson, SC"),
        );

        assert_eq!(
            seed_url.as_deref(),
            Some("https://www.tripadvisor.com/Restaurants-g30090-c26-Anderson_South_Carolina.html")
        );
    }
}
