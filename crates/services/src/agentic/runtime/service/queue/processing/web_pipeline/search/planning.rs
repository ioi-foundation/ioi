include!("planning/support.rs");

fn pre_read_should_use_direct_candidate_recovery_selection(
    candidate_recovery_selection_available: bool,
    pre_read_payload_sources_len: usize,
) -> bool {
    candidate_recovery_selection_available && pre_read_payload_sources_len == 0
}

pub(crate) async fn maybe_handle_web_search(
    service: &RuntimeAgentService,
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
    let intent_id = resolved_intent_id(agent_state);
    if complete_web_search_after_duplicate_no_effect_if_ready(
        service,
        agent_state,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        tool_name,
        is_gated,
        success,
        out,
        err,
        completion_summary,
        verification_checks,
    )
    .await?
    {
        return Ok(());
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
    let retrieval_contract =
        if let Some(contract) = pending_contract.or_else(|| bundle.retrieval_contract.clone()) {
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
                let semantic_alignment_recovery_query = semantic_alignment_recovery_query(
                    query_contract.as_str(),
                    query_value.as_str(),
                    &retrieval_contract,
                    min_sources,
                    &candidate_source_hints_from_bundle(bundle),
                    locality_hint.as_deref(),
                );
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
    let discovery_sources = match expand_evidence_authority_link_out_sources(
        &retrieval_contract,
        &query_contract,
        discovery_sources,
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
    let candidate_recovery_plan =
        pre_read_candidate_plan_from_bundle_with_contract_and_locality_hint_and_recovery_mode(
            Some(&retrieval_contract),
            &query_contract,
            min_sources,
            &planning_bundle,
            locality_hint.as_deref(),
            true,
        );
    let mut candidate_recovery_plan = merge_candidate_recovery_plan_with_pending_inventory(
        &retrieval_contract,
        &query_contract,
        min_sources,
        locality_hint.as_deref(),
        agent_state.pending_search_completion.as_ref(),
        candidate_recovery_plan,
        verification_checks,
    );
    if query_requires_market_quote_grounding(&query_contract) {
        let direct_quote_hints = market_quote_grounding_direct_source_hints(&query_contract);
        for hint in direct_quote_hints {
            if !candidate_recovery_plan
                .candidate_urls
                .iter()
                .any(|url| url.eq_ignore_ascii_case(&hint.url))
            {
                candidate_recovery_plan.candidate_urls.push(hint.url.clone());
            }
            if !candidate_recovery_plan
                .candidate_source_hints
                .iter()
                .any(|existing| existing.url.eq_ignore_ascii_case(&hint.url))
            {
                candidate_recovery_plan.candidate_source_hints.push(hint);
            }
        }
        candidate_recovery_plan.total_candidates = candidate_recovery_plan
            .total_candidates
            .max(candidate_recovery_plan.candidate_urls.len());
    }
    let pre_read_payload_source_hints = ordered_source_hints_with_selected_urls_first(
        &candidate_recovery_plan.candidate_urls,
        &merge_source_hints(
            discovery_hints.clone(),
            &candidate_recovery_plan.candidate_source_hints,
        ),
    );
    let pre_read_payload_sources = pre_read_selection_sources_from_planning_context(
        &planning_bundle,
        &pre_read_payload_source_hints,
    );
    let pre_read_payload_source_observations =
        pre_read_selection_source_observations_from_planning_context(
            &planning_bundle,
            &pre_read_payload_sources,
        );
    let pre_read_payload_seed_hints = merge_source_hints(
        source_hints_from_web_sources(&pre_read_payload_sources),
        &pre_read_payload_source_hints,
    );
    let geo_seed_mode_applicable =
        crate::agentic::web::contract_requires_geo_scoped_entity_expansion(&retrieval_contract)
            && required_url_count > 1;
    let candidate_recovery_direct_selected_urls = candidate_recovery_local_business_direct_detail_urls(
        &retrieval_contract,
        &query_contract,
        min_sources,
        &candidate_recovery_plan.candidate_urls,
        &candidate_recovery_plan.candidate_source_hints,
        locality_hint.as_deref(),
        required_url_count,
    );
    let candidate_recovery_discovery_seed_url = candidate_recovery_local_business_discovery_seed_url(
        &retrieval_contract,
        &query_contract,
        min_sources,
        &discovery_sources,
        &source_observations,
        &candidate_recovery_plan.candidate_source_hints,
        locality_hint.as_deref(),
    );
    let candidate_recovery_selection_ready = if geo_seed_mode_applicable {
        candidate_recovery_direct_selected_urls.len() >= required_url_count
            || candidate_recovery_discovery_seed_url.is_some()
    } else {
        candidate_recovery_plan.candidate_urls.len() >= required_url_count
    };
    let search_url_attempt = search_attempt_urls_from_bundle(
        bundle,
        &candidate_recovery_plan.candidate_urls,
        &pre_read_payload_source_hints,
    );
    let market_quote_recovery_required = query_requires_market_quote_grounding(&query_contract)
        && market_quote_hint_coverage_count(
            &query_contract,
            &candidate_recovery_plan.candidate_source_hints,
        ) < market_quote_hint_coverage_floor(&query_contract, min_sources);
    if market_quote_recovery_required {
        let market_quote_recovery_query = market_quote_missing_group_search_query(
            &query_contract,
            &candidate_recovery_plan.candidate_source_hints,
        )
        .unwrap_or_default();
        let market_quote_recovery_limit =
            constraint_grounded_search_limit(query_contract.as_str(), min_sources);
        let market_quote_recovery_marker = format!(
            "search://market_quote/{}",
            market_quote_recovery_query.trim().to_ascii_lowercase()
        );
        let recovery_pending_seed = PendingSearchCompletion {
            query: query_value.clone(),
            query_contract: query_contract.clone(),
            retrieval_contract: Some(retrieval_contract.clone()),
            url: bundle.url.clone().unwrap_or_default(),
            started_step: pre_state_step_index,
            started_at_ms,
            deadline_ms: started_at_ms.saturating_add(WEB_PIPELINE_BUDGET_MS),
            candidate_urls: candidate_recovery_plan.candidate_urls.clone(),
            candidate_source_hints: merge_source_hints(
                discovery_hints.clone(),
                &candidate_recovery_plan.candidate_source_hints,
            ),
            attempted_urls: search_url_attempt.clone(),
            blocked_urls: Vec::new(),
            successful_reads: Vec::new(),
            min_sources,
        };
        let recovery_pending =
            if let Some(existing) = agent_state.pending_search_completion.clone() {
                merge_pending_search_completion(existing, recovery_pending_seed)
            } else {
                recovery_pending_seed
            };
        let market_quote_recovery_already_attempted = recovery_pending
            .attempted_urls
            .iter()
            .any(|url| url.eq_ignore_ascii_case(&market_quote_recovery_marker));
        let market_quote_recovery_queued = !market_quote_recovery_query.trim().is_empty()
            && !market_quote_recovery_already_attempted
            && !market_quote_recovery_query
                .trim()
                .eq_ignore_ascii_case(query_value.trim())
            && queue_web_search_from_pipeline(
                agent_state,
                session_id,
                market_quote_recovery_query.as_str(),
                Some(query_contract.as_str()),
                Some(&retrieval_contract),
                market_quote_recovery_limit,
            )?;
        verification_checks.push("web_market_quote_recovery_required=true".to_string());
        verification_checks.push(format!(
            "web_market_quote_recovery_query={}",
            market_quote_recovery_query
        ));
        verification_checks.push(format!(
            "web_market_quote_recovery_limit={}",
            market_quote_recovery_limit
        ));
        verification_checks.push(format!(
            "web_market_quote_recovery_already_attempted={}",
            market_quote_recovery_already_attempted
        ));
        verification_checks.push(format!(
            "web_market_quote_recovery_queued={}",
            market_quote_recovery_queued
        ));
        if market_quote_recovery_queued {
            let mut recovery_pending = recovery_pending;
            recovery_pending
                .attempted_urls
                .push(market_quote_recovery_marker);
            agent_state.pending_search_completion = Some(recovery_pending);
            verification_checks.push("web_pipeline_active=true".to_string());
            verification_checks.push("web_sources_success=0".to_string());
            verification_checks.push("web_sources_blocked=0".to_string());
            verification_checks.push("web_budget_ms=0".to_string());
            *success = true;
            *out = Some(format!(
                "Queued market quote grounding search before pre-read selection: {}",
                market_quote_recovery_query
            ));
            *err = None;
            agent_state.status = AgentStatus::Running;
            return Ok(());
        }
        agent_state.pending_search_completion = Some(recovery_pending);
    }
    let evidence_probe_recovery_required = evidence_grounded_recovery_required(
        &query_contract,
        &retrieval_contract,
        &candidate_recovery_plan,
        required_url_count,
        candidate_recovery_selection_ready,
    );
    if evidence_probe_recovery_required {
        let authority_hint_read_recovery_urls = evidence_authority_hint_read_recovery_urls(
            &retrieval_contract,
            query_contract.as_str(),
            min_sources,
            &candidate_recovery_plan,
            &[],
            &discovery_hints,
            locality_hint.as_deref(),
            required_url_count,
        );
        let evidence_probe_recovery_source_hints = evidence_probe_recovery_source_hints(
            &discovery_hints,
            &candidate_recovery_plan.probe_source_hints,
            &authority_hint_read_recovery_urls,
        );
        let evidence_probe_recovery_query =
            constraint_grounded_probe_query_with_contract_and_hints_and_locality_hint(
                query_contract.as_str(),
                Some(&retrieval_contract),
                min_sources,
                &evidence_probe_recovery_source_hints,
                query_value.trim(),
                locality_hint.as_deref(),
            );
        let evidence_probe_recovery_limit =
            constraint_grounded_search_limit(query_contract.as_str(), min_sources);
        let authority_hint_read_recovery_site_terms = if crate::agentic::runtime::service::queue::support::query_probe_document_authority_site_terms(
            query_contract.as_str(),
            Some(&retrieval_contract),
            &evidence_probe_recovery_source_hints,
        )
        .is_empty()
        {
            Vec::new()
        } else {
            authority_hint_read_recovery_site_terms(&authority_hint_read_recovery_urls)
        };
        let mut evidence_probe_recovery_query_value =
            evidence_probe_recovery_query.clone().unwrap_or_default();
        if !evidence_probe_recovery_query_value.trim().is_empty()
            && !authority_hint_read_recovery_site_terms.is_empty()
        {
            evidence_probe_recovery_query_value = append_missing_query_terms(
                &evidence_probe_recovery_query_value,
                &authority_hint_read_recovery_site_terms,
            );
        }
        let recovery_pending_seed = PendingSearchCompletion {
            query: query_value.clone(),
            query_contract: query_contract.clone(),
            retrieval_contract: Some(retrieval_contract.clone()),
            url: bundle.url.clone().unwrap_or_default(),
            started_step: pre_state_step_index,
            started_at_ms,
            deadline_ms: started_at_ms.saturating_add(WEB_PIPELINE_BUDGET_MS),
            candidate_urls: candidate_recovery_plan.candidate_urls.clone(),
            candidate_source_hints: merge_source_hints(
                discovery_hints.clone(),
                &candidate_recovery_plan.candidate_source_hints,
            ),
            attempted_urls: search_url_attempt.clone(),
            blocked_urls: Vec::new(),
            successful_reads: Vec::new(),
            min_sources,
        };
        let mut recovery_pending =
            if let Some(existing) = agent_state.pending_search_completion.clone() {
                merge_pending_search_completion(existing, recovery_pending_seed)
            } else {
                recovery_pending_seed
            };
        let authority_hint_read_recovery_queued = if authority_hint_read_recovery_urls.is_empty() {
            false
        } else {
            queue_web_read_batch_from_pipeline(
                agent_state,
                session_id,
                &authority_hint_read_recovery_urls,
                pending_web_read_allows_browser_fallback(&recovery_pending),
            )? > 0
        };
        let evidence_probe_recovery_already_attempted = evidence_grounded_recovery_attempted(
            Some(&recovery_pending),
            evidence_probe_recovery_query_value.as_str(),
        );
        let evidence_probe_recovery_queued = !evidence_probe_recovery_query_value.trim().is_empty()
            && !evidence_probe_recovery_already_attempted
            && !evidence_probe_recovery_query_value
                .trim()
                .eq_ignore_ascii_case(query_value.trim())
            && queue_web_search_from_pipeline(
                agent_state,
                session_id,
                evidence_probe_recovery_query_value.as_str(),
                Some(query_contract.as_str()),
                Some(&retrieval_contract),
                evidence_probe_recovery_limit,
            )?;
        verification_checks.push(format!("web_pre_read_grounded_recovery_required={}", true));
        verification_checks.push(format!(
            "web_pre_read_authority_hint_read_recovery_candidate_urls={}",
            authority_hint_read_recovery_urls.len()
        ));
        if !authority_hint_read_recovery_urls.is_empty() {
            verification_checks.push(format!(
                "web_pre_read_authority_hint_read_recovery_url_values={}",
                authority_hint_read_recovery_urls.join(" | ")
            ));
        }
        verification_checks.push(format!(
            "web_pre_read_authority_hint_read_recovery_queued={}",
            authority_hint_read_recovery_queued
        ));
        verification_checks.push(format!(
            "web_pre_read_grounded_recovery_query={}",
            evidence_probe_recovery_query_value
        ));
        verification_checks.push(format!(
            "web_pre_read_grounded_recovery_limit={}",
            evidence_probe_recovery_limit
        ));
        verification_checks.push(format!(
            "web_pre_read_grounded_recovery_already_attempted={}",
            evidence_probe_recovery_already_attempted
        ));
        verification_checks.push(format!(
            "web_pre_read_grounded_recovery_queued={}",
            evidence_probe_recovery_queued
        ));
        if authority_hint_read_recovery_queued || evidence_probe_recovery_queued {
            mark_evidence_grounded_recovery_attempt(
                &mut recovery_pending,
                evidence_probe_recovery_query_value.as_str(),
            );
            agent_state.pending_search_completion = Some(recovery_pending);
            verification_checks.push("web_pipeline_active=true".to_string());
            verification_checks.push("web_sources_success=0".to_string());
            verification_checks.push("web_sources_blocked=0".to_string());
            verification_checks.push("web_budget_ms=0".to_string());
            *success = true;
            *out = Some(if authority_hint_read_recovery_queued {
                format!(
                    "Queued authority read recovery before pre-read selection: {}",
                    authority_hint_read_recovery_urls.join(", ")
                )
            } else {
                format!(
                    "Queued grounded search recovery before pre-read selection: {}",
                    evidence_probe_recovery_query_value
                )
            });
            *err = None;
            agent_state.status = AgentStatus::Running;
            return Ok(());
        }
        agent_state.pending_search_completion = Some(recovery_pending);
    }
    let candidate_recovery_selection_mode =
        if crate::agentic::web::contract_requires_geo_scoped_entity_expansion(&retrieval_contract)
            && required_url_count > 1
            && candidate_recovery_direct_selected_urls.len() < required_url_count
            && candidate_recovery_discovery_seed_url.is_some()
        {
            PreReadSelectionMode::DiscoverySeed
        } else {
            PreReadSelectionMode::DirectDetail
        };
    let candidate_recovery_selected_urls = match candidate_recovery_selection_mode {
        PreReadSelectionMode::DirectDetail => {
            if crate::agentic::web::contract_requires_geo_scoped_entity_expansion(
                &retrieval_contract,
            ) {
                candidate_recovery_direct_selected_urls.clone()
            } else {
                distinct_domain_preserving_selected_urls(
                    &retrieval_contract,
                    query_contract.as_str(),
                    &candidate_recovery_plan.candidate_urls,
                    required_url_count,
                )
            }
        }
        PreReadSelectionMode::DiscoverySeed => candidate_recovery_discovery_seed_url
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
    };
    let candidate_recovery_selection_available = match candidate_recovery_selection_mode {
        PreReadSelectionMode::DirectDetail => {
            candidate_recovery_selected_urls.len() == required_url_count
        }
        PreReadSelectionMode::DiscoverySeed => !candidate_recovery_selected_urls.is_empty(),
    };
    let mut payload_error: Option<String> = None;
    let payload_synthesis_skipped: bool;
    let candidate_recovery_fallback_used: bool;
    let candidate_recovery_top_up_used =
        candidate_recovery_plan.candidate_urls.len() > candidate_recovery_selected_urls.len();
    let selection = if pre_read_should_use_direct_candidate_recovery_selection(
        candidate_recovery_selection_available,
        pre_read_payload_sources.len(),
    ) {
        payload_synthesis_skipped = true;
        candidate_recovery_fallback_used = false;
        PreReadSelectionResponse {
            selection_mode: candidate_recovery_selection_mode,
            urls: candidate_recovery_selected_urls.clone(),
        }
    } else {
        payload_synthesis_skipped = false;
        candidate_recovery_fallback_used = false;
        match synthesize_pre_read_selection(
            service,
            Some(&retrieval_contract),
            &query_contract,
            required_url_count,
            &pre_read_payload_sources,
            &pre_read_payload_source_observations,
        )
        .await
        {
            Ok(selection) => selection,
            Err(error) => {
                payload_error = Some(error.clone());
                if let Some(pending) = agent_state.pending_search_completion.as_mut() {
                    let seeded = seed_pending_inventory_from_pre_read_payload_hints(
                        pending,
                        &pre_read_payload_seed_hints,
                    );
                    verification_checks.push(format!(
                        "web_pre_read_payload_inventory_seeded_on_error={}",
                        seeded
                    ));
                    if seeded {
                        verification_checks.push(format!(
                            "web_pre_read_payload_inventory_seeded_candidate_urls={}",
                            pending.candidate_urls.len()
                        ));
                    }
                }
                if let Some(recovered_selection) = recovered_pre_read_selection_after_payload_error(
                    &retrieval_contract,
                    query_contract.as_str(),
                    required_url_count,
                    &candidate_recovery_selected_urls,
                    &candidate_recovery_plan,
                    &pre_read_payload_seed_hints,
                ) {
                    verification_checks.push(format!("web_pre_read_payload_error={}", error));
                    verification_checks.push(
                        "web_pre_read_candidate_selection_after_payload_error=true".to_string(),
                    );
                    recovered_selection
                } else {
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
        merge_source_hints(discovery_hints, &candidate_recovery_plan.candidate_source_hints);
    let mut selected_urls = selection.urls;
    let selected_urls_before_resolution = selected_urls.clone();
    let allowed_resolution_urls =
        semantic_alignment_required.then_some(semantic_aligned_discovery_urls.as_slice());
    resolve_selected_urls_from_hints(&mut selected_urls, &merged_hints, allowed_resolution_urls);
    let merged_candidate_urls = merge_candidate_urls_preserving_order(
        &selected_urls,
        &candidate_recovery_plan.candidate_urls,
        &semantic_aligned_discovery_urls,
    );
    if !crate::agentic::web::contract_requires_geo_scoped_entity_expansion(&retrieval_contract) {
        selected_urls = distinct_domain_preserving_selected_urls(
            &retrieval_contract,
            query_contract.as_str(),
            &merged_candidate_urls,
            required_url_count,
        );
    }
    let candidate_urls = if payload_synthesis_skipped
        || query_requires_market_quote_grounding(query_contract.as_str())
    {
        merged_candidate_urls
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
    let aligned_selected_urls = selected_source_alignment_urls(
        query_contract.as_str(),
        &retrieval_contract,
        &selected_urls,
        &semantic_aligned_discovery_urls,
        &merged_hints,
        locality_hint.as_deref(),
    );
    let selected_subject_alignment_floor_met = if semantic_alignment_required {
        let minimum_aligned_selection = if geo_scoped_entity_expansion {
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
        let rebound_query = if crate::agentic::web::contract_requires_geo_scoped_entity_expansion(
            &retrieval_contract,
        ) {
            crate::agentic::runtime::service::queue::web_pipeline::local_business_entity_discovery_query_contract(
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
    verification_checks.push(format!(
        "web_pre_read_payload_sources={}",
        pre_read_payload_sources.len()
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
        "web_pre_read_candidate_fallback_used={}",
        candidate_recovery_fallback_used
    ));
    verification_checks.push(format!(
        "web_pre_read_candidate_top_up_used={}",
        candidate_recovery_top_up_used
    ));
    verification_checks.push(format!(
        "web_pre_read_local_business_direct_detail_selected={}",
        candidate_recovery_direct_selected_urls.len()
    ));
    verification_checks.push(format!(
        "web_pre_read_local_business_discovery_seed_available={}",
        candidate_recovery_discovery_seed_url.is_some()
    ));
    if let Some(seed_url) = candidate_recovery_discovery_seed_url.as_deref() {
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
        let completion_reason = web_pipeline_completion_reason(&pending, web_pipeline_now_ms());
        let terminal_completion_reason = completion_reason.filter(|reason| {
            crate::agentic::runtime::service::queue::support::web_pipeline_completion_terminalization_allowed(
                &pending,
                *reason,
                total_queued_reads,
            )
        });
        let selection_reason = terminal_completion_reason
            .or(completion_reason)
            .unwrap_or(WebPipelineCompletionReason::ExhaustedCandidates);
        mark_web_pipeline_waiting_for_model_answer(
            service,
            agent_state,
            session_id,
            pre_state_step_index,
            intent_id.as_str(),
            pending,
            selection_reason,
            out,
            err,
            completion_summary,
            verification_checks,
        );
        *success = true;
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
#[path = "planning/planning_regression_tests.rs"]
mod planning_regression_tests;
