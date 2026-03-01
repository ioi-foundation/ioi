use super::*;

fn projection_candidate_url_allowed(raw: &str) -> bool {
    let trimmed = raw.trim();
    !trimmed.is_empty()
        && is_citable_web_url(trimmed)
        && !is_search_hub_url(trimmed)
        && !is_multi_item_listing_url(trimmed)
        && looks_like_deep_article_url(trimmed)
}

fn resolved_hint_candidate_url(hint: &PendingSearchReadSummary) -> Option<String> {
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

fn collect_projection_candidate_urls(
    selected_urls: &[String],
    merged_hints: &[PendingSearchReadSummary],
    target_count: usize,
    distinct_domain_floor: usize,
    blocked_domains: &std::collections::BTreeSet<String>,
) -> Vec<String> {
    let mut ordered_candidates = Vec::new();
    for url in selected_urls {
        let trimmed = url.trim();
        if !projection_candidate_url_allowed(trimmed) {
            continue;
        }
        if normalized_domain_key(trimmed)
            .map(|domain| blocked_domains.contains(&domain))
            .unwrap_or(false)
        {
            continue;
        }
        let _ = push_unique_selected_url(&mut ordered_candidates, trimmed);
    }
    for hint in merged_hints {
        let Some(candidate) = resolved_hint_candidate_url(hint) else {
            continue;
        };
        if normalized_domain_key(&candidate)
            .map(|domain| blocked_domains.contains(&domain))
            .unwrap_or(false)
        {
            continue;
        }
        let _ = push_unique_selected_url(&mut ordered_candidates, &candidate);
    }

    let target = target_count.max(1);
    let domain_floor = distinct_domain_floor.min(target);
    let mut output = Vec::new();
    let mut seen_domains = std::collections::BTreeSet::new();

    if domain_floor > 1 {
        for candidate in &ordered_candidates {
            if output.len() >= target || seen_domains.len() >= domain_floor {
                break;
            }
            let domain_key = normalized_domain_key(candidate)
                .unwrap_or_else(|| candidate.trim().to_ascii_lowercase());
            if !seen_domains.insert(domain_key) {
                continue;
            }
            let _ = push_unique_selected_url(&mut output, candidate);
        }
    }

    for candidate in &ordered_candidates {
        if output.len() >= target {
            break;
        }
        let _ = push_unique_selected_url(&mut output, candidate);
    }

    output
}

fn pre_read_batch_target(query_contract: &str, min_sources: u32) -> usize {
    constraint_grounded_search_limit(query_contract, min_sources.max(1)) as usize
}

pub(in super::super) async fn maybe_handle_web_search(
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
    let query_contract =
        select_web_pipeline_query_contract(agent_state.goal.as_str(), &query_value);
    let min_sources = web_pipeline_min_sources(&query_contract).max(1);
    let headline_lookup_mode = query_is_generic_headline_collection(&query_contract);
    let required_url_count = min_sources as usize;
    let pre_read_target = pre_read_batch_target(&query_contract, min_sources);
    let started_at_ms = web_pipeline_now_ms();
    let locality_hint = if query_requires_runtime_locality_scope(&query_contract) {
        effective_locality_scope_hint(None)
    } else {
        None
    };

    let discovery_sources = ranked_discovery_sources(bundle);
    let deterministic_plan = pre_read_candidate_plan_from_bundle_with_locality_hint(
        &query_contract,
        min_sources,
        bundle,
        locality_hint.as_deref(),
    );
    let probe_source_hints = deterministic_plan.probe_source_hints.clone();
    let selection = synthesize_pre_read_payload_urls(
        service,
        &query_contract,
        required_url_count,
        &discovery_sources,
    )
    .await;
    let (selected_urls, payload_error, payload_synthesis_skipped) = match selection {
        Ok(urls) => (urls, None, false),
        Err(error) => (Vec::new(), Some(error), false),
    };
    let mut selected_urls = selected_urls;
    let mut selected_hints = selected_source_hints_for_urls(bundle, &selected_urls);
    let locality_scope_required = query_requires_runtime_locality_scope(&query_contract);
    if locality_scope_required {
        if deterministic_plan.candidate_urls.is_empty() {
            // When locality scope is required, avoid committing non-local synthesized URLs.
            selected_urls.clear();
            selected_hints.clear();
        } else {
            selected_urls.retain(|selected| {
                let selected_trimmed = selected.trim();
                deterministic_plan.candidate_urls.iter().any(|allowed| {
                    let allowed_trimmed = allowed.trim();
                    allowed_trimmed.eq_ignore_ascii_case(selected_trimmed)
                        || url_structurally_equivalent(allowed_trimmed, selected_trimmed)
                })
            });
            selected_hints = selected_source_hints_for_urls(bundle, &selected_urls);
        }
    }
    let deterministic_fallback_used = (payload_error.is_some() || selected_urls.is_empty())
        && !deterministic_plan.candidate_urls.is_empty();
    if deterministic_fallback_used {
        selected_urls = deterministic_plan.candidate_urls.clone();
        selected_hints = deterministic_plan.candidate_source_hints.clone();
    }
    let mut deterministic_top_up_used = false;
    if selected_urls.len() < required_url_count {
        for candidate in &deterministic_plan.candidate_urls {
            if selected_urls.len() >= required_url_count {
                break;
            }
            if push_unique_selected_url(&mut selected_urls, candidate) {
                deterministic_top_up_used = true;
            }
        }
        if selected_urls.len() < required_url_count {
            for source in &probe_source_hints {
                if selected_urls.len() >= required_url_count {
                    break;
                }
                if push_unique_selected_url(&mut selected_urls, &source.url) {
                    deterministic_top_up_used = true;
                }
            }
        }
        if deterministic_top_up_used {
            selected_hints = selected_source_hints_for_urls(bundle, &selected_urls);
        }
    }
    let mut merged_hints = merge_source_hints(
        merge_source_hints(
            selected_hints,
            deterministic_plan.candidate_source_hints.as_slice(),
        ),
        probe_source_hints.as_slice(),
    );
    let discovery_hints = candidate_source_hints_from_bundle(bundle);
    merged_hints = merge_source_hints(merged_hints, discovery_hints.as_slice());
    resolve_selected_urls_from_hints(&mut selected_urls, &merged_hints);
    let blocked_domains = agent_state
        .pending_search_completion
        .as_ref()
        .map(|pending| {
            pending
                .blocked_urls
                .iter()
                .filter_map(|url| normalized_domain_key(url))
                .collect::<std::collections::BTreeSet<_>>()
        })
        .unwrap_or_default();
    selected_urls = collect_projection_candidate_urls(
        &selected_urls,
        &merged_hints,
        pre_read_target,
        required_url_count,
        &blocked_domains,
    );

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
        url: bundle.url.clone().unwrap_or_default(),
        started_step: pre_state_step_index,
        started_at_ms,
        deadline_ms: started_at_ms.saturating_add(WEB_PIPELINE_BUDGET_MS),
        candidate_urls: selected_urls.clone(),
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
    let mut probe_queued = false;
    let mut probe_budget_ok = true;
    let constraint_probe_attempt_count = pending
        .attempted_urls
        .iter()
        .filter(|entry| entry.trim().starts_with("ioi://constraint-probe/"))
        .count();
    let pending_search_recovery_probe_allowed = had_pending_pipeline
        && deterministic_plan.requires_constraint_search_probe
        && queued_reads == 0
        && preexisting_queued_reads > 0
        && pending.successful_reads.is_empty()
        && selected_urls.is_empty()
        && (payload_error.is_some() || payload_synthesis_skipped)
        && constraint_probe_attempt_count < 2
        && web_pipeline_grounded_probe_attempt_available(&pending);
    let probe_allowed = deterministic_plan.requires_constraint_search_probe
        && (!had_pending_pipeline || pending_search_recovery_probe_allowed);
    if probe_allowed {
        let now_ms = web_pipeline_now_ms();
        probe_budget_ok = web_pipeline_can_queue_probe_search_latency_aware(&pending, now_ms);
        if probe_budget_ok {
            let prior_query = bundle
                .query
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| pending.query.trim());
            if let Some(probe_query) = constraint_grounded_probe_query_with_hints_and_locality_hint(
                pending.query_contract.as_str(),
                pending.min_sources,
                &probe_source_hints,
                prior_query,
                locality_hint.as_deref(),
            ) {
                let probe_limit = constraint_grounded_search_limit(
                    pending.query_contract.as_str(),
                    pending.min_sources,
                );
                probe_queued = queue_web_search_from_pipeline(
                    agent_state,
                    session_id,
                    probe_query.as_str(),
                    probe_limit,
                )?;
                if probe_queued {
                    let probe_attempt_marker = format!("ioi://constraint-probe/{}", probe_query);
                    if !pending
                        .attempted_urls
                        .iter()
                        .any(|entry| entry == &probe_attempt_marker)
                    {
                        pending.attempted_urls.push(probe_attempt_marker);
                    }
                    verification_checks
                        .push(format!("web_constraint_search_probe_query={}", probe_query));
                    verification_checks
                        .push(format!("web_constraint_search_probe_limit={}", probe_limit));
                }
            }
        }
    }

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
        "web_pre_read_discovery_sources={}",
        discovery_sources.len()
    ));
    verification_checks.push(format!("web_pre_read_required_urls={}", required_url_count));
    verification_checks.push(format!(
        "web_pre_read_selected_urls={}",
        selected_urls.len()
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
        deterministic_plan.requires_constraint_search_probe
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

    if total_queued_reads == 0 && !probe_queued {
        if let Some(error) = payload_error {
            // Preserve synthesis diagnostics while carrying the explicit state-3 failure signal.
            pending
                .blocked_urls
                .push(format!("ioi://state3-synthesis-error/{}", error));
        }
        let summary = synthesize_summary(
            service,
            &pending,
            WebPipelineCompletionReason::ExhaustedCandidates,
        )
        .await;
        complete_with_summary(
            agent_state,
            summary,
            success,
            out,
            err,
            completion_summary,
            true,
        );
        let intent_id = resolved_intent_id(agent_state);
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
