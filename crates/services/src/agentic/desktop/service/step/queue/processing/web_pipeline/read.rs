use super::*;
use crate::agentic::desktop::service::step::queue::support::{
    append_final_web_completion_receipts_with_rendered_summary,
    append_pending_web_success_from_hint, compact_excerpt, explicit_query_scope_hint,
    headline_actionable_source_inventory, headline_source_is_actionable,
    local_business_menu_surface_url, matched_local_business_target_names,
    merged_local_business_target_names, query_requires_local_business_menu_surface,
    retrieval_contract_entity_diversity_required,
    retrieval_contract_is_generic_headline_collection, retrieval_contract_required_story_count,
    retrieval_contract_requires_runtime_locality, selected_local_business_target_sources,
    source_matches_local_business_target_name, story_completion_contract_ready,
    synthesis_query_contract, web_pipeline_completion_terminalization_allowed,
    WEB_PIPELINE_EXCERPT_CHARS,
};

pub(in super::super) async fn maybe_handle_web_read(
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
    if tool_name != "web__read" {
        return Ok(());
    }
    let Some(mut pending) = agent_state.pending_search_completion.clone() else {
        return Ok(());
    };
    let parsed_bundle = if *success {
        out.as_deref().and_then(parse_web_evidence_bundle)
    } else {
        None
    };

    let current_url = match tool_wrapper {
        AgentTool::WebRead { url, .. } => url.trim().to_string(),
        _ => String::new(),
    };

    if !current_url.is_empty() {
        mark_pending_web_attempted(&mut pending, &current_url);
    }

    let blocked_candidate_absorbed = absorb_blocked_pending_web_read_candidate(
        &mut pending,
        &current_url,
        is_gated,
        err.as_deref(),
        verification_checks,
    );

    if !is_gated && *success {
        if let Some(bundle) = parsed_bundle.as_ref() {
            append_pending_web_success_from_bundle(&mut pending, &bundle, &current_url);
        } else {
            append_pending_web_success_fallback(&mut pending, &current_url, out.as_deref());
        }
    }
    let local_business_expansion_queued = if !is_gated && *success {
        if let Some(bundle) = parsed_bundle.as_ref() {
            maybe_queue_local_business_expansion_searches(
                service,
                agent_state,
                session_id,
                &mut pending,
                bundle,
                verification_checks,
            )
            .await?
        } else {
            false
        }
    } else {
        false
    };
    let local_business_menu_followup_queued = if !is_gated && *success {
        if let Some(bundle) = parsed_bundle.as_ref() {
            maybe_queue_local_business_menu_followup_reads(
                agent_state,
                session_id,
                &mut pending,
                bundle,
                &current_url,
                verification_checks,
            )?
        } else {
            false
        }
    } else {
        false
    };

    let now_ms = web_pipeline_now_ms();
    let elapsed_ms = now_ms.saturating_sub(pending.started_at_ms);
    let remaining_candidates = remaining_pending_web_candidates(&pending);
    let query_contract = synthesis_query_contract(&pending);
    let retrieval_contract = pending.retrieval_contract.as_ref();
    let locality_scope = explicit_query_scope_hint(&query_contract).or_else(|| {
        retrieval_contract_requires_runtime_locality(retrieval_contract, &query_contract)
            .then(|| effective_locality_scope_hint(None))
            .flatten()
    });
    let headline_collection_mode =
        retrieval_contract_is_generic_headline_collection(retrieval_contract, &query_contract);
    let required_story_floor =
        retrieval_contract_required_story_count(retrieval_contract, &query_contract).max(1);
    let (headline_actionable_sources_observed, headline_actionable_domains_observed) =
        if headline_collection_mode {
            headline_actionable_source_inventory(&pending.successful_reads)
        } else {
            (0, 0)
        };
    let story_floor_met = !headline_collection_mode
        || (headline_actionable_sources_observed >= required_story_floor
            && headline_actionable_domains_observed >= required_story_floor);
    let min_sources_required = pending.min_sources.max(1) as usize;
    let local_business_entity_floor_required =
        retrieval_contract_entity_diversity_required(retrieval_contract, &query_contract);
    let local_business_targets = if local_business_entity_floor_required {
        merged_local_business_target_names(
            &pending.attempted_urls,
            &pending.successful_reads,
            locality_scope.as_deref(),
            required_story_floor.max(min_sources_required),
        )
    } else {
        Vec::new()
    };
    let matched_local_business_targets = if local_business_targets.is_empty() {
        Vec::new()
    } else {
        matched_local_business_target_names(
            &local_business_targets,
            &pending.successful_reads,
            locality_scope.as_deref(),
        )
    };
    let local_business_selected_sources = if local_business_targets.is_empty() {
        Vec::new()
    } else {
        selected_local_business_target_sources(
            &query_contract,
            &local_business_targets,
            &pending.successful_reads,
            locality_scope.as_deref(),
            required_story_floor.max(min_sources_required),
        )
    };
    let local_business_entity_floor_met = !local_business_entity_floor_required
        || (!local_business_targets.is_empty()
            && matched_local_business_targets.len()
                >= required_story_floor.max(min_sources_required));
    let selected_quality_urls = if local_business_selected_sources.is_empty() {
        if headline_collection_mode {
            pending
                .successful_reads
                .iter()
                .filter(|source| headline_source_is_actionable(source))
                .map(|source| source.url.clone())
                .collect::<Vec<_>>()
        } else {
            pending
                .successful_reads
                .iter()
                .map(|source| source.url.clone())
                .collect::<Vec<_>>()
        }
    } else {
        local_business_selected_sources
            .iter()
            .map(|source| source.url.clone())
            .collect::<Vec<_>>()
    };
    let selected_source_observation =
        selected_source_quality_observation_with_contract_and_locality_hint(
            retrieval_contract,
            &query_contract,
            pending.min_sources,
            &selected_quality_urls,
            &pending.successful_reads,
            locality_scope.as_deref(),
        );
    let selected_source_total = selected_source_observation.total_sources;
    let selected_source_compatible = selected_source_observation.compatible_sources;
    let selected_source_locality_compatible =
        selected_source_observation.locality_compatible_sources;
    let selected_source_distinct_domains = selected_source_observation.distinct_domains;
    let selected_source_low_priority = selected_source_observation.low_priority_sources;
    let selected_source_quality_floor_met = selected_source_observation.quality_floor_met;
    let selected_source_low_priority_urls = selected_source_observation.low_priority_urls.clone();
    let selected_source_entity_anchor_required = selected_source_observation.entity_anchor_required;
    let selected_source_entity_anchor_compatible =
        selected_source_observation.entity_anchor_compatible_sources;
    let selected_source_entity_anchor_floor_met =
        selected_source_observation.entity_anchor_floor_met;
    let selected_source_entity_anchor_urls = selected_source_observation
        .entity_anchor_source_urls
        .clone();
    let selected_source_entity_anchor_mismatched_urls = selected_source_observation
        .entity_anchor_mismatched_urls
        .clone();
    let floor_unmet = pending.successful_reads.len() < min_sources_required;
    let source_floor_met = !floor_unmet;
    let completion_contract_ready = story_completion_contract_ready(&pending, required_story_floor);
    let quality_floor_unmet = floor_unmet
        || !story_floor_met
        || !local_business_entity_floor_met
        || !selected_source_quality_floor_met
        || !completion_contract_ready;
    let next_viable_candidate_available =
        crate::agentic::desktop::service::step::queue::support::next_pending_web_candidate(
            &pending,
        )
        .is_some();
    let probe_marker_prefix = "ioi://constraint-probe/";
    let probe_allowed = grounded_probe_search_allowed(
        local_business_expansion_queued,
        next_viable_candidate_available,
        quality_floor_unmet,
        web_pipeline_grounded_probe_attempt_available(&pending),
    );
    let mut probe_budget_ok = true;
    let mut probe_queued = false;
    if probe_allowed {
        probe_budget_ok = web_pipeline_can_queue_probe_search_latency_aware(&pending, now_ms);
        if probe_budget_ok {
            let query_contract = if pending.query_contract.trim().is_empty() {
                pending.query.as_str()
            } else {
                pending.query_contract.as_str()
            };
            let prior_query = if pending.query.trim().is_empty() {
                query_contract.trim()
            } else {
                pending.query.trim()
            };
            if let Some(probe_query) =
                constraint_grounded_probe_query_with_contract_and_hints_and_locality_hint(
                    query_contract,
                    pending.retrieval_contract.as_ref(),
                    pending.min_sources,
                    &pending.candidate_source_hints,
                    prior_query,
                    locality_scope.as_deref(),
                )
            {
                let probe_limit =
                    constraint_grounded_search_limit(query_contract, pending.min_sources);
                verification_checks
                    .push(format!("web_constraint_search_probe_query={}", probe_query));
                verification_checks
                    .push(format!("web_constraint_search_probe_limit={}", probe_limit));
                probe_queued = queue_web_search_from_pipeline(
                    agent_state,
                    session_id,
                    probe_query.as_str(),
                    Some(query_contract),
                    pending.retrieval_contract.as_ref(),
                    probe_limit,
                )?;
                if probe_queued {
                    pending
                        .attempted_urls
                        .push(format!("{}{}", probe_marker_prefix, probe_query));
                }
            } else {
                verification_checks
                    .push("web_constraint_search_probe_query_unavailable=true".to_string());
            }
        }
    }

    let queued_read_count = queued_web_read_count(agent_state);
    let completion_reason = if probe_queued {
        None
    } else {
        if local_business_expansion_queued || local_business_menu_followup_queued {
            None
        } else {
            web_pipeline_completion_reason(&pending, now_ms).filter(|reason| {
                web_pipeline_completion_terminalization_allowed(
                    &pending,
                    *reason,
                    queued_read_count,
                )
            })
        }
    };
    let intent_id = resolved_intent_id(agent_state);

    verification_checks.push(format!(
        "web_sources_success={}",
        pending.successful_reads.len()
    ));
    if !pending.successful_reads.is_empty() {
        verification_checks.push(format!(
            "web_successful_read_url_values={}",
            pending
                .successful_reads
                .iter()
                .map(|source| source.url.as_str())
                .collect::<Vec<_>>()
                .join(" | ")
        ));
        verification_checks.push(format!(
            "web_successful_read_title_values={}",
            pending
                .successful_reads
                .iter()
                .map(|source| source.title.as_deref().unwrap_or_default().trim())
                .collect::<Vec<_>>()
                .join(" | ")
        ));
    }
    verification_checks.push(format!(
        "web_sources_blocked={}",
        pending.blocked_urls.len()
    ));
    verification_checks.push(format!(
        "web_selected_sources_total={}",
        selected_source_total
    ));
    if !selected_quality_urls.is_empty() {
        verification_checks.push(format!(
            "web_selected_source_url_values={}",
            selected_quality_urls.join(" | ")
        ));
    }
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
    verification_checks.push(format!(
        "web_selected_source_entity_anchor_required={}",
        selected_source_entity_anchor_required
    ));
    verification_checks.push(format!(
        "web_selected_source_entity_anchor_compatible={}",
        selected_source_entity_anchor_compatible
    ));
    verification_checks.push(format!(
        "web_selected_source_entity_anchor_floor_met={}",
        selected_source_entity_anchor_floor_met
    ));
    verification_checks.push(format!(
        "web_selected_source_identifier_evidence_required={}",
        selected_source_observation.identifier_evidence_required
    ));
    verification_checks.push(format!(
        "web_selected_source_identifier_bearing_sources={}",
        selected_source_observation.identifier_bearing_sources
    ));
    verification_checks.push(format!(
        "web_selected_source_authority_identifier_sources={}",
        selected_source_observation.authority_identifier_sources
    ));
    verification_checks.push(format!(
        "web_selected_source_required_identifier_label_coverage={}",
        selected_source_observation.required_identifier_label_coverage
    ));
    verification_checks.push(format!(
        "web_selected_source_optional_identifier_label_coverage={}",
        selected_source_observation.optional_identifier_label_coverage
    ));
    verification_checks.push(format!(
        "web_selected_source_required_identifier_group_floor={}",
        selected_source_observation.required_identifier_group_floor
    ));
    verification_checks.push(format!(
        "web_selected_source_identifier_coverage_floor_met={}",
        selected_source_observation.identifier_coverage_floor_met
    ));
    verification_checks.push(format!(
        "web_completion_contract_ready={}",
        completion_contract_ready
    ));
    if !selected_source_low_priority_urls.is_empty() {
        verification_checks.push(format!(
            "web_selected_sources_low_priority_urls={}",
            selected_source_low_priority_urls.join(" | ")
        ));
    }
    if !selected_source_entity_anchor_urls.is_empty() {
        verification_checks.push(format!(
            "web_selected_source_entity_anchor_url_values={}",
            selected_source_entity_anchor_urls.join(" | ")
        ));
    }
    if !selected_source_entity_anchor_mismatched_urls.is_empty() {
        verification_checks.push(format!(
            "web_selected_source_entity_anchor_mismatched_url_values={}",
            selected_source_entity_anchor_mismatched_urls.join(" | ")
        ));
    }
    if !selected_source_observation
        .missing_identifier_urls
        .is_empty()
    {
        verification_checks.push(format!(
            "web_selected_source_missing_identifier_urls={}",
            selected_source_observation
                .missing_identifier_urls
                .join(" | ")
        ));
    }
    verification_checks.push(format!("web_budget_ms={}", elapsed_ms));
    verification_checks.push(format!("web_remaining_candidates={}", remaining_candidates));
    verification_checks.push(format!(
        "web_next_viable_candidate_available={}",
        next_viable_candidate_available
    ));
    verification_checks.push(format!("web_source_floor_met={}", source_floor_met));
    verification_checks.push(format!(
        "web_headline_story_floor_required={}",
        required_story_floor
    ));
    verification_checks.push(format!(
        "web_headline_story_floor_observed={}",
        headline_actionable_sources_observed
    ));
    verification_checks.push(format!(
        "web_headline_story_floor_distinct_domains={}",
        headline_actionable_domains_observed
    ));
    verification_checks.push(format!("web_headline_story_floor_met={}", story_floor_met));
    verification_checks.push(format!(
        "web_local_business_entity_floor_required={}",
        local_business_entity_floor_required
    ));
    verification_checks.push(format!(
        "web_local_business_entity_targets_discovered={}",
        !local_business_targets.is_empty()
    ));
    verification_checks.push(format!(
        "web_local_business_entity_required_count={}",
        required_story_floor.max(min_sources_required)
    ));
    verification_checks.push(format!(
        "web_local_business_entity_target_total={}",
        local_business_targets.len()
    ));
    verification_checks.push(format!(
        "web_local_business_entity_observed={}",
        matched_local_business_targets.len()
    ));
    verification_checks.push(format!(
        "web_local_business_entity_floor_met={}",
        local_business_entity_floor_met
    ));
    if !local_business_targets.is_empty() {
        verification_checks.push(format!(
            "web_local_business_entity_targets={}",
            local_business_targets.join(" | ")
        ));
    }
    if !matched_local_business_targets.is_empty() {
        verification_checks.push(format!(
            "web_local_business_entity_matched={}",
            matched_local_business_targets.join(" | ")
        ));
    }
    if !local_business_selected_sources.is_empty() {
        verification_checks.push(format!(
            "web_local_business_entity_source_values={}",
            local_business_selected_sources
                .iter()
                .map(|source| source.url.as_str())
                .collect::<Vec<_>>()
                .join(" | ")
        ));
    }
    verification_checks.push(format!(
        "web_constraint_search_probe_allowed={}",
        probe_allowed
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
        "web_local_business_expansion_runtime_queued={}",
        local_business_expansion_queued
    ));
    verification_checks.push(format!(
        "web_local_business_menu_followup_runtime_queued={}",
        local_business_menu_followup_queued
    ));
    emit_web_contract_receipt(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "verification",
        "sources_success",
        true,
        "web.pipeline.read.sources_success.v1",
        &pending.successful_reads.len().to_string(),
        "scalar",
        None,
    );
    emit_web_contract_receipt(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "verification",
        "source_floor",
        source_floor_met,
        "web.pipeline.read.source_floor.v1",
        &format!(
            "observed_sources={};required_sources={}",
            pending.successful_reads.len(),
            min_sources_required
        ),
        "summary",
        None,
    );
    emit_web_contract_receipt(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "verification",
        "selected_source_total",
        true,
        "web.pipeline.read.selected_source_total.v1",
        &selected_source_total.to_string(),
        "scalar",
        None,
    );
    emit_web_contract_receipt(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "verification",
        "selected_source_distinct_domains",
        true,
        "web.pipeline.read.selected_source_distinct_domains.v1",
        &selected_source_distinct_domains.to_string(),
        "scalar",
        None,
    );
    emit_web_contract_receipt(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "verification",
        "selected_source_quality_floor",
        selected_source_quality_floor_met,
        "web.pipeline.read.selected_source_quality.v1",
        &format!(
            "selected_total={};compatible={};locality_compatible={};distinct_domains={};low_priority={};entity_anchor_required={};entity_anchor_compatible={}",
            selected_source_total,
            selected_source_compatible,
            selected_source_locality_compatible,
            selected_source_distinct_domains,
            selected_source_low_priority,
            selected_source_entity_anchor_required,
            selected_source_entity_anchor_compatible
        ),
        "summary",
        None,
    );
    emit_web_contract_receipt(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "verification",
        "local_business_entity_anchor_floor",
        selected_source_entity_anchor_floor_met,
        "web.pipeline.read.local_business_entity_anchor.v1",
        &format!(
            "required={};selected_total={};anchor_compatible={}",
            selected_source_entity_anchor_required,
            selected_source_total,
            selected_source_entity_anchor_compatible
        ),
        "summary",
        None,
    );
    emit_web_contract_receipt(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "verification",
        "selected_source_identifier_coverage_floor",
        selected_source_observation.identifier_coverage_floor_met,
        "web.pipeline.read.selected_source_identifier_coverage.v1",
        &format!(
            "identifier_evidence_required={};identifier_bearing_sources={};authority_identifier_sources={};required_identifier_label_coverage={};optional_identifier_label_coverage={};required_identifier_group_floor={}",
            selected_source_observation.identifier_evidence_required,
            selected_source_observation.identifier_bearing_sources,
            selected_source_observation.authority_identifier_sources,
            selected_source_observation.required_identifier_label_coverage,
            selected_source_observation.optional_identifier_label_coverage,
            selected_source_observation.required_identifier_group_floor
        ),
        "summary",
        None,
    );
    emit_web_string_receipts(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "verification",
        "selected_source_url",
        "web.pipeline.read.selected_sources.v1",
        "url",
        &selected_quality_urls,
    );
    emit_web_contract_receipt(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "verification",
        "local_business_entity_floor",
        local_business_entity_floor_met,
        "web.pipeline.read.local_business_floor.v1",
        &format!(
            "required={};targets={};matched={}",
            local_business_entity_floor_required,
            local_business_targets.len(),
            matched_local_business_targets.len()
        ),
        "summary",
        None,
    );
    emit_web_string_receipts(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "verification",
        "local_business_entity_anchor_source_url",
        "web.pipeline.read.local_business_entity_anchor_sources.v1",
        "url",
        &selected_source_entity_anchor_urls,
    );
    emit_web_string_receipts(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "verification",
        "local_business_entity_anchor_mismatched_url",
        "web.pipeline.read.local_business_entity_anchor_mismatches.v1",
        "url",
        &selected_source_entity_anchor_mismatched_urls,
    );
    emit_web_string_receipts(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "verification",
        "local_business_entity_name",
        "web.pipeline.read.local_business_entities.v1",
        "entity_name",
        &matched_local_business_targets,
    );
    emit_web_string_receipts(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "verification",
        "local_business_entity_source_url",
        "web.pipeline.read.local_business_entity_sources.v1",
        "url",
        &local_business_selected_sources
            .iter()
            .map(|source| source.url.clone())
            .collect::<Vec<_>>(),
    );

    if let Some(reason) = completion_reason {
        let selection = synthesize_summary(service, &pending, reason).await;
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
            reason,
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
            "web_pipeline_read_completion_gate_passed",
        );
        verification_checks.push("cec_completion_gate_emitted=true".to_string());
        verification_checks.push("web_pipeline_active=false".to_string());
        verification_checks.push("terminal_chat_reply_ready=true".to_string());
        return Ok(());
    }

    let challenge =
        blocked_candidate_absorbed || is_human_challenge_error(err.as_deref().unwrap_or(""));
    let mut followup_candidate_queued = false;
    let mut followup_candidate_url = None::<String>;
    if !probe_queued && queued_web_read_count(agent_state) == 0 {
        if let Some(next_url) =
            crate::agentic::desktop::service::step::queue::support::next_pending_web_candidate(
                &pending,
            )
        {
            followup_candidate_queued = queue_web_read_from_pipeline(
                agent_state,
                session_id,
                &next_url,
                pending_web_read_allows_browser_fallback(&pending),
            )?;
            if followup_candidate_queued {
                followup_candidate_url = Some(next_url);
            }
        }
    }
    verification_checks.push(format!(
        "web_followup_candidate_queued={}",
        followup_candidate_queued
    ));
    if let Some(url) = followup_candidate_url.as_deref() {
        verification_checks.push(format!("web_followup_candidate_url={}", url));
    }
    verification_checks.push("web_pipeline_active=true".to_string());
    agent_state.pending_search_completion = Some(pending);
    agent_state.status = AgentStatus::Running;
    if blocked_candidate_absorbed || !*success {
        let note = if is_gated {
            format!(
                "Recorded gated source in fixed payload (no approval retries): {}",
                current_url
            )
        } else if challenge {
            format!(
                "Recorded challenged source in fixed payload (no fallback retries): {}",
                current_url
            )
        } else {
            format!(
                "Source read failed in fixed payload (no fallback retries): {}",
                current_url
            )
        };
        *success = true;
        *out = Some(note);
        *err = None;
    }

    Ok(())
}

fn absorb_blocked_pending_web_read_candidate(
    pending: &mut PendingSearchCompletion,
    current_url: &str,
    is_gated: bool,
    err: Option<&str>,
    verification_checks: &mut Vec<String>,
) -> bool {
    let trimmed = current_url.trim();
    let human_challenge = is_human_challenge_error(err.unwrap_or(""));
    if trimmed.is_empty() || (!is_gated && !human_challenge) {
        return false;
    }

    mark_pending_web_blocked(pending, trimmed);
    if append_pending_web_success_from_hint(pending, trimmed) {
        verification_checks.push("web_headline_blocked_read_recovered_from_hint=true".to_string());
    }
    if is_gated {
        verification_checks.push("web_gated_read_absorbed_as_blocked_candidate=true".to_string());
    }

    true
}

fn same_normalized_source_host(left: &str, right: &str) -> bool {
    let normalize = |value: &str| {
        source_host(value).map(|host| {
            host.strip_prefix("www.")
                .unwrap_or(&host)
                .to_ascii_lowercase()
        })
    };
    match (normalize(left), normalize(right)) {
        (Some(left_host), Some(right_host)) => left_host == right_host,
        _ => false,
    }
}

fn pending_records_url(pending: &PendingSearchCompletion, candidate_url: &str) -> bool {
    let candidate_trimmed = candidate_url.trim();
    if candidate_trimmed.is_empty() {
        return false;
    }

    pending.candidate_urls.iter().any(|existing| {
        existing.eq_ignore_ascii_case(candidate_trimmed)
            || url_structurally_equivalent(existing, candidate_trimmed)
    }) || pending.successful_reads.iter().any(|source| {
        source.url.eq_ignore_ascii_case(candidate_trimmed)
            || url_structurally_equivalent(&source.url, candidate_trimmed)
    }) || pending.blocked_urls.iter().any(|existing| {
        existing.eq_ignore_ascii_case(candidate_trimmed)
            || url_structurally_equivalent(existing, candidate_trimmed)
    }) || pending.attempted_urls.iter().any(|existing| {
        existing.eq_ignore_ascii_case(candidate_trimmed)
            || url_structurally_equivalent(existing, candidate_trimmed)
    })
}

fn current_local_business_source_summary(
    pending: &PendingSearchCompletion,
    bundle: &WebEvidenceBundle,
    current_url: &str,
) -> Option<PendingSearchReadSummary> {
    let current_trimmed = current_url.trim();
    if current_trimmed.is_empty() {
        return None;
    }

    pending
        .successful_reads
        .iter()
        .rev()
        .find(|source| {
            source.url.eq_ignore_ascii_case(current_trimmed)
                || url_structurally_equivalent(&source.url, current_trimmed)
        })
        .cloned()
        .or_else(|| {
            pending
                .candidate_source_hints
                .iter()
                .find(|source| {
                    source.url.eq_ignore_ascii_case(current_trimmed)
                        || url_structurally_equivalent(&source.url, current_trimmed)
                })
                .cloned()
        })
        .or_else(|| {
            bundle
                .documents
                .iter()
                .find(|doc| {
                    doc.url.eq_ignore_ascii_case(current_trimmed)
                        || url_structurally_equivalent(&doc.url, current_trimmed)
                })
                .map(|doc| PendingSearchReadSummary {
                    url: current_trimmed.to_string(),
                    title: doc.title.clone(),
                    excerpt: compact_excerpt(&doc.content_text, WEB_PIPELINE_EXCERPT_CHARS),
                })
        })
        .or_else(|| {
            bundle
                .sources
                .iter()
                .find(|source| {
                    source.url.eq_ignore_ascii_case(current_trimmed)
                        || url_structurally_equivalent(&source.url, current_trimmed)
                })
                .map(|source| PendingSearchReadSummary {
                    url: current_trimmed.to_string(),
                    title: source.title.clone(),
                    excerpt: compact_excerpt(
                        source.snippet.as_deref().unwrap_or_default(),
                        WEB_PIPELINE_EXCERPT_CHARS,
                    ),
                })
        })
}

fn maybe_queue_local_business_menu_followup_reads(
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    pending: &mut PendingSearchCompletion,
    bundle: &WebEvidenceBundle,
    current_url: &str,
    verification_checks: &mut Vec<String>,
) -> Result<bool, TransactionError> {
    let query_contract = if pending.query_contract.trim().is_empty() {
        pending.query.trim()
    } else {
        pending.query_contract.trim()
    };
    let retrieval_contract = pending.retrieval_contract.as_ref();
    let locality_hint = explicit_query_scope_hint(query_contract).or_else(|| {
        retrieval_contract_requires_runtime_locality(retrieval_contract, query_contract)
            .then(|| effective_locality_scope_hint(None))
            .flatten()
    });
    if !query_requires_local_business_menu_surface(
        query_contract,
        retrieval_contract,
        locality_hint.as_deref(),
    ) {
        return Ok(false);
    }

    let current_trimmed = current_url.trim();
    if current_trimmed.is_empty() || local_business_menu_surface_url(current_trimmed) {
        return Ok(false);
    }

    let Some(current_source) =
        current_local_business_source_summary(pending, bundle, current_trimmed)
    else {
        verification_checks
            .push("web_local_business_menu_followup_current_source_unavailable=true".to_string());
        return Ok(false);
    };
    let Some(target_name) =
        local_business_target_name_from_source(&current_source, locality_hint.as_deref())
    else {
        verification_checks
            .push("web_local_business_menu_followup_target_unavailable=true".to_string());
        return Ok(false);
    };

    let menu_candidates = candidate_source_hints_from_bundle(bundle)
        .into_iter()
        .filter(|source| {
            let candidate_url = source.url.trim();
            !candidate_url.is_empty()
                && local_business_menu_surface_url(candidate_url)
                && !candidate_url.eq_ignore_ascii_case(current_trimmed)
                && !url_structurally_equivalent(candidate_url, current_trimmed)
                && same_normalized_source_host(candidate_url, current_trimmed)
                && source_matches_local_business_target_name(
                    &target_name,
                    locality_hint.as_deref(),
                    candidate_url,
                    source.title.as_deref().unwrap_or_default(),
                    &source.excerpt,
                )
                && !pending_records_url(pending, candidate_url)
        })
        .collect::<Vec<_>>();

    if menu_candidates.is_empty() {
        verification_checks.push(format!(
            "web_local_business_menu_followup_candidates={}::target={}",
            0, target_name
        ));
        return Ok(false);
    }

    let allow_browser_fallback = pending_web_read_allows_browser_fallback(pending);
    let mut queued_urls = Vec::new();
    for source in menu_candidates.into_iter().take(1) {
        if !pending.candidate_urls.iter().any(|existing| {
            existing.eq_ignore_ascii_case(&source.url)
                || url_structurally_equivalent(existing, &source.url)
        }) {
            pending.candidate_urls.push(source.url.clone());
        }
        if !pending.candidate_source_hints.iter().any(|existing| {
            existing.url.eq_ignore_ascii_case(&source.url)
                || url_structurally_equivalent(&existing.url, &source.url)
        }) {
            pending.candidate_source_hints.push(source.clone());
        }
        if queue_web_read_from_pipeline(
            agent_state,
            session_id,
            &source.url,
            allow_browser_fallback,
        )? {
            queued_urls.push(source.url);
        }
    }

    verification_checks.push(format!(
        "web_local_business_menu_followup_candidates={}::target={}",
        queued_urls.len(),
        target_name
    ));
    if !queued_urls.is_empty() {
        verification_checks.push(format!(
            "web_local_business_menu_followup_url_values={}",
            queued_urls.join(" | ")
        ));
    }
    Ok(!queued_urls.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, VecDeque};

    fn nist_briefing_contract() -> ioi_types::app::agentic::WebRetrievalContract {
        crate::agentic::web::derive_web_retrieval_contract(
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.",
            None,
        )
        .expect("retrieval contract")
    }

    #[test]
    fn gated_document_briefing_read_is_absorbed_as_blocked_candidate() {
        let gated_url = "https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved";
        let fallback_url = "https://qramm.org/learn/nist-pqc-standards.html";
        let mut pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(nist_briefing_contract()),
            url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1,
            deadline_ms: 60_000,
            candidate_urls: vec![gated_url.to_string(), fallback_url.to_string()],
            candidate_source_hints: vec![
                PendingSearchReadSummary {
                    url: gated_url.to_string(),
                    title: Some("Post-Quantum Cryptography FIPS Approved | CSRC".to_string()),
                    excerpt: "The Secretary of Commerce approved FIPS 203, FIPS 204 and FIPS 205."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: fallback_url.to_string(),
                    title: Some(
                        "NIST Post-Quantum Cryptography Standards: Complete Guide to FIPS 203, 204, and 205"
                            .to_string(),
                    ),
                    excerpt:
                        "NIST released FIPS 203, FIPS 204 and FIPS 205 as production-ready standards."
                            .to_string(),
                },
            ],
            attempted_urls: Vec::new(),
            blocked_urls: Vec::new(),
            successful_reads: vec![PendingSearchReadSummary {
                url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                title: Some(
                    "NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST"
                        .to_string(),
                ),
                excerpt:
                    "NIST released FIPS 203, FIPS 204 and FIPS 205 as its first three finalized post-quantum encryption standards."
                        .to_string(),
            }],
            min_sources: 2,
        };
        let mut verification_checks = Vec::new();

        let absorbed = absorb_blocked_pending_web_read_candidate(
            &mut pending,
            gated_url,
            true,
            None,
            &mut verification_checks,
        );

        assert!(absorbed);
        assert!(pending.blocked_urls.iter().any(|url| url == gated_url));
        assert_eq!(
            crate::agentic::desktop::service::step::queue::support::next_pending_web_candidate(
                &pending
            )
            .as_deref(),
            Some(fallback_url)
        );
        assert!(verification_checks
            .iter()
            .any(|check| { check == "web_gated_read_absorbed_as_blocked_candidate=true" }));
    }

    fn test_agent_state() -> AgentState {
        AgentState {
            session_id: [7u8; 32],
            goal: "find restaurants".to_string(),
            transcript_root: [0u8; 32],
            status: AgentStatus::Running,
            step_count: 0,
            max_steps: 8,
            last_action_type: None,
            parent_session_id: None,
            child_session_ids: vec![],
            budget: 0,
            tokens_used: 0,
            consecutive_failures: 0,
            pending_approval: None,
            pending_tool_call: None,
            pending_tool_jcs: None,
            pending_tool_hash: None,
            pending_request_nonce: None,
            pending_visual_hash: None,
            recent_actions: vec![],
            mode: crate::agentic::desktop::types::AgentMode::default(),
            current_tier: crate::agentic::desktop::types::ExecutionTier::default(),
            last_screen_phash: None,
            execution_queue: vec![],
            pending_search_completion: None,
            planner_state: None,
            active_skill_hash: None,
            tool_execution_log: BTreeMap::new(),
            visual_som_map: None,
            visual_semantic_map: None,
            swarm_context: None,
            target: None,
            resolved_intent: None,
            awaiting_intent_clarification: false,
            working_directory: ".".to_string(),
            command_history: VecDeque::new(),
            active_lens: None,
        }
    }

    #[test]
    fn local_business_menu_followup_read_is_queued_from_bundle_child_url() {
        let query =
            "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
        let mut pending = PendingSearchCompletion {
            query: query.to_string(),
            query_contract: query.to_string(),
            retrieval_contract: Some(
                crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                    .expect("retrieval contract"),
            ),
            url: "https://www.restaurantji.com/sc/anderson/italian/".to_string(),
            started_step: 1,
            started_at_ms: 1,
            deadline_ms: 60_000,
            candidate_urls: vec![],
            candidate_source_hints: vec![PendingSearchReadSummary {
                url: "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/"
                    .to_string(),
                title: Some(
                    "Coach House Restaurant, Anderson - Menu, Reviews (242), Photos (52) - Restaurantji"
                        .to_string(),
                ),
                excerpt:
                    "Anderson steakhouse and Italian restaurant with lasagna, ravioli and house specials."
                        .to_string(),
            }],
            attempted_urls: vec![],
            blocked_urls: vec![],
            successful_reads: vec![PendingSearchReadSummary {
                url: "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/"
                    .to_string(),
                title: Some(
                    "Coach House Restaurant, Anderson - Menu, Reviews (242), Photos (52) - Restaurantji"
                        .to_string(),
                ),
                excerpt:
                    "Anderson steakhouse and Italian restaurant with lasagna, ravioli and house specials."
                        .to_string(),
            }],
            min_sources: 3,
        };
        let bundle = WebEvidenceBundle {
            schema_version: 1,
            retrieved_at_ms: 0,
            tool: "web__read".to_string(),
            backend: "edge:read:http".to_string(),
            query: Some(query.to_string()),
            url: Some(
                "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/".to_string(),
            ),
            sources: vec![ioi_types::app::agentic::WebSource {
                source_id: "menu-1".to_string(),
                rank: Some(1),
                url: "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/menu/"
                    .to_string(),
                title: Some("Menu".to_string()),
                snippet: Some(
                    "View the menu, hours, phone number, address and map for Coach House Restaurant."
                        .to_string(),
                ),
                domain: Some("restaurantji.com".to_string()),
            }],
            source_observations: vec![],
            documents: vec![],
            provider_candidates: vec![],
            retrieval_contract: pending.retrieval_contract.clone(),
        };
        let mut verification_checks = Vec::new();
        let mut agent_state = test_agent_state();

        let queued = maybe_queue_local_business_menu_followup_reads(
            &mut agent_state,
            [7u8; 32],
            &mut pending,
            &bundle,
            "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/",
            &mut verification_checks,
        )
        .expect("menu followup queued");

        assert!(queued);
        assert!(pending.candidate_urls.iter().any(|url| {
            url == "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/menu/"
        }));
        assert!(agent_state.execution_queue.iter().any(|request| {
            serde_json::from_slice::<serde_json::Value>(&request.params)
                .ok()
                .and_then(|value| {
                    value
                        .get("url")
                        .and_then(|value| value.as_str())
                        .map(str::to_string)
                })
                .as_deref()
                == Some("https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/menu/")
        }));
        assert!(verification_checks
            .iter()
            .any(|check| { check.contains("web_local_business_menu_followup_url_values=") }));
    }
}
