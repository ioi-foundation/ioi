use super::*;
use crate::agentic::desktop::service::step::queue::support::{
    append_pending_web_success_from_hint, explicit_query_scope_hint,
    headline_actionable_source_inventory, headline_source_is_actionable,
    matched_local_business_target_names, merged_local_business_target_names,
    retrieval_contract_entity_diversity_required,
    retrieval_contract_is_generic_headline_collection, retrieval_contract_required_story_count,
    retrieval_contract_requires_runtime_locality, selected_local_business_target_sources,
    synthesis_query_contract,
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
    if is_gated || tool_name != "web__read" {
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

    if *success {
        if let Some(bundle) = parsed_bundle.as_ref() {
            append_pending_web_success_from_bundle(&mut pending, &bundle, &current_url);
        } else {
            append_pending_web_success_fallback(&mut pending, &current_url, out.as_deref());
        }
    } else if !current_url.is_empty() && is_human_challenge_error(err.as_deref().unwrap_or("")) {
        mark_pending_web_blocked(&mut pending, &current_url);
        if append_pending_web_success_from_hint(&mut pending, &current_url) {
            verification_checks
                .push("web_headline_blocked_read_recovered_from_hint=true".to_string());
        }
    }

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
    let (
        selected_source_total,
        selected_source_compatible,
        selected_source_locality_compatible,
        selected_source_distinct_domains,
        selected_source_low_priority,
        selected_source_quality_floor_met,
        selected_source_low_priority_urls,
    ) = selected_source_structural_metrics(
        retrieval_contract,
        &query_contract,
        pending.min_sources,
        &selected_quality_urls,
        &pending.successful_reads,
    );
    let floor_unmet = pending.successful_reads.len() < min_sources_required;
    let source_floor_met = !floor_unmet;
    let quality_floor_unmet = floor_unmet
        || !story_floor_met
        || !local_business_entity_floor_met
        || !selected_source_quality_floor_met;
    let probe_marker_prefix = "ioi://constraint-probe/";
    let probe_allowed = remaining_candidates == 0
        && quality_floor_unmet
        && web_pipeline_grounded_probe_attempt_available(&pending);
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

    let completion_reason = if probe_queued {
        None
    } else {
        web_pipeline_completion_reason(&pending, now_ms)
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
    if !selected_source_low_priority_urls.is_empty() {
        verification_checks.push(format!(
            "web_selected_sources_low_priority_urls={}",
            selected_source_low_priority_urls.join(" | ")
        ));
    }
    verification_checks.push(format!("web_budget_ms={}", elapsed_ms));
    verification_checks.push(format!("web_remaining_candidates={}", remaining_candidates));
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
            "selected_total={};compatible={};locality_compatible={};distinct_domains={};low_priority={}",
            selected_source_total,
            selected_source_compatible,
            selected_source_locality_compatible,
            selected_source_distinct_domains,
            selected_source_low_priority
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
        let final_facts = final_web_completion_facts(&pending, reason);
        emit_web_contract_receipt(
            service,
            session_id,
            pre_state_step_index,
            intent_id.as_str(),
            "verification",
            "story_slots_observed",
            true,
            "web.pipeline.completion.story_slots_observed.v1",
            &final_facts.observed_story_slots.to_string(),
            "scalar",
            None,
        );
        emit_web_contract_receipt(
            service,
            session_id,
            pre_state_step_index,
            intent_id.as_str(),
            "verification",
            "story_slot_floor",
            final_facts.story_slot_floor_met,
            "web.pipeline.completion.story_slots.v1",
            &final_facts.observed_story_slots.to_string(),
            "scalar",
            None,
        );
        emit_web_contract_receipt(
            service,
            session_id,
            pre_state_step_index,
            intent_id.as_str(),
            "verification",
            "story_citation_floor",
            final_facts.story_citation_floor_met,
            "web.pipeline.completion.story_citations.v1",
            &final_facts.observed_story_slots.to_string(),
            "scalar",
            None,
        );
        emit_web_contract_receipt(
            service,
            session_id,
            pre_state_step_index,
            intent_id.as_str(),
            "verification",
            "comparison_ready",
            final_facts.comparison_ready,
            "web.pipeline.completion.comparison.v1",
            &format!("comparison_required={}", final_facts.comparison_required),
            "summary",
            None,
        );
        emit_web_contract_receipt(
            service,
            session_id,
            pre_state_step_index,
            intent_id.as_str(),
            "verification",
            "single_snapshot_metric_grounding",
            final_facts.single_snapshot_metric_grounding,
            "web.pipeline.completion.single_snapshot_metric.v1",
            &final_facts.single_snapshot_metric_grounding.to_string(),
            "bool",
            None,
        );
        emit_web_string_receipts(
            service,
            session_id,
            pre_state_step_index,
            intent_id.as_str(),
            "verification",
            "selected_source_url",
            "web.pipeline.completion.selected_sources.v1",
            "url",
            &final_facts.selected_source_urls,
        );
        emit_web_string_receipts(
            service,
            session_id,
            pre_state_step_index,
            intent_id.as_str(),
            "verification",
            "local_business_entity_name",
            "web.pipeline.completion.local_business_entities.v1",
            "entity_name",
            &final_facts.matched_local_business_targets,
        );
        emit_web_string_receipts(
            service,
            session_id,
            pre_state_step_index,
            intent_id.as_str(),
            "verification",
            "local_business_entity_source_url",
            "web.pipeline.completion.local_business_entity_sources.v1",
            "url",
            &final_facts.local_business_source_urls,
        );
        append_final_web_completion_receipts(&pending, reason, verification_checks);
        let summary = synthesize_summary(service, &pending, reason).await;
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

    let challenge = is_human_challenge_error(err.as_deref().unwrap_or(""));
    let mut followup_candidate_queued = false;
    let mut followup_candidate_url = None::<String>;
    if !probe_queued && queued_web_read_count(agent_state) == 0 {
        if let Some(next_url) =
            crate::agentic::desktop::service::step::queue::support::next_pending_web_candidate(
                &pending,
            )
        {
            followup_candidate_queued =
                queue_web_read_from_pipeline(agent_state, session_id, &next_url)?;
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
    if !*success {
        let note = if challenge {
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
