use super::super::support::{
    append_pending_web_success_fallback, append_pending_web_success_from_bundle,
    constraint_grounded_probe_query_with_hints, constraint_grounded_search_limit,
    fallback_search_summary, is_human_challenge_error, mark_pending_web_attempted,
    mark_pending_web_blocked, merge_pending_search_completion, next_pending_web_candidate,
    parse_web_evidence_bundle, pre_read_candidate_plan_from_bundle_with_recovery_mode,
    queue_web_read_from_pipeline, queue_web_search_from_pipeline, remaining_pending_web_candidates,
    select_web_pipeline_query_contract, summarize_search_results, synthesize_web_pipeline_reply,
    synthesize_web_pipeline_reply_hybrid, web_pipeline_can_queue_initial_read,
    web_pipeline_can_queue_probe_search, web_pipeline_can_queue_probe_search_latency_aware,
    web_pipeline_completion_reason, web_pipeline_min_sources, web_pipeline_now_ms,
    web_pipeline_remaining_budget_ms, web_pipeline_requires_metric_probe_followup,
    WebPipelineCompletionReason, WEB_PIPELINE_BUDGET_MS,
};
use super::completion::complete_with_summary;
use super::routing::is_web_research_scope;
use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::{AgentState, AgentStatus, PendingSearchCompletion};
use ioi_types::app::agentic::AgentTool;
use ioi_types::error::TransactionError;

async fn synthesize_summary(
    service: &DesktopAgentService,
    pending: &PendingSearchCompletion,
    reason: WebPipelineCompletionReason,
) -> String {
    if let Some(hybrid_summary) =
        synthesize_web_pipeline_reply_hybrid(service.reasoning_inference.clone(), pending, reason)
            .await
    {
        hybrid_summary
    } else {
        synthesize_web_pipeline_reply(pending, reason)
    }
}

pub(super) async fn maybe_handle_web_search(
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
    let min_sources = web_pipeline_min_sources(&query_contract);
    let started_at_ms = web_pipeline_now_ms();
    let prior_pending = agent_state.pending_search_completion.clone();
    let allow_floor_recovery_exploration = prior_pending
        .as_ref()
        .map(|existing| {
            let min_sources_required = existing.min_sources.max(1) as usize;
            let successful_sources = existing.successful_reads.len();
            successful_sources > 0 && successful_sources < min_sources_required
        })
        .unwrap_or(false);
    let candidate_plan = pre_read_candidate_plan_from_bundle_with_recovery_mode(
        &query_contract,
        min_sources,
        bundle,
        allow_floor_recovery_exploration,
    );
    let plan_total_candidates = candidate_plan.total_candidates;
    let plan_pruned_candidates = candidate_plan.pruned_candidates;
    let plan_resolvable_candidates = candidate_plan.resolvable_candidates;
    let probe_source_hints = candidate_plan.probe_source_hints.clone();
    let mut plan_requires_probe = candidate_plan.requires_constraint_search_probe;
    let prior_no_progress_probe_cycle = prior_pending
        .as_ref()
        .map(|existing| {
            existing.successful_reads.is_empty()
                && existing.blocked_urls.is_empty()
                && existing.candidate_urls.is_empty()
                && existing.candidate_source_hints.is_empty()
        })
        .unwrap_or(false);
    let search_url_attempt = bundle
        .url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
        .into_iter()
        .collect::<Vec<_>>();
    let mut pending = PendingSearchCompletion {
        query: query_value,
        query_contract: query_contract.clone(),
        url: bundle.url.clone().unwrap_or_default(),
        started_step: pre_state_step_index,
        started_at_ms,
        deadline_ms: started_at_ms.saturating_add(WEB_PIPELINE_BUDGET_MS),
        candidate_urls: candidate_plan.candidate_urls,
        candidate_source_hints: candidate_plan.candidate_source_hints,
        attempted_urls: search_url_attempt,
        blocked_urls: Vec::new(),
        successful_reads: Vec::new(),
        min_sources,
    };
    if let Some(existing_pending) = agent_state.pending_search_completion.take() {
        pending = merge_pending_search_completion(existing_pending, pending);
    }
    if pending.candidate_urls.is_empty() {
        plan_requires_probe = true;
    }
    let min_sources = pending.min_sources;
    let min_sources_required = min_sources.max(1) as usize;
    if pending.successful_reads.len() < min_sources_required
        && remaining_pending_web_candidates(&pending) == 0
    {
        plan_requires_probe = true;
    }
    if plan_total_candidates == 0 && prior_no_progress_probe_cycle {
        plan_requires_probe = false;
    }

    let queue_now_ms = web_pipeline_now_ms();
    let remaining_budget_ms = web_pipeline_remaining_budget_ms(pending.deadline_ms, queue_now_ms);
    let probe_budget_allows =
        web_pipeline_can_queue_probe_search(pending.deadline_ms, queue_now_ms);
    let read_budget_allows = web_pipeline_can_queue_initial_read(pending.deadline_ms, queue_now_ms);

    let mut completion_reason = web_pipeline_completion_reason(&pending, queue_now_ms);
    let mut queued_next = false;
    let mut queued_probe = false;
    let remaining_candidates = remaining_pending_web_candidates(&pending);
    let source_floor_gap = pending
        .successful_reads
        .len()
        .saturating_add(remaining_candidates)
        < min_sources_required;
    let first_search_pass =
        pending.successful_reads.is_empty() && pending.attempted_urls.len() <= 1;
    let prefer_probe_before_read = plan_requires_probe
        && !first_search_pass
        && (remaining_candidates == 0 || (source_floor_gap && remaining_candidates <= 1))
        && plan_resolvable_candidates == 0;
    if completion_reason.is_none() {
        if prefer_probe_before_read && plan_requires_probe && probe_budget_allows {
            if let Some(probe_query) = constraint_grounded_probe_query_with_hints(
                &query_contract,
                min_sources,
                &probe_source_hints,
                &pending.query,
            ) {
                queued_probe = queue_web_search_from_pipeline(
                    agent_state,
                    session_id,
                    &probe_query,
                    constraint_grounded_search_limit(&query_contract, min_sources),
                )?;
                if queued_probe {
                    pending.query = probe_query;
                }
            }
        }
        if !queued_probe && read_budget_allows {
            if let Some(next_url) = next_pending_web_candidate(&pending) {
                queued_next = queue_web_read_from_pipeline(agent_state, session_id, &next_url)?;
            }
        }
        if !queued_next && !queued_probe && plan_requires_probe && probe_budget_allows {
            if let Some(probe_query) = constraint_grounded_probe_query_with_hints(
                &query_contract,
                min_sources,
                &probe_source_hints,
                &pending.query,
            ) {
                queued_probe = queue_web_search_from_pipeline(
                    agent_state,
                    session_id,
                    &probe_query,
                    constraint_grounded_search_limit(&query_contract, min_sources),
                )?;
                if queued_probe {
                    pending.query = probe_query;
                }
            }
        }
        if !queued_next && !queued_probe {
            if remaining_candidates == 0 {
                completion_reason = Some(WebPipelineCompletionReason::ExhaustedCandidates);
            } else if !read_budget_allows && (!plan_requires_probe || !probe_budget_allows) {
                completion_reason = Some(WebPipelineCompletionReason::DeadlineReached);
            }
        }
    }
    let remaining = remaining_pending_web_candidates(&pending);
    let budget_prevents_followup = completion_reason.is_none()
        && !queued_probe
        && !queued_next
        && remaining > 0
        && (!read_budget_allows || (plan_requires_probe && !probe_budget_allows));

    verification_checks.push(format!(
        "web_pre_read_candidates_total={}",
        plan_total_candidates
    ));
    verification_checks.push(format!(
        "web_pre_read_candidates_pruned={}",
        plan_pruned_candidates
    ));
    verification_checks.push(format!(
        "web_pre_read_candidates_resolvable={}",
        plan_resolvable_candidates
    ));
    verification_checks.push(format!("web_min_sources={}", min_sources));
    verification_checks.push(format!(
        "web_constraint_search_probe_required={}",
        plan_requires_probe
    ));
    verification_checks.push(format!(
        "web_probe_preferred_before_read={}",
        prefer_probe_before_read
    ));
    verification_checks.push(format!(
        "web_constraint_search_probe_queued={}",
        queued_probe
    ));
    verification_checks.push(format!("web_remaining_budget_ms={}", remaining_budget_ms));
    verification_checks.push(format!("web_probe_budget_allows={}", probe_budget_allows));
    verification_checks.push(format!("web_read_budget_allows={}", read_budget_allows));
    verification_checks.push(format!(
        "web_pipeline_active={}",
        queued_probe || queued_next || (remaining > 0 && !budget_prevents_followup)
    ));
    verification_checks.push("web_sources_success=0".to_string());
    verification_checks.push("web_sources_blocked=0".to_string());
    verification_checks.push("web_budget_ms=0".to_string());

    if let Some(reason) = completion_reason {
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
        verification_checks.push("web_pipeline_active=false".to_string());
        verification_checks.push("terminal_chat_reply_ready=true".to_string());
    } else if budget_prevents_followup {
        let summary = synthesize_summary(
            service,
            &pending,
            WebPipelineCompletionReason::DeadlineReached,
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
        verification_checks.push("web_pipeline_active=false".to_string());
        verification_checks.push("terminal_chat_reply_ready=true".to_string());
    } else if queued_probe || queued_next || remaining > 0 {
        agent_state.pending_search_completion = Some(pending);
        agent_state.status = AgentStatus::Running;
    } else {
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
        verification_checks.push("web_pipeline_active=false".to_string());
        verification_checks.push("terminal_chat_reply_ready=true".to_string());
    }

    Ok(())
}

pub(super) async fn maybe_handle_web_read(
    service: &DesktopAgentService,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
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

    let current_url = match tool_wrapper {
        AgentTool::WebRead { url, .. } => url.trim().to_string(),
        _ => String::new(),
    };

    if !current_url.is_empty() {
        mark_pending_web_attempted(&mut pending, &current_url);
    }

    if *success {
        if let Some(bundle) = out.as_deref().and_then(parse_web_evidence_bundle) {
            append_pending_web_success_from_bundle(&mut pending, &bundle, &current_url);
        } else {
            append_pending_web_success_fallback(&mut pending, &current_url, out.as_deref());
        }
    } else if !current_url.is_empty() && is_human_challenge_error(err.as_deref().unwrap_or("")) {
        mark_pending_web_blocked(&mut pending, &current_url);
    }

    let now_ms = web_pipeline_now_ms();
    let elapsed_ms = now_ms.saturating_sub(pending.started_at_ms);
    let remaining_budget_ms = web_pipeline_remaining_budget_ms(pending.deadline_ms, now_ms);
    let read_budget_allows = web_pipeline_can_queue_initial_read(pending.deadline_ms, now_ms);
    let mut completion_reason = web_pipeline_completion_reason(&pending, now_ms);
    let mut queued_next = false;
    let mut queued_probe = false;
    let probe_budget_allows = web_pipeline_can_queue_probe_search_latency_aware(&pending, now_ms);
    if completion_reason.is_none() {
        let remaining_candidates = remaining_pending_web_candidates(&pending);
        let min_sources_required = pending.min_sources.max(1) as usize;
        let source_floor_unmet = pending.successful_reads.len() < min_sources_required;
        let metric_probe_followup = web_pipeline_requires_metric_probe_followup(&pending, now_ms);
        let queue_probe = |pending: &mut PendingSearchCompletion,
                           agent_state: &mut AgentState|
         -> Result<bool, TransactionError> {
            let mut probe_hints = pending.successful_reads.clone();
            for hint in &pending.candidate_source_hints {
                let hint_url = hint.url.trim();
                if hint_url.is_empty() {
                    continue;
                }
                if probe_hints
                    .iter()
                    .any(|existing| existing.url.trim().eq_ignore_ascii_case(hint_url))
                {
                    continue;
                }
                probe_hints.push(hint.clone());
            }
            if let Some(probe_query) = constraint_grounded_probe_query_with_hints(
                &pending.query_contract,
                pending.min_sources,
                &probe_hints,
                &pending.query,
            ) {
                let queued = queue_web_search_from_pipeline(
                    agent_state,
                    session_id,
                    &probe_query,
                    constraint_grounded_search_limit(&pending.query_contract, pending.min_sources),
                )?;
                if queued {
                    pending.query = probe_query;
                }
                return Ok(queued);
            }
            Ok(false)
        };
        if read_budget_allows {
            if let Some(next_url) = next_pending_web_candidate(&pending) {
                queued_next = queue_web_read_from_pipeline(agent_state, session_id, &next_url)?;
            }
        }
        if !queued_next && metric_probe_followup && probe_budget_allows {
            queued_probe = queue_probe(&mut pending, agent_state)?;
        }
        if !queued_next
            && !queued_probe
            && source_floor_unmet
            && remaining_candidates == 0
            && probe_budget_allows
        {
            queued_probe = queue_probe(&mut pending, agent_state)?;
        }
        verification_checks.push(format!(
            "web_metric_probe_followup={}",
            metric_probe_followup
        ));
        if !queued_next && !queued_probe && !read_budget_allows && remaining_candidates > 0 {
            completion_reason = Some(WebPipelineCompletionReason::DeadlineReached);
        }
        if !queued_next && !queued_probe && remaining_candidates == 0 {
            completion_reason = Some(WebPipelineCompletionReason::ExhaustedCandidates);
        }
    }

    verification_checks.push(format!(
        "web_sources_success={}",
        pending.successful_reads.len()
    ));
    verification_checks.push(format!(
        "web_sources_blocked={}",
        pending.blocked_urls.len()
    ));
    verification_checks.push(format!("web_budget_ms={}", elapsed_ms));
    verification_checks.push(format!("web_remaining_budget_ms={}", remaining_budget_ms));
    verification_checks.push(format!("web_read_budget_allows={}", read_budget_allows));
    verification_checks.push(format!("web_probe_budget_allows={}", probe_budget_allows));
    verification_checks.push(format!(
        "web_constraint_search_probe_queued={}",
        queued_probe
    ));

    if let Some(reason) = completion_reason {
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
        verification_checks.push("web_pipeline_active=false".to_string());
        verification_checks.push("terminal_chat_reply_ready=true".to_string());
        log::info!(
            "Web pipeline completed for session {} (sources_success={} blocked={}).",
            hex::encode(&session_id[..4]),
            pending.successful_reads.len(),
            pending.blocked_urls.len()
        );
    } else {
        let challenge = is_human_challenge_error(err.as_deref().unwrap_or(""));
        verification_checks.push("web_pipeline_active=true".to_string());
        agent_state.pending_search_completion = Some(pending);
        if !*success {
            let note = if challenge {
                format!(
                    "Skipped challenged source and queued next candidate: {}",
                    current_url
                )
            } else {
                format!(
                    "Source read failed; queued alternate candidate: {}",
                    current_url
                )
            };
            *success = true;
            *out = Some(note);
            *err = None;
            agent_state.status = AgentStatus::Running;
        }
    }

    Ok(())
}

pub(super) fn maybe_handle_browser_snapshot(
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    tool_name: &str,
    is_gated: bool,
    success: &mut bool,
    out: &mut Option<String>,
    err: &mut Option<String>,
    completion_summary: &mut Option<String>,
) {
    if is_gated || tool_name != "browser__snapshot" {
        return;
    }
    let Some(pending) = agent_state.pending_search_completion.clone() else {
        return;
    };
    let summary = if *success {
        summarize_search_results(&pending.query, &pending.url, out.as_deref().unwrap_or(""))
    } else {
        fallback_search_summary(&pending.query, &pending.url)
    };
    complete_with_summary(
        agent_state,
        summary,
        success,
        out,
        err,
        completion_summary,
        true,
    );
    log::info!(
        "Search flow completed after browser__snapshot for session {}.",
        hex::encode(&session_id[..4])
    );
}
