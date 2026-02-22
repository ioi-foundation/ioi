use super::{
    constraint_grounded_probe_query_with_hints, constraint_grounded_search_limit,
    merge_pending_search_completion, next_pending_web_candidate,
    pre_read_candidate_plan_from_bundle, queue_web_read_from_pipeline,
    queue_web_search_from_pipeline, remaining_pending_web_candidates,
    synthesize_web_pipeline_reply, synthesize_web_pipeline_reply_hybrid,
    web_pipeline_can_queue_initial_read_latency_aware,
    web_pipeline_can_queue_probe_search_latency_aware, web_pipeline_completion_reason,
    web_pipeline_latency_pressure_label, web_pipeline_min_sources, web_pipeline_now_ms,
    web_pipeline_remaining_budget_ms, web_pipeline_required_probe_budget_ms,
    web_pipeline_required_read_budget_ms, AgentState, AgentStatus, DesktopAgentService,
    PendingSearchCompletion, TransactionError, WebPipelineCompletionReason, WEB_PIPELINE_BUDGET_MS,
};
use ioi_types::app::agentic::WebEvidenceBundle;

pub(super) async fn apply_pre_read_bundle(
    service: &DesktopAgentService,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    started_step: u32,
    bundle: &WebEvidenceBundle,
    query_fallback: &str,
    verification_checks: &mut Vec<String>,
    history_entry: &mut Option<String>,
    action_output: &mut Option<String>,
    terminal_chat_reply_output: &mut Option<String>,
    is_lifecycle_action: &mut bool,
) -> Result<(), TransactionError> {
    let query_value = bundle
        .query
        .clone()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            let trimmed = query_fallback.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        })
        .unwrap_or_else(|| agent_state.goal.clone());
    let query_contract = {
        let trimmed_goal = agent_state.goal.trim();
        if trimmed_goal.is_empty() {
            query_value.clone()
        } else {
            trimmed_goal.to_string()
        }
    };
    let min_sources = web_pipeline_min_sources(&query_contract);
    let started_at_ms = web_pipeline_now_ms();
    let candidate_plan = pre_read_candidate_plan_from_bundle(&query_contract, min_sources, bundle);
    let plan_total_candidates = candidate_plan.total_candidates;
    let plan_pruned_candidates = candidate_plan.pruned_candidates;
    let plan_resolvable_candidates = candidate_plan.resolvable_candidates;
    let probe_source_hints = candidate_plan.probe_source_hints.clone();
    let mut plan_requires_probe = candidate_plan.requires_constraint_search_probe;
    let prior_pending = agent_state.pending_search_completion.clone();
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
        started_step,
        started_at_ms,
        deadline_ms: started_at_ms.saturating_add(WEB_PIPELINE_BUDGET_MS),
        candidate_urls: candidate_plan.candidate_urls,
        candidate_source_hints: candidate_plan.candidate_source_hints,
        attempted_urls: search_url_attempt,
        blocked_urls: Vec::new(),
        successful_reads: Vec::new(),
        min_sources,
    };
    if let Some(existing_pending) = prior_pending {
        pending = merge_pending_search_completion(existing_pending, pending);
    }
    if pending.candidate_urls.is_empty() {
        plan_requires_probe = true;
    }
    if plan_total_candidates == 0 && prior_no_progress_probe_cycle {
        plan_requires_probe = false;
    }

    let queue_now_ms = web_pipeline_now_ms();
    let remaining_budget_ms = web_pipeline_remaining_budget_ms(pending.deadline_ms, queue_now_ms);
    let probe_budget_required_ms = web_pipeline_required_probe_budget_ms(&pending, queue_now_ms);
    let read_budget_required_ms = web_pipeline_required_read_budget_ms(&pending, queue_now_ms);
    let probe_budget_allows =
        web_pipeline_can_queue_probe_search_latency_aware(&pending, queue_now_ms);
    let read_budget_allows =
        web_pipeline_can_queue_initial_read_latency_aware(&pending, queue_now_ms);
    let latency_pressure = web_pipeline_latency_pressure_label(&pending, queue_now_ms);
    let mut completion_reason = web_pipeline_completion_reason(&pending, queue_now_ms);
    let mut queued_next = false;
    let mut queued_probe = false;
    if completion_reason.is_none() {
        if read_budget_allows {
            if let Some(next_url) = next_pending_web_candidate(&pending) {
                queued_next = queue_web_read_from_pipeline(agent_state, session_id, &next_url)?;
            }
        }
        if !queued_next && plan_requires_probe && probe_budget_allows {
            if let Some(probe_query) = constraint_grounded_probe_query_with_hints(
                &query_contract,
                min_sources,
                &probe_source_hints,
                &pending.query,
            ) {
                let search_limit = constraint_grounded_search_limit(&query_contract, min_sources);
                queued_probe = queue_web_search_from_pipeline(
                    agent_state,
                    session_id,
                    &probe_query,
                    search_limit,
                )?;
            }
        }
        if !queued_next && !queued_probe {
            let remaining_candidates = remaining_pending_web_candidates(&pending);
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
        "web_constraint_search_probe_queued={}",
        queued_probe
    ));
    verification_checks.push(format!("web_remaining_budget_ms={}", remaining_budget_ms));
    verification_checks.push(format!(
        "web_probe_budget_required_ms={}",
        probe_budget_required_ms
    ));
    verification_checks.push(format!(
        "web_read_budget_required_ms={}",
        read_budget_required_ms
    ));
    verification_checks.push(format!("web_probe_budget_allows={}", probe_budget_allows));
    verification_checks.push(format!("web_read_budget_allows={}", read_budget_allows));
    verification_checks.push(format!("web_latency_pressure={}", latency_pressure));
    verification_checks.push(format!(
        "web_pipeline_active={}",
        queued_probe || queued_next || (remaining > 0 && !budget_prevents_followup)
    ));
    verification_checks.push("web_sources_success=0".to_string());
    verification_checks.push("web_sources_blocked=0".to_string());
    verification_checks.push("web_budget_ms=0".to_string());

    if let Some(reason) = completion_reason {
        let summary = if let Some(hybrid_summary) = synthesize_web_pipeline_reply_hybrid(
            service.reasoning_inference.clone(),
            &pending,
            reason,
        )
        .await
        {
            hybrid_summary
        } else {
            synthesize_web_pipeline_reply(&pending, reason)
        };
        *action_output = Some(summary.clone());
        *history_entry = Some(summary.clone());
        *terminal_chat_reply_output = Some(summary.clone());
        *is_lifecycle_action = true;
        agent_state.status = AgentStatus::Completed(Some(summary));
        agent_state.pending_search_completion = None;
        agent_state.execution_queue.clear();
        agent_state.recent_actions.clear();
        verification_checks.push("terminal_chat_reply_ready=true".to_string());
    } else if budget_prevents_followup {
        let reason = WebPipelineCompletionReason::DeadlineReached;
        let summary = if let Some(hybrid_summary) = synthesize_web_pipeline_reply_hybrid(
            service.reasoning_inference.clone(),
            &pending,
            reason,
        )
        .await
        {
            hybrid_summary
        } else {
            synthesize_web_pipeline_reply(&pending, reason)
        };
        *action_output = Some(summary.clone());
        *history_entry = Some(summary.clone());
        *terminal_chat_reply_output = Some(summary.clone());
        *is_lifecycle_action = true;
        agent_state.status = AgentStatus::Completed(Some(summary));
        agent_state.pending_search_completion = None;
        agent_state.execution_queue.clear();
        agent_state.recent_actions.clear();
        verification_checks.push("terminal_chat_reply_ready=true".to_string());
    } else if queued_probe || queued_next || remaining > 0 {
        agent_state.pending_search_completion = Some(pending);
    } else {
        let reason = WebPipelineCompletionReason::ExhaustedCandidates;
        let summary = if let Some(hybrid_summary) = synthesize_web_pipeline_reply_hybrid(
            service.reasoning_inference.clone(),
            &pending,
            reason,
        )
        .await
        {
            hybrid_summary
        } else {
            synthesize_web_pipeline_reply(&pending, reason)
        };
        *action_output = Some(summary.clone());
        *history_entry = Some(summary.clone());
        *terminal_chat_reply_output = Some(summary.clone());
        *is_lifecycle_action = true;
        agent_state.status = AgentStatus::Completed(Some(summary));
        agent_state.pending_search_completion = None;
        agent_state.execution_queue.clear();
        agent_state.recent_actions.clear();
        verification_checks.push("terminal_chat_reply_ready=true".to_string());
    }

    Ok(())
}
