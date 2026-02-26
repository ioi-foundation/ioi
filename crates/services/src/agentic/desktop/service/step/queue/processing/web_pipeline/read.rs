use super::*;

pub(in super::super) async fn maybe_handle_web_read(
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
    let remaining_candidates = remaining_pending_web_candidates(&pending);
    let min_sources_required = pending.min_sources.max(1) as usize;
    let floor_unmet = pending.successful_reads.len() < min_sources_required;
    let probe_marker_prefix = "ioi://constraint-probe/";
    let probe_already_attempted = pending
        .attempted_urls
        .iter()
        .any(|url| url.starts_with(probe_marker_prefix));
    let probe_allowed = remaining_candidates == 0 && floor_unmet && !probe_already_attempted;
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
            let locality_hint = if query_requires_runtime_locality_scope(query_contract) {
                effective_locality_scope_hint(None)
            } else {
                None
            };
            let prior_query = if pending.query.trim().is_empty() {
                query_contract.trim()
            } else {
                pending.query.trim()
            };
            if let Some(probe_query) = constraint_grounded_probe_query_with_hints_and_locality_hint(
                query_contract,
                pending.min_sources,
                &pending.candidate_source_hints,
                prior_query,
                locality_hint.as_deref(),
            ) {
                let probe_limit =
                    constraint_grounded_search_limit(query_contract, pending.min_sources);
                probe_queued = queue_web_search_from_pipeline(
                    agent_state,
                    session_id,
                    probe_query.as_str(),
                    probe_limit,
                )?;
                if probe_queued {
                    pending
                        .attempted_urls
                        .push(format!("{}{}", probe_marker_prefix, probe_query));
                    verification_checks
                        .push(format!("web_constraint_search_probe_query={}", probe_query));
                    verification_checks
                        .push(format!("web_constraint_search_probe_limit={}", probe_limit));
                }
            }
        }
    }

    let completion_reason = if probe_queued {
        None
    } else if pending.deadline_ms > 0 && now_ms >= pending.deadline_ms {
        Some(WebPipelineCompletionReason::DeadlineReached)
    } else if remaining_candidates == 0 {
        if pending.successful_reads.len() >= min_sources_required {
            Some(WebPipelineCompletionReason::MinSourcesReached)
        } else {
            Some(WebPipelineCompletionReason::ExhaustedCandidates)
        }
    } else {
        None
    };

    verification_checks.push(format!(
        "web_sources_success={}",
        pending.successful_reads.len()
    ));
    verification_checks.push(format!(
        "web_sources_blocked={}",
        pending.blocked_urls.len()
    ));
    verification_checks.push(format!("web_budget_ms={}", elapsed_ms));
    verification_checks.push(format!("web_remaining_candidates={}", remaining_candidates));
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
        return Ok(());
    }

    let challenge = is_human_challenge_error(err.as_deref().unwrap_or(""));
    verification_checks.push("web_pipeline_active=true".to_string());
    agent_state.pending_search_completion = Some(pending);
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
        agent_state.status = AgentStatus::Running;
    }

    Ok(())
}
