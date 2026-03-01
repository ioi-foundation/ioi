use super::*;
use crate::agentic::desktop::service::step::queue::support::{
    required_story_count, synthesis_query_contract,
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
    let query_contract = synthesis_query_contract(&pending);
    let headline_collection_mode = query_is_generic_headline_collection(&query_contract);
    let required_story_floor = required_story_count(&query_contract).max(1);
    let observed_story_domains = pending
        .successful_reads
        .iter()
        .filter_map(|source| source_host(source.url.trim()))
        .map(|host| host.strip_prefix("www.").unwrap_or(&host).to_string())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let story_floor_met = !headline_collection_mode
        || (pending.successful_reads.len() >= required_story_floor
            && observed_story_domains >= required_story_floor);
    let min_sources_required = pending.min_sources.max(1) as usize;
    let floor_unmet = pending.successful_reads.len() < min_sources_required;
    let source_floor_met = !floor_unmet;
    let quality_floor_unmet = floor_unmet || !story_floor_met;
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
    } else {
        web_pipeline_completion_reason(&pending, now_ms)
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
    verification_checks.push(format!("web_source_floor_met={}", source_floor_met));
    verification_checks.push(format!(
        "web_headline_story_floor_required={}",
        required_story_floor
    ));
    verification_checks.push(format!(
        "web_headline_story_floor_observed={}",
        observed_story_domains
    ));
    verification_checks.push(format!("web_headline_story_floor_met={}", story_floor_met));
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
        let intent_id = resolved_intent_id(agent_state);
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
