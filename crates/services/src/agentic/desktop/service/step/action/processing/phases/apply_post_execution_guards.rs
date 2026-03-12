use super::*;

fn blocked_web_read_note(read_url: &str, challenged: bool) -> String {
    if challenged {
        return format!(
            "Recorded challenged source in fixed payload (no fallback retries): {}",
            read_url
        );
    }

    format!(
        "Source read failed in fixed payload (no fallback retries): {}",
        read_url
    )
}

fn normalize_blocked_web_read_for_continuation(
    success: &mut bool,
    error_msg: &mut Option<String>,
    history_entry: &mut Option<String>,
    action_output: &mut Option<String>,
    stop_condition_hit: &mut bool,
    escalation_path: &mut Option<String>,
    verification_checks: &mut Vec<String>,
    read_url: &str,
    challenged: bool,
) {
    if *success {
        return;
    }

    let note = blocked_web_read_note(read_url, challenged);
    *success = true;
    *error_msg = None;
    *history_entry = Some(note.clone());
    *action_output = Some(note);
    *stop_condition_hit = false;
    *escalation_path = None;
    verification_checks.push("web_blocked_read_continues=true".to_string());
}

pub(crate) async fn apply_post_execution_guards(
    ctx: ApplyPostExecutionGuardsContext<'_, '_>,
    state_in: ActionProcessingState,
) -> Result<ActionProcessingState, TransactionError> {
    let ApplyPostExecutionGuardsContext {
        service,
        state,
        agent_state,
        session_id,
        block_height,
        block_timestamp_ns,
        tool_call_result,
        final_visual_phash,
    } = ctx;

    let ActionProcessingState {
        policy_decision,
        action_payload,
        intent_hash,
        retry_intent_hash,
        mut success,
        mut error_msg,
        is_gated,
        mut is_lifecycle_action,
        current_tool_name,
        mut history_entry,
        mut action_output,
        trace_visual_hash,
        executed_tool_jcs,
        mut failure_class,
        mut stop_condition_hit,
        mut escalation_path,
        remediation_queued,
        mut verification_checks,
        mut awaiting_sudo_password,
        mut awaiting_clarification,
        command_probe_completed,
        invalid_tool_call_fail_fast,
        invalid_tool_call_bootstrap_web,
        invalid_tool_call_fail_fast_mailbox,
        mut terminal_chat_reply_output,
    } = state_in;
    let is_install_package_tool = current_tool_name == "sys__install_package"
        || current_tool_name == "sys::install_package"
        || current_tool_name.ends_with("install_package");
    let clarification_required = !success
        && error_msg
            .as_deref()
            .map(|msg| requires_wait_for_clarification(&current_tool_name, msg))
            .unwrap_or(false);

    if !success
        && is_install_package_tool
        && error_msg
            .as_deref()
            .map(is_sudo_password_required_install_error)
            .unwrap_or(false)
    {
        awaiting_sudo_password = true;
        stop_condition_hit = true;
        escalation_path = Some("wait_for_sudo_password".to_string());
        is_lifecycle_action = true;
        failure_class = Some(FailureClass::PermissionOrApprovalRequired);
        agent_state.status = AgentStatus::Paused("Waiting for sudo password".to_string());
        mark_incident_wait_for_user(
            state,
            session_id,
            "wait_for_sudo_password",
            FailureClass::PermissionOrApprovalRequired,
            error_msg.as_deref(),
        )?;
        // Discard any queued remediation actions so resume prioritizes retrying
        // the canonical pending install with user-provided runtime secret.
        agent_state.execution_queue.clear();
        agent_state.pending_approval = None;
        agent_state.pending_tool_call = Some(tool_call_result.clone());
        agent_state.pending_request_nonce = Some(agent_state.step_count as u64);
        agent_state.pending_visual_hash = Some(final_visual_phash);
        agent_state.last_screen_phash = Some(final_visual_phash);
        if let Some(tool_jcs) = executed_tool_jcs.clone() {
            let tool_hash_bytes = ioi_crypto::algorithms::hash::sha256(&tool_jcs).map_err(|e| {
                TransactionError::Invalid(format!("Failed to hash pending install tool: {}", e))
            })?;
            let mut hash_arr = [0u8; 32];
            hash_arr.copy_from_slice(tool_hash_bytes.as_ref());
            agent_state.pending_tool_jcs = Some(tool_jcs);
            agent_state.pending_tool_hash = Some(hash_arr);
        }
        if let Some(err_text) = error_msg.clone() {
            let tool_msg = ioi_types::app::agentic::ChatMessage {
                role: "tool".to_string(),
                content: format!("Tool Output ({}): {}", current_tool_name, err_text),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
                trace_hash: None,
            };
            let _ = service
                .append_chat_to_scs(session_id, &tool_msg, block_height)
                .await?;
        }
        let sys_msg = ioi_types::app::agentic::ChatMessage {
            role: "system".to_string(),
            content: "System: WAIT_FOR_SUDO_PASSWORD. Install requires sudo password. Enter password to retry once."
                .to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            trace_hash: None,
        };
        let _ = service
            .append_chat_to_scs(session_id, &sys_msg, block_height)
            .await?;
        verification_checks.push("awaiting_sudo_password=true".to_string());
    }

    if clarification_required {
        awaiting_clarification = true;
        stop_condition_hit = true;
        escalation_path = Some("wait_for_clarification".to_string());
        is_lifecycle_action = true;
        failure_class = Some(FailureClass::UserInterventionNeeded);
        mark_incident_wait_for_user(
            state,
            session_id,
            "wait_for_clarification",
            FailureClass::UserInterventionNeeded,
            error_msg.as_deref(),
        )?;
        agent_state.status =
            AgentStatus::Paused("Waiting for clarification on target identity.".to_string());
        agent_state.pending_approval = None;
        agent_state.pending_tool_call = None;
        agent_state.pending_tool_jcs = None;
        agent_state.pending_tool_hash = None;
        agent_state.pending_request_nonce = None;
        agent_state.pending_visual_hash = None;
        agent_state.execution_queue.clear();

        if let Some(err_text) = error_msg.clone() {
            let tool_msg = ioi_types::app::agentic::ChatMessage {
                role: "tool".to_string(),
                content: format!("Tool Output ({}): {}", current_tool_name, err_text),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
                trace_hash: None,
            };
            let _ = service
                .append_chat_to_scs(session_id, &tool_msg, block_height)
                .await?;
        }
        let sys_msg = ioi_types::app::agentic::ChatMessage {
            role: "system".to_string(),
            content:
                "System: WAIT_FOR_CLARIFICATION. Target identity could not be resolved. Provide clarification input to continue."
                    .to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            trace_hash: None,
        };
        let _ = service
            .append_chat_to_scs(session_id, &sys_msg, block_height)
            .await?;
        verification_checks.push("awaiting_clarification=true".to_string());
    }

    if invalid_tool_call_fail_fast
        && !is_gated
        && !awaiting_sudo_password
        && !awaiting_clarification
    {
        let summary = if invalid_tool_call_fail_fast_mailbox {
            format!(
                "Mailbox connector action executed, but response synthesis failed due schema validation. Please retry the request. Run timestamp (UTC ms): {}.",
                block_timestamp_ns / 1_000_000
            )
        } else {
            "Invalid tool call generated during web research. Stopping early to avoid recovery churn."
                .to_string()
        };
        success = true;
        error_msg = None;
        stop_condition_hit = true;
        escalation_path = Some("invalid_tool_call_fail_fast".to_string());
        is_lifecycle_action = true;
        action_output = Some(summary.clone());
        if invalid_tool_call_fail_fast_mailbox {
            terminal_chat_reply_output = Some(summary.clone());
            verification_checks.push("mailbox_invalid_tool_call_fail_fast=true".to_string());
            verification_checks.push("terminal_chat_reply_ready=true".to_string());
        }
        agent_state.status = AgentStatus::Completed(Some(summary));
        agent_state.execution_queue.clear();
        agent_state.pending_search_completion = None;
        verification_checks.push("invalid_tool_call_fail_fast=true".to_string());
    }

    if invalid_tool_call_bootstrap_web
        && !is_gated
        && !awaiting_sudo_password
        && !awaiting_clarification
    {
        let goal = agent_state.goal.clone();
        let queued = queue_web_search_bootstrap(agent_state, session_id, &goal)?;
        success = true;
        error_msg = None;
        stop_condition_hit = false;
        escalation_path = None;
        is_lifecycle_action = true;
        let note = if queued {
            "Model returned empty tool output; bootstrapped deterministic web__search.".to_string()
        } else {
            "Model returned empty tool output; web__search bootstrap already queued.".to_string()
        };
        history_entry = Some(note.clone());
        action_output = Some(note);
        agent_state.status = AgentStatus::Running;
        verification_checks.push("invalid_tool_call_bootstrap_web=true".to_string());
    }

    if !is_gated
        && !awaiting_sudo_password
        && !awaiting_clarification
        && current_tool_name == "web__read"
    {
        if let Some(mut pending) = agent_state.pending_search_completion.clone() {
            let read_url = extract_web_read_url_from_payload(&action_payload).unwrap_or_default();
            if !read_url.is_empty() {
                mark_pending_web_attempted(&mut pending, &read_url);
            }

            if success {
                if let Some(bundle) = history_entry.as_deref().and_then(parse_web_evidence_bundle) {
                    append_pending_web_success_from_bundle(&mut pending, &bundle, &read_url);
                } else {
                    append_pending_web_success_fallback(
                        &mut pending,
                        &read_url,
                        history_entry.as_deref(),
                    );
                }
            } else if !read_url.is_empty()
                && is_human_challenge_error(error_msg.as_deref().unwrap_or(""))
            {
                mark_pending_web_blocked(&mut pending, &read_url);
            }

            let now_ms = web_pipeline_now_ms();
            let elapsed_ms = now_ms.saturating_sub(pending.started_at_ms);
            let remaining_candidates = remaining_pending_web_candidates(&pending);
            let completion_reason = web_pipeline_completion_reason(&pending, now_ms);

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
            verification_checks.push(format!("web_constraint_search_probe_queued={}", false));

            if let Some(reason) = completion_reason {
                let mut summary_candidates = Vec::new();
                if let Some(hybrid_summary) =
                    synthesize_web_pipeline_reply_hybrid(service, &pending, reason).await
                {
                    summary_candidates.push(
                        crate::agentic::desktop::service::step::queue::web_pipeline::FinalWebSummaryCandidate {
                            provider: "hybrid",
                            summary: hybrid_summary,
                        },
                    );
                }
                summary_candidates.push(
                    crate::agentic::desktop::service::step::queue::web_pipeline::FinalWebSummaryCandidate {
                        provider: "deterministic",
                        summary: synthesize_web_pipeline_reply(&pending, reason),
                    },
                );
                let selection =
                    crate::agentic::desktop::service::step::queue::web_pipeline::select_final_web_summary_from_candidates(
                        &pending,
                        reason,
                        summary_candidates,
                    )
                    .expect("web summary selection requires at least one candidate");
                verification_checks
                    .push(format!("web_final_summary_provider={}", selection.provider));
                verification_checks.push(format!(
                    "web_final_summary_contract_ready={}",
                    selection.contract_ready
                ));
                for evaluation in &selection.evaluations {
                    verification_checks.push(format!(
                        "web_final_summary_candidate={}::contract_ready={}::rendered_layout={}::document_layout_met={}",
                        evaluation.provider,
                        evaluation.contract_ready,
                        evaluation.facts.briefing_rendered_layout_profile,
                        evaluation.facts.briefing_document_layout_met
                    ));
                }
                let summary = selection.summary;
                let final_facts =
                    final_web_completion_facts_with_rendered_summary(&pending, reason, &summary);
                let intent_id = resolved_intent_id(agent_state);
                crate::agentic::desktop::service::step::queue::emit_final_web_completion_contract_receipts(
                    service,
                    session_id,
                    agent_state.step_count,
                    intent_id.as_str(),
                    &final_facts,
                );
                append_final_web_completion_receipts_with_rendered_summary(
                    &pending,
                    reason,
                    &summary,
                    &mut verification_checks,
                );
                if !crate::agentic::desktop::service::step::queue::web_pipeline::final_web_completion_contract_ready(&final_facts) {
                    agent_state.pending_search_completion = Some(pending);
                    verification_checks.push("execution_contract_gate_blocked=true".to_string());
                    verification_checks.push(
                        "execution_contract_missing_keys=receipt::final_output_contract_ready=true"
                            .to_string(),
                    );
                    verification_checks.push(
                        "web_pipeline_terminalization_blocked_on_rendered_output=true"
                            .to_string(),
                    );
                    verification_checks.push("web_pipeline_active=true".to_string());
                    verification_checks.push("terminal_chat_reply_ready=false".to_string());
                    let blocked_by_challenge =
                        is_human_challenge_error(error_msg.as_deref().unwrap_or(""));
                    normalize_blocked_web_read_for_continuation(
                        &mut success,
                        &mut error_msg,
                        &mut history_entry,
                        &mut action_output,
                        &mut stop_condition_hit,
                        &mut escalation_path,
                        &mut verification_checks,
                        &read_url,
                        blocked_by_challenge,
                    );
                    if success {
                        agent_state.status = AgentStatus::Running;
                    }
                } else {
                    success = true;
                    error_msg = None;
                    action_output = Some(summary.clone());
                    history_entry = Some(summary.clone());
                    terminal_chat_reply_output = Some(summary.clone());
                    is_lifecycle_action = true;
                    agent_state.status = AgentStatus::Completed(Some(summary));
                    agent_state.pending_search_completion = None;
                    agent_state.execution_queue.clear();
                    agent_state.recent_actions.clear();
                    verification_checks.push("web_pipeline_active=false".to_string());
                    verification_checks.push("terminal_chat_reply_ready=true".to_string());
                }
            } else {
                let challenge = is_human_challenge_error(error_msg.as_deref().unwrap_or(""));
                agent_state.pending_search_completion = Some(pending);
                verification_checks.push("web_pipeline_active=true".to_string());
                normalize_blocked_web_read_for_continuation(
                    &mut success,
                    &mut error_msg,
                    &mut history_entry,
                    &mut action_output,
                    &mut stop_condition_hit,
                    &mut escalation_path,
                    &mut verification_checks,
                    &read_url,
                    challenge,
                );
                if success {
                    agent_state.status = AgentStatus::Running;
                }
            }
        }
    }

    Ok(ActionProcessingState {
        policy_decision,
        action_payload,
        intent_hash,
        retry_intent_hash,
        success,
        error_msg,
        is_gated,
        is_lifecycle_action,
        current_tool_name,
        history_entry,
        action_output,
        trace_visual_hash,
        executed_tool_jcs,
        failure_class,
        stop_condition_hit,
        escalation_path,
        remediation_queued,
        verification_checks,
        awaiting_sudo_password,
        awaiting_clarification,
        command_probe_completed,
        invalid_tool_call_fail_fast,
        invalid_tool_call_bootstrap_web,
        invalid_tool_call_fail_fast_mailbox,
        terminal_chat_reply_output,
    })
}

#[cfg(test)]
mod tests {
    use super::{blocked_web_read_note, normalize_blocked_web_read_for_continuation};

    #[test]
    fn blocked_web_read_note_distinguishes_challenge_from_generic_failure() {
        assert_eq!(
            blocked_web_read_note("https://example.com", true),
            "Recorded challenged source in fixed payload (no fallback retries): https://example.com"
        );
        assert_eq!(
            blocked_web_read_note("https://example.com", false),
            "Source read failed in fixed payload (no fallback retries): https://example.com"
        );
    }

    #[test]
    fn normalize_blocked_web_read_for_continuation_clears_failure_state() {
        let mut success = false;
        let mut error_msg = Some("ERROR_CLASS=HumanChallengeRequired captcha".to_string());
        let mut history_entry = None;
        let mut action_output = None;
        let mut stop_condition_hit = true;
        let mut escalation_path = Some("pause".to_string());
        let mut verification_checks = Vec::new();

        normalize_blocked_web_read_for_continuation(
            &mut success,
            &mut error_msg,
            &mut history_entry,
            &mut action_output,
            &mut stop_condition_hit,
            &mut escalation_path,
            &mut verification_checks,
            "https://example.com",
            true,
        );

        assert!(success);
        assert!(error_msg.is_none());
        assert_eq!(
            history_entry.as_deref(),
            Some(
                "Recorded challenged source in fixed payload (no fallback retries): https://example.com"
            )
        );
        assert_eq!(history_entry, action_output);
        assert!(!stop_condition_hit);
        assert!(escalation_path.is_none());
        assert!(verification_checks
            .iter()
            .any(|check| check == "web_blocked_read_continues=true"));
    }
}
