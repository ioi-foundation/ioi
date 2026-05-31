use super::*;
use crate::agentic::runtime::service::queue::web_pipeline::WebPipelineCompletionReason;
use crate::agentic::runtime::service::visual_loop::browser_completion::browser_snapshot_completion;

const BROWSER_SNAPSHOT_CONTENT_HASH_RECEIPT: &str = "browser_snapshot_content_hash";
const BROWSER_SNAPSHOT_CONTENT_STEP_RECEIPT: &str = "browser_snapshot_content_step";

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

fn web_pipeline_completion_reason_label(reason: WebPipelineCompletionReason) -> &'static str {
    match reason {
        WebPipelineCompletionReason::MinSourcesReached => "min_sources_reached",
        WebPipelineCompletionReason::ExhaustedCandidates => "exhausted_candidates",
        WebPipelineCompletionReason::DeadlineReached => "deadline_reached",
    }
}

fn preserve_tool_history_or_fill_ready_note(
    history_entry: &mut Option<String>,
    action_output: &mut Option<String>,
) {
    const READY_NOTE: &str = "Web evidence is ready for a model-authored final answer.";
    if history_entry
        .as_deref()
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        *history_entry = Some(READY_NOTE.to_string());
    }
    if action_output
        .as_deref()
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        *action_output = history_entry.clone();
    }
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
    *success = false;
    if error_msg.is_none() {
        *error_msg = Some(format!("ERROR_CLASS=BlockedWebRead {}", note));
    }
    *history_entry = Some(note.clone());
    *action_output = Some(note);
    *stop_condition_hit = true;
    if escalation_path.is_none() {
        *escalation_path = Some("blocked_web_read_requires_remediation".to_string());
    }
    verification_checks.push("web_blocked_read_requires_remediation=true".to_string());
}

fn maybe_normalize_unchanged_browser_snapshot(
    agent_state: &mut AgentState,
    current_tool_name: &str,
    success: &mut bool,
    error_msg: &mut Option<String>,
    history_entry: &mut Option<String>,
    action_output: &mut Option<String>,
    failure_class: &mut Option<FailureClass>,
    verification_checks: &mut Vec<String>,
) {
    if !*success
        || current_tool_name != "browser__inspect"
        || agent_state.pending_search_completion.is_some()
    {
        return;
    }

    let snapshot_output = history_entry
        .as_deref()
        .or(action_output.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let Some(snapshot_output) = snapshot_output else {
        return;
    };

    let Ok(snapshot_digest) = sha256(snapshot_output.as_bytes()) else {
        return;
    };
    let snapshot_hash = hex::encode(snapshot_digest);
    let current_step = agent_state.step_count;
    let prior_hash = execution_evidence_value(
        &agent_state.tool_execution_log,
        BROWSER_SNAPSHOT_CONTENT_HASH_RECEIPT,
    )
    .map(str::to_string);
    let prior_step = execution_evidence_value(
        &agent_state.tool_execution_log,
        BROWSER_SNAPSHOT_CONTENT_STEP_RECEIPT,
    )
    .and_then(|value| value.parse::<u32>().ok());

    record_execution_evidence_with_value(
        &mut agent_state.tool_execution_log,
        BROWSER_SNAPSHOT_CONTENT_HASH_RECEIPT,
        snapshot_hash.clone(),
    );
    record_execution_evidence_with_value(
        &mut agent_state.tool_execution_log,
        BROWSER_SNAPSHOT_CONTENT_STEP_RECEIPT,
        current_step.to_string(),
    );
    verification_checks.push("browser_snapshot_content_hash_recorded=true".to_string());

    let unchanged_immediate_replay = prior_hash.as_deref() == Some(snapshot_hash.as_str())
        && prior_step
            .map(|step| current_step == step.saturating_add(1))
            .unwrap_or(false);
    if !unchanged_immediate_replay {
        return;
    }

    let summary = "Repeated `browser__inspect` returned the same browser state as the previous step. Do not call `browser__inspect` again yet. Use a different browser action or act on the visible control already named in `RECENT PENDING BROWSER STATE`.".to_string();
    *success = false;
    *failure_class = Some(FailureClass::NoEffectAfterAction);
    *error_msg = Some(format!("ERROR_CLASS=NoEffectAfterAction {}", summary));
    *history_entry = Some(summary);
    *action_output = error_msg.clone();
    verification_checks.push("browser_snapshot_immediate_replay_unchanged=true".to_string());
}

fn resolved_install_plan_ref_from_output(output: Option<&str>) -> Option<String> {
    let text = output?.trim();
    let json_start = text.find('{')?;
    let value: serde_json::Value = serde_json::from_str(&text[json_start..]).ok()?;
    value
        .get("install_event")
        .and_then(|event| event.get("plan_ref"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
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
        block_timestamp_ns: _block_timestamp_ns,
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
        tool_normalization_observation,
        mut awaiting_sudo_password,
        mut awaiting_clarification,
        command_probe_completed,
        invalid_tool_call_fail_fast,
        invalid_tool_call_bootstrap_web,
        invalid_tool_call_fail_fast_mailbox,
        mut terminal_chat_reply_output,
    } = state_in;
    let is_software_install_tool = current_tool_name == "software_install__execute_plan";
    let clarification_required = !success
        && error_msg
            .as_deref()
            .map(|msg| requires_wait_for_clarification(&current_tool_name, msg))
            .unwrap_or(false);

    if !success
        && is_software_install_tool
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

    if success
        && current_tool_name == "software_install__resolve"
        && !is_gated
        && !awaiting_sudo_password
        && !awaiting_clarification
    {
        if let Some(plan_ref) = resolved_install_plan_ref_from_output(
            history_entry.as_deref().or(action_output.as_deref()),
        ) {
            let params = serde_json::to_vec(&serde_json::json!({ "plan_ref": plan_ref }))
                .map_err(|error| TransactionError::Serialization(error.to_string()))?;
            agent_state.execution_queue.insert(
                0,
                ioi_types::app::ActionRequest {
                    target: ioi_types::app::ActionTarget::SoftwareInstallExecute,
                    params,
                    context: ioi_types::app::ActionContext {
                        agent_id: "desktop_agent".to_string(),
                        session_id: Some(session_id),
                        window_id: None,
                    },
                    nonce: agent_state.step_count as u64
                        + agent_state.execution_queue.len() as u64
                        + 1,
                },
            );
            is_lifecycle_action = true;
            agent_state.status = AgentStatus::Running;
            verification_checks.push("install_execute_queued_from_resolved_plan=true".to_string());
        }
    }

    if invalid_tool_call_fail_fast
        && !is_gated
        && !awaiting_sudo_password
        && !awaiting_clarification
    {
        let feedback = if invalid_tool_call_fail_fast_mailbox {
            concat!(
                "Tool result: mailbox connector action returned an invalid tool payload. ",
                "Return this typed failure to the model loop so it can retry the connector action ",
                "or produce a model-authored blocker."
            )
            .to_string()
        } else {
            "Tool result: invalid tool call generated during web research; return this typed failure to the model loop for retry, narrowing, or a model-authored blocker."
                .to_string()
        };
        success = true;
        error_msg = None;
        stop_condition_hit = false;
        escalation_path = None;
        is_lifecycle_action = false;
        history_entry = Some(feedback.clone());
        action_output = Some(feedback);
        if invalid_tool_call_fail_fast_mailbox {
            terminal_chat_reply_output = None;
            verification_checks
                .push("mailbox_invalid_tool_call_returned_to_model_loop=true".to_string());
            verification_checks.push("terminal_chat_reply_ready=false".to_string());
        }
        agent_state.status = AgentStatus::Running;
        verification_checks.push("invalid_tool_call_returned_to_model_loop=true".to_string());
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
            "Model returned empty tool output; queued typed web__search.".to_string()
        } else {
            "Model returned empty tool output; web__search bootstrap already queued.".to_string()
        };
        history_entry = Some(note.clone());
        action_output = Some(note);
        agent_state.status = AgentStatus::Running;
        verification_checks.push("invalid_tool_call_bootstrap_web=true".to_string());
    }

    if !is_gated && !awaiting_sudo_password && !awaiting_clarification {
        maybe_normalize_unchanged_browser_snapshot(
            agent_state,
            &current_tool_name,
            &mut success,
            &mut error_msg,
            &mut history_entry,
            &mut action_output,
            &mut failure_class,
            &mut verification_checks,
        );
    }

    if !is_gated
        && !awaiting_sudo_password
        && !awaiting_clarification
        && success
        && terminal_chat_reply_output.is_none()
    {
        if let Some(completion) = browser_snapshot_completion(
            agent_state,
            &current_tool_name,
            history_entry.as_deref().or(action_output.as_deref()),
        ) {
            completion.append_contract_checks(&mut verification_checks);
            let summary = completion.summary;
            history_entry = Some(summary.clone());
            action_output = Some(summary.clone());
            terminal_chat_reply_output = Some(summary.clone());
            is_lifecycle_action = true;
            stop_condition_hit = true;
            escalation_path = None;
            agent_state.status = AgentStatus::Completed(Some(summary));
            agent_state.execution_queue.clear();
            agent_state.recent_actions.clear();
            agent_state.pending_search_completion = None;
        }
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
                let intent_id = resolved_intent_id(agent_state);
                emit_completion_gate_status_event(
                    service,
                    session_id,
                    agent_state.step_count,
                    intent_id.as_str(),
                    true,
                    "web_pipeline_evidence_ready_for_model_answer",
                );
                verification_checks.push("cec_completion_gate_emitted=true".to_string());
                verification_checks.push(format!(
                    "web_pipeline_model_answer_ready_reason={}",
                    web_pipeline_completion_reason_label(reason)
                ));
                verification_checks
                    .push("web_pipeline_waiting_for_model_authored_answer=true".to_string());
                verification_checks.push("web_pipeline_active=true".to_string());
                verification_checks.push("terminal_chat_reply_ready=false".to_string());
                let drained =
                    crate::agentic::runtime::service::queue::drain_queued_web_retrieve_actions(
                        agent_state,
                    );
                verification_checks.push(format!(
                    "web_pipeline_queued_retrievals_drained_for_model_answer={}",
                    drained
                ));
                success = true;
                error_msg = None;
                preserve_tool_history_or_fill_ready_note(&mut history_entry, &mut action_output);
                stop_condition_hit = false;
                terminal_chat_reply_output = None;
                is_lifecycle_action = false;
                agent_state.status = AgentStatus::Running;
                agent_state.pending_search_completion = Some(pending);
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
        tool_normalization_observation,
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
#[path = "apply_post_execution_guards/tests.rs"]
mod tests;
