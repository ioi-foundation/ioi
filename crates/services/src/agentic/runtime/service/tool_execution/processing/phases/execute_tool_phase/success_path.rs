use super::command_failure_reply::governed_shell_failure_terminal_reply;
use super::events::{
    emit_execution_contract_receipt_event, emit_execution_contract_receipt_event_with_observation,
};
use super::file_policy_observation::{
    governed_file_policy_failure_observation, record_policy_blocked_workspace_read_observation,
};
use super::tool_outcome::{apply_tool_outcome_and_followups, ToolOutcomeContext};
use super::*;
use crate::agentic::runtime::service::decision_loop::cognition::build_browser_snapshot_pending_state_context_with_history;
use crate::agentic::runtime::service::lifecycle::{
    browser_subagent_request_from_dynamic, run_browser_subagent,
};
use crate::agentic::runtime::service::tool_execution::tool_success_evidence_name;
use crate::agentic::runtime::event_log_bridge::managed_session_projected_event;
use crate::agentic::runtime::managed_session_snapshot::{
    managed_session_snapshot_for_state, record_managed_browser_session_result,
};
use serde_json::json;

mod chat_context;
mod receipts;

use chat_context::{compact_tool_history_entry_for_chat, tool_history_message_content};
use receipts::{
    record_browser_success_markers, record_install_success_contract_receipts,
    record_workspace_change_lifecycle_receipt, record_workspace_edit_receipt,
    record_workspace_read_receipt,
};

pub(crate) use receipts::record_non_command_success_receipts;
#[cfg(test)]
pub(super) use receipts::workspace_change_lifecycle_receipt_details;

#[cfg(test)]
use chat_context::{
    transcript_context_excerpts, TOOL_CHAT_HISTORY_BROWSER_CLICK_CHAR_LIMIT,
    TOOL_CHAT_HISTORY_BROWSER_SNAPSHOT_CHAR_LIMIT, TOOL_CHAT_HISTORY_RAW_CHAR_LIMIT,
};

#[cfg(test)]
use receipts::{workspace_edit_receipt_details, workspace_read_receipt_details};

pub(super) struct ExecutionSuccessContext<'a, 's> {
    pub service: &'a RuntimeAgentService,
    pub state: &'s mut dyn StateAccess,
    pub agent_state: &'a mut AgentState,
    pub rules: &'a ActionRules,
    pub call_context: ServiceCallContext<'a>,
    pub tool: &'a AgentTool,
    pub tool_args: &'a serde_json::Value,
    pub session_id: [u8; 32],
    pub block_height: u64,
    pub block_timestamp_ns: u64,
    pub step_index: u32,
    pub resolved_intent_id: &'a str,
    pub synthesized_payload_hash: Option<String>,
    pub command_scope: bool,
    pub req_hash_hex: &'a str,
    pub retry_intent_hash: Option<&'a str>,
    pub success: &'a mut bool,
    pub error_msg: &'a mut Option<String>,
    pub history_entry: &'a mut Option<String>,
    pub action_output: &'a mut Option<String>,
    pub trace_visual_hash: &'a mut Option<[u8; 32]>,
    pub is_lifecycle_action: &'a mut bool,
    pub current_tool_name: &'a mut String,
    pub terminal_chat_reply_output: &'a mut Option<String>,
    pub verification_checks: &'a mut Vec<String>,
    pub command_probe_completed: &'a mut bool,
    pub execution_result: (bool, Option<String>, Option<String>, Option<[u8; 32]>),
}

/// Managed-session producer (real session-lifecycle). On a successful `browser__*`
/// tool, record the managed browser session into KV via the same recorder the
/// managed-session snapshot reads, then emit a `managed_session.projected` runtime
/// thread event on the KernelEvent channel. The event-log bridge resolves the
/// daemon thread for `session_id` and persists it to `<state_dir>/events`, so
/// `GET /v1/threads/:id/managed-sessions` projects real sessions. Best-effort: any
/// failure (non-browser tool, KV error, empty snapshot, no event channel) is a
/// silent no-op and never affects the turn.
fn emit_managed_browser_session(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    agent_state: &AgentState,
    tool_name: &str,
    output: Option<&str>,
    error_class: Option<&str>,
    block_timestamp_ns: u64,
) {
    if !tool_name.trim().to_ascii_lowercase().starts_with("browser__") {
        return;
    }
    let updated_at_ms = block_timestamp_ns / 1_000_000;
    if record_managed_browser_session_result(
        state,
        agent_state,
        tool_name,
        output.unwrap_or_default(),
        error_class,
        updated_at_ms,
    )
    .is_err()
    {
        return;
    }
    let Ok(snapshot) = managed_session_snapshot_for_state(state, agent_state) else {
        return;
    };
    if snapshot.sessions.is_empty() {
        return;
    }
    let Some(tx) = service.event_sender.as_ref() else {
        return;
    };
    let event = managed_session_projected_event(&agent_state.session_id, &snapshot);
    let Ok(event_json) = serde_json::to_string(&event) else {
        return;
    };
    let _ = tx.send(ioi_types::app::KernelEvent::RuntimeThreadEvent {
        session_id: agent_state.session_id,
        event_json,
    });
}

fn should_treat_command_failure_as_tool_observation(
    command_scope: bool,
    tool: &AgentTool,
    success: bool,
    history_entry: &Option<String>,
    governed_shell_failure_terminal_reply_ready: bool,
) -> bool {
    command_scope
        && is_command_execution_provider_tool(tool)
        && !success
        && !governed_shell_failure_terminal_reply_ready
        && command_history::extract_command_history(history_entry).is_some()
}

pub(super) async fn handle_execution_success(
    ctx: ExecutionSuccessContext<'_, '_>,
) -> Result<(), TransactionError> {
    let ExecutionSuccessContext {
        service,
        state,
        agent_state,
        rules,
        call_context,
        tool,
        tool_args,
        session_id,
        block_height,
        block_timestamp_ns,
        step_index,
        resolved_intent_id,
        synthesized_payload_hash,
        command_scope,
        req_hash_hex,
        retry_intent_hash,
        success,
        error_msg,
        history_entry,
        action_output,
        trace_visual_hash,
        is_lifecycle_action,
        current_tool_name,
        terminal_chat_reply_output,
        verification_checks,
        command_probe_completed,
        execution_result,
    } = ctx;

    let (s, entry, e, visual_hash) = execution_result;
    *success = s;
    *error_msg = e;
    *history_entry = entry.clone();
    if let Some(visual_hash) = visual_hash {
        *trace_visual_hash = Some(visual_hash);
        verification_checks.push(format!(
            "visual_observation_checksum={}",
            hex::encode(visual_hash)
        ));
    }
    let governed_shell_failure_terminal_reply_ready =
        if command_scope && is_command_execution_provider_tool(tool) && !*success {
            let failure_text = error_msg.as_deref().or_else(|| history_entry.as_deref());
            if let Some(reply) = failure_text
                .and_then(|failure| governed_shell_failure_terminal_reply(tool, failure))
            {
                *action_output = Some(reply.clone());
                *terminal_chat_reply_output = Some(reply);
                verification_checks
                    .push("governed_shell_failure_terminal_reply_ready=true".to_string());
                verification_checks.push("terminal_chat_reply_ready=true".to_string());
                true
            } else {
                false
            }
        } else {
            false
        };
    if should_treat_command_failure_as_tool_observation(
        command_scope,
        tool,
        *success,
        history_entry,
        governed_shell_failure_terminal_reply_ready,
    ) {
        verification_checks.push("command_failure_observed_as_tool_result=true".to_string());
        *success = true;
        *error_msg = None;
    }
    if !*success {
        let failure_text = error_msg
            .as_deref()
            .or_else(|| history_entry.as_deref())
            .map(str::to_string);
        if let Some(failure_text) = failure_text {
            record_policy_blocked_workspace_read_observation(
                agent_state,
                tool,
                step_index,
                &failure_text,
            );
            if let Some(observation) = governed_file_policy_failure_observation(tool, &failure_text)
            {
                *history_entry = Some(observation.clone());
                *action_output = Some(observation.clone());
                *terminal_chat_reply_output = Some(observation);
                verification_checks
                    .push("governed_file_policy_failure_terminal_reply_ready=true".to_string());
                verification_checks.push("terminal_chat_reply_ready=true".to_string());
            }
        }
    }
    if command_scope && is_command_execution_provider_tool(tool) && !*success {
        let cause = error_msg
            .clone()
            .unwrap_or_else(|| "unknown execution failure".to_string());
        if !cause.contains("ERROR_CLASS=ExecutionFailedTerminal") {
            *error_msg = Some(format!(
                "ERROR_CLASS=ExecutionFailedTerminal stage=execution cause={}",
                cause
            ));
        }
        let execution_failure = error_msg
            .clone()
            .unwrap_or_else(|| "ERROR_CLASS=ExecutionFailedTerminal".to_string());
        emit_execution_contract_receipt_event(
            service,
            session_id,
            step_index,
            resolved_intent_id,
            "execution",
            "execution",
            false,
            &execution_failure,
            None,
            None,
            synthesized_payload_hash.clone(),
        );
    }
    if *success && !current_tool_name.trim().is_empty() {
        let tool_evidence_name = tool_success_evidence_name(current_tool_name);
        record_execution_evidence_with_value(
            &mut agent_state.tool_execution_log,
            &tool_evidence_name,
            format!("step={};tool={}", step_index, current_tool_name),
        );
        verification_checks.push(execution_evidence_key(&tool_evidence_name));
    }

    // Orchestration meta-tools require access to chain state; execute them
    // on the primary path here instead of the stateless ToolExecutor.
    if *success {
        match tool {
            AgentTool::AgentDelegate {
                goal,
                budget,
                playbook_id,
                template_id,
                workflow_id,
                role,
                success_criteria,
                merge_mode,
                expected_output,
            } => {
                let tool_jcs = match serde_jcs::to_vec(tool) {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        *success = false;
                        *error_msg = Some(format!(
                            "ERROR_CLASS=UnexpectedState Failed to encode delegation tool: {}",
                            err
                        ));
                        *history_entry = None;
                        Vec::new()
                    }
                };

                if *success {
                    match sha256(&tool_jcs) {
                        Ok(tool_hash) => {
                            match spawn_delegated_child_session(
                                service,
                                state,
                                agent_state,
                                tool_hash,
                                goal,
                                *budget,
                                playbook_id.as_deref(),
                                template_id.as_deref(),
                                workflow_id.as_deref(),
                                role.as_deref(),
                                success_criteria.as_deref(),
                                merge_mode.as_deref(),
                                expected_output.as_deref(),
                                step_index,
                                block_height,
                            )
                            .await
                            {
                                Ok(spawned) => {
                                    let assignment = &spawned.assignment;
                                    *history_entry = Some(
                                        json!({
                                            "child_session_id_hex": hex::encode(spawned.child_session_id),
                                            "budget": assignment.budget,
                                            "playbook_id": assignment.playbook_id,
                                            "template_id": assignment.template_id,
                                            "workflow_id": assignment.workflow_id,
                                            "role": assignment.role,
                                            "success_criteria": assignment.completion_contract.success_criteria,
                                            "merge_mode": assignment.completion_contract.merge_mode.as_label(),
                                            "expected_output": assignment.completion_contract.expected_output,
                                        })
                                        .to_string(),
                                    );
                                    *error_msg = None;
                                }
                                Err(err) => {
                                    *success = false;
                                    *error_msg = Some(err.to_string());
                                    *history_entry = None;
                                }
                            }
                        }
                        Err(err) => {
                            *success = false;
                            *error_msg = Some(format!(
                                "ERROR_CLASS=UnexpectedState Delegation hash failed: {}",
                                err
                            ));
                            *history_entry = None;
                        }
                    }
                }
            }
            AgentTool::AgentAwait {
                child_session_id_hex,
            } => match child_session::await_child_session_status(
                service,
                state,
                agent_state,
                step_index,
                block_height,
                call_context,
                child_session_id_hex,
            )
            .await
            {
                Ok(out) => {
                    *history_entry = Some(out);
                    *error_msg = None;
                }
                Err(err) => {
                    *success = false;
                    *error_msg = Some(err);
                    *history_entry = None;
                }
            },
            AgentTool::Dynamic(value) => {
                match browser_subagent_request_from_dynamic(value).and_then(|request| {
                    request.ok_or_else(|| {
                        "ERROR_CLASS=UnsupportedTool browser__subagent request missing.".to_string()
                    })
                }) {
                    Ok(request) => {
                        let tool_jcs = match serde_jcs::to_vec(tool) {
                            Ok(bytes) => bytes,
                            Err(err) => {
                                *success = false;
                                *error_msg = Some(format!(
                                    "ERROR_CLASS=UnexpectedState Failed to encode browser subagent tool: {}",
                                    err
                                ));
                                *history_entry = None;
                                Vec::new()
                            }
                        };

                        if *success {
                            match sha256(&tool_jcs) {
                                Ok(tool_hash) => match run_browser_subagent(
                                    service,
                                    state,
                                    agent_state,
                                    tool_hash,
                                    step_index,
                                    block_height,
                                    call_context,
                                    &request,
                                )
                                .await
                                {
                                    Ok(browser_outcome) => {
                                        *history_entry = Some(
                                            json!({
                                                "child_session_id_hex": browser_outcome.child_session_id_hex,
                                                "status": browser_outcome.status,
                                                "task_name": request.task_name,
                                                "recording_name": request.recording_name,
                                                "final_report": browser_outcome.final_report,
                                            })
                                            .to_string(),
                                        );
                                        *success = browser_outcome.success;
                                        *error_msg = if browser_outcome.success {
                                            None
                                        } else {
                                            Some(
                                                "Browser subagent returned control to the parent."
                                                    .to_string(),
                                            )
                                        };
                                    }
                                    Err(err) => {
                                        *success = false;
                                        *error_msg = Some(err);
                                        *history_entry = None;
                                    }
                                },
                                Err(err) => {
                                    *success = false;
                                    *error_msg = Some(format!(
                                        "ERROR_CLASS=UnexpectedState Browser subagent hash failed: {}",
                                        err
                                    ));
                                    *history_entry = None;
                                }
                            }
                        }
                    }
                    Err(error)
                        if value
                            .get("name")
                            .and_then(serde_json::Value::as_str)
                            .is_some_and(|name| name.eq_ignore_ascii_case("browser__subagent")) =>
                    {
                        *success = false;
                        *error_msg = Some(error);
                        *history_entry = None;
                    }
                    Err(_) => {}
                }
            }
            _ => {}
        }
    }

    if matches!(
        tool,
        AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
    ) {
        let raw_entry = command_history::extract_command_history(history_entry);
        if raw_entry.is_some() {
            verification_checks.push("capability_execution_evidence=command_history".to_string());
        } else {
            verification_checks.push("capability_execution_evidence=tool_output".to_string());
        }
        if let Some(raw_entry_ref) = raw_entry.as_ref() {
            verification_checks.push(format!(
                "capability_execution_last_exit_code={}",
                raw_entry_ref.exit_code
            ));
        }

        if command_scope {
            record_success_condition(&mut agent_state.tool_execution_log, "execution_artifact");
            verification_checks.push(success_condition_key("execution_artifact"));
            let artifact_evidence = raw_entry
                .as_ref()
                .map(|entry| format!("command_exit_code={}", entry.exit_code))
                .unwrap_or_else(|| {
                    format!(
                        "command_history_missing=true;tool_output_chars={}",
                        history_entry
                            .as_ref()
                            .map(|entry| entry.chars().count())
                            .unwrap_or(0)
                    )
                });
            emit_execution_contract_receipt_event(
                service,
                session_id,
                step_index,
                resolved_intent_id,
                "execution",
                "execution_artifact",
                true,
                &artifact_evidence,
                None,
                None,
                synthesized_payload_hash.clone(),
            );
        }

        if let Some(raw_entry) = raw_entry {
            let history =
                command_history::scrub_command_history_fields(&service.scrubber, raw_entry).await;
            command_history::append_to_bounded_history(
                &mut agent_state.command_history,
                history,
                MAX_COMMAND_HISTORY,
            );
        }
    }

    if command_scope && *success && matches!(tool, AgentTool::SoftwareInstallExecutePlan { .. }) {
        verification_checks.push("capability_execution_evidence=tool_output".to_string());
        record_success_condition(&mut agent_state.tool_execution_log, "execution_artifact");
        verification_checks.push(success_condition_key("execution_artifact"));
        let artifact_evidence = format!(
            "software_install_plan_ref=redacted;tool_output_chars={}",
            history_entry
                .as_ref()
                .map(|entry| entry.chars().count())
                .unwrap_or(0)
        );
        emit_execution_contract_receipt_event(
            service,
            session_id,
            step_index,
            resolved_intent_id,
            "execution",
            "execution_artifact",
            true,
            &artifact_evidence,
            None,
            None,
            synthesized_payload_hash.clone(),
        );
        record_install_success_contract_receipts(
            service,
            agent_state,
            verification_checks,
            session_id,
            step_index,
            resolved_intent_id,
            synthesized_payload_hash.clone(),
            history_entry.as_deref(),
        );
    }

    if command_scope && *success && matches!(tool, AgentTool::AutomationCreateMonitor { .. }) {
        verification_checks.push("capability_execution_evidence=tool_output".to_string());
        record_success_condition(&mut agent_state.tool_execution_log, "execution_artifact");
        verification_checks.push(success_condition_key("execution_artifact"));
        let artifact_evidence = format!(
            "automation_monitor_install=true;tool_output_chars={}",
            history_entry
                .as_ref()
                .map(|entry| entry.chars().count())
                .unwrap_or(0)
        );
        emit_execution_contract_receipt_event(
            service,
            session_id,
            step_index,
            resolved_intent_id,
            "execution",
            "execution_artifact",
            true,
            &artifact_evidence,
            None,
            None,
            synthesized_payload_hash.clone(),
        );
    }

    let record_success_idempotence =
        should_record_success_idempotence_for_tool_result(verification_checks);
    if !record_success_idempotence {
        verification_checks
            .push("model_chat_reply_contract_rejection_not_recorded_as_success=true".to_string());
    }
    if (*success || *command_probe_completed)
        && !req_hash_hex.is_empty()
        && record_success_idempotence
    {
        agent_state.tool_execution_log.insert(
            req_hash_hex.to_string(),
            ToolCallStatus::Executed("success".into()),
        );
        if let Some(retry_hash) = retry_intent_hash {
            mark_action_fingerprint_executed_at_step(
                &mut agent_state.tool_execution_log,
                retry_hash,
                step_index,
                "success",
            );
        }
        agent_state.pending_approval = None;
        agent_state.pending_tool_jcs = None;
        agent_state.pending_request_nonce = None;
    }

    if *success {
        record_workspace_read_receipt(agent_state, tool, step_index);
        record_workspace_edit_receipt(
            service,
            agent_state,
            verification_checks,
            session_id,
            step_index,
            resolved_intent_id,
            synthesized_payload_hash.clone(),
            tool,
        );
        record_workspace_change_lifecycle_receipt(
            service,
            agent_state,
            verification_checks,
            session_id,
            step_index,
            resolved_intent_id,
            synthesized_payload_hash.clone(),
            tool,
            history_entry.as_deref(),
        );

        record_browser_success_markers(
            service,
            agent_state,
            tool,
            history_entry.as_deref(),
            *trace_visual_hash,
            verification_checks,
            session_id,
            step_index,
            resolved_intent_id,
            synthesized_payload_hash.clone(),
        );

        // Managed-session producer (real session-lifecycle): a successful
        // `browser__*` tool means the agent is driving an operator-observable
        // sandbox browser session. Record it into KV and bridge the managed-session
        // snapshot onto the daemon's event log so GET /managed-sessions projects it.
        emit_managed_browser_session(
            service,
            &mut *state,
            agent_state,
            current_tool_name.as_str(),
            action_output.as_deref(),
            error_msg.as_deref(),
            block_timestamp_ns,
        );

        if is_command_execution_provider_tool(tool) {
            if command_scope && requires_timer_notification_contract(agent_state) {
                if matches!(
                    tool,
                    AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
                ) {
                    if sys_exec_arms_timer_delay_backend(tool) {
                        record_success_condition(
                            &mut agent_state.tool_execution_log,
                            TIMER_SLEEP_BACKEND_SUCCESS_CONDITION,
                        );
                        verification_checks
                            .push(success_condition_key(TIMER_SLEEP_BACKEND_SUCCESS_CONDITION));
                        let delay_seconds =
                            sys_exec_timer_delay_seconds(tool).map(|value| value.to_string());
                        emit_execution_contract_receipt_event_with_observation(
                            service,
                            session_id,
                            step_index,
                            resolved_intent_id,
                            "execution",
                            TIMER_SLEEP_BACKEND_SUCCESS_CONDITION,
                            true,
                            "timer_sleep_backend=armed",
                            Some("tool_payload"),
                            delay_seconds.as_deref(),
                            Some("seconds"),
                            None,
                            None,
                            synthesized_payload_hash.clone(),
                        );
                        if let Some(delay_seconds) = delay_seconds.as_deref() {
                            emit_execution_contract_receipt_event_with_observation(
                                service,
                                session_id,
                                step_index,
                                resolved_intent_id,
                                "execution",
                                "timer_delay_seconds",
                                true,
                                "timer_delay_seconds_observed=true",
                                Some("tool_payload"),
                                Some(delay_seconds),
                                Some("seconds"),
                                None,
                                None,
                                synthesized_payload_hash.clone(),
                            );
                        }
                    }
                    if let Some(command_preview) = sys_exec_command_preview(tool) {
                        if command_arms_deferred_notification_path(&command_preview) {
                            record_success_condition(
                                &mut agent_state.tool_execution_log,
                                TIMER_NOTIFICATION_PATH_SUCCESS_CONDITION,
                            );
                            verification_checks.push(success_condition_key(
                                TIMER_NOTIFICATION_PATH_SUCCESS_CONDITION,
                            ));
                            emit_execution_contract_receipt_event_with_observation(
                                service,
                                session_id,
                                step_index,
                                resolved_intent_id,
                                "execution",
                                TIMER_NOTIFICATION_PATH_SUCCESS_CONDITION,
                                true,
                                "timer_notification_path_armed=true",
                                Some("tool_payload"),
                                Some("deferred_notification"),
                                Some("strategy"),
                                None,
                                None,
                                synthesized_payload_hash.clone(),
                            );
                            record_execution_evidence(
                                &mut agent_state.tool_execution_log,
                                "notification_strategy",
                            );
                            verification_checks
                                .push(execution_evidence_key("notification_strategy"));
                            emit_execution_contract_receipt_event_with_observation(
                                service,
                                session_id,
                                step_index,
                                resolved_intent_id,
                                "execution",
                                "notification_strategy",
                                true,
                                "notification_strategy=deferred",
                                Some("tool_payload"),
                                Some("deferred"),
                                Some("strategy"),
                                None,
                                None,
                                synthesized_payload_hash.clone(),
                            );
                            verification_checks
                                .push("timer_notification_path_armed=true".to_string());
                        }
                    }
                }
            }
            if command_scope {
                record_execution_evidence(&mut agent_state.tool_execution_log, "execution");
                verification_checks.push(execution_evidence_key("execution"));
                emit_execution_contract_receipt_event(
                    service,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    "execution",
                    "execution",
                    true,
                    "execution_invocation_completed=true",
                    None,
                    None,
                    synthesized_payload_hash.clone(),
                );
            }
            verification_checks.push("capability_execution_phase=verification".to_string());
            if command_scope {
                record_verification_evidence(
                    &mut agent_state.tool_execution_log,
                    verification_checks,
                    tool,
                    if matches!(
                        tool,
                        AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
                    ) {
                        agent_state.command_history.back()
                    } else {
                        None
                    },
                );
                let verification_commit = execution_evidence_value(
                    &agent_state.tool_execution_log,
                    VERIFICATION_COMMIT_EVIDENCE,
                )
                .map(str::to_string);
                emit_execution_contract_receipt_event(
                    service,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    "verification",
                    "verification",
                    true,
                    "verification_receipt_recorded=true",
                    verification_commit.clone(),
                    None,
                    synthesized_payload_hash.clone(),
                );
                emit_execution_contract_receipt_event(
                    service,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    "verification",
                    VERIFICATION_COMMIT_EVIDENCE,
                    verification_commit
                        .as_deref()
                        .map(|value| value.starts_with("sha256:"))
                        .unwrap_or(false),
                    verification_commit
                        .as_deref()
                        .unwrap_or("verification_commit=missing"),
                    verification_commit.clone(),
                    None,
                    synthesized_payload_hash.clone(),
                );
            }
        }
        if !command_scope {
            if let Err(error) = record_non_command_success_receipts(
                service,
                agent_state,
                rules,
                current_tool_name,
                tool_args,
                history_entry.as_deref(),
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                verification_checks,
            )
            .await
            {
                *success = false;
                *error_msg = Some(error.clone());
                *history_entry = Some(error.clone());
                *action_output = Some(error);
                return Ok(());
            }
        }
        if let Some(entry) = history_entry.clone() {
            let snapshot_pending_context = if current_tool_name == "browser__inspect" {
                service
                    .hydrate_session_history(session_id)
                    .ok()
                    .map(|history| {
                        build_browser_snapshot_pending_state_context_with_history(&entry, &history)
                    })
                    .filter(|context| !context.trim().is_empty())
            } else {
                None
            };
            let compact_entry = compact_tool_history_entry_for_chat(current_tool_name, &entry);
            if !compact_entry.trim().is_empty() {
                let content = tool_history_message_content(current_tool_name, &compact_entry);
                let tool_msg = ioi_types::app::agentic::ChatMessage {
                    role: "tool".to_string(),
                    content,
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64,
                    trace_hash: None,
                };
                let _ = service
                    .append_chat_to_scs(session_id, &tool_msg, block_height)
                    .await?;
            }
            if let Some(pending_context) = snapshot_pending_context {
                let sys_msg = ioi_types::app::agentic::ChatMessage {
                    role: "system".to_string(),
                    content: pending_context,
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64,
                    trace_hash: None,
                };
                let _ = service
                    .append_chat_to_scs(session_id, &sys_msg, block_height)
                    .await?;
            }
        }
    }

    apply_tool_outcome_and_followups(ToolOutcomeContext {
        service,
        state,
        agent_state,
        rules,
        tool,
        tool_args,
        session_id,
        block_height,
        block_timestamp_ns,
        step_index,
        resolved_intent_id,
        synthesized_payload_hash,
        command_scope,
        success,
        error_msg,
        history_entry,
        action_output,
        is_lifecycle_action,
        current_tool_name,
        terminal_chat_reply_output,
        verification_checks,
        command_probe_completed,
    })
    .await?;

    Ok(())
}

fn should_record_success_idempotence_for_tool_result(verification_checks: &[String]) -> bool {
    !verification_checks
        .iter()
        .any(|check| check == "terminal_chat_reply_deferred_for_active_web_pipeline=true")
}

#[cfg(test)]
#[path = "success_path/tests.rs"]
mod tests;
