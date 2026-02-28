use super::events::{
    emit_completion_gate_status_event, emit_completion_gate_violation_events,
    emit_execution_contract_receipt_event,
};
use super::system_fail::handle_system_fail_outcome;
use super::web_followup::apply_web_research_followups;
use super::*;

pub(super) struct ToolOutcomeContext<'a, 's> {
    pub service: &'a DesktopAgentService,
    pub _state: &'s mut dyn StateAccess,
    pub agent_state: &'a mut AgentState,
    pub tool: &'a AgentTool,
    pub tool_args: &'a serde_json::Value,
    pub session_id: [u8; 32],
    pub block_timestamp_ns: u64,
    pub step_index: u32,
    pub resolved_intent_id: &'a str,
    pub synthesized_payload_hash: Option<String>,
    pub command_scope: bool,
    pub success: &'a mut bool,
    pub error_msg: &'a mut Option<String>,
    pub history_entry: &'a mut Option<String>,
    pub action_output: &'a mut Option<String>,
    pub is_lifecycle_action: &'a mut bool,
    pub current_tool_name: &'a mut String,
    pub terminal_chat_reply_output: &'a mut Option<String>,
    pub verification_checks: &'a mut Vec<String>,
    pub command_probe_completed: &'a mut bool,
}

pub(super) async fn apply_tool_outcome_and_followups(
    ctx: ToolOutcomeContext<'_, '_>,
) -> Result<(), TransactionError> {
    let ToolOutcomeContext {
        service,
        _state: _,
        agent_state,
        tool,
        tool_args,
        session_id,
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
    } = ctx;

    match tool {
        AgentTool::AgentComplete { result } => {
            let missing_contract_markers = missing_execution_contract_markers(agent_state);
            if !missing_contract_markers.is_empty() {
                let missing = missing_contract_markers.join(",");
                let contract_error = execution_contract_violation_error(&missing);
                *success = false;
                *error_msg = Some(contract_error.clone());
                *history_entry = Some(contract_error.clone());
                *action_output = Some(contract_error);
                agent_state.status = AgentStatus::Running;
                verification_checks.push("execution_contract_gate_blocked=true".to_string());
                verification_checks.push(format!("execution_contract_missing_keys={}", missing));
                emit_completion_gate_violation_events(
                    service,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    &missing,
                );
            } else {
                let completed_result =
                    if is_system_clock_read_intent(agent_state.resolved_intent.as_ref()) {
                        summarize_system_clock_or_plain_output(result)
                            .unwrap_or_else(|| result.clone())
                    } else {
                        result.clone()
                    };
                let completed_result = enrich_command_scope_summary(&completed_result, agent_state);
                agent_state.status = AgentStatus::Completed(Some(completed_result.clone()));
                *is_lifecycle_action = true;
                *action_output = Some(completed_result.clone());
                if !completed_result.trim().is_empty() {
                    *terminal_chat_reply_output = Some(completed_result.clone());
                    verification_checks.push("terminal_chat_reply_ready=true".to_string());
                }
                evaluate_and_crystallize(service, agent_state, session_id, &completed_result).await;
                emit_completion_gate_status_event(
                    service,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    true,
                    "agent_complete_contract_gate_passed",
                );
            }
        }
        AgentTool::SysChangeDir { .. } => {
            if *success {
                if let Some(new_cwd) = history_entry.as_ref() {
                    agent_state.working_directory = new_cwd.clone();
                }
            }
        }
        AgentTool::ChatReply { message } => {
            let missing_contract_markers = missing_execution_contract_markers(agent_state);
            if !missing_contract_markers.is_empty() {
                let missing = missing_contract_markers.join(",");
                let contract_error = execution_contract_violation_error(&missing);
                *success = false;
                *error_msg = Some(contract_error.clone());
                *history_entry = Some(contract_error.clone());
                *action_output = Some(contract_error);
                agent_state.status = AgentStatus::Running;
                verification_checks.push("execution_contract_gate_blocked=true".to_string());
                verification_checks.push(format!("execution_contract_missing_keys={}", missing));
                emit_completion_gate_violation_events(
                    service,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    &missing,
                );
            } else {
                let message = enrich_command_scope_summary(message, agent_state);
                agent_state.status = AgentStatus::Completed(Some(message.clone()));
                *is_lifecycle_action = true;
                *action_output = Some(message.clone());
                *terminal_chat_reply_output = Some(message.clone());
                evaluate_and_crystallize(service, agent_state, session_id, &message).await;
                emit_completion_gate_status_event(
                    service,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    true,
                    "chat_reply_contract_gate_passed",
                );
            }
        }
        AgentTool::OsLaunchApp { app_name } => {
            if *success
                && should_auto_complete_open_app_goal(
                    &agent_state.goal,
                    app_name,
                    agent_state
                        .target
                        .as_ref()
                        .and_then(|target| target.app_hint.as_deref()),
                )
            {
                let summary = format!("Opened {}.", app_name);
                agent_state.status = AgentStatus::Completed(Some(summary.clone()));
                *is_lifecycle_action = true;
                *action_output = Some(summary.clone());
                *terminal_chat_reply_output = Some(summary);
                verification_checks.push("terminal_chat_reply_ready=true".to_string());
                agent_state.execution_queue.clear();
                agent_state.pending_search_completion = None;
                log::info!(
                    "Auto-completed app-launch session {} after successful os__launch_app.",
                    hex::encode(&session_id[..4])
                );
            }
        }
        AgentTool::SysInstallPackage { package, .. } => {
            if *success && command_scope {
                let summary = history_entry
                    .as_deref()
                    .map(str::trim)
                    .filter(|entry| !entry.is_empty())
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("Installed package '{}'.", package));
                let summary = enrich_command_scope_summary(&summary, agent_state);
                let missing_contract_markers = missing_execution_contract_markers(agent_state);
                if missing_contract_markers.is_empty() {
                    *error_msg = None;
                    agent_state.status = AgentStatus::Completed(Some(summary.clone()));
                    *is_lifecycle_action = true;
                    *action_output = Some(summary.clone());
                    *terminal_chat_reply_output = None;
                    verification_checks.push("install_dependency_terminalized=true".to_string());
                    agent_state.execution_queue.clear();
                    agent_state.pending_search_completion = None;
                    emit_completion_gate_status_event(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        true,
                        "install_dependency_completion_gate_passed",
                    );
                } else {
                    let missing = missing_contract_markers.join(",");
                    let contract_error = execution_contract_violation_error(&missing);
                    *success = false;
                    *error_msg = Some(contract_error.clone());
                    *history_entry = Some(contract_error.clone());
                    *action_output = Some(contract_error);
                    agent_state.status = AgentStatus::Running;
                    verification_checks.push("execution_contract_gate_blocked=true".to_string());
                    verification_checks
                        .push(format!("execution_contract_missing_keys={}", missing));
                    emit_completion_gate_violation_events(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        &missing,
                    );
                }
            }
        }
        AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. } => {
            if is_command_probe_intent(agent_state.resolved_intent.as_ref()) {
                if let Some(raw) = history_entry.as_deref() {
                    if let Some(summary) = summarize_command_probe_output(tool, raw) {
                        // Probe markers are deterministic completion signals even
                        // when the underlying command exits non-zero.
                        *command_probe_completed = true;
                        *success = true;
                        *error_msg = None;
                        agent_state.status = AgentStatus::Completed(Some(summary.clone()));
                        *is_lifecycle_action = true;
                        *action_output = Some(summary);
                        agent_state.execution_queue.clear();
                        agent_state.pending_search_completion = None;
                    }
                }
            } else if is_system_clock_read_intent(agent_state.resolved_intent.as_ref()) {
                if let Some(summary) = history_entry
                    .as_deref()
                    .and_then(summarize_system_clock_or_plain_output)
                {
                    let summary = enrich_command_scope_summary(&summary, agent_state);
                    mark_execution_postcondition(
                        &mut agent_state.tool_execution_log,
                        CLOCK_TIMESTAMP_POSTCONDITION,
                    );
                    verification_checks.push(postcondition_marker(CLOCK_TIMESTAMP_POSTCONDITION));
                    emit_execution_contract_receipt_event(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "verification",
                        CLOCK_TIMESTAMP_POSTCONDITION,
                        true,
                        "clock_timestamp_observed=true",
                        None,
                        None,
                        synthesized_payload_hash.clone(),
                    );
                    *success = true;
                    *error_msg = None;
                    agent_state.status = AgentStatus::Completed(Some(summary.clone()));
                    *is_lifecycle_action = true;
                    *action_output = Some(summary.clone());
                    *terminal_chat_reply_output = Some(summary);
                    agent_state.execution_queue.clear();
                    agent_state.pending_search_completion = None;
                } else {
                    let missing = postcondition_marker(CLOCK_TIMESTAMP_POSTCONDITION);
                    let contract_error = execution_contract_violation_error(&missing);
                    *success = false;
                    *error_msg = Some(contract_error.clone());
                    *history_entry = Some(contract_error.clone());
                    *action_output = Some(contract_error);
                    agent_state.status = AgentStatus::Running;
                    verification_checks.push("execution_contract_gate_blocked=true".to_string());
                    verification_checks
                        .push(format!("execution_contract_missing_keys={}", missing));
                    emit_execution_contract_receipt_event(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "verification",
                        CLOCK_TIMESTAMP_POSTCONDITION,
                        false,
                        "clock_timestamp_observed=false",
                        None,
                        None,
                        synthesized_payload_hash.clone(),
                    );
                }
            } else if command_scope {
                if let Some(summary) =
                    duplicate_command_completion_summary(tool, agent_state.command_history.back())
                {
                    let missing_contract_markers = missing_execution_contract_markers(agent_state);
                    if missing_contract_markers.is_empty() {
                        *success = true;
                        *error_msg = None;
                        agent_state.status = AgentStatus::Completed(Some(summary.clone()));
                        *is_lifecycle_action = true;
                        *action_output = Some(summary.clone());
                        *terminal_chat_reply_output = Some(summary);
                        agent_state.execution_queue.clear();
                        agent_state.pending_search_completion = None;
                        verification_checks.push("timer_schedule_terminalized=true".to_string());
                        verification_checks.push("terminal_chat_reply_ready=true".to_string());
                        emit_completion_gate_status_event(
                            service,
                            session_id,
                            step_index,
                            resolved_intent_id,
                            true,
                            "command_scope_completion_gate_passed",
                        );
                    } else {
                        let missing = missing_contract_markers.join(",");
                        let contract_error = execution_contract_violation_error(&missing);
                        *success = false;
                        *error_msg = Some(contract_error.clone());
                        *history_entry = Some(contract_error.clone());
                        *action_output = Some(contract_error);
                        verification_checks
                            .push("execution_contract_gate_blocked=true".to_string());
                        verification_checks
                            .push(format!("execution_contract_missing_keys={}", missing));
                        emit_completion_gate_violation_events(
                            service,
                            session_id,
                            step_index,
                            resolved_intent_id,
                            &missing,
                        );
                    }
                }
            }
        }
        AgentTool::MemorySearch { query } => {
            let mut promoted_memory_search = false;
            if *success && should_use_web_research_path(agent_state) {
                if let Some(raw) = history_entry.as_deref() {
                    if let Some(bundle) = parse_web_evidence_bundle(raw) {
                        if bundle.tool == "web__search" {
                            promoted_memory_search = true;
                            *current_tool_name = "web__search".to_string();
                            verification_checks
                                .push("memory_search_promoted_to_web_search=true".to_string());
                            apply_pre_read_bundle(
                                service,
                                agent_state,
                                session_id,
                                step_index,
                                &bundle,
                                query,
                                verification_checks,
                                history_entry,
                                action_output,
                                terminal_chat_reply_output,
                                is_lifecycle_action,
                            )
                            .await?;
                        }
                    }
                }
            }

            if !promoted_memory_search
                && *success
                && should_use_web_research_path(agent_state)
                && agent_state.pending_search_completion.is_none()
                && history_entry
                    .as_deref()
                    .map(is_empty_memory_search_output)
                    .unwrap_or(true)
            {
                let bootstrap_query = if query.trim().is_empty() {
                    agent_state.goal.clone()
                } else {
                    query.clone()
                };
                let queued = queue_web_search_bootstrap(agent_state, session_id, &bootstrap_query)?;
                verification_checks.push("web_search_bootstrap_from_memory=true".to_string());
                let note = if queued {
                    "No memory hits for this news query; queued deterministic web__search."
                        .to_string()
                } else {
                    "No memory hits for this news query; deterministic web__search was already queued."
                        .to_string()
                };
                *history_entry = Some(note.clone());
                *action_output = Some(note);
                agent_state.status = AgentStatus::Running;
            }
        }
        AgentTool::WebSearch { query, .. } => {
            if *success && should_use_web_research_path(agent_state) {
                if let Some(raw) = history_entry.as_deref() {
                    if let Some(bundle) = parse_web_evidence_bundle(raw) {
                        apply_pre_read_bundle(
                            service,
                            agent_state,
                            session_id,
                            step_index,
                            &bundle,
                            query,
                            verification_checks,
                            history_entry,
                            action_output,
                            terminal_chat_reply_output,
                            is_lifecycle_action,
                        )
                        .await?;
                    }
                }
            }
        }
        AgentTool::SystemFail { reason, .. } => {
            handle_system_fail_outcome(
                agent_state,
                reason,
                block_timestamp_ns,
                success,
                error_msg,
                history_entry,
                action_output,
                terminal_chat_reply_output,
                current_tool_name,
                is_lifecycle_action,
                verification_checks,
            );
        }
        _ => {}
    }

    apply_web_research_followups(
        agent_state,
        *success,
        current_tool_name.as_str(),
        session_id,
        step_index,
        tool_args,
        history_entry,
        action_output,
        verification_checks,
    )?;
    Ok(())
}
