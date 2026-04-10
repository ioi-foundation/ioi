use super::super::*;
use crate::agentic::runtime::service::step::action::verified_command_probe_completion_summary;
use crate::agentic::runtime::utils::persist_agent_state;

pub(crate) struct LifecycleStatusPhaseContext<'a, 's> {
    pub service: &'a RuntimeAgentService,
    pub state: &'s mut dyn StateAccess,
    pub agent_state: &'a mut AgentState,
    pub session_id: [u8; 32],
    pub block_height: u64,
    pub pre_state_summary: ioi_types::app::RoutingStateSummary,
    pub routing_decision: TierRoutingDecision,
    pub policy_decision: String,
    pub verification_checks: &'a mut Vec<String>,
    pub tool: AgentTool,
    pub tool_name: String,
    pub tool_jcs: Vec<u8>,
    pub tool_hash: [u8; 32],
    pub pending_vhash: [u8; 32],
    pub action_json: String,
    pub intent_hash: String,
    pub retry_intent_hash: String,
    pub rules: ActionRules,
    pub command_scope: bool,
    pub success: bool,
    pub out: Option<String>,
    pub err: Option<String>,
    pub log_visual_hash: [u8; 32],
}

fn normalize_resumed_output_only_success(
    tool_name: &str,
    success: &mut bool,
    out: &Option<String>,
    err: &Option<String>,
    verification_checks: &mut Vec<String>,
) {
    if *success || err.is_some() {
        return;
    }
    let has_output = out
        .as_deref()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    if !has_output {
        return;
    }
    *success = true;
    verification_checks.push("resume_output_only_success_normalized=true".to_string());
    verification_checks.push(format!("resume_output_only_success_tool={}", tool_name));
}

fn remaining_queue_is_only_mail_reply_provider_fallbacks(agent_state: &AgentState) -> bool {
    let mut saw_mail_reply_fallback = false;
    for request in &agent_state.execution_queue {
        let target = request.target.canonical_label();
        if crate::agentic::runtime::service::step::intent_resolver::tool_has_capability(
            &target,
            "mail.reply",
        ) || crate::agentic::runtime::service::step::intent_resolver::tool_has_capability(
            &target,
            "mail.send",
        ) {
            saw_mail_reply_fallback = true;
            continue;
        }
        return false;
    }
    saw_mail_reply_fallback
}

fn should_terminalize_mail_reply_intent(agent_state: &AgentState, tool_name: &str) -> bool {
    let resolved_mail_reply_intent = agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| {
            resolved.intent_id == "mail.reply"
                || resolved
                    .required_capabilities
                    .iter()
                    .any(|capability| capability.as_str() == "mail.reply")
        })
        .unwrap_or(false);
    let fallback_only_queue = remaining_queue_is_only_mail_reply_provider_fallbacks(agent_state);
    crate::agentic::runtime::service::step::intent_resolver::tool_has_capability(
        tool_name,
        "mail.reply",
    ) && (resolved_mail_reply_intent || fallback_only_queue)
}

fn mail_reply_completion_summary(out: Option<&str>) -> String {
    out.and_then(|value| {
        value
            .split("\n\n")
            .next()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
    .unwrap_or_else(|| "Email request completed.".to_string())
}

async fn crystallize_successful_session(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    agent_state: &AgentState,
    session_id: [u8; 32],
    block_height: u64,
) {
    evaluate_and_crystallize(service, state, agent_state, session_id).await;
    let _ = service
        .update_skill_reputation(state, session_id, true, block_height)
        .await;
}

pub(crate) async fn run_lifecycle_status_phase(
    ctx: LifecycleStatusPhaseContext<'_, '_>,
) -> Result<(), TransactionError> {
    let LifecycleStatusPhaseContext {
        service,
        state,
        agent_state,
        session_id,
        block_height,
        pre_state_summary,
        routing_decision,
        policy_decision,
        verification_checks,
        tool,
        tool_name,
        tool_jcs,
        tool_hash,
        pending_vhash,
        action_json,
        intent_hash,
        retry_intent_hash,
        rules,
        command_scope,
        success,
        out,
        err,
        log_visual_hash,
    } = ctx;

    let mut success = success;
    let mut out = out;
    let mut err = err;
    let mut failure_class: Option<FailureClass> = None;
    let mut stop_condition_hit = false;
    let mut escalation_path: Option<String> = None;
    let mut remediation_queued = false;
    let mut awaiting_sudo_password = false;
    let mut awaiting_clarification = false;
    let mut terminal_response_emitted = false;
    let prior_consecutive_failures = agent_state.consecutive_failures;

    normalize_resumed_output_only_success(
        &tool_name,
        &mut success,
        &out,
        &err,
        verification_checks,
    );

    let is_install_package_tool = matches!(tool, AgentTool::SysInstallPackage { .. });
    let clarification_required = !success
        && err
            .as_deref()
            .map(|msg| requires_wait_for_clarification(&tool_name, msg))
            .unwrap_or(false);

    if !success
        && is_install_package_tool
        && err
            .as_deref()
            .map(is_sudo_password_required_install_error)
            .unwrap_or(false)
    {
        awaiting_sudo_password = true;
        failure_class = Some(FailureClass::PermissionOrApprovalRequired);
        stop_condition_hit = true;
        escalation_path = Some("wait_for_sudo_password".to_string());
        agent_state.status = AgentStatus::Paused("Waiting for sudo password".to_string());
        mark_incident_wait_for_user(
            state,
            session_id,
            "wait_for_sudo_password",
            FailureClass::PermissionOrApprovalRequired,
            err.as_deref(),
        )?;
        agent_state.execution_queue.clear();
    }

    if clarification_required {
        awaiting_clarification = true;
        failure_class = Some(FailureClass::UserInterventionNeeded);
        stop_condition_hit = true;
        escalation_path = Some("wait_for_clarification".to_string());
        mark_incident_wait_for_user(
            state,
            session_id,
            "wait_for_clarification",
            FailureClass::UserInterventionNeeded,
            err.as_deref(),
        )?;
        agent_state.status =
            AgentStatus::Paused("Waiting for clarification on target identity.".to_string());
    }

    let output_str = out
        .clone()
        .unwrap_or_else(|| err.clone().unwrap_or_default());
    let key = get_state_key(&session_id);

    goto_trace_log(
        agent_state,
        state,
        &key,
        session_id,
        log_visual_hash,
        "[Resumed Action]".to_string(),
        output_str.clone(),
        success,
        err.clone(),
        "resumed_action".to_string(),
        service.event_sender.clone(),
        agent_state.active_skill_hash,
        service.memory_runtime.as_ref(),
    )?;

    let content = if success {
        out.as_deref()
            .unwrap_or("Action executed successfully.")
            .to_string()
    } else {
        format!(
            "Action Failed: {}",
            err.as_deref().unwrap_or("Unknown error")
        )
    };

    let msg = ioi_types::app::agentic::ChatMessage {
        role: "tool".to_string(),
        content: content.clone(),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        trace_hash: None,
    };
    service
        .append_chat_to_scs(session_id, &msg, block_height)
        .await?;

    if success {
        mark_action_fingerprint_executed_at_step(
            &mut agent_state.tool_execution_log,
            &retry_intent_hash,
            pre_state_summary.step_index,
            "success",
        );
    }

    if awaiting_sudo_password {
        restore_pending_resume_state(
            agent_state,
            tool_jcs.clone(),
            tool_hash,
            pending_vhash,
            action_json.clone(),
        );
        agent_state.execution_queue.clear();
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
        service
            .append_chat_to_scs(session_id, &sys_msg, block_height)
            .await?;
        if let Some(tx) = &service.event_sender {
            let _ = tx.send(KernelEvent::AgentActionResult {
                session_id,
                step_index: agent_state.step_count,
                tool_name: "sys__install_package".to_string(),
                output: err.clone().unwrap_or_default(),
                error_class: extract_error_class_token(err.as_deref()).map(str::to_string),
                agent_status: "Paused".to_string(),
            });
        }
        verification_checks.push("awaiting_sudo_password=true".to_string());
    } else if awaiting_clarification {
        clear_pending_resume_state(agent_state);
        agent_state.execution_queue.clear();
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
        service
            .append_chat_to_scs(session_id, &sys_msg, block_height)
            .await?;
        verification_checks.push("awaiting_clarification=true".to_string());
    } else {
        clear_pending_resume_state(agent_state);
    }

    let mut reflexive_completion = false;
    if success && (content.contains("agent_complete") || content.contains("agent__complete")) {
        if let Some(json_start) = content.find('{') {
            if let Some(json_end) = content.rfind('}') {
                if json_end > json_start {
                    let potential_json = &content[json_start..=json_end];
                    if let Ok(detected_tool) = middleware::normalize_tool_call(potential_json) {
                        if let AgentTool::AgentComplete { result } = detected_tool {
                            log::info!(
                                "Reflexive Agent (Resume): Detected completion signal in tool output."
                            );
                            let missing_contract_markers =
                                missing_execution_contract_markers_with_rules(agent_state, &rules);
                            if !missing_contract_markers.is_empty() {
                                let missing = missing_contract_markers.join(",");
                                let contract_error = execution_contract_violation_error(&missing);
                                success = false;
                                err = Some(contract_error.clone());
                                out = Some(contract_error);
                                verification_checks
                                    .push("execution_contract_gate_blocked=true".to_string());
                                verification_checks
                                    .push(format!("execution_contract_missing_keys={}", missing));
                                agent_state.status = AgentStatus::Running;
                            } else {
                                let completed_result = if is_system_clock_read_intent(
                                    agent_state.resolved_intent.as_ref(),
                                ) {
                                    summarize_system_clock_output(&result)
                                        .unwrap_or_else(|| result.clone())
                                } else {
                                    result.clone()
                                };
                                let completed_result =
                                    enrich_command_scope_summary(&completed_result, agent_state);
                                let composed = compose_terminal_chat_reply(&completed_result);
                                let completed_result = composed.output;
                                agent_state.status =
                                    AgentStatus::Completed(Some(completed_result.clone()));
                                reflexive_completion = true;

                                if let Some(tx) = &service.event_sender {
                                    emit_terminal_completion_events(
                                        tx,
                                        session_id,
                                        agent_state.step_count,
                                        &completed_result,
                                        status::status_str(&agent_state.status),
                                    );
                                    terminal_response_emitted = true;
                                }

                                crystallize_successful_session(
                                    service,
                                    state,
                                    agent_state,
                                    session_id,
                                    block_height,
                                )
                                .await;
                            }
                        }
                    }
                }
            }
        }
    }

    if !reflexive_completion && !awaiting_sudo_password && !awaiting_clarification {
        if success && should_terminalize_mail_reply_intent(agent_state, &tool_name) {
            let (_, tool_args) = canonical_tool_identity(&tool);
            let intent_id = resolved_intent_id(agent_state);
            match record_non_command_success_receipts(
                service,
                agent_state,
                &rules,
                &tool_name,
                &tool_args,
                out.as_deref(),
                session_id,
                pre_state_summary.step_index,
                &intent_id,
                None,
                verification_checks,
            )
            .await
            {
                Ok(()) => {
                    let missing_contract_markers =
                        missing_execution_contract_markers_with_rules(agent_state, &rules);
                    if !missing_contract_markers.is_empty() {
                        let missing = missing_contract_markers.join(",");
                        let contract_error = execution_contract_violation_error(&missing);
                        success = false;
                        err = Some(contract_error.clone());
                        out = Some(contract_error);
                        verification_checks
                            .push("execution_contract_gate_blocked=true".to_string());
                        verification_checks
                            .push(format!("execution_contract_missing_keys={}", missing));
                        agent_state.status = AgentStatus::Running;
                    } else {
                        let summary = mail_reply_completion_summary(out.as_deref());
                        agent_state.status = AgentStatus::Completed(Some(summary.clone()));
                        agent_state.execution_queue.clear();
                        emit_completion_gate_status_event(
                            service,
                            session_id,
                            pre_state_summary.step_index,
                            &intent_id,
                            true,
                            "mail_reply_resume_completion_gate_passed",
                        );
                        verification_checks.push("cec_completion_gate_emitted=true".to_string());
                        verification_checks.push("mail_reply_terminalized=true".to_string());
                        verification_checks.push("terminal_chat_reply_ready=true".to_string());
                        crystallize_successful_session(
                            service,
                            state,
                            agent_state,
                            session_id,
                            block_height,
                        )
                        .await;
                        if let Some(tx) = &service.event_sender {
                            emit_terminal_completion_events(
                                tx,
                                session_id,
                                agent_state.step_count,
                                &summary,
                                status::status_str(&agent_state.status),
                            );
                            terminal_response_emitted = true;
                        }
                    }
                }
                Err(error) => {
                    success = false;
                    err = Some(error.clone());
                    out = Some(error);
                    agent_state.status = AgentStatus::Running;
                }
            }
        } else {
            match &tool {
                AgentTool::AgentComplete { result } => {
                    let missing_contract_markers =
                        missing_execution_contract_markers_with_rules(agent_state, &rules);
                    if !missing_contract_markers.is_empty() {
                        let missing = missing_contract_markers.join(",");
                        let contract_error = execution_contract_violation_error(&missing);
                        success = false;
                        err = Some(contract_error.clone());
                        out = Some(contract_error);
                        verification_checks
                            .push("execution_contract_gate_blocked=true".to_string());
                        verification_checks
                            .push(format!("execution_contract_missing_keys={}", missing));
                        agent_state.status = AgentStatus::Running;
                    } else {
                        let completed_result =
                            if is_system_clock_read_intent(agent_state.resolved_intent.as_ref()) {
                                summarize_system_clock_output(result)
                                    .unwrap_or_else(|| result.clone())
                            } else {
                                result.clone()
                            };
                        let completed_result =
                            enrich_command_scope_summary(&completed_result, agent_state);
                        let composed = compose_terminal_chat_reply(&completed_result);
                        let completed_result = composed.output;
                        agent_state.status = AgentStatus::Completed(Some(completed_result.clone()));
                        crystallize_successful_session(
                            service,
                            state,
                            agent_state,
                            session_id,
                            block_height,
                        )
                        .await;

                        if let Some(tx) = &service.event_sender {
                            emit_terminal_completion_events(
                                tx,
                                session_id,
                                agent_state.step_count,
                                &completed_result,
                                status::status_str(&agent_state.status),
                            );
                            terminal_response_emitted = true;
                        }
                    }
                }
                AgentTool::ChatReply { message } => {
                    let missing_contract_markers =
                        missing_execution_contract_markers_with_rules(agent_state, &rules);
                    if !missing_contract_markers.is_empty() {
                        let missing = missing_contract_markers.join(",");
                        let contract_error = execution_contract_violation_error(&missing);
                        success = false;
                        err = Some(contract_error.clone());
                        out = Some(contract_error);
                        verification_checks
                            .push("execution_contract_gate_blocked=true".to_string());
                        verification_checks
                            .push(format!("execution_contract_missing_keys={}", missing));
                        agent_state.status = AgentStatus::Running;
                    } else {
                        let message = enrich_command_scope_summary(message, agent_state);
                        let composed = compose_terminal_chat_reply(&message);
                        let message = composed.output;
                        agent_state.status = AgentStatus::Completed(Some(message.clone()));
                        crystallize_successful_session(
                            service,
                            state,
                            agent_state,
                            session_id,
                            block_height,
                        )
                        .await;

                        if let Some(tx) = &service.event_sender {
                            let _ = tx.send(KernelEvent::AgentActionResult {
                                session_id,
                                step_index: agent_state.step_count,
                                tool_name: "chat__reply".to_string(),
                                output: message.clone(),
                                error_class: None,
                                agent_status: status::status_str(&agent_state.status),
                            });
                            terminal_response_emitted = true;
                        }
                    }
                }
                AgentTool::SysChangeDir { .. } => {
                    if success {
                        agent_state.working_directory = content.clone();
                    }
                    agent_state.status = AgentStatus::Running;
                }
                AgentTool::Computer(ComputerAction::Screenshot) => {
                    if success
                        && is_ui_capture_screenshot_intent(agent_state.resolved_intent.as_ref())
                    {
                        let summary = "Screenshot captured.".to_string();
                        agent_state.status = AgentStatus::Completed(Some(summary.clone()));
                        agent_state.execution_queue.clear();
                        verification_checks
                            .push("screenshot_capture_terminalized=true".to_string());
                        crystallize_successful_session(
                            service,
                            state,
                            agent_state,
                            session_id,
                            block_height,
                        )
                        .await;
                        if let Some(tx) = &service.event_sender {
                            emit_terminal_completion_events(
                                tx,
                                session_id,
                                agent_state.step_count,
                                &summary,
                                status::status_str(&agent_state.status),
                            );
                            terminal_response_emitted = true;
                        }
                    } else {
                        agent_state.status = AgentStatus::Running;
                    }
                }
                AgentTool::OsLaunchApp { app_name } => {
                    if success
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
                        crystallize_successful_session(
                            service,
                            state,
                            agent_state,
                            session_id,
                            block_height,
                        )
                        .await;
                        if let Some(tx) = &service.event_sender {
                            emit_terminal_completion_events(
                                tx,
                                session_id,
                                agent_state.step_count,
                                &summary,
                                status::status_str(&agent_state.status),
                            );
                            terminal_response_emitted = true;
                        }
                    } else {
                        agent_state.status = AgentStatus::Running;
                    }
                }
                AgentTool::AutomationCreateMonitor { title, .. } => {
                    if success && command_scope {
                        let summary = out
                            .as_deref()
                            .map(str::trim)
                            .filter(|entry| !entry.is_empty())
                            .map(str::to_string)
                            .unwrap_or_else(|| {
                                format!(
                                    "Installed automation monitor '{}'.",
                                    title.as_deref().unwrap_or("workflow")
                                )
                            });
                        let summary = enrich_command_scope_summary(&summary, agent_state);
                        let missing_contract_markers =
                            missing_execution_contract_markers_with_rules(agent_state, &rules);
                        if !missing_contract_markers.is_empty() {
                            let missing = missing_contract_markers.join(",");
                            let contract_error = execution_contract_violation_error(&missing);
                            success = false;
                            err = Some(contract_error.clone());
                            out = Some(contract_error);
                            verification_checks
                                .push("execution_contract_gate_blocked=true".to_string());
                            verification_checks
                                .push(format!("execution_contract_missing_keys={}", missing));
                            agent_state.status = AgentStatus::Running;
                        } else {
                            agent_state.status = AgentStatus::Completed(Some(summary.clone()));
                            agent_state.execution_queue.clear();
                            verification_checks
                                .push("automation_monitor_terminalized=true".to_string());
                            verification_checks.push("terminal_chat_reply_ready=true".to_string());
                            crystallize_successful_session(
                                service,
                                state,
                                agent_state,
                                session_id,
                                block_height,
                            )
                            .await;
                            if let Some(tx) = &service.event_sender {
                                emit_terminal_completion_events(
                                    tx,
                                    session_id,
                                    agent_state.step_count,
                                    &summary,
                                    status::status_str(&agent_state.status),
                                );
                                terminal_response_emitted = true;
                            }
                        }
                    } else {
                        agent_state.status = AgentStatus::Running;
                    }
                }
                AgentTool::SysInstallPackage { package, .. } => {
                    if success && command_scope {
                        let summary = out
                            .as_deref()
                            .map(str::trim)
                            .filter(|entry| !entry.is_empty())
                            .map(str::to_string)
                            .unwrap_or_else(|| format!("Installed package '{}'.", package));
                        let summary = enrich_command_scope_summary(&summary, agent_state);
                        let missing_contract_markers =
                            missing_execution_contract_markers_with_rules(agent_state, &rules);
                        if !missing_contract_markers.is_empty() {
                            let missing = missing_contract_markers.join(",");
                            let contract_error = execution_contract_violation_error(&missing);
                            success = false;
                            err = Some(contract_error.clone());
                            out = Some(contract_error);
                            verification_checks
                                .push("execution_contract_gate_blocked=true".to_string());
                            verification_checks
                                .push(format!("execution_contract_missing_keys={}", missing));
                            agent_state.status = AgentStatus::Running;
                        } else {
                            agent_state.status = AgentStatus::Completed(Some(summary.clone()));
                            agent_state.execution_queue.clear();
                            verification_checks
                                .push("install_dependency_terminalized=true".to_string());
                            verification_checks.push("terminal_chat_reply_ready=true".to_string());
                            crystallize_successful_session(
                                service,
                                state,
                                agent_state,
                                session_id,
                                block_height,
                            )
                            .await;
                            emit_completion_gate_status_event(
                                service,
                                session_id,
                                pre_state_summary.step_index,
                                &resolved_intent_id(agent_state),
                                true,
                                "install_dependency_resume_completion_gate_passed",
                            );
                            if let Some(tx) = &service.event_sender {
                                emit_terminal_completion_events(
                                    tx,
                                    session_id,
                                    agent_state.step_count,
                                    &summary,
                                    status::status_str(&agent_state.status),
                                );
                                terminal_response_emitted = true;
                            }
                        }
                    } else {
                        agent_state.status = AgentStatus::Running;
                    }
                }
                AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. } => {
                    if success && is_command_probe_intent(agent_state.resolved_intent.as_ref()) {
                        if let Some(summary) = out
                            .as_deref()
                            .and_then(|raw| summarize_command_probe_output(&tool, raw))
                        {
                            agent_state.status = AgentStatus::Completed(Some(summary.clone()));
                            agent_state.execution_queue.clear();
                            crystallize_successful_session(
                                service,
                                state,
                                agent_state,
                                session_id,
                                block_height,
                            )
                            .await;
                            if let Some(tx) = &service.event_sender {
                                emit_terminal_completion_events(
                                    tx,
                                    session_id,
                                    agent_state.step_count,
                                    &summary,
                                    status::status_str(&agent_state.status),
                                );
                                terminal_response_emitted = true;
                            }
                        } else {
                            agent_state.status = AgentStatus::Running;
                        }
                    } else if success
                        && is_system_clock_read_intent(agent_state.resolved_intent.as_ref())
                    {
                        let summary = out
                            .as_deref()
                            .and_then(summarize_system_clock_or_plain_output)
                            .unwrap_or_else(|| "<unavailable>".to_string());
                        agent_state.status = AgentStatus::Completed(Some(summary.clone()));
                        agent_state.execution_queue.clear();
                        crystallize_successful_session(
                            service,
                            state,
                            agent_state,
                            session_id,
                            block_height,
                        )
                        .await;
                        if let Some(tx) = &service.event_sender {
                            emit_terminal_completion_events(
                                tx,
                                session_id,
                                agent_state.step_count,
                                &summary,
                                status::status_str(&agent_state.status),
                            );
                            terminal_response_emitted = true;
                        }
                    } else if success && command_scope {
                        if let Some(summary) = out.as_deref().and_then(|raw| {
                            summarize_structured_command_receipt_output(
                                raw,
                                agent_state
                                    .command_history
                                    .back()
                                    .map(|entry| entry.timestamp_ms),
                            )
                        }) {
                            let summary = enrich_command_scope_summary(&summary, agent_state);
                            let missing_contract_markers =
                                missing_execution_contract_markers_with_rules(agent_state, &rules);
                            if !missing_contract_markers.is_empty() {
                                let missing = missing_contract_markers.join(",");
                                let contract_error = execution_contract_violation_error(&missing);
                                success = false;
                                err = Some(contract_error.clone());
                                out = Some(contract_error);
                                verification_checks
                                    .push("execution_contract_gate_blocked=true".to_string());
                                verification_checks
                                    .push(format!("execution_contract_missing_keys={}", missing));
                                agent_state.status = AgentStatus::Running;
                            } else {
                                agent_state.status = AgentStatus::Completed(Some(summary.clone()));
                                agent_state.execution_queue.clear();
                                verification_checks.push(
                                    "structured_command_receipt_terminalized=true".to_string(),
                                );
                                verification_checks
                                    .push("terminal_chat_reply_ready=true".to_string());
                                crystallize_successful_session(
                                    service,
                                    state,
                                    agent_state,
                                    session_id,
                                    block_height,
                                )
                                .await;
                                if let Some(tx) = &service.event_sender {
                                    emit_terminal_completion_events(
                                        tx,
                                        session_id,
                                        agent_state.step_count,
                                        &summary,
                                        status::status_str(&agent_state.status),
                                    );
                                    terminal_response_emitted = true;
                                }
                            }
                        } else if let Some(summary) =
                            timer_completion_summary(&tool, agent_state.command_history.back())
                        {
                            let missing_contract_markers =
                                missing_execution_contract_markers_with_rules(agent_state, &rules);
                            if !missing_contract_markers.is_empty() {
                                let missing = missing_contract_markers.join(",");
                                let contract_error = execution_contract_violation_error(&missing);
                                success = false;
                                err = Some(contract_error.clone());
                                out = Some(contract_error);
                                verification_checks
                                    .push("execution_contract_gate_blocked=true".to_string());
                                verification_checks
                                    .push(format!("execution_contract_missing_keys={}", missing));
                                agent_state.status = AgentStatus::Running;
                            } else {
                                agent_state.status = AgentStatus::Completed(Some(summary.clone()));
                                agent_state.execution_queue.clear();
                                verification_checks
                                    .push("timer_schedule_terminalized=true".to_string());
                                verification_checks
                                    .push("terminal_chat_reply_ready=true".to_string());
                                crystallize_successful_session(
                                    service,
                                    state,
                                    agent_state,
                                    session_id,
                                    block_height,
                                )
                                .await;
                                if let Some(tx) = &service.event_sender {
                                    emit_terminal_completion_events(
                                        tx,
                                        session_id,
                                        agent_state.step_count,
                                        &summary,
                                        status::status_str(&agent_state.status),
                                    );
                                    terminal_response_emitted = true;
                                }
                            }
                        } else if let Some(summary) = verified_command_probe_completion_summary(
                            &tool,
                            &agent_state.command_history,
                        ) {
                            let summary = enrich_command_scope_summary(&summary, agent_state);
                            let missing_contract_markers =
                                missing_execution_contract_markers_with_rules(agent_state, &rules);
                            if !missing_contract_markers.is_empty() {
                                let missing = missing_contract_markers.join(",");
                                let contract_error = execution_contract_violation_error(&missing);
                                success = false;
                                err = Some(contract_error.clone());
                                out = Some(contract_error);
                                verification_checks
                                    .push("execution_contract_gate_blocked=true".to_string());
                                verification_checks
                                    .push(format!("execution_contract_missing_keys={}", missing));
                                agent_state.status = AgentStatus::Running;
                            } else {
                                agent_state.status = AgentStatus::Completed(Some(summary.clone()));
                                agent_state.execution_queue.clear();
                                verification_checks
                                    .push("verified_command_probe_terminalized=true".to_string());
                                verification_checks
                                    .push("terminal_chat_reply_ready=true".to_string());
                                crystallize_successful_session(
                                    service,
                                    state,
                                    agent_state,
                                    session_id,
                                    block_height,
                                )
                                .await;
                                if let Some(tx) = &service.event_sender {
                                    emit_terminal_completion_events(
                                        tx,
                                        session_id,
                                        agent_state.step_count,
                                        &summary,
                                        status::status_str(&agent_state.status),
                                    );
                                    terminal_response_emitted = true;
                                }
                            }
                        } else {
                            agent_state.status = AgentStatus::Running;
                        }
                    } else {
                        agent_state.status = AgentStatus::Running;
                    }
                }
                _ => {
                    agent_state.status = AgentStatus::Running;
                }
            }
        }
    }

    if !awaiting_sudo_password
        && !awaiting_clarification
        && !terminal_response_emitted
        && !matches!(
            &tool,
            AgentTool::AgentComplete { .. } | AgentTool::ChatReply { .. }
        )
    {
        if let Some(tx) = &service.event_sender {
            let output = out.clone().or_else(|| err.clone()).unwrap_or_else(|| {
                if success {
                    "Action executed successfully.".to_string()
                } else {
                    "Unknown error".to_string()
                }
            });
            let _ = tx.send(KernelEvent::AgentActionResult {
                session_id,
                step_index: agent_state.step_count,
                tool_name: tool_name.clone(),
                output,
                error_class: extract_error_class_token(err.as_deref()).map(str::to_string),
                agent_status: status::status_str(&agent_state.status),
            });
        }
    }

    if !awaiting_sudo_password && !awaiting_clarification {
        let incident_directive = advance_incident_after_action_outcome(
            service,
            state,
            agent_state,
            session_id,
            &retry_intent_hash,
            &tool_jcs,
            success,
            block_height,
            err.as_deref(),
            verification_checks,
        )
        .await?;
        if matches!(incident_directive, IncidentDirective::QueueActions) {
            remediation_queued = true;
            stop_condition_hit = false;
            escalation_path = None;
            agent_state.status = AgentStatus::Running;
        }
    }

    if success {
        agent_state.recent_actions.clear();
    } else if !awaiting_sudo_password && !awaiting_clarification {
        if is_cec_terminal_error(err.as_deref()) {
            stop_condition_hit = true;
            escalation_path = Some("execution_contract_terminal".to_string());
            remediation_queued = false;
            agent_state.execution_queue.clear();
            let terminal_reason = err
                .clone()
                .unwrap_or_else(|| "ERROR_CLASS=ExecutionContractViolation".to_string());
            agent_state.status = AgentStatus::Failed(terminal_reason);
            verification_checks.push("cec_terminal_error=true".to_string());
        } else {
            failure_class = classify_failure(err.as_deref(), &policy_decision);
            if let Some(class) = failure_class {
                let target_id = crate::agentic::runtime::service::step::anti_loop::specialized_attempt_target_id(
                    state,
                    service.memory_runtime.as_ref(),
                    &tool_name,
                    Some(&tool_jcs),
                )
                .or_else(|| {
                    agent_state.target.as_ref().and_then(|target| {
                        target
                            .app_hint
                            .as_deref()
                            .filter(|v| !v.trim().is_empty())
                            .or_else(|| {
                                target
                                    .title_pattern
                                    .as_deref()
                                    .filter(|v| !v.trim().is_empty())
                            })
                            .map(str::to_string)
                    })
                });
                let raw_window_fingerprint = if log_visual_hash == [0u8; 32] {
                    None
                } else {
                    Some(hex::encode(log_visual_hash))
                };
                let window_fingerprint =
                    crate::agentic::runtime::service::step::anti_loop::canonical_attempt_window_fingerprint(
                        class,
                        command_scope,
                        raw_window_fingerprint.as_deref(),
                    );
                let attempt_key = build_attempt_key(
                    &retry_intent_hash,
                    routing_decision.tier,
                    &tool_name,
                    target_id.as_deref(),
                    window_fingerprint.as_deref(),
                );
                let (repeat_count, attempt_key_hash) =
                    register_failure_attempt(agent_state, class, &attempt_key);
                let budget_remaining = retry_budget_remaining(repeat_count);
                let blocked_without_change = should_block_retry_without_change(class, repeat_count);
                verification_checks.push(format!("attempt_repeat_count={}", repeat_count));
                verification_checks.push(format!("attempt_key_hash={}", attempt_key_hash));
                verification_checks.push(format!(
                    "attempt_retry_budget_remaining={}",
                    budget_remaining
                ));
                verification_checks.push(format!(
                    "attempt_retry_blocked_without_change={}",
                    blocked_without_change
                ));
                let incident_state = load_incident_state(state, &session_id)?;
                if should_enter_incident_recovery(
                    Some(class),
                    &policy_decision,
                    stop_condition_hit,
                    incident_state.as_ref(),
                ) {
                    let (resolved_retry_hash, recovery_tool_name, recovery_tool_jcs): (
                        String,
                        String,
                        Vec<u8>,
                    ) = if let Some(existing) = incident_state.as_ref().filter(|i| i.active) {
                        (
                            existing.root_retry_hash.clone(),
                            existing.root_tool_name.clone(),
                            existing.root_tool_jcs.clone(),
                        )
                    } else {
                        (
                            retry_intent_hash.clone(),
                            tool_name.clone(),
                            tool_jcs.clone(),
                        )
                    };
                    remediation_queued = matches!(
                        start_or_continue_incident_recovery(
                            service,
                            state,
                            agent_state,
                            session_id,
                            block_height,
                            &rules,
                            &resolved_retry_hash,
                            &recovery_tool_name,
                            &recovery_tool_jcs,
                            class,
                            err.as_deref(),
                            verification_checks,
                        )
                        .await?,
                        IncidentDirective::QueueActions
                    );
                }

                let install_lookup_failure = err
                    .as_deref()
                    .map(|msg| requires_wait_for_clarification(&tool_name, msg))
                    .unwrap_or(false);

                if remediation_queued {
                    stop_condition_hit = false;
                    escalation_path = None;
                    agent_state.status = AgentStatus::Running;
                } else if install_lookup_failure {
                    stop_condition_hit = true;
                    escalation_path = Some("wait_for_clarification".to_string());
                    awaiting_clarification = true;
                    mark_incident_wait_for_user(
                        state,
                        session_id,
                        "wait_for_clarification",
                        FailureClass::UserInterventionNeeded,
                        err.as_deref(),
                    )?;
                    agent_state.execution_queue.clear();
                    agent_state.status = AgentStatus::Paused(
                        "Waiting for clarification on target identity.".to_string(),
                    );
                } else if matches!(class, FailureClass::UserInterventionNeeded) {
                    stop_condition_hit = true;
                    escalation_path = Some(escalation_path_for_failure(class).to_string());
                    agent_state.status = AgentStatus::Paused(
                    "Waiting for user intervention: complete the required human verification in your browser/app, then resume.".to_string(),
                );
                } else if is_web_research_scope(agent_state)
                    && matches!(class, FailureClass::UnexpectedState)
                {
                    stop_condition_hit = false;
                    escalation_path = None;
                    success = true;
                    err = None;
                    out = Some(format!(
                        "Transient unexpected state while executing '{}'; continuing web research.",
                        tool_name
                    ));
                    agent_state.status = AgentStatus::Running;
                    agent_state.recent_actions.clear();
                    verification_checks.push("web_unexpected_retry_bypass=true".to_string());
                } else if blocked_without_change {
                    stop_condition_hit = true;
                    escalation_path = Some(escalation_path_for_failure(class).to_string());
                    agent_state.status = AgentStatus::Paused(format!(
                        "Retry blocked: unchanged AttemptKey for {}",
                        class.as_str()
                    ));
                    if matches!(
                        class,
                        FailureClass::FocusMismatch
                            | FailureClass::TargetNotFound
                            | FailureClass::VisionTargetNotFound
                            | FailureClass::NoEffectAfterAction
                            | FailureClass::TierViolation
                            | FailureClass::MissingDependency
                            | FailureClass::ContextDrift
                            | FailureClass::ToolUnavailable
                            | FailureClass::NonDeterministicUI
                            | FailureClass::TimeoutOrHang
                            | FailureClass::UnexpectedState
                    ) {
                        agent_state.consecutive_failures = agent_state.consecutive_failures.max(3);
                    }
                } else if should_trip_retry_guard(class, repeat_count) {
                    stop_condition_hit = true;
                    escalation_path = Some(escalation_path_for_failure(class).to_string());
                    agent_state.status = AgentStatus::Paused(format!(
                        "Retry guard tripped after repeated {} failures",
                        class.as_str()
                    ));
                    if matches!(
                        class,
                        FailureClass::FocusMismatch
                            | FailureClass::TargetNotFound
                            | FailureClass::VisionTargetNotFound
                            | FailureClass::NoEffectAfterAction
                            | FailureClass::TierViolation
                            | FailureClass::MissingDependency
                            | FailureClass::ContextDrift
                            | FailureClass::ToolUnavailable
                            | FailureClass::NonDeterministicUI
                            | FailureClass::TimeoutOrHang
                            | FailureClass::UnexpectedState
                    ) {
                        agent_state.consecutive_failures = agent_state.consecutive_failures.max(3);
                    }
                }
            }
        }
    }

    verification_checks.push(format!("policy_decision={}", policy_decision));
    verification_checks.push("was_resume=true".to_string());
    verification_checks.push(format!("awaiting_sudo_password={}", awaiting_sudo_password));
    verification_checks.push(format!("awaiting_clarification={}", awaiting_clarification));
    verification_checks.push(format!("remediation_queued={}", remediation_queued));
    verification_checks.push(format!("stop_condition_hit={}", stop_condition_hit));
    verification_checks.push(format!(
        "routing_tier_selected={}",
        tier_as_str(routing_decision.tier)
    ));
    verification_checks.push(format!(
        "routing_reason_code={}",
        routing_decision.reason_code
    ));
    verification_checks.push(format!(
        "routing_source_failure={}",
        routing_decision
            .source_failure
            .map(|class| class.as_str().to_string())
            .unwrap_or_else(|| "None".to_string())
    ));
    verification_checks.push(format!(
        "routing_tier_matches_pre_state={}",
        pre_state_summary.tier == tier_as_str(routing_decision.tier)
    ));
    if let Some(class) = failure_class {
        verification_checks.push(format!("failure_class={}", class.as_str()));
    }

    if !awaiting_sudo_password && !awaiting_clarification {
        agent_state.step_count += 1;
    }

    if success {
        if !stop_condition_hit {
            agent_state.consecutive_failures = 0;
        }
    } else if requires_visual_integrity(&tool) {
        agent_state.consecutive_failures = agent_state.consecutive_failures.max(3);
    }

    let mut artifacts = extract_artifacts(err.as_deref(), out.as_deref());
    artifacts.push(format!(
        "trace://agent_step/{}",
        pre_state_summary.step_index
    ));
    artifacts.push(format!("trace://session/{}", hex::encode(&session_id[..4])));
    let intent_id_for_contract = agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| resolved.intent_id.clone())
        .unwrap_or_else(|| "resolver.unclassified".to_string());
    persist_step_contract_evidence(
        state,
        session_id,
        pre_state_summary.step_index,
        intent_id_for_contract.as_str(),
        verification_checks,
        prior_consecutive_failures,
    )?;
    let checks = std::mem::take(verification_checks);
    let post_state = build_post_state_summary(agent_state, success, checks);
    let policy_binding = policy_binding_hash(&intent_hash, &policy_decision);
    let incident_fields =
        incident_receipt_fields(load_incident_state(state, &session_id)?.as_ref());
    let failure_class_name = failure_class
        .map(|class| class.as_str().to_string())
        .unwrap_or_default();
    let receipt = RoutingReceiptEvent {
        session_id,
        step_index: pre_state_summary.step_index,
        intent_hash,
        policy_decision,
        tool_name,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        pre_state: pre_state_summary,
        action_json,
        post_state,
        artifacts,
        failure_class: failure_class.map(to_routing_failure_class),
        failure_class_name,
        intent_class: incident_fields.intent_class,
        incident_id: incident_fields.incident_id,
        incident_stage: incident_fields.incident_stage,
        strategy_name: incident_fields.strategy_name,
        strategy_node: incident_fields.strategy_node,
        gate_state: incident_fields.gate_state,
        resolution_action: incident_fields.resolution_action,
        stop_condition_hit,
        escalation_path,
        lineage_ptr: lineage_pointer(agent_state.active_skill_hash),
        mutation_receipt_ptr: mutation_receipt_pointer(state, &session_id),
        policy_binding_hash: policy_binding,
        policy_binding_sig: None,
        policy_binding_signer: None,
    };
    emit_routing_receipt(service.event_sender.as_ref(), receipt);

    if matches!(agent_state.status, AgentStatus::Failed(_)) {
        let _ = service
            .update_skill_reputation(state, session_id, false, block_height)
            .await;
    }

    persist_agent_state(state, &key, &agent_state, service.memory_runtime.as_ref())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::runtime::service::step::action::command_contract::{
        PROVIDER_SELECTION_COMMIT_RECEIPT, VERIFICATION_COMMIT_RECEIPT,
    };
    use crate::agentic::runtime::service::step::action::{
        mark_execution_postcondition, receipt_marker,
    };
    use crate::agentic::runtime::types::{AgentMode, ExecutionTier, ToolCallStatus};
    use async_trait::async_trait;
    use ioi_api::state::StateAccess;
    use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
    use ioi_api::vm::inference::mock::MockInferenceRuntime;
    use ioi_api::vm::inference::InferenceRuntime;
    use ioi_drivers::browser::BrowserDriver;
    use ioi_drivers::terminal::TerminalDriver;
    use ioi_memory::MemoryRuntime;
    use ioi_types::app::agentic::{
        AgentTool, CapabilityId, IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState,
    };
    use ioi_types::app::{ActionRequest, ContextSlice, KernelEvent, RoutingStateSummary};
    use ioi_types::error::{StateError, VmError};
    use serde_json::json;
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::Arc;

    #[derive(Debug, Default, Clone)]
    struct MockState {
        data: BTreeMap<Vec<u8>, Vec<u8>>,
    }

    impl StateAccess for MockState {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
            Ok(self.data.get(key).cloned())
        }

        fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
            self.data.insert(key.to_vec(), value.to_vec());
            Ok(())
        }

        fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
            self.data.remove(key);
            Ok(())
        }

        fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
            for (key, value) in updates {
                self.insert(key, value)?;
            }
            Ok(())
        }

        fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
            keys.iter().map(|key| self.get(key)).collect()
        }

        fn batch_apply(
            &mut self,
            inserts: &[(Vec<u8>, Vec<u8>)],
            deletes: &[Vec<u8>],
        ) -> Result<(), StateError> {
            for (key, value) in inserts {
                self.insert(key, value)?;
            }
            for key in deletes {
                self.delete(key)?;
            }
            Ok(())
        }

        fn prefix_scan(
            &self,
            prefix: &[u8],
        ) -> Result<ioi_api::state::StateScanIter<'_>, StateError> {
            let items = self
                .data
                .iter()
                .filter(|(key, _)| key.starts_with(prefix))
                .map(|(key, value)| {
                    Ok((
                        Arc::<[u8]>::from(key.clone().into_boxed_slice()),
                        Arc::<[u8]>::from(value.clone().into_boxed_slice()),
                    ))
                })
                .collect::<Vec<_>>();
            Ok(Box::new(items.into_iter()))
        }
    }

    struct NoopGuiDriver;

    #[async_trait]
    impl GuiDriver for NoopGuiDriver {
        async fn capture_screen(
            &self,
            _crop_rect: Option<(i32, i32, u32, u32)>,
        ) -> Result<Vec<u8>, VmError> {
            Err(VmError::HostError("noop gui".into()))
        }

        async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
            Err(VmError::HostError("noop gui".into()))
        }

        async fn capture_tree(&self) -> Result<String, VmError> {
            Err(VmError::HostError("noop gui".into()))
        }

        async fn capture_context(&self, _intent: &ActionRequest) -> Result<ContextSlice, VmError> {
            Err(VmError::HostError("noop gui".into()))
        }

        async fn inject_input(&self, _event: InputEvent) -> Result<(), VmError> {
            Err(VmError::HostError("noop gui".into()))
        }

        async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
            Ok(None)
        }

        async fn register_som_overlay(
            &self,
            _map: std::collections::HashMap<u32, (i32, i32, i32, i32)>,
        ) -> Result<(), VmError> {
            Ok(())
        }
    }

    fn mail_reply_resolved_intent() -> ResolvedIntentState {
        ResolvedIntentState {
            intent_id: "mail.reply".to_string(),
            scope: IntentScopeProfile::Conversation,
            band: IntentConfidenceBand::High,
            score: 1.0,
            top_k: vec![],
            required_capabilities: vec![CapabilityId::from("mail.reply")],
            required_receipts: vec![],
            required_postconditions: vec![],
            risk_class: "medium".to_string(),
            preferred_tier: "tool_first".to_string(),
            matrix_version: "test".to_string(),
            embedding_model_id: String::new(),
            embedding_model_version: String::new(),
            similarity_function_id: String::new(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: String::new(),
            matrix_source_hash: [0u8; 32],
            receipt_hash: [0u8; 32],
            provider_selection: None,
            instruction_contract: None,
            constrained: false,
        }
    }

    fn agent_state_with_mail_reply() -> AgentState {
        AgentState {
            session_id: [4u8; 32],
            goal: "send the email".to_string(),
            transcript_root: [0u8; 32],
            status: AgentStatus::Running,
            step_count: 0,
            max_steps: 10,
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
            mode: AgentMode::default(),
            current_tier: ExecutionTier::default(),
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
            resolved_intent: Some(mail_reply_resolved_intent()),
            awaiting_intent_clarification: false,
            working_directory: ".".to_string(),
            command_history: VecDeque::new(),
            active_lens: None,
        }
    }

    fn automation_monitor_resolved_intent() -> ResolvedIntentState {
        ResolvedIntentState {
            intent_id: "automation.monitor".to_string(),
            scope: IntentScopeProfile::CommandExecution,
            band: IntentConfidenceBand::High,
            score: 1.0,
            top_k: vec![],
            required_capabilities: vec![CapabilityId::from("automation.monitor.install")],
            required_receipts: vec![],
            required_postconditions: vec![],
            risk_class: "medium".to_string(),
            preferred_tier: "tool_first".to_string(),
            matrix_version: "test".to_string(),
            embedding_model_id: String::new(),
            embedding_model_version: String::new(),
            similarity_function_id: String::new(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: String::new(),
            matrix_source_hash: [0u8; 32],
            receipt_hash: [0u8; 32],
            provider_selection: None,
            instruction_contract: None,
            constrained: false,
        }
    }

    fn install_dependency_resolved_intent() -> ResolvedIntentState {
        ResolvedIntentState {
            intent_id: "command.exec.install_dependency".to_string(),
            scope: IntentScopeProfile::CommandExecution,
            band: IntentConfidenceBand::High,
            score: 1.0,
            top_k: vec![],
            required_capabilities: vec![CapabilityId::from("command.exec.install_dependency")],
            required_receipts: vec![],
            required_postconditions: vec![],
            risk_class: "medium".to_string(),
            preferred_tier: "tool_first".to_string(),
            matrix_version: "test".to_string(),
            embedding_model_id: String::new(),
            embedding_model_version: String::new(),
            similarity_function_id: String::new(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: String::new(),
            matrix_source_hash: [0u8; 32],
            receipt_hash: [0u8; 32],
            provider_selection: None,
            instruction_contract: None,
            constrained: false,
        }
    }

    fn agent_state_with_automation_monitor() -> AgentState {
        AgentState {
            session_id: [7u8; 32],
            goal: "Monitor Hacker News and notify me whenever a post about Web4 or post-quantum cryptography hits the front page.".to_string(),
            transcript_root: [0u8; 32],
            status: AgentStatus::Running,
            step_count: 0,
            max_steps: 10,
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
            mode: AgentMode::default(),
            current_tier: ExecutionTier::default(),
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
            resolved_intent: Some(automation_monitor_resolved_intent()),
            awaiting_intent_clarification: false,
            working_directory: ".".to_string(),
            command_history: VecDeque::new(),
            active_lens: None,
        }
    }

    fn agent_state_with_install_dependency() -> AgentState {
        AgentState {
            session_id: [9u8; 32],
            goal: "install cowsay".to_string(),
            transcript_root: [0u8; 32],
            status: AgentStatus::Running,
            step_count: 0,
            max_steps: 10,
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
            mode: AgentMode::default(),
            current_tier: ExecutionTier::default(),
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
            resolved_intent: Some(install_dependency_resolved_intent()),
            awaiting_intent_clarification: false,
            working_directory: ".".to_string(),
            command_history: VecDeque::new(),
            active_lens: None,
        }
    }

    fn build_resume_test_service() -> RuntimeAgentService {
        let (tx, _rx) = tokio::sync::broadcast::channel(32);
        let inference: Arc<dyn InferenceRuntime> = Arc::new(MockInferenceRuntime);
        RuntimeAgentService::new(
            Arc::new(NoopGuiDriver),
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            inference,
        )
        .with_memory_runtime(Arc::new(
            MemoryRuntime::open_sqlite_in_memory().expect("memory runtime"),
        ))
        .with_event_sender(tx)
    }

    #[test]
    fn terminalizes_mail_reply_resume_when_intent_is_mail_reply() {
        let agent_state = agent_state_with_mail_reply();
        assert!(should_terminalize_mail_reply_intent(
            &agent_state,
            "connector__google__gmail_send_email"
        ));
    }

    #[test]
    fn terminalizes_mail_reply_resume_when_only_fallback_provider_actions_remain() {
        let mut agent_state = agent_state_with_mail_reply();
        agent_state.resolved_intent = None;
        agent_state
            .execution_queue
            .push(ioi_types::app::ActionRequest {
                target: ioi_types::app::ActionTarget::Custom(
                    "connector__google__gmail_draft_email".to_string(),
                ),
                params: vec![],
                context: ioi_types::app::ActionContext {
                    agent_id: "desktop_agent".to_string(),
                    session_id: Some(agent_state.session_id),
                    window_id: None,
                },
                nonce: 0,
            });

        assert!(should_terminalize_mail_reply_intent(
            &agent_state,
            "connector__google__gmail_send_email"
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn approved_automation_monitor_resume_terminalizes_instead_of_looping() {
        let service = build_resume_test_service();
        let mut receiver = service
            .event_sender
            .as_ref()
            .expect("event sender")
            .subscribe();
        let mut state = MockState::default();
        let mut agent_state = agent_state_with_automation_monitor();
        let tool = AgentTool::AutomationCreateMonitor {
            title: Some("Hacker News Monitor for Web4 and Post-Quantum Cryptography".to_string()),
            description: Some(
                "Monitor Hacker News for posts about Web4 and post-quantum cryptography."
                    .to_string(),
            ),
            keywords: vec!["Web4".to_string(), "post-quantum cryptography".to_string()],
            interval_seconds: Some(300),
            source_prompt: Some(agent_state.goal.clone()),
        };
        let tool_jcs = serde_jcs::to_vec(&tool).expect("tool jcs");
        let output = concat!(
            "Scheduled workflow: Hacker News Monitor for Web4 and Post-Quantum Cryptography\n",
            "Workflow ID: monitor_hacker_news_cc9364be12aa\n",
            "Poll interval: 300 seconds\n",
            "Source: https://news.ycombinator.com/\n",
            "Keywords: post-quantum cryptography, web4\n",
            "Artifact path: ./ioi-data/automation/artifacts/monitor_hacker_news_cc9364be12aa.json"
        )
        .to_string();
        let mut verification_checks = Vec::new();
        let session_id = agent_state.session_id;
        let current_tier = agent_state.current_tier;
        agent_state.tool_execution_log.insert(
            receipt_marker("host_discovery"),
            ToolCallStatus::Executed("/home/test".to_string()),
        );
        agent_state.tool_execution_log.insert(
            receipt_marker("provider_selection"),
            ToolCallStatus::Executed("automation.monitor.install".to_string()),
        );
        agent_state.tool_execution_log.insert(
            receipt_marker(PROVIDER_SELECTION_COMMIT_RECEIPT),
            ToolCallStatus::Executed("sha256:provider-selection".to_string()),
        );
        agent_state.tool_execution_log.insert(
            receipt_marker("execution"),
            ToolCallStatus::Executed("automation__create_monitor".to_string()),
        );
        agent_state.tool_execution_log.insert(
            receipt_marker("verification"),
            ToolCallStatus::Executed("automation_monitor_install=true".to_string()),
        );
        agent_state.tool_execution_log.insert(
            receipt_marker(VERIFICATION_COMMIT_RECEIPT),
            ToolCallStatus::Executed("sha256:verification".to_string()),
        );
        mark_execution_postcondition(&mut agent_state.tool_execution_log, "execution_artifact");

        run_lifecycle_status_phase(LifecycleStatusPhaseContext {
            service: &service,
            state: &mut state,
            agent_state: &mut agent_state,
            session_id,
            block_height: 1,
            pre_state_summary: RoutingStateSummary {
                agent_status: "Running".to_string(),
                tier: "tool_first".to_string(),
                step_index: 0,
                consecutive_failures: 0,
                target_hint: None,
            },
            routing_decision: TierRoutingDecision {
                tier: current_tier,
                reason_code: "resume_test",
                source_failure: None,
            },
            policy_decision: "approved".to_string(),
            verification_checks: &mut verification_checks,
            tool,
            tool_name: "automation__create_monitor".to_string(),
            tool_jcs,
            tool_hash: [0u8; 32],
            pending_vhash: [0u8; 32],
            action_json: json!({
                "name": "automation__create_monitor",
                "arguments": {
                    "interval_seconds": 300,
                    "keywords": ["Web4", "post-quantum cryptography"],
                }
            })
            .to_string(),
            intent_hash: "intent-hash".to_string(),
            retry_intent_hash: "retry-intent-hash".to_string(),
            rules: ActionRules::default(),
            command_scope: true,
            success: true,
            out: Some(output.clone()),
            err: None,
            log_visual_hash: [0u8; 32],
        })
        .await
        .expect("resume lifecycle status");

        assert!(matches!(
            agent_state.status,
            AgentStatus::Completed(Some(ref summary)) if summary == &output
        ));
        assert!(agent_state.execution_queue.is_empty());

        let mut saw_chat_reply = false;
        let mut saw_running_automation_result = false;
        while let Ok(event) = receiver.try_recv() {
            if let KernelEvent::AgentActionResult {
                tool_name,
                agent_status,
                ..
            } = event
            {
                if tool_name == "chat__reply" && agent_status == "Completed" {
                    saw_chat_reply = true;
                }
                if tool_name == "automation__create_monitor" && agent_status == "Running" {
                    saw_running_automation_result = true;
                }
            }
        }

        assert!(saw_chat_reply);
        assert!(!saw_running_automation_result);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn approved_install_resume_terminalizes_instead_of_looping() {
        let service = build_resume_test_service();
        let mut receiver = service
            .event_sender
            .as_ref()
            .expect("event sender")
            .subscribe();
        let mut state = MockState::default();
        let mut agent_state = agent_state_with_install_dependency();
        let tool = AgentTool::SysInstallPackage {
            package: "cowsay".to_string(),
            manager: Some("apt".to_string()),
        };
        let tool_jcs = serde_jcs::to_vec(&tool).expect("tool jcs");
        let output = "Installed 'cowsay' via 'apt-get' (sudo-password)".to_string();
        let mut verification_checks = Vec::new();
        let session_id = agent_state.session_id;
        let current_tier = agent_state.current_tier;
        agent_state.tool_execution_log.insert(
            receipt_marker("host_discovery"),
            ToolCallStatus::Executed("/home/test".to_string()),
        );
        agent_state.tool_execution_log.insert(
            receipt_marker("provider_selection"),
            ToolCallStatus::Executed("command.exec.install_dependency".to_string()),
        );
        agent_state.tool_execution_log.insert(
            receipt_marker(PROVIDER_SELECTION_COMMIT_RECEIPT),
            ToolCallStatus::Executed("sha256:provider-selection".to_string()),
        );
        agent_state.tool_execution_log.insert(
            receipt_marker("execution"),
            ToolCallStatus::Executed("sys__install_package".to_string()),
        );
        agent_state.tool_execution_log.insert(
            receipt_marker("verification"),
            ToolCallStatus::Executed("install_package_success=true".to_string()),
        );
        agent_state.tool_execution_log.insert(
            receipt_marker(VERIFICATION_COMMIT_RECEIPT),
            ToolCallStatus::Executed("sha256:verification".to_string()),
        );
        mark_execution_postcondition(&mut agent_state.tool_execution_log, "execution_artifact");

        run_lifecycle_status_phase(LifecycleStatusPhaseContext {
            service: &service,
            state: &mut state,
            agent_state: &mut agent_state,
            session_id,
            block_height: 1,
            pre_state_summary: RoutingStateSummary {
                agent_status: "Running".to_string(),
                tier: "tool_first".to_string(),
                step_index: 0,
                consecutive_failures: 0,
                target_hint: None,
            },
            routing_decision: TierRoutingDecision {
                tier: current_tier,
                reason_code: "resume_test",
                source_failure: None,
            },
            policy_decision: "approved".to_string(),
            verification_checks: &mut verification_checks,
            tool,
            tool_name: "sys__install_package".to_string(),
            tool_jcs,
            tool_hash: [0u8; 32],
            pending_vhash: [0u8; 32],
            action_json: json!({
                "name": "sys__install_package",
                "arguments": {
                    "package": "cowsay",
                    "manager": "apt",
                }
            })
            .to_string(),
            intent_hash: "intent-hash".to_string(),
            retry_intent_hash: "retry-intent-hash".to_string(),
            rules: ActionRules::default(),
            command_scope: true,
            success: true,
            out: Some(output.clone()),
            err: None,
            log_visual_hash: [0u8; 32],
        })
        .await
        .expect("resume lifecycle status");

        assert!(matches!(
            agent_state.status,
            AgentStatus::Completed(Some(ref summary)) if summary == &output
        ));
        assert!(agent_state.execution_queue.is_empty());

        let mut saw_chat_reply = false;
        let mut saw_running_install_result = false;
        while let Ok(event) = receiver.try_recv() {
            if let KernelEvent::AgentActionResult {
                tool_name,
                agent_status,
                ..
            } = event
            {
                if tool_name == "chat__reply" && agent_status == "Completed" {
                    saw_chat_reply = true;
                }
                if tool_name == "sys__install_package" && agent_status == "Running" {
                    saw_running_install_result = true;
                }
            }
        }

        assert!(saw_chat_reply);
        assert!(!saw_running_install_result);
    }
}
