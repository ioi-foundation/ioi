use super::events::emit_execution_contract_receipt_event;
use super::tool_outcome::{apply_tool_outcome_and_followups, ToolOutcomeContext};
use super::*;

pub(super) struct ExecutionSuccessContext<'a, 's> {
    pub service: &'a DesktopAgentService,
    pub state: &'s mut dyn StateAccess,
    pub agent_state: &'a mut AgentState,
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

pub(super) async fn handle_execution_success(
    ctx: ExecutionSuccessContext<'_, '_>,
) -> Result<(), TransactionError> {
    let ExecutionSuccessContext {
        service,
        state,
        agent_state,
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
    if command_scope
        && matches!(
            tool,
            AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
        )
        && !*success
    {
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

    // Orchestration meta-tools require access to chain state; execute them
    // on the primary path here instead of the stateless ToolExecutor.
    if *success {
        match tool {
            AgentTool::AgentDelegate { goal, budget } => {
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
                                step_index,
                                block_height,
                            )
                            .await
                            {
                                Ok(child_session_id) => {
                                    *history_entry = Some(format!(
                                        "{{\"child_session_id_hex\":\"{}\"}}",
                                        hex::encode(child_session_id)
                                    ));
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
            } => match child_session::await_child_session_status(state, child_session_id_hex) {
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
            mark_execution_postcondition(&mut agent_state.tool_execution_log, "execution_artifact");
            verification_checks.push(postcondition_marker("execution_artifact"));
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

    if (*success || *command_probe_completed) && !req_hash_hex.is_empty() {
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
    }

    if *success {
        if matches!(
            tool,
            AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
        ) {
            if command_scope && requires_timer_notification_contract(agent_state) {
                if sys_exec_arms_timer_delay_backend(tool) {
                    mark_execution_postcondition(
                        &mut agent_state.tool_execution_log,
                        TIMER_SLEEP_BACKEND_POSTCONDITION,
                    );
                    verification_checks
                        .push(postcondition_marker(TIMER_SLEEP_BACKEND_POSTCONDITION));
                    emit_execution_contract_receipt_event(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "execution",
                        TIMER_SLEEP_BACKEND_POSTCONDITION,
                        true,
                        "timer_sleep_backend=armed",
                        None,
                        None,
                        synthesized_payload_hash.clone(),
                    );
                }
                if let Some(command_preview) = sys_exec_command_preview(tool) {
                    if command_arms_deferred_notification_path(&command_preview) {
                        mark_execution_postcondition(
                            &mut agent_state.tool_execution_log,
                            TIMER_NOTIFICATION_PATH_POSTCONDITION,
                        );
                        verification_checks
                            .push(postcondition_marker(TIMER_NOTIFICATION_PATH_POSTCONDITION));
                        emit_execution_contract_receipt_event(
                            service,
                            session_id,
                            step_index,
                            resolved_intent_id,
                            "execution",
                            TIMER_NOTIFICATION_PATH_POSTCONDITION,
                            true,
                            "timer_notification_path_armed=true",
                            None,
                            None,
                            synthesized_payload_hash.clone(),
                        );
                        mark_execution_receipt(
                            &mut agent_state.tool_execution_log,
                            "notification_strategy",
                        );
                        verification_checks.push(receipt_marker("notification_strategy"));
                        emit_execution_contract_receipt_event(
                            service,
                            session_id,
                            step_index,
                            resolved_intent_id,
                            "execution",
                            "notification_strategy",
                            true,
                            "notification_strategy=deferred",
                            None,
                            None,
                            synthesized_payload_hash.clone(),
                        );
                        verification_checks.push("timer_notification_path_armed=true".to_string());
                    }
                }
            }
            if command_scope {
                mark_execution_receipt(&mut agent_state.tool_execution_log, "execution");
                verification_checks.push(receipt_marker("execution"));
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
                record_verification_receipts(
                    &mut agent_state.tool_execution_log,
                    verification_checks,
                    tool,
                    agent_state.command_history.back(),
                );
                let verification_commit = execution_receipt_value(
                    &agent_state.tool_execution_log,
                    VERIFICATION_COMMIT_RECEIPT,
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
                    VERIFICATION_COMMIT_RECEIPT,
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
        if let Some(entry) = history_entry.clone() {
            let tool_msg = ioi_types::app::agentic::ChatMessage {
                role: "tool".to_string(),
                content: entry,
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
    }

    apply_tool_outcome_and_followups(ToolOutcomeContext {
        service,
        _state: state,
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
    })
    .await?;

    Ok(())
}
