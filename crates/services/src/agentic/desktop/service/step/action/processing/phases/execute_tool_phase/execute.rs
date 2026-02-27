use super::contracts::{bootstrap_contract, duplicate_execution_state};
use super::duplicate::{handle_duplicate_command_execution, DuplicateExecutionContext};
use super::events::{
    emit_completion_gate_status_event, emit_completion_gate_violation_events,
    emit_execution_contract_receipt_event,
};
use super::pending_approval::{handle_pending_approval, PendingApprovalContext};
use super::precheck::run_execution_prechecks;
use super::system_fail::handle_system_fail_outcome;
use super::timer_contract::{
    prepare_timer_contract, restore_pending_visual_context, TimerContractContext,
};
use super::web_followup::apply_web_research_followups;
use super::*;

pub(crate) async fn execute_tool_phase(
    ctx: ExecuteToolPhaseContext<'_, '_>,
    state_in: ActionProcessingState,
) -> Result<ActionProcessingState, TransactionError> {
    let ExecuteToolPhaseContext {
        service,
        state,
        agent_state,
        call_context,
        tool,
        tool_args,
        rules,
        session_id,
        block_height,
        block_timestamp_ns,
        final_visual_phash,
        req_hash_hex,
        tool_call_result,
        pre_state_summary,
    } = ctx;

    let ActionProcessingState {
        mut policy_decision,
        action_payload,
        intent_hash,
        retry_intent_hash,
        mut success,
        mut error_msg,
        mut is_gated,
        mut is_lifecycle_action,
        mut current_tool_name,
        mut history_entry,
        mut action_output,
        mut trace_visual_hash,
        executed_tool_jcs,
        failure_class,
        stop_condition_hit,
        escalation_path,
        remediation_queued,
        mut verification_checks,
        awaiting_sudo_password,
        awaiting_clarification,
        mut command_probe_completed,
        invalid_tool_call_fail_fast,
        invalid_tool_call_bootstrap_web,
        invalid_tool_call_fail_fast_mailbox,
        mut terminal_chat_reply_output,
    } = state_in;
    let mut tool = tool;
    let os_driver = service
        .os_driver
        .clone()
        .ok_or(TransactionError::Invalid("OS driver missing".into()))?;
    let action_fingerprint = retry_intent_hash.clone().unwrap_or_default();
    let bootstrap = bootstrap_contract(
        service,
        agent_state,
        &tool,
        &current_tool_name,
        session_id,
        pre_state_summary.step_index,
        &mut verification_checks,
    );
    let command_scope = bootstrap.command_scope;
    let resolved_intent_id = bootstrap.resolved_intent_id;
    let mut synthesized_payload_hash = bootstrap.synthesized_payload_hash;
    let route_label = bootstrap.route_label;
    let (duplicate_command_execution, matching_command_history_entry) = duplicate_execution_state(
        agent_state,
        &tool,
        command_scope,
        pre_state_summary.step_index,
        &action_fingerprint,
        &mut verification_checks,
    );
    if duplicate_command_execution {
        let duplicate_outcome = handle_duplicate_command_execution(DuplicateExecutionContext {
            service,
            agent_state,
            tool: &tool,
            matching_command_history_entry,
            command_scope,
            action_fingerprint: &action_fingerprint,
            session_id,
            step_index: pre_state_summary.step_index,
            resolved_intent_id: &resolved_intent_id,
            verification_checks: &mut verification_checks,
        });
        success = duplicate_outcome.success;
        error_msg = duplicate_outcome.error_msg;
        history_entry = duplicate_outcome.history_entry;
        action_output = duplicate_outcome.action_output;
        terminal_chat_reply_output = duplicate_outcome.terminal_chat_reply_output;
        is_lifecycle_action = duplicate_outcome.is_lifecycle_action;
    } else {
        if run_execution_prechecks(
            service,
            agent_state,
            &tool,
            &current_tool_name,
            command_scope,
            &req_hash_hex,
            session_id,
            pre_state_summary.step_index,
            &resolved_intent_id,
            route_label,
            synthesized_payload_hash.clone(),
            &mut verification_checks,
            &mut policy_decision,
            &mut success,
            &mut error_msg,
            &mut history_entry,
            &mut action_output,
        ) {
            let timer_contract = prepare_timer_contract(TimerContractContext {
                service,
                agent_state,
                tool,
                command_scope,
                req_hash_hex: &req_hash_hex,
                session_id,
                step_index: pre_state_summary.step_index,
                resolved_intent_id: &resolved_intent_id,
                verification_checks: &mut verification_checks,
                synthesized_payload_hash,
            });
            tool = timer_contract.tool;
            synthesized_payload_hash = timer_contract.synthesized_payload_hash;
            let should_execute_tool = timer_contract.should_execute_tool;
            if let Some(synth_error) = timer_contract.pre_execution_error {
                success = false;
                error_msg = Some(synth_error.clone());
                history_entry = Some(synth_error.clone());
                action_output = Some(synth_error);
            }

            restore_pending_visual_context(service, agent_state).await;

            // [FIX] Pass the required InferenceRuntime (reasoning) to ToolExecutor constructor inside handle_action_execution
            if should_execute_tool {
                match service
                    .handle_action_execution_with_state(
                        state,
                        call_context,
                        tool.clone(),
                        session_id,
                        agent_state.step_count,
                        final_visual_phash,
                        &rules,
                        &agent_state,
                        &os_driver,
                        None,
                    )
                    .await
                {
                    Ok((s, entry, e, visual_hash)) => {
                        success = s;
                        error_msg = e;
                        history_entry = entry.clone();
                        if let Some(visual_hash) = visual_hash {
                            trace_visual_hash = Some(visual_hash);
                            verification_checks.push(format!(
                                "visual_observation_checksum={}",
                                hex::encode(visual_hash)
                            ));
                        }
                        if command_scope
                            && matches!(
                                &tool,
                                AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
                            )
                            && !success
                        {
                            let cause = error_msg
                                .clone()
                                .unwrap_or_else(|| "unknown execution failure".to_string());
                            if !cause.contains("ERROR_CLASS=ExecutionFailedTerminal") {
                                error_msg = Some(format!(
                                    "ERROR_CLASS=ExecutionFailedTerminal stage=execution cause={}",
                                    cause
                                ));
                            }
                            let execution_failure = error_msg.clone().unwrap_or_else(|| {
                                "ERROR_CLASS=ExecutionFailedTerminal".to_string()
                            });
                            emit_execution_contract_receipt_event(
                                service,
                                session_id,
                                pre_state_summary.step_index,
                                &resolved_intent_id,
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
                        if success {
                            match &tool {
                                AgentTool::AgentDelegate { goal, budget } => {
                                    let tool_jcs = match serde_jcs::to_vec(&tool) {
                                        Ok(bytes) => bytes,
                                        Err(err) => {
                                            success = false;
                                            error_msg = Some(format!(
                                                "ERROR_CLASS=UnexpectedState Failed to encode delegation tool: {}",
                                                err
                                            ));
                                            history_entry = None;
                                            Vec::new()
                                        }
                                    };

                                    if success {
                                        match sha256(&tool_jcs) {
                                            Ok(tool_hash) => {
                                                match spawn_delegated_child_session(
                                                    service,
                                                    state,
                                                    agent_state,
                                                    tool_hash,
                                                    goal,
                                                    *budget,
                                                    pre_state_summary.step_index,
                                                    block_height,
                                                )
                                                .await
                                                {
                                                    Ok(child_session_id) => {
                                                        history_entry = Some(format!(
                                                            "{{\"child_session_id_hex\":\"{}\"}}",
                                                            hex::encode(child_session_id)
                                                        ));
                                                        error_msg = None;
                                                    }
                                                    Err(err) => {
                                                        success = false;
                                                        error_msg = Some(err.to_string());
                                                        history_entry = None;
                                                    }
                                                }
                                            }
                                            Err(err) => {
                                                success = false;
                                                error_msg = Some(format!(
                                                    "ERROR_CLASS=UnexpectedState Delegation hash failed: {}",
                                                    err
                                                ));
                                                history_entry = None;
                                            }
                                        }
                                    }
                                }
                                AgentTool::AgentAwait {
                                    child_session_id_hex,
                                } => {
                                    match child_session::await_child_session_status(
                                        state,
                                        child_session_id_hex,
                                    ) {
                                        Ok(out) => {
                                            history_entry = Some(out);
                                            error_msg = None;
                                        }
                                        Err(err) => {
                                            success = false;
                                            error_msg = Some(err);
                                            history_entry = None;
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }

                        if matches!(
                            &tool,
                            AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
                        ) {
                            if let Some(raw_entry) =
                                command_history::extract_command_history(&history_entry)
                            {
                                verification_checks.push(
                                    "capability_execution_evidence=command_history".to_string(),
                                );
                                verification_checks.push(format!(
                                    "capability_execution_last_exit_code={}",
                                    raw_entry.exit_code
                                ));
                                if command_scope {
                                    mark_execution_postcondition(
                                        &mut agent_state.tool_execution_log,
                                        "execution_artifact",
                                    );
                                    verification_checks
                                        .push(postcondition_marker("execution_artifact"));
                                    emit_execution_contract_receipt_event(
                                        service,
                                        session_id,
                                        pre_state_summary.step_index,
                                        &resolved_intent_id,
                                        "execution",
                                        "execution_artifact",
                                        true,
                                        &format!("command_exit_code={}", raw_entry.exit_code),
                                        None,
                                        None,
                                        synthesized_payload_hash.clone(),
                                    );
                                }
                                let history_entry = command_history::scrub_command_history_fields(
                                    &service.scrubber,
                                    raw_entry,
                                )
                                .await;
                                command_history::append_to_bounded_history(
                                    &mut agent_state.command_history,
                                    history_entry,
                                    MAX_COMMAND_HISTORY,
                                );
                            }
                        }

                        if (success || command_probe_completed) && !req_hash_hex.is_empty() {
                            agent_state.tool_execution_log.insert(
                                req_hash_hex.clone(),
                                ToolCallStatus::Executed("success".into()),
                            );
                            if let Some(retry_hash) = retry_intent_hash.as_deref() {
                                mark_action_fingerprint_executed_at_step(
                                    &mut agent_state.tool_execution_log,
                                    retry_hash,
                                    pre_state_summary.step_index,
                                    "success",
                                );
                            }
                            agent_state.pending_approval = None;
                            agent_state.pending_tool_jcs = None;
                        }

                        if success {
                            if matches!(
                                &tool,
                                AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
                            ) {
                                if command_scope
                                    && requires_timer_notification_contract(agent_state)
                                {
                                    if sys_exec_arms_timer_delay_backend(&tool) {
                                        mark_execution_postcondition(
                                            &mut agent_state.tool_execution_log,
                                            TIMER_SLEEP_BACKEND_POSTCONDITION,
                                        );
                                        verification_checks.push(postcondition_marker(
                                            TIMER_SLEEP_BACKEND_POSTCONDITION,
                                        ));
                                        emit_execution_contract_receipt_event(
                                            service,
                                            session_id,
                                            pre_state_summary.step_index,
                                            &resolved_intent_id,
                                            "execution",
                                            TIMER_SLEEP_BACKEND_POSTCONDITION,
                                            true,
                                            "timer_sleep_backend=armed",
                                            None,
                                            None,
                                            synthesized_payload_hash.clone(),
                                        );
                                    }
                                    if let Some(command_preview) = sys_exec_command_preview(&tool) {
                                        if command_arms_deferred_notification_path(&command_preview)
                                        {
                                            mark_execution_postcondition(
                                                &mut agent_state.tool_execution_log,
                                                TIMER_NOTIFICATION_PATH_POSTCONDITION,
                                            );
                                            verification_checks.push(postcondition_marker(
                                                TIMER_NOTIFICATION_PATH_POSTCONDITION,
                                            ));
                                            emit_execution_contract_receipt_event(
                                                service,
                                                session_id,
                                                pre_state_summary.step_index,
                                                &resolved_intent_id,
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
                                            verification_checks
                                                .push(receipt_marker("notification_strategy"));
                                            emit_execution_contract_receipt_event(
                                                service,
                                                session_id,
                                                pre_state_summary.step_index,
                                                &resolved_intent_id,
                                                "execution",
                                                "notification_strategy",
                                                true,
                                                "notification_strategy=deferred",
                                                None,
                                                None,
                                                synthesized_payload_hash.clone(),
                                            );
                                            verification_checks.push(
                                                "timer_notification_path_armed=true".to_string(),
                                            );
                                        }
                                    }
                                }
                                if command_scope {
                                    mark_execution_receipt(
                                        &mut agent_state.tool_execution_log,
                                        "execution",
                                    );
                                    verification_checks.push(receipt_marker("execution"));
                                    emit_execution_contract_receipt_event(
                                        service,
                                        session_id,
                                        pre_state_summary.step_index,
                                        &resolved_intent_id,
                                        "execution",
                                        "execution",
                                        true,
                                        "execution_invocation_completed=true",
                                        None,
                                        None,
                                        synthesized_payload_hash.clone(),
                                    );
                                }
                                verification_checks
                                    .push("capability_execution_phase=verification".to_string());
                                if command_scope {
                                    record_verification_receipts(
                                        &mut agent_state.tool_execution_log,
                                        &mut verification_checks,
                                        &tool,
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
                                        pre_state_summary.step_index,
                                        &resolved_intent_id,
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
                                        pre_state_summary.step_index,
                                        &resolved_intent_id,
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
                                    timestamp: SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap()
                                        .as_millis()
                                        as u64,
                                    trace_hash: None,
                                };
                                let _ = service
                                    .append_chat_to_scs(session_id, &tool_msg, block_height)
                                    .await?;
                            }
                        }

                        match &tool {
                            AgentTool::AgentComplete { result } => {
                                let missing_contract_markers =
                                    missing_execution_contract_markers(agent_state);
                                if !missing_contract_markers.is_empty() {
                                    let missing = missing_contract_markers.join(",");
                                    let contract_error =
                                        execution_contract_violation_error(&missing);
                                    success = false;
                                    error_msg = Some(contract_error.clone());
                                    history_entry = Some(contract_error.clone());
                                    action_output = Some(contract_error);
                                    agent_state.status = AgentStatus::Running;
                                    verification_checks
                                        .push("execution_contract_gate_blocked=true".to_string());
                                    verification_checks.push(format!(
                                        "execution_contract_missing_keys={}",
                                        missing
                                    ));
                                    emit_completion_gate_violation_events(
                                        service,
                                        session_id,
                                        pre_state_summary.step_index,
                                        &resolved_intent_id,
                                        &missing,
                                    );
                                } else {
                                    let completed_result = if is_system_clock_read_intent(
                                        agent_state.resolved_intent.as_ref(),
                                    ) {
                                        summarize_system_clock_or_plain_output(result)
                                            .unwrap_or_else(|| result.clone())
                                    } else {
                                        result.clone()
                                    };
                                    let completed_result = enrich_command_scope_summary(
                                        &completed_result,
                                        agent_state,
                                    );
                                    agent_state.status =
                                        AgentStatus::Completed(Some(completed_result.clone()));
                                    is_lifecycle_action = true;
                                    action_output = Some(completed_result.clone());
                                    if !completed_result.trim().is_empty() {
                                        terminal_chat_reply_output = Some(completed_result.clone());
                                        verification_checks
                                            .push("terminal_chat_reply_ready=true".to_string());
                                    }
                                    evaluate_and_crystallize(
                                        service,
                                        agent_state,
                                        session_id,
                                        &completed_result,
                                    )
                                    .await;
                                    emit_completion_gate_status_event(
                                        service,
                                        session_id,
                                        pre_state_summary.step_index,
                                        &resolved_intent_id,
                                        true,
                                        "agent_complete_contract_gate_passed",
                                    );
                                }
                            }
                            AgentTool::SysChangeDir { .. } => {
                                if success {
                                    if let Some(new_cwd) = history_entry.as_ref() {
                                        agent_state.working_directory = new_cwd.clone();
                                    }
                                }
                            }
                            AgentTool::ChatReply { message } => {
                                let missing_contract_markers =
                                    missing_execution_contract_markers(agent_state);
                                if !missing_contract_markers.is_empty() {
                                    let missing = missing_contract_markers.join(",");
                                    let contract_error =
                                        execution_contract_violation_error(&missing);
                                    success = false;
                                    error_msg = Some(contract_error.clone());
                                    history_entry = Some(contract_error.clone());
                                    action_output = Some(contract_error);
                                    agent_state.status = AgentStatus::Running;
                                    verification_checks
                                        .push("execution_contract_gate_blocked=true".to_string());
                                    verification_checks.push(format!(
                                        "execution_contract_missing_keys={}",
                                        missing
                                    ));
                                    emit_completion_gate_violation_events(
                                        service,
                                        session_id,
                                        pre_state_summary.step_index,
                                        &resolved_intent_id,
                                        &missing,
                                    );
                                } else {
                                    let message =
                                        enrich_command_scope_summary(message, agent_state);
                                    agent_state.status =
                                        AgentStatus::Completed(Some(message.clone()));
                                    is_lifecycle_action = true;
                                    action_output = Some(message.clone());
                                    terminal_chat_reply_output = Some(message.clone());
                                    evaluate_and_crystallize(
                                        service,
                                        agent_state,
                                        session_id,
                                        &message,
                                    )
                                    .await;
                                    emit_completion_gate_status_event(
                                        service,
                                        session_id,
                                        pre_state_summary.step_index,
                                        &resolved_intent_id,
                                        true,
                                        "chat_reply_contract_gate_passed",
                                    );
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
                                    agent_state.status =
                                        AgentStatus::Completed(Some(summary.clone()));
                                    is_lifecycle_action = true;
                                    action_output = Some(summary.clone());
                                    terminal_chat_reply_output = Some(summary);
                                    verification_checks
                                        .push("terminal_chat_reply_ready=true".to_string());
                                    agent_state.execution_queue.clear();
                                    agent_state.pending_search_completion = None;
                                    log::info!(
                                    "Auto-completed app-launch session {} after successful os__launch_app.",
                                    hex::encode(&session_id[..4])
                                );
                                }
                            }
                            AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. } => {
                                if is_command_probe_intent(agent_state.resolved_intent.as_ref()) {
                                    if let Some(raw) = history_entry.as_deref() {
                                        if let Some(summary) =
                                            summarize_command_probe_output(&tool, raw)
                                        {
                                            // Probe markers are deterministic completion signals even
                                            // when the underlying command exits non-zero.
                                            command_probe_completed = true;
                                            success = true;
                                            error_msg = None;
                                            agent_state.status =
                                                AgentStatus::Completed(Some(summary.clone()));
                                            is_lifecycle_action = true;
                                            action_output = Some(summary);
                                            agent_state.execution_queue.clear();
                                            agent_state.pending_search_completion = None;
                                        }
                                    }
                                } else if is_system_clock_read_intent(
                                    agent_state.resolved_intent.as_ref(),
                                ) {
                                    if let Some(summary) = history_entry
                                        .as_deref()
                                        .and_then(summarize_system_clock_or_plain_output)
                                    {
                                        let summary =
                                            enrich_command_scope_summary(&summary, agent_state);
                                        mark_execution_postcondition(
                                            &mut agent_state.tool_execution_log,
                                            CLOCK_TIMESTAMP_POSTCONDITION,
                                        );
                                        verification_checks.push(postcondition_marker(
                                            CLOCK_TIMESTAMP_POSTCONDITION,
                                        ));
                                        emit_execution_contract_receipt_event(
                                            service,
                                            session_id,
                                            pre_state_summary.step_index,
                                            &resolved_intent_id,
                                            "verification",
                                            CLOCK_TIMESTAMP_POSTCONDITION,
                                            true,
                                            "clock_timestamp_observed=true",
                                            None,
                                            None,
                                            synthesized_payload_hash.clone(),
                                        );
                                        success = true;
                                        error_msg = None;
                                        agent_state.status =
                                            AgentStatus::Completed(Some(summary.clone()));
                                        is_lifecycle_action = true;
                                        action_output = Some(summary.clone());
                                        terminal_chat_reply_output = Some(summary);
                                        agent_state.execution_queue.clear();
                                        agent_state.pending_search_completion = None;
                                    } else {
                                        let missing =
                                            postcondition_marker(CLOCK_TIMESTAMP_POSTCONDITION);
                                        let contract_error =
                                            execution_contract_violation_error(&missing);
                                        success = false;
                                        error_msg = Some(contract_error.clone());
                                        history_entry = Some(contract_error.clone());
                                        action_output = Some(contract_error);
                                        agent_state.status = AgentStatus::Running;
                                        verification_checks.push(
                                            "execution_contract_gate_blocked=true".to_string(),
                                        );
                                        verification_checks.push(format!(
                                            "execution_contract_missing_keys={}",
                                            missing
                                        ));
                                        emit_execution_contract_receipt_event(
                                            service,
                                            session_id,
                                            pre_state_summary.step_index,
                                            &resolved_intent_id,
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
                                    if let Some(summary) = duplicate_command_completion_summary(
                                        &tool,
                                        agent_state.command_history.back(),
                                    ) {
                                        let missing_contract_markers =
                                            missing_execution_contract_markers(agent_state);
                                        if missing_contract_markers.is_empty() {
                                            success = true;
                                            error_msg = None;
                                            agent_state.status =
                                                AgentStatus::Completed(Some(summary.clone()));
                                            is_lifecycle_action = true;
                                            action_output = Some(summary.clone());
                                            terminal_chat_reply_output = Some(summary);
                                            agent_state.execution_queue.clear();
                                            agent_state.pending_search_completion = None;
                                            verification_checks.push(
                                                "timer_schedule_terminalized=true".to_string(),
                                            );
                                            verification_checks
                                                .push("terminal_chat_reply_ready=true".to_string());
                                            emit_completion_gate_status_event(
                                                service,
                                                session_id,
                                                pre_state_summary.step_index,
                                                &resolved_intent_id,
                                                true,
                                                "command_scope_completion_gate_passed",
                                            );
                                        } else {
                                            let missing = missing_contract_markers.join(",");
                                            let contract_error =
                                                execution_contract_violation_error(&missing);
                                            success = false;
                                            error_msg = Some(contract_error.clone());
                                            history_entry = Some(contract_error.clone());
                                            action_output = Some(contract_error);
                                            verification_checks.push(
                                                "execution_contract_gate_blocked=true".to_string(),
                                            );
                                            verification_checks.push(format!(
                                                "execution_contract_missing_keys={}",
                                                missing
                                            ));
                                            emit_completion_gate_violation_events(
                                                service,
                                                session_id,
                                                pre_state_summary.step_index,
                                                &resolved_intent_id,
                                                &missing,
                                            );
                                        }
                                    }
                                }
                            }
                            AgentTool::MemorySearch { query } => {
                                let mut promoted_memory_search = false;
                                if success && should_use_web_research_path(agent_state) {
                                    if let Some(raw) = history_entry.as_deref() {
                                        if let Some(bundle) = parse_web_evidence_bundle(raw) {
                                            if bundle.tool == "web__search" {
                                                promoted_memory_search = true;
                                                current_tool_name = "web__search".to_string();
                                                verification_checks.push(
                                                    "memory_search_promoted_to_web_search=true"
                                                        .to_string(),
                                                );
                                                apply_pre_read_bundle(
                                                    service,
                                                    agent_state,
                                                    session_id,
                                                    pre_state_summary.step_index,
                                                    &bundle,
                                                    query,
                                                    &mut verification_checks,
                                                    &mut history_entry,
                                                    &mut action_output,
                                                    &mut terminal_chat_reply_output,
                                                    &mut is_lifecycle_action,
                                                )
                                                .await?;
                                            }
                                        }
                                    }
                                }

                                if !promoted_memory_search
                                    && success
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
                                    let queued = queue_web_search_bootstrap(
                                        agent_state,
                                        session_id,
                                        &bootstrap_query,
                                    )?;
                                    verification_checks
                                        .push("web_search_bootstrap_from_memory=true".to_string());
                                    let note = if queued {
                                        "No memory hits for this news query; queued deterministic web__search.".to_string()
                                    } else {
                                        "No memory hits for this news query; deterministic web__search was already queued."
                                            .to_string()
                                    };
                                    history_entry = Some(note.clone());
                                    action_output = Some(note);
                                    agent_state.status = AgentStatus::Running;
                                }
                            }
                            AgentTool::WebSearch { query, .. } => {
                                if success && should_use_web_research_path(agent_state) {
                                    if let Some(raw) = history_entry.as_deref() {
                                        if let Some(bundle) = parse_web_evidence_bundle(raw) {
                                            apply_pre_read_bundle(
                                                service,
                                                agent_state,
                                                session_id,
                                                pre_state_summary.step_index,
                                                &bundle,
                                                query,
                                                &mut verification_checks,
                                                &mut history_entry,
                                                &mut action_output,
                                                &mut terminal_chat_reply_output,
                                                &mut is_lifecycle_action,
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
                                    &mut success,
                                    &mut error_msg,
                                    &mut history_entry,
                                    &mut action_output,
                                    &mut terminal_chat_reply_output,
                                    &mut current_tool_name,
                                    &mut is_lifecycle_action,
                                    &mut verification_checks,
                                );
                            }
                            _ => {}
                        }

                        apply_web_research_followups(
                            agent_state,
                            success,
                            &current_tool_name,
                            session_id,
                            pre_state_summary.step_index,
                            &tool_args,
                            &mut history_entry,
                            &mut action_output,
                            &mut verification_checks,
                        )?;
                    }
                    Err(TransactionError::PendingApproval(h)) => {
                        let pending_approval = handle_pending_approval(PendingApprovalContext {
                            service,
                            state,
                            agent_state,
                            rules,
                            session_id,
                            block_height,
                            block_timestamp_ns,
                            final_visual_phash,
                            current_tool_name: &current_tool_name,
                            tool: &tool,
                            tool_call_result: &tool_call_result,
                            retry_intent_hash: retry_intent_hash.as_deref(),
                            intent_hash: intent_hash.as_str(),
                            approval_hash_hex: &h,
                            verification_checks: &mut verification_checks,
                        })
                        .await?;
                        policy_decision = pending_approval.policy_decision;
                        success = pending_approval.success;
                        error_msg = pending_approval.error_msg;
                        is_gated = pending_approval.is_gated;
                        is_lifecycle_action = pending_approval.is_lifecycle_action;
                    }
                    Err(e) => {
                        success = false;
                        let msg = e.to_string();
                        if msg.to_lowercase().contains("blocked by policy") {
                            policy_decision = "denied".to_string();
                        }
                        error_msg = Some(msg.clone());
                        if !req_hash_hex.is_empty() {
                            agent_state
                                .tool_execution_log
                                .insert(req_hash_hex.clone(), ToolCallStatus::Failed(msg));
                        }
                    }
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
