use super::events::{
    emit_execution_contract_receipt_event, emit_execution_contract_receipt_event_with_observation,
};
use super::tool_outcome::{apply_tool_outcome_and_followups, ToolOutcomeContext};
use super::*;
use crate::agentic::desktop::connectors::connector_postcondition_verifier_bindings;

fn record_browser_marker_receipt(
    service: &DesktopAgentService,
    agent_state: &mut AgentState,
    verification_checks: &mut Vec<String>,
    session_id: [u8; 32],
    step_index: u32,
    resolved_intent_id: &str,
    synthesized_payload_hash: Option<String>,
    key: &str,
    evidence: &str,
) {
    mark_execution_receipt_with_value(
        &mut agent_state.tool_execution_log,
        key,
        evidence.to_string(),
    );
    verification_checks.push(receipt_marker(key));
    emit_execution_contract_receipt_event(
        service,
        session_id,
        step_index,
        resolved_intent_id,
        "execution",
        key,
        true,
        evidence,
        None,
        None,
        synthesized_payload_hash,
    );
}

fn record_browser_marker_postcondition(
    service: &DesktopAgentService,
    agent_state: &mut AgentState,
    verification_checks: &mut Vec<String>,
    session_id: [u8; 32],
    step_index: u32,
    resolved_intent_id: &str,
    synthesized_payload_hash: Option<String>,
    key: &str,
    evidence: &str,
) {
    mark_execution_postcondition(&mut agent_state.tool_execution_log, key);
    verification_checks.push(postcondition_marker(key));
    emit_execution_contract_receipt_event(
        service,
        session_id,
        step_index,
        resolved_intent_id,
        "verification",
        key,
        true,
        evidence,
        None,
        None,
        synthesized_payload_hash,
    );
}

fn parse_find_text_found(history_entry: Option<&str>) -> Option<bool> {
    let raw = history_entry?;
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    value
        .get("result")
        .and_then(|result| result.get("found"))
        .and_then(|found| found.as_bool())
}

fn parse_wait_condition_met(history_entry: Option<&str>) -> Option<bool> {
    let raw = history_entry?;
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    value
        .get("wait")
        .and_then(|wait| wait.get("met"))
        .and_then(|met| met.as_bool())
}

fn compact_browser_receipt_evidence(history_entry: Option<&str>) -> String {
    let raw = history_entry
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .unwrap_or("browser_action_success=true");

    let normalized = serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|value| serde_jcs::to_vec(&value).ok())
        .unwrap_or_else(|| raw.as_bytes().to_vec());

    sha256(&normalized)
        .map(|digest| format!("sha256:{}", hex::encode(digest.as_ref())))
        .unwrap_or_else(|_| "sha256:unavailable".to_string())
}

fn record_browser_success_markers(
    service: &DesktopAgentService,
    agent_state: &mut AgentState,
    tool: &AgentTool,
    history_entry: Option<&str>,
    trace_visual_hash: Option<[u8; 32]>,
    verification_checks: &mut Vec<String>,
    session_id: [u8; 32],
    step_index: u32,
    resolved_intent_id: &str,
    synthesized_payload_hash: Option<String>,
) {
    let evidence = compact_browser_receipt_evidence(history_entry);

    match tool {
        AgentTool::BrowserUploadFile { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_upload_file",
                evidence.as_str(),
            );
            record_browser_marker_postcondition(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_file_attached",
                "browser_file_attached=true",
            );
        }
        AgentTool::BrowserSelectDropdown { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_dropdown_selected",
                evidence.as_str(),
            );
            record_browser_marker_postcondition(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_dropdown_selection_applied",
                "browser_dropdown_selection_applied=true",
            );
        }
        AgentTool::BrowserGoBack { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_history_back",
                evidence.as_str(),
            );
            record_browser_marker_postcondition(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_navigation_changed",
                "browser_navigation_changed=true",
            );
        }
        AgentTool::BrowserWait { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_wait",
                evidence.as_str(),
            );
            record_browser_marker_postcondition(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_wait_completed",
                "browser_wait_completed=true",
            );
            if parse_wait_condition_met(history_entry) == Some(true) {
                record_browser_marker_postcondition(
                    service,
                    agent_state,
                    verification_checks,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    None,
                    "browser_wait_condition_met",
                    "browser_wait_condition_met=true",
                );
            }
        }
        AgentTool::BrowserTabSwitch { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_tab_switch",
                evidence.as_str(),
            );
            record_browser_marker_postcondition(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_active_tab_selected",
                "browser_active_tab_selected=true",
            );
        }
        AgentTool::BrowserTabClose { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_tab_close",
                evidence.as_str(),
            );
            record_browser_marker_postcondition(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_tab_closed",
                "browser_tab_closed=true",
            );
        }
        AgentTool::BrowserFindText { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_find_text",
                evidence.as_str(),
            );
            if parse_find_text_found(history_entry) == Some(true) {
                record_browser_marker_postcondition(
                    service,
                    agent_state,
                    verification_checks,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    synthesized_payload_hash,
                    "browser_text_found",
                    "browser_text_found=true",
                );
            }
        }
        AgentTool::BrowserScreenshot { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash.clone(),
                "browser_screenshot",
                evidence.as_str(),
            );
            if trace_visual_hash.is_some() {
                record_browser_marker_postcondition(
                    service,
                    agent_state,
                    verification_checks,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    synthesized_payload_hash,
                    "browser_visual_observation",
                    "browser_visual_observation=true",
                );
            }
        }
        AgentTool::BrowserDropdownOptions { .. } => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_dropdown_options",
                evidence.as_str(),
            );
        }
        AgentTool::BrowserTabList {} => {
            record_browser_marker_receipt(
                service,
                agent_state,
                verification_checks,
                session_id,
                step_index,
                resolved_intent_id,
                synthesized_payload_hash,
                "browser_tab_list",
                evidence.as_str(),
            );
        }
        _ => {}
    }
}

async fn verify_non_command_postconditions(
    service: &DesktopAgentService,
    agent_state: &mut AgentState,
    current_tool_name: &str,
    tool_args: &serde_json::Value,
    history_entry: Option<&str>,
    session_id: [u8; 32],
    step_index: u32,
    resolved_intent_id: &str,
    synthesized_payload_hash: Option<String>,
    verification_checks: &mut Vec<String>,
) -> Result<(), String> {
    let Some(resolved) = agent_state.resolved_intent.as_ref() else {
        return Ok(());
    };
    if resolved.required_postconditions.is_empty() {
        return Ok(());
    }
    let connector_id = resolved
        .provider_selection
        .as_ref()
        .and_then(|selection| selection.selected_connector_id.as_deref())
        .ok_or_else(|| {
            "ERROR_CLASS=GroundingMissing Postcondition verification requires a selected connector."
                .to_string()
        })?;
    let verifier = connector_postcondition_verifier_bindings()
        .into_iter()
        .find(|binding| binding.connector_id == connector_id)
        .ok_or_else(|| {
            format!(
                "ERROR_CLASS=VerificationMissing No postcondition verifier is registered for connector '{}'.",
                connector_id
            )
        })?;
    let history_entry = history_entry.ok_or_else(|| {
        "ERROR_CLASS=VerificationMissing Postcondition verification requires structured tool output."
            .to_string()
    })?;
    let Some(proof) = (verifier.verify)(agent_state, current_tool_name, tool_args, history_entry)
        .await
        .map_err(|error| format!("ERROR_CLASS=PostconditionFailed {}", error))?
    else {
        return Err(
            "ERROR_CLASS=VerificationMissing Connector verifier returned no postcondition proof."
                .to_string(),
        );
    };

    for evidence in proof.evidence {
        mark_execution_postcondition(&mut agent_state.tool_execution_log, &evidence.key);
        verification_checks.push(postcondition_marker(&evidence.key));
        emit_execution_contract_receipt_event_with_observation(
            service,
            session_id,
            step_index,
            resolved_intent_id,
            "verification",
            &evidence.key,
            true,
            &evidence.evidence,
            Some("connector_verifier"),
            evidence.observed_value.as_deref(),
            evidence.evidence_type.as_deref(),
            None,
            evidence.provider_id,
            synthesized_payload_hash.clone(),
        );
    }

    Ok(())
}

pub(super) struct ExecutionSuccessContext<'a, 's> {
    pub service: &'a DesktopAgentService,
    pub state: &'s mut dyn StateAccess,
    pub agent_state: &'a mut AgentState,
    pub rules: &'a ActionRules,
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

    if command_scope && *success && matches!(tool, AgentTool::SysInstallPackage { .. }) {
        verification_checks.push("capability_execution_evidence=tool_output".to_string());
        mark_execution_postcondition(&mut agent_state.tool_execution_log, "execution_artifact");
        verification_checks.push(postcondition_marker("execution_artifact"));
        let (package, manager) = match tool {
            AgentTool::SysInstallPackage { package, manager } => {
                (package.trim(), manager.as_deref().unwrap_or("auto"))
            }
            _ => ("unknown", "auto"),
        };
        let artifact_evidence = format!(
            "install_package={};install_manager={};tool_output_chars={}",
            package,
            manager,
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
        agent_state.pending_request_nonce = None;
    }

    if *success {
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

        if is_command_execution_provider_tool(tool) {
            if command_scope && requires_timer_notification_contract(agent_state) {
                if matches!(
                    tool,
                    AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
                ) {
                    if sys_exec_arms_timer_delay_backend(tool) {
                        mark_execution_postcondition(
                            &mut agent_state.tool_execution_log,
                            TIMER_SLEEP_BACKEND_POSTCONDITION,
                        );
                        verification_checks
                            .push(postcondition_marker(TIMER_SLEEP_BACKEND_POSTCONDITION));
                        let delay_seconds =
                            sys_exec_timer_delay_seconds(tool).map(|value| value.to_string());
                        emit_execution_contract_receipt_event_with_observation(
                            service,
                            session_id,
                            step_index,
                            resolved_intent_id,
                            "execution",
                            TIMER_SLEEP_BACKEND_POSTCONDITION,
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
                            mark_execution_postcondition(
                                &mut agent_state.tool_execution_log,
                                TIMER_NOTIFICATION_PATH_POSTCONDITION,
                            );
                            verification_checks
                                .push(postcondition_marker(TIMER_NOTIFICATION_PATH_POSTCONDITION));
                            emit_execution_contract_receipt_event_with_observation(
                                service,
                                session_id,
                                step_index,
                                resolved_intent_id,
                                "execution",
                                TIMER_NOTIFICATION_PATH_POSTCONDITION,
                                true,
                                "timer_notification_path_armed=true",
                                Some("tool_payload"),
                                Some("deferred_notification"),
                                Some("strategy"),
                                None,
                                None,
                                synthesized_payload_hash.clone(),
                            );
                            mark_execution_receipt(
                                &mut agent_state.tool_execution_log,
                                "notification_strategy",
                            );
                            verification_checks.push(receipt_marker("notification_strategy"));
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
                    if matches!(
                        tool,
                        AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
                    ) {
                        agent_state.command_history.back()
                    } else {
                        None
                    },
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
        if !command_scope {
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

            if let Err(error) = verify_non_command_postconditions(
                service,
                agent_state,
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

            mark_execution_receipt(&mut agent_state.tool_execution_log, "verification");
            verification_checks.push(receipt_marker("verification"));
            emit_execution_contract_receipt_event(
                service,
                session_id,
                step_index,
                resolved_intent_id,
                "verification",
                "verification",
                true,
                "verification_receipt_recorded=true",
                None,
                None,
                synthesized_payload_hash.clone(),
            );
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
        rules,
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
