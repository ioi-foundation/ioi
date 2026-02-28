use super::super::*;
use ioi_api::vm::drivers::os::OsDriver;
use std::sync::Arc;

pub(crate) struct ExecutionTimerPhaseContext<'a, 's> {
    pub service: &'a DesktopAgentService,
    pub state: &'s mut dyn StateAccess,
    pub agent_state: &'a mut AgentState,
    pub os_driver: &'a Arc<dyn OsDriver>,
    pub tool: AgentTool,
    pub rules: &'a ActionRules,
    pub session_id: [u8; 32],
    pub tool_hash: [u8; 32],
    pub pending_vhash: [u8; 32],
    pub scoped_exception_override_hash: Option<[u8; 32]>,
    pub precheck_error: Option<String>,
    pub log_visual_hash: [u8; 32],
    pub command_scope: bool,
    pub step_index: u32,
    pub block_height: u64,
    pub call_context: ServiceCallContext<'a>,
    pub verification_checks: &'a mut Vec<String>,
    pub policy_decision: &'a mut String,
}

pub(crate) struct ExecutionTimerPhaseData {
    pub tool: AgentTool,
    pub success: bool,
    pub out: Option<String>,
    pub err: Option<String>,
    pub log_visual_hash: [u8; 32],
}

pub(crate) async fn run_execution_timer_phase(
    ctx: ExecutionTimerPhaseContext<'_, '_>,
) -> ExecutionTimerPhaseData {
    let ExecutionTimerPhaseContext {
        service,
        state,
        agent_state,
        os_driver,
        mut tool,
        rules,
        session_id,
        tool_hash,
        pending_vhash,
        scoped_exception_override_hash,
        precheck_error,
        mut log_visual_hash,
        command_scope,
        step_index,
        block_height,
        call_context,
        verification_checks,
        policy_decision,
    } = ctx;

    let has_precheck_error = precheck_error.is_some();
    let is_sys_exec_tool = matches!(
        tool,
        AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
    );
    let lowercase_rename_payload_candidate =
        is_sys_exec_tool && sys_exec_targets_lowercase_rename_payload(&tool);
    if command_scope && sys_exec_arms_timer_delay_backend(&tool) {
        record_timer_notification_contract_requirement(
            &mut agent_state.tool_execution_log,
            verification_checks,
        );
    }
    if command_scope
        && lowercase_rename_payload_candidate
        && lowercase_rename_contract_target(agent_state, &tool).is_some()
    {
        record_lowercase_rename_contract_requirement(
            &mut agent_state.tool_execution_log,
            verification_checks,
        );
    }
    let timer_notification_required =
        command_scope && requires_timer_notification_contract(agent_state) && is_sys_exec_tool;
    let mut timer_delay_backend_armed = sys_exec_arms_timer_delay_backend(&tool);
    let mut notification_path_armed = sys_exec_command_preview(&tool)
        .as_deref()
        .map(command_arms_deferred_notification_path)
        .unwrap_or(false);
    let mut skip_execution_due_to_contract = false;
    let mut pre_execution_contract_error: Option<String> = None;

    if timer_notification_required && timer_delay_backend_armed && !notification_path_armed {
        if let Some(rewritten_tool) = synthesize_allowlisted_timer_notification_tool(&tool) {
            let original_preview = sys_exec_command_preview(&tool).unwrap_or_default();
            tool = rewritten_tool;
            let rewritten_preview = sys_exec_command_preview(&tool).unwrap_or_default();
            timer_delay_backend_armed = sys_exec_arms_timer_delay_backend(&tool);
            notification_path_armed = sys_exec_command_preview(&tool)
                .as_deref()
                .map(command_arms_deferred_notification_path)
                .unwrap_or(false);
            verification_checks
                .push("timer_notification_payload_auto_synthesized=true".to_string());
            verification_checks.push(format!(
                "timer_notification_payload_original={}",
                original_preview
            ));
            verification_checks.push(format!(
                "timer_notification_payload_synthesized={}",
                rewritten_preview
            ));
        }
    }

    if timer_notification_required {
        verification_checks.push("timer_delay_backend_required=true".to_string());
        verification_checks.push(format!(
            "timer_delay_backend_detected={}",
            timer_delay_backend_armed
        ));
        verification_checks.push("timer_notification_path_required=true".to_string());
        verification_checks.push(format!(
            "timer_notification_path_detected={}",
            notification_path_armed
        ));
    }
    if timer_notification_required && (!timer_delay_backend_armed || !notification_path_armed) {
        let mut missing_keys = Vec::<String>::new();
        if !timer_delay_backend_armed {
            missing_keys.push(postcondition_marker(TIMER_SLEEP_BACKEND_POSTCONDITION));
        }
        if !notification_path_armed {
            missing_keys.push(postcondition_marker(TIMER_NOTIFICATION_PATH_POSTCONDITION));
        }
        for marker in &missing_keys {
            verification_checks.push(format!("execution_contract_missing_keys={}", marker));
        }
        let missing_csv = missing_keys.join(",");
        verification_checks.push("cec_pre_execution_payload_lint_failed=true".to_string());
        verification_checks.push("execution_contract_gate_blocked=true".to_string());
        pre_execution_contract_error = Some(format!(
            "ERROR_CLASS=SynthesisFailed stage=provider_selection cause=timer_payload_contract_lint_failed missing_keys={} guidance=Use an allowlisted deferred notification payload (for example: systemd-run --on-active=<seconds> notify-send ...).",
            missing_csv
        ));
        skip_execution_due_to_contract = true;
    }

    let lowercase_rename_required = command_scope
        && requires_lowercase_rename_contract(agent_state)
        && is_sys_exec_tool
        && lowercase_rename_payload_candidate;
    if lowercase_rename_required && !skip_execution_due_to_contract {
        verification_checks.push("lowercase_rename_contract_required=true".to_string());
        if let Some(rewritten_tool) =
            synthesize_allowlisted_lowercase_rename_tool(agent_state, &tool)
        {
            let original_preview = sys_exec_command_preview(&tool).unwrap_or_default();
            tool = rewritten_tool;
            let rewritten_preview = sys_exec_command_preview(&tool).unwrap_or_default();
            verification_checks.push("lowercase_rename_payload_auto_synthesized=true".to_string());
            verification_checks.push(format!(
                "lowercase_rename_payload_original={}",
                original_preview
            ));
            verification_checks.push(format!(
                "lowercase_rename_payload_synthesized={}",
                rewritten_preview
            ));
        }

        let has_postcheck_payload = sys_exec_payload_contains(&tool, "LOWERCASE_RENAME_POSTCHECK");
        verification_checks.push(format!(
            "lowercase_rename_postcheck_payload_detected={}",
            has_postcheck_payload
        ));
        if !has_postcheck_payload {
            let missing_key = postcondition_marker(LOWERCASE_RENAME_POSTCONDITION);
            verification_checks.push(format!("execution_contract_missing_keys={}", missing_key));
            verification_checks.push("cec_pre_execution_payload_lint_failed=true".to_string());
            verification_checks.push("execution_contract_gate_blocked=true".to_string());
            pre_execution_contract_error = Some(format!(
                "ERROR_CLASS=SynthesisFailed stage=provider_selection cause=lowercase_rename_payload_contract_lint_failed missing_keys={} guidance=Use a files-only lowercase rename payload that emits LOWERCASE_RENAME_POSTCHECK with uppercase_remaining.",
                missing_key
            ));
            skip_execution_due_to_contract = true;
        }
    }

    let (success, out, err, persisted_visual_hash) = if skip_execution_due_to_contract {
        let error = pre_execution_contract_error
            .unwrap_or_else(|| "ERROR_CLASS=SynthesisFailed".to_string());
        (false, Some(error.clone()), Some(error), None)
    } else {
        let exec = execution::execute(
            service,
            state,
            agent_state,
            os_driver,
            &tool,
            rules,
            session_id,
            tool_hash,
            pending_vhash,
            scoped_exception_override_hash,
            has_precheck_error,
            precheck_error,
            step_index,
            block_height,
            call_context,
        )
        .await;
        (exec.success, exec.out, exec.err, exec.visual_hash)
    };
    if let Some(visual_hash) = persisted_visual_hash {
        log_visual_hash = visual_hash;
        verification_checks.push(format!(
            "visual_observation_checksum={}",
            hex::encode(visual_hash)
        ));
    }
    if is_sys_exec_tool {
        let mut command_history_seen = false;
        if let Some(raw) = out.as_deref() {
            if let Some(entry) = command_history_entry(raw) {
                command_history_seen = true;
                append_command_history_entry(&mut agent_state.command_history, entry);
                if command_scope {
                    mark_execution_postcondition(
                        &mut agent_state.tool_execution_log,
                        "execution_artifact",
                    );
                    verification_checks.push(postcondition_marker("execution_artifact"));
                }
            }
            if let Some(exit_code) = command_history_exit_code(raw) {
                command_history_seen = true;
                verification_checks
                    .push("capability_execution_evidence=command_history".to_string());
                verification_checks
                    .push(format!("capability_execution_last_exit_code={}", exit_code));
            }
        }
        if !command_history_seen {
            verification_checks.push("capability_execution_evidence=tool_output".to_string());
        }
        if success {
            if command_scope && requires_lowercase_rename_contract(agent_state) {
                let history_postcheck = agent_state
                    .command_history
                    .back()
                    .and_then(command_history_lowercase_rename_postcheck);
                let transcript_postcheck = if history_postcheck.is_none() {
                    out.as_deref()
                        .and_then(parse_lowercase_rename_postcheck_receipt)
                } else {
                    None
                };
                let discovery_postcheck =
                    if history_postcheck.is_none() && transcript_postcheck.is_none() {
                        lowercase_rename_contract_target(agent_state, &tool).and_then(|target| {
                            match discover_lowercase_rename_postcheck(&target.target_dir) {
                                Ok(receipt) => Some(receipt),
                                Err(error) => {
                                    verification_checks.push(format!(
                                        "lowercase_rename_postcheck_discovery_error={}",
                                        error
                                    ));
                                    None
                                }
                            }
                        })
                    } else {
                        None
                    };
                let (postcheck, postcheck_source) = if let Some(receipt) = history_postcheck {
                    (Some(receipt), "command_history")
                } else if let Some(receipt) = transcript_postcheck {
                    (Some(receipt), "tool_output")
                } else if let Some(receipt) = discovery_postcheck {
                    (Some(receipt), "filesystem_discovery")
                } else {
                    (None, "none")
                };
                verification_checks.push(format!(
                    "lowercase_rename_postcheck_seen={}",
                    postcheck.is_some()
                ));
                verification_checks.push(format!(
                    "lowercase_rename_postcheck_source={}",
                    postcheck_source
                ));
                if let Some(receipt) = postcheck {
                    verification_checks.push(format!(
                        "lowercase_rename_postcheck_total_files={}",
                        receipt.total_files
                    ));
                    verification_checks.push(format!(
                        "lowercase_rename_postcheck_uppercase_remaining={}",
                        receipt.uppercase_remaining
                    ));
                    verification_checks.push(format!(
                        "lowercase_rename_postcheck_target_dir={}",
                        receipt.target_dir
                    ));
                    if receipt.uppercase_remaining == 0 {
                        mark_execution_postcondition(
                            &mut agent_state.tool_execution_log,
                            LOWERCASE_RENAME_POSTCONDITION,
                        );
                        verification_checks
                            .push(postcondition_marker(LOWERCASE_RENAME_POSTCONDITION));
                    }
                }
            }
            if command_scope && requires_timer_notification_contract(agent_state) {
                if sys_exec_arms_timer_delay_backend(&tool) {
                    mark_execution_postcondition(
                        &mut agent_state.tool_execution_log,
                        TIMER_SLEEP_BACKEND_POSTCONDITION,
                    );
                    verification_checks
                        .push(postcondition_marker(TIMER_SLEEP_BACKEND_POSTCONDITION));
                }
                if let Some(command_preview) = sys_exec_command_preview(&tool) {
                    if command_arms_deferred_notification_path(&command_preview) {
                        mark_execution_postcondition(
                            &mut agent_state.tool_execution_log,
                            TIMER_NOTIFICATION_PATH_POSTCONDITION,
                        );
                        verification_checks
                            .push(postcondition_marker(TIMER_NOTIFICATION_PATH_POSTCONDITION));
                        mark_execution_receipt(
                            &mut agent_state.tool_execution_log,
                            "notification_strategy",
                        );
                        verification_checks.push(receipt_marker("notification_strategy"));
                        verification_checks.push("timer_notification_path_armed=true".to_string());
                    }
                }
            }
            if command_scope {
                mark_execution_receipt(&mut agent_state.tool_execution_log, "execution");
                verification_checks.push(receipt_marker("execution"));
            }
            verification_checks.push("capability_execution_phase=verification".to_string());
            if command_scope {
                record_verification_receipts(
                    &mut agent_state.tool_execution_log,
                    verification_checks,
                    &tool,
                    agent_state.command_history.back(),
                );
            }
        }
    }

    if let Some(err_msg) = err.as_deref() {
        if err_msg.to_lowercase().contains("blocked by policy") {
            *policy_decision = "denied".to_string();
        }
    }

    ExecutionTimerPhaseData {
        tool,
        success,
        out,
        err,
        log_visual_hash,
    }
}
