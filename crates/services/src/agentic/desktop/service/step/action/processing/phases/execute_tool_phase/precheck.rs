use super::events::emit_execution_contract_receipt_event;
use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn run_execution_prechecks(
    service: &DesktopAgentService,
    agent_state: &mut AgentState,
    tool: &AgentTool,
    current_tool_name: &str,
    command_scope: bool,
    req_hash_hex: &str,
    session_id: [u8; 32],
    step_index: u32,
    resolved_intent_id: &str,
    route_label: Option<&'static str>,
    synthesized_payload_hash: Option<String>,
    verification_checks: &mut Vec<String>,
    policy_decision: &mut String,
    success: &mut bool,
    error_msg: &mut Option<String>,
    history_entry: &mut Option<String>,
    action_output: &mut Option<String>,
) -> bool {
    let tool_allowed =
        is_tool_allowed_for_resolution(agent_state.resolved_intent.as_ref(), current_tool_name);
    if !tool_allowed {
        *policy_decision = "denied".to_string();
        *success = false;
        *error_msg = Some(format!(
            "ERROR_CLASS=PolicyBlocked Tool '{}' blocked by global intent scope.",
            current_tool_name
        ));
        if !req_hash_hex.is_empty() {
            agent_state.tool_execution_log.insert(
                req_hash_hex.to_string(),
                ToolCallStatus::Failed("intent_scope_block".to_string()),
            );
        }
        return false;
    }

    if command_scope
        && is_system_clock_read_intent(agent_state.resolved_intent.as_ref())
        && matches!(
            tool,
            AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
        )
        && !sys_exec_satisfies_clock_read_contract(tool)
    {
        *policy_decision = "denied".to_string();
        *success = false;
        let missing = receipt_marker("provider_selection");
        let contract_error = execution_contract_violation_error(&missing);
        *error_msg = Some(contract_error.clone());
        *history_entry = Some(contract_error.clone());
        *action_output = Some(contract_error);
        verification_checks.push("clock_payload_contract_violation=true".to_string());
        verification_checks.push("execution_contract_gate_blocked=true".to_string());
        verification_checks.push(format!("execution_contract_missing_keys={}", missing));
        emit_execution_contract_receipt_event(
            service,
            session_id,
            step_index,
            resolved_intent_id,
            "provider_selection",
            "provider_selection",
            false,
            "clock_payload_lint_failed",
            None,
            route_label.map(str::to_string),
            synthesized_payload_hash,
        );
        if !req_hash_hex.is_empty() {
            agent_state.tool_execution_log.insert(
                req_hash_hex.to_string(),
                ToolCallStatus::Failed("clock_payload_contract_violation".to_string()),
            );
        }
        return false;
    }

    if command_scope
        && matches!(
            tool,
            AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
        )
    {
        if let Some(home_mismatch) = sys_exec_foreign_absolute_home_path(tool) {
            let timestamp_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let host_receipt = runtime_host_environment_receipt(timestamp_ms);
            let lint_error = format!(
                "ERROR_CLASS=SynthesisFailed stage=provider_selection cause=home_path_contract_lint_failed runtime_home_dir={} runtime_home_owner={} payload_home_dir={} payload_home_owner={}",
                home_mismatch.runtime_home_directory.as_str(),
                home_mismatch.runtime_home_owner.as_str(),
                home_mismatch.payload_home_directory.as_str(),
                home_mismatch.payload_home_owner.as_str()
            );
            let evidence_material = format!(
                "lint=home_path_owner_mismatch;observed_value={};probe_source={};timestamp_ms={};satisfied={};runtime_home_owner={};payload_home_owner={};payload_home_dir={}",
                host_receipt.observed_value.as_str(),
                host_receipt.probe_source.as_str(),
                host_receipt.timestamp_ms,
                host_receipt.satisfied,
                home_mismatch.runtime_home_owner.as_str(),
                home_mismatch.payload_home_owner.as_str(),
                home_mismatch.payload_home_directory.as_str()
            );

            *policy_decision = "denied".to_string();
            *success = false;
            *error_msg = Some(lint_error.clone());
            *history_entry = Some(lint_error.clone());
            *action_output = Some(lint_error.clone());

            verification_checks.push("cec_pre_execution_payload_lint_failed=true".to_string());
            verification_checks.push("execution_contract_gate_blocked=true".to_string());
            verification_checks
                .push("execution_contract_failed_stage=provider_selection".to_string());
            verification_checks.push(
                "execution_contract_failure_cause=home_path_contract_lint_failed".to_string(),
            );
            verification_checks.push(format!(
                "host_home_dir={}",
                home_mismatch.runtime_home_directory.as_str()
            ));
            verification_checks.push(format!(
                "payload_home_dir={}",
                home_mismatch.payload_home_directory.as_str()
            ));
            verification_checks.push(format!(
                "host_home_owner={}",
                home_mismatch.runtime_home_owner.as_str()
            ));
            verification_checks.push(format!(
                "payload_home_owner={}",
                home_mismatch.payload_home_owner.as_str()
            ));
            verification_checks.push(format!(
                "host_discovery_probe_source={}",
                host_receipt.probe_source.as_str()
            ));
            verification_checks.push(format!(
                "host_discovery_timestamp_ms={}",
                host_receipt.timestamp_ms
            ));
            verification_checks.push(format!(
                "host_discovery_satisfied={}",
                host_receipt.satisfied
            ));
            emit_execution_contract_receipt_event(
                service,
                session_id,
                step_index,
                resolved_intent_id,
                "provider_selection",
                "provider_selection",
                false,
                &evidence_material,
                None,
                route_label.map(str::to_string),
                synthesized_payload_hash,
            );
            if !req_hash_hex.is_empty() {
                agent_state.tool_execution_log.insert(
                    req_hash_hex.to_string(),
                    ToolCallStatus::Failed("home_path_contract_lint_failed".to_string()),
                );
            }
            return false;
        }
    }

    true
}
