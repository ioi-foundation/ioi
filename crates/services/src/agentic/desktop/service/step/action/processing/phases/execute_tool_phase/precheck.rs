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

    true
}
