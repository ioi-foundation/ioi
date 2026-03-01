use super::events::{emit_completion_gate_status_event, emit_completion_gate_violation_events};
use super::*;

pub(super) struct DuplicateExecutionContext<'a> {
    pub service: &'a DesktopAgentService,
    pub agent_state: &'a mut AgentState,
    pub rules: &'a ActionRules,
    pub tool: &'a AgentTool,
    pub matching_command_history_entry: Option<crate::agentic::desktop::types::CommandExecution>,
    pub command_scope: bool,
    pub action_fingerprint: &'a str,
    pub session_id: [u8; 32],
    pub step_index: u32,
    pub resolved_intent_id: &'a str,
    pub verification_checks: &'a mut Vec<String>,
}

pub(super) struct DuplicateExecutionOutcome {
    pub success: bool,
    pub error_msg: Option<String>,
    pub history_entry: Option<String>,
    pub action_output: Option<String>,
    pub terminal_chat_reply_output: Option<String>,
    pub is_lifecycle_action: bool,
}

pub(super) fn handle_duplicate_command_execution(
    ctx: DuplicateExecutionContext<'_>,
) -> DuplicateExecutionOutcome {
    let DuplicateExecutionContext {
        service,
        agent_state,
        rules,
        tool,
        matching_command_history_entry,
        command_scope,
        action_fingerprint,
        session_id,
        step_index,
        resolved_intent_id,
        verification_checks,
    } = ctx;

    let mut success = false;
    let mut error_msg = None;
    let history_entry: Option<String>;
    let action_output: Option<String>;
    let mut terminal_chat_reply_output = None;
    let mut is_lifecycle_action = false;
    let matching_command_history_entry = matching_command_history_entry.as_ref();
    let is_command_tool = matches!(
        tool,
        AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
    );

    if let Some(summary) =
        duplicate_command_completion_summary(tool, matching_command_history_entry)
    {
        let missing_contract_markers =
            missing_execution_contract_markers_with_rules(agent_state, rules);
        if missing_contract_markers.is_empty() {
            success = true;
            history_entry = Some(summary.clone());
            action_output = Some(summary.clone());
            terminal_chat_reply_output = Some(summary.clone());
            is_lifecycle_action = true;
            agent_state.status = AgentStatus::Completed(Some(summary));
            agent_state.execution_queue.clear();
            agent_state.pending_search_completion = None;
            verification_checks.push("duplicate_action_fingerprint_terminalized=true".to_string());
            verification_checks.push("terminal_chat_reply_ready=true".to_string());
            emit_completion_gate_status_event(
                service,
                session_id,
                step_index,
                resolved_intent_id,
                true,
                "duplicate_command_completion",
            );
        } else {
            let missing = missing_contract_markers.join(",");
            let contract_error = execution_contract_violation_error(&missing);
            error_msg = Some(contract_error.clone());
            history_entry = Some(contract_error.clone());
            action_output = Some(contract_error);
            agent_state.status = AgentStatus::Running;
            verification_checks.push("execution_contract_gate_blocked=true".to_string());
            verification_checks.push(format!("execution_contract_missing_keys={}", missing));
            verification_checks.push("duplicate_action_fingerprint_blocked=true".to_string());
            emit_completion_gate_violation_events(
                service,
                session_id,
                step_index,
                resolved_intent_id,
                &missing,
            );
        }
    } else if let Some(summary) =
        duplicate_command_cached_success_summary(tool, matching_command_history_entry)
    {
        let missing_contract_markers =
            missing_execution_contract_markers_with_rules(agent_state, rules);
        if missing_contract_markers.is_empty() {
            success = true;
            history_entry = Some(summary.clone());
            if command_scope {
                let completion = duplicate_command_cached_completion_summary(
                    tool,
                    matching_command_history_entry,
                )
                .unwrap_or_else(|| summary.clone());
                let completion = enrich_command_scope_summary(&completion, agent_state);
                action_output = Some(completion.clone());
                terminal_chat_reply_output = Some(completion.clone());
                agent_state.status = AgentStatus::Completed(Some(completion));
                is_lifecycle_action = true;
                agent_state.execution_queue.clear();
                agent_state.pending_search_completion = None;
                verification_checks
                    .push("duplicate_action_fingerprint_terminalized=true".to_string());
                verification_checks.push("terminal_chat_reply_ready=true".to_string());
            } else {
                action_output = Some(summary);
                agent_state.status = AgentStatus::Running;
            }
            verification_checks.push("duplicate_action_fingerprint_cached=true".to_string());
            emit_completion_gate_status_event(
                service,
                session_id,
                step_index,
                resolved_intent_id,
                true,
                "duplicate_command_cached_completion",
            );
        } else {
            let missing = missing_contract_markers.join(",");
            let contract_error = execution_contract_violation_error(&missing);
            error_msg = Some(contract_error.clone());
            history_entry = Some(contract_error.clone());
            action_output = Some(contract_error);
            agent_state.status = AgentStatus::Running;
            verification_checks.push("execution_contract_gate_blocked=true".to_string());
            verification_checks.push(format!("execution_contract_missing_keys={}", missing));
            verification_checks.push("duplicate_action_fingerprint_blocked=true".to_string());
            emit_completion_gate_violation_events(
                service,
                session_id,
                step_index,
                resolved_intent_id,
                &missing,
            );
        }
    } else if is_command_tool {
        let summary = duplicate_command_execution_summary(tool);
        let duplicate_error = format!("ERROR_CLASS=NoEffectAfterAction {}", summary);
        error_msg = Some(duplicate_error.clone());
        history_entry = Some(summary);
        action_output = Some(duplicate_error);
        agent_state.status = AgentStatus::Running;
        verification_checks.push("duplicate_action_fingerprint_blocked=true".to_string());
    } else {
        let tool_name = canonical_tool_identity(tool).0;
        let summary = format!(
            "Skipped immediate replay of '{}' because the same action fingerprint was already executed on the previous step. This fingerprint is now cooled down at the current step; choose a different action or finish with the gathered evidence.",
            tool_name
        );
        mark_action_fingerprint_executed_at_step(
            &mut agent_state.tool_execution_log,
            action_fingerprint,
            step_index,
            "duplicate_skip",
        );
        let noop_duplicate_allowed = is_non_command_duplicate_noop_tool(&tool_name);
        if noop_duplicate_allowed {
            success = true;
            error_msg = None;
            action_output = Some(summary.clone());
            verification_checks
                .push("duplicate_action_fingerprint_non_command_noop=true".to_string());
        } else {
            let duplicate_error = format!("ERROR_CLASS=NoEffectAfterAction {}", summary);
            success = false;
            error_msg = Some(duplicate_error.clone());
            action_output = Some(duplicate_error);
        }
        history_entry = Some(summary.clone());
        agent_state.status = AgentStatus::Running;
        verification_checks
            .push("duplicate_action_fingerprint_non_command_skipped=true".to_string());
        verification_checks
            .push("duplicate_action_fingerprint_non_command_step_advanced=true".to_string());
    }
    verification_checks.push(format!(
        "duplicate_action_fingerprint={}",
        action_fingerprint
    ));
    verification_checks.push(format!(
        "duplicate_action_fingerprint_non_terminal={}",
        !success
    ));

    DuplicateExecutionOutcome {
        success,
        error_msg,
        history_entry,
        action_output,
        terminal_chat_reply_output,
        is_lifecycle_action,
    }
}

fn is_non_command_duplicate_noop_tool(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "wallet_network__mail_read_latest" | "wallet_mail_read_latest" | "mail__read_latest"
    )
}
