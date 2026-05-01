use super::events::{emit_execution_contract_receipt_event, synthesized_payload_hash_for_tool};
use super::*;
use crate::agentic::runtime::service::tool_execution::command_contract::timer_payload_requires_allowlisted_scheduler;

pub(super) struct TimerContractContext<'a> {
    pub service: &'a RuntimeAgentService,
    pub agent_state: &'a mut AgentState,
    pub tool: AgentTool,
    pub command_scope: bool,
    pub req_hash_hex: &'a str,
    pub session_id: [u8; 32],
    pub step_index: u32,
    pub resolved_intent_id: &'a str,
    pub verification_checks: &'a mut Vec<String>,
    pub synthesized_payload_hash: Option<String>,
}

pub(super) struct TimerContractPreparation {
    pub tool: AgentTool,
    pub synthesized_payload_hash: Option<String>,
    pub should_execute_tool: bool,
    pub pre_execution_error: Option<String>,
}

pub(super) async fn restore_pending_visual_context(
    service: &RuntimeAgentService,
    agent_state: &AgentState,
) {
    let target_hash_opt = agent_state
        .pending_visual_hash
        .or(agent_state.last_screen_phash);
    if let Some(target_hash) = target_hash_opt {
        let _ = service.restore_visual_context(target_hash).await;
    }
}

pub(super) fn prepare_timer_contract(ctx: TimerContractContext<'_>) -> TimerContractPreparation {
    let TimerContractContext {
        service,
        agent_state,
        tool,
        command_scope,
        req_hash_hex,
        session_id,
        step_index,
        resolved_intent_id,
        verification_checks,
        synthesized_payload_hash,
    } = ctx;

    let mut tool = tool;
    let mut synthesized_payload_hash = synthesized_payload_hash;
    let mut should_execute_tool = true;
    let mut pre_execution_error = None;
    let is_sys_exec_tool = matches!(
        tool,
        AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
    );

    if command_scope && sys_exec_arms_timer_delay_backend(&tool) {
        record_timer_notification_contract_requirement(
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

    if timer_notification_required && timer_payload_requires_allowlisted_scheduler(&tool) {
        if let Some(rewritten_tool) = synthesize_allowlisted_timer_notification_tool(&tool) {
            let original_preview = sys_exec_command_preview(&tool).unwrap_or_default();
            tool = rewritten_tool;
            synthesized_payload_hash = synthesized_payload_hash_for_tool(&tool);
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
            missing_keys.push(success_condition_key(TIMER_SLEEP_BACKEND_SUCCESS_CONDITION));
        }
        if !notification_path_armed {
            missing_keys.push(success_condition_key(
                TIMER_NOTIFICATION_PATH_SUCCESS_CONDITION,
            ));
        }
        for marker in &missing_keys {
            verification_checks.push(format!("execution_contract_missing_keys={}", marker));
        }

        let missing_csv = missing_keys.join(",");
        let synth_error = format!(
            "ERROR_CLASS=SynthesisFailed stage=provider_selection cause=timer_payload_contract_lint_failed missing_keys={} guidance=Use an allowlisted deferred notification payload (for example: systemd-run --on-active=<seconds> notify-send ...).",
            missing_csv
        );
        pre_execution_error = Some(synth_error);
        verification_checks.push("cec_pre_execution_payload_lint_failed=true".to_string());
        verification_checks.push("execution_contract_gate_blocked=true".to_string());
        emit_execution_contract_receipt_event(
            service,
            session_id,
            step_index,
            resolved_intent_id,
            "provider_selection",
            "provider_selection",
            false,
            "timer_payload_contract_lint_failed",
            None,
            None,
            synthesized_payload_hash.clone(),
        );
        if !timer_delay_backend_armed {
            emit_execution_contract_receipt_event(
                service,
                session_id,
                step_index,
                resolved_intent_id,
                "execution",
                TIMER_SLEEP_BACKEND_SUCCESS_CONDITION,
                false,
                "timer_sleep_backend=missing_pre_execution",
                None,
                None,
                synthesized_payload_hash.clone(),
            );
        }
        if !notification_path_armed {
            emit_execution_contract_receipt_event(
                service,
                session_id,
                step_index,
                resolved_intent_id,
                "execution",
                TIMER_NOTIFICATION_PATH_SUCCESS_CONDITION,
                false,
                "timer_notification_path_armed=false_pre_execution",
                None,
                None,
                synthesized_payload_hash.clone(),
            );
        }
        if !req_hash_hex.is_empty() {
            agent_state.tool_execution_log.insert(
                req_hash_hex.to_string(),
                ToolCallStatus::Failed("timer_payload_contract_lint_failed".to_string()),
            );
        }
        should_execute_tool = false;
    }

    TimerContractPreparation {
        tool,
        synthesized_payload_hash,
        should_execute_tool,
        pre_execution_error,
    }
}
