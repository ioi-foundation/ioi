// Path: crates/services/src/agentic/desktop/service/actions/resume/mod.rs

mod approvals;
mod execution;
mod flow;
mod focus;
mod hashing;
mod phases;
mod status;
mod visual;

use super::checks::requires_visual_integrity;
use super::evaluation::evaluate_and_crystallize;
use crate::agentic::desktop::execution::system::is_sudo_password_required_install_error;
use crate::agentic::desktop::keys::{get_state_key, pii, AGENT_POLICY_PREFIX};
use crate::agentic::desktop::service::step::action::command_contract::{
    append_command_history_entry, capability_route_label, command_arms_deferred_notification_path,
    command_history_entry, command_history_exit_code, enrich_command_scope_summary,
    execution_contract_violation_error, format_utc_rfc3339, is_cec_terminal_error,
    missing_execution_contract_markers, parse_sleep_seconds, record_provider_selection_receipts,
    record_timer_notification_contract_requirement, record_verification_receipts,
    render_command_preview, requires_timer_notification_contract,
    synthesize_allowlisted_timer_notification_tool, sys_exec_arms_timer_delay_backend,
    sys_exec_command_preview, target_utc_from_run_and_sleep, TIMER_NOTIFICATION_PATH_POSTCONDITION,
    TIMER_SLEEP_BACKEND_POSTCONDITION,
};
use crate::agentic::desktop::service::step::action::{
    canonical_intent_hash, canonical_retry_intent_hash, canonical_tool_identity,
    is_command_probe_intent, is_system_clock_read_intent, is_ui_capture_screenshot_intent,
    mark_action_fingerprint_executed, mark_execution_postcondition, mark_execution_receipt,
    postcondition_marker, receipt_marker, summarize_command_probe_output,
    summarize_system_clock_or_plain_output, summarize_system_clock_output,
};
use crate::agentic::desktop::service::step::anti_loop::{
    build_attempt_key, build_post_state_summary, build_state_summary, classify_failure,
    emit_routing_receipt, escalation_path_for_failure, extract_artifacts, latest_failure_class,
    lineage_pointer, mutation_receipt_pointer, policy_binding_hash, register_failure_attempt,
    requires_wait_for_clarification, retry_budget_remaining, should_block_retry_without_change,
    should_trip_retry_guard, tier_as_str, to_routing_failure_class, FailureClass,
    TierRoutingDecision,
};
use crate::agentic::desktop::service::step::helpers::{
    default_safe_policy, should_auto_complete_open_app_goal,
};
use crate::agentic::desktop::service::step::incident::{
    advance_incident_after_action_outcome, incident_receipt_fields, load_incident_state,
    mark_gate_denied, mark_incident_wait_for_user, should_enter_incident_recovery,
    start_or_continue_incident_recovery, IncidentDirective,
};
use crate::agentic::desktop::service::{DesktopAgentService, ServiceCallContext};
use crate::agentic::desktop::types::{AgentState, AgentStatus, CommandExecution};
use crate::agentic::desktop::utils::goto_trace_log;
use crate::agentic::rules::ActionRules;

use crate::agentic::desktop::middleware;

use hex;
use ioi_api::state::StateAccess;
use ioi_pii::resolve_expected_request_hash;
use ioi_types::app::agentic::{AgentTool, ComputerAction, IntentScopeProfile, PiiReviewRequest};
use ioi_types::app::{KernelEvent, RoutingReceiptEvent};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn clear_pending_resume_state(agent_state: &mut AgentState) {
    agent_state.pending_tool_jcs = None;
    agent_state.pending_tool_hash = None;
    agent_state.pending_visual_hash = None;
    agent_state.pending_tool_call = None;
    agent_state.pending_approval = None;
}

pub(super) fn restore_pending_resume_state(
    agent_state: &mut AgentState,
    tool_jcs: Vec<u8>,
    tool_hash: [u8; 32],
    pending_visual_hash: [u8; 32],
    action_json: String,
) {
    agent_state.pending_tool_jcs = Some(tool_jcs);
    agent_state.pending_tool_hash = Some(tool_hash);
    agent_state.pending_visual_hash = Some(pending_visual_hash);
    agent_state.pending_tool_call = Some(action_json);
    agent_state.pending_approval = None;
}

fn is_web_research_scope(agent_state: &AgentState) -> bool {
    agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| resolved.scope == IntentScopeProfile::WebResearch)
        .unwrap_or(false)
}

fn emit_terminal_completion_events(
    tx: &tokio::sync::broadcast::Sender<KernelEvent>,
    session_id: [u8; 32],
    step_index: u32,
    output: &str,
    agent_status: String,
) {
    let output_text = output.to_string();
    let status_text = agent_status;
    let _ = tx.send(KernelEvent::AgentActionResult {
        session_id,
        step_index,
        tool_name: "agent__complete".to_string(),
        output: output_text.clone(),
        agent_status: status_text.clone(),
    });
    let _ = tx.send(KernelEvent::AgentActionResult {
        session_id,
        step_index,
        tool_name: "chat__reply".to_string(),
        output: output_text,
        agent_status: status_text,
    });
}

fn extract_background_pid(stdout: &str) -> Option<String> {
    let marker_idx = stdout.find("PID:")?;
    let suffix = &stdout[marker_idx + "PID:".len()..];
    let pid: String = suffix
        .chars()
        .skip_while(|c| c.is_ascii_whitespace())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if pid.is_empty() {
        None
    } else {
        Some(pid)
    }
}

fn timer_completion_summary(
    tool: &AgentTool,
    history_entry: Option<&CommandExecution>,
) -> Option<String> {
    let (sleep_seconds, executed_command) = match tool {
        AgentTool::SysExec {
            command,
            args,
            detach,
            ..
        } => {
            if !*detach {
                return None;
            }
            let command_preview = render_command_preview(command, args);
            let sleep_seconds = parse_sleep_seconds(&command_preview)?;
            (sleep_seconds, command_preview)
        }
        _ => return None,
    };
    let entry = history_entry?;
    if entry.exit_code != 0 {
        return None;
    }
    let run_timestamp_utc = format_utc_rfc3339(entry.timestamp_ms)?;
    let target_utc = target_utc_from_run_and_sleep(entry.timestamp_ms, sleep_seconds)?;
    let mechanism = if let Some(pid) = extract_background_pid(&entry.stdout) {
        format!(
            "Detached sys__exec command '{}' launched as background process (PID: {}).",
            executed_command, pid
        )
    } else {
        format!(
            "Detached sys__exec command '{}' launched as background process.",
            executed_command
        )
    };
    Some(format!(
        "Timer scheduled.\nMechanism: {}\nRun timestamp (UTC): {}\nTarget UTC: {}",
        mechanism, run_timestamp_utc, target_utc
    ))
}

pub async fn resume_pending_action(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    block_height: u64,
    block_timestamp_ns: u64,
    call_context: ServiceCallContext<'_>,
) -> Result<(), TransactionError> {
    flow::resume_pending_action_flow(flow::ResumePendingActionFlowContext {
        service,
        state,
        agent_state,
        session_id,
        block_height,
        block_timestamp_ns,
        call_context,
    })
    .await
}
