// Path: crates/services/src/agentic/desktop/service/actions/resume/mod.rs

mod approvals;
mod execution;
mod focus;
mod hashing;
mod status;
mod visual;

use super::checks::requires_visual_integrity;
use super::evaluation::evaluate_and_crystallize;
use crate::agentic::desktop::execution::system::is_sudo_password_required_install_error;
use crate::agentic::desktop::keys::{get_state_key, pii, AGENT_POLICY_PREFIX};
use crate::agentic::desktop::service::step::action::{
    canonical_intent_hash, canonical_retry_intent_hash, canonical_tool_identity,
    has_execution_postcondition, has_execution_receipt, is_command_probe_intent,
    is_system_clock_read_intent, mark_action_fingerprint_executed, mark_execution_postcondition,
    mark_execution_receipt, postcondition_marker, receipt_marker, summarize_command_probe_output,
    summarize_system_clock_output,
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
use crate::agentic::desktop::types::{
    AgentState, AgentStatus, CommandExecution, MAX_COMMAND_HISTORY,
};
use crate::agentic::desktop::utils::goto_trace_log;
use crate::agentic::rules::ActionRules;

use crate::agentic::desktop::middleware;

use hex;
use ioi_api::state::StateAccess;
use ioi_pii::resolve_expected_request_hash;
use ioi_types::app::agentic::{AgentTool, IntentScopeProfile, PiiReviewRequest};
use ioi_types::app::{KernelEvent, RoutingReceiptEvent};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use std::time::{SystemTime, UNIX_EPOCH};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const COMMAND_HISTORY_PREFIX: &str = "COMMAND_HISTORY:";
const TIMER_SLEEP_BACKEND_POSTCONDITION: &str = "timer_sleep_backend";
const TIMER_NOTIFICATION_PATH_POSTCONDITION: &str = "notification_path_armed";

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

fn capability_route_label(tool_name: &str) -> Option<&'static str> {
    if tool_name.starts_with("os__") || tool_name.starts_with("browser__") {
        return Some("native_integration");
    }
    if tool_name == "sys__install_package" {
        return Some("enablement_request");
    }
    if tool_name == "sys__exec" || tool_name == "sys__exec_session" {
        return Some("script_backend");
    }
    None
}

const TARGET_UTC_MARKER: &str = "Target UTC:";
const RUN_TIMESTAMP_UTC_MARKER: &str = "Run timestamp (UTC):";
const COMMAND_SCOPE_REQUIRED_RECEIPTS: [&str; 3] =
    ["provider_selection", "execution", "verification"];
const COMMAND_SCOPE_REQUIRED_POSTCONDITIONS: [&str; 1] = ["execution_artifact"];

fn execution_contract_violation_error(missing_keys: &str) -> String {
    format!(
        "ERROR_CLASS=NoEffectAfterAction Execution contract unmet. Select a different action or verify required markers. missing_keys={}",
        missing_keys
    )
}

fn command_history_exit_code(output: &str) -> Option<i64> {
    command_history_payload(output)?
        .get("exit_code")
        .and_then(|value| value.as_i64())
}

fn command_history_payload(output: &str) -> Option<serde_json::Value> {
    let marker_idx = output.find(COMMAND_HISTORY_PREFIX)?;
    let suffix = &output[marker_idx + COMMAND_HISTORY_PREFIX.len()..];
    let payload = suffix.lines().next().unwrap_or_default().trim();
    if payload.is_empty() {
        return None;
    }
    serde_json::from_str::<serde_json::Value>(payload).ok()
}

fn command_history_entry(output: &str) -> Option<CommandExecution> {
    let marker_idx = output.find(COMMAND_HISTORY_PREFIX)?;
    let suffix = &output[marker_idx + COMMAND_HISTORY_PREFIX.len()..];
    let payload = suffix.lines().next().unwrap_or_default().trim();
    if payload.is_empty() {
        return None;
    }
    serde_json::from_str::<CommandExecution>(payload).ok()
}

fn append_command_history_entry(
    history: &mut std::collections::VecDeque<CommandExecution>,
    entry: CommandExecution,
) {
    history.push_back(entry);
    while history.len() > MAX_COMMAND_HISTORY {
        let _ = history.pop_front();
    }
}

fn format_utc_rfc3339(timestamp_ms: u64) -> Option<String> {
    let seconds = i64::try_from(timestamp_ms / 1_000).ok()?;
    let milliseconds = i64::try_from(timestamp_ms % 1_000).ok()?;
    let timestamp = OffsetDateTime::from_unix_timestamp(seconds).ok()?
        + time::Duration::milliseconds(milliseconds);
    timestamp.format(&Rfc3339).ok()
}

fn parse_utc_rfc3339(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value.trim(), &Rfc3339).ok()
}

fn extract_structured_field(summary: &str, marker: &str) -> Option<String> {
    for line in summary.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(marker) {
            let token = rest.trim().trim_end_matches('.');
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }
    None
}

fn upsert_structured_field(summary: &str, marker: &str, value: &str) -> String {
    let replacement_line = format!("{} {}", marker, value);
    let mut replaced = false;
    let mut lines = Vec::<String>::new();
    for line in summary.lines() {
        if line.trim().starts_with(marker) {
            lines.push(replacement_line.clone());
            replaced = true;
        } else if let Some(marker_idx) = line.find(marker) {
            let prefix = line[..marker_idx].trim_end();
            if !prefix.is_empty() {
                lines.push(prefix.to_string());
            }
            lines.push(replacement_line.clone());
            replaced = true;
        } else {
            lines.push(line.to_string());
        }
    }
    if !replaced {
        lines.push(replacement_line);
    }
    lines.join("\n")
}

fn parse_sleep_seconds(command: &str) -> Option<i64> {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    for (index, token) in tokens.iter().enumerate() {
        if normalize_shell_token(token) != "sleep" {
            continue;
        }
        if let Some(seconds) = tokens
            .get(index + 1)
            .and_then(|value| parse_positive_shell_integer(value))
        {
            return Some(seconds);
        }
    }
    None
}

fn normalize_shell_token(token: &str) -> String {
    token
        .trim_matches(|ch: char| {
            matches!(
                ch,
                '\'' | '"' | '`' | '(' | ')' | '[' | ']' | '{' | '}' | ';' | ',' | '&' | '|'
            )
        })
        .to_ascii_lowercase()
}

fn parse_positive_shell_integer(token: &str) -> Option<i64> {
    let digits = token.trim_matches(|ch: char| !ch.is_ascii_digit());
    if digits.is_empty() || !digits.chars().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    digits.parse::<i64>().ok().filter(|seconds| *seconds > 0)
}

fn requires_timer_notification_contract(agent_state: &AgentState) -> bool {
    let goal_lc = agent_state.goal.to_ascii_lowercase();
    goal_lc.contains("timer")
        || goal_lc.contains("countdown")
        || goal_lc.contains("alarm")
        || goal_lc.contains("remind me in")
        || goal_lc.contains("wake me in")
}

fn render_command_preview(command: &str, args: &[String]) -> String {
    let command = command.trim();
    if args.is_empty() {
        command.to_string()
    } else {
        format!("{} {}", command, args.join(" "))
    }
}

fn sys_exec_command_preview(tool: &AgentTool) -> Option<String> {
    match tool {
        AgentTool::SysExec { command, args, .. } => Some(render_command_preview(command, args)),
        AgentTool::SysExecSession { command, args, .. } => {
            Some(render_command_preview(command, args))
        }
        _ => None,
    }
}

fn command_arms_notification_path(command_preview: &str) -> bool {
    let command_lc = command_preview.to_ascii_lowercase();
    const NOTIFICATION_MARKERS: [&str; 10] = [
        "notify-send",
        "paplay",
        "pw-play",
        "aplay",
        "canberra-gtk-play",
        "zenity --notification",
        "kdialog --passivepopup",
        "spd-say",
        "terminal-notifier",
        "osascript",
    ];
    NOTIFICATION_MARKERS
        .iter()
        .any(|marker| command_lc.contains(marker))
}

fn command_arms_deferred_notification_path(command_preview: &str) -> bool {
    command_arms_notification_path(command_preview)
        && command_arms_timer_delay_backend(command_preview)
}

fn command_arms_timer_delay_backend(command_preview: &str) -> bool {
    let command_lc = command_preview.to_ascii_lowercase();
    parse_sleep_seconds(command_preview).is_some()
        || (command_lc.contains("systemd-run") && command_lc.contains("--on-active"))
        || command_lc.starts_with("at ")
        || command_lc.contains(" at now")
}

fn sys_exec_arms_timer_delay_backend(tool: &AgentTool) -> bool {
    sys_exec_command_preview(tool)
        .as_deref()
        .map(command_arms_timer_delay_backend)
        .unwrap_or(false)
}

fn latest_timer_backend_history_entry(agent_state: &AgentState) -> Option<&CommandExecution> {
    agent_state
        .command_history
        .iter()
        .rev()
        .find(|entry| parse_sleep_seconds(&entry.command).is_some())
}

fn derived_target_utc_from_history(agent_state: &AgentState) -> Option<String> {
    let entry = latest_timer_backend_history_entry(agent_state)?;
    let sleep_seconds = parse_sleep_seconds(&entry.command)?;
    let run_timestamp = parse_utc_rfc3339(&format_utc_rfc3339(entry.timestamp_ms)?)?;
    (run_timestamp + time::Duration::seconds(sleep_seconds))
        .format(&Rfc3339)
        .ok()
}

fn missing_execution_contract_markers(agent_state: &AgentState) -> Vec<String> {
    let command_scope = agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| resolved.scope == IntentScopeProfile::CommandExecution)
        .unwrap_or(false);
    if !command_scope {
        return Vec::new();
    }

    let mut missing = Vec::<String>::new();
    if !has_execution_receipt(&agent_state.tool_execution_log, "host_discovery") {
        missing.push(receipt_marker("host_discovery"));
    }
    for receipt in COMMAND_SCOPE_REQUIRED_RECEIPTS {
        if !has_execution_receipt(&agent_state.tool_execution_log, receipt) {
            missing.push(receipt_marker(receipt));
        }
    }
    for postcondition in COMMAND_SCOPE_REQUIRED_POSTCONDITIONS {
        if !has_execution_postcondition(&agent_state.tool_execution_log, postcondition) {
            missing.push(postcondition_marker(postcondition));
        }
    }
    if requires_timer_notification_contract(agent_state) {
        if !has_execution_postcondition(
            &agent_state.tool_execution_log,
            TIMER_SLEEP_BACKEND_POSTCONDITION,
        ) {
            missing.push(postcondition_marker(TIMER_SLEEP_BACKEND_POSTCONDITION));
        }
        if has_execution_postcondition(
            &agent_state.tool_execution_log,
            TIMER_SLEEP_BACKEND_POSTCONDITION,
        ) && !has_execution_postcondition(
            &agent_state.tool_execution_log,
            TIMER_NOTIFICATION_PATH_POSTCONDITION,
        ) {
            missing.push(postcondition_marker(TIMER_NOTIFICATION_PATH_POSTCONDITION));
        }
    }
    missing
}

fn enrich_command_scope_summary(summary: &str, agent_state: &AgentState) -> String {
    let command_scope = agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| resolved.scope == IntentScopeProfile::CommandExecution)
        .unwrap_or(false);
    if !command_scope {
        return summary.to_string();
    }

    let run_timestamp_utc = latest_timer_backend_history_entry(agent_state)
        .or_else(|| agent_state.command_history.back())
        .and_then(|entry| format_utc_rfc3339(entry.timestamp_ms));
    let Some(run_timestamp_utc) = run_timestamp_utc else {
        return summary.to_string();
    };
    let mut enriched = summary.to_string();
    let run_timestamp = parse_utc_rfc3339(&run_timestamp_utc);
    let target_timestamp = extract_structured_field(&enriched, TARGET_UTC_MARKER)
        .as_deref()
        .and_then(parse_utc_rfc3339);
    if target_timestamp
        .zip(run_timestamp)
        .map(|(target, run)| target < run)
        .unwrap_or(true)
    {
        if let Some(derived_target_utc) = derived_target_utc_from_history(agent_state) {
            enriched = upsert_structured_field(&enriched, TARGET_UTC_MARKER, &derived_target_utc);
        }
    }
    if extract_structured_field(&enriched, RUN_TIMESTAMP_UTC_MARKER).is_none() {
        enriched = upsert_structured_field(&enriched, RUN_TIMESTAMP_UTC_MARKER, &run_timestamp_utc);
    }
    enriched
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
    let pre_state_summary = build_state_summary(agent_state);
    let routing_decision = TierRoutingDecision {
        tier: agent_state.current_tier,
        reason_code: "resume_preserve_tier",
        source_failure: latest_failure_class(agent_state),
    };
    let mut policy_decision = "approved".to_string();
    let mut failure_class: Option<FailureClass> = None;
    let mut stop_condition_hit = false;
    let mut escalation_path: Option<String> = None;
    let mut remediation_queued = false;
    let mut verification_checks = Vec::new();
    let mut awaiting_sudo_password = false;
    let mut awaiting_clarification = false;

    // 1. Load Canonical Request Bytes
    let tool_jcs = agent_state
        .pending_tool_jcs
        .as_ref()
        .ok_or(TransactionError::Invalid("Missing pending_tool_jcs".into()))?
        .clone();

    let tool_hash = agent_state
        .pending_tool_hash
        .ok_or(TransactionError::Invalid(
            "Missing pending_tool_hash".into(),
        ))?;

    // 2. Deserialize Tool FIRST
    let tool: AgentTool = serde_json::from_slice(&tool_jcs)
        .map_err(|e| TransactionError::Serialization(format!("Corrupt pending tool: {}", e)))?;
    let (tool_name, tool_args) = canonical_tool_identity(&tool);
    let action_json = serde_json::to_string(&tool).unwrap_or_else(|_| "{}".to_string());
    let intent_hash = canonical_intent_hash(
        &tool_name,
        &tool_args,
        routing_decision.tier,
        pre_state_summary.step_index,
        env!("CARGO_PKG_VERSION"),
    );
    let retry_intent_hash = canonical_retry_intent_hash(
        &tool_name,
        &tool_args,
        routing_decision.tier,
        env!("CARGO_PKG_VERSION"),
    );
    let command_scope = agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| resolved.scope == IntentScopeProfile::CommandExecution)
        .unwrap_or(false);
    if let Some(route_label) = capability_route_label(&tool_name) {
        verification_checks.push(format!("capability_route_selected={}", route_label));
        if command_scope {
            mark_execution_receipt(&mut agent_state.tool_execution_log, "provider_selection");
            verification_checks.push(receipt_marker("provider_selection"));
        }
    }
    if matches!(
        &tool,
        AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
    ) {
        if agent_state.command_history.is_empty() {
            verification_checks.push("capability_execution_phase=discovery".to_string());
            if command_scope {
                mark_execution_receipt(&mut agent_state.tool_execution_log, "host_discovery");
                verification_checks.push(receipt_marker("host_discovery"));
            }
        }
        verification_checks.push("capability_execution_phase=execution".to_string());
    }

    let policy_key = [AGENT_POLICY_PREFIX, session_id.as_slice()].concat();
    let mut rules: ActionRules = state
        .get(&policy_key)?
        .and_then(|b| codec::from_bytes_canonical(&b).ok())
        .unwrap_or_else(default_safe_policy);
    let block_timestamp_ms = block_timestamp_ns / 1_000_000;
    let block_timestamp_secs = block_timestamp_ns / 1_000_000_000;
    let incident_state = load_incident_state(state, &session_id)?;
    let pending_gate_hash = incident_state
        .as_ref()
        .and_then(|incident| incident.pending_gate.as_ref())
        .and_then(|pending| hashing::parse_hash_hex(&pending.request_hash));
    let expected_request_hash = resolve_expected_request_hash(pending_gate_hash, tool_hash);
    let request_key = pii::review::request(&expected_request_hash);
    let pii_request: Option<PiiReviewRequest> = state
        .get(&request_key)?
        .and_then(|bytes| codec::from_bytes_canonical(&bytes).ok());

    // 3. Validate approval token before executing anything.
    // Runtime secret retries for sys__install_package are allowed without approval token.
    let approval = approvals::validate_and_apply(
        service,
        state,
        agent_state,
        session_id,
        &tool,
        tool_hash,
        expected_request_hash,
        pii_request.as_ref(),
        block_timestamp_ms,
        block_timestamp_secs,
        &mut rules,
        &mut verification_checks,
    )
    .await?;
    let scoped_exception_override_hash = approval.scoped_exception_override_hash;
    let explicit_pii_deny = approval.explicit_pii_deny;

    let os_driver = service
        .os_driver
        .clone()
        .ok_or(TransactionError::Invalid("OS driver missing".into()))?;

    // 4. Visual Guard: Context Drift Check (typed, recoverable).
    let pending_vhash = agent_state
        .pending_visual_hash
        .ok_or(TransactionError::Invalid(
            "Missing pending_visual_hash".into(),
        ))?;

    let (mut precheck_error, log_visual_hash) = visual::run_visual_prechecks(
        service,
        &os_driver,
        &tool,
        pending_vhash,
        &mut verification_checks,
    )
    .await;

    if explicit_pii_deny {
        mark_gate_denied(state, session_id)?;
        let deny_error = if pii_request.is_some() {
            "PII review denied by approver. Step failed closed.".to_string()
        } else {
            "Approval denied by approver. Step failed closed.".to_string()
        };
        let key = get_state_key(&session_id);
        goto_trace_log(
            agent_state,
            state,
            &key,
            session_id,
            pending_vhash,
            "[Resumed Action]".to_string(),
            deny_error.clone(),
            false,
            Some(deny_error.clone()),
            "resumed_action".to_string(),
            service.event_sender.clone(),
            agent_state.active_skill_hash,
        )?;

        let deny_msg = ioi_types::app::agentic::ChatMessage {
            role: "system".to_string(),
            content: if pii_request.is_some() {
                "System: PII review denied. Current step failed closed.".to_string()
            } else {
                "System: Approval denied. Current step failed closed.".to_string()
            },
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            trace_hash: None,
        };
        service
            .append_chat_to_scs(session_id, &deny_msg, block_height)
            .await?;

        agent_state.pending_tool_jcs = None;
        agent_state.pending_tool_hash = None;
        agent_state.pending_visual_hash = None;
        agent_state.pending_tool_call = None;
        agent_state.pending_approval = None;
        agent_state.status = AgentStatus::Running;
        agent_state.step_count = agent_state.step_count.saturating_add(1);
        agent_state.consecutive_failures = agent_state.consecutive_failures.saturating_add(1);
        state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;
        return Ok(());
    }

    // Focus Guard: approval UX can steal focus to Autopilot shell.
    // For resumed spatial actions, force-focus the target surface before clicking.
    if precheck_error.is_none() && requires_visual_integrity(&tool) {
        if let Some(err) = focus::ensure_target_focused_for_resume(&os_driver, agent_state).await {
            precheck_error = Some(err);
        }
    }

    // Execute with SNAPSHOT MAP unless prechecks failed.
    let has_precheck_error = precheck_error.is_some();
    let timer_notification_required = command_scope
        && requires_timer_notification_contract(agent_state)
        && matches!(
            tool,
            AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
        );
    let timer_delay_backend_armed = sys_exec_arms_timer_delay_backend(&tool);
    let notification_path_armed = sys_exec_command_preview(&tool)
        .as_deref()
        .map(command_arms_deferred_notification_path)
        .unwrap_or(false);
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
    if timer_notification_required && !timer_delay_backend_armed {
        verification_checks.push(format!(
            "execution_contract_missing_keys={}",
            postcondition_marker(TIMER_SLEEP_BACKEND_POSTCONDITION)
        ));
    }
    if timer_notification_required && !notification_path_armed {
        verification_checks.push(format!(
            "execution_contract_missing_keys={}",
            postcondition_marker(TIMER_NOTIFICATION_PATH_POSTCONDITION)
        ));
    }
    let exec = execution::execute(
        service,
        state,
        agent_state,
        &os_driver,
        &tool,
        &rules,
        session_id,
        tool_hash,
        pending_vhash,
        scoped_exception_override_hash,
        has_precheck_error,
        precheck_error,
        pre_state_summary.step_index,
        block_height,
        call_context,
    )
    .await;
    let (mut success, mut out, mut err) = (exec.success, exec.out, exec.err);
    if matches!(
        &tool,
        AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
    ) {
        if let Some(raw) = out.as_deref() {
            if let Some(entry) = command_history_entry(raw) {
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
                verification_checks
                    .push("capability_execution_evidence=command_history".to_string());
                verification_checks
                    .push(format!("capability_execution_last_exit_code={}", exit_code));
            }
        }
        if success {
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
                mark_execution_receipt(&mut agent_state.tool_execution_log, "verification");
                verification_checks.push(receipt_marker("verification"));
            }
        }
    }

    if let Some(err_msg) = err.as_deref() {
        if err_msg.to_lowercase().contains("blocked by policy") {
            policy_decision = "denied".to_string();
        }
    }
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
        // Drop any queued remediation actions while awaiting credentials.
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
        content: content.clone(), // Clone for content check
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
        mark_action_fingerprint_executed(
            &mut agent_state.tool_execution_log,
            &retry_intent_hash,
            "success",
        );
    }

    if awaiting_sudo_password {
        agent_state.pending_tool_jcs = Some(tool_jcs.clone());
        agent_state.pending_tool_hash = Some(tool_hash);
        agent_state.pending_visual_hash = Some(pending_vhash);
        agent_state.pending_tool_call = Some(action_json.clone());
        agent_state.pending_approval = None;
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
                agent_status: "Paused".to_string(),
            });
        }
        verification_checks.push("awaiting_sudo_password=true".to_string());
    } else if awaiting_clarification {
        agent_state.pending_tool_jcs = None;
        agent_state.pending_tool_hash = None;
        agent_state.pending_visual_hash = None;
        agent_state.pending_tool_call = None;
        agent_state.pending_approval = None;
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
        // Clear pending state
        agent_state.pending_tool_jcs = None;
        agent_state.pending_tool_hash = None;
        agent_state.pending_visual_hash = None;
        agent_state.pending_tool_call = None;
        agent_state.pending_approval = None;
    }

    // [FIX] Reflexive Agent State Update (Ported from process.rs)
    // Check if the resumed action output a completion signal
    let mut reflexive_completion = false;
    if success {
        if content.contains("agent_complete") || content.contains("agent__complete") {
            if let Some(json_start) = content.find('{') {
                if let Some(json_end) = content.rfind('}') {
                    if json_end > json_start {
                        let potential_json = &content[json_start..=json_end];
                        if let Ok(detected_tool) = middleware::normalize_tool_call(potential_json) {
                            if let AgentTool::AgentComplete { result } = detected_tool {
                                log::info!("Reflexive Agent (Resume): Detected completion signal in tool output.");
                                let missing_contract_markers =
                                    missing_execution_contract_markers(agent_state);
                                if !missing_contract_markers.is_empty() {
                                    let missing = missing_contract_markers.join(",");
                                    let contract_error =
                                        execution_contract_violation_error(&missing);
                                    success = false;
                                    err = Some(contract_error.clone());
                                    out = Some(contract_error);
                                    verification_checks
                                        .push("execution_contract_gate_blocked=true".to_string());
                                    verification_checks.push(format!(
                                        "execution_contract_missing_keys={}",
                                        missing
                                    ));
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
                                    let completed_result = enrich_command_scope_summary(
                                        &completed_result,
                                        agent_state,
                                    );
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
                                    }

                                    evaluate_and_crystallize(
                                        service,
                                        agent_state,
                                        session_id,
                                        &completed_result,
                                    )
                                    .await;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if !reflexive_completion && !awaiting_sudo_password && !awaiting_clarification {
        match &tool {
            AgentTool::AgentComplete { result } => {
                let missing_contract_markers = missing_execution_contract_markers(agent_state);
                if !missing_contract_markers.is_empty() {
                    let missing = missing_contract_markers.join(",");
                    let contract_error = execution_contract_violation_error(&missing);
                    success = false;
                    err = Some(contract_error.clone());
                    out = Some(contract_error);
                    verification_checks.push("execution_contract_gate_blocked=true".to_string());
                    verification_checks
                        .push(format!("execution_contract_missing_keys={}", missing));
                    agent_state.status = AgentStatus::Running;
                } else {
                    let completed_result =
                        if is_system_clock_read_intent(agent_state.resolved_intent.as_ref()) {
                            summarize_system_clock_output(result).unwrap_or_else(|| result.clone())
                        } else {
                            result.clone()
                        };
                    let completed_result =
                        enrich_command_scope_summary(&completed_result, agent_state);
                    agent_state.status = AgentStatus::Completed(Some(completed_result.clone()));
                    evaluate_and_crystallize(service, agent_state, session_id, &completed_result)
                        .await;

                    if let Some(tx) = &service.event_sender {
                        emit_terminal_completion_events(
                            tx,
                            session_id,
                            agent_state.step_count,
                            &completed_result,
                            status::status_str(&agent_state.status),
                        );
                    }
                }
            }
            AgentTool::ChatReply { message } => {
                let missing_contract_markers = missing_execution_contract_markers(agent_state);
                if !missing_contract_markers.is_empty() {
                    let missing = missing_contract_markers.join(",");
                    let contract_error = execution_contract_violation_error(&missing);
                    success = false;
                    err = Some(contract_error.clone());
                    out = Some(contract_error);
                    verification_checks.push("execution_contract_gate_blocked=true".to_string());
                    verification_checks
                        .push(format!("execution_contract_missing_keys={}", missing));
                    agent_state.status = AgentStatus::Running;
                } else {
                    let message = enrich_command_scope_summary(message, agent_state);
                    agent_state.status = AgentStatus::Completed(Some(message.clone()));
                    evaluate_and_crystallize(service, agent_state, session_id, &message).await;

                    if let Some(tx) = &service.event_sender {
                        let _ = tx.send(KernelEvent::AgentActionResult {
                            session_id: session_id,
                            step_index: agent_state.step_count,
                            tool_name: "chat__reply".to_string(),
                            output: message.clone(),
                            // [NEW] Authoritative Status
                            agent_status: status::status_str(&agent_state.status),
                        });
                    }
                }
            }
            AgentTool::SysChangeDir { .. } => {
                if success {
                    agent_state.working_directory = content.clone();
                }
                agent_state.status = AgentStatus::Running;
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
                    evaluate_and_crystallize(service, agent_state, session_id, &summary).await;
                    if let Some(tx) = &service.event_sender {
                        emit_terminal_completion_events(
                            tx,
                            session_id,
                            agent_state.step_count,
                            &summary,
                            status::status_str(&agent_state.status),
                        );
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
                        evaluate_and_crystallize(service, agent_state, session_id, &summary).await;
                        if let Some(tx) = &service.event_sender {
                            emit_terminal_completion_events(
                                tx,
                                session_id,
                                agent_state.step_count,
                                &summary,
                                status::status_str(&agent_state.status),
                            );
                        }
                    } else {
                        agent_state.status = AgentStatus::Running;
                    }
                } else if success
                    && is_system_clock_read_intent(agent_state.resolved_intent.as_ref())
                {
                    let summary = out
                        .as_deref()
                        .and_then(summarize_system_clock_output)
                        .unwrap_or_else(|| "Current UTC time: <unavailable>".to_string());
                    agent_state.status = AgentStatus::Completed(Some(summary.clone()));
                    agent_state.execution_queue.clear();
                    evaluate_and_crystallize(service, agent_state, session_id, &summary).await;
                    if let Some(tx) = &service.event_sender {
                        emit_terminal_completion_events(
                            tx,
                            session_id,
                            agent_state.step_count,
                            &summary,
                            status::status_str(&agent_state.status),
                        );
                    }
                } else {
                    agent_state.status = AgentStatus::Running;
                }
            }
            _ => {
                // For standard actions, just return to running state
                agent_state.status = AgentStatus::Running;
            }
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
            &mut verification_checks,
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
        failure_class = classify_failure(err.as_deref(), &policy_decision);
        if let Some(class) = failure_class {
            let target_id = agent_state.target.as_ref().and_then(|target| {
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
            });
            let window_fingerprint = if log_visual_hash == [0u8; 32] {
                None
            } else {
                Some(hex::encode(log_visual_hash))
            };
            let attempt_key = build_attempt_key(
                &retry_intent_hash,
                routing_decision.tier,
                &tool_name,
                target_id,
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
                        &mut verification_checks,
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
                // Keep web research autonomous under transient tool/schema instability.
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

    verification_checks.push(format!("policy_decision={}", policy_decision));
    verification_checks.push(format!("was_resume=true"));
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
        // Keep resumed spatial failures in a high-observability tier so the next step
        // can recover with fresh visual grounding instead of dropping back to headless.
        agent_state.consecutive_failures = agent_state.consecutive_failures.max(3);
    }

    let mut artifacts = extract_artifacts(err.as_deref(), out.as_deref());
    artifacts.push(format!(
        "trace://agent_step/{}",
        pre_state_summary.step_index
    ));
    artifacts.push(format!("trace://session/{}", hex::encode(&session_id[..4])));
    let post_state = build_post_state_summary(agent_state, success, verification_checks);
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
        scs_lineage_ptr: lineage_pointer(agent_state.active_skill_hash),
        mutation_receipt_ptr: mutation_receipt_pointer(state, &session_id),
        policy_binding_hash: policy_binding,
        policy_binding_sig: None,
        policy_binding_signer: None,
    };
    emit_routing_receipt(service.event_sender.as_ref(), receipt);

    state.insert(&key, &codec::to_bytes_canonical(&agent_state)?)?;

    Ok(())
}
