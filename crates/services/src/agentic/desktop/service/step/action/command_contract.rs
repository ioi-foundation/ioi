use super::support::{
    has_execution_postcondition, has_execution_receipt, postcondition_marker, receipt_marker,
};
use crate::agentic::desktop::types::{AgentState, CommandExecution, MAX_COMMAND_HISTORY};
use ioi_types::app::agentic::{AgentTool, IntentScopeProfile};
use std::collections::VecDeque;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const COMMAND_HISTORY_PREFIX: &str = "COMMAND_HISTORY:";
pub const TARGET_UTC_MARKER: &str = "Target UTC:";
pub const RUN_TIMESTAMP_UTC_MARKER: &str = "Run timestamp (UTC):";
pub const TIMER_SLEEP_BACKEND_POSTCONDITION: &str = "timer_sleep_backend";
pub const TIMER_NOTIFICATION_PATH_POSTCONDITION: &str = "notification_path_armed";
const COMMAND_SCOPE_REQUIRED_RECEIPTS: [&str; 3] =
    ["provider_selection", "execution", "verification"];
const COMMAND_SCOPE_REQUIRED_POSTCONDITIONS: [&str; 1] = ["execution_artifact"];

pub fn capability_route_label(tool_name: &str) -> Option<&'static str> {
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

pub fn execution_contract_violation_error(missing_keys: &str) -> String {
    format!(
        "ERROR_CLASS=NoEffectAfterAction Execution contract unmet. Select a different action or verify required markers. missing_keys={}",
        missing_keys
    )
}

pub fn command_history_exit_code(output: &str) -> Option<i64> {
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

pub fn command_history_entry(output: &str) -> Option<CommandExecution> {
    let marker_idx = output.find(COMMAND_HISTORY_PREFIX)?;
    let suffix = &output[marker_idx + COMMAND_HISTORY_PREFIX.len()..];
    let payload = suffix.lines().next().unwrap_or_default().trim();
    if payload.is_empty() {
        return None;
    }
    serde_json::from_str::<CommandExecution>(payload).ok()
}

pub fn append_command_history_entry(
    history: &mut VecDeque<CommandExecution>,
    entry: CommandExecution,
) {
    history.push_back(entry);
    while history.len() > MAX_COMMAND_HISTORY {
        let _ = history.pop_front();
    }
}

pub fn format_utc_rfc3339(timestamp_ms: u64) -> Option<String> {
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

pub fn upsert_structured_field(summary: &str, marker: &str, value: &str) -> String {
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

pub fn parse_sleep_seconds(command: &str) -> Option<i64> {
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

pub fn requires_timer_notification_contract(agent_state: &AgentState) -> bool {
    let goal_lc = agent_state.goal.to_ascii_lowercase();
    goal_lc.contains("timer")
        || goal_lc.contains("countdown")
        || goal_lc.contains("alarm")
        || goal_lc.contains("remind me in")
        || goal_lc.contains("wake me in")
}

pub fn render_command_preview(command: &str, args: &[String]) -> String {
    let command = command.trim();
    if args.is_empty() {
        command.to_string()
    } else {
        format!("{} {}", command, args.join(" "))
    }
}

pub fn sys_exec_command_preview(tool: &AgentTool) -> Option<String> {
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

pub fn command_arms_deferred_notification_path(command_preview: &str) -> bool {
    command_arms_notification_path(command_preview)
        && command_arms_timer_delay_backend(command_preview)
}

pub fn command_arms_timer_delay_backend(command_preview: &str) -> bool {
    let command_lc = command_preview.to_ascii_lowercase();
    parse_sleep_seconds(command_preview).is_some()
        || (command_lc.contains("systemd-run") && command_lc.contains("--on-active"))
        || command_lc.starts_with("at ")
        || command_lc.contains(" at now")
}

pub fn sys_exec_arms_timer_delay_backend(tool: &AgentTool) -> bool {
    sys_exec_command_preview(tool)
        .as_deref()
        .map(command_arms_timer_delay_backend)
        .unwrap_or(false)
}

pub fn target_utc_from_run_and_sleep(timestamp_ms: u64, sleep_seconds: i64) -> Option<String> {
    let run_seconds = i64::try_from(timestamp_ms / 1_000).ok()?;
    let run_millis = i64::try_from(timestamp_ms % 1_000).ok()?;
    let run_timestamp = OffsetDateTime::from_unix_timestamp(run_seconds).ok()?
        + time::Duration::milliseconds(run_millis);
    (run_timestamp + time::Duration::seconds(sleep_seconds))
        .format(&Rfc3339)
        .ok()
}

fn latest_timer_backend_history_entry(agent_state: &AgentState) -> Option<&CommandExecution> {
    agent_state
        .command_history
        .iter()
        .rev()
        .find(|entry| parse_sleep_seconds(&entry.command).is_some())
}

fn target_utc_from_command_history_entry(entry: &CommandExecution) -> Option<String> {
    let sleep_seconds = parse_sleep_seconds(&entry.command)?;
    target_utc_from_run_and_sleep(entry.timestamp_ms, sleep_seconds)
}

fn derived_target_utc_from_history(agent_state: &AgentState) -> Option<String> {
    let entry = latest_timer_backend_history_entry(agent_state)?;
    target_utc_from_command_history_entry(entry)
}

pub fn missing_execution_contract_markers(agent_state: &AgentState) -> Vec<String> {
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

pub fn enrich_command_scope_summary(summary: &str, agent_state: &AgentState) -> String {
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
