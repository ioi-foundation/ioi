use super::support::{
    execution_evidence_key, execution_evidence_value, has_execution_evidence,
    persist_step_evidence_to_ledger, record_execution_evidence,
    record_execution_evidence_with_value, success_condition_key,
};
use crate::agentic::rules::ActionRules;
use crate::agentic::runtime::types::{AgentState, CommandExecution, ToolCallStatus};
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::{AgentTool, IntentCatalogEntry, IntentScopeProfile};
use ioi_types::app::ActionTarget;
use regex::Regex;
use std::collections::BTreeMap;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[path = "command_contract/environment.rs"]
mod environment;
#[path = "command_contract/history.rs"]
mod history;

pub const TARGET_UTC_MARKER: &str = "Target UTC:";
pub const RUN_TIMESTAMP_UTC_MARKER: &str = "Run timestamp (UTC):";
pub const MECHANISM_MARKER: &str = "Mechanism:";
pub const TIMER_SLEEP_BACKEND_SUCCESS_CONDITION: &str = "timer_sleep_backend";
pub const TIMER_NOTIFICATION_PATH_SUCCESS_CONDITION: &str = "notification_path_armed";
pub const TIMER_NOTIFICATION_CONTRACT_REQUIRED_EVIDENCE: &str =
    "timer_notification_contract_required";
pub const WEB_PIPELINE_TERMINAL_EVIDENCE: &str = "web_pipeline_terminal";
pub const PROVIDER_SELECTION_COMMIT_EVIDENCE: &str = "provider_selection_commit";
pub const VERIFICATION_COMMIT_EVIDENCE: &str = "verification_commit";
const COMMAND_SCOPE_REQUIRED_EVIDENCE: [&str; 3] =
    ["provider_selection", "execution", "verification"];
const COMMAND_SCOPE_SUCCESS_CONDITIONS: [&str; 1] = ["execution_artifact"];
pub const CLOCK_TIMESTAMP_SUCCESS_CONDITION: &str = "clock_timestamp_observed";
const RRSA_BASE_REQUIRED_RECEIPTS: [&str; 3] = [
    "rrsa_request_binding",
    "rrsa_firewall_decision",
    "rrsa_domain",
];
const RRSA_UI_REQUIRED_RECEIPTS: [&str; 1] = ["rrsa_output_commitment"];
const RRSA_FILESYSTEM_REQUIRED_RECEIPTS: [&str; 2] =
    ["rrsa_output_commitment", "rrsa_path_scope_binding"];
const RRSA_NETWORK_REQUIRED_RECEIPTS: [&str; 2] = ["rrsa_output_commitment", "rrsa_domain_binding"];
const RRSA_WALLET_REQUIRED_RECEIPTS: [&str; 3] = [
    "rrsa_tx_hash_binding",
    "rrsa_approval_grant_ref",
    "rrsa_eei_bundle_commitment",
];

const CLOCK_PAYLOAD_COMMAND_TOKENS: [&str; 6] = [
    "date",
    "timedatectl",
    "hwclock",
    "get-date",
    "datetime",
    "clock_gettime",
];
const CLOCK_PAYLOAD_NETWORK_TOKENS: [&str; 10] = [
    "curl", "wget", "fetch", "http", "https", "ftp", "nc", "ncat", "netcat", "telnet",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalReplyComposerOutcome {
    pub output: String,
    pub applied: bool,
    pub template_id: &'static str,
    pub validator_passed: bool,
    pub degradation_reason: Option<&'static str>,
}

#[allow(unused_imports)]
pub use environment::{
    runtime_desktop_directory, runtime_home_directory, runtime_host_environment_evidence,
    sys_exec_foreign_absolute_home_path, ForeignHomePathEvidence, HostEnvironmentEvidence,
};
pub use history::{append_command_history_entry, command_history_entry, command_history_exit_code};

include!("command_contract/contract_resolution.rs");

pub fn resolved_contract_requirements_with_rules(
    agent_state: &AgentState,
    rules: &ActionRules,
) -> (Vec<String>, Vec<String>) {
    resolved_contract_requirements(
        agent_state,
        Some(&rules.ontology_policy.intent_routing.intent_catalog),
    )
}

pub fn contract_requires_evidence_with_rules(
    agent_state: &AgentState,
    rules: &ActionRules,
    receipt: &str,
) -> bool {
    let (required_evidence, _) = resolved_contract_requirements_with_rules(agent_state, rules);
    required_evidence.iter().any(|marker| marker == receipt)
}

pub fn contract_requires_success_condition_with_rules(
    agent_state: &AgentState,
    rules: &ActionRules,
    postcondition: &str,
) -> bool {
    let (_, success_conditions) = resolved_contract_requirements_with_rules(agent_state, rules);
    success_conditions
        .iter()
        .any(|marker| marker == postcondition)
}

pub fn is_command_execution_provider_tool(tool: &AgentTool) -> bool {
    matches!(
        tool,
        AgentTool::SysExec { .. }
            | AgentTool::SysExecSession { .. }
            | AgentTool::SoftwareInstallExecutePlan { .. }
            | AgentTool::AutomationCreateMonitor { .. }
    )
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
        let rest = if let Some(rest) = trimmed.strip_prefix(marker) {
            Some(rest)
        } else if let Some(marker_idx) = trimmed.find(marker) {
            Some(&trimmed[marker_idx + marker.len()..])
        } else {
            None
        };
        if let Some(rest) = rest {
            let token = rest
                .trim()
                .split(" Target UTC:")
                .next()
                .unwrap_or_default()
                .split(" Run timestamp (UTC):")
                .next()
                .unwrap_or_default()
                .split(" Mechanism:")
                .next()
                .unwrap_or_default()
                .trim()
                .trim_end_matches('.');
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

include!("command_contract/reply_composition.rs");

fn is_path_token_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '/' | '_' | '-' | '.' | ':')
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

fn parse_systemd_on_active_seconds(command: &str) -> Option<i64> {
    for token in command.split_whitespace() {
        let normalized = normalize_shell_token(token);
        let Some(value) = normalized.strip_prefix("--on-active=") else {
            continue;
        };
        let digits = value.trim_end_matches('s');
        if digits.is_empty() || !digits.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }
        if let Ok(seconds) = digits.parse::<i64>() {
            if seconds > 0 {
                return Some(seconds);
            }
        }
    }
    None
}

pub fn inferred_timer_delay_seconds(command: &str) -> Option<i64> {
    parse_sleep_seconds(command).or_else(|| parse_systemd_on_active_seconds(command))
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

fn scheduler_timer_notification_args(sleep_seconds: i64) -> Vec<String> {
    let rounded_minutes = ((sleep_seconds + 59) / 60).max(1);
    vec![
        "--user".to_string(),
        format!("--on-active={}s", sleep_seconds),
        "notify-send".to_string(),
        "Timer Complete".to_string(),
        format!("{} minute timer elapsed.", rounded_minutes),
    ]
}

pub fn timer_payload_requires_allowlisted_scheduler(tool: &AgentTool) -> bool {
    let Some(command_preview) = sys_exec_command_preview(tool) else {
        return false;
    };
    if parse_sleep_seconds(&command_preview).is_none() {
        return false;
    }

    match tool {
        AgentTool::SysExec { detach, .. } => {
            !detach || !command_arms_deferred_notification_path(&command_preview)
        }
        AgentTool::SysExecSession { .. } => true,
        _ => false,
    }
}

pub fn synthesize_allowlisted_timer_notification_tool(tool: &AgentTool) -> Option<AgentTool> {
    let command_preview = sys_exec_command_preview(tool)?;
    let sleep_seconds = parse_sleep_seconds(&command_preview)?;

    let args = scheduler_timer_notification_args(sleep_seconds);
    match tool {
        AgentTool::SysExec { stdin, detach, .. } => Some(AgentTool::SysExec {
            command: "systemd-run".to_string(),
            args,
            stdin: stdin.clone(),
            wait_ms_before_async: None,
            detach: *detach,
        }),
        AgentTool::SysExecSession { stdin, .. } => Some(AgentTool::SysExecSession {
            command: "systemd-run".to_string(),
            args,
            stdin: stdin.clone(),
            wait_ms_before_async: None,
        }),
        _ => None,
    }
}

fn command_preview_tokens(command_preview: &str) -> Vec<String> {
    command_preview
        .to_ascii_lowercase()
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-'))
        .filter(|token| !token.trim().is_empty())
        .map(|token| token.to_string())
        .collect()
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
    inferred_timer_delay_seconds(command_preview).is_some()
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

pub fn sys_exec_timer_delay_seconds(tool: &AgentTool) -> Option<i64> {
    sys_exec_command_preview(tool)
        .as_deref()
        .and_then(inferred_timer_delay_seconds)
}

pub fn record_provider_selection_evidence(
    tool_execution_log: &mut BTreeMap<String, ToolCallStatus>,
    verification_checks: &mut Vec<String>,
    tool_name: &str,
    route_label: &str,
) {
    record_execution_evidence_with_value(
        tool_execution_log,
        "provider_selection",
        route_label.to_string(),
    );
    verification_checks.push(execution_evidence_key("provider_selection"));
    let commit = provider_selection_commit(tool_name, route_label)
        .unwrap_or_else(|| "sha256:unavailable".to_string());
    record_execution_evidence_with_value(
        tool_execution_log,
        PROVIDER_SELECTION_COMMIT_EVIDENCE,
        commit.clone(),
    );
    verification_checks.push(execution_evidence_key(PROVIDER_SELECTION_COMMIT_EVIDENCE));
    verification_checks.push(format!("provider_selection_route={}", route_label));
    verification_checks.push(format!("provider_selection_commit={}", commit));
}

pub fn record_verification_evidence(
    tool_execution_log: &mut BTreeMap<String, ToolCallStatus>,
    verification_checks: &mut Vec<String>,
    tool: &AgentTool,
    history_entry: Option<&CommandExecution>,
) {
    record_execution_evidence(tool_execution_log, "verification");
    verification_checks.push(execution_evidence_key("verification"));
    if let Some(commit) = verification_probe_commit(tool, history_entry) {
        record_execution_evidence_with_value(
            tool_execution_log,
            VERIFICATION_COMMIT_EVIDENCE,
            commit.clone(),
        );
        verification_checks.push(execution_evidence_key(VERIFICATION_COMMIT_EVIDENCE));
        verification_checks.push(format!("verification_probe_commit={}", commit));
    } else {
        verification_checks.push("verification_probe_commit=missing".to_string());
    }
}

fn verification_probe_commit(
    tool: &AgentTool,
    history_entry: Option<&CommandExecution>,
) -> Option<String> {
    let probe_command = verification_probe_command(tool, history_entry)?;
    let digest = sha256(probe_command.as_bytes()).ok()?;
    Some(format!("sha256:{}", hex::encode(digest.as_ref())))
}

fn verification_probe_command(
    tool: &AgentTool,
    history_entry: Option<&CommandExecution>,
) -> Option<String> {
    if let AgentTool::SoftwareInstallExecutePlan { plan_ref } = tool {
        let digest = sha256(plan_ref.as_bytes()).ok()?;
        return Some(format!(
            "software_install_plan_ref=sha256:{}",
            hex::encode(digest.as_ref())
        ));
    }

    let source_command = history_entry
        .map(|entry| entry.command.clone())
        .or_else(|| sys_exec_command_preview(tool))?;
    let source_command = source_command.trim();
    if source_command.is_empty() {
        return None;
    }
    if parse_sleep_seconds(source_command).is_some() {
        return Some(format!(
            "ps -eo pid,command | grep -F -- {}",
            shell_quote_single(source_command)
        ));
    }
    let binary = source_command
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim();
    if binary.is_empty() {
        return None;
    }
    Some(format!("command -v -- {}", shell_quote_single(binary)))
}

fn shell_quote_single(value: &str) -> String {
    let escaped = value.replace('\'', "'\"'\"'");
    format!("'{}'", escaped)
}

fn provider_selection_commit(tool_name: &str, route_label: &str) -> Option<String> {
    let payload = format!("tool_name={};route_label={}", tool_name, route_label);
    let digest = sha256(payload.as_bytes()).ok()?;
    Some(format!("sha256:{}", hex::encode(digest.as_ref())))
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

fn append_unique_marker(values: &mut Vec<String>, marker: &str) {
    if !values.iter().any(|value| value == marker) {
        values.push(marker.to_string());
    }
}

fn rrsa_required_receipts(agent_state: &AgentState) -> Vec<String> {
    rrsa_required_receipts_for_domain(execution_evidence_value(
        &agent_state.tool_execution_log,
        "rrsa_domain",
    ))
}

fn rrsa_required_receipts_from_ledger(agent_state: &AgentState) -> Vec<String> {
    rrsa_required_receipts_for_domain(agent_state.execution_ledger.evidence_value("rrsa_domain"))
}

fn rrsa_required_receipts_for_domain(domain_raw: Option<&str>) -> Vec<String> {
    let mut required = Vec::<String>::new();
    let Some(domain_raw) = domain_raw else {
        return required;
    };
    let domain = domain_raw.trim().to_ascii_lowercase();
    if domain.is_empty() {
        return required;
    }

    for receipt in RRSA_BASE_REQUIRED_RECEIPTS {
        append_unique_marker(&mut required, receipt);
    }
    match domain.as_str() {
        "ui_browser" => {
            for receipt in RRSA_UI_REQUIRED_RECEIPTS {
                append_unique_marker(&mut required, receipt);
            }
        }
        "filesystem" => {
            for receipt in RRSA_FILESYSTEM_REQUIRED_RECEIPTS {
                append_unique_marker(&mut required, receipt);
            }
        }
        "network_web" => {
            for receipt in RRSA_NETWORK_REQUIRED_RECEIPTS {
                append_unique_marker(&mut required, receipt);
            }
        }
        "wallet" => {
            for receipt in RRSA_WALLET_REQUIRED_RECEIPTS {
                append_unique_marker(&mut required, receipt);
            }
        }
        _ => {}
    }
    required
}

fn receipt_requires_commit_hash(receipt: &str) -> bool {
    matches!(
        receipt,
        PROVIDER_SELECTION_COMMIT_EVIDENCE | VERIFICATION_COMMIT_EVIDENCE
    ) || receipt.ends_with("_commit")
}

fn push_unique_missing(missing: &mut Vec<String>, marker: String) {
    if !missing.iter().any(|existing| existing == &marker) {
        missing.push(marker);
    }
}

#[cfg(test)]
#[path = "command_contract/tests.rs"]
mod tests;
