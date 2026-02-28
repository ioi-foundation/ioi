use super::support::{
    execution_receipt_value, has_execution_postcondition, has_execution_receipt,
    mark_execution_receipt, mark_execution_receipt_with_value, postcondition_marker,
    receipt_marker,
};
use crate::agentic::desktop::types::{AgentState, CommandExecution, ToolCallStatus};
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::{AgentTool, IntentScopeProfile};
use ioi_types::app::ActionTarget;
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
pub const TIMER_SLEEP_BACKEND_POSTCONDITION: &str = "timer_sleep_backend";
pub const TIMER_NOTIFICATION_PATH_POSTCONDITION: &str = "notification_path_armed";
pub const TIMER_NOTIFICATION_CONTRACT_REQUIRED_RECEIPT: &str =
    "timer_notification_contract_required";
pub const PROVIDER_SELECTION_COMMIT_RECEIPT: &str = "provider_selection_commit";
pub const VERIFICATION_COMMIT_RECEIPT: &str = "verification_commit";
const COMMAND_SCOPE_REQUIRED_RECEIPTS: [&str; 3] =
    ["provider_selection", "execution", "verification"];
const COMMAND_SCOPE_REQUIRED_POSTCONDITIONS: [&str; 1] = ["execution_artifact"];
pub const CLOCK_TIMESTAMP_POSTCONDITION: &str = "clock_timestamp_observed";

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
    pub fallback_reason: Option<&'static str>,
}

#[allow(unused_imports)]
pub use environment::{
    runtime_desktop_directory, runtime_home_directory, runtime_host_environment_receipt,
    sys_exec_foreign_absolute_home_path, ForeignHomePathEvidence, HostEnvironmentReceipt,
};
pub use history::{append_command_history_entry, command_history_entry, command_history_exit_code};

pub fn capability_route_label(tool: &AgentTool) -> Option<&'static str> {
    match tool {
        AgentTool::SysInstallPackage { .. } => Some("enablement_request"),
        AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. } => Some("script_backend"),
        _ => match tool.target() {
            ActionTarget::WindowFocus
            | ActionTarget::ClipboardWrite
            | ActionTarget::ClipboardRead
            | ActionTarget::BrowserInteract
            | ActionTarget::BrowserInspect
            | ActionTarget::GuiClick
            | ActionTarget::GuiType
            | ActionTarget::GuiScroll
            | ActionTarget::GuiInspect => Some("native_integration"),
            _ => None,
        },
    }
}

pub fn is_command_execution_provider_tool(tool: &AgentTool) -> bool {
    matches!(
        tool,
        AgentTool::SysExec { .. }
            | AgentTool::SysExecSession { .. }
            | AgentTool::SysInstallPackage { .. }
    )
}

pub fn extract_error_class_token(error: Option<&str>) -> Option<&str> {
    let raw = error?;
    let marker = "ERROR_CLASS=";
    let start = raw.find(marker)?;
    raw[start + marker.len()..]
        .split_whitespace()
        .next()
        .filter(|token| !token.trim().is_empty())
}

pub fn is_cec_terminal_error(error: Option<&str>) -> bool {
    matches!(
        extract_error_class_token(error),
        Some(
            "ExecutionContractViolation"
                | "DiscoveryMissing"
                | "SynthesisFailed"
                | "ExecutionFailedTerminal"
                | "VerificationMissing"
                | "PostconditionFailed"
        )
    )
}

pub fn execution_contract_violation_error(missing_keys: &str) -> String {
    let mut missing_receipts = Vec::<String>::new();
    let mut missing_postconditions = Vec::<String>::new();
    for token in missing_keys
        .split(',')
        .map(|token| token.trim())
        .filter(|token| !token.is_empty())
    {
        if let Some(rest) = token.strip_prefix("receipt::") {
            missing_receipts.push(rest.trim_end_matches("=true").to_string());
        } else if let Some(rest) = token.strip_prefix("postcondition::") {
            missing_postconditions.push(rest.trim_end_matches("=true").to_string());
        }
    }

    let (error_class, failed_stage) = if missing_receipts
        .iter()
        .any(|receipt| receipt == "host_discovery")
    {
        ("DiscoveryMissing", "discovery")
    } else if missing_receipts
        .iter()
        .any(|receipt| receipt == "provider_selection" || receipt == "provider_selection_commit")
    {
        ("SynthesisFailed", "provider_selection")
    } else if missing_receipts
        .iter()
        .any(|receipt| receipt == "verification" || receipt == "verification_commit")
    {
        ("VerificationMissing", "verification")
    } else if !missing_postconditions.is_empty() {
        ("PostconditionFailed", "completion_gate")
    } else {
        ("ExecutionContractViolation", "completion_gate")
    };

    let missing_receipts_str = if missing_receipts.is_empty() {
        "none".to_string()
    } else {
        missing_receipts.join("|")
    };
    let missing_postconditions_str = if missing_postconditions.is_empty() {
        "none".to_string()
    } else {
        missing_postconditions.join("|")
    };

    format!(
        "ERROR_CLASS={} base_error_class=ExecutionContractViolation Execution contract unmet. failed_stage={} missing_receipts={} missing_postconditions={} missing_keys={}",
        error_class, failed_stage, missing_receipts_str, missing_postconditions_str, missing_keys
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

pub fn compose_terminal_chat_reply(summary: &str) -> TerminalReplyComposerOutcome {
    let trimmed = summary.trim();
    if trimmed.is_empty() {
        return TerminalReplyComposerOutcome {
            output: summary.to_string(),
            applied: false,
            template_id: "passthrough",
            validator_passed: true,
            fallback_reason: None,
        };
    }

    let pdf_paths = extract_pdf_paths_for_composer(trimmed);
    if pdf_paths.len() < 2 {
        return TerminalReplyComposerOutcome {
            output: summary.to_string(),
            applied: false,
            template_id: "passthrough",
            validator_passed: true,
            fallback_reason: None,
        };
    }

    let summary_len = trimmed.chars().count().max(1);
    let path_chars: usize = pdf_paths.iter().map(|path| path.chars().count()).sum();
    if path_chars * 100 < summary_len * 35 {
        return TerminalReplyComposerOutcome {
            output: summary.to_string(),
            applied: false,
            template_id: "passthrough",
            validator_passed: true,
            fallback_reason: None,
        };
    }

    let run_timestamp = extract_structured_field(trimmed, RUN_TIMESTAMP_UTC_MARKER);
    let target_utc = extract_structured_field(trimmed, TARGET_UTC_MARKER);
    let mechanism = extract_structured_field(trimmed, MECHANISM_MARKER);
    let template_choice = deterministic_template_choice(trimmed);
    let template_id = if template_choice == 0 {
        "markdown_paths"
    } else {
        "markdown_paths_with_count"
    };

    let mut lines = Vec::<String>::new();
    if template_choice == 1 {
        lines.push(format!("Found {} matching PDF files:", pdf_paths.len()));
    } else {
        lines.push("Matching PDF files:".to_string());
    }
    lines.push(String::new());
    for path in &pdf_paths {
        lines.push(format!("- `{}`", path));
    }

    let mut metadata_lines = Vec::<String>::new();
    if let Some(mechanism) = mechanism.as_deref() {
        metadata_lines.push(format!("{} {}", MECHANISM_MARKER, mechanism));
    }
    if let Some(run_timestamp) = run_timestamp.as_deref() {
        metadata_lines.push(format!("{} {}", RUN_TIMESTAMP_UTC_MARKER, run_timestamp));
    }
    if let Some(target_utc) = target_utc.as_deref() {
        metadata_lines.push(format!("{} {}", TARGET_UTC_MARKER, target_utc));
    }
    if !metadata_lines.is_empty() {
        lines.push(String::new());
    }
    lines.extend(metadata_lines);

    let candidate = lines.join("\n").trim().to_string();
    if candidate.is_empty() {
        return TerminalReplyComposerOutcome {
            output: summary.to_string(),
            applied: false,
            template_id,
            validator_passed: false,
            fallback_reason: Some("empty_candidate"),
        };
    }

    if !composed_reply_is_valid(
        &candidate,
        &pdf_paths,
        run_timestamp.as_deref(),
        target_utc.as_deref(),
        mechanism.as_deref(),
    ) {
        return TerminalReplyComposerOutcome {
            output: summary.to_string(),
            applied: false,
            template_id,
            validator_passed: false,
            fallback_reason: Some("validator_failed"),
        };
    }

    TerminalReplyComposerOutcome {
        output: candidate,
        applied: true,
        template_id,
        validator_passed: true,
        fallback_reason: None,
    }
}

fn deterministic_template_choice(summary: &str) -> u8 {
    sha256(summary.as_bytes())
        .ok()
        .map(|digest| digest.as_ref().first().copied().unwrap_or(0) % 2)
        .unwrap_or(0)
}

fn composed_reply_is_valid(
    candidate: &str,
    pdf_paths: &[String],
    run_timestamp: Option<&str>,
    target_utc: Option<&str>,
    mechanism: Option<&str>,
) -> bool {
    if candidate.trim().is_empty() {
        return false;
    }

    let candidate_paths = extract_pdf_paths_for_composer(candidate);
    if !pdf_paths.iter().all(|path| {
        candidate_paths
            .iter()
            .any(|candidate_path| candidate_path.eq_ignore_ascii_case(path))
    }) {
        return false;
    }

    if let Some(run_timestamp) = run_timestamp {
        if extract_structured_field(candidate, RUN_TIMESTAMP_UTC_MARKER).as_deref()
            != Some(run_timestamp)
        {
            return false;
        }
    }
    if let Some(target_utc) = target_utc {
        if extract_structured_field(candidate, TARGET_UTC_MARKER).as_deref() != Some(target_utc) {
            return false;
        }
    }
    if let Some(mechanism) = mechanism {
        if extract_structured_field(candidate, MECHANISM_MARKER).as_deref() != Some(mechanism) {
            return false;
        }
    }
    true
}

fn extract_pdf_paths_for_composer(summary: &str) -> Vec<String> {
    let lower = summary.to_ascii_lowercase();
    let bytes = summary.as_bytes();
    let mut paths = Vec::<String>::new();
    let mut offset = 0usize;

    while offset < lower.len() {
        let Some(found) = lower[offset..].find(".pdf") else {
            break;
        };
        let end = offset + found + 4;
        let mut start = find_preferred_pdf_path_start(summary, end).unwrap_or(offset + found);
        if start == offset + found {
            while start > 0 {
                if bytes.get(start) == Some(&b'/')
                    && start >= 4
                    && lower[start - 4..start].eq_ignore_ascii_case(".pdf")
                {
                    break;
                }
                let prev = bytes[start - 1] as char;
                if !is_path_token_char(prev) {
                    break;
                }
                start -= 1;
            }
        }
        let candidate = normalize_composer_path(&summary[start..end]);
        if is_valid_composer_pdf_path(&candidate)
            && !paths
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(&candidate))
        {
            paths.push(candidate);
        }
        offset = end;
    }

    paths
}

fn find_preferred_pdf_path_start(summary: &str, end: usize) -> Option<usize> {
    let prefix = &summary[..end];
    let mut best: Option<usize> = None;
    for marker in ["/home/", "/Users/", "~/"] {
        for (idx, _) in prefix.match_indices(marker) {
            if !is_path_start_boundary(prefix, idx) {
                continue;
            }
            if best.map(|current| idx > current).unwrap_or(true) {
                best = Some(idx);
            }
        }
    }
    best
}

fn is_path_start_boundary(prefix: &str, idx: usize) -> bool {
    if idx == 0 {
        return true;
    }
    if prefix[..idx].to_ascii_lowercase().ends_with(".pdf") {
        return true;
    }
    let prev = prefix.as_bytes()[idx - 1] as char;
    prev.is_ascii_whitespace()
        || matches!(prev, '"' | '\'' | '`' | '(' | '[' | '{' | ',' | ';' | ':')
}

fn normalize_composer_path(path: &str) -> String {
    path.trim()
        .trim_matches(|ch: char| {
            matches!(
                ch,
                '"' | '\'' | '`' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';' | '<' | '>'
            )
        })
        .to_string()
}

fn is_valid_composer_pdf_path(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    if !(lower.starts_with('/') || lower.starts_with("~/")) {
        return false;
    }
    lower.ends_with(".pdf")
}

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
    has_execution_receipt(
        &agent_state.tool_execution_log,
        TIMER_NOTIFICATION_CONTRACT_REQUIRED_RECEIPT,
    ) || latest_timer_backend_history_entry(agent_state).is_some()
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

fn is_simple_sleep_timer_command(command_preview: &str) -> bool {
    let tokens: Vec<&str> = command_preview.split_whitespace().collect();
    if tokens.len() != 2 {
        return false;
    }
    tokens
        .first()
        .map(|token| token.eq_ignore_ascii_case("sleep"))
        .unwrap_or(false)
        && tokens
            .get(1)
            .map(|token| token.chars().all(|ch| ch.is_ascii_digit()))
            .unwrap_or(false)
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

pub fn synthesize_allowlisted_timer_notification_tool(tool: &AgentTool) -> Option<AgentTool> {
    let command_preview = sys_exec_command_preview(tool)?;
    let sleep_seconds = parse_sleep_seconds(&command_preview)?;
    if !is_simple_sleep_timer_command(&command_preview) {
        return None;
    }

    let args = scheduler_timer_notification_args(sleep_seconds);
    match tool {
        AgentTool::SysExec { stdin, detach, .. } => Some(AgentTool::SysExec {
            command: "systemd-run".to_string(),
            args,
            stdin: stdin.clone(),
            detach: *detach,
        }),
        AgentTool::SysExecSession { stdin, .. } => Some(AgentTool::SysExecSession {
            command: "systemd-run".to_string(),
            args,
            stdin: stdin.clone(),
        }),
        _ => None,
    }
}

pub fn is_system_clock_read_contract_intent(agent_state: &AgentState) -> bool {
    agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| resolved.intent_id == "system.clock.read")
        .unwrap_or(false)
}

fn command_preview_tokens(command_preview: &str) -> Vec<String> {
    command_preview
        .to_ascii_lowercase()
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-'))
        .filter(|token| !token.trim().is_empty())
        .map(|token| token.to_string())
        .collect()
}

pub fn sys_exec_satisfies_clock_read_contract(tool: &AgentTool) -> bool {
    let Some(command_preview) = sys_exec_command_preview(tool) else {
        return false;
    };
    let tokens = command_preview_tokens(&command_preview);
    if tokens.is_empty() {
        return false;
    }
    let has_clock_token = tokens.iter().any(|token| {
        CLOCK_PAYLOAD_COMMAND_TOKENS
            .iter()
            .any(|allowed| token == allowed)
    });
    if !has_clock_token {
        return false;
    }
    !tokens.iter().any(|token| {
        CLOCK_PAYLOAD_NETWORK_TOKENS
            .iter()
            .any(|blocked| token == blocked)
    })
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

pub fn record_provider_selection_receipts(
    tool_execution_log: &mut BTreeMap<String, ToolCallStatus>,
    verification_checks: &mut Vec<String>,
    tool_name: &str,
    route_label: &str,
) {
    mark_execution_receipt_with_value(
        tool_execution_log,
        "provider_selection",
        route_label.to_string(),
    );
    verification_checks.push(receipt_marker("provider_selection"));
    let commit = provider_selection_commit(tool_name, route_label)
        .unwrap_or_else(|| "sha256:unavailable".to_string());
    mark_execution_receipt_with_value(
        tool_execution_log,
        PROVIDER_SELECTION_COMMIT_RECEIPT,
        commit.clone(),
    );
    verification_checks.push(receipt_marker(PROVIDER_SELECTION_COMMIT_RECEIPT));
    verification_checks.push(format!("provider_selection_route={}", route_label));
    verification_checks.push(format!("provider_selection_commit={}", commit));
}

pub fn record_timer_notification_contract_requirement(
    tool_execution_log: &mut BTreeMap<String, ToolCallStatus>,
    verification_checks: &mut Vec<String>,
) {
    mark_execution_receipt(
        tool_execution_log,
        TIMER_NOTIFICATION_CONTRACT_REQUIRED_RECEIPT,
    );
    verification_checks.push(receipt_marker(TIMER_NOTIFICATION_CONTRACT_REQUIRED_RECEIPT));
}

pub fn record_verification_receipts(
    tool_execution_log: &mut BTreeMap<String, ToolCallStatus>,
    verification_checks: &mut Vec<String>,
    tool: &AgentTool,
    history_entry: Option<&CommandExecution>,
) {
    mark_execution_receipt(tool_execution_log, "verification");
    verification_checks.push(receipt_marker("verification"));
    if let Some(commit) = verification_probe_commit(tool, history_entry) {
        mark_execution_receipt_with_value(
            tool_execution_log,
            VERIFICATION_COMMIT_RECEIPT,
            commit.clone(),
        );
        verification_checks.push(receipt_marker(VERIFICATION_COMMIT_RECEIPT));
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
    if let AgentTool::SysInstallPackage { package, .. } = tool {
        let package = package.trim();
        if package.is_empty() {
            return None;
        }
        return Some(format!("command -v -- {}", shell_quote_single(package)));
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
    let provider_selection_value =
        execution_receipt_value(&agent_state.tool_execution_log, "provider_selection");
    if provider_selection_value
        .map(|value| value.trim().is_empty())
        .unwrap_or(false)
    {
        missing.push(receipt_marker("provider_selection"));
    }
    let provider_selection_commit = execution_receipt_value(
        &agent_state.tool_execution_log,
        PROVIDER_SELECTION_COMMIT_RECEIPT,
    );
    if provider_selection_commit
        .map(|value| !value.starts_with("sha256:"))
        .unwrap_or(true)
    {
        missing.push(receipt_marker(PROVIDER_SELECTION_COMMIT_RECEIPT));
    }
    let verification_commit =
        execution_receipt_value(&agent_state.tool_execution_log, VERIFICATION_COMMIT_RECEIPT);
    if verification_commit
        .map(|value| !value.starts_with("sha256:"))
        .unwrap_or(true)
    {
        missing.push(receipt_marker(VERIFICATION_COMMIT_RECEIPT));
    }
    for postcondition in COMMAND_SCOPE_REQUIRED_POSTCONDITIONS {
        if !has_execution_postcondition(&agent_state.tool_execution_log, postcondition) {
            missing.push(postcondition_marker(postcondition));
        }
    }
    if is_system_clock_read_contract_intent(agent_state)
        && !has_execution_postcondition(
            &agent_state.tool_execution_log,
            CLOCK_TIMESTAMP_POSTCONDITION,
        )
    {
        missing.push(postcondition_marker(CLOCK_TIMESTAMP_POSTCONDITION));
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

    let mut enriched = summary.to_string();
    let timer_contract_active = requires_timer_notification_contract(agent_state);
    let run_timestamp_utc = if timer_contract_active {
        latest_timer_backend_history_entry(agent_state)
            .or_else(|| agent_state.command_history.back())
            .and_then(|entry| format_utc_rfc3339(entry.timestamp_ms))
    } else {
        agent_state
            .command_history
            .back()
            .and_then(|entry| format_utc_rfc3339(entry.timestamp_ms))
    };
    let Some(run_timestamp_utc) = run_timestamp_utc else {
        return enriched;
    };
    if timer_contract_active {
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
                enriched =
                    upsert_structured_field(&enriched, TARGET_UTC_MARKER, &derived_target_utc);
            }
        }
    }
    if extract_structured_field(&enriched, RUN_TIMESTAMP_UTC_MARKER).is_none() {
        enriched = upsert_structured_field(&enriched, RUN_TIMESTAMP_UTC_MARKER, &run_timestamp_utc);
    }
    enriched
}

#[cfg(test)]
mod tests {
    use super::{
        compose_terminal_chat_reply, enrich_command_scope_summary,
        execution_contract_violation_error, is_command_execution_provider_tool,
        record_verification_receipts, VERIFICATION_COMMIT_RECEIPT,
    };
    use crate::agentic::desktop::service::step::action::support::{
        mark_execution_postcondition, mark_execution_receipt,
    };
    use crate::agentic::desktop::types::{
        AgentMode, AgentState, AgentStatus, CommandExecution, ExecutionTier, ToolCallStatus,
    };
    use ioi_types::app::agentic::AgentTool;
    use ioi_types::app::agentic::{IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState};
    use std::collections::{BTreeMap, VecDeque};

    fn test_agent_state() -> AgentState {
        AgentState {
            session_id: [0u8; 32],
            goal: "Run a command".to_string(),
            transcript_root: [0u8; 32],
            status: AgentStatus::Running,
            step_count: 0,
            max_steps: 16,
            last_action_type: None,
            parent_session_id: None,
            child_session_ids: vec![],
            budget: 1,
            tokens_used: 0,
            consecutive_failures: 0,
            pending_approval: None,
            pending_tool_call: None,
            pending_tool_jcs: None,
            pending_tool_hash: None,
            pending_visual_hash: None,
            recent_actions: vec![],
            mode: AgentMode::Agent,
            current_tier: ExecutionTier::DomHeadless,
            last_screen_phash: None,
            execution_queue: vec![],
            pending_search_completion: None,
            active_skill_hash: None,
            tool_execution_log: BTreeMap::new(),
            visual_som_map: None,
            visual_semantic_map: None,
            swarm_context: None,
            target: None,
            resolved_intent: None,
            awaiting_intent_clarification: false,
            working_directory: ".".to_string(),
            command_history: VecDeque::new(),
            active_lens: None,
        }
    }

    fn command_scope_intent(intent_id: &str) -> ResolvedIntentState {
        ResolvedIntentState {
            intent_id: intent_id.to_string(),
            scope: IntentScopeProfile::CommandExecution,
            band: IntentConfidenceBand::High,
            score: 0.92,
            top_k: vec![],
            required_capabilities: vec![],
            risk_class: "low".to_string(),
            preferred_tier: "tool_first".to_string(),
            matrix_version: "v1".to_string(),
            embedding_model_id: "test".to_string(),
            embedding_model_version: "test".to_string(),
            similarity_function_id: "cosine".to_string(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: "v1".to_string(),
            matrix_source_hash: [0u8; 32],
            receipt_hash: [0u8; 32],
            constrained: false,
        }
    }

    #[test]
    fn execution_contract_violation_error_maps_missing_verification_to_spec_class() {
        let error = execution_contract_violation_error("receipt::verification=true");
        assert!(error.starts_with("ERROR_CLASS=VerificationMissing "));
        assert!(error.contains("base_error_class=ExecutionContractViolation"));
    }

    #[test]
    fn install_package_is_treated_as_command_execution_provider_tool() {
        let install = AgentTool::SysInstallPackage {
            package: "vlc".to_string(),
            manager: None,
        };
        assert!(is_command_execution_provider_tool(&install));
    }

    #[test]
    fn install_package_verification_receipts_emit_commit() {
        let mut log = BTreeMap::<String, ToolCallStatus>::new();
        let mut checks = Vec::<String>::new();
        let tool = AgentTool::SysInstallPackage {
            package: "vlc".to_string(),
            manager: Some("apt-get".to_string()),
        };

        record_verification_receipts(&mut log, &mut checks, &tool, None);

        assert!(super::has_execution_receipt(&log, "verification"));
        let commit = super::execution_receipt_value(&log, VERIFICATION_COMMIT_RECEIPT)
            .expect("verification commit receipt should be present for install package");
        assert!(commit.starts_with("sha256:"));
        assert!(checks
            .iter()
            .any(|check| check == "receipt::verification=true"));
    }

    #[test]
    fn terminal_reply_composer_formats_dense_pdf_path_output() {
        let summary = "/home/heathledger/Documents/ioi/one.pdf/home/heathledger/Documents/ioi/two.pdf /home/heathledger/Pictures/news at DuckDuckGo.pdf Run timestamp (UTC): 2026-02-27T17:55:09.632Z";
        let outcome = compose_terminal_chat_reply(summary);

        assert!(outcome.applied);
        assert!(outcome.validator_passed);
        assert!(outcome
            .output
            .contains("- `/home/heathledger/Documents/ioi/one.pdf`"));
        assert!(outcome
            .output
            .contains("- `/home/heathledger/Documents/ioi/two.pdf`"));
        assert!(outcome
            .output
            .contains("- `/home/heathledger/Pictures/news at DuckDuckGo.pdf`"));
        assert!(outcome
            .output
            .contains("Run timestamp (UTC): 2026-02-27T17:55:09.632Z"));
    }

    #[test]
    fn enrich_summary_preserves_terse_message_and_appends_timestamp() {
        let mut state = test_agent_state();
        state.resolved_intent = Some(command_scope_intent("command.exec"));
        mark_execution_receipt(&mut state.tool_execution_log, "execution");
        mark_execution_postcondition(&mut state.tool_execution_log, "execution_artifact");
        state.command_history.push_back(CommandExecution {
            command: "bash -s".to_string(),
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            timestamp_ms: 1_772_304_000_000,
            step_index: 1,
        });

        let enriched = enrich_command_scope_summary("phone-preview.mp4", &state);
        assert!(enriched.contains("phone-preview.mp4"));
        assert!(enriched.contains("Run timestamp (UTC):"));
    }

    #[test]
    fn enrich_summary_preserves_non_terse_message() {
        let mut state = test_agent_state();
        state.resolved_intent = Some(command_scope_intent("command.exec"));
        mark_execution_receipt(&mut state.tool_execution_log, "execution");
        mark_execution_postcondition(&mut state.tool_execution_log, "execution_artifact");
        state.command_history.push_back(CommandExecution {
            command: "bash -s".to_string(),
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            timestamp_ms: 1_772_304_000_000,
            step_index: 1,
        });

        let summary = "Completed command run with expected output.";
        let enriched = enrich_command_scope_summary(summary, &state);
        assert!(enriched.contains(summary));
    }
}
