use super::support::{
    execution_receipt_value, has_execution_postcondition, has_execution_receipt,
    mark_execution_receipt, mark_execution_receipt_with_value, postcondition_marker,
    receipt_marker,
};
use crate::agentic::desktop::types::{
    AgentState, CommandExecution, ToolCallStatus, MAX_COMMAND_HISTORY,
};
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::{AgentTool, IntentScopeProfile};
use ioi_types::app::ActionTarget;
use serde::Deserialize;
use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::path::Path;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const COMMAND_HISTORY_PREFIX: &str = "COMMAND_HISTORY:";
pub const TARGET_UTC_MARKER: &str = "Target UTC:";
pub const RUN_TIMESTAMP_UTC_MARKER: &str = "Run timestamp (UTC):";
pub const MECHANISM_MARKER: &str = "Mechanism:";
pub const TIMER_SLEEP_BACKEND_POSTCONDITION: &str = "timer_sleep_backend";
pub const TIMER_NOTIFICATION_PATH_POSTCONDITION: &str = "notification_path_armed";
pub const TIMER_NOTIFICATION_CONTRACT_REQUIRED_RECEIPT: &str =
    "timer_notification_contract_required";
pub const LOWERCASE_RENAME_CONTRACT_REQUIRED_RECEIPT: &str = "lowercase_rename_contract_required";
pub const PROVIDER_SELECTION_COMMIT_RECEIPT: &str = "provider_selection_commit";
pub const VERIFICATION_COMMIT_RECEIPT: &str = "verification_commit";
pub const LOWERCASE_RENAME_POSTCONDITION: &str = "lowercase_rename_postcheck";
pub const LOWERCASE_RENAME_TARGET_DIR_RECEIPT: &str = "lowercase_rename_target_dir";
pub const LOWERCASE_RENAME_TOTAL_FILES_RECEIPT: &str = "lowercase_rename_total_files";
pub const LOWERCASE_RENAME_UPPERCASE_REMAINING_RECEIPT: &str =
    "lowercase_rename_uppercase_remaining";
const COMMAND_SCOPE_REQUIRED_RECEIPTS: [&str; 3] =
    ["provider_selection", "execution", "verification"];
const COMMAND_SCOPE_REQUIRED_POSTCONDITIONS: [&str; 1] = ["execution_artifact"];
pub const CLOCK_TIMESTAMP_POSTCONDITION: &str = "clock_timestamp_observed";
const LOWERCASE_RENAME_POSTCHECK_PREFIX: &str = "LOWERCASE_RENAME_POSTCHECK:";
const LOWERCASE_RENAME_POSTCHECK_MAX_FINAL_NAMES: usize = 64;

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

#[derive(Debug, Clone)]
pub struct HostEnvironmentReceipt {
    pub observed_value: String,
    pub probe_source: String,
    pub timestamp_ms: u64,
    pub satisfied: bool,
    pub desktop_directory: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignHomePathEvidence {
    pub runtime_home_directory: String,
    pub runtime_home_owner: String,
    pub payload_home_directory: String,
    pub payload_home_owner: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LowercaseRenameContractTarget {
    pub target_dir: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct LowercaseRenamePostcheckReceipt {
    pub target_dir: String,
    pub total_files: usize,
    pub uppercase_remaining: usize,
    #[serde(default)]
    pub final_names: Vec<String>,
}

pub fn runtime_home_directory() -> Option<String> {
    discover_runtime_home_directory().map(|(home_dir, _)| home_dir)
}

pub fn runtime_desktop_directory() -> Option<String> {
    let home_dir = runtime_home_directory()?;
    Some(runtime_desktop_from_home(&home_dir))
}

pub fn runtime_host_environment_receipt(timestamp_ms: u64) -> HostEnvironmentReceipt {
    let fallback_probe = "process_env:HOME|USERPROFILE|HOMEDRIVE+HOMEPATH".to_string();
    match discover_runtime_home_directory() {
        Some((home_dir, probe_source)) => HostEnvironmentReceipt {
            observed_value: home_dir.clone(),
            probe_source,
            timestamp_ms,
            satisfied: true,
            desktop_directory: Some(runtime_desktop_from_home(&home_dir)),
        },
        None => HostEnvironmentReceipt {
            observed_value: "unavailable".to_string(),
            probe_source: fallback_probe,
            timestamp_ms,
            satisfied: false,
            desktop_directory: None,
        },
    }
}

pub fn sys_exec_foreign_absolute_home_path(tool: &AgentTool) -> Option<ForeignHomePathEvidence> {
    let runtime_home_dir = runtime_home_directory()?;
    detect_foreign_home_path_for_runtime_home(tool, &runtime_home_dir)
}

fn detect_foreign_home_path_for_runtime_home(
    tool: &AgentTool,
    runtime_home_dir: &str,
) -> Option<ForeignHomePathEvidence> {
    let runtime_home_owner = home_owner_from_path(runtime_home_dir)?;
    let command_preview = sys_exec_command_preview(tool)?;
    for payload_home_dir in extract_absolute_home_directories(&command_preview) {
        let Some(payload_home_owner) = home_owner_from_path(&payload_home_dir) else {
            continue;
        };
        if !payload_home_owner.eq_ignore_ascii_case(&runtime_home_owner) {
            return Some(ForeignHomePathEvidence {
                runtime_home_directory: runtime_home_dir.to_string(),
                runtime_home_owner,
                payload_home_directory: payload_home_dir,
                payload_home_owner,
            });
        }
    }
    None
}

fn discover_runtime_home_directory() -> Option<(String, String)> {
    if let Some(home) = nonempty_env_var("HOME") {
        return Some((
            normalize_path_for_receipts(&home),
            "process_env:HOME".to_string(),
        ));
    }
    if let Some(user_profile) = nonempty_env_var("USERPROFILE") {
        return Some((
            normalize_path_for_receipts(&user_profile),
            "process_env:USERPROFILE".to_string(),
        ));
    }
    let home_drive = nonempty_env_var("HOMEDRIVE");
    let home_path = nonempty_env_var("HOMEPATH");
    if let (Some(home_drive), Some(home_path)) = (home_drive, home_path) {
        let joined = format!("{}{}", home_drive.trim_end_matches(['\\', '/']), home_path);
        return Some((
            normalize_path_for_receipts(&joined),
            "process_env:HOMEDRIVE+HOMEPATH".to_string(),
        ));
    }
    None
}

fn nonempty_env_var(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn normalize_path_for_receipts(path: &str) -> String {
    let cleaned = path.trim().trim_matches('"').trim_matches('\'');
    let normalized = cleaned.replace('\\', "/");
    let trimmed = normalized.trim_end_matches('/');
    if trimmed.is_empty() {
        normalized
    } else {
        trimmed.to_string()
    }
}

fn runtime_desktop_from_home(home_dir: &str) -> String {
    format!("{}/Desktop", home_dir.trim_end_matches('/'))
}

fn home_owner_from_path(path: &str) -> Option<String> {
    let normalized = normalize_path_for_receipts(path);
    let parts = normalized
        .split('/')
        .filter(|segment| !segment.trim().is_empty())
        .collect::<Vec<_>>();
    if parts.len() < 2 {
        return None;
    }
    for (idx, part) in parts.iter().enumerate() {
        if (part.eq_ignore_ascii_case("home") || part.eq_ignore_ascii_case("users"))
            && idx + 1 < parts.len()
        {
            return Some(parts[idx + 1].to_string());
        }
    }
    None
}

fn extract_absolute_home_directories(command_preview: &str) -> Vec<String> {
    let mut directories = Vec::<String>::new();
    for marker in ["/home/", "/Users/"] {
        let mut search_offset = 0usize;
        while let Some(relative_idx) = command_preview[search_offset..].find(marker) {
            let absolute_idx = search_offset + relative_idx;
            let suffix = &command_preview[absolute_idx..];
            let candidate = suffix
                .chars()
                .take_while(|ch| is_path_token_char(*ch))
                .collect::<String>();
            if candidate.len() > marker.len() {
                let normalized_candidate = normalize_path_for_receipts(&candidate);
                if home_owner_from_path(&normalized_candidate).is_some()
                    && !directories
                        .iter()
                        .any(|existing| existing.eq_ignore_ascii_case(&normalized_candidate))
                {
                    directories.push(normalized_candidate);
                }
            }
            search_offset = absolute_idx + marker.len();
        }
    }
    directories
}

fn is_path_token_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '/' | '_' | '-' | '.' | ':')
}

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

pub fn command_history_exit_code(output: &str) -> Option<i64> {
    command_history_payload(output)?
        .get("exit_code")
        .and_then(|value| value.as_i64())
}

fn command_history_payload(output: &str) -> Option<serde_json::Value> {
    let payload = latest_command_history_payload(output)?;
    serde_json::from_str::<serde_json::Value>(payload).ok()
}

pub fn command_history_entry(output: &str) -> Option<CommandExecution> {
    let payload = latest_command_history_payload(output)?;
    serde_json::from_str::<CommandExecution>(payload).ok()
}

fn latest_command_history_payload(output: &str) -> Option<&str> {
    let mut latest_payload: Option<&str> = None;

    for (marker_idx, _) in output.match_indices(COMMAND_HISTORY_PREFIX) {
        let suffix = &output[marker_idx + COMMAND_HISTORY_PREFIX.len()..];
        if let Some(start) = suffix.find('{') {
            if let Some(json) = extract_balanced_json_object(suffix, start) {
                latest_payload = Some(json);
                continue;
            }
        }

        let fallback = suffix.lines().next().unwrap_or_default().trim();
        if !fallback.is_empty() {
            latest_payload = Some(fallback);
        }
    }

    latest_payload
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

pub fn requires_lowercase_rename_contract(agent_state: &AgentState) -> bool {
    has_execution_receipt(
        &agent_state.tool_execution_log,
        LOWERCASE_RENAME_CONTRACT_REQUIRED_RECEIPT,
    )
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

fn is_lowercase_rename_contract_goal(goal: &str) -> bool {
    let goal_lc = goal.to_ascii_lowercase();
    let has_rename = goal_lc.contains("rename");
    let has_lowercase = goal_lc.contains("lowercase") || goal_lc.contains("lower case");
    let has_downloads = goal_lc.contains("download");
    let has_file_scope = goal_lc.contains("file");
    has_rename && has_lowercase && has_downloads && has_file_scope
}

fn extract_goal_lowercase_fixture_token(goal: &str) -> Option<String> {
    let goal_lc = goal.to_ascii_lowercase();
    let marker = "ioi_lowercase_";
    let start = goal_lc.find(marker)?;
    let suffix = &goal_lc[start..];
    let token = suffix
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
        .collect::<String>();
    if token.len() <= marker.len() {
        None
    } else {
        Some(token)
    }
}

fn path_targets_downloads(path: &str) -> bool {
    let normalized = normalize_path_for_receipts(path);
    normalized
        .split('/')
        .any(|segment| segment.eq_ignore_ascii_case("downloads"))
}

fn extract_tilde_paths(command_preview: &str) -> Vec<String> {
    let mut paths = Vec::<String>::new();
    let mut search_offset = 0usize;
    while let Some(relative_idx) = command_preview[search_offset..].find("~/") {
        let absolute_idx = search_offset + relative_idx;
        let suffix = &command_preview[absolute_idx..];
        let candidate = suffix
            .chars()
            .take_while(|ch| *ch == '~' || is_path_token_char(*ch))
            .collect::<String>();
        if candidate.len() > 2 {
            if let Some(home_dir) = runtime_home_directory() {
                let expanded = normalize_path_for_receipts(
                    format!("{}/{}", home_dir, candidate.trim_start_matches("~/")).as_str(),
                );
                if !paths.iter().any(|existing| existing == &expanded) {
                    paths.push(expanded);
                }
            }
        }
        search_offset = absolute_idx + 2;
    }
    paths
}

fn extract_downloads_target_from_command_preview(command_preview: &str) -> Option<String> {
    let mut candidates = extract_absolute_home_directories(command_preview);
    candidates.extend(extract_tilde_paths(command_preview));

    let preview_lc = command_preview.to_ascii_lowercase();
    if preview_lc.contains("$home/downloads") || preview_lc.contains("${home}/downloads") {
        if let Some(home_dir) = runtime_home_directory() {
            let fallback = format!("{}/Downloads", home_dir.trim_end_matches('/'));
            if !candidates.iter().any(|existing| existing == &fallback) {
                candidates.push(fallback);
            }
        }
    }

    candidates
        .into_iter()
        .filter(|candidate| path_targets_downloads(candidate))
        .max_by_key(|candidate| candidate.len())
}

fn is_naive_lowercase_rename_payload(command_preview: &str) -> bool {
    let preview_lc = command_preview.to_ascii_lowercase();
    (preview_lc.contains("for file in ")
        && preview_lc.contains("tr '[:upper:]' '[:lower:]'")
        && preview_lc.contains("mv "))
        || (preview_lc.contains("rename ")
            && preview_lc.contains("y/a-z/a-z/")
            && preview_lc.contains(" *"))
}

fn is_lowercase_rename_payload_candidate(command_preview: &str) -> bool {
    let preview_lc = command_preview.to_ascii_lowercase();
    preview_lc.contains("lowercase_rename_postcheck")
        || is_naive_lowercase_rename_payload(command_preview)
        || (preview_lc.contains("tr '[:upper:]' '[:lower:]'") && preview_lc.contains("mv "))
        || (preview_lc.contains("rename ")
            && preview_lc.contains("a-z")
            && preview_lc.contains("*"))
}

pub fn sys_exec_targets_lowercase_rename_payload(tool: &AgentTool) -> bool {
    let preview_match = sys_exec_command_preview(tool)
        .map(|preview| is_lowercase_rename_payload_candidate(&preview))
        .unwrap_or(false);
    let stdin_match = match tool {
        AgentTool::SysExec { stdin, .. } | AgentTool::SysExecSession { stdin, .. } => stdin
            .as_deref()
            .map(is_lowercase_rename_payload_candidate)
            .unwrap_or(false),
        _ => false,
    };
    preview_match || stdin_match
}

pub fn sys_exec_payload_contains(tool: &AgentTool, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    match tool {
        AgentTool::SysExec {
            command,
            args,
            stdin,
            ..
        } => {
            render_command_preview(command, args).contains(needle)
                || stdin
                    .as_deref()
                    .map(|payload| payload.contains(needle))
                    .unwrap_or(false)
        }
        AgentTool::SysExecSession {
            command,
            args,
            stdin,
        } => {
            render_command_preview(command, args).contains(needle)
                || stdin
                    .as_deref()
                    .map(|payload| payload.contains(needle))
                    .unwrap_or(false)
        }
        _ => false,
    }
}

pub fn lowercase_rename_contract_target(
    agent_state: &AgentState,
    tool: &AgentTool,
) -> Option<LowercaseRenameContractTarget> {
    if !is_lowercase_rename_contract_goal(&agent_state.goal) {
        return None;
    }

    if let Some(fixture_token) = extract_goal_lowercase_fixture_token(&agent_state.goal) {
        if let Some(home_dir) = runtime_home_directory() {
            return Some(LowercaseRenameContractTarget {
                target_dir: format!(
                    "{}/Downloads/{}",
                    home_dir.trim_end_matches('/'),
                    fixture_token
                ),
            });
        }
    }

    if let Some(command_preview) = sys_exec_command_preview(tool) {
        if let Some(target_dir) = extract_downloads_target_from_command_preview(&command_preview) {
            return Some(LowercaseRenameContractTarget { target_dir });
        }
    }

    runtime_home_directory().map(|home_dir| LowercaseRenameContractTarget {
        target_dir: format!("{}/Downloads", home_dir.trim_end_matches('/')),
    })
}

fn lowercase_rename_contract_script(target_dir: &str) -> String {
    let target_dir_quoted = shell_quote_single(target_dir);
    format!(
        r#"set -euo pipefail
target_dir={target_dir_quoted}
mkdir -p -- "$target_dir"

while IFS= read -r -d '' src; do
  base="$(basename -- "$src")"
  lower="$(printf '%s' "$base" | tr '[:upper:]' '[:lower:]')"
  if [ "$base" = "$lower" ]; then
    continue
  fi
  dst="$target_dir/$lower"
  if [ "$src" = "$dst" ]; then
    continue
  fi
  if [ -e "$dst" ] && [ "$src" != "$dst" ]; then
    stem="$lower"
    ext=""
    if [[ "$lower" == *.* ]]; then
      stem="${{lower%.*}}"
      ext=".${{lower##*.}}"
    fi
    n=1
    while [ -e "$target_dir/${{stem}}(${{n}})${{ext}}" ]; do
      n=$((n + 1))
    done
    dst="$target_dir/${{stem}}(${{n}})${{ext}}"
  fi
  mv -- "$src" "$dst"
done < <(find "$target_dir" -mindepth 1 -maxdepth 1 -type f -print0)

uppercase_remaining=0
total_files=0
final_names_json="["
sep=""
final_names_count=0
max_final_names={LOWERCASE_RENAME_POSTCHECK_MAX_FINAL_NAMES}
while IFS= read -r -d '' name; do
  total_files=$((total_files + 1))
  lower="$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')"
  if [ "$name" != "$lower" ]; then
    uppercase_remaining=$((uppercase_remaining + 1))
  fi
  if [ "$final_names_count" -lt "$max_final_names" ]; then
    escaped="${{name//\\/\\\\}}"
    escaped="${{escaped//\"/\\\"}}"
    escaped="${{escaped//$'\n'/\\n}}"
    escaped="${{escaped//$'\r'/\\r}}"
    escaped="${{escaped//$'\t'/\\t}}"
    escaped="${{escaped//$'\b'/\\b}}"
    escaped="${{escaped//$'\f'/\\f}}"
    final_names_json="${{final_names_json}}${{sep}}\"${{escaped}}\""
    sep=","
    final_names_count=$((final_names_count + 1))
  fi
done < <(find "$target_dir" -mindepth 1 -maxdepth 1 -type f -printf '%f\0' | LC_ALL=C sort -z)

final_names_json="${{final_names_json}}]"
target_escaped="$(printf '%s' "$target_dir" | sed 's/\\/\\\\/g; s/\"/\\\"/g')"
printf 'LOWERCASE_RENAME_POSTCHECK:{{"target_dir":"%s","total_files":%d,"uppercase_remaining":%d,"final_names":%s}}\n' "$target_escaped" "$total_files" "$uppercase_remaining" "$final_names_json"
"#
    )
}

pub fn synthesize_allowlisted_lowercase_rename_tool(
    agent_state: &AgentState,
    tool: &AgentTool,
) -> Option<AgentTool> {
    if !sys_exec_targets_lowercase_rename_payload(tool) {
        return None;
    }
    let target = lowercase_rename_contract_target(agent_state, tool)?;
    let script = lowercase_rename_contract_script(&target.target_dir);
    let args = vec!["-s".to_string()];
    match tool {
        AgentTool::SysExec { .. } => Some(AgentTool::SysExec {
            command: "bash".to_string(),
            args,
            stdin: Some(script),
            detach: false,
        }),
        AgentTool::SysExecSession { .. } => Some(AgentTool::SysExecSession {
            command: "bash".to_string(),
            args,
            stdin: Some(script),
        }),
        _ => None,
    }
}

pub fn parse_lowercase_rename_postcheck_receipt(
    output: &str,
) -> Option<LowercaseRenamePostcheckReceipt> {
    output
        .match_indices(LOWERCASE_RENAME_POSTCHECK_PREFIX)
        .filter_map(|(marker_idx, _)| {
            let payload = &output[marker_idx + LOWERCASE_RENAME_POSTCHECK_PREFIX.len()..];
            parse_lowercase_rename_postcheck_payload(payload)
        })
        .last()
}

fn parse_lowercase_rename_postcheck_payload(
    payload: &str,
) -> Option<LowercaseRenamePostcheckReceipt> {
    payload
        .char_indices()
        .filter_map(|(idx, ch)| (ch == '{').then_some(idx))
        .filter_map(|start| {
            extract_balanced_json_object(payload, start)
                .and_then(|json| serde_json::from_str::<LowercaseRenamePostcheckReceipt>(json).ok())
        })
        .last()
}

fn extract_balanced_json_object(payload: &str, start: usize) -> Option<&str> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut started = false;

    for (idx, ch) in payload[start..].char_indices() {
        match ch {
            '"' if !escaped => {
                in_string = !in_string;
            }
            '\\' if in_string => {
                escaped = !escaped;
                continue;
            }
            '{' if !in_string => {
                depth += 1;
                started = true;
            }
            '}' if !in_string => {
                if depth == 0 {
                    return None;
                }
                depth -= 1;
                if started && depth == 0 {
                    let end = start + idx;
                    return Some(&payload[start..=end]);
                }
            }
            _ => {}
        }
        escaped = false;
    }

    None
}

pub fn command_history_lowercase_rename_postcheck(
    history_entry: &CommandExecution,
) -> Option<LowercaseRenamePostcheckReceipt> {
    parse_lowercase_rename_postcheck_receipt(&history_entry.stdout)
        .or_else(|| parse_lowercase_rename_postcheck_receipt(&history_entry.stderr))
}

pub fn discover_lowercase_rename_postcheck(
    target_dir: &str,
) -> Result<LowercaseRenamePostcheckReceipt, String> {
    let target = Path::new(target_dir);
    let entries = fs::read_dir(target).map_err(|error| {
        format!(
            "target_dir_read_failed target_dir={} error={}",
            target_dir, error
        )
    })?;

    let mut names = Vec::<String>::new();
    let mut uppercase_remaining = 0usize;

    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "target_dir_iter_failed target_dir={} error={}",
                target_dir, error
            )
        })?;
        let file_type = entry.file_type().map_err(|error| {
            format!(
                "target_dir_file_type_failed target_dir={} error={}",
                target_dir, error
            )
        })?;
        if !file_type.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name != name.to_ascii_lowercase() {
            uppercase_remaining = uppercase_remaining.saturating_add(1);
        }
        names.push(name);
    }

    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    let total_files = names.len();
    let final_names = names
        .into_iter()
        .take(LOWERCASE_RENAME_POSTCHECK_MAX_FINAL_NAMES)
        .collect::<Vec<_>>();

    Ok(LowercaseRenamePostcheckReceipt {
        target_dir: target_dir.to_string(),
        total_files,
        uppercase_remaining,
        final_names,
    })
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

pub fn record_lowercase_rename_contract_requirement(
    tool_execution_log: &mut BTreeMap<String, ToolCallStatus>,
    verification_checks: &mut Vec<String>,
) {
    mark_execution_receipt(
        tool_execution_log,
        LOWERCASE_RENAME_CONTRACT_REQUIRED_RECEIPT,
    );
    verification_checks.push(receipt_marker(LOWERCASE_RENAME_CONTRACT_REQUIRED_RECEIPT));
}

pub fn record_lowercase_rename_postcheck_receipts(
    tool_execution_log: &mut BTreeMap<String, ToolCallStatus>,
    receipt: &LowercaseRenamePostcheckReceipt,
) {
    mark_execution_receipt_with_value(
        tool_execution_log,
        LOWERCASE_RENAME_TARGET_DIR_RECEIPT,
        receipt.target_dir.clone(),
    );
    mark_execution_receipt_with_value(
        tool_execution_log,
        LOWERCASE_RENAME_TOTAL_FILES_RECEIPT,
        receipt.total_files.to_string(),
    );
    mark_execution_receipt_with_value(
        tool_execution_log,
        LOWERCASE_RENAME_UPPERCASE_REMAINING_RECEIPT,
        receipt.uppercase_remaining.to_string(),
    );
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
    if requires_lowercase_rename_contract(agent_state)
        && !has_execution_postcondition(
            &agent_state.tool_execution_log,
            LOWERCASE_RENAME_POSTCONDITION,
        )
    {
        missing.push(postcondition_marker(LOWERCASE_RENAME_POSTCONDITION));
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

    let mut enriched =
        lowercase_rename_completion_summary(agent_state).unwrap_or_else(|| summary.to_string());
    let run_timestamp_utc = latest_timer_backend_history_entry(agent_state)
        .or_else(|| agent_state.command_history.back())
        .and_then(|entry| format_utc_rfc3339(entry.timestamp_ms));
    let Some(run_timestamp_utc) = run_timestamp_utc else {
        return enriched;
    };
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

fn lowercase_rename_completion_summary(agent_state: &AgentState) -> Option<String> {
    if !requires_lowercase_rename_contract(agent_state) {
        return None;
    }
    if !has_execution_postcondition(
        &agent_state.tool_execution_log,
        LOWERCASE_RENAME_POSTCONDITION,
    ) {
        return None;
    }

    let latest_postcheck = agent_state
        .command_history
        .iter()
        .rev()
        .find_map(command_history_lowercase_rename_postcheck);
    let target_dir = execution_receipt_value(
        &agent_state.tool_execution_log,
        LOWERCASE_RENAME_TARGET_DIR_RECEIPT,
    )
    .filter(|value| !value.trim().is_empty())
    .map(str::to_string)
    .or_else(|| {
        latest_postcheck
            .as_ref()
            .map(|receipt| receipt.target_dir.clone())
    })
    .unwrap_or_else(|| "target directory".to_string());
    let total_files = execution_receipt_value(
        &agent_state.tool_execution_log,
        LOWERCASE_RENAME_TOTAL_FILES_RECEIPT,
    )
    .and_then(|value| value.parse::<usize>().ok())
    .or_else(|| latest_postcheck.as_ref().map(|receipt| receipt.total_files))
    .unwrap_or(0);
    let uppercase_remaining = execution_receipt_value(
        &agent_state.tool_execution_log,
        LOWERCASE_RENAME_UPPERCASE_REMAINING_RECEIPT,
    )
    .and_then(|value| value.parse::<usize>().ok())
    .or_else(|| {
        latest_postcheck
            .as_ref()
            .map(|receipt| receipt.uppercase_remaining)
    })
    .unwrap_or(0);

    if uppercase_remaining == 0 {
        if path_targets_downloads(&target_dir) {
            Some(format!(
                "All files in the Downloads folder are lowercase. Files checked: {}.",
                total_files
            ))
        } else {
            Some(format!(
                "All files in '{}' are lowercase. Files checked: {}.",
                target_dir, total_files
            ))
        }
    } else {
        Some(format!(
            "Lowercase rename is incomplete in '{}': {} files still contain uppercase characters ({} files checked).",
            target_dir, uppercase_remaining, total_files
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        command_history_entry, command_history_exit_code,
        command_history_lowercase_rename_postcheck, compose_terminal_chat_reply,
        detect_foreign_home_path_for_runtime_home, discover_lowercase_rename_postcheck,
        enrich_command_scope_summary, execution_contract_violation_error,
        lowercase_rename_contract_target, parse_lowercase_rename_postcheck_receipt,
        provider_selection_commit, synthesize_allowlisted_lowercase_rename_tool,
        synthesize_allowlisted_timer_notification_tool, sys_exec_command_preview,
        sys_exec_satisfies_clock_read_contract, sys_exec_targets_lowercase_rename_payload,
        verification_probe_commit, COMMAND_HISTORY_PREFIX,
        LOWERCASE_RENAME_CONTRACT_REQUIRED_RECEIPT, LOWERCASE_RENAME_POSTCONDITION,
        LOWERCASE_RENAME_TARGET_DIR_RECEIPT, LOWERCASE_RENAME_TOTAL_FILES_RECEIPT,
        LOWERCASE_RENAME_UPPERCASE_REMAINING_RECEIPT,
    };
    use crate::agentic::desktop::service::step::action::support::{
        mark_execution_postcondition, mark_execution_receipt, mark_execution_receipt_with_value,
    };
    use crate::agentic::desktop::types::{
        AgentMode, AgentState, AgentStatus, CommandExecution, ExecutionTier,
    };
    use ioi_types::app::agentic::{
        AgentTool, IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState,
    };
    use std::collections::{BTreeMap, VecDeque};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_agent_state_with_goal(goal: &str) -> AgentState {
        AgentState {
            session_id: [0u8; 32],
            goal: goal.to_string(),
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

    fn test_resolved_intent(scope: IntentScopeProfile) -> ResolvedIntentState {
        ResolvedIntentState {
            intent_id: "command.exec".to_string(),
            scope,
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
    fn provider_selection_commit_is_stable_sha256_value() {
        let left =
            provider_selection_commit("sys__exec", "script_backend").expect("provider commit");
        let right =
            provider_selection_commit("sys__exec", "script_backend").expect("provider commit");
        assert_eq!(left, right);
        assert!(left.starts_with("sha256:"));
    }

    #[test]
    fn verification_probe_commit_is_emitted_for_sys_exec() {
        let tool = AgentTool::SysExec {
            command: "sleep".to_string(),
            args: vec!["10".to_string()],
            stdin: None,
            detach: true,
        };
        let commit = verification_probe_commit(&tool, None).expect("verification commit");
        assert!(commit.starts_with("sha256:"));
    }

    #[test]
    fn sys_exec_clock_read_contract_accepts_local_clock_reads() {
        let tool = AgentTool::SysExec {
            command: "date".to_string(),
            args: vec!["-u".to_string(), "+%Y-%m-%dT%H:%M:%SZ".to_string()],
            stdin: None,
            detach: false,
        };
        assert!(sys_exec_satisfies_clock_read_contract(&tool));
    }

    #[test]
    fn sys_exec_clock_read_contract_rejects_network_retrieval_payloads() {
        let tool = AgentTool::SysExec {
            command: "curl".to_string(),
            args: vec!["https://example.com/weather".to_string()],
            stdin: None,
            detach: false,
        };
        assert!(!sys_exec_satisfies_clock_read_contract(&tool));
    }

    #[test]
    fn simple_sleep_timer_is_rewritten_to_allowlisted_scheduler_payload() {
        let tool = AgentTool::SysExec {
            command: "sleep".to_string(),
            args: vec!["900".to_string()],
            stdin: None,
            detach: true,
        };

        let rewritten =
            synthesize_allowlisted_timer_notification_tool(&tool).expect("timer rewrite");
        let preview = sys_exec_command_preview(&rewritten).expect("preview");
        assert!(preview.contains("systemd-run"));
        assert!(preview.contains("--on-active=900s"));
        assert!(preview.contains("notify-send"));
    }

    #[test]
    fn complex_shell_timer_command_is_not_auto_rewritten() {
        let tool = AgentTool::SysExec {
            command: "sleep 900 && echo done".to_string(),
            args: vec![],
            stdin: None,
            detach: true,
        };
        assert!(synthesize_allowlisted_timer_notification_tool(&tool).is_none());
    }

    #[test]
    fn lowercase_rename_contract_target_uses_fixture_token_from_goal() {
        let goal = "Rename every file in my Downloads folder to lowercase. operate only inside \"~/Downloads/ioi_lowercase_12345\".";
        let state = test_agent_state_with_goal(goal);
        let tool = AgentTool::SysExec {
            command: "echo".to_string(),
            args: vec!["noop".to_string()],
            stdin: None,
            detach: false,
        };

        let target = lowercase_rename_contract_target(&state, &tool).expect("target");
        assert!(target
            .target_dir
            .to_ascii_lowercase()
            .ends_with("/downloads/ioi_lowercase_12345"));
    }

    #[test]
    fn naive_lowercase_rename_payload_is_rewritten_to_safe_script() {
        let goal = "Rename every file in my Downloads folder to lowercase.";
        let state = test_agent_state_with_goal(goal);
        let tool = AgentTool::SysExec {
            command: "cd /home/heathledger/Downloads && for file in *; do mv \"$file\" \"$(echo $file | tr '[:upper:]' '[:lower:]')\"; done".to_string(),
            args: vec![],
            stdin: None,
            detach: false,
        };

        let rewritten =
            synthesize_allowlisted_lowercase_rename_tool(&state, &tool).expect("rewrite");
        let preview = sys_exec_command_preview(&rewritten).expect("preview");
        assert!(preview.contains("bash -s"));
        match rewritten {
            AgentTool::SysExec { stdin, .. } => {
                let payload = stdin.expect("synthesized stdin payload");
                assert!(payload.contains("LOWERCASE_RENAME_POSTCHECK"));
                assert!(payload.contains("find \"$target_dir\" -mindepth 1 -maxdepth 1 -type f"));
            }
            other => panic!("expected SysExec rewrite, got {:?}", other),
        }
    }

    #[test]
    fn lowercase_payload_candidate_ignores_setup_commands() {
        let mkdir_tool = AgentTool::SysExec {
            command: "mkdir".to_string(),
            args: vec![
                "-p".to_string(),
                "/home/heathledger/Downloads/ioi_lowercase_1".to_string(),
            ],
            stdin: None,
            detach: false,
        };
        assert!(!sys_exec_targets_lowercase_rename_payload(&mkdir_tool));

        let rename_tool = AgentTool::SysExec {
            command: "for file in *; do mv \"$file\" \"$(echo $file | tr '[:upper:]' '[:lower:]')\"; done".to_string(),
            args: vec![],
            stdin: None,
            detach: false,
        };
        assert!(sys_exec_targets_lowercase_rename_payload(&rename_tool));
    }

    #[test]
    fn stdin_lowercase_payload_is_detected_and_rewritten() {
        let goal = "Rename every file in my Downloads folder to lowercase.";
        let state = test_agent_state_with_goal(goal);
        let tool = AgentTool::SysExec {
            command: "bash".to_string(),
            args: vec![],
            stdin: Some(
                "for file in /home/heathledger/Downloads/*; do mv \"$file\" \"$(echo $file | tr '[:upper:]' '[:lower:]')\"; done".to_string(),
            ),
            detach: false,
        };

        assert!(sys_exec_targets_lowercase_rename_payload(&tool));
        let rewritten =
            synthesize_allowlisted_lowercase_rename_tool(&state, &tool).expect("rewrite");
        let preview = sys_exec_command_preview(&rewritten).expect("preview");
        assert!(preview.contains("bash -s"));
        match rewritten {
            AgentTool::SysExec { stdin, .. } => {
                let payload = stdin.expect("stdin payload");
                assert!(payload.contains("LOWERCASE_RENAME_POSTCHECK"));
            }
            other => panic!("expected SysExec rewrite, got {:?}", other),
        }
    }

    #[test]
    fn absolute_glob_lowercase_loop_is_rewritten_for_exec_session() {
        let goal = "Rename every file in my Downloads folder to lowercase.";
        let state = test_agent_state_with_goal(goal);
        let tool = AgentTool::SysExecSession {
            command: "for file in /home/heathledger/Downloads/ioi_lowercase_1/*; do basename=$(basename \"$file\"); lowercase_basename=$(echo \"$basename\" | tr '[:upper:]' '[:lower:]'); mv \"$file\" \"/home/heathledger/Downloads/ioi_lowercase_1/$lowercase_basename\"; done".to_string(),
            args: vec![],
            stdin: None,
        };

        assert!(sys_exec_targets_lowercase_rename_payload(&tool));
        let rewritten =
            synthesize_allowlisted_lowercase_rename_tool(&state, &tool).expect("rewrite");
        let preview = sys_exec_command_preview(&rewritten).expect("preview");
        assert!(preview.contains("bash -s"));
        match rewritten {
            AgentTool::SysExecSession { stdin, .. } => {
                let payload = stdin.expect("synthesized stdin payload");
                assert!(payload.contains("LOWERCASE_RENAME_POSTCHECK"));
            }
            other => panic!("expected SysExecSession rewrite, got {:?}", other),
        }
    }

    #[test]
    fn bash_c_absolute_glob_lowercase_loop_is_rewritten() {
        let goal = "Rename every file in my Downloads folder to lowercase.";
        let state = test_agent_state_with_goal(goal);
        let tool = AgentTool::SysExec {
            command: "bash".to_string(),
            args: vec![
                "-c".to_string(),
                "for file in /home/heathledger/Downloads/ioi_lowercase_1/*; do basename=$(basename \\\"$file\\\"); lowercase_basename=$(echo \\\"$basename\\\" | tr '[:upper:]' '[:lower:]'); mv \\\"$file\\\" \\\"/home/heathledger/Downloads/ioi_lowercase_1/$lowercase_basename\\\"; done".to_string(),
            ],
            stdin: None,
            detach: false,
        };

        assert!(sys_exec_targets_lowercase_rename_payload(&tool));
        let rewritten =
            synthesize_allowlisted_lowercase_rename_tool(&state, &tool).expect("rewrite");
        let preview = sys_exec_command_preview(&rewritten).expect("preview");
        assert!(preview.contains("bash -s"));
        match rewritten {
            AgentTool::SysExec { stdin, .. } => {
                let payload = stdin.expect("synthesized stdin payload");
                assert!(payload.contains("LOWERCASE_RENAME_POSTCHECK"));
            }
            other => panic!("expected SysExec rewrite, got {:?}", other),
        }
    }

    #[test]
    fn lowercase_rename_postcheck_parser_reads_latest_receipt() {
        let output = concat!(
            "noise\n",
            "LOWERCASE_RENAME_POSTCHECK:{\"target_dir\":\"/tmp/a\",\"total_files\":1,\"uppercase_remaining\":1,\"final_names\":[\"A.TXT\"]}\n",
            "LOWERCASE_RENAME_POSTCHECK:{\"target_dir\":\"/tmp/a\",\"total_files\":1,\"uppercase_remaining\":0,\"final_names\":[\"a.txt\"]}\n",
        );

        let receipt = parse_lowercase_rename_postcheck_receipt(output).expect("receipt");
        assert_eq!(receipt.target_dir, "/tmp/a");
        assert_eq!(receipt.uppercase_remaining, 0);
        assert_eq!(receipt.final_names, vec!["a.txt".to_string()]);
    }

    #[test]
    fn lowercase_rename_postcheck_parser_accepts_prefixed_terminal_lines() {
        let output = concat!(
            "> printf 'LOWERCASE_RENAME_POSTCHECK:{{\"target_dir\":\"%s\"}}\\n'\n",
            "> LOWERCASE_RENAME_POSTCHECK:{\"target_dir\":\"/tmp/a\",\"total_files\":1,\"uppercase_remaining\":0,\"final_names\":[\"a.txt\"]}\n",
        );
        let receipt = parse_lowercase_rename_postcheck_receipt(output).expect("receipt");
        assert_eq!(receipt.target_dir, "/tmp/a");
        assert_eq!(receipt.total_files, 1);
        assert_eq!(receipt.uppercase_remaining, 0);
    }

    #[test]
    fn lowercase_rename_postcheck_parser_handles_merged_echo_noise() {
        let output = concat!(
            "LOWERCASE_RENAME_POSTCHECK:{{\"target_dir\":\"%s\",\"total_files\":%d}}",
            "noise",
            "LOWERCASE_RENAME_POSTCHECK:{\"target_dir\":\"/tmp/c\",\"total_files\":3,\"uppercase_remaining\":0,\"final_names\":[\"a.txt\",\"b.txt\",\"c.txt\"]}",
            "tail"
        );
        let receipt = parse_lowercase_rename_postcheck_receipt(output).expect("receipt");
        assert_eq!(receipt.target_dir, "/tmp/c");
        assert_eq!(receipt.total_files, 3);
        assert_eq!(receipt.uppercase_remaining, 0);
        assert_eq!(
            receipt.final_names,
            vec![
                "a.txt".to_string(),
                "b.txt".to_string(),
                "c.txt".to_string()
            ]
        );
    }

    #[test]
    fn lowercase_rename_postcheck_parser_handles_json_with_braces_in_names() {
        let output = concat!(
            "LOWERCASE_RENAME_POSTCHECK:{\"target_dir\":\"/tmp/d\",\"total_files\":1,\"uppercase_remaining\":0,\"final_names\":[\"a{b}.txt\"]}\n"
        );
        let receipt = parse_lowercase_rename_postcheck_receipt(output).expect("receipt");
        assert_eq!(receipt.target_dir, "/tmp/d");
        assert_eq!(receipt.total_files, 1);
        assert_eq!(receipt.uppercase_remaining, 0);
        assert_eq!(receipt.final_names, vec!["a{b}.txt".to_string()]);
    }

    #[test]
    fn lowercase_rename_postcheck_discovery_counts_files_and_uppercase_names() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let target_dir = std::env::temp_dir().join(format!("ioi_lowercase_discovery_{}", stamp));
        fs::create_dir_all(&target_dir).expect("create temp target");
        fs::write(target_dir.join("A.TXT"), b"a").expect("write A.TXT");
        fs::write(target_dir.join("b.txt"), b"b").expect("write b.txt");
        fs::write(target_dir.join("C File.MD"), b"c").expect("write C File.MD");
        let nested = target_dir.join("UPPERDIR");
        fs::create_dir_all(&nested).expect("create nested dir");
        fs::write(nested.join("NESTED.TXT"), b"n").expect("write nested file");

        let receipt = discover_lowercase_rename_postcheck(&target_dir.to_string_lossy())
            .expect("discovery receipt");

        assert_eq!(receipt.target_dir, target_dir.to_string_lossy());
        assert_eq!(receipt.total_files, 3);
        assert_eq!(receipt.uppercase_remaining, 2);
        assert_eq!(
            receipt.final_names,
            vec![
                "A.TXT".to_string(),
                "C File.MD".to_string(),
                "b.txt".to_string()
            ]
        );

        let _ = fs::remove_dir_all(&target_dir);
    }

    #[test]
    fn lowercase_rename_postcheck_discovery_errors_for_missing_directory() {
        let missing = std::env::temp_dir().join(format!(
            "ioi_lowercase_missing_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let result = discover_lowercase_rename_postcheck(&missing.to_string_lossy());
        assert!(result.is_err());
    }

    #[test]
    fn command_history_lowercase_postcheck_reads_receipt() {
        let history = CommandExecution {
            command: "bash -lc rename".to_string(),
            exit_code: 0,
            stdout: "LOWERCASE_RENAME_POSTCHECK:{\"target_dir\":\"/tmp/b\",\"total_files\":2,\"uppercase_remaining\":0,\"final_names\":[\"a.txt\",\"b.txt\"]}".to_string(),
            stderr: String::new(),
            timestamp_ms: 1,
            step_index: 1,
        };
        let receipt = command_history_lowercase_rename_postcheck(&history).expect("receipt");
        assert_eq!(receipt.target_dir, "/tmp/b");
        assert_eq!(receipt.total_files, 2);
    }

    #[test]
    fn command_history_parser_prefers_latest_valid_payload_with_noise() {
        let older = CommandExecution {
            command: "echo older".to_string(),
            exit_code: 1,
            stdout: "old".to_string(),
            stderr: String::new(),
            timestamp_ms: 1,
            step_index: 1,
        };
        let newer = CommandExecution {
            command: "bash -s".to_string(),
            exit_code: 0,
            stdout: "LOWERCASE_RENAME_POSTCHECK:{\"target_dir\":\"/tmp/d\",\"total_files\":1,\"uppercase_remaining\":0,\"final_names\":[\"a.txt\"]}".to_string(),
            stderr: String::new(),
            timestamp_ms: 2,
            step_index: 2,
        };

        let output = format!(
            "noise {}{} tail\n> {}{}\u{001b}[0m",
            COMMAND_HISTORY_PREFIX,
            serde_json::to_string(&older).expect("serialize older"),
            COMMAND_HISTORY_PREFIX,
            serde_json::to_string(&newer).expect("serialize newer"),
        );

        let parsed = command_history_entry(&output).expect("parse latest command history");
        assert_eq!(parsed.command, "bash -s");
        assert_eq!(parsed.step_index, 2);
        assert_eq!(command_history_exit_code(&output), Some(0));
    }

    #[test]
    fn provider_selection_home_lint_flags_foreign_linux_home_owner() {
        let tool = AgentTool::SysExec {
            command: "mkdir".to_string(),
            args: vec!["-p".to_string(), "/home/user/Desktop/Projects".to_string()],
            stdin: None,
            detach: false,
        };

        let evidence = detect_foreign_home_path_for_runtime_home(&tool, "/home/heathledger")
            .expect("foreign home directory evidence");
        assert_eq!(evidence.runtime_home_owner, "heathledger");
        assert_eq!(evidence.payload_home_owner, "user");
        assert_eq!(
            evidence.payload_home_directory,
            "/home/user/Desktop/Projects"
        );
    }

    #[test]
    fn provider_selection_home_lint_allows_runtime_home_owner_match() {
        let tool = AgentTool::SysExec {
            command: "mkdir".to_string(),
            args: vec![
                "-p".to_string(),
                "/home/heathledger/Desktop/Projects".to_string(),
            ],
            stdin: None,
            detach: false,
        };

        assert!(detect_foreign_home_path_for_runtime_home(&tool, "/home/heathledger").is_none());
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
    fn terminal_reply_composer_passthrough_when_not_pdf_path_dense() {
        let summary = "Opened browser and navigated to search results.";
        let outcome = compose_terminal_chat_reply(summary);

        assert!(!outcome.applied);
        assert!(outcome.validator_passed);
        assert_eq!(outcome.output, summary);
        assert_eq!(outcome.template_id, "passthrough");
    }

    #[test]
    fn enrich_summary_uses_lowercase_contract_receipts_over_raw_stdout() {
        let mut state =
            test_agent_state_with_goal("Rename every file in my Downloads folder to lowercase.");
        state.resolved_intent = Some(test_resolved_intent(IntentScopeProfile::CommandExecution));
        mark_execution_receipt(
            &mut state.tool_execution_log,
            LOWERCASE_RENAME_CONTRACT_REQUIRED_RECEIPT,
        );
        mark_execution_postcondition(
            &mut state.tool_execution_log,
            LOWERCASE_RENAME_POSTCONDITION,
        );
        mark_execution_receipt_with_value(
            &mut state.tool_execution_log,
            LOWERCASE_RENAME_TARGET_DIR_RECEIPT,
            "/home/heathledger/Downloads".to_string(),
        );
        mark_execution_receipt_with_value(
            &mut state.tool_execution_log,
            LOWERCASE_RENAME_TOTAL_FILES_RECEIPT,
            "73".to_string(),
        );
        mark_execution_receipt_with_value(
            &mut state.tool_execution_log,
            LOWERCASE_RENAME_UPPERCASE_REMAINING_RECEIPT,
            "0".to_string(),
        );
        state.command_history.push_back(CommandExecution {
            command: "bash -s".to_string(),
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            timestamp_ms: 1_772_304_000_000,
            step_index: 1,
        });

        let enriched = enrich_command_scope_summary("phone-preview.mp4", &state);
        assert!(enriched.contains("All files in the Downloads folder are lowercase."));
        assert!(enriched.contains("Files checked: 73."));
        assert!(enriched.contains("Run timestamp (UTC):"));
        assert!(!enriched.contains("phone-preview.mp4"));
    }
}
