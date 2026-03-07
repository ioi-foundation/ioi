use super::support::{
    execution_receipt_value, has_execution_postcondition, has_execution_receipt,
    mark_execution_receipt, mark_execution_receipt_with_value, postcondition_marker,
    receipt_marker,
};
use crate::agentic::desktop::types::{AgentState, CommandExecution, ToolCallStatus};
use crate::agentic::rules::ActionRules;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::{
    AgentTool, IntentMatrixEntry, IntentRoutingPolicy, IntentScopeProfile,
};
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
pub const TIMER_SLEEP_BACKEND_POSTCONDITION: &str = "timer_sleep_backend";
pub const TIMER_NOTIFICATION_PATH_POSTCONDITION: &str = "notification_path_armed";
pub const TIMER_NOTIFICATION_CONTRACT_REQUIRED_RECEIPT: &str =
    "timer_notification_contract_required";
pub const WEB_PIPELINE_TERMINAL_RECEIPT: &str = "web_pipeline_terminal";
pub const PROVIDER_SELECTION_COMMIT_RECEIPT: &str = "provider_selection_commit";
pub const VERIFICATION_COMMIT_RECEIPT: &str = "verification_commit";
const COMMAND_SCOPE_REQUIRED_RECEIPTS: [&str; 3] =
    ["provider_selection", "execution", "verification"];
const COMMAND_SCOPE_REQUIRED_POSTCONDITIONS: [&str; 1] = ["execution_artifact"];
pub const CLOCK_TIMESTAMP_POSTCONDITION: &str = "clock_timestamp_observed";
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
    "rrsa_approval_token_ref",
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
    pub fallback_reason: Option<&'static str>,
}

#[allow(unused_imports)]
pub use environment::{
    runtime_desktop_directory, runtime_home_directory, runtime_host_environment_receipt,
    sys_exec_foreign_absolute_home_path, ForeignHomePathEvidence, HostEnvironmentReceipt,
};
pub use history::{append_command_history_entry, command_history_entry, command_history_exit_code};

include!("command_contract/contract_resolution.rs");

pub fn is_command_execution_provider_tool(tool: &AgentTool) -> bool {
    matches!(
        tool,
        AgentTool::SysExec { .. }
            | AgentTool::SysExecSession { .. }
            | AgentTool::SysInstallPackage { .. }
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

fn append_unique_marker(values: &mut Vec<String>, marker: &str) {
    if !values.iter().any(|value| value == marker) {
        values.push(marker.to_string());
    }
}

fn rrsa_required_receipts(agent_state: &AgentState) -> Vec<String> {
    let mut required = Vec::<String>::new();
    let Some(domain_raw) = execution_receipt_value(&agent_state.tool_execution_log, "rrsa_domain")
    else {
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
        PROVIDER_SELECTION_COMMIT_RECEIPT | VERIFICATION_COMMIT_RECEIPT
    ) || receipt.ends_with("_commit")
}

fn push_unique_missing(missing: &mut Vec<String>, marker: String) {
    if !missing.iter().any(|existing| existing == &marker) {
        missing.push(marker);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        compose_terminal_chat_reply, enrich_command_scope_summary,
        execution_contract_violation_error, is_command_execution_provider_tool,
        missing_execution_contract_markers_with_rules, record_verification_receipts,
        synthesize_allowlisted_timer_notification_tool,
        timer_payload_requires_allowlisted_scheduler, VERIFICATION_COMMIT_RECEIPT,
        WEB_PIPELINE_TERMINAL_RECEIPT,
    };
    use crate::agentic::desktop::service::step::action::support::{
        mark_execution_postcondition, mark_execution_receipt, mark_execution_receipt_with_value,
    };
    use crate::agentic::desktop::types::{
        AgentMode, AgentState, AgentStatus, CommandExecution, ExecutionTier, ToolCallStatus,
    };
    use crate::agentic::rules::ActionRules;
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
            planner_state: None,
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

    fn resolved_intent(intent_id: &str, scope: IntentScopeProfile) -> ResolvedIntentState {
        ResolvedIntentState {
            intent_id: intent_id.to_string(),
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

    fn command_scope_intent(intent_id: &str) -> ResolvedIntentState {
        resolved_intent(intent_id, IntentScopeProfile::CommandExecution)
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

    #[test]
    fn enrich_summary_normalizes_runtime_home_paths_for_non_command_scope() {
        let mut state = test_agent_state();
        state.resolved_intent = Some(resolved_intent(
            "workspace.ops",
            IntentScopeProfile::WorkspaceOps,
        ));
        let previous_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", "/tmp/ioi-fixture/home");

        let enriched = enrich_command_scope_summary(
            "Moved files to ~/Downloads/ioi_lowercase_123 and /home/Downloads/ioi_lowercase_123",
            &state,
        );
        let expected = "/tmp/ioi-fixture/home/Downloads/ioi_lowercase_123";
        assert_eq!(enriched.matches(expected).count(), 2);
        assert!(!enriched.contains("~/Downloads/ioi_lowercase_123"));

        if let Some(value) = previous_home {
            std::env::set_var("HOME", value);
        } else {
            std::env::remove_var("HOME");
        }
    }

    #[test]
    fn enrich_summary_does_not_duplicate_existing_runtime_home_paths() {
        let mut state = test_agent_state();
        state.resolved_intent = Some(resolved_intent(
            "workspace.ops",
            IntentScopeProfile::WorkspaceOps,
        ));
        let previous_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", "/tmp/ioi-fixture/home");

        let input = "/tmp/ioi-fixture/home/Documents/report.pdf";
        let enriched = enrich_command_scope_summary(input, &state);
        assert_eq!(enriched, input);

        if let Some(value) = previous_home {
            std::env::set_var("HOME", value);
        } else {
            std::env::remove_var("HOME");
        }
    }

    #[test]
    fn command_probe_rrs_does_not_require_topology_receipts() {
        let mut state = test_agent_state();
        state.resolved_intent = Some(command_scope_intent("command.probe"));
        mark_execution_receipt(&mut state.tool_execution_log, "execution");
        mark_execution_receipt(&mut state.tool_execution_log, "verification");

        let rules = ActionRules::default();
        let missing = missing_execution_contract_markers_with_rules(&state, &rules);

        assert!(
            missing.is_empty(),
            "expected no missing markers, got {missing:?}"
        );
    }

    #[test]
    fn app_launch_rrs_requires_topology_receipts() {
        let mut state = test_agent_state();
        state.resolved_intent = Some(resolved_intent("app.launch", IntentScopeProfile::AppLaunch));
        mark_execution_receipt(&mut state.tool_execution_log, "execution");
        mark_execution_receipt(&mut state.tool_execution_log, "verification");

        let rules = ActionRules::default();
        let missing = missing_execution_contract_markers_with_rules(&state, &rules);

        assert!(missing.contains(&"receipt::host_discovery=true".to_string()));
        assert!(missing.contains(&"receipt::provider_selection=true".to_string()));
    }

    #[test]
    fn rrsa_network_domain_enforces_domain_binding_at_completion_gate() {
        let mut state = test_agent_state();
        state.resolved_intent = Some(command_scope_intent("command.probe"));
        mark_execution_receipt(&mut state.tool_execution_log, "execution");
        mark_execution_receipt(&mut state.tool_execution_log, "verification");
        mark_execution_receipt_with_value(
            &mut state.tool_execution_log,
            "rrsa_request_binding",
            "sha256:abc".to_string(),
        );
        mark_execution_receipt_with_value(
            &mut state.tool_execution_log,
            "rrsa_firewall_decision",
            "sha256:def".to_string(),
        );
        mark_execution_receipt_with_value(
            &mut state.tool_execution_log,
            "rrsa_domain",
            "network_web".to_string(),
        );
        mark_execution_receipt_with_value(
            &mut state.tool_execution_log,
            "rrsa_output_commitment",
            "sha256:123".to_string(),
        );

        let rules = ActionRules::default();
        let missing = missing_execution_contract_markers_with_rules(&state, &rules);
        assert!(missing.contains(&"receipt::rrsa_domain_binding=true".to_string()));
    }

    #[test]
    fn rrsa_wallet_domain_enforces_tx_approval_and_eei_bindings() {
        let mut state = test_agent_state();
        state.resolved_intent = Some(command_scope_intent("command.probe"));
        mark_execution_receipt(&mut state.tool_execution_log, "execution");
        mark_execution_receipt(&mut state.tool_execution_log, "verification");
        mark_execution_receipt_with_value(
            &mut state.tool_execution_log,
            "rrsa_request_binding",
            "sha256:abc".to_string(),
        );
        mark_execution_receipt_with_value(
            &mut state.tool_execution_log,
            "rrsa_firewall_decision",
            "sha256:def".to_string(),
        );
        mark_execution_receipt_with_value(
            &mut state.tool_execution_log,
            "rrsa_domain",
            "wallet".to_string(),
        );
        mark_execution_receipt_with_value(
            &mut state.tool_execution_log,
            "rrsa_tx_hash_binding",
            "sha256:tx".to_string(),
        );

        let rules = ActionRules::default();
        let missing = missing_execution_contract_markers_with_rules(&state, &rules);
        assert!(missing.contains(&"receipt::rrsa_approval_token_ref=true".to_string()));
        assert!(missing.contains(&"receipt::rrsa_eei_bundle_commitment=true".to_string()));
    }

    #[test]
    fn pending_web_pipeline_requires_terminal_receipt_at_completion_gate() {
        let mut state = test_agent_state();
        state.pending_search_completion = Some(Default::default());

        let rules = ActionRules::default();
        let missing = missing_execution_contract_markers_with_rules(&state, &rules);

        assert!(missing.contains(&format!("receipt::{}=true", WEB_PIPELINE_TERMINAL_RECEIPT)));
    }

    #[test]
    fn pending_web_pipeline_terminal_receipt_clears_completion_gate_requirement() {
        let mut state = test_agent_state();
        state.pending_search_completion = Some(Default::default());
        mark_execution_receipt(&mut state.tool_execution_log, WEB_PIPELINE_TERMINAL_RECEIPT);

        let rules = ActionRules::default();
        let missing = missing_execution_contract_markers_with_rules(&state, &rules);

        assert!(
            !missing.contains(&format!("receipt::{}=true", WEB_PIPELINE_TERMINAL_RECEIPT)),
            "unexpected missing markers: {missing:?}"
        );
    }

    #[test]
    fn timer_payload_scheduler_rewrite_covers_foreground_sleep_notify_chain() {
        let tool = AgentTool::SysExecSession {
            command: "sleep 900 && notify-send 'Timer' '15 minutes are up!'".to_string(),
            args: vec![],
            stdin: None,
        };

        assert!(timer_payload_requires_allowlisted_scheduler(&tool));
        let rewritten = synthesize_allowlisted_timer_notification_tool(&tool)
            .expect("sleep-backed timer chain should synthesize a scheduler-backed payload");

        match rewritten {
            AgentTool::SysExecSession { command, args, .. } => {
                assert_eq!(command, "systemd-run");
                assert!(args.iter().any(|arg| arg == "--user"));
                assert!(args.iter().any(|arg| arg == "--on-active=900s"));
                assert!(args.iter().any(|arg| arg == "notify-send"));
            }
            other => panic!("unexpected rewritten tool: {other:?}"),
        }
    }

    #[test]
    fn detached_deferred_sleep_timer_does_not_require_scheduler_rewrite() {
        let tool = AgentTool::SysExec {
            command: "bash".to_string(),
            args: vec![
                "-lc".to_string(),
                "nohup sh -c 'sleep 900 && notify-send Timer Done' &".to_string(),
            ],
            stdin: None,
            detach: true,
        };

        assert!(!timer_payload_requires_allowlisted_scheduler(&tool));
    }
}
