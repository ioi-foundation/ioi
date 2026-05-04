use crate::kernel::thresholds;
use crate::models::{AgentEvent, AgentPhase, AgentTask, AppState, EventStatus, EventType};
use std::sync::Mutex;
use tauri::Manager;

pub(super) const CLARIFICATION_WAIT_STEP: &str = "Waiting for clarification on target identity.";
pub(super) const LEGACY_CLARIFICATION_WAIT_STEP: &str =
    "Waiting for user clarification on app/package name.";
pub(super) const LEGACY_INSTALL_CLARIFICATION_STEP: &str = "Waiting for install clarification";
pub(super) const INTENT_CLARIFICATION_WAIT_STEP: &str = "Waiting for intent clarification.";
pub(super) const WAIT_FOR_CLARIFICATION_PROMPT: &str =
    "System: WAIT_FOR_CLARIFICATION. Target identity could not be resolved. Provide clarification input to continue.";
pub(super) const WAIT_FOR_INTENT_CLARIFICATION_PROMPT: &str =
    "System: WAIT_FOR_INTENT_CLARIFICATION. Intent confidence is too low to proceed safely. Please clarify the requested outcome.";
// This signature already means the model retried an invalid non-command tool path
// and immediately hit a duplicate no-op against a prior success, so waiting for
// multiple repeats only prolongs an obviously stalled loop.
const DUPLICATE_NOOP_INTENT_CLARIFICATION_THRESHOLD: usize = 1;

pub(super) fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn normalize_session_id(value: &str) -> String {
    value
        .trim()
        .trim_start_matches("0x")
        .replace('-', "")
        .to_ascii_lowercase()
}

pub(super) fn bind_task_session(task: &mut AgentTask, incoming_session_id: &str) {
    if incoming_session_id.trim().is_empty() {
        return;
    }

    match task.session_id.as_deref() {
        None => {
            task.session_id = Some(incoming_session_id.to_string());
        }
        Some(existing) => {
            let existing_norm = normalize_session_id(existing);
            let incoming_norm = normalize_session_id(incoming_session_id);
            if existing_norm.is_empty() || existing_norm == incoming_norm {
                task.session_id = Some(incoming_session_id.to_string());
            }
        }
    }
}

pub(super) fn thread_id_from_session(app: &tauri::AppHandle, session_id: &str) -> String {
    let state = app.state::<Mutex<AppState>>();
    if let Ok(guard) = state.lock() {
        if let Some(task) = &guard.current_task {
            return task.session_id.clone().unwrap_or_else(|| task.id.clone());
        }
    }
    if !session_id.is_empty() {
        return session_id.to_string();
    }
    "unknown-thread".to_string()
}

pub(super) fn snippet(text: &str) -> String {
    thresholds::trim_excerpt(text, 4, 320)
}

pub(super) fn collect_urls(text: &str, limit: usize) -> Vec<String> {
    let mut out = Vec::new();
    for token in text.split_whitespace() {
        let normalized = token
            .trim_matches(|c: char| ",.;:()[]{}<>\"'`".contains(c))
            .to_string();
        if normalized.starts_with("http://") || normalized.starts_with("https://") {
            if !out.iter().any(|u| u == &normalized) {
                out.push(normalized);
            }
        }
        if out.len() >= limit {
            break;
        }
    }
    out
}

pub(super) fn event_status_from_agent_status(agent_status: &str) -> EventStatus {
    match agent_status {
        "Failed" => EventStatus::Failure,
        "Paused" => EventStatus::Partial,
        _ => EventStatus::Success,
    }
}

pub(super) fn event_type_for_tool(tool_name: &str) -> EventType {
    let t = tool_name.to_lowercase();
    if t.contains("browser__navigate") || t.contains("browser::navigate") {
        EventType::BrowserNavigate
    } else if t.contains("browser__inspect") || t.contains("browser::inspect") {
        EventType::BrowserSnapshot
    } else if t.contains("search")
        || t.contains("grep")
        || t.contains("ripgrep")
        || t == "rg"
        || t.contains("find")
    {
        EventType::CodeSearch
    } else if t.contains("test") || t.contains("pytest") || t.contains("cargo test") {
        EventType::TestRun
    } else if t.contains("edit")
        || t.contains("patch")
        || t.contains("write")
        || t.contains("replace")
    {
        EventType::FileEdit
    } else if t.contains("read") || t.contains("cat") {
        EventType::FileRead
    } else {
        EventType::CommandRun
    }
}

pub(super) fn is_software_install_tool(tool_name: &str) -> bool {
    let tool = tool_name.to_ascii_lowercase();
    matches!(
        tool.as_str(),
        "software_install__resolve" | "software_install__execute_plan"
    )
}

pub(super) fn is_sudo_password_required_install(tool_name: &str, output: &str) -> bool {
    if !is_software_install_tool(tool_name) {
        return false;
    }
    let text = output.to_ascii_lowercase();
    let package_lookup_failure = text.contains("unable to locate package")
        || text.contains("no match for argument")
        || text.contains("has no installation candidate")
        || text.contains("cannot find a package");
    if package_lookup_failure {
        return false;
    }
    text.contains("sudo:")
        || text.contains("a password is required")
        || text.contains("not in the sudoers")
        || text.contains("incorrect password")
        || text.contains("sorry, try again")
        || (text.contains("error_class=permissionorapprovalrequired") && text.contains("sudo"))
}

pub(super) fn is_software_install_lookup_failure(tool_name: &str, output: &str) -> bool {
    if !is_software_install_tool(tool_name) {
        return false;
    }
    let text = output.to_ascii_lowercase();
    text.contains("unable to locate package")
        || text.contains("no match for argument")
        || text.contains("has no installation candidate")
        || text.contains("cannot find a package")
        || text.contains("error_class=missingdependency")
}

pub(super) fn is_launch_app_lookup_failure(tool_name: &str, output: &str) -> bool {
    let tool = tool_name.to_ascii_lowercase();
    if tool != "app__launch" && tool != "os::launch_app" && !tool.ends_with("launch_app") {
        return false;
    }
    let text = output.to_ascii_lowercase();
    let marker_launch_miss =
        text.contains("error_class=toolunavailable") && text.contains("failed to launch");
    let detailed_launch_miss = text.contains("failed to launch")
        && (text.contains("no such file")
            || text.contains("not found")
            || text.contains("unable to locate")
            || text.contains("cannot find")
            || text.contains("gtk-launch"));
    let no_installed_target = text.contains("resolution_outcome=noinstalledtarget");
    marker_launch_miss || detailed_launch_miss || no_installed_target
}

pub(super) fn launch_lookup_requires_install_prompt(output: &str) -> bool {
    let text = output.to_ascii_lowercase();
    text.contains("resolution_outcome=noinstalledtarget")
        || text.contains("install_action=promptinstallorprovideidentifier")
}

#[derive(Clone, Copy)]
pub(super) enum ClarificationPreset {
    IdentityLookup,
    InstallLookup,
    LaunchLookup,
    IntentClarification,
}

pub(super) fn explicit_clarification_preset_for_tool(
    tool_name: &str,
) -> Option<ClarificationPreset> {
    let tool = tool_name.to_ascii_lowercase();
    if tool == "system::intent_clarification"
        || tool == "system__intent_clarification"
        || tool.ends_with("intent_clarification")
        || tool == "system::locality_clarification"
        || tool == "system__locality_clarification"
        || tool.ends_with("locality_clarification")
    {
        return Some(ClarificationPreset::IntentClarification);
    }
    None
}

pub(super) fn clarification_preset_for_tool(tool_name: &str) -> Option<ClarificationPreset> {
    if let Some(preset) = explicit_clarification_preset_for_tool(tool_name) {
        return Some(preset);
    }
    if is_software_install_tool(tool_name) {
        return Some(ClarificationPreset::InstallLookup);
    }
    let tool = tool_name.to_ascii_lowercase();
    if tool == "app__launch" || tool == "os::launch_app" || tool.ends_with("launch_app") {
        return Some(ClarificationPreset::LaunchLookup);
    }
    None
}

pub(super) fn detect_clarification_preset(
    tool_name: &str,
    output: &str,
) -> Option<ClarificationPreset> {
    if is_software_install_lookup_failure(tool_name, output) {
        return Some(ClarificationPreset::InstallLookup);
    }
    if is_launch_app_lookup_failure(tool_name, output) {
        return Some(ClarificationPreset::LaunchLookup);
    }
    if is_locality_scope_clarification(output) {
        return Some(ClarificationPreset::IntentClarification);
    }
    if is_intent_clarification_pause(output) {
        return Some(ClarificationPreset::IntentClarification);
    }
    None
}

pub(super) fn is_identity_resolution_kind(kind: &str) -> bool {
    kind.eq_ignore_ascii_case("identity_resolution")
        || kind.eq_ignore_ascii_case("tool_lookup")
        || kind.eq_ignore_ascii_case("software_install_lookup")
        || kind.eq_ignore_ascii_case("intent_resolution")
        || kind.eq_ignore_ascii_case("locality_resolution")
}

pub(super) fn is_waiting_for_identity_clarification_step(step: &str) -> bool {
    step.eq_ignore_ascii_case(CLARIFICATION_WAIT_STEP)
        || step.eq_ignore_ascii_case(LEGACY_CLARIFICATION_WAIT_STEP)
        || step.eq_ignore_ascii_case(LEGACY_INSTALL_CLARIFICATION_STEP)
        || step.eq_ignore_ascii_case(INTENT_CLARIFICATION_WAIT_STEP)
        || step.eq_ignore_ascii_case("Waiting for intent clarification")
}

pub(super) fn clarification_wait_step_for_preset(preset: ClarificationPreset) -> &'static str {
    match preset {
        ClarificationPreset::IdentityLookup
        | ClarificationPreset::InstallLookup
        | ClarificationPreset::LaunchLookup => CLARIFICATION_WAIT_STEP,
        ClarificationPreset::IntentClarification => INTENT_CLARIFICATION_WAIT_STEP,
    }
}

pub(super) fn clarification_prompt_for_preset(preset: ClarificationPreset) -> &'static str {
    match preset {
        ClarificationPreset::IdentityLookup
        | ClarificationPreset::InstallLookup
        | ClarificationPreset::LaunchLookup => WAIT_FOR_CLARIFICATION_PROMPT,
        ClarificationPreset::IntentClarification => WAIT_FOR_INTENT_CLARIFICATION_PROMPT,
    }
}

fn has_verification_check(verification_checks: &[String], expected: &str) -> bool {
    verification_checks
        .iter()
        .any(|check| check.eq_ignore_ascii_case(expected))
}

fn recent_duplicate_non_command_noop_receipt_count_from_events(
    events: &[AgentEvent],
    tool_name: &str,
) -> usize {
    let mut count = 0;

    for event in events.iter().rev() {
        if event.event_type != EventType::Receipt {
            continue;
        }

        let event_tool = event
            .digest
            .get("tool_name")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        let checks = event
            .details
            .get("verification_checks")
            .and_then(|value| value.as_array())
            .map(|values| {
                values
                    .iter()
                    .filter_map(|value| value.as_str())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        if event_tool.eq_ignore_ascii_case(tool_name)
            && checks.iter().any(|check| {
                check.eq_ignore_ascii_case("duplicate_action_fingerprint_non_command_skipped=true")
            })
            && checks.iter().any(|check| {
                check.eq_ignore_ascii_case("duplicate_action_fingerprint_prior_success_noop=true")
            })
            && checks
                .iter()
                .any(|check| check.eq_ignore_ascii_case("invalid_tool_call_repair_attempted=true"))
        {
            count += 1;
            continue;
        }

        break;
    }

    count
}

pub(super) fn duplicate_noop_loop_requires_intent_clarification(
    task: &AgentTask,
    tool_name: &str,
    verification_checks: &[String],
) -> bool {
    duplicate_noop_loop_requires_intent_clarification_from_events(
        &task.events,
        tool_name,
        verification_checks,
    )
}

pub(super) fn duplicate_noop_loop_requires_intent_clarification_from_events(
    events: &[AgentEvent],
    tool_name: &str,
    verification_checks: &[String],
) -> bool {
    if !has_verification_check(
        verification_checks,
        "duplicate_action_fingerprint_non_command_skipped=true",
    ) || !has_verification_check(
        verification_checks,
        "duplicate_action_fingerprint_prior_success_noop=true",
    ) || !has_verification_check(
        verification_checks,
        "invalid_tool_call_repair_attempted=true",
    ) {
        return false;
    }

    recent_duplicate_non_command_noop_receipt_count_from_events(events, tool_name) + 1
        >= DUPLICATE_NOOP_INTENT_CLARIFICATION_THRESHOLD
}

fn is_intent_clarification_pause(output: &str) -> bool {
    let text = output.to_ascii_lowercase();
    text.contains("wait_for_intent_clarification")
        || text.contains("waiting for intent clarification")
        || (text.contains("wait_for_clarification") && text.contains("intent"))
}

fn is_locality_scope_clarification(output: &str) -> bool {
    let text = output.to_ascii_lowercase();
    text.contains("wait_for_locality_scope")
        || text.contains("waiting for locality clarification")
        || (text.contains("locality") && text.contains("city/region"))
}

pub(crate) fn is_waiting_prompt_active(task: &AgentTask) -> bool {
    task.credential_request.is_some()
        || task.clarification_request.is_some()
        || task
            .current_step
            .eq_ignore_ascii_case("Waiting for sudo password")
        || is_waiting_for_identity_clarification_step(&task.current_step)
}

pub(super) fn is_hard_terminal_task(task: &AgentTask) -> bool {
    if task.phase == AgentPhase::Failed {
        return true;
    }
    if task.phase != AgentPhase::Complete {
        return false;
    }
    if task.current_step.eq_ignore_ascii_case("Ready for input") {
        return true;
    }
    if task.current_step.eq_ignore_ascii_case("Task completed") {
        return true;
    }
    task.receipt.is_some()
        && task.gate_info.is_none()
        && task.pending_request_hash.is_none()
        && !is_waiting_prompt_active(task)
}

pub(super) fn extract_missing_package_hint(output: &str) -> Option<String> {
    let lower = output.to_ascii_lowercase();
    let marker = "unable to locate package ";
    let idx = lower.find(marker)?;
    let token_start = idx + marker.len();
    let remainder = output.get(token_start..)?.trim();
    let raw = remainder.split_whitespace().next()?;
    let cleaned = raw
        .trim_matches(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'));
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned.to_string())
    }
}

pub(super) fn extract_launch_target_hint(output: &str) -> Option<String> {
    let lower = output.to_ascii_lowercase();
    let marker = "failed to launch ";
    let idx = lower.find(marker)?;
    let token_start = idx + marker.len();
    let remainder = output.get(token_start..)?.trim();
    let raw = remainder
        .split('|')
        .next()
        .unwrap_or(remainder)
        .split(':')
        .next()
        .unwrap_or(remainder)
        .split_whitespace()
        .next()
        .unwrap_or(remainder)
        .trim();
    let cleaned = raw.trim_matches(|c: char| {
        !(c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '/' || c == ':')
    });
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned.to_string())
    }
}

#[cfg(test)]
#[path = "support/tests.rs"]
mod tests;
