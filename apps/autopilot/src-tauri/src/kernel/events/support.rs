use crate::kernel::thresholds;
use crate::models::{AgentPhase, AgentTask, AppState, EventStatus, EventType};
use std::sync::Mutex;
use tauri::Manager;

pub(super) const CLARIFICATION_WAIT_STEP: &str = "Waiting for clarification on target identity.";
pub(super) const LEGACY_CLARIFICATION_WAIT_STEP: &str =
    "Waiting for user clarification on app/package name.";
pub(super) const LEGACY_INSTALL_CLARIFICATION_STEP: &str = "Waiting for install clarification";
pub(super) const WAIT_FOR_CLARIFICATION_PROMPT: &str =
    "System: WAIT_FOR_CLARIFICATION. Target identity could not be resolved. Provide clarification input to continue.";

pub(super) fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

pub(super) fn thread_id_from_session(app: &tauri::AppHandle, session_id: &str) -> String {
    if !session_id.is_empty() {
        return session_id.to_string();
    }
    let state = app.state::<Mutex<AppState>>();
    if let Ok(guard) = state.lock() {
        if let Some(task) = &guard.current_task {
            return task.session_id.clone().unwrap_or_else(|| task.id.clone());
        }
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
    } else if t.contains("browser__extract") || t.contains("browser::extract") {
        EventType::BrowserExtract
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

pub(super) fn is_install_package_tool(tool_name: &str) -> bool {
    let tool = tool_name.to_ascii_lowercase();
    tool == "sys__install_package"
        || tool == "sys::install_package"
        || tool.ends_with("install_package")
}

pub(super) fn is_sudo_password_required_install(tool_name: &str, output: &str) -> bool {
    if !is_install_package_tool(tool_name) {
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

pub(super) fn is_install_package_lookup_failure(tool_name: &str, output: &str) -> bool {
    if !is_install_package_tool(tool_name) {
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
    if tool != "os__launch_app" && tool != "os::launch_app" && !tool.ends_with("launch_app") {
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
    marker_launch_miss || detailed_launch_miss
}

#[derive(Clone, Copy)]
pub(super) enum ClarificationPreset {
    IdentityLookup,
    InstallLookup,
    LaunchLookup,
}

pub(super) fn clarification_preset_for_tool(tool_name: &str) -> Option<ClarificationPreset> {
    if is_install_package_tool(tool_name) {
        return Some(ClarificationPreset::InstallLookup);
    }
    let tool = tool_name.to_ascii_lowercase();
    if tool == "os__launch_app" || tool == "os::launch_app" || tool.ends_with("launch_app") {
        return Some(ClarificationPreset::LaunchLookup);
    }
    None
}

pub(super) fn detect_clarification_preset(
    tool_name: &str,
    output: &str,
) -> Option<ClarificationPreset> {
    if is_install_package_lookup_failure(tool_name, output) {
        return Some(ClarificationPreset::InstallLookup);
    }
    if is_launch_app_lookup_failure(tool_name, output) {
        return Some(ClarificationPreset::LaunchLookup);
    }
    None
}

pub(super) fn is_identity_resolution_kind(kind: &str) -> bool {
    kind.eq_ignore_ascii_case("identity_resolution")
        || kind.eq_ignore_ascii_case("tool_lookup")
        || kind.eq_ignore_ascii_case("install_package_lookup")
}

pub(super) fn is_waiting_for_identity_clarification_step(step: &str) -> bool {
    step.eq_ignore_ascii_case(CLARIFICATION_WAIT_STEP)
        || step.eq_ignore_ascii_case(LEGACY_CLARIFICATION_WAIT_STEP)
        || step.eq_ignore_ascii_case(LEGACY_INSTALL_CLARIFICATION_STEP)
}

pub(super) fn is_waiting_prompt_active(task: &AgentTask) -> bool {
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
