use crate::kernel::{session, state};
use crate::models::{AppState, SessionServerSessionRecord, SessionServerSnapshot, SessionSummary};
use crate::orchestrator;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tauri::State;

fn normalize_optional_text(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn workspace_root_from_task(task: &crate::models::AgentTask) -> Option<String> {
    task.build_session
        .as_ref()
        .map(|session| session.workspace_root.clone())
        .or_else(|| {
            task.renderer_session
                .as_ref()
                .map(|session| session.workspace_root.clone())
        })
        .or_else(|| {
            task.chat_session
                .as_ref()
                .and_then(|session| session.workspace_root.clone())
        })
}

fn load_local_sessions(
    memory_runtime: Option<&Arc<ioi_memory::MemoryRuntime>>,
) -> Vec<SessionSummary> {
    memory_runtime
        .map(orchestrator::get_local_sessions)
        .unwrap_or_default()
}

fn continuity_mode_label(target: &state::KernelRpcTarget) -> String {
    if target.remote_hint {
        "Explicit remote kernel".to_string()
    } else if target.configured {
        "Explicit kernel target".to_string()
    } else {
        "Default local kernel".to_string()
    }
}

fn continuity_status_label(
    target: &state::KernelRpcTarget,
    kernel_reachable: bool,
    remote_history_available: bool,
    remote_only_session_count: usize,
) -> String {
    if !kernel_reachable && target.configured {
        return "Configured but unreachable".to_string();
    }
    if !kernel_reachable {
        return "Kernel unavailable".to_string();
    }
    if remote_history_available && remote_only_session_count > 0 {
        return "Remote history merged".to_string();
    }
    if remote_history_available {
        return "Server continuity live".to_string();
    }
    if target.remote_hint {
        return "Remote kernel connected".to_string();
    }
    "Kernel connected".to_string()
}

fn continuity_detail(
    target: &state::KernelRpcTarget,
    kernel_reachable: bool,
    remote_history_available: bool,
    remote_only_session_count: usize,
    remote_error: Option<&str>,
) -> String {
    if !kernel_reachable {
        let detail = remote_error
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("The kernel RPC target could not be reached.");
        if target.configured {
            return format!(
                "The shell is configured against {} but continuity is currently offline: {}",
                target.source_label, detail
            );
        }
        return format!(
            "The default kernel RPC target is unavailable, so only retained local state is visible right now: {}",
            detail
        );
    }

    if remote_history_available && remote_only_session_count > 0 {
        return format!(
            "{} remote-only retained session{} are being merged into the shared session projection, so reset and shell hops can rehydrate work without inventing duplicate state.",
            remote_only_session_count,
            if remote_only_session_count == 1 { "" } else { "s" }
        );
    }

    if remote_history_available {
        return "The kernel is reachable and remote session history is already flowing into the same retained projection used by Chat, retained sessions, and the standalone REPL."
            .to_string();
    }

    if target.remote_hint {
        return "The shell is pointed at a remote kernel target, but that server has not reported retained session history yet."
            .to_string();
    }

    "The shell is attached to the default kernel target, but remote-retained session history has not diverged from local state yet."
        .to_string()
}

fn kernel_connection_detail(
    target: &state::KernelRpcTarget,
    kernel_reachable: bool,
    remote_error: Option<&str>,
) -> String {
    if kernel_reachable {
        return format!(
            "{} is reachable through {}.",
            target.url, target.source_label
        );
    }

    let error = remote_error
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("transport unavailable");
    format!(
        "{} is currently unreachable through {}: {}",
        target.url, target.source_label, error
    )
}

fn session_has_workspace_root(summary: &SessionSummary) -> bool {
    summary
        .workspace_root
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some()
}

fn remote_session_presence(
    session_id: &str,
    local_session_ids: &HashSet<String>,
    attachable: bool,
) -> (&'static str, &'static str) {
    match (local_session_ids.contains(session_id), attachable) {
        (true, true) => ("merged_attachable", "Merged attachable"),
        (true, false) => ("merged_history_only", "Merged history only"),
        (false, true) => ("remote_only_attachable", "Remote-only attachable"),
        (false, false) => ("remote_only_history_only", "Remote-only history"),
    }
}

fn current_session_continuity(
    session_id: Option<&str>,
    remote_session_ids: &HashSet<String>,
    merged_lookup: &HashMap<String, &SessionSummary>,
) -> (String, String, String) {
    let Some(session_id) = session_id.map(str::trim).filter(|value| !value.is_empty()) else {
        return (
            "idle".to_string(),
            "No active session selected".to_string(),
            "Open or retain a session to inspect whether its remote continuity is mirrored, attachable, or history-only.".to_string(),
        );
    };

    if !remote_session_ids.contains(session_id) {
        return (
            "local_only".to_string(),
            "Current session local only".to_string(),
            "The active session is not visible in remote retained history yet, so shell hops would still rely on local continuity only.".to_string(),
        );
    }

    if merged_lookup
        .get(session_id)
        .map(|summary| session_has_workspace_root(summary))
        .unwrap_or(false)
    {
        return (
            "mirrored_attachable".to_string(),
            "Current session mirrored remotely".to_string(),
            "The active session is visible in remote retained history and still carries a workspace root, so Chat, retained sessions, and the standalone REPL can reopen the same remote-backed continuity target.".to_string(),
        );
    }

    (
        "mirrored_history_only".to_string(),
        "Current session mirrored as history".to_string(),
        "The active session is visible in remote retained history, but only summary continuity survived there; retain a workspace-backed run again before expecting PTY-backed remote attach.".to_string(),
    )
}

fn recent_remote_sessions(
    remote_sessions: &[SessionSummary],
    merged_sessions: &[SessionSummary],
    local_session_ids: &HashSet<String>,
) -> Vec<SessionServerSessionRecord> {
    let merged_lookup = merged_sessions
        .iter()
        .map(|summary| (summary.session_id.clone(), summary))
        .collect::<HashMap<_, _>>();
    let mut rows = remote_sessions
        .iter()
        .filter_map(|remote| {
            let merged = merged_lookup.get(&remote.session_id)?;
            let (presence_state, presence_label) = remote_session_presence(
                &merged.session_id,
                local_session_ids,
                session_has_workspace_root(merged),
            );
            Some(SessionServerSessionRecord {
                session_id: merged.session_id.clone(),
                title: merged.title.clone(),
                timestamp: merged.timestamp,
                source_label: if local_session_ids.contains(&remote.session_id) {
                    "Merged with local shell".to_string()
                } else {
                    "Remote-only history".to_string()
                },
                presence_state: presence_state.to_string(),
                presence_label: presence_label.to_string(),
                resume_hint: merged.resume_hint.clone(),
                workspace_root: merged.workspace_root.clone(),
            })
        })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| right.timestamp.cmp(&left.timestamp));
    rows.truncate(6);
    rows
}

fn build_server_snapshot(
    session_id: Option<String>,
    workspace_root: Option<String>,
    target: state::KernelRpcTarget,
    local_sessions: Vec<SessionSummary>,
    remote_sessions: Vec<SessionSummary>,
    remote_error: Option<String>,
) -> SessionServerSnapshot {
    let local_session_ids = local_sessions
        .iter()
        .map(|summary| summary.session_id.clone())
        .collect::<HashSet<_>>();
    let remote_session_ids = remote_sessions
        .iter()
        .map(|summary| summary.session_id.clone())
        .collect::<HashSet<_>>();
    let overlapping_session_count = remote_session_ids.intersection(&local_session_ids).count();
    let remote_only_session_count = remote_session_ids
        .len()
        .saturating_sub(overlapping_session_count);
    let mut merged_sessions = local_sessions.clone();
    session::merge_remote_session_history(&mut merged_sessions, remote_sessions.clone());
    merged_sessions.sort_by(|left, right| right.timestamp.cmp(&left.timestamp));
    let merged_lookup = merged_sessions
        .iter()
        .map(|summary| (summary.session_id.clone(), summary))
        .collect::<HashMap<_, _>>();
    let remote_attachable_session_count = remote_sessions
        .iter()
        .filter(|remote| {
            merged_lookup
                .get(&remote.session_id)
                .map(|summary| session_has_workspace_root(summary))
                .unwrap_or(false)
        })
        .count();
    let remote_history_only_session_count = remote_sessions
        .len()
        .saturating_sub(remote_attachable_session_count);

    let kernel_reachable = remote_error.is_none();
    let remote_history_available = !remote_sessions.is_empty();
    let continuity_mode_label = continuity_mode_label(&target);
    let continuity_status_label = continuity_status_label(
        &target,
        kernel_reachable,
        remote_history_available,
        remote_only_session_count,
    );
    let continuity_detail = continuity_detail(
        &target,
        kernel_reachable,
        remote_history_available,
        remote_only_session_count,
        remote_error.as_deref(),
    );
    let current_session_visible_remotely = session_id
        .as_ref()
        .map(|session_id| remote_session_ids.contains(session_id))
        .unwrap_or(false);
    let (
        current_session_continuity_state,
        current_session_continuity_label,
        current_session_continuity_detail,
    ) = current_session_continuity(session_id.as_deref(), &remote_session_ids, &merged_lookup);

    let mut notes = vec![format!("RPC target: {}", target.url)];
    notes.push(format!("Target source: {}", target.source_label));
    notes.push(format!(
        "{} local retained session{} visible before merge.",
        local_sessions.len(),
        if local_sessions.len() == 1 { "" } else { "s" }
    ));
    if remote_history_available {
        notes.push(format!(
            "{} remote retained session{} visible from the kernel history feed.",
            remote_sessions.len(),
            if remote_sessions.len() == 1 { "" } else { "s" }
        ));
        notes.push(format!(
            "{} remote session{} still carry workspace roots; {} are history-only.",
            remote_attachable_session_count,
            if remote_attachable_session_count == 1 {
                ""
            } else {
                "s"
            },
            remote_history_only_session_count
        ));
    }
    if current_session_visible_remotely {
        notes.push("The active session is visible in remote retained history.".to_string());
    }
    if let Some(error) = remote_error
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        notes.push(format!("Continuity warning: {}", error));
    }

    SessionServerSnapshot {
        generated_at_ms: state::now(),
        session_id,
        workspace_root,
        rpc_url: target.url.clone(),
        rpc_source_label: target.source_label.clone(),
        continuity_mode_label,
        continuity_status_label,
        continuity_detail,
        kernel_connection_label: if kernel_reachable {
            "Reachable".to_string()
        } else {
            "Unavailable".to_string()
        },
        kernel_connection_detail: kernel_connection_detail(
            &target,
            kernel_reachable,
            remote_error.as_deref(),
        ),
        explicit_rpc_target: target.configured,
        remote_kernel_target: target.remote_hint,
        kernel_reachable,
        remote_history_available,
        local_session_count: local_sessions.len(),
        remote_session_count: remote_sessions.len(),
        merged_session_count: merged_sessions.len(),
        remote_only_session_count,
        overlapping_session_count,
        remote_attachable_session_count,
        remote_history_only_session_count,
        current_session_visible_remotely,
        current_session_continuity_state,
        current_session_continuity_label,
        current_session_continuity_detail,
        notes,
        recent_remote_sessions: recent_remote_sessions(
            &remote_sessions,
            &merged_sessions,
            &local_session_ids,
        ),
    }
}

#[tauri::command]
pub async fn get_session_server_snapshot(
    state: State<'_, Mutex<AppState>>,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> Result<SessionServerSnapshot, String> {
    let requested_session_id = normalize_optional_text(session_id);
    let requested_workspace_root = normalize_optional_text(workspace_root);
    let (memory_runtime, current_task) = {
        let guard = state
            .lock()
            .map_err(|_| "Failed to lock app state.".to_string())?;
        (guard.memory_runtime.clone(), guard.current_task.clone())
    };

    let matched_task = current_task.as_ref().filter(|task| {
        requested_session_id
            .as_deref()
            .map(|session_id| {
                task.session_id
                    .as_deref()
                    .map(|task_session_id| session_id == task_session_id)
                    .unwrap_or(false)
                    || session_id == task.id
            })
            .unwrap_or(true)
    });
    let resolved_session_id = requested_session_id
        .or_else(|| matched_task.and_then(|task| task.session_id.clone()))
        .filter(|value| !value.trim().is_empty());
    let resolved_workspace_root = requested_workspace_root
        .or_else(|| matched_task.and_then(workspace_root_from_task))
        .filter(|value| !value.trim().is_empty());

    let local_sessions = load_local_sessions(memory_runtime.as_ref());
    let remote_result = session::fetch_remote_session_history(&state).await;
    let (remote_sessions, remote_error) = match remote_result {
        Ok(remote_sessions) => (remote_sessions, None),
        Err(error) => (Vec::new(), Some(error)),
    };

    Ok(build_server_snapshot(
        resolved_session_id,
        resolved_workspace_root,
        state::kernel_rpc_target(),
        local_sessions,
        remote_sessions,
        remote_error,
    ))
}

#[cfg(test)]
#[path = "server_mode/tests.rs"]
mod tests;
