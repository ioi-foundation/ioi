use crate::kernel::{data, state};
use crate::models::{
    AppState, LocalEngineEnvironmentBinding, SessionRemoteEnvBinding, SessionRemoteEnvSnapshot,
};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use tauri::State;

const PROCESS_ENV_ROWS: &[(&str, bool)] = &[
    ("AUTOPILOT_LOCAL_GPU_DEV", false),
    ("AUTOPILOT_FORCE_X11", false),
    ("AUTOPILOT_RESET_DATA_ON_BOOT", false),
    ("AUTOPILOT_KERNEL_RPC_URL", false),
    ("XDG_SESSION_TYPE", false),
    ("TZ", false),
    ("AUTOPILOT_STUDIO_ROUTING_RUNTIME_URL", false),
    ("AUTOPILOT_STUDIO_ROUTING_RUNTIME_MODEL", false),
    ("AUTOPILOT_ACCEPTANCE_RUNTIME_URL", false),
    ("AUTOPILOT_ACCEPTANCE_RUNTIME_MODEL", false),
    ("OPENAI_API_KEY", true),
    ("AUTOPILOT_STUDIO_ROUTING_RUNTIME_API_KEY", true),
    ("AUTOPILOT_STUDIO_ROUTING_OPENAI_API_KEY", true),
    ("AUTOPILOT_ACCEPTANCE_RUNTIME_API_KEY", true),
    ("AUTOPILOT_ACCEPTANCE_OPENAI_API_KEY", true),
];

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
            task.studio_session
                .as_ref()
                .and_then(|session| session.workspace_root.clone())
        })
}

fn workspace_label(workspace_root: Option<&str>) -> String {
    let Some(workspace_root) = workspace_root
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return "Session remote environment".to_string();
    };

    workspace_root
        .replace('\\', "/")
        .split('/')
        .filter(|segment| !segment.is_empty())
        .last()
        .map(str::to_string)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| workspace_root.to_string())
}

fn env_text(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn clip_text(value: &str, max_chars: usize) -> String {
    let compact = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.chars().count() <= max_chars {
        return compact;
    }
    compact
        .chars()
        .take(max_chars.saturating_sub(1))
        .collect::<String>()
        + "…"
}

fn binding_scope_label(key: &str) -> String {
    let upper = key.trim().to_ascii_uppercase();
    if upper.starts_with("AUTOPILOT_STUDIO_ROUTING_") {
        "Routing runtime".to_string()
    } else if upper.starts_with("AUTOPILOT_ACCEPTANCE_") {
        "Acceptance runtime".to_string()
    } else if upper == "OPENAI_API_KEY" {
        "Provider auth".to_string()
    } else if upper == "XDG_SESSION_TYPE" || upper == "TZ" {
        "Shell process".to_string()
    } else if upper.starts_with("AUTOPILOT_") || upper.starts_with("LOCAL_LLM_") {
        "Primary runtime".to_string()
    } else if upper.starts_with("OPENAI_") {
        "Provider runtime".to_string()
    } else {
        "Runtime".to_string()
    }
}

fn binding_value_preview(value: &str, secret: bool) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return "Not set".to_string();
    }
    if secret {
        return "Present (redacted)".to_string();
    }
    clip_text(trimmed, 96)
}

fn binding_provenance_label(source_label: &str, secret: bool) -> String {
    match (source_label, secret) {
        ("Local engine control plane", true) => "Configured secret binding".to_string(),
        ("Local engine control plane", false) => "Configured runtime binding".to_string(),
        (_, true) => "Process secret".to_string(),
        _ => "Shell/runtime environment".to_string(),
    }
}

fn binding_source_key(key: &str, source_label: &str) -> String {
    format!("{}::{source_label}", key.trim())
}

fn overlapping_binding_count(rows: &[SessionRemoteEnvBinding]) -> usize {
    let mut sources_by_key: HashMap<String, HashSet<String>> = HashMap::new();
    for row in rows {
        sources_by_key
            .entry(row.key.clone())
            .or_default()
            .insert(row.source_label.clone());
    }

    sources_by_key
        .values()
        .filter(|sources| sources.len() > 1)
        .count()
}

fn push_binding_row(
    rows: &mut Vec<SessionRemoteEnvBinding>,
    seen_keys: &mut HashSet<String>,
    key: &str,
    value: &str,
    source_label: &str,
    secret: bool,
) {
    let normalized_key = key.trim().to_string();
    let source_key = binding_source_key(&normalized_key, source_label);
    if normalized_key.is_empty() || !seen_keys.insert(source_key) {
        return;
    }

    rows.push(SessionRemoteEnvBinding {
        key: normalized_key.clone(),
        value_preview: binding_value_preview(value, secret),
        source_label: source_label.to_string(),
        scope_label: binding_scope_label(&normalized_key),
        provenance_label: binding_provenance_label(source_label, secret),
        secret,
        redacted: secret && !value.trim().is_empty(),
    });
}

fn control_plane_bindings(
    control_plane_bindings: &[LocalEngineEnvironmentBinding],
    rows: &mut Vec<SessionRemoteEnvBinding>,
    seen_keys: &mut HashSet<String>,
) {
    for binding in control_plane_bindings {
        push_binding_row(
            rows,
            seen_keys,
            &binding.key,
            &binding.value,
            "Local engine control plane",
            binding.secret,
        );
    }
}

fn process_bindings(rows: &mut Vec<SessionRemoteEnvBinding>, seen_keys: &mut HashSet<String>) {
    for (key, secret) in PROCESS_ENV_ROWS {
        let Some(value) = env_text(key) else {
            continue;
        };
        push_binding_row(rows, seen_keys, key, &value, "Runtime process", *secret);
    }
}

fn build_remote_env_snapshot(
    session_id: Option<String>,
    workspace_root: Option<String>,
    control_plane: crate::models::LocalEngineControlPlane,
) -> SessionRemoteEnvSnapshot {
    let mut bindings = Vec::new();
    let mut seen_keys = HashSet::new();
    control_plane_bindings(&control_plane.environment, &mut bindings, &mut seen_keys);
    process_bindings(&mut bindings, &mut seen_keys);
    bindings.sort_by(|left, right| {
        left.key
            .cmp(&right.key)
            .then_with(|| left.source_label.cmp(&right.source_label))
    });

    let binding_count = bindings.len();
    let overlapping_binding_count = overlapping_binding_count(&bindings);
    let secret_binding_count = bindings.iter().filter(|binding| binding.secret).count();
    let redacted_binding_count = bindings.iter().filter(|binding| binding.redacted).count();
    let control_plane_binding_count = bindings
        .iter()
        .filter(|binding| binding.source_label == "Local engine control plane")
        .count();
    let process_binding_count = bindings
        .iter()
        .filter(|binding| binding.source_label == "Runtime process")
        .count();
    let focused_scope_label = workspace_label(workspace_root.as_deref());
    let governing_source_label = if control_plane_binding_count > 0 && process_binding_count > 0 {
        "Local engine control plane + runtime process".to_string()
    } else if control_plane_binding_count > 0 {
        "Local engine control plane".to_string()
    } else {
        "Runtime process".to_string()
    };
    let posture_label = if overlapping_binding_count > 0 {
        "Source drift requires review".to_string()
    } else if redacted_binding_count > 0 {
        "Secrets redacted in projection".to_string()
    } else {
        "Read-only environment projection".to_string()
    };
    let posture_detail = if overlapping_binding_count > 0 {
        format!(
            "{} binding key{} appear{} in both the local engine control plane and the runtime process. Review the paired rows before relying on remote continuity or widening environment-backed execution.",
            overlapping_binding_count,
            if overlapping_binding_count == 1 { "" } else { "s" },
            if overlapping_binding_count == 1 { "s" } else { "" }
        )
    } else if redacted_binding_count > 0 {
        "This session view keeps secret environment bindings redacted while still showing which runtime lanes, providers, and shell settings are active."
            .to_string()
    } else {
        "This session view shows the active runtime and shell environment posture without exposing mutating controls yet."
            .to_string()
    };

    let mut notes = Vec::new();
    if let Some(session_id) = session_id.as_ref() {
        notes.push(format!("Session scope: {}", clip_text(session_id, 24)));
    }
    if let Some(workspace_root) = workspace_root.as_ref() {
        notes.push(format!("Workspace root: {}", workspace_root));
    }
    notes.push(format!(
        "{} configured runtime bindings visible in this projection.",
        control_plane_binding_count
    ));
    if process_binding_count > 0 {
        notes.push(format!(
            "{} process-level overrides are active for this shell/runtime.",
            process_binding_count
        ));
    }
    if overlapping_binding_count > 0 {
        notes.push(format!(
            "{} binding key{} currently differ across the control plane and runtime process projection.",
            overlapping_binding_count,
            if overlapping_binding_count == 1 { "" } else { "s" }
        ));
    }
    notes.extend(control_plane.notes.into_iter().take(2));

    SessionRemoteEnvSnapshot {
        generated_at_ms: state::now(),
        session_id,
        workspace_root,
        focused_scope_label,
        governing_source_label,
        posture_label,
        posture_detail,
        binding_count,
        control_plane_binding_count,
        process_binding_count,
        overlapping_binding_count,
        secret_binding_count,
        redacted_binding_count,
        notes,
        bindings,
    }
}

#[tauri::command]
pub fn get_session_remote_env_snapshot(
    state: State<'_, Mutex<AppState>>,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> Result<SessionRemoteEnvSnapshot, String> {
    let requested_session_id = normalize_optional_text(session_id);
    let requested_workspace_root = normalize_optional_text(workspace_root);
    let (memory_runtime, current_task) = {
        let guard = state
            .lock()
            .map_err(|_| "Failed to lock app state.".to_string())?;
        (
            guard
                .memory_runtime
                .clone()
                .ok_or_else(|| "Local persistence unavailable.".to_string())?,
            guard.current_task.clone(),
        )
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

    let control_plane = data::load_or_initialize_local_engine_control_plane(&memory_runtime);
    Ok(build_remote_env_snapshot(
        resolved_session_id,
        resolved_workspace_root,
        control_plane,
    ))
}

#[cfg(test)]
#[path = "remote_env/tests.rs"]
mod tests;
