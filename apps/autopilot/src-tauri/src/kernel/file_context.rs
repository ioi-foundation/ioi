use crate::models::{AppState, SessionFileContext};
use crate::orchestrator;
use std::sync::Mutex;
use tauri::State;

const MAX_RECENT_FILES: usize = 12;

fn normalize_optional_text(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn normalize_path(path: &str) -> Option<String> {
    let normalized = path.trim().replace('\\', "/");
    let normalized = normalized.trim_start_matches("./").trim().to_string();
    if normalized.is_empty() || normalized == "." {
        None
    } else {
        Some(normalized)
    }
}

fn dedupe_paths(paths: &mut Vec<String>) {
    let mut deduped = Vec::with_capacity(paths.len());
    for path in paths.drain(..) {
        if deduped.iter().any(|existing| existing == &path) {
            continue;
        }
        deduped.push(path);
    }
    *paths = deduped;
}

fn push_front_unique(paths: &mut Vec<String>, path: String, limit: usize) {
    paths.retain(|existing| existing != &path);
    paths.insert(0, path);
    if paths.len() > limit {
        paths.truncate(limit);
    }
}

fn retain_without_path(paths: &mut Vec<String>, target: &str) -> bool {
    let previous_len = paths.len();
    paths.retain(|path| path != target);
    previous_len != paths.len()
}

fn dedupe_context_paths(context: &mut SessionFileContext) {
    dedupe_paths(&mut context.pinned_files);
    dedupe_paths(&mut context.recent_files);
    dedupe_paths(&mut context.explicit_includes);
    dedupe_paths(&mut context.explicit_excludes);
}

pub(crate) fn apply_pin_file_context_path(
    context: &mut SessionFileContext,
    path: &str,
) -> Result<(), String> {
    let normalized_path =
        normalize_path(path).ok_or_else(|| "A valid file path is required.".to_string())?;
    retain_without_path(&mut context.explicit_excludes, &normalized_path);
    push_front_unique(
        &mut context.pinned_files,
        normalized_path.clone(),
        usize::MAX,
    );
    push_front_unique(
        &mut context.explicit_includes,
        normalized_path.clone(),
        usize::MAX,
    );
    push_front_unique(&mut context.recent_files, normalized_path, MAX_RECENT_FILES);
    dedupe_context_paths(context);
    Ok(())
}

pub(crate) fn apply_include_file_context_path(
    context: &mut SessionFileContext,
    path: &str,
) -> Result<(), String> {
    let normalized_path =
        normalize_path(path).ok_or_else(|| "A valid file path is required.".to_string())?;
    retain_without_path(&mut context.explicit_excludes, &normalized_path);
    push_front_unique(
        &mut context.explicit_includes,
        normalized_path.clone(),
        usize::MAX,
    );
    push_front_unique(&mut context.recent_files, normalized_path, MAX_RECENT_FILES);
    dedupe_context_paths(context);
    Ok(())
}

pub(crate) fn apply_exclude_file_context_path(
    context: &mut SessionFileContext,
    path: &str,
) -> Result<(), String> {
    let normalized_path =
        normalize_path(path).ok_or_else(|| "A valid file path is required.".to_string())?;
    retain_without_path(&mut context.pinned_files, &normalized_path);
    retain_without_path(&mut context.explicit_includes, &normalized_path);
    push_front_unique(
        &mut context.explicit_excludes,
        normalized_path.clone(),
        usize::MAX,
    );
    push_front_unique(&mut context.recent_files, normalized_path, MAX_RECENT_FILES);
    dedupe_context_paths(context);
    Ok(())
}

pub(crate) fn apply_remove_file_context_path(
    context: &mut SessionFileContext,
    path: &str,
) -> Result<(), String> {
    let normalized_path =
        normalize_path(path).ok_or_else(|| "A valid file path is required.".to_string())?;
    retain_without_path(&mut context.pinned_files, &normalized_path);
    retain_without_path(&mut context.recent_files, &normalized_path);
    retain_without_path(&mut context.explicit_includes, &normalized_path);
    retain_without_path(&mut context.explicit_excludes, &normalized_path);
    dedupe_context_paths(context);
    Ok(())
}

pub(crate) fn apply_recent_file_context_path(
    context: &mut SessionFileContext,
    path: &str,
) -> Result<(), String> {
    let normalized_path =
        normalize_path(path).ok_or_else(|| "A valid file path is required.".to_string())?;
    push_front_unique(&mut context.recent_files, normalized_path, MAX_RECENT_FILES);
    dedupe_context_paths(context);
    Ok(())
}

fn with_file_context_mutation<F>(
    state: &State<'_, Mutex<AppState>>,
    session_id: Option<String>,
    workspace_root: Option<String>,
    mutate: F,
) -> Result<SessionFileContext, String>
where
    F: FnOnce(&mut SessionFileContext) -> Result<(), String>,
{
    let session_id = normalize_optional_text(session_id);
    let workspace_root = normalize_optional_text(workspace_root);
    let memory_runtime = state
        .lock()
        .map_err(|_| "Failed to lock app state.".to_string())?
        .memory_runtime
        .clone()
        .ok_or_else(|| "Local persistence unavailable.".to_string())?;

    let mut context = orchestrator::load_session_file_context(
        &memory_runtime,
        session_id.as_deref(),
        workspace_root.as_deref(),
    );
    mutate(&mut context)?;
    dedupe_context_paths(&mut context);
    if context.workspace_root.trim().is_empty() {
        context.workspace_root = std::env::current_dir()
            .ok()
            .map(|path| path.display().to_string())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| ".".to_string());
    }
    context.session_id = session_id.clone();
    context.updated_at_ms = crate::kernel::state::now();
    orchestrator::save_session_file_context(&memory_runtime, session_id.as_deref(), &context);
    Ok(context)
}

#[tauri::command]
pub fn get_session_file_context(
    state: State<'_, Mutex<AppState>>,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> Result<SessionFileContext, String> {
    let session_id = normalize_optional_text(session_id);
    let workspace_root = normalize_optional_text(workspace_root);
    let memory_runtime = state
        .lock()
        .map_err(|_| "Failed to lock app state.".to_string())?
        .memory_runtime
        .clone()
        .ok_or_else(|| "Local persistence unavailable.".to_string())?;
    Ok(orchestrator::load_session_file_context(
        &memory_runtime,
        session_id.as_deref(),
        workspace_root.as_deref(),
    ))
}

#[tauri::command]
pub fn pin_session_file_context_path(
    state: State<'_, Mutex<AppState>>,
    session_id: Option<String>,
    workspace_root: Option<String>,
    path: String,
) -> Result<SessionFileContext, String> {
    with_file_context_mutation(&state, session_id, workspace_root, |context| {
        apply_pin_file_context_path(context, &path)
    })
}

#[tauri::command]
pub fn include_session_file_context_path(
    state: State<'_, Mutex<AppState>>,
    session_id: Option<String>,
    workspace_root: Option<String>,
    path: String,
) -> Result<SessionFileContext, String> {
    with_file_context_mutation(&state, session_id, workspace_root, |context| {
        apply_include_file_context_path(context, &path)
    })
}

#[tauri::command]
pub fn exclude_session_file_context_path(
    state: State<'_, Mutex<AppState>>,
    session_id: Option<String>,
    workspace_root: Option<String>,
    path: String,
) -> Result<SessionFileContext, String> {
    with_file_context_mutation(&state, session_id, workspace_root, |context| {
        apply_exclude_file_context_path(context, &path)
    })
}

#[tauri::command]
pub fn remove_session_file_context_path(
    state: State<'_, Mutex<AppState>>,
    session_id: Option<String>,
    workspace_root: Option<String>,
    path: String,
) -> Result<SessionFileContext, String> {
    with_file_context_mutation(&state, session_id, workspace_root, |context| {
        apply_remove_file_context_path(context, &path)
    })
}

#[tauri::command]
pub fn record_session_file_context_recent_path(
    state: State<'_, Mutex<AppState>>,
    session_id: Option<String>,
    workspace_root: Option<String>,
    path: String,
) -> Result<SessionFileContext, String> {
    with_file_context_mutation(&state, session_id, workspace_root, |context| {
        apply_recent_file_context_path(context, &path)
    })
}

#[tauri::command]
pub fn clear_session_file_context(
    state: State<'_, Mutex<AppState>>,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> Result<SessionFileContext, String> {
    let session_id = normalize_optional_text(session_id);
    let workspace_root = normalize_optional_text(workspace_root);
    let memory_runtime = state
        .lock()
        .map_err(|_| "Failed to lock app state.".to_string())?
        .memory_runtime
        .clone()
        .ok_or_else(|| "Local persistence unavailable.".to_string())?;
    orchestrator::clear_session_file_context(&memory_runtime, session_id.as_deref());
    Ok(orchestrator::load_session_file_context(
        &memory_runtime,
        session_id.as_deref(),
        workspace_root.as_deref(),
    ))
}

#[cfg(test)]
#[path = "file_context/tests.rs"]
mod tests;
