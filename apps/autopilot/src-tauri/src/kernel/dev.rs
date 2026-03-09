use crate::kernel::connectors::{GoogleAutomationManager, ShieldPolicyManager};
use crate::models::{AgentPhase, AppState, ResetAutopilotDataResult};
use crate::{autopilot_data_dir_for, open_or_create_studio_scs};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, State};

fn remove_file_if_exists(path: &Path, removed_paths: &mut Vec<String>) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    std::fs::remove_file(path)
        .map_err(|error| format!("Failed to remove '{}': {}", path.display(), error))?;
    removed_paths.push(path.display().to_string());
    Ok(())
}

fn remove_dir_if_exists(path: &Path, removed_paths: &mut Vec<String>) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    std::fs::remove_dir_all(path)
        .map_err(|error| format!("Failed to remove '{}': {}", path.display(), error))?;
    removed_paths.push(path.display().to_string());
    Ok(())
}

#[tauri::command]
pub async fn reset_autopilot_data(
    app: AppHandle,
    state: State<'_, Mutex<AppState>>,
    google_manager: State<'_, GoogleAutomationManager>,
    policy_manager: State<'_, ShieldPolicyManager>,
) -> Result<ResetAutopilotDataResult, String> {
    let phase = state
        .lock()
        .map_err(|_| "Failed to lock app state".to_string())?
        .current_task
        .as_ref()
        .map(|task| task.phase.clone());

    if matches!(phase, Some(AgentPhase::Running) | Some(AgentPhase::Gate)) {
        return Err("Stop the active task before resetting Autopilot data.".to_string());
    }

    google_manager.reset_registry().await?;
    policy_manager.reset_to_default()?;

    let old_scs = {
        let mut app_state = state
            .lock()
            .map_err(|_| "Failed to lock app state".to_string())?;
        app_state.current_task = None;
        app_state.gate_response = None;
        app_state.is_simulating = false;
        app_state.event_index.clear();
        app_state.artifact_index.clear();
        app_state.studio_scs.take()
    };
    drop(old_scs);

    let data_dir = autopilot_data_dir_for(&app);
    let mut removed_paths = Vec::new();
    remove_file_if_exists(&data_dir.join("studio.scs"), &mut removed_paths)?;
    remove_dir_if_exists(&data_dir.join("spotlight-validation"), &mut removed_paths)?;

    let fresh_store = open_or_create_studio_scs(&data_dir)?;
    {
        let mut app_state = state
            .lock()
            .map_err(|_| "Failed to lock app state".to_string())?;
        app_state.studio_scs = Some(Arc::new(Mutex::new(fresh_store)));
    }

    let result = ResetAutopilotDataResult {
        data_dir: data_dir.display().to_string(),
        removed_paths,
        identity_preserved: true,
        remote_history_may_persist: true,
    };

    app.emit("autopilot-data-reset", &result)
        .map_err(|error| format!("Failed to emit reset event: {}", error))?;

    Ok(result)
}
