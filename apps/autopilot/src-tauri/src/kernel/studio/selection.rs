use super::*;

pub(super) fn attach_artifact_selection(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    selection: StudioArtifactSelectionTarget,
) -> Result<(), String> {
    let (mut task, memory_runtime) = current_task_and_memory_runtime(&state)?;
    let studio_session = task
        .studio_session
        .as_mut()
        .ok_or_else(|| "No Studio artifact session is attached to the current task.".to_string())?;

    studio_session.selected_targets = vec![selection];
    studio_session.updated_at = now_iso();
    persist_current_task_update(&state, &app, task, memory_runtime)
}
