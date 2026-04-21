use super::*;

pub(super) fn attach_artifact_selection(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    selection: ChatArtifactSelectionTarget,
) -> Result<(), String> {
    let (mut task, memory_runtime) = current_task_and_memory_runtime(&state)?;
    let chat_session = task
        .chat_session
        .as_mut()
        .ok_or_else(|| "No Chat artifact session is attached to the current task.".to_string())?;

    chat_session.selected_targets = vec![selection];
    chat_session.updated_at = now_iso();
    persist_current_task_update(&state, &app, task, memory_runtime)
}

pub(super) fn attach_widget_state(
    state: State<'_, Mutex<AppState>>,
    app: AppHandle,
    widget_state: ChatRetainedWidgetState,
) -> Result<(), String> {
    let (mut task, memory_runtime) = current_task_and_memory_runtime(&state)?;
    let chat_session = task
        .chat_session
        .as_mut()
        .ok_or_else(|| "No Chat artifact session is attached to the current task.".to_string())?;

    chat_session.widget_state = Some(widget_state);
    chat_session.updated_at = now_iso();
    persist_current_task_update(&state, &app, task, memory_runtime)
}
