fn merge_session_summaries(
    mut base: Vec<SessionSummary>,
    overlay: Vec<SessionSummary>,
) -> Vec<SessionSummary> {
    for summary in overlay {
        if let Some(position) = base
            .iter()
            .position(|existing| existing.session_id == summary.session_id)
        {
            base[position] = summary;
        } else {
            base.push(summary);
        }
    }

    base.sort_by(|left, right| right.timestamp.cmp(&left.timestamp));
    base
}

fn current_task_snapshot(state: &State<'_, Mutex<AppState>>) -> Option<crate::models::AgentTask> {
    state.lock().ok().and_then(|guard| {
        guard.current_task.clone().map(|mut task| {
            task.sync_runtime_views();
            task
        })
    })
}

fn cached_session_history_snapshot(state: &State<'_, Mutex<AppState>>) -> Vec<SessionSummary> {
    state
        .lock()
        .map(|guard| guard.session_history_projection.clone())
        .unwrap_or_default()
}

fn projected_cached_session_history(state: &State<'_, Mutex<AppState>>) -> Vec<SessionSummary> {
    let (cached_sessions, memory_runtime) = match state.lock() {
        Ok(guard) => (
            guard.session_history_projection.clone(),
            guard.memory_runtime.clone(),
        ),
        Err(_) => return Vec::new(),
    };

    merge_session_summaries(
        cached_sessions,
        local_session_history_snapshot(memory_runtime.as_ref()),
    )
}

async fn refresh_cached_session_history(state: &State<'_, Mutex<AppState>>) -> Vec<SessionSummary> {
    let mut all_sessions = {
        let memory_runtime = state
            .lock()
            .ok()
            .and_then(|guard| guard.memory_runtime.clone());
        local_session_history_snapshot(memory_runtime.as_ref())
    };

    match fetch_remote_session_history(state).await {
        Ok(remote_sessions) => {
            merge_remote_session_history(&mut all_sessions, remote_sessions);
        }
        Err(error) => {
            eprintln!("[Kernel] {}", error);
        }
    }

    all_sessions.sort_by(|left, right| right.timestamp.cmp(&left.timestamp));
    if let Ok(mut guard) = state.lock() {
        guard.session_history_projection = all_sessions.clone();
    }
    all_sessions
}

async fn refresh_cached_session_history_with_change(
    state: &State<'_, Mutex<AppState>>,
) -> (Vec<SessionSummary>, bool) {
    let previous_sessions = cached_session_history_snapshot(state);
    let refreshed_sessions = refresh_cached_session_history(state).await;
    let changed = refreshed_sessions != previous_sessions;
    (refreshed_sessions, changed)
}

pub async fn emit_session_projection_update(app: &AppHandle, refresh_history: bool) {
    let state = app.state::<Mutex<AppState>>();
    let sessions = if refresh_history {
        refresh_cached_session_history(&state).await
    } else {
        projected_cached_session_history(&state)
    };

    let projection = SessionProjection {
        task: current_task_snapshot(&state),
        sessions,
    };
    let _ = app.emit("session-projection-updated", &projection);
}

pub async fn emit_session_projection_update_if_history_changed(
    app: &AppHandle,
    reason: &str,
) -> bool {
    let state = app.state::<Mutex<AppState>>();
    let should_refresh = match state.lock() {
        Ok(mut guard) => {
            if guard.session_projection_refresh_in_flight {
                false
            } else {
                guard.session_projection_refresh_in_flight = true;
                true
            }
        }
        Err(_) => false,
    };

    if !should_refresh {
        return false;
    }

    let (sessions, changed) = refresh_cached_session_history_with_change(&state).await;
    if let Ok(mut guard) = state.lock() {
        guard.session_projection_refresh_in_flight = false;
    }

    if !changed {
        return false;
    }

    println!(
        "[Kernel] Session projection refreshed via {} ({} sessions)",
        reason,
        sessions.len()
    );
    let projection = SessionProjection {
        task: current_task_snapshot(&state),
        sessions,
    };
    let _ = app.emit("session-projection-updated", &projection);
    true
}

pub async fn spawn_session_projection_monitor(app: AppHandle) {
    loop {
        tokio::time::sleep(Duration::from_millis(SESSION_HISTORY_MONITOR_INTERVAL_MS)).await;
        let _ = emit_session_projection_update_if_history_changed(&app, "monitor").await;
    }
}

#[tauri::command]
pub async fn get_session_projection(
    state: State<'_, Mutex<AppState>>,
) -> Result<SessionProjection, String> {
    Ok(SessionProjection {
        task: current_task_snapshot(&state),
        sessions: refresh_cached_session_history(&state).await,
    })
}
