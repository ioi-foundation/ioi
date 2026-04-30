fn build_session_rewind_snapshot(
    sessions: Vec<SessionSummary>,
    current_task: Option<&crate::models::AgentTask>,
) -> SessionRewindSnapshot {
    let active_session_id =
        current_task.and_then(|task| task.session_id.clone().or_else(|| Some(task.id.clone())));
    let active_session_title = active_session_id.as_ref().and_then(|session_id| {
        sessions
            .iter()
            .find(|summary| &summary.session_id == session_id)
            .map(title_for_session)
            .or_else(|| {
                current_task.and_then(|task| {
                    let title = task.intent.trim();
                    if title.is_empty() {
                        None
                    } else {
                        Some(title.to_string())
                    }
                })
            })
    });

    let last_stable_session_id = sessions
        .iter()
        .find(|summary| stable_session(summary, active_session_id.as_deref()))
        .map(|summary| summary.session_id.clone());

    let candidates = sessions
        .into_iter()
        .take(12)
        .map(|summary| {
            let is_current = active_session_id.as_deref() == Some(summary.session_id.as_str());
            let is_last_stable =
                last_stable_session_id.as_deref() == Some(summary.session_id.as_str());
            let summary_title = title_for_session(&summary);
            let preview_detail = session_preview_detail(&summary);
            let preview_headline = if is_current {
                "Reload the current retained session.".to_string()
            } else if is_last_stable {
                "Rewind shell focus to the last stable retained session.".to_string()
            } else {
                "Reattach this retained session in Chat.".to_string()
            };
            let discard_summary = match active_session_title.as_ref() {
                Some(active_title) if !is_current => format!(
                    "Replaces the active Chat session focus from \"{active_title}\" with this retained session. Retained evidence and other sessions stay stored."
                ),
                _ => "Refreshes this retained session without deleting evidence or other session history.".to_string(),
            };
            let action_label = if is_current {
                "Reload current session".to_string()
            } else if is_last_stable {
                "Rewind to this session".to_string()
            } else {
                "Open retained session".to_string()
            };

            SessionRewindCandidate {
                session_id: summary.session_id,
                title: summary_title,
                timestamp: summary.timestamp,
                phase: summary.phase,
                current_step: summary.current_step,
                resume_hint: summary.resume_hint,
                workspace_root: summary.workspace_root,
                is_current,
                is_last_stable,
                action_label,
                preview_headline,
                preview_detail,
                discard_summary,
            }
        })
        .collect();

    SessionRewindSnapshot {
        active_session_id,
        active_session_title,
        last_stable_session_id,
        candidates,
    }
}

#[tauri::command]
pub async fn get_session_rewind_snapshot(
    state: State<'_, Mutex<AppState>>,
) -> Result<SessionRewindSnapshot, String> {
    let current_task = current_task_snapshot(&state);
    let sessions = refresh_cached_session_history(&state).await;
    Ok(build_session_rewind_snapshot(
        sessions,
        current_task.as_ref(),
    ))
}
