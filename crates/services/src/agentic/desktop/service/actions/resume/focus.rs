use crate::agentic::desktop::types::AgentState;
use ioi_api::vm::drivers::os::{OsDriver, WindowInfo};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

pub(super) fn is_missing_focus_dependency_error(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("error_class=missingdependency")
        || (lower.contains("wmctrl")
            && (lower.contains("no such file")
                || lower.contains("not found")
                || lower.contains("missing dependency")))
}

pub(super) async fn ensure_target_focused_for_resume(
    os_driver: &Arc<dyn OsDriver>,
    agent_state: &AgentState,
) -> Option<String> {
    // Approval UX can steal focus to the shell. For resumed spatial actions, force-focus the
    // target surface before injecting input.
    let Some(target) = &agent_state.target else {
        return None;
    };
    let hint = target.app_hint.as_deref().unwrap_or("").trim();
    if hint.is_empty() {
        return None;
    }

    let hint_lower = hint.to_lowercase();
    let matches_target = |fg: &WindowInfo| {
        let fg_title = fg.title.to_lowercase();
        let fg_app = fg.app_name.to_lowercase();
        fg_title.contains(&hint_lower) || fg_app.contains(&hint_lower)
    };

    let mut fg_info = os_driver.get_active_window_info().await.unwrap_or(None);
    let mut is_target_focused = fg_info.as_ref().map(matches_target).unwrap_or(false);

    if is_target_focused {
        return None;
    }

    log::info!(
        "Resume focus guard: foreground drifted. Attempting focus to '{}'",
        hint
    );

    let mut focus_queries = vec![hint.to_string()];
    if let Some(pattern) = target.title_pattern.as_deref().map(str::trim) {
        if !pattern.is_empty()
            && !focus_queries
                .iter()
                .any(|q| q.eq_ignore_ascii_case(pattern))
        {
            focus_queries.push(pattern.to_string());
        }
    }

    for query in focus_queries {
        match os_driver.focus_window(&query).await {
            Ok(true) => {
                // Give WM time to apply focus before injecting input.
                sleep(Duration::from_millis(180)).await;
                fg_info = os_driver.get_active_window_info().await.unwrap_or(None);
                is_target_focused = fg_info.as_ref().map(matches_target).unwrap_or(false);
                if is_target_focused {
                    break;
                }
            }
            Ok(false) => {
                log::warn!("Resume focus guard: no window matched '{}'", query);
            }
            Err(e) => {
                let err = e.to_string();
                if is_missing_focus_dependency_error(&err) {
                    return Some(format!(
                        "ERROR_CLASS=MissingDependency Focus dependency unavailable while focusing '{}': {}",
                        query, err
                    ));
                }
                log::warn!(
                    "Resume focus guard: focus_window failed for '{}': {}",
                    query,
                    err
                );
            }
        }
    }

    if !is_target_focused {
        if let Some(fg) = fg_info {
            log::warn!(
                "Resume focus guard: still unfocused after attempts. Foreground is '{}' ({}) while target is '{}'.",
                fg.title,
                fg.app_name,
                hint
            );
        } else {
            log::warn!(
                "Resume focus guard: unable to verify foreground window after focus attempts for '{}'.",
                hint
            );
        }
    }

    None
}
