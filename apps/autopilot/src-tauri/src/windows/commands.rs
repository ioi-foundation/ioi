use tauri::{AppHandle, Emitter, Manager, UserAttentionType, WebviewWindow, WebviewWindowBuilder};

use super::layout::{apply_layout, focus_window_best_effort};
use super::state::CHAT_SESSION_LAYOUT;
use super::{record_chat_launch_receipt_for_app, summarize_chat_launch_envelope};
use serde_json::{json, Value};

pub fn show_chat_session(app: AppHandle) {
    show_autopilot_surface(app);
}

pub fn show_pill(app: AppHandle) {
    if let Some(window) = app.get_webview_window("pill") {
        let _ = window.hide();
    }
}

pub fn hide_pill(app: AppHandle) {
    if let Some(window) = app.get_webview_window("pill") {
        let _ = window.hide();
    }
}

pub fn hide_chat_session(app: AppHandle) {
    if let Some(window) = app.get_webview_window("chat-session") {
        let _ = window.hide();
    }
}

fn show_autopilot_surface(app: AppHandle) {
    show_chat(app);
}

pub fn toggle_chat_session_sidebar(app: AppHandle, visible: bool) {
    if let Ok(mut layout) = CHAT_SESSION_LAYOUT.lock() {
        if layout.sidebar_visible == visible {
            return;
        }
        layout.sidebar_visible = visible;
        let layout_snapshot = *layout;
        drop(layout);
        let _ = apply_layout(&app, &layout_snapshot);
    }
}

pub fn toggle_chat_session_artifact_panel(app: AppHandle, visible: bool) {
    if let Ok(mut layout) = CHAT_SESSION_LAYOUT.lock() {
        if layout.artifact_panel_visible == visible {
            return;
        }
        layout.artifact_panel_visible = visible;
        let layout_snapshot = *layout;
        drop(layout);
        let _ = apply_layout(&app, &layout_snapshot);
    }
}

pub fn get_chat_session_layout() -> Result<(bool, bool), String> {
    if let Ok(layout) = CHAT_SESSION_LAYOUT.lock() {
        Ok((layout.sidebar_visible, layout.artifact_panel_visible))
    } else {
        Err("Lock failed".into())
    }
}

pub fn show_gate(app: AppHandle) {
    hide_pill(app.clone());
    if let Some(window) = app.get_webview_window("gate") {
        let _ = window.hide();
    }
    show_chat(app);
}

pub fn hide_gate(app: AppHandle) {
    if let Some(window) = app.get_webview_window("gate") {
        let _ = window.hide();
    }
}

pub fn show_chat(app: AppHandle) {
    hide_pill(app.clone());
    if let Some(window) = app.get_webview_window("chat-session") {
        let _ = window.hide();
    }
    let existing_window = app.get_webview_window("chat");
    let visible_before = existing_window
        .as_ref()
        .and_then(|window| window.is_visible().ok());
    let minimized_before = existing_window
        .as_ref()
        .and_then(|window| window.is_minimized().ok());
    let maximized_before = existing_window
        .as_ref()
        .and_then(|window| window.is_maximized().ok());
    let existed_before = existing_window.is_some();
    record_chat_launch_receipt_for_app(
        &app,
        "show_requested",
        json!({
            "windowLabel": "chat",
            "windowExistedBefore": existed_before,
            "visibleBefore": visible_before,
            "minimizedBefore": minimized_before,
            "maximizedBefore": maximized_before,
        }),
    );
    if let Some(window) = ensure_webview_window(&app, "chat") {
        let recreated = !existed_before;
        if window.is_maximized().unwrap_or(false) {
            let _ = window.unmaximize();
        }
        let _ = window.center();
        let _ = window.set_resizable(true);
        let _ = window.set_always_on_top(false);
        surface_window_best_effort(&window, true);
        record_chat_launch_receipt_for_app(
            &app,
            "show_surfaced",
            json!({
                "windowLabel": "chat",
                "recreatedWindow": recreated,
                "visibleAfter": window.is_visible().ok(),
                "minimizedAfter": window.is_minimized().ok(),
                "maximizedAfter": window.is_maximized().ok(),
            }),
        );
    } else {
        record_chat_launch_receipt_for_app(
            &app,
            "show_failed",
            json!({
                "windowLabel": "chat",
                "windowExistedBefore": existed_before,
            }),
        );
        eprintln!("[Autopilot] Unable to surface Chat because the window is unavailable.");
    }
}

pub fn show_chat_with_target(app: AppHandle, envelope: Value) {
    let launch_summary = summarize_chat_launch_envelope(&envelope);
    record_chat_launch_receipt_for_app(
        &app,
        "show_target_requested",
        json!({
            "windowLabel": "chat",
            "launch": launch_summary.clone(),
        }),
    );
    show_chat(app.clone());

    let Some(window) = app.get_webview_window("chat") else {
        record_chat_launch_receipt_for_app(
            &app,
            "show_target_window_missing",
            json!({
                "windowLabel": "chat",
                "launch": launch_summary,
            }),
        );
        return;
    };

    match window.emit("request-chat-launch", envelope.clone()) {
        Ok(()) => record_chat_launch_receipt_for_app(
            &app,
            "show_target_emitted",
            json!({
                "windowLabel": "chat",
                "launch": launch_summary,
            }),
        ),
        Err(error) => record_chat_launch_receipt_for_app(
            &app,
            "show_target_emit_failed",
            json!({
                "windowLabel": "chat",
                "launch": launch_summary,
                "error": error.to_string(),
            }),
        ),
    }
}

pub fn hide_chat(app: AppHandle) {
    if let Some(window) = app.get_webview_window("chat") {
        let _ = window.hide();
    }
}

fn ensure_webview_window(app: &AppHandle, label: &str) -> Option<WebviewWindow> {
    if let Some(window) = app.get_webview_window(label) {
        return Some(window);
    }

    let config = app
        .config()
        .app
        .windows
        .iter()
        .find(|candidate| candidate.label == label)
        .cloned()?;

    match WebviewWindowBuilder::from_config(app, &config).and_then(|builder| builder.build()) {
        Ok(window) => {
            eprintln!(
                "[Autopilot] Recreated missing '{}' window from config.",
                label
            );
            Some(window)
        }
        Err(error) => {
            eprintln!(
                "[Autopilot] Failed to recreate missing '{}' window from config: {}",
                label, error
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn gate_command_routes_to_primary_chat_surface() {
        let source = include_str!("commands.rs");
        let show_gate_start = source
            .find("pub fn show_gate")
            .expect("show_gate should exist");
        let show_gate_end = source[show_gate_start..]
            .find("pub fn hide_gate")
            .map(|offset| show_gate_start + offset)
            .expect("hide_gate should follow show_gate");
        let show_gate_source = &source[show_gate_start..show_gate_end];

        assert!(
            show_gate_source.contains("show_chat(app)"),
            "chat-origin approvals should surface the primary /chat window",
        );
        assert!(
            !show_gate_source.contains("set_always_on_top(true)")
                && !show_gate_source.contains("surface_window_best_effort(&window, true)"),
            "show_gate must not open a separate primary approval window",
        );
    }

    #[test]
    fn legacy_chat_session_hide_does_not_hide_primary_chat() {
        let source = include_str!("commands.rs");
        let hide_start = source
            .find("pub fn hide_chat_session")
            .expect("hide_chat_session should exist");
        let hide_end = source[hide_start..]
            .find("pub fn toggle_chat_session_sidebar")
            .map(|offset| hide_start + offset)
            .expect("toggle_chat_session_sidebar should follow hide_chat_session");
        let hide_source = &source[hide_start..hide_end];

        assert!(
            !hide_source.contains("hide_chat(app)"),
            "hiding the passive legacy chat-session surface must not close the primary /chat window",
        );
    }

    #[test]
    fn pill_surface_is_not_a_primary_operator_window() {
        let source = include_str!("commands.rs");
        let show_start = source
            .find("pub fn show_pill")
            .expect("show_pill should exist");
        let show_end = source[show_start..]
            .find("pub fn hide_pill")
            .map(|offset| show_start + offset)
            .expect("hide_pill should follow show_pill");
        let show_source = &source[show_start..show_end];

        assert!(
            show_source.contains("window.hide()"),
            "show_pill should be inert and hide any stale pill window",
        );
        assert!(
            !show_source.contains("surface_window_best_effort")
                && !show_source.contains("window.show()"),
            "pill must not be surfaced as an operator window",
        );
    }
}

fn surface_window_best_effort(window: &WebviewWindow, reveal_in_task_switcher: bool) {
    if window.is_minimized().unwrap_or(false) {
        let _ = window.unminimize();
    }

    let _ = window.set_focusable(true);
    let _ = window.show();

    #[cfg(target_os = "linux")]
    {
        let _ = window.set_skip_taskbar(!reveal_in_task_switcher);
        let _ = window.set_visible_on_all_workspaces(reveal_in_task_switcher);
        let _ = window.request_user_attention(Some(UserAttentionType::Informational));

        eprintln!(
            "[Autopilot] Surfacing '{}' (task_switcher={}, visible={:?}, minimized={:?})",
            window.label(),
            reveal_in_task_switcher,
            window.is_visible(),
            window.is_minimized()
        );
    }

    focus_window_best_effort(window);

    #[cfg(target_os = "linux")]
    let _ = window.request_user_attention(None);
}
