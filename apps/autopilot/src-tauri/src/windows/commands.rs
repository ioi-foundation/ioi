use tauri::{
    AppHandle, Emitter, Manager, Position, Size, UserAttentionType, WebviewWindow,
    WebviewWindowBuilder,
};

use super::layout::{apply_layout, focus_window_best_effort};
use super::monitor::get_target_monitor;
use super::state::SPOTLIGHT_LAYOUT;
use super::{
    queue_pending_studio_launch_for_app, record_chat_launch_receipt_for_app,
    should_surface_overlay_windows_in_task_switcher, summarize_studio_launch_envelope,
    TASKBAR_MARGIN,
};
use serde_json::{json, Value};

const PILL_WIDTH: f64 = 440.0;
const PILL_HEIGHT: f64 = 138.0;
const PILL_BOTTOM_MARGIN: f64 = 32.0;

pub fn show_spotlight(app: AppHandle) {
    show_autopilot_surface(app);
}

pub fn show_pill(app: AppHandle) {
    if let Some(window) = app.get_webview_window("pill") {
        position_pill_window(&app, &window);
        surface_window_best_effort(&window, false);
    }
}

pub fn hide_pill(app: AppHandle) {
    if let Some(window) = app.get_webview_window("pill") {
        let _ = window.hide();
    }
}

pub fn hide_spotlight(app: AppHandle) {
    hide_autopilot_surface(app);
}

fn show_autopilot_surface(app: AppHandle) {
    hide_pill(app.clone());
    if let Some(window) = app.get_webview_window("spotlight") {
        let layout_snapshot = SPOTLIGHT_LAYOUT
            .lock()
            .map(|layout| *layout)
            .unwrap_or_default();
        let _ = apply_layout(&app, &layout_snapshot);
        surface_window_best_effort(&window, should_surface_overlay_windows_in_task_switcher());
        return;
    }

    let envelope = queue_pending_studio_launch_for_app(
        &app,
        json!({
            "kind": "view",
            "view": "autopilot",
        }),
    );
    if let Ok(envelope) = envelope {
        show_chat_with_target(app, envelope);
    } else {
        show_chat(app);
    }
}

fn hide_autopilot_surface(app: AppHandle) {
    if let Some(window) = app.get_webview_window("spotlight") {
        let _ = window.hide();
        show_pill(app);
        return;
    }

    hide_studio(app);
}

fn position_pill_window(app: &AppHandle, window: &WebviewWindow) {
    let Some(monitor) = get_target_monitor(app) else {
        let _ = window.center();
        return;
    };

    let scale = monitor.scale_factor();
    let monitor_size = monitor.size();
    let monitor_pos = monitor.position();

    let width_px = PILL_WIDTH * scale;
    let height_px = PILL_HEIGHT * scale;
    let x = monitor_pos.x as f64 + ((monitor_size.width as f64 - width_px) / 2.0).max(0.0);
    let y = monitor_pos.y as f64
        + (monitor_size.height as f64
            - height_px
            - ((PILL_BOTTOM_MARGIN + TASKBAR_MARGIN) * scale))
            .max(0.0);

    let _ = window.set_size(Size::Physical(tauri::PhysicalSize {
        width: width_px.round().max(1.0) as u32,
        height: height_px.round().max(1.0) as u32,
    }));
    let _ = window.set_position(Position::Physical(tauri::PhysicalPosition {
        x: x.round() as i32,
        y: y.round() as i32,
    }));
}

pub fn toggle_spotlight_sidebar(app: AppHandle, visible: bool) {
    if let Ok(mut layout) = SPOTLIGHT_LAYOUT.lock() {
        if layout.sidebar_visible == visible {
            return;
        }
        layout.sidebar_visible = visible;
        let layout_snapshot = *layout;
        drop(layout);
        let _ = apply_layout(&app, &layout_snapshot);
    }
}

pub fn toggle_spotlight_artifact_panel(app: AppHandle, visible: bool) {
    if let Ok(mut layout) = SPOTLIGHT_LAYOUT.lock() {
        if layout.artifact_panel_visible == visible {
            return;
        }
        layout.artifact_panel_visible = visible;
        let layout_snapshot = *layout;
        drop(layout);
        let _ = apply_layout(&app, &layout_snapshot);
    }
}

pub fn get_spotlight_layout() -> Result<(bool, bool), String> {
    if let Ok(layout) = SPOTLIGHT_LAYOUT.lock() {
        Ok((layout.sidebar_visible, layout.artifact_panel_visible))
    } else {
        Err("Lock failed".into())
    }
}

pub fn show_gate(app: AppHandle) {
    hide_pill(app.clone());
    if let Some(window) = app.get_webview_window("gate") {
        let _ = window.center();
        let _ = window.set_always_on_top(true);
        surface_window_best_effort(&window, true);
    }
}

pub fn hide_gate(app: AppHandle) {
    if let Some(window) = app.get_webview_window("gate") {
        let _ = window.hide();
    }
    if no_primary_operator_surface_visible(&app) {
        show_pill(app);
    }
}

pub fn show_chat(app: AppHandle) {
    hide_pill(app.clone());
    if let Some(window) = app.get_webview_window("spotlight") {
        let _ = window.hide();
    }
    let existing_window = app.get_webview_window("studio");
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
            "windowLabel": "studio",
            "windowExistedBefore": existed_before,
            "visibleBefore": visible_before,
            "minimizedBefore": minimized_before,
            "maximizedBefore": maximized_before,
        }),
    );
    if let Some(window) = ensure_webview_window(&app, "studio") {
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
                "windowLabel": "studio",
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
                "windowLabel": "studio",
                "windowExistedBefore": existed_before,
            }),
        );
        eprintln!("[Autopilot] Unable to surface Studio because the window is unavailable.");
    }
}

pub fn show_chat_with_target(app: AppHandle, envelope: Value) {
    let launch_summary = summarize_studio_launch_envelope(&envelope);
    record_chat_launch_receipt_for_app(
        &app,
        "show_target_requested",
        json!({
            "windowLabel": "studio",
            "launch": launch_summary.clone(),
        }),
    );
    show_chat(app.clone());

    let Some(window) = app.get_webview_window("studio") else {
        record_chat_launch_receipt_for_app(
            &app,
            "show_target_window_missing",
            json!({
                "windowLabel": "studio",
                "launch": launch_summary,
            }),
        );
        return;
    };

    match window.emit("request-studio-launch", envelope.clone()) {
        Ok(()) => record_chat_launch_receipt_for_app(
            &app,
            "show_target_emitted",
            json!({
                "windowLabel": "studio",
                "launch": launch_summary,
            }),
        ),
        Err(error) => record_chat_launch_receipt_for_app(
            &app,
            "show_target_emit_failed",
            json!({
                "windowLabel": "studio",
                "launch": launch_summary,
                "error": error.to_string(),
            }),
        ),
    }
}

pub fn hide_studio(app: AppHandle) {
    if let Some(window) = app.get_webview_window("studio") {
        let _ = window.hide();
    }
    if no_primary_operator_surface_visible(&app) {
        show_pill(app);
    }
}

fn no_primary_operator_surface_visible(app: &AppHandle) -> bool {
    let spotlight_visible = app
        .get_webview_window("spotlight")
        .and_then(|window| window.is_visible().ok())
        .unwrap_or(false);
    let studio_visible = app
        .get_webview_window("studio")
        .and_then(|window| window.is_visible().ok())
        .unwrap_or(false);
    let gate_visible = app
        .get_webview_window("gate")
        .and_then(|window| window.is_visible().ok())
        .unwrap_or(false);

    !spotlight_visible && !studio_visible && !gate_visible
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
