use tauri::{AppHandle, Emitter, Manager};

use super::layout::{apply_layout, focus_window_best_effort};
use super::state::SPOTLIGHT_LAYOUT;

pub fn show_spotlight(app: AppHandle) {
    show_studio(app.clone());
    let _ = app.emit("request-studio-view", "autopilot");
}

pub fn hide_spotlight(app: AppHandle) {
    hide_studio(app);
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
    if let Some(window) = app.get_webview_window("gate") {
        let _ = window.center();
        #[cfg(not(target_os = "linux"))]
        let _ = window.set_always_on_top(true);
        let _ = window.show();
        focus_window_best_effort(&window);
        #[cfg(target_os = "linux")]
        if window.is_visible().unwrap_or(false) {
            let _ = window.set_always_on_top(true);
        }
    }
}

pub fn hide_gate(app: AppHandle) {
    if let Some(window) = app.get_webview_window("gate") {
        let _ = window.hide();
    }
}

pub fn show_studio(app: AppHandle) {
    if let Some(window) = app.get_webview_window("studio") {
        let _ = window.show();
        focus_window_best_effort(&window);
    }
}

pub fn hide_studio(app: AppHandle) {
    if let Some(window) = app.get_webview_window("studio") {
        let _ = window.hide();
    }
}
