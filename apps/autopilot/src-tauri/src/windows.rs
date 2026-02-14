// apps/autopilot/src-tauri/src/windows.rs

mod commands;
mod layout;
mod monitor;
mod state;

#[derive(Debug, Clone, Copy, Default)]
pub struct SpotlightLayout {
    pub sidebar_visible: bool,
    pub artifact_panel_visible: bool,
}

// Layout constants (logical pixels)
pub(super) const BASE_WIDTH: f64 = 450.0;
pub(super) const SIDEBAR_WIDTH: f64 = 260.0;
pub(super) const ARTIFACT_PANEL_WIDTH: f64 = 400.0;
pub(super) const SPOTLIGHT_HEIGHT: f64 = 600.0;

// Linux taskbar margin - typical panel height
#[cfg(target_os = "linux")]
pub(super) const TASKBAR_MARGIN: f64 = 48.0;
#[cfg(not(target_os = "linux"))]
pub(super) const TASKBAR_MARGIN: f64 = 0.0;

#[tauri::command]
pub fn show_spotlight(app: tauri::AppHandle) {
    commands::show_spotlight(app);
}

#[tauri::command]
pub fn hide_spotlight(app: tauri::AppHandle) {
    commands::hide_spotlight(app);
}

#[tauri::command]
pub fn toggle_spotlight_sidebar(app: tauri::AppHandle, visible: bool) {
    commands::toggle_spotlight_sidebar(app, visible);
}

#[tauri::command]
pub fn toggle_spotlight_artifact_panel(app: tauri::AppHandle, visible: bool) {
    commands::toggle_spotlight_artifact_panel(app, visible);
}

#[tauri::command]
pub fn get_spotlight_layout() -> Result<(bool, bool), String> {
    commands::get_spotlight_layout()
}

#[tauri::command]
pub fn show_gate(app: tauri::AppHandle) {
    commands::show_gate(app);
}

#[tauri::command]
pub fn hide_gate(app: tauri::AppHandle) {
    commands::hide_gate(app);
}

#[tauri::command]
pub fn show_studio(app: tauri::AppHandle) {
    commands::show_studio(app);
}

#[tauri::command]
pub fn hide_studio(app: tauri::AppHandle) {
    commands::hide_studio(app);
}
