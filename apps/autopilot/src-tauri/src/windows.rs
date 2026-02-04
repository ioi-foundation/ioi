// apps/autopilot/src-tauri/src/windows.rs

use tauri::{AppHandle, Manager, WebviewWindow};
use std::sync::Mutex;
use once_cell::sync::Lazy;

// ============================================
// DOCK STATE MANAGEMENT
// ============================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DockPosition {
    Right,      // Docked to right edge of screen
    Center,     // Centered spotlight mode
    Float,      // Free-floating (user moved it)
}

#[derive(Debug, Clone, Copy)]
pub struct SpotlightLayout {
    pub dock_position: DockPosition,
    pub sidebar_visible: bool,
    pub artifact_panel_visible: bool,
}

impl Default for SpotlightLayout {
    fn default() -> Self {
        Self {
            dock_position: DockPosition::Right,
            sidebar_visible: false,
            artifact_panel_visible: false,
        }
    }
}

// Global layout state
static SPOTLIGHT_LAYOUT: Lazy<Mutex<SpotlightLayout>> = Lazy::new(|| {
    Mutex::new(SpotlightLayout::default())
});

// Layout constants (logical pixels)
const BASE_WIDTH: f64 = 450.0;
const SIDEBAR_WIDTH: f64 = 260.0;
const ARTIFACT_PANEL_WIDTH: f64 = 400.0;
const SPOTLIGHT_HEIGHT: f64 = 600.0;
const VERTICAL_MARGIN: f64 = 0.0;

// Linux taskbar margin - typical panel height
#[cfg(target_os = "linux")]
const TASKBAR_MARGIN: f64 = 48.0;
#[cfg(not(target_os = "linux"))]
const TASKBAR_MARGIN: f64 = 0.0;

// ============================================
// HELPER FUNCTIONS
// ============================================

/// Get the monitor that the spotlight window is on (or should be on)
fn get_target_monitor(app: &AppHandle) -> Option<tauri::Monitor> {
    // Priority: spotlight's current monitor > studio's monitor > primary
    if let Some(window) = app.get_webview_window("spotlight") {
        if let Ok(Some(monitor)) = window.current_monitor() {
            return Some(monitor);
        }
    }
    
    if let Some(studio) = app.get_webview_window("studio") {
        if let Ok(Some(monitor)) = studio.current_monitor() {
            return Some(monitor);
        }
    }
    
    if let Some(window) = app.get_webview_window("spotlight") {
        if let Ok(Some(monitor)) = window.primary_monitor() {
            return Some(monitor);
        }
    }
    
    None
}

/// Calculate the required window width based on current layout
fn calculate_window_width(layout: &SpotlightLayout) -> f64 {
    let mut width = BASE_WIDTH;
    
    if layout.sidebar_visible {
        width += SIDEBAR_WIDTH;
    }
    
    if layout.artifact_panel_visible {
        width += ARTIFACT_PANEL_WIDTH;
    }
    
    width
}

/// Apply geometry changes with platform-specific ordering and safety.
/// This prevents the "undock" issue on Linux by ensuring size updates 
/// propagate to the WM before position updates are applied.
fn set_window_geometry(window: &WebviewWindow, x: f64, y: f64, width: f64, height: f64) {
    // 1. Set Size first
    let _ = window.set_size(tauri::Size::Logical(tauri::LogicalSize { width, height }));
    
    // 2. Set Position
    // On Linux/X11, setting position immediately after size might race if the WM compensates.
    // We defer the position update slightly to ensure it overrides any auto-placement or clamping
    // based on the old geometry.
    #[cfg(target_os = "linux")]
    {
        let w_handle = window.clone();
        tauri::async_runtime::spawn(async move {
            // Tiny delay to let the resize event propagate to WM
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            let _ = w_handle.set_position(tauri::Position::Logical(tauri::LogicalPosition { x, y }));
            
            // Redundancy check: force it again after a frame if it drifted (common in KWin/Mutter)
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let _ = w_handle.set_position(tauri::Position::Logical(tauri::LogicalPosition { x, y }));
        });
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = window.set_position(tauri::Position::Logical(tauri::LogicalPosition { x, y }));
    }
}

fn calculate_window_position(
    dock: DockPosition,
    window_width: f64,
    window_height: f64,
    screen_width: f64,
    screen_height: f64,
    monitor_x: f64,
    monitor_y: f64,
) -> (f64, f64) {
    match dock {
        DockPosition::Right => {
            // Anchor to right edge
            let x = monitor_x + screen_width - window_width;
            let y = monitor_y + VERTICAL_MARGIN;
            (x, y)
        }
        DockPosition::Center => {
            // Centered
            let x = monitor_x + (screen_width - window_width) / 2.0;
            let y = monitor_y + (screen_height - window_height) / 2.0;
            (x, y)
        }
        DockPosition::Float => {
            // For floating, this function usually isn't called directly for position
            // unless resetting.
            (monitor_x, monitor_y)
        }
    }
}

fn apply_layout(app: &AppHandle, layout: &SpotlightLayout) -> Result<(), String> {
    let window = app.get_webview_window("spotlight")
        .ok_or("Spotlight window not found")?;
    
    let monitor = get_target_monitor(app)
        .ok_or("No monitor found")?;
    
    let scale = monitor.scale_factor();
    let screen_size = monitor.size();
    let screen_w = screen_size.width as f64 / scale;
    let screen_h = screen_size.height as f64 / scale;
    
    let monitor_pos = monitor.position();
    let monitor_x = monitor_pos.x as f64 / scale;
    let monitor_y = monitor_pos.y as f64 / scale;
    
    // Calculate dimensions
    let available_height = screen_h - TASKBAR_MARGIN - VERTICAL_MARGIN;
    let width = calculate_window_width(layout);
    let height = match layout.dock_position {
        DockPosition::Right => available_height,
        DockPosition::Center => SPOTLIGHT_HEIGHT.min(available_height),
        DockPosition::Float => {
            if let Ok(size) = window.outer_size() {
                (size.height as f64 / scale).min(available_height)
            } else {
                SPOTLIGHT_HEIGHT.min(available_height)
            }
        }
    };
    
    // Calculate position
    let (x, y) = if layout.dock_position == DockPosition::Float {
        if let Ok(pos) = window.outer_position() {
            let current_x = pos.x as f64 / scale;
            let current_y = pos.y as f64 / scale;
            
            // Adjust X to keep right edge stable if width changed
            if let Ok(current_size) = window.outer_size() {
                let current_width = current_size.width as f64 / scale;
                let width_diff = width - current_width;
                (current_x - width_diff, current_y)
            } else {
                (current_x, current_y)
            }
        } else {
            calculate_window_position(DockPosition::Center, width, height, screen_w, screen_h, monitor_x, monitor_y)
        }
    } else {
        calculate_window_position(layout.dock_position, width, height, screen_w, screen_h, monitor_x, monitor_y)
    };
    
    // Apply changes
    if window.is_maximized().unwrap_or(false) {
        let _ = window.unmaximize();
    }
    let _ = window.set_resizable(true);
    
    set_window_geometry(&window, x, y, width, height);
    
    // Visual properties
    #[cfg(not(target_os = "linux"))]
    {
        let _ = window.set_decorations(false);
        let _ = window.set_shadow(true);
        let _ = window.set_always_on_top(layout.dock_position != DockPosition::Float);
    }
    
    #[cfg(target_os = "linux")]
    if window.is_visible().unwrap_or(false) {
        let _ = window.set_always_on_top(layout.dock_position != DockPosition::Float);
    }
    
    Ok(())
}

// ============================================
// TAURI COMMANDS
// ============================================

#[tauri::command]
pub fn show_spotlight(app: AppHandle) {
    if let Some(window) = app.get_webview_window("spotlight") {
        // Prepare window
        let _ = window.set_resizable(true);
        
        // On non-Linux, apply layout first to avoid flicker
        #[cfg(not(target_os = "linux"))]
        if let Ok(layout) = SPOTLIGHT_LAYOUT.lock() {
            let _ = apply_layout(&app, &layout);
        }
        
        let _ = window.show();
        let _ = window.set_focus();
        
        // On Linux, applying layout after show is safer for some compositors
        #[cfg(target_os = "linux")]
        if let Ok(layout) = SPOTLIGHT_LAYOUT.lock() {
            let _ = apply_layout(&app, &layout);
        }
    }
}

#[tauri::command]
pub fn hide_spotlight(app: AppHandle) {
    if let Some(window) = app.get_webview_window("spotlight") {
        let _ = window.hide();
    }
}

#[tauri::command]
pub fn set_spotlight_mode(app: AppHandle, mode: String) {
    let position = match mode.as_str() {
        "spotlight" | "center" => DockPosition::Center,
        "sidebar" | "right" => DockPosition::Right,
        "float" => DockPosition::Float,
        _ => DockPosition::Right,
    };
    
    if let Ok(mut layout) = SPOTLIGHT_LAYOUT.lock() {
        layout.dock_position = position;
        let _ = apply_layout(&app, &layout);
    }
    
    // Ensure visibility
    if let Some(window) = app.get_webview_window("spotlight") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

#[tauri::command]
pub fn toggle_spotlight_sidebar(app: AppHandle, visible: bool) {
    if let Ok(mut layout) = SPOTLIGHT_LAYOUT.lock() {
        if layout.sidebar_visible == visible { return; }
        layout.sidebar_visible = visible;
        
        // Apply changes
        // This will trigger the set_window_geometry logic which handles the X11 race condition
        let _ = apply_layout(&app, &layout);
    }
}

#[tauri::command]
pub fn toggle_spotlight_artifact_panel(app: AppHandle, visible: bool) {
    if let Ok(mut layout) = SPOTLIGHT_LAYOUT.lock() {
        if layout.artifact_panel_visible == visible { return; }
        layout.artifact_panel_visible = visible;
        let _ = apply_layout(&app, &layout);
    }
}

#[tauri::command]
pub fn get_spotlight_layout() -> Result<(String, bool, bool), String> {
    if let Ok(layout) = SPOTLIGHT_LAYOUT.lock() {
        let s = match layout.dock_position {
            DockPosition::Right => "right",
            DockPosition::Center => "center",
            DockPosition::Float => "float",
        };
        Ok((s.to_string(), layout.sidebar_visible, layout.artifact_panel_visible))
    } else {
        Err("Lock failed".into())
    }
}

#[tauri::command]
pub fn resize_spotlight(app: AppHandle, width: f64, height: f64) {
    if let Some(window) = app.get_webview_window("spotlight") {
        // User manual resize implies floating mode
        if let Ok(mut layout) = SPOTLIGHT_LAYOUT.lock() {
            layout.dock_position = DockPosition::Float;
        }
        let _ = window.set_size(tauri::Size::Logical(tauri::LogicalSize { width, height }));
    }
}

#[tauri::command]
pub fn dock_spotlight_right(app: AppHandle) {
    if let Ok(mut layout) = SPOTLIGHT_LAYOUT.lock() {
        layout.dock_position = DockPosition::Right;
        let _ = apply_layout(&app, &layout);
    }
}

// ============================================
// GATE WINDOW
// ============================================

#[tauri::command]
pub fn show_gate(app: AppHandle) {
    if let Some(window) = app.get_webview_window("gate") {
        let _ = window.center();
        #[cfg(not(target_os = "linux"))]
        let _ = window.set_always_on_top(true);
        let _ = window.show();
        let _ = window.set_focus();
        #[cfg(target_os = "linux")]
        if window.is_visible().unwrap_or(false) { let _ = window.set_always_on_top(true); }
    }
}

#[tauri::command]
pub fn hide_gate(app: AppHandle) {
    if let Some(window) = app.get_webview_window("gate") {
        let _ = window.hide();
    }
}

// ============================================
// STUDIO WINDOW
// ============================================

#[tauri::command]
pub fn show_studio(app: AppHandle) {
    if let Some(window) = app.get_webview_window("studio") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

#[tauri::command]
pub fn hide_studio(app: AppHandle) {
    if let Some(window) = app.get_webview_window("studio") {
        let _ = window.hide();
    }
}