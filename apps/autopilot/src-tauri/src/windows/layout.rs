#[cfg(target_os = "linux")]
use gtk::prelude::{GtkWindowExt, WidgetExt};

use tauri::{AppHandle, Manager, WebviewWindow};

use super::monitor::get_target_monitor;
use super::{
    SpotlightLayout, ARTIFACT_PANEL_WIDTH, BASE_WIDTH, SIDEBAR_WIDTH, SPOTLIGHT_HEIGHT,
    TASKBAR_MARGIN,
};

pub(super) fn focus_window_best_effort(window: &WebviewWindow) {
    let _ = window.set_focusable(true);
    let _ = window.set_focus();

    #[cfg(target_os = "linux")]
    if let Ok(gtk_window) = window.gtk_window() {
        gtk_window.set_accept_focus(true);
        gtk_window.set_focus_on_map(true);

        if let Some(gdk_window) = gtk_window.window() {
            // 0 is the standard "current time" sentinel for GDK/X11 focus calls.
            gdk_window.focus(0);
            gdk_window.raise();
        }

        gtk_window.present();
    }
}

fn set_window_geometry(
    window: &WebviewWindow,
    x_px: f64,
    y_px: f64,
    width_px: f64,
    height_px: f64,
) {
    let width = width_px.max(1.0).round() as u32;
    let height = height_px.max(1.0).round() as u32;
    let x = x_px.round() as i32;
    let y = y_px.round() as i32;

    let _ = window.set_size(tauri::Size::Physical(tauri::PhysicalSize { width, height }));
    let _ = window.set_position(tauri::Position::Physical(tauri::PhysicalPosition { x, y }));
}

pub(super) fn apply_layout(app: &AppHandle, layout: &SpotlightLayout) -> Result<(), String> {
    let window = app
        .get_webview_window("spotlight")
        .ok_or("Spotlight window not found")?;

    let monitor = get_target_monitor(app).ok_or("No monitor found")?;

    let scale = monitor.scale_factor();
    let screen_size = monitor.size();
    let screen_w = screen_size.width as f64;
    let screen_h = screen_size.height as f64;

    let monitor_pos = monitor.position();
    let monitor_x = monitor_pos.x as f64;
    let monitor_y = monitor_pos.y as f64;

    let mut window_width_px = BASE_WIDTH * scale;
    if layout.sidebar_visible {
        window_width_px += SIDEBAR_WIDTH * scale;
    }
    if layout.artifact_panel_visible {
        window_width_px += ARTIFACT_PANEL_WIDTH * scale;
    }

    // Keep width within the monitor even when both side panels are visible.
    let max_window_width = (screen_w - (32.0 * scale)).max(1.0);
    window_width_px = window_width_px.min(max_window_width);

    let available_height = (screen_h - (TASKBAR_MARGIN * scale)).max(1.0);
    let window_height_px = (SPOTLIGHT_HEIGHT * scale).min(available_height);

    let x = monitor_x + ((screen_w - window_width_px) / 2.0).max(0.0);
    let y = monitor_y + ((screen_h - window_height_px) / 2.0).max(0.0);

    if window.is_maximized().unwrap_or(false) {
        let _ = window.unmaximize();
    }

    let _ = window.set_decorations(false);
    let _ = window.set_resizable(false);
    let _ = window.set_focusable(true);
    let _ = window.set_ignore_cursor_events(false);

    #[cfg(target_os = "linux")]
    {
        let _ = window.set_skip_taskbar(true);
        let _ = window.set_always_on_top(true);
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = window.set_always_on_top(true);
    }

    set_window_geometry(&window, x, y, window_width_px, window_height_px);

    Ok(())
}
