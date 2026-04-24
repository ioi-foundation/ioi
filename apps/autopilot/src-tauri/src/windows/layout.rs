#[cfg(target_os = "linux")]
use gtk::prelude::{GtkWindowExt, WidgetExt};

use tauri::{AppHandle, Manager, WebviewWindow};

use super::monitor::get_target_monitor;
use super::{
    should_surface_overlay_windows_in_task_switcher, ChatSessionLayout, ARTIFACT_PANEL_WIDTH,
    BASE_WIDTH, CHAT_SESSION_HEIGHT, COMPACT_ARTIFACT_PANEL_WIDTH, COMPACT_SIDEBAR_WIDTH,
    SIDEBAR_WIDTH, TASKBAR_MARGIN,
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

    #[cfg(target_os = "linux")]
    if let Ok(gtk_window) = window.gtk_window() {
        // Tauri's position update can be ignored on X11 after a live resize.
        // Mirror the geometry through GTK so expanded Chat panels stay on-screen.
        gtk_window.resize(width as i32, height as i32);
        gtk_window.move_(x, y);
        gtk_window.queue_resize();
    }
}

pub(super) fn apply_layout(app: &AppHandle, layout: &ChatSessionLayout) -> Result<(), String> {
    let window = app
        .get_webview_window("chat-session")
        .ok_or("Chat session window not found")?;

    let monitor = get_target_monitor(app).ok_or("No monitor found")?;

    let scale = monitor.scale_factor();
    let screen_size = monitor.size();
    let screen_w = screen_size.width as f64;
    let screen_h = screen_size.height as f64;

    let monitor_pos = monitor.position();
    let monitor_x = monitor_pos.x as f64;
    let monitor_y = monitor_pos.y as f64;

    let sidebar_width = if layout.sidebar_visible {
        if layout.artifact_panel_visible {
            COMPACT_SIDEBAR_WIDTH
        } else {
            SIDEBAR_WIDTH
        }
    } else {
        0.0
    };
    let artifact_width = if layout.artifact_panel_visible {
        if layout.sidebar_visible {
            COMPACT_ARTIFACT_PANEL_WIDTH
        } else {
            ARTIFACT_PANEL_WIDTH
        }
    } else {
        0.0
    };

    let mut window_width_px = (BASE_WIDTH + sidebar_width + artifact_width) * scale;

    // Keep width within the monitor even when both side panels are visible.
    let max_window_width = (screen_w - (32.0 * scale)).max(1.0);
    window_width_px = window_width_px.min(max_window_width);

    let available_height = (screen_h - (TASKBAR_MARGIN * scale)).max(1.0);
    let window_height_px = (CHAT_SESSION_HEIGHT * scale).min(available_height);

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
        let reveal_in_task_switcher = should_surface_overlay_windows_in_task_switcher();
        let _ = window.set_skip_taskbar(!reveal_in_task_switcher);
        let _ = window.set_visible_on_all_workspaces(reveal_in_task_switcher);
        let _ = window.set_always_on_top(true);
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = window.set_always_on_top(true);
    }

    set_window_geometry(&window, x, y, window_width_px, window_height_px);

    Ok(())
}
