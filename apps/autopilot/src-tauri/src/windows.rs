use tauri::{AppHandle, Manager};

#[tauri::command]
pub fn show_spotlight(app: AppHandle) {
    if let Some(window) = app.get_webview_window("spotlight") {
        let _ = window.show();
        let _ = window.set_focus();
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
    if let Some(window) = app.get_webview_window("spotlight") {
        if let Ok(Some(monitor)) = window.primary_monitor() {
            let size = monitor.size();
            let scale = monitor.scale_factor();
            let screen_w = size.width as f64 / scale;
            let screen_h = size.height as f64 / scale;

            let _ = window.hide();
            let _ = window.set_decorations(true);
            let _ = window.set_shadow(true);
            let _ = window.set_always_on_top(true);

            if mode == "spotlight" {
                // Allow resizing and maximizing for full-screen workflows
                let _ = window.set_resizable(true);
                let _ = window.set_maximizable(true);
                
                // Larger default size for immersive view
                let width = 1200.0;
                let height = 800.0;
                let x = (screen_w - width) / 2.0;
                let y = (screen_h - height) / 2.0;
                
                let _ = window.set_size(tauri::Size::Logical(tauri::LogicalSize { width, height }));
                let _ = window.set_position(tauri::Position::Logical(tauri::LogicalPosition { x, y }));
            } else {
                // Sidebar Mode: Docked to right
                let _ = window.set_resizable(true); 
                let _ = window.set_maximizable(false);
                
                let width = 450.0;
                let height = screen_h - 40.0; 
                let x = screen_w - width;
                let y = 0.0;
                
                let _ = window.set_size(tauri::Size::Logical(tauri::LogicalSize { width, height }));
                let _ = window.set_position(tauri::Position::Logical(tauri::LogicalPosition { x, y }));
            }

            let _ = window.show();
            let _ = window.set_focus();
        }
    }
}

#[tauri::command]
pub fn show_pill(app: AppHandle) {
    if let Some(window) = app.get_webview_window("pill") {
        if let Ok(Some(monitor)) = window.primary_monitor() {
            let size = monitor.size();
            let scale = monitor.scale_factor();
            let screen_w = size.width as f64 / scale;
            let screen_h = size.height as f64 / scale;
            let win_w = 310.0;
            let win_h = 60.0;
            let margin = 16.0;
            let taskbar = 48.0;
            let x = screen_w - win_w - margin;
            let y = screen_h - win_h - margin - taskbar;
            let _ = window.set_position(tauri::Position::Logical(tauri::LogicalPosition { x, y }));
            let _ = window.set_always_on_top(true);
        }
        let _ = window.show();
    }
}

#[tauri::command]
pub fn hide_pill(app: AppHandle) {
    if let Some(window) = app.get_webview_window("pill") {
        let _ = window.hide();
    }
}

#[tauri::command]
pub fn resize_pill(app: AppHandle, expanded: bool) {
    if let Some(window) = app.get_webview_window("pill") {
        let height = if expanded { 160.0 } else { 60.0 };
        let _ = window.set_size(tauri::Size::Logical(tauri::LogicalSize {
            width: 310.0,
            height,
        }));
    }
}

#[tauri::command]
pub fn show_gate(app: AppHandle) {
    if let Some(window) = app.get_webview_window("gate") {
        let _ = window.center();
        let _ = window.set_always_on_top(true);
        let _ = window.show();
        let _ = window.set_focus();
    }
}

#[tauri::command]
pub fn hide_gate(app: AppHandle) {
    if let Some(window) = app.get_webview_window("gate") {
        let _ = window.hide();
    }
}

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