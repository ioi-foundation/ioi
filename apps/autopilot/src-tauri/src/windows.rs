// apps/autopilot/src-tauri/src/windows.rs

use tauri::{AppHandle, Manager};

#[tauri::command]
pub fn show_spotlight(app: AppHandle) {
    if let Some(window) = app.get_webview_window("spotlight") {
        println!("[Autopilot] 'spotlight' window found. Making visible...");
        // Ensure decorations are off before showing to prevent artifacts
        let _ = window.set_decorations(false);
        if let Err(e) = window.show() {
            eprintln!("[Autopilot] Failed to show spotlight window: {}", e);
        }
        if let Err(e) = window.set_focus() {
            eprintln!("[Autopilot] Failed to focus spotlight window: {}", e);
        }
    } else {
        eprintln!("[Autopilot] CRITICAL: 'spotlight' window not found in AppHandle!");
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
        println!("[Autopilot] Received set_spotlight_mode request: {}", mode);

        // [FIX] Robust monitor detection
        // 1. Try current monitor of spotlight
        // 2. Try current monitor of studio (if spotlight is hidden/unmapped)
        // 3. Fallback to primary
        let mut monitor_opt = window.current_monitor().ok().flatten();

        if monitor_opt.is_none() {
            if let Some(studio) = app.get_webview_window("studio") {
                monitor_opt = studio.current_monitor().ok().flatten();
            }
        }
        
        if monitor_opt.is_none() {
            monitor_opt = window.primary_monitor().ok().flatten();
        }

        let scale = monitor_opt.as_ref().map(|m| m.scale_factor()).unwrap_or(1.0);
        let screen_size = monitor_opt.as_ref().map(|m| m.size());
        let screen_w = screen_size.map(|s| s.width as f64 / scale).unwrap_or(1920.0);
        let screen_h = screen_size.map(|s| s.height as f64 / scale).unwrap_or(1080.0);
        
        // [NEW] Get monitor position offset (important for secondary monitors)
        let monitor_pos = monitor_opt.as_ref().map(|m| m.position());
        let monitor_x = monitor_pos.map(|p| p.x as f64 / scale).unwrap_or(0.0);
        let monitor_y = monitor_pos.map(|p| p.y as f64 / scale).unwrap_or(0.0);

        // Ensure decorations are FALSE
        let _ = window.set_decorations(false);
        let _ = window.set_shadow(true);
        let _ = window.set_always_on_top(true);

        // [FIX] Force un-maximize to ensure set_position works reliably
        if window.is_maximized().unwrap_or(false) {
            let _ = window.unmaximize();
        }

        if mode == "spotlight" {
            // Center large window
            let _ = window.set_resizable(true);
            
            let width = 800.0;
            let height = 600.0;
            let x = monitor_x + (screen_w - width) / 2.0;
            let y = monitor_y + (screen_h - height) / 2.0;
            
            let _ = window.set_size(tauri::Size::Logical(tauri::LogicalSize { width, height }));
            let _ = window.set_position(tauri::Position::Logical(tauri::LogicalPosition { x, y }));
        } else {
            // Sidebar docked right (Legacy support, might be unused in Glass Box)
            let _ = window.set_resizable(true); 
            
            let width = 450.0;
            let height = screen_h - 40.0; 
            
            let x = monitor_x + screen_w - width;
            let y = monitor_y + 0.0; 
            
            let _ = window.set_size(tauri::Size::Logical(tauri::LogicalSize { width, height }));
            let _ = window.set_position(tauri::Position::Logical(tauri::LogicalPosition { x, y }));
        }

        println!("[Autopilot] Mode applied. Showing window now.");
        if let Err(e) = window.show() {
             eprintln!("[Autopilot] Error showing window in set_spotlight_mode: {}", e);
        }
        let _ = window.set_focus();
    } else {
        eprintln!("[Autopilot] ERR: Spotlight window not found in set_spotlight_mode");
    }
}

// [NEW] Consolidated Resizing Logic for Glass Box Architecture
// Handles transition between Pill (Compact) and Chat (Expanded)
#[tauri::command]
pub fn resize_spotlight(app: AppHandle, width: f64, height: f64) {
    if let Some(window) = app.get_webview_window("spotlight") {
        let _ = window.set_size(tauri::Size::Logical(tauri::LogicalSize { width, height }));
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