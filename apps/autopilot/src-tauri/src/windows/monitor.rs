use tauri::{AppHandle, Manager};

/// Get the monitor that the spotlight window is on (or should be on)
pub(super) fn get_target_monitor(app: &AppHandle) -> Option<tauri::Monitor> {
    // Priority:
    // 1) spotlight current monitor
    // 2) monitor containing spotlight center (from outer geometry)
    // 3) studio current monitor
    // 4) primary monitor
    // 5) largest available monitor
    if let Some(window) = app.get_webview_window("spotlight") {
        if let Ok(Some(monitor)) = window.current_monitor() {
            return Some(monitor);
        }

        if let (Ok(pos), Ok(size), Ok(monitors)) = (
            window.outer_position(),
            window.outer_size(),
            app.available_monitors(),
        ) {
            let center_x = pos.x + (size.width as i32 / 2);
            let center_y = pos.y + (size.height as i32 / 2);
            for monitor in monitors {
                let mpos = monitor.position();
                let msize = monitor.size();
                let mx = mpos.x;
                let my = mpos.y;
                let mw = msize.width as i32;
                let mh = msize.height as i32;
                if center_x >= mx && center_x < mx + mw && center_y >= my && center_y < my + mh {
                    return Some(monitor);
                }
            }
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

    if let Ok(monitors) = app.available_monitors() {
        let mut best: Option<tauri::Monitor> = None;
        let mut best_area: u64 = 0;
        for monitor in monitors {
            let size = monitor.size();
            let area = (size.width as u64) * (size.height as u64);
            if area >= best_area {
                best_area = area;
                best = Some(monitor);
            }
        }
        if best.is_some() {
            return best;
        }
    }

    None
}
