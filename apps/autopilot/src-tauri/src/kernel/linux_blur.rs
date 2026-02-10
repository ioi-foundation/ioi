// apps/autopilot/src-tauri/src/kernel/linux_blur.rs

#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(target_os = "linux")]
use tauri::WebviewWindow;

/// Attempts to inject X11 atoms to request background blur from the compositor (KWin/Picom).
/// This is a "Best Effort" approach using standard utils (xprop) to avoid heavy build dependencies.
#[cfg(target_os = "linux")]
pub fn setup_kwin_blur(window: &WebviewWindow) {
    let title = window.title().unwrap_or("Autopilot".into());

    // Spawn a thread to wait briefly for the window to map, then inject properties
    let title_clone = title.to_string();

    std::thread::spawn(move || {
        // Wait for window to actually appear on X server
        std::thread::sleep(std::time::Duration::from_millis(800));

        // 1. Attempt to find Window ID using xdotool (common utility)
        let output = Command::new("xdotool")
            .arg("search")
            .arg("--name")
            .arg(&title_clone)
            .output();

        if let Ok(o) = output {
            let stdout = String::from_utf8_lossy(&o.stdout);
            // xdotool might return multiple IDs, usually the last one is the actual mapped window
            if let Some(id_str) = stdout.lines().last() {
                let id = id_str.trim();
                if !id.is_empty() {
                    println!("[Linux] Found window ID {}, requesting blur atoms...", id);

                    // 2. Set the Blur Atom (Supported by KDE KWin and Dual-Kawase Picom)
                    // Property: _KDE_NET_WM_BLUR_BEHIND_REGION
                    // Value: 0 (Cardinal) indicates "Blur whole window"
                    let _ = Command::new("xprop")
                        .arg("-id")
                        .arg(id)
                        .arg("-f")
                        .arg("_KDE_NET_WM_BLUR_BEHIND_REGION")
                        .arg("32c")
                        .arg("-set")
                        .arg("_KDE_NET_WM_BLUR_BEHIND_REGION")
                        .arg("0")
                        .spawn();

                    // 3. Optional: Set specific opacity hint if needed (though Tauri config does this)
                    // _NET_WM_WINDOW_OPACITY
                }
            }
        } else {
            println!("[Linux] xdotool not found. Native blur request skipped (falling back to CSS texture).");
        }
    });
}
