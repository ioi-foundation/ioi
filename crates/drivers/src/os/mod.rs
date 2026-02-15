// Path: crates/drivers/src/os/mod.rs

use active_win_pos_rs::get_active_window;
use anyhow::Result;
use arboard::Clipboard;
use async_trait::async_trait;
use ioi_api::vm::drivers::os::{OsDriver, WindowInfo};
use ioi_types::error::VmError;
use std::io::ErrorKind;
use std::process::Command;
use std::sync::Mutex;

/// Deterministic fallback OS driver used when a runtime does not provide
/// native OS integrations.
pub struct UnavailableOsDriver;

impl UnavailableOsDriver {
    fn missing_dependency_error(action: &str) -> VmError {
        VmError::HostError(format!(
            "ERROR_CLASS=MissingDependency OS driver is unavailable for {} in this runtime.",
            action
        ))
    }
}

impl Default for UnavailableOsDriver {
    fn default() -> Self {
        Self
    }
}

/// Native implementation of the OS Driver using `active-win-pos-rs` and `arboard`.
pub struct NativeOsDriver {
    clipboard: Mutex<Option<Clipboard>>,
}

impl NativeOsDriver {
    pub fn new() -> Self {
        // Initialize clipboard lazily or log warning
        let cb = match Clipboard::new() {
            Ok(c) => Some(c),
            Err(e) => {
                tracing::warn!("Failed to initialize clipboard: {}", e);
                None
            }
        };
        Self {
            clipboard: Mutex::new(cb),
        }
    }
}

// Implement Default manually to handle clipboard
impl Default for NativeOsDriver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl OsDriver for UnavailableOsDriver {
    async fn get_active_window_title(&self) -> Result<Option<String>, VmError> {
        Ok(None)
    }

    async fn get_active_window_info(&self) -> Result<Option<WindowInfo>, VmError> {
        Ok(None)
    }

    async fn focus_window(&self, _title_query: &str) -> Result<bool, VmError> {
        Err(Self::missing_dependency_error("window focus"))
    }

    async fn set_clipboard(&self, _content: &str) -> Result<(), VmError> {
        Err(Self::missing_dependency_error("clipboard write"))
    }

    async fn get_clipboard(&self) -> Result<String, VmError> {
        Err(Self::missing_dependency_error("clipboard read"))
    }
}

#[async_trait]
impl OsDriver for NativeOsDriver {
    async fn get_active_window_title(&self) -> Result<Option<String>, VmError> {
        let op = || match get_active_window() {
            Ok(window) => Ok(Some(window.title)),
            Err(e) => {
                tracing::warn!("Failed to get active window: {:?}", e);
                Ok(None)
            }
        };

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            return handle
                .spawn_blocking(op)
                .await
                .map_err(|e| VmError::HostError(format!("Task join error: {}", e)))?;
        }
        op()
    }

    async fn get_active_window_info(&self) -> Result<Option<WindowInfo>, VmError> {
        let op = || match get_active_window() {
            Ok(w) => Ok(Some(WindowInfo {
                title: w.title,
                x: w.position.x as i32,
                y: w.position.y as i32,
                width: w.position.width as i32,
                height: w.position.height as i32,
                app_name: w.app_name,
            })),
            Err(e) => {
                tracing::warn!("Failed to get active window info: {:?}", e);
                Ok(None)
            }
        };

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            return handle
                .spawn_blocking(op)
                .await
                .map_err(|e| VmError::HostError(format!("Task join error: {}", e)))?;
        }
        op()
    }

    async fn focus_window(&self, title_query: &str) -> Result<bool, VmError> {
        let query = title_query.to_string();

        let op = move || -> Result<bool, String> {
            #[cfg(target_os = "linux")]
            {
                // Requires `wmctrl` installed
                // wmctrl -a <TITLE>
                let output = match Command::new("wmctrl").arg("-a").arg(&query).output() {
                    Ok(output) => output,
                    Err(e) if e.kind() == ErrorKind::NotFound => return Err(
                        "ERROR_CLASS=MissingDependency Missing focus dependency 'wmctrl' on Linux."
                            .to_string(),
                    ),
                    Err(e) => return Err(format!("Failed to execute wmctrl: {}", e)),
                };

                if output.status.success() {
                    Ok(true)
                } else {
                    tracing::warn!(
                        "wmctrl focus failed for query '{}': {}",
                        query,
                        String::from_utf8_lossy(&output.stderr)
                    );
                    Ok(false)
                }
            }
            #[cfg(target_os = "macos")]
            {
                // AppleScript to focus app/window
                let script = format!(
                    r#"
                    tell application "System Events"
                        set procList to every process whose visible is true
                        repeat with proc in procList
                            try
                                tell proc
                                    if (name of proc contains "{0}") or (name of first window of proc contains "{0}") then
                                        set frontmost to true
                                        return "true"
                                    end if
                                end tell
                            end try
                        end repeat
                    end tell
                    return "false"
                    "#,
                    query
                );
                let output = Command::new("osascript")
                    .arg("-e")
                    .arg(&script)
                    .output()
                    .map_err(|e| format!("osascript failed: {}", e))?;

                let res = String::from_utf8_lossy(&output.stdout);
                Ok(res.trim() == "true")
            }
            #[cfg(target_os = "windows")]
            {
                // PowerShell snippet to focus window
                // NOTE: Focusing windows from background process in Windows is restricted.
                // This script attempts a basic AppActivate.
                let script = format!(
                    r#"
                    $w = Get-Process | Where-Object {{ $_.MainWindowTitle -like "*{0}*" }} | Select-Object -First 1
                    if ($w) {{
                        $wsh = New-Object -ComObject WScript.Shell
                        $wsh.AppActivate($w.Id)
                        Write-Output "true"
                    }} else {{
                        Write-Output "false"
                    }}
                    "#,
                    query
                );
                let output = Command::new("powershell")
                    .arg("-Command")
                    .arg(&script)
                    .output()
                    .map_err(|e| format!("powershell failed: {}", e))?;

                let res = String::from_utf8_lossy(&output.stdout);
                Ok(res.trim() == "true")
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            {
                Err("Window focus not supported on this OS".to_string())
            }
        };

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle
                .spawn_blocking(op)
                .await
                .map_err(|e| VmError::HostError(format!("Task join error: {}", e)))?
                .map_err(|e| VmError::HostError(e))
        } else {
            op().map_err(|e| VmError::HostError(e))
        }
    }

    async fn set_clipboard(&self, content: &str) -> Result<(), VmError> {
        let content_owned = content.to_string();
        // Use a closure to wrap the blocking operation
        let op = {
            // We need to move ownership or access the mutex inside the closure.
            // Since Mutex isn't Clone, we can't capture `self` easily inside spawn_blocking if we don't clone the Arc/Mutex.
            // However, NativeOsDriver owns the Mutex.
            // But Clipboard operations are blocking.
            // The simplest way without refactoring NativeOsDriver to hold Arc<Mutex> internally (which it doesn't currently)
            // is to just block on the lock. Clipboard ops are fast enough for now, or we accept blocking the async thread briefly.
            // But `arboard` clipboard access is generally fast.
            // If we really want to spawn_blocking, we need `self` to be `Arc` or cloneable.
            // The `OsDriver` trait takes `&self`.

            // For now, let's execute synchronously inside the async function.
            // In a high-concurrency server this is bad, but for a local agent it's acceptable.
            let mut guard = self.clipboard.lock().unwrap();
            if let Some(cb) = guard.as_mut() {
                cb.set_text(content_owned)
                    .map_err(|e| VmError::HostError(format!("Clipboard write failed: {}", e)))
            } else {
                Err(VmError::HostError("Clipboard not available".into()))
            }
        };
        op
    }

    async fn get_clipboard(&self) -> Result<String, VmError> {
        let mut guard = self.clipboard.lock().unwrap();

        if let Some(cb) = guard.as_mut() {
            cb.get_text()
                .map_err(|e| VmError::HostError(format!("Clipboard read failed: {}", e)))
        } else {
            Err(VmError::HostError("Clipboard not available".into()))
        }
    }
}
