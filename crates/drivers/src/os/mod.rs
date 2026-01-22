// Path: crates/drivers/src/os/mod.rs

use anyhow::Result;
use async_trait::async_trait;
use active_win_pos_rs::get_active_window;
use ioi_api::vm::drivers::os::OsDriver;
use ioi_types::error::VmError;

/// Native implementation of the OS Driver using `active-win-pos-rs`.
#[derive(Default, Clone)]
pub struct NativeOsDriver;

impl NativeOsDriver {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl OsDriver for NativeOsDriver {
    async fn get_active_window_title(&self) -> Result<Option<String>, VmError> {
        let op = || {
            match get_active_window() {
                Ok(window) => Ok(Some(window.title)),
                Err(e) => {
                    // Log but don't fail hard; just return None implies "unknown context"
                    // which might fail-closed in policy depending on configuration.
                    tracing::warn!("Failed to get active window: {:?}", e);
                    Ok(None)
                }
            }
        };

        // Offload to a blocking thread when a Tokio runtime is available.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            return handle
                .spawn_blocking(op)
                .await
                .map_err(|e| VmError::HostError(format!("Task join error: {}", e)))?;
        }

        // Fallback for non-Tokio worker threads (e.g., parallel execution pool).
        op()
    }
}
