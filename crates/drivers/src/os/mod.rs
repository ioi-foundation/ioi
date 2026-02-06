// Path: crates/drivers/src/os/mod.rs

use anyhow::Result;
use async_trait::async_trait;
use active_win_pos_rs::get_active_window;
use ioi_api::vm::drivers::os::{OsDriver, WindowInfo};
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
                    tracing::warn!("Failed to get active window: {:?}", e);
                    Ok(None)
                }
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
        let op = || {
            match get_active_window() {
                Ok(w) => Ok(Some(WindowInfo {
                    title: w.title,
                    x: w.position.x as i32,
                    y: w.position.y as i32,
                    // [FIX] Use w.position.width/height instead of w.size
                    width: w.position.width as i32,
                    height: w.position.height as i32,
                    app_name: w.app_name,
                })),
                Err(e) => {
                    tracing::warn!("Failed to get active window info: {:?}", e);
                    Ok(None)
                }
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
}