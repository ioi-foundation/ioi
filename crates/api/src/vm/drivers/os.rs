// Path: crates/api/src/vm/drivers/os.rs

use async_trait::async_trait;
use ioi_types::error::VmError;

/// Detailed information about a window.
#[derive(Debug, Clone)]
pub struct WindowInfo {
    pub title: String,
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub app_name: String,
}

/// Interface for interacting with the Operating System context.
#[async_trait]
pub trait OsDriver: Send + Sync {
    /// Retrieves the title of the currently active (focused) window.
    /// Returns `None` if the active window cannot be determined.
    async fn get_active_window_title(&self) -> Result<Option<String>, VmError>;

    /// [NEW] Retrieves detailed info about the active window.
    async fn get_active_window_info(&self) -> Result<Option<WindowInfo>, VmError>;
}