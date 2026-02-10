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

    /// Retrieves detailed info about the active window.
    async fn get_active_window_info(&self) -> Result<Option<WindowInfo>, VmError>;

    /// Focuses a window by matching its title (fuzzy match).
    /// Returns `true` if a matching window was found and focus was requested.
    async fn focus_window(&self, title_query: &str) -> Result<bool, VmError>;

    /// Writes text to the system clipboard.
    async fn set_clipboard(&self, content: &str) -> Result<(), VmError>;

    /// Reads text from the system clipboard.
    async fn get_clipboard(&self) -> Result<String, VmError>;
}
