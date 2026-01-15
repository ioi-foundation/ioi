// Path: crates/api/src/vm/drivers/os.rs

use async_trait::async_trait;
use ioi_types::error::VmError;

/// Interface for interacting with the Operating System context.
#[async_trait]
pub trait OsDriver: Send + Sync {
    /// Retrieves the title of the currently active (focused) window.
    /// Returns `None` if the active window cannot be determined.
    async fn get_active_window_title(&self) -> Result<Option<String>, VmError>;
}