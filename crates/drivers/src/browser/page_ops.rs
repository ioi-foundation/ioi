use super::*;
use chromiumoxide::cdp::browser_protocol::dom::{
    BackendNodeId, GetDocumentParams, QuerySelectorParams, SetFileInputFilesParams,
};
use chromiumoxide::cdp::browser_protocol::input::{
    DispatchKeyEventParams, DispatchKeyEventType, InsertTextParams,
};
use chromiumoxide::cdp::browser_protocol::page::{
    GetNavigationHistoryParams, NavigateToHistoryEntryParams,
};
use chromiumoxide::keys;
use std::time::Instant;

impl BrowserDriver {
    pub async fn known_active_url(&self) -> Option<String> {
        self.active_page_url.lock().await.clone()
    }

    fn validate_upload_paths(paths: &[String]) -> std::result::Result<Vec<String>, BrowserError> {
        if paths.is_empty() {
            return Err(BrowserError::Internal(
                "browser__upload_file requires at least one path".to_string(),
            ));
        }

        paths
            .iter()
            .map(|raw| {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return Err(BrowserError::Internal(
                        "browser__upload_file paths cannot be empty".to_string(),
                    ));
                }
                let path = std::path::Path::new(trimmed);
                if !path.is_absolute() {
                    return Err(BrowserError::Internal(format!(
                        "Upload path must be an absolute scoped file path: '{}'",
                        trimmed
                    )));
                }
                if !path.is_file() {
                    return Err(BrowserError::Internal(format!(
                        "Upload path is not a file: '{}'",
                        trimmed
                    )));
                }
                Ok(trimmed.to_string())
            })
            .collect::<Result<Vec<String>, BrowserError>>()
    }

    pub async fn active_url(&self) -> std::result::Result<String, BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;
        let current_url = self
            .check_connection_error(page.url().await)
            .await
            .map_err(|e| BrowserError::Internal(format!("Failed to query active URL: {}", e)))
            .map(|url| url.unwrap_or_default())?;
        *self.active_page_url.lock().await = Some(current_url.clone());
        Ok(current_url)
    }

    pub async fn go_back(&self, steps: u32) -> std::result::Result<(u32, String), BrowserError> {
        self.require_runtime()?;
        self.ensure_page().await?;

        let page = { self.active_page.lock().await.clone() }.ok_or(BrowserError::NoActivePage)?;
        let target_steps = if steps == 0 { 1 } else { steps };
        let mut moved = 0u32;

        while moved < target_steps {
            let history = self
                .check_connection_error(page.execute(GetNavigationHistoryParams::default()).await)
                .await
                .map_err(|e| {
                    BrowserError::Internal(format!("Failed to fetch navigation history: {}", e))
                })?;

            if history.current_index <= 0 {
                break;
            }

            let prev_index = (history.current_index - 1) as usize;
            let Some(entry) = history.entries.get(prev_index) else {
                break;
            };

            self.check_connection_error(
                page.execute(NavigateToHistoryEntryParams::new(entry.id))
                    .await,
            )
            .await
            .map_err(|e| {
                BrowserError::Internal(format!(
                    "Failed to navigate to history entry {}: {}",
                    entry.id, e
                ))
            })?;

            page.wait_for_navigation().await.map_err(|e| {
                BrowserError::Internal(format!("Back navigation wait failed: {}", e))
            })?;

            self.reset_pointer_state().await;
            moved += 1;
        }

        let current_url = self
            .check_connection_error(page.url().await)
            .await
            .map_err(|e| BrowserError::Internal(format!("Failed to query active URL: {}", e)))?
            .unwrap_or_default();
        *self.active_page_url.lock().await = Some(current_url.clone());
        self.record_browser_use_event("GoBackEvent", None, Some(current_url.clone()), None)
            .await;

        Ok((moved, current_url))
    }
}

include!("page_ops/navigation.rs");

include!("page_ops/waits.rs");

include!("page_ops/text_search.rs");

include!("page_ops/file_inputs.rs");

include!("page_ops/dropdowns.rs");

include!("page_ops/tab_management.rs");

include!("page_ops/browser_use_state.rs");

include!("page_ops/input_events.rs");
