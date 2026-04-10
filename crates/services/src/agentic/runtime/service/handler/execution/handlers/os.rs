use super::super::super::focus;
use super::super::{no_visual, ActionExecutionOutcome};
use ioi_api::vm::drivers::os::OsDriver;
use std::sync::Arc;

pub(crate) async fn handle_os_focus_window_tool(
    os_driver: &Arc<dyn OsDriver>,
    title: String,
) -> ActionExecutionOutcome {
    match os_driver.focus_window(&title).await {
        Ok(true) => {
            // Give the window manager a brief moment to apply focus.
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            let focused = os_driver.get_active_window_info().await.unwrap_or(None);
            let msg = if let Some(win) = focused {
                format!("Focused '{}' ({})", win.title, win.app_name)
            } else {
                format!("Focus requested for '{}'", title)
            };
            no_visual(true, Some(msg), None)
        }
        Ok(false) => no_visual(false, None, Some(format!("No window matched '{}'", title))),
        Err(e) => {
            let err = e.to_string();
            if focus::is_missing_focus_dependency_error(&err) {
                no_visual(
                    false,
                    None,
                    Some(format!(
                        "ERROR_CLASS=MissingDependency Focus dependency unavailable for '{}': {}",
                        title, err
                    )),
                )
            } else {
                no_visual(
                    false,
                    None,
                    Some(format!("Window focus failed for '{}': {}", title, err)),
                )
            }
        }
    }
}

pub(crate) async fn handle_os_copy_tool(
    os_driver: &Arc<dyn OsDriver>,
    content: String,
) -> ActionExecutionOutcome {
    match os_driver.set_clipboard(&content).await {
        Ok(()) => no_visual(true, Some("Copied to clipboard".to_string()), None),
        Err(e) => no_visual(false, None, Some(format!("Clipboard write failed: {}", e))),
    }
}

pub(crate) async fn handle_os_paste_tool(os_driver: &Arc<dyn OsDriver>) -> ActionExecutionOutcome {
    match os_driver.get_clipboard().await {
        Ok(content) => no_visual(true, Some(content), None),
        Err(e) => no_visual(false, None, Some(format!("Clipboard read failed: {}", e))),
    }
}
