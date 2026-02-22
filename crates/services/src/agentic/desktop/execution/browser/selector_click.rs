use super::super::{ToolExecutionResult, ToolExecutor};
use crate::agentic::desktop::types::ExecutionTier;
use ioi_api::vm::drivers::gui::{AtomicInput, InputEvent};
use ioi_drivers::browser::SelectorProbe;
use serde_json::json;
use tokio::time::{sleep, Duration};

use super::surface::is_probable_browser_window;

const SEARCH_FOCUS_SELECTORS: &[&str] = &[
    "textarea[name='q']",
    "input[name='q']",
    "input[type='search']",
    "textarea[aria-label*='search' i]",
    "input[aria-label*='search' i]",
    "textarea[placeholder*='search' i]",
    "input[placeholder*='search' i]",
];

pub(super) fn selector_focus_postcondition(
    pre: &SelectorProbe,
    post: Option<&SelectorProbe>,
) -> bool {
    let Some(post) = post else {
        return false;
    };

    if pre.editable {
        return post.found && post.visible && post.focused;
    }

    // Accept successful state transitions where the click navigated or the
    // target disappeared after activation.
    if !pre.url.is_empty() && !post.url.is_empty() && post.url != pre.url {
        return true;
    }
    if pre.found && !post.found {
        return true;
    }

    post.found && post.visible && post.topmost
}

pub(super) fn selector_looks_like_search_target(selector: &str) -> bool {
    let s = selector.to_ascii_lowercase();
    s.contains("search")
        || s.contains("name='q'")
        || s.contains("name=\"q\"")
        || s.contains("[name=q]")
        || s.contains("textarea")
        || s.contains("input")
}

pub(super) fn requires_browser_focus_guard(tier: Option<ExecutionTier>) -> bool {
    !matches!(tier, Some(ExecutionTier::DomHeadless))
}

pub(super) fn ensure_browser_focus_guard(exec: &ToolExecutor) -> Option<ToolExecutionResult> {
    if !requires_browser_focus_guard(exec.current_tier) {
        return None;
    }

    if let Some(win) = exec.active_window.as_ref() {
        if !is_probable_browser_window(&win.title, &win.app_name) {
            return Some(ToolExecutionResult::failure(format!(
                "ERROR_CLASS=FocusMismatch Active window is '{}' ({}) but browser click requires a focused browser surface.",
                win.title, win.app_name
            )));
        }
    }

    None
}

pub(super) async fn handle_browser_click(
    exec: &ToolExecutor,
    selector: &str,
) -> ToolExecutionResult {
    if let Some(blocked) = ensure_browser_focus_guard(exec) {
        return blocked;
    }

    let pre = match exec.browser.probe_selector(selector).await {
        Ok(p) => p,
        Err(e) => {
            return ToolExecutionResult::failure(format!(
                "ERROR_CLASS=TargetNotFound Failed to inspect selector '{}': {}",
                selector, e
            ))
        }
    };

    if !pre.found {
        return ToolExecutionResult::failure(format!(
            "ERROR_CLASS=TargetNotFound Selector '{}' does not exist on the current page.",
            selector
        ));
    }

    let mut fallback_used = "none".to_string();
    let mut click_errors: Vec<String> = Vec::new();

    if !pre.visible {
        match exec.browser.focus_selector(selector).await {
            Ok(true) => fallback_used = "selector_focus_pre".to_string(),
            Ok(false) => {}
            Err(e) => click_errors.push(format!("focus_pre={}", e)),
        }
    }

    if let Err(e) = exec.browser.click_selector(selector).await {
        click_errors.push(format!("click_primary={}", e));
        let _ = exec.browser.focus_selector(selector).await;
        match exec.browser.click_selector(selector).await {
            Ok(_) => {
                fallback_used = "selector_refocus_retry".to_string();
            }
            Err(second) => {
                click_errors.push(format!("click_retry={}", second));
            }
        }
    }

    let mut post = exec.browser.probe_selector(selector).await.ok();
    let mut postcondition_met = selector_focus_postcondition(&pre, post.as_ref());

    if !postcondition_met {
        match exec.browser.focus_selector(selector).await {
            Ok(true) => {
                fallback_used = "selector_focus".to_string();
                post = exec.browser.probe_selector(selector).await.ok();
                postcondition_met = selector_focus_postcondition(&pre, post.as_ref());
            }
            Ok(false) => {}
            Err(e) => click_errors.push(format!("focus_post={}", e)),
        }
    }

    if !postcondition_met && selector_looks_like_search_target(selector) {
        match exec
            .browser
            .focus_first_selector(SEARCH_FOCUS_SELECTORS)
            .await
        {
            Ok(Some(matched)) => {
                fallback_used = format!("search_selector:{}", matched);
                sleep(Duration::from_millis(120)).await;
                postcondition_met = exec
                    .browser
                    .is_active_element_editable()
                    .await
                    .unwrap_or(false);
            }
            Ok(None) => {}
            Err(e) => click_errors.push(format!("search_selector_focus={}", e)),
        }
    }

    if !postcondition_met && selector_looks_like_search_target(selector) {
        match exec
            .gui
            .inject_input(InputEvent::KeyPress {
                key: "/".to_string(),
            })
            .await
        {
            Ok(()) => {
                sleep(Duration::from_millis(120)).await;
                postcondition_met = exec
                    .browser
                    .is_active_element_editable()
                    .await
                    .unwrap_or(false);
                if postcondition_met {
                    fallback_used = "keyboard_slash".to_string();
                }
            }
            Err(e) => click_errors.push(format!("slash_fallback={}", e)),
        }
    }

    let mut location_shortcut_sent = false;
    if !postcondition_met && selector_looks_like_search_target(selector) {
        let modifier = if cfg!(target_os = "macos") {
            "command"
        } else {
            "ctrl"
        };
        let chord = InputEvent::AtomicSequence(vec![
            AtomicInput::KeyDown {
                key: modifier.to_string(),
            },
            AtomicInput::KeyPress {
                key: "l".to_string(),
            },
            AtomicInput::KeyUp {
                key: modifier.to_string(),
            },
        ]);

        match exec.gui.inject_input(chord).await {
            Ok(()) => {
                location_shortcut_sent = true;
                fallback_used = "location_bar_shortcut".to_string();
            }
            Err(e) => click_errors.push(format!("location_bar_fallback={}", e)),
        }
    }

    let verification = json!({
        "selector": selector,
        "pre": {
            "url": pre.url,
            "found": pre.found,
            "visible": pre.visible,
            "topmost": pre.topmost,
            "focused": pre.focused,
            "editable": pre.editable,
            "blocked_by": pre.blocked_by,
            "tag": pre.tag,
            "role": pre.role,
        },
        "post": post.as_ref().map(|p| json!({
            "url": p.url,
            "found": p.found,
            "visible": p.visible,
            "topmost": p.topmost,
            "focused": p.focused,
            "editable": p.editable,
            "blocked_by": p.blocked_by,
            "tag": p.tag,
            "role": p.role,
        })),
        "postcondition_met": postcondition_met,
        "location_shortcut_sent": location_shortcut_sent,
        "fallback_used": fallback_used,
        "click_errors": click_errors,
    });

    if postcondition_met || location_shortcut_sent {
        ToolExecutionResult::success(format!(
            "Browser click/focus succeeded. verify={verification}"
        ))
    } else {
        ToolExecutionResult::failure(format!(
            "ERROR_CLASS=NoEffectAfterAction Browser click/focus failed to satisfy postcondition for '{}'. verify={}",
            selector, verification
        ))
    }
}
