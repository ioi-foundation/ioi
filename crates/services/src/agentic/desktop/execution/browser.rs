// Path: crates/services/src/agentic/desktop/execution/browser.rs

use super::{ToolExecutionResult, ToolExecutor};
use ioi_api::vm::drivers::gui::{AtomicInput, InputEvent};
use ioi_drivers::browser::SelectorProbe;
use ioi_types::app::agentic::AgentTool;
use serde_json::json;
use tokio::time::{sleep, Duration};

const SEARCH_FOCUS_SELECTORS: &[&str] = &[
    "textarea[name='q']",
    "input[name='q']",
    "input[type='search']",
    "textarea[aria-label*='search' i]",
    "input[aria-label*='search' i]",
    "textarea[placeholder*='search' i]",
    "input[placeholder*='search' i]",
];

fn detect_human_challenge(url: &str, context: &str, content: &str) -> Option<&'static str> {
    if !context.eq_ignore_ascii_case("hermetic") {
        return None;
    }

    let url_lc = url.to_ascii_lowercase();
    let content_lc = content.to_ascii_lowercase();

    if url_lc.contains("/sorry/") || content_lc.contains("/sorry/") {
        return Some("challenge redirect (/sorry/) detected");
    }
    if content_lc.contains("recaptcha") || content_lc.contains("g-recaptcha") {
        return Some("reCAPTCHA challenge marker detected");
    }
    if content_lc.contains("i'm not a robot") || content_lc.contains("i am not a robot") {
        return Some("robot-verification checkbox detected");
    }
    if content_lc.contains("unusual traffic from your computer network")
        || content_lc.contains("our systems have detected unusual traffic")
    {
        return Some("unusual-traffic challenge detected");
    }
    if content_lc.contains("verify you are human")
        || content_lc.contains("human verification")
        || content_lc.contains("please verify you are a human")
    {
        return Some("human-verification challenge detected");
    }

    None
}

fn selector_focus_postcondition(probe: &SelectorProbe) -> bool {
    if !probe.found || !probe.visible {
        return false;
    }
    if probe.editable {
        probe.focused
    } else {
        true
    }
}

fn selector_looks_like_search_target(selector: &str) -> bool {
    let s = selector.to_ascii_lowercase();
    s.contains("search")
        || s.contains("name='q'")
        || s.contains("name=\"q\"")
        || s.contains("[name=q]")
        || s.contains("textarea")
        || s.contains("input")
}

fn is_probable_browser_window(title: &str, app_name: &str) -> bool {
    let title_lc = title.to_ascii_lowercase();
    let app_lc = app_name.to_ascii_lowercase();
    let browsers = [
        "chrome", "chromium", "brave", "firefox", "edge", "safari", "arc",
    ];
    browsers
        .iter()
        .any(|name| title_lc.contains(name) || app_lc.contains(name))
}

pub async fn handle(exec: &ToolExecutor, tool: AgentTool) -> ToolExecutionResult {
    match tool {
        AgentTool::BrowserNavigate { url, context } => {
            match exec.browser.navigate(&url, &context).await {
                Ok(content) => {
                    if let Some(reason) = detect_human_challenge(&url, &context, &content) {
                        return ToolExecutionResult::failure(format!(
                            "ERROR_CLASS=HumanChallengeRequired {}. Open the same URL in Local Browser, complete the challenge manually, then resume: {}",
                            reason, url
                        ));
                    }

                    ToolExecutionResult::success(format!(
                        "Navigated to {} [{}]. Content len: {}",
                        url,
                        context,
                        content.len()
                    ))
                }
                Err(e) => ToolExecutionResult::failure(format!("Navigation failed: {}", e)),
            }
        }
        AgentTool::BrowserExtract {} => match exec.browser.extract_dom().await {
            Ok(dom) => ToolExecutionResult::success(dom),
            Err(e) => ToolExecutionResult::failure(format!("Extraction failed: {}", e)),
        },
        AgentTool::BrowserClick { selector } => {
            if let Some(win) = exec.active_window.as_ref() {
                if !is_probable_browser_window(&win.title, &win.app_name) {
                    return ToolExecutionResult::failure(format!(
                        "ERROR_CLASS=FocusMismatch Active window is '{}' ({}) but browser click requires a focused browser surface.",
                        win.title, win.app_name
                    ));
                }
            }

            let pre = match exec.browser.probe_selector(&selector).await {
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
                match exec.browser.focus_selector(&selector).await {
                    Ok(true) => fallback_used = "selector_focus_pre".to_string(),
                    Ok(false) => {}
                    Err(e) => click_errors.push(format!("focus_pre={}", e)),
                }
            }

            if let Err(e) = exec.browser.click_selector(&selector).await {
                click_errors.push(format!("click_primary={}", e));
                let _ = exec.browser.focus_selector(&selector).await;
                match exec.browser.click_selector(&selector).await {
                    Ok(_) => {
                        fallback_used = "selector_refocus_retry".to_string();
                    }
                    Err(second) => {
                        click_errors.push(format!("click_retry={}", second));
                    }
                }
            }

            let mut post = exec.browser.probe_selector(&selector).await.ok();
            let mut postcondition_met = post
                .as_ref()
                .map(selector_focus_postcondition)
                .unwrap_or(false);

            if !postcondition_met {
                match exec.browser.focus_selector(&selector).await {
                    Ok(true) => {
                        fallback_used = "selector_focus".to_string();
                        post = exec.browser.probe_selector(&selector).await.ok();
                        postcondition_met = post
                            .as_ref()
                            .map(selector_focus_postcondition)
                            .unwrap_or(false);
                    }
                    Ok(false) => {}
                    Err(e) => click_errors.push(format!("focus_post={}", e)),
                }
            }

            if !postcondition_met && selector_looks_like_search_target(&selector) {
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

            if !postcondition_met && selector_looks_like_search_target(&selector) {
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
            if !postcondition_met && selector_looks_like_search_target(&selector) {
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
        AgentTool::BrowserSyntheticClick { x, y } => {
            match exec.browser.synthetic_click(x as f64, y as f64).await {
                Ok(_) => ToolExecutionResult::success(format!("Clicked at ({}, {})", x, y)),
                Err(e) => ToolExecutionResult::failure(format!("Synthetic click failed: {}", e)),
            }
        }
        _ => ToolExecutionResult::failure("Unsupported Browser action"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(editable: bool, focused: bool, visible: bool) -> SelectorProbe {
        SelectorProbe {
            editable,
            focused,
            visible,
            found: true,
            ..Default::default()
        }
    }

    #[test]
    fn focus_postcondition_requires_focus_for_editable_targets() {
        assert!(!selector_focus_postcondition(&probe(true, false, true)));
        assert!(selector_focus_postcondition(&probe(true, true, true)));
    }

    #[test]
    fn focus_postcondition_accepts_non_editable_click_targets() {
        assert!(selector_focus_postcondition(&probe(false, false, true)));
    }

    #[test]
    fn search_selector_detection_catches_google_box() {
        assert!(selector_looks_like_search_target("textarea[name='q']"));
        assert!(selector_looks_like_search_target(
            "input[aria-label='Search']"
        ));
        assert!(!selector_looks_like_search_target(
            "button[data-test='submit']"
        ));
    }

    #[test]
    fn browser_window_detection_matches_common_titles() {
        assert!(is_probable_browser_window("Google", "Google Chrome"));
        assert!(is_probable_browser_window(
            "Firefox Developer Edition",
            "firefox"
        ));
        assert!(!is_probable_browser_window(
            "Calculator",
            "gnome-calculator"
        ));
    }
}
