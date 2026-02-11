// Path: crates/services/src/agentic/desktop/execution/browser.rs

use super::resilience;
use super::{ToolExecutionResult, ToolExecutor};
use ioi_api::vm::drivers::gui::{AtomicInput, InputEvent, MouseButton};
use ioi_api::vm::drivers::os::WindowInfo;
use ioi_drivers::browser::{context::BrowserContentFrame, SelectorProbe};
use ioi_drivers::gui::accessibility::{AccessibilityNode, Rect};
use ioi_drivers::gui::lenses::{auto::AutoLens, AppLens};
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

#[derive(Debug, Clone, Copy)]
pub(super) struct BrowserSurfaceRegions {
    pub viewport_rect: Rect,
    pub url_bar_rect: Rect,
    pub source: &'static str,
}

impl BrowserSurfaceRegions {
    pub fn viewport_center(self) -> (u32, u32) {
        let cx = self.viewport_rect.x + (self.viewport_rect.width / 2);
        let cy = self.viewport_rect.y + (self.viewport_rect.height / 2);
        (cx.max(0) as u32, cy.max(0) as u32)
    }

    fn url_bar_center(self) -> (u32, u32) {
        let cx = self.url_bar_rect.x + (self.url_bar_rect.width / 2);
        let cy = self.url_bar_rect.y + (self.url_bar_rect.height / 2);
        (cx.max(0) as u32, cy.max(0) as u32)
    }
}

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

fn apply_browser_auto_lens(raw_tree: AccessibilityNode) -> AccessibilityNode {
    let lens = AutoLens;
    lens.transform(&raw_tree).unwrap_or(raw_tree)
}

fn render_browser_tree_xml(tree: &AccessibilityNode) -> String {
    let lens = AutoLens;
    lens.render(tree, 0)
}

fn find_cdp_id_by_semantic_id(node: &AccessibilityNode, target_id: &str) -> Option<String> {
    if node.id == target_id {
        return node.attributes.get("cdp_node_id").cloned();
    }

    for child in &node.children {
        if let Some(found) = find_cdp_id_by_semantic_id(child, target_id) {
            return Some(found);
        }
    }

    None
}

pub(super) fn is_probable_browser_window(title: &str, app_name: &str) -> bool {
    let title_lc = title.to_ascii_lowercase();
    let app_lc = app_name.to_ascii_lowercase();
    let browsers = [
        "chrome", "chromium", "brave", "firefox", "edge", "safari", "arc",
    ];
    browsers
        .iter()
        .any(|name| title_lc.contains(name) || app_lc.contains(name))
}

fn to_rect_from_window(window: &WindowInfo) -> Option<Rect> {
    if window.width <= 0 || window.height <= 0 {
        return None;
    }
    Some(Rect {
        x: window.x,
        y: window.y,
        width: window.width,
        height: window.height,
    })
}

fn to_rect_from_content_frame(frame: BrowserContentFrame) -> Option<Rect> {
    let width = frame.rect.width.round() as i32;
    let height = frame.rect.height.round() as i32;
    if width <= 0 || height <= 0 {
        return None;
    }

    Some(Rect {
        x: frame.rect.x.round() as i32,
        y: frame.rect.y.round() as i32,
        width,
        height,
    })
}

fn clamp_rect_to_bounds(rect: Rect, bounds: Rect) -> Option<Rect> {
    let left = rect.x.max(bounds.x);
    let top = rect.y.max(bounds.y);
    let right = (rect.x + rect.width).min(bounds.x + bounds.width);
    let bottom = (rect.y + rect.height).min(bounds.y + bounds.height);

    let width = right - left;
    let height = bottom - top;
    if width <= 0 || height <= 0 {
        return None;
    }

    Some(Rect {
        x: left,
        y: top,
        width,
        height,
    })
}

fn estimate_browser_surface_regions(
    window: &WindowInfo,
    content_rect: Option<Rect>,
) -> Option<BrowserSurfaceRegions> {
    let window_rect = to_rect_from_window(window)?;
    let heur_chrome = ((window_rect.height as f32 * 0.14).round() as i32)
        .clamp(72, 180)
        .min((window_rect.height - 24).max(24));
    let heur_viewport = Rect {
        x: window_rect.x + 4,
        y: window_rect.y + heur_chrome,
        width: (window_rect.width - 8).max(16),
        height: (window_rect.height - heur_chrome - 4).max(16),
    };

    let (viewport_rect, source) = if let Some(content) = content_rect {
        if let Some(clamped) = clamp_rect_to_bounds(content, window_rect) {
            let top_gap = clamped.y - window_rect.y;
            let left_gap = (clamped.x - window_rect.x).abs();
            let width_ratio = clamped.width as f32 / window_rect.width.max(1) as f32;
            let height_ratio = clamped.height as f32 / window_rect.height.max(1) as f32;
            let frame_matches_active_window = (16..=260).contains(&top_gap)
                && left_gap <= 40
                && width_ratio >= 0.5
                && height_ratio >= 0.4;

            if clamped.height >= 64 && clamped.width >= 120 && frame_matches_active_window {
                (clamped, "cdp_content_frame")
            } else {
                (heur_viewport, "window_heuristic")
            }
        } else {
            (heur_viewport, "window_heuristic")
        }
    } else {
        (heur_viewport, "window_heuristic")
    };

    let chrome_height = (viewport_rect.y - window_rect.y)
        .max(24)
        .min((window_rect.height - 12).max(24));
    let horizontal_padding = (window_rect.width / 9).clamp(24, 280);
    let mut url_left = window_rect.x + horizontal_padding;
    let mut url_right = window_rect.x + window_rect.width - horizontal_padding;
    if url_right - url_left < 160 {
        url_left = window_rect.x + 12;
        url_right = window_rect.x + window_rect.width - 12;
    }

    let mut url_height = ((chrome_height as f32) * 0.45).round() as i32;
    url_height = url_height.clamp(24, 44);
    let mut url_y = window_rect.y + ((chrome_height as f32) * 0.28).round() as i32;
    if url_y + url_height >= viewport_rect.y {
        url_y = (viewport_rect.y - url_height - 6).max(window_rect.y + 6);
    }

    let url_rect = Rect {
        x: url_left,
        y: url_y,
        width: (url_right - url_left).max(80),
        height: url_height,
    };

    Some(BrowserSurfaceRegions {
        viewport_rect,
        url_bar_rect: url_rect,
        source,
    })
}

pub(super) async fn browser_surface_regions(exec: &ToolExecutor) -> Option<BrowserSurfaceRegions> {
    let window = exec.active_window.as_ref()?;
    if !is_probable_browser_window(&window.title, &window.app_name) {
        return None;
    }

    let content_rect = exec
        .browser
        .get_content_frame()
        .await
        .ok()
        .and_then(to_rect_from_content_frame);

    estimate_browser_surface_regions(window, content_rect)
}

async fn attempt_visual_navigate(
    exec: &ToolExecutor,
    url: &str,
    context: &str,
    primary_error: &str,
) -> Result<String, String> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err("ERROR_CLASS=NavigationFallbackFailed Visual navigation requires an absolute http/https URL.".to_string());
    }

    let window = exec.active_window.as_ref().ok_or_else(|| {
        "ERROR_CLASS=NavigationFallbackFailed Visual fallback requires a focused browser window."
            .to_string()
    })?;

    if !is_probable_browser_window(&window.title, &window.app_name) {
        return Err(format!(
            "ERROR_CLASS=FocusMismatch Active window is '{}' ({}) and cannot accept visual browser navigation.",
            window.title, window.app_name
        ));
    }

    let regions = browser_surface_regions(exec).await.ok_or_else(|| {
        "ERROR_CLASS=NavigationFallbackFailed Failed to derive browser viewport/url-bar geometry."
            .to_string()
    })?;

    let (url_x, url_y) = regions.url_bar_center();
    let (viewport_x, viewport_y) = regions.viewport_center();

    exec.gui
        .inject_input(InputEvent::Click {
            button: MouseButton::Left,
            x: url_x,
            y: url_y,
            expected_visual_hash: None,
        })
        .await
        .map_err(|e| {
            format!(
                "ERROR_CLASS=NavigationFallbackFailed Failed to click URL bar candidate: {}",
                e
            )
        })?;

    sleep(Duration::from_millis(70)).await;

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
        AtomicInput::Wait { millis: 40 },
        AtomicInput::Type {
            text: url.trim().to_string(),
        },
        AtomicInput::KeyPress {
            key: "enter".to_string(),
        },
    ]);

    exec.gui.inject_input(chord).await.map_err(|e| {
        format!(
            "ERROR_CLASS=NavigationFallbackFailed Failed to execute visual URL entry macro: {}",
            e
        )
    })?;

    sleep(Duration::from_millis(220)).await;
    let _ = exec
        .gui
        .inject_input(InputEvent::MouseMove {
            x: viewport_x,
            y: viewport_y,
        })
        .await;

    let verification = json!({
        "fallback_used": "visual_url_entry",
        "context_requested": context,
        "geometry_source": regions.source,
        "url_bar_center": [url_x, url_y],
        "viewport_center": [viewport_x, viewport_y],
        "active_window": {
            "title": window.title,
            "app_name": window.app_name,
            "x": window.x,
            "y": window.y,
            "width": window.width,
            "height": window.height,
        },
        "driver_error": primary_error,
    });

    Ok(verification.to_string())
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
                Err(e) => {
                    let primary_error = e.to_string();
                    let allow_visual_fallback =
                        resilience::allow_vision_fallback_for_tier(exec.current_tier);

                    if allow_visual_fallback
                        && exec
                            .active_window
                            .as_ref()
                            .map(|w| is_probable_browser_window(&w.title, &w.app_name))
                            .unwrap_or(false)
                    {
                        match attempt_visual_navigate(exec, &url, &context, &primary_error).await {
                            Ok(verification) => {
                                return ToolExecutionResult::success(format!(
                                    "Navigated to {} [{}] via visual fallback. verify={}",
                                    url, context, verification
                                ))
                            }
                            Err(visual_error) => {
                                return ToolExecutionResult::failure(format!(
                                    "ERROR_CLASS=NavigationFallbackFailed Navigation failed via browser driver: {}. Visual fallback failed: {}",
                                    primary_error, visual_error
                                ))
                            }
                        }
                    }

                    if allow_visual_fallback {
                        return ToolExecutionResult::failure(format!(
                            "Navigation failed: {}. Visual fallback unavailable because no focused browser window was detected.",
                            primary_error
                        ));
                    }

                    ToolExecutionResult::failure(format!("Navigation failed: {}", primary_error))
                }
            }
        }
        AgentTool::BrowserExtract {} => match exec.browser.get_accessibility_tree().await {
            Ok(raw_tree) => {
                let transformed = apply_browser_auto_lens(raw_tree);
                ToolExecutionResult::success(render_browser_tree_xml(&transformed))
            }
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
        AgentTool::BrowserClickElement { id } => {
            if let Some(win) = exec.active_window.as_ref() {
                if !is_probable_browser_window(&win.title, &win.app_name) {
                    return ToolExecutionResult::failure(format!(
                        "ERROR_CLASS=FocusMismatch Active window is '{}' ({}) but browser click requires a focused browser surface.",
                        win.title, win.app_name
                    ));
                }
            }

            let raw_tree = match exec.browser.get_accessibility_tree().await {
                Ok(tree) => tree,
                Err(e) => {
                    return ToolExecutionResult::failure(format!(
                        "Failed to fetch browser accessibility tree: {}",
                        e
                    ))
                }
            };

            let transformed = apply_browser_auto_lens(raw_tree);
            let cdp_node_id = match find_cdp_id_by_semantic_id(&transformed, &id) {
                Some(cdp_id) => cdp_id,
                None => {
                    return ToolExecutionResult::failure(format!(
                        "ERROR_CLASS=TargetNotFound Element '{}' not found in current browser view. Run `browser__extract` again and retry with a fresh ID.",
                        id
                    ))
                }
            };

            match exec.browser.click_ax_node(&cdp_node_id).await {
                Ok(()) => ToolExecutionResult::success(format!("Clicked element '{}'", id)),
                Err(e) => ToolExecutionResult::failure(format!(
                    "ERROR_CLASS=NoEffectAfterAction Failed to click element '{}': {}",
                    id, e
                )),
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
    use ioi_api::vm::drivers::os::WindowInfo;
    use std::collections::HashMap;

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

    fn window_info() -> WindowInfo {
        WindowInfo {
            title: "Google Chrome".to_string(),
            app_name: "chrome".to_string(),
            x: 10,
            y: 20,
            width: 1200,
            height: 900,
        }
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

    #[test]
    fn surface_regions_use_content_frame_when_valid() {
        let win = window_info();
        let content = Rect {
            x: 12,
            y: 120,
            width: 1188,
            height: 790,
        };

        let regions = estimate_browser_surface_regions(&win, Some(content)).unwrap();
        assert_eq!(regions.source, "cdp_content_frame");
        assert_eq!(regions.viewport_rect.y, 120);
    }

    #[test]
    fn surface_regions_fallback_to_window_heuristic() {
        let win = window_info();
        let bad_content = Rect {
            x: 0,
            y: 0,
            width: 5,
            height: 5,
        };

        let regions = estimate_browser_surface_regions(&win, Some(bad_content)).unwrap();
        assert_eq!(regions.source, "window_heuristic");
        assert!(regions.viewport_rect.y > win.y);
    }

    #[test]
    fn surface_regions_reject_unaligned_content_frame() {
        let win = window_info();
        let unrelated_content = Rect {
            x: 0,
            y: 0,
            width: 1920,
            height: 1080,
        };

        let regions = estimate_browser_surface_regions(&win, Some(unrelated_content)).unwrap();
        assert_eq!(regions.source, "window_heuristic");
    }

    #[test]
    fn semantic_id_lookup_returns_cdp_node_id() {
        let node = AccessibilityNode {
            id: "root".to_string(),
            role: "root".to_string(),
            name: None,
            value: None,
            rect: Rect {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
            },
            children: vec![AccessibilityNode {
                id: "btn_submit".to_string(),
                role: "button".to_string(),
                name: Some("Submit".to_string()),
                value: None,
                rect: Rect {
                    x: 10,
                    y: 10,
                    width: 120,
                    height: 40,
                },
                children: vec![],
                is_visible: true,
                attributes: HashMap::from([("cdp_node_id".to_string(), "ax-node-42".to_string())]),
                som_id: None,
            }],
            is_visible: true,
            attributes: HashMap::new(),
            som_id: None,
        };

        let cdp_id = find_cdp_id_by_semantic_id(&node, "btn_submit");
        assert_eq!(cdp_id.as_deref(), Some("ax-node-42"));
    }

    #[test]
    fn semantic_id_lookup_returns_none_for_missing_id() {
        let node = AccessibilityNode {
            id: "root".to_string(),
            role: "root".to_string(),
            name: None,
            value: None,
            rect: Rect {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
            },
            children: vec![],
            is_visible: true,
            attributes: HashMap::new(),
            som_id: None,
        };

        assert!(find_cdp_id_by_semantic_id(&node, "btn_missing").is_none());
    }
}
