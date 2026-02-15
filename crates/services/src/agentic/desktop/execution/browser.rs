// Path: crates/services/src/agentic/desktop/execution/browser.rs

use super::{ToolExecutionResult, ToolExecutor};
use crate::agentic::desktop::types::ExecutionTier;
use ioi_api::vm::drivers::gui::{AtomicInput, InputEvent};
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
}

impl BrowserSurfaceRegions {
    pub fn viewport_center(self) -> (u32, u32) {
        let cx = self.viewport_rect.x + (self.viewport_rect.width / 2);
        let cy = self.viewport_rect.y + (self.viewport_rect.height / 2);
        (cx.max(0) as u32, cy.max(0) as u32)
    }
}

fn detect_human_challenge(url: &str, content: &str) -> Option<&'static str> {
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

fn selector_focus_postcondition(pre: &SelectorProbe, post: Option<&SelectorProbe>) -> bool {
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

fn rect_center(rect: Rect) -> Option<(f64, f64)> {
    if rect.width <= 0 || rect.height <= 0 {
        return None;
    }

    Some((
        rect.x as f64 + (rect.width as f64 / 2.0),
        rect.y as f64 + (rect.height as f64 / 2.0),
    ))
}

#[derive(Debug, Clone, Default, PartialEq)]
struct BrowserSemanticTarget {
    cdp_node_id: Option<String>,
    backend_dom_node_id: Option<String>,
    center_point: Option<(f64, f64)>,
}

fn find_semantic_target_by_id(
    node: &AccessibilityNode,
    target_id: &str,
) -> Option<BrowserSemanticTarget> {
    if node.id == target_id {
        return Some(BrowserSemanticTarget {
            cdp_node_id: node.attributes.get("cdp_node_id").cloned(),
            backend_dom_node_id: node.attributes.get("backend_dom_node_id").cloned(),
            center_point: rect_center(node.rect),
        });
    }

    for child in &node.children {
        if let Some(found) = find_semantic_target_by_id(child, target_id) {
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

fn requires_browser_focus_guard(tier: Option<ExecutionTier>) -> bool {
    !matches!(tier, Some(ExecutionTier::DomHeadless))
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

    let viewport_rect = if let Some(content) = content_rect {
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
                clamped
            } else {
                heur_viewport
            }
        } else {
            heur_viewport
        }
    } else {
        heur_viewport
    };

    Some(BrowserSurfaceRegions { viewport_rect })
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

pub async fn handle(exec: &ToolExecutor, tool: AgentTool) -> ToolExecutionResult {
    match tool {
        AgentTool::BrowserNavigate { url } => match exec.browser.navigate(&url).await {
            Ok(content) => {
                if let Some(reason) = detect_human_challenge(&url, &content) {
                    return ToolExecutionResult::failure(format!(
                            "ERROR_CLASS=HumanChallengeRequired {}. Complete the challenge manually in your own browser/app, then resume: {}",
                            reason, url
                        ));
                }

                ToolExecutionResult::success(format!(
                    "Navigated to {}. Content len: {}",
                    url,
                    content.len()
                ))
            }
            Err(e) => ToolExecutionResult::failure(format!("Navigation failed: {}", e)),
        },
        AgentTool::BrowserExtract {} => match exec.browser.get_accessibility_tree().await {
            Ok(raw_tree) => {
                let transformed = apply_browser_auto_lens(raw_tree);
                ToolExecutionResult::success(render_browser_tree_xml(&transformed))
            }
            Err(e) => ToolExecutionResult::failure(format!("Extraction failed: {}", e)),
        },
        AgentTool::BrowserClick { selector } => {
            if requires_browser_focus_guard(exec.current_tier) {
                if let Some(win) = exec.active_window.as_ref() {
                    if !is_probable_browser_window(&win.title, &win.app_name) {
                        return ToolExecutionResult::failure(format!(
                            "ERROR_CLASS=FocusMismatch Active window is '{}' ({}) but browser click requires a focused browser surface.",
                            win.title, win.app_name
                        ));
                    }
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
            let mut postcondition_met = selector_focus_postcondition(&pre, post.as_ref());

            if !postcondition_met {
                match exec.browser.focus_selector(&selector).await {
                    Ok(true) => {
                        fallback_used = "selector_focus".to_string();
                        post = exec.browser.probe_selector(&selector).await.ok();
                        postcondition_met = selector_focus_postcondition(&pre, post.as_ref());
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
            if requires_browser_focus_guard(exec.current_tier) {
                if let Some(win) = exec.active_window.as_ref() {
                    if !is_probable_browser_window(&win.title, &win.app_name) {
                        return ToolExecutionResult::failure(format!(
                            "ERROR_CLASS=FocusMismatch Active window is '{}' ({}) but browser click requires a focused browser surface.",
                            win.title, win.app_name
                        ));
                    }
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
            let semantic_target = match find_semantic_target_by_id(&transformed, &id) {
                Some(target) => target,
                None => {
                    return ToolExecutionResult::failure(format!(
                        "ERROR_CLASS=TargetNotFound Element '{}' not found in current browser view. Run `browser__extract` again and retry with a fresh ID.",
                        id
                    ))
                }
            };

            if semantic_target.backend_dom_node_id.is_none()
                && semantic_target.cdp_node_id.is_none()
                && semantic_target.center_point.is_none()
            {
                return ToolExecutionResult::failure(format!(
                    "ERROR_CLASS=TargetNotFound Element '{}' is present but does not expose actionable browser node identifiers or clickable geometry.",
                    id
                ));
            }

            let mut click_errors: Vec<String> = Vec::new();

            if let Some(backend_id) = semantic_target.backend_dom_node_id.as_deref() {
                match exec.browser.click_backend_dom_node(backend_id).await {
                    Ok(()) => {
                        return ToolExecutionResult::success(format!("Clicked element '{}'", id))
                    }
                    Err(e) => click_errors.push(format!("backend_dom_node_id={}", e)),
                }
            }

            if let Some(cdp_id) = semantic_target.cdp_node_id.as_deref() {
                match exec.browser.click_ax_node(cdp_id).await {
                    Ok(()) => {
                        return ToolExecutionResult::success(format!("Clicked element '{}'", id))
                    }
                    Err(e) => click_errors.push(format!("cdp_node_id={}", e)),
                }
            }

            if let Some((x, y)) = semantic_target.center_point {
                match exec.browser.synthetic_click(x, y).await {
                    Ok(()) => {
                        return ToolExecutionResult::success(format!(
                            "Clicked element '{}' via geometry fallback",
                            id
                        ))
                    }
                    Err(e) => {
                        click_errors.push(format!("geometry_center=({:.2},{:.2})={}", x, y, e))
                    }
                }
            }

            ToolExecutionResult::failure(format!(
                "ERROR_CLASS=NoEffectAfterAction Failed to click element '{}': {}",
                id,
                click_errors.join("; ")
            ))
        }
        AgentTool::BrowserSyntheticClick { x, y } => {
            match exec.browser.synthetic_click(x as f64, y as f64).await {
                Ok(_) => ToolExecutionResult::success(format!("Clicked at ({}, {})", x, y)),
                Err(e) => ToolExecutionResult::failure(format!("Synthetic click failed: {}", e)),
            }
        }
        AgentTool::BrowserScroll { delta_x, delta_y } => {
            match exec.browser.scroll(delta_x, delta_y).await {
                Ok(_) => ToolExecutionResult::success(format!(
                    "Scrolled browser by ({}, {})",
                    delta_x, delta_y
                )),
                Err(e) => ToolExecutionResult::failure(format!("Browser scroll failed: {}", e)),
            }
        }
        AgentTool::BrowserType { text, selector } => {
            match exec.browser.type_text(&text, selector.as_deref()).await {
                Ok(_) => ToolExecutionResult::success(format!("Typed '{}' into browser", text)),
                Err(e) => ToolExecutionResult::failure(format!("Browser type failed: {}", e)),
            }
        }
        AgentTool::BrowserKey { key } => match exec.browser.press_key(&key).await {
            Ok(_) => ToolExecutionResult::success(format!("Pressed '{}' in browser", key)),
            Err(e) => ToolExecutionResult::failure(format!("Browser key press failed: {}", e)),
        },
        _ => ToolExecutionResult::failure("Unsupported Browser action"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_api::vm::drivers::os::WindowInfo;
    use std::collections::HashMap;

    fn probe(editable: bool, focused: bool, visible: bool, topmost: bool) -> SelectorProbe {
        SelectorProbe {
            url: "https://example.test".to_string(),
            editable,
            focused,
            visible,
            topmost,
            found: true,
            ..Default::default()
        }
    }

    #[test]
    fn focus_postcondition_requires_focus_for_editable_targets() {
        let pre = probe(true, false, true, true);
        let post_not_focused = probe(true, false, true, true);
        let post_focused = probe(true, true, true, true);
        assert!(!selector_focus_postcondition(&pre, Some(&post_not_focused)));
        assert!(selector_focus_postcondition(&pre, Some(&post_focused)));
    }

    #[test]
    fn focus_postcondition_requires_topmost_for_non_editable_targets() {
        let pre = probe(false, false, true, false);
        let post_occluded = probe(false, false, true, false);
        let post_topmost = probe(false, false, true, true);

        assert!(!selector_focus_postcondition(&pre, Some(&post_occluded)));
        assert!(selector_focus_postcondition(&pre, Some(&post_topmost)));
    }

    #[test]
    fn focus_postcondition_accepts_navigation_transition() {
        let pre = probe(false, false, true, true);
        let mut post = probe(false, false, false, false);
        post.found = false;
        post.url = "https://example.test/next".to_string();

        assert!(selector_focus_postcondition(&pre, Some(&post)));
    }

    #[test]
    fn focus_postcondition_accepts_disappearing_target_transition() {
        let pre = probe(false, false, true, true);
        let mut post = probe(false, false, false, false);
        post.found = false;
        post.url = pre.url.clone();

        assert!(selector_focus_postcondition(&pre, Some(&post)));
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
    fn browser_focus_guard_is_disabled_for_dom_headless() {
        assert!(!requires_browser_focus_guard(Some(
            ExecutionTier::DomHeadless
        )));
    }

    #[test]
    fn browser_focus_guard_is_enabled_for_visual_tiers() {
        assert!(requires_browser_focus_guard(Some(
            ExecutionTier::VisualForeground
        )));
        assert!(requires_browser_focus_guard(Some(
            ExecutionTier::VisualBackground
        )));
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
        assert!(regions.viewport_rect.y > win.y);
    }

    #[test]
    fn semantic_target_lookup_returns_backend_and_cdp_ids() {
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
                attributes: HashMap::from([
                    ("cdp_node_id".to_string(), "ax-node-42".to_string()),
                    ("backend_dom_node_id".to_string(), "73".to_string()),
                ]),
                som_id: None,
            }],
            is_visible: true,
            attributes: HashMap::new(),
            som_id: None,
        };

        let target = find_semantic_target_by_id(&node, "btn_submit")
            .expect("semantic target should resolve");
        assert_eq!(target.cdp_node_id.as_deref(), Some("ax-node-42"));
        assert_eq!(target.backend_dom_node_id.as_deref(), Some("73"));
        assert_eq!(target.center_point, Some((70.0, 30.0)));
    }

    #[test]
    fn semantic_target_lookup_omits_center_for_degenerate_rect() {
        let node = AccessibilityNode {
            id: "btn_submit".to_string(),
            role: "button".to_string(),
            name: Some("Submit".to_string()),
            value: None,
            rect: Rect {
                x: 10,
                y: 10,
                width: 0,
                height: 40,
            },
            children: vec![],
            is_visible: true,
            attributes: HashMap::new(),
            som_id: None,
        };

        let target = find_semantic_target_by_id(&node, "btn_submit")
            .expect("semantic target should resolve");
        assert!(target.center_point.is_none());
    }

    #[test]
    fn semantic_target_lookup_returns_none_for_missing_id() {
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

        assert!(find_semantic_target_by_id(&node, "btn_missing").is_none());
    }
}
