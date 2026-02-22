use super::element_click::{
    click_element_postcondition_met, find_semantic_target_by_browser_ids,
    find_semantic_target_by_id, BrowserSemanticTarget,
};
use super::selector_click::{
    requires_browser_focus_guard, selector_focus_postcondition, selector_looks_like_search_target,
};
use super::surface::{estimate_browser_surface_regions, is_probable_browser_window};
use crate::agentic::desktop::types::ExecutionTier;
use ioi_api::vm::drivers::os::WindowInfo;
use ioi_drivers::browser::SelectorProbe;
use ioi_drivers::gui::accessibility::{AccessibilityNode, Rect};
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

    let target =
        find_semantic_target_by_id(&node, "btn_submit").expect("semantic target should resolve");
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

    let target =
        find_semantic_target_by_id(&node, "btn_submit").expect("semantic target should resolve");
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

#[test]
fn browser_id_lookup_matches_backend_and_cdp_ids() {
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
            id: "search_input".to_string(),
            role: "textbox".to_string(),
            name: Some("Search".to_string()),
            value: None,
            rect: Rect {
                x: 12,
                y: 20,
                width: 200,
                height: 36,
            },
            children: vec![],
            is_visible: true,
            attributes: HashMap::from([
                ("cdp_node_id".to_string(), "ax-100".to_string()),
                ("backend_dom_node_id".to_string(), "88".to_string()),
                ("focused".to_string(), "true".to_string()),
            ]),
            som_id: None,
        }],
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
    };

    let by_cdp = find_semantic_target_by_browser_ids(&node, Some("ax-100"), None)
        .expect("lookup by cdp id should resolve");
    assert_eq!(by_cdp.backend_dom_node_id.as_deref(), Some("88"));
    assert!(by_cdp.focused);

    let by_backend = find_semantic_target_by_browser_ids(&node, None, Some("88"))
        .expect("lookup by backend id should resolve");
    assert_eq!(by_backend.cdp_node_id.as_deref(), Some("ax-100"));
}

#[test]
fn click_element_postcondition_succeeds_when_target_disappears() {
    let pre_target = BrowserSemanticTarget {
        cdp_node_id: Some("ax-42".to_string()),
        backend_dom_node_id: Some("73".to_string()),
        center_point: Some((12.0, 20.0)),
        focused: false,
        editable: false,
    };

    let postcondition = click_element_postcondition_met(
        "<root><button/></root>",
        &pre_target,
        "<root><div/></root>",
        None,
    );
    assert!(postcondition.target_disappeared);
    assert!(postcondition.met());
}

#[test]
fn click_element_postcondition_succeeds_on_editable_focus_transition() {
    let pre_target = BrowserSemanticTarget {
        cdp_node_id: Some("ax-100".to_string()),
        backend_dom_node_id: Some("88".to_string()),
        center_point: Some((40.0, 22.0)),
        focused: false,
        editable: true,
    };
    let post_target = BrowserSemanticTarget {
        cdp_node_id: Some("ax-100".to_string()),
        backend_dom_node_id: Some("88".to_string()),
        center_point: Some((40.0, 22.0)),
        focused: true,
        editable: true,
    };

    let postcondition = click_element_postcondition_met(
        "<root><textbox/></root>",
        &pre_target,
        "<root><textbox/></root>",
        Some(&post_target),
    );
    assert!(postcondition.editable_focus_transition);
    assert!(postcondition.met());
}

#[test]
fn click_element_postcondition_succeeds_on_tree_change() {
    let pre_target = BrowserSemanticTarget {
        cdp_node_id: Some("ax-77".to_string()),
        backend_dom_node_id: Some("99".to_string()),
        center_point: Some((20.0, 20.0)),
        focused: false,
        editable: false,
    };
    let post_target = BrowserSemanticTarget {
        cdp_node_id: Some("ax-77".to_string()),
        backend_dom_node_id: Some("99".to_string()),
        center_point: Some((20.0, 20.0)),
        focused: false,
        editable: false,
    };

    let postcondition = click_element_postcondition_met(
        "<root><button name='continue'/></root>",
        &pre_target,
        "<root><dialog name='confirm'/></root>",
        Some(&post_target),
    );
    assert!(postcondition.tree_changed);
    assert!(postcondition.met());
}

#[test]
fn click_element_postcondition_fails_without_effect_signals() {
    let pre_target = BrowserSemanticTarget {
        cdp_node_id: Some("ax-5".to_string()),
        backend_dom_node_id: Some("7".to_string()),
        center_point: Some((8.0, 8.0)),
        focused: false,
        editable: false,
    };
    let post_target = BrowserSemanticTarget {
        cdp_node_id: Some("ax-5".to_string()),
        backend_dom_node_id: Some("7".to_string()),
        center_point: Some((8.0, 8.0)),
        focused: false,
        editable: false,
    };

    let postcondition = click_element_postcondition_met(
        "<root><button id='same'/></root>",
        &pre_target,
        "<root><button id='same'/></root>",
        Some(&post_target),
    );
    assert!(!postcondition.target_disappeared);
    assert!(!postcondition.editable_focus_transition);
    assert!(!postcondition.tree_changed);
    assert!(!postcondition.met());
}
