use super::element_click::{
    click_element_postcondition_counts_as_success, click_element_postcondition_met,
    find_semantic_target_by_browser_ids, find_semantic_target_by_dom_id,
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
fn focus_postcondition_accepts_target_becoming_hidden() {
    let pre = probe(false, false, true, true);
    let post = probe(false, false, false, false);

    assert!(selector_focus_postcondition(&pre, Some(&post)));
}

#[test]
fn focus_postcondition_accepts_new_blocking_overlay() {
    let pre = probe(false, false, true, true);
    let mut post = probe(false, false, true, false);
    post.blocked_by = Some("#modal".to_string());

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
fn dom_id_lookup_matches_dom_fallback_targets() {
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
            id: "inp_6ba480".to_string(),
            role: "textbox".to_string(),
            name: None,
            value: None,
            rect: Rect {
                x: 2,
                y: 66,
                width: 128,
                height: 21,
            },
            children: vec![],
            is_visible: true,
            attributes: HashMap::from([
                ("dom_id".to_string(), "tt".to_string()),
                ("focused".to_string(), "true".to_string()),
            ]),
            som_id: None,
        }],
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
    };

    let target =
        find_semantic_target_by_dom_id(&node, "tt").expect("lookup by dom id should resolve");
    assert_eq!(target.semantic_id.as_deref(), Some("inp_6ba480"));
    assert_eq!(target.dom_id.as_deref(), Some("tt"));
    assert!(target.focused);
}

#[test]
fn semantic_target_lookup_matches_dom_id_aliases() {
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
            id: "inp_awaiting_dispatch".to_string(),
            role: "combobox".to_string(),
            name: Some("Awaiting Dispatch".to_string()),
            value: Some("Awaiting Dispatch".to_string()),
            rect: Rect {
                x: 20,
                y: 90,
                width: 180,
                height: 40,
            },
            children: vec![],
            is_visible: true,
            attributes: HashMap::from([
                ("dom_id".to_string(), "status".to_string()),
                (
                    "semantic_aliases".to_string(),
                    "awaitingdispatch inp_awaiting_dispatch status inp_status".to_string(),
                ),
            ]),
            som_id: None,
        }],
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
    };

    let target =
        find_semantic_target_by_id(&node, "inp_status").expect("alias lookup should resolve");
    assert_eq!(target.semantic_id.as_deref(), Some("inp_awaiting_dispatch"));
    assert_eq!(target.dom_id.as_deref(), Some("status"));
}

#[test]
fn click_element_postcondition_succeeds_when_target_disappears() {
    let pre_target = BrowserSemanticTarget {
        semantic_id: Some("btn_submit".to_string()),
        dom_id: None,
        cdp_node_id: Some("ax-42".to_string()),
        backend_dom_node_id: Some("73".to_string()),
        center_point: Some((12.0, 20.0)),
        focused: false,
        editable: false,
        ..Default::default()
    };

    let postcondition = click_element_postcondition_met(
        "<root><button/></root>",
        &pre_target,
        None,
        "<root><div/></root>",
        None,
        None,
    );
    assert!(postcondition.target_disappeared);
    assert!(postcondition.met());
}

#[test]
fn click_element_postcondition_succeeds_on_editable_focus_transition() {
    let pre_target = BrowserSemanticTarget {
        semantic_id: Some("search_input".to_string()),
        dom_id: None,
        cdp_node_id: Some("ax-100".to_string()),
        backend_dom_node_id: Some("88".to_string()),
        center_point: Some((40.0, 22.0)),
        focused: false,
        editable: true,
        ..Default::default()
    };
    let post_target = BrowserSemanticTarget {
        semantic_id: Some("search_input".to_string()),
        dom_id: None,
        cdp_node_id: Some("ax-100".to_string()),
        backend_dom_node_id: Some("88".to_string()),
        center_point: Some((40.0, 22.0)),
        focused: true,
        editable: true,
        ..Default::default()
    };

    let postcondition = click_element_postcondition_met(
        "<root><textbox/></root>",
        &pre_target,
        None,
        "<root><textbox/></root>",
        Some(&post_target),
        None,
    );
    assert!(postcondition.editable_focus_transition);
    assert!(postcondition.met());
}

#[test]
fn click_element_postcondition_succeeds_on_tree_change() {
    let pre_target = BrowserSemanticTarget {
        semantic_id: Some("btn_confirm".to_string()),
        dom_id: None,
        cdp_node_id: Some("ax-77".to_string()),
        backend_dom_node_id: Some("99".to_string()),
        center_point: Some((20.0, 20.0)),
        focused: false,
        editable: false,
        ..Default::default()
    };
    let post_target = BrowserSemanticTarget {
        semantic_id: Some("btn_confirm".to_string()),
        dom_id: None,
        cdp_node_id: Some("ax-77".to_string()),
        backend_dom_node_id: Some("99".to_string()),
        center_point: Some((20.0, 20.0)),
        focused: false,
        editable: false,
        ..Default::default()
    };

    let postcondition = click_element_postcondition_met(
        "<root><button name='continue'/></root>",
        &pre_target,
        None,
        "<root><dialog name='confirm'/></root>",
        Some(&post_target),
        None,
    );
    assert!(postcondition.tree_changed);
    assert!(postcondition.met());
}

#[test]
fn click_element_postcondition_fails_without_effect_signals() {
    let pre_target = BrowserSemanticTarget {
        semantic_id: Some("btn_same".to_string()),
        dom_id: None,
        cdp_node_id: Some("ax-5".to_string()),
        backend_dom_node_id: Some("7".to_string()),
        center_point: Some((8.0, 8.0)),
        focused: false,
        editable: false,
        ..Default::default()
    };
    let post_target = BrowserSemanticTarget {
        semantic_id: Some("btn_same".to_string()),
        dom_id: None,
        cdp_node_id: Some("ax-5".to_string()),
        backend_dom_node_id: Some("7".to_string()),
        center_point: Some((8.0, 8.0)),
        focused: false,
        editable: false,
        ..Default::default()
    };

    let postcondition = click_element_postcondition_met(
        "<root><button id='same'/></root>",
        &pre_target,
        None,
        "<root><button id='same'/></root>",
        Some(&post_target),
        None,
    );
    assert!(!postcondition.target_disappeared);
    assert!(!postcondition.editable_focus_transition);
    assert!(!postcondition.tree_changed);
    assert!(!postcondition.url_changed);
    assert!(!postcondition.met());
}

#[test]
fn click_element_postcondition_succeeds_on_url_change() {
    let pre_target = BrowserSemanticTarget {
        semantic_id: Some("lnk_ticket".to_string()),
        dom_id: Some("ticket-link-t-204".to_string()),
        cdp_node_id: Some("ax-204".to_string()),
        backend_dom_node_id: Some("204".to_string()),
        center_point: Some((98.5, 642.0)),
        focused: false,
        editable: false,
        tag_name: Some("a".to_string()),
        ..Default::default()
    };
    let post_target = BrowserSemanticTarget {
        semantic_id: Some("lnk_ticket".to_string()),
        dom_id: Some("ticket-link-t-204".to_string()),
        cdp_node_id: Some("ax-204".to_string()),
        backend_dom_node_id: Some("204".to_string()),
        center_point: Some((98.5, 642.0)),
        focused: false,
        editable: false,
        tag_name: Some("a".to_string()),
        ..Default::default()
    };

    let postcondition = click_element_postcondition_met(
        "<root><link id='ticket-link-t-204'/></root>",
        &pre_target,
        Some("http://127.0.0.1:34049/workflow/session/queue"),
        "<root><link id='ticket-link-t-204'/></root>",
        Some(&post_target),
        Some("http://127.0.0.1:34049/workflow/session/tickets/T-204"),
    );
    assert!(postcondition.url_changed);
    assert!(postcondition.met());
    assert!(click_element_postcondition_counts_as_success(
        &pre_target,
        Some(&post_target),
        None,
        &postcondition
    ));
}

#[test]
fn link_click_tree_change_without_navigation_does_not_count_as_success() {
    let pre_target = BrowserSemanticTarget {
        semantic_id: Some("lnk_ticket".to_string()),
        dom_id: Some("ticket-link-t-215".to_string()),
        cdp_node_id: Some("ax-215".to_string()),
        backend_dom_node_id: Some("215".to_string()),
        center_point: Some((98.5, 813.0)),
        focused: false,
        editable: false,
        tag_name: Some("a".to_string()),
        ..Default::default()
    };
    let post_target = BrowserSemanticTarget {
        semantic_id: Some("lnk_ticket".to_string()),
        dom_id: Some("ticket-link-t-215".to_string()),
        cdp_node_id: Some("ax-215".to_string()),
        backend_dom_node_id: Some("215".to_string()),
        center_point: Some((98.5, 813.0)),
        focused: false,
        editable: false,
        tag_name: Some("a".to_string()),
        ..Default::default()
    };

    let postcondition = click_element_postcondition_met(
        "<root><link id='ticket-link-t-215'/><table id='queue'/></root>",
        &pre_target,
        Some("http://127.0.0.1:34049/workflow/session/queue"),
        "<root><link id='ticket-link-t-215'/><table id='queue' data-refresh='1'/></root>",
        Some(&post_target),
        Some("http://127.0.0.1:34049/workflow/session/queue"),
    );
    assert!(postcondition.tree_changed);
    assert!(!postcondition.url_changed);
    assert!(!postcondition.material_semantic_change);
    assert!(postcondition.met());
    assert!(!click_element_postcondition_counts_as_success(
        &pre_target,
        Some(&post_target),
        None,
        &postcondition
    ));
}

#[test]
fn link_click_tree_change_with_selected_state_counts_as_success() {
    let pre_target = BrowserSemanticTarget {
        semantic_id: Some("lnk_tab".to_string()),
        dom_id: Some("tab-overview".to_string()),
        cdp_node_id: Some("ax-tab".to_string()),
        backend_dom_node_id: Some("tab-1".to_string()),
        focused: false,
        editable: false,
        selected: Some(false),
        tag_name: Some("a".to_string()),
        ..Default::default()
    };
    let post_target = BrowserSemanticTarget {
        semantic_id: Some("lnk_tab".to_string()),
        dom_id: Some("tab-overview".to_string()),
        cdp_node_id: Some("ax-tab".to_string()),
        backend_dom_node_id: Some("tab-1".to_string()),
        focused: false,
        editable: false,
        selected: Some(true),
        tag_name: Some("a".to_string()),
        ..Default::default()
    };

    let postcondition = click_element_postcondition_met(
        "<root><link id='tab-overview' selected='false'/></root>",
        &pre_target,
        Some("http://127.0.0.1:34049/workflow/session/dashboard"),
        "<root><link id='tab-overview' selected='true'/><region id='overview'/></root>",
        Some(&post_target),
        Some("http://127.0.0.1:34049/workflow/session/dashboard"),
    );
    assert!(postcondition.tree_changed);
    assert!(!postcondition.url_changed);
    assert!(click_element_postcondition_counts_as_success(
        &pre_target,
        Some(&post_target),
        None,
        &postcondition
    ));
}

#[test]
fn link_click_tree_change_with_center_shift_counts_as_success() {
    let pre_target = BrowserSemanticTarget {
        semantic_id: Some("lnk_next".to_string()),
        center_point: Some((60.5, 191.5)),
        tag_name: Some("a".to_string()),
        ..Default::default()
    };
    let post_target = BrowserSemanticTarget {
        semantic_id: Some("lnk_next".to_string()),
        center_point: Some((73.5, 191.5)),
        tag_name: Some("a".to_string()),
        ..Default::default()
    };

    let postcondition = click_element_postcondition_met(
        "<root><link id='lnk_next' x='56'/><heading id='heading_karol'/></root>",
        &pre_target,
        Some("file:///tmp/miniwob/phone-book.1.html"),
        "<root><link id='lnk_next' x='69'/><heading id='heading_deena'/></root>",
        Some(&post_target),
        Some("file:///tmp/miniwob/phone-book.1.html"),
    );
    assert!(postcondition.tree_changed);
    assert!(!postcondition.url_changed);
    assert!(click_element_postcondition_counts_as_success(
        &pre_target,
        Some(&post_target),
        None,
        &postcondition
    ));
}

#[test]
fn link_click_tree_change_with_material_semantic_delta_counts_as_success() {
    let pre_target = BrowserSemanticTarget {
        semantic_id: Some("lnk_443422".to_string()),
        center_point: Some((73.5, 191.5)),
        tag_name: Some("a".to_string()),
        ..Default::default()
    };
    let post_target = BrowserSemanticTarget {
        semantic_id: Some("lnk_443422".to_string()),
        center_point: Some((73.5, 191.5)),
        tag_name: Some("a".to_string()),
        ..Default::default()
    };

    let postcondition = click_element_postcondition_met(
        "<root><generic id='grp_query' name='Find Deena in the contact book and click on their address.'/><heading id='heading_lauraine' name='Lauraine'/><generic id='grp_phone' name='Phone:'/><link id='lnk_lauraine_phone' name='827-889-0501'/><generic id='grp_email' name='Email:'/><link id='lnk_lauraine_email' name='lauraine5464@myspace.ca'/><generic id='grp_address' name='Address:'/><link id='lnk_lauraine_address' name='5193 Buchanan Ave, Unit 31'/><link id='lnk_443422' name='>'/><generic id='grp_time_left' name='Time left: 5 / 15sec' omitted='true'/></root>",
        &pre_target,
        Some("file:///tmp/miniwob/phone-book.1.html"),
        "<root><generic id='grp_query' name='Find Deena in the contact book and click on their address.'/><heading id='heading_deena' name='Deena'/><generic id='grp_phone' name='Phone:'/><link id='lnk_deena_phone' name='315-479-0478'/><generic id='grp_email' name='Email:'/><link id='lnk_deena_email' name='deena689@live.se'/><generic id='grp_address' name='Address:'/><link id='lnk_deena_address' name='5159 Middleton Crescent, Apt 5'/><link id='lnk_443422' name='>'/><generic id='grp_time_left' name='Time left: 4 / 15sec' omitted='true'/></root>",
        Some(&post_target),
        Some("file:///tmp/miniwob/phone-book.1.html"),
    );
    assert!(postcondition.tree_changed);
    assert!(!postcondition.url_changed);
    assert!(postcondition.material_semantic_change);
    assert!(postcondition.semantic_change_delta >= 4);
    assert!(click_element_postcondition_counts_as_success(
        &pre_target,
        Some(&post_target),
        None,
        &postcondition
    ));
}

#[test]
fn click_element_postcondition_accepts_dom_fallback_focus_transition() {
    let pre_target = BrowserSemanticTarget {
        semantic_id: Some("inp_6ba480".to_string()),
        dom_id: Some("tt".to_string()),
        cdp_node_id: None,
        backend_dom_node_id: None,
        center_point: Some((66.0, 76.5)),
        focused: false,
        editable: true,
        ..Default::default()
    };
    let post_target = BrowserSemanticTarget {
        semantic_id: Some("inp_6ba480".to_string()),
        dom_id: Some("tt".to_string()),
        cdp_node_id: None,
        backend_dom_node_id: None,
        center_point: Some((66.0, 76.5)),
        focused: true,
        editable: true,
        ..Default::default()
    };

    let postcondition = click_element_postcondition_met(
        "<root><textbox id='inp_6ba480'/></root>",
        &pre_target,
        None,
        "<root><textbox id='inp_6ba480' focused='true'/></root>",
        Some(&post_target),
        None,
    );
    assert!(postcondition.editable_focus_transition);
    assert!(postcondition.met());
}
