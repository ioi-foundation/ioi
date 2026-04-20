use super::{detect_pagination_buttons_from_tree, render_pagination_buttons_text};
use crate::browser::dom_ops::browser_use::BrowserUseSnapshotNode;
use crate::browser::dom_ops::browser_use_dom::identity::build_browser_use_element_identity_map;
use crate::browser::dom_ops::browser_use_dom::{BrowserUseAxData, BrowserUseDomTreeNode};
use std::collections::HashMap;

fn node(
    node_type: i64,
    node_name: &str,
    backend_node_id: Option<i64>,
    clickable: bool,
) -> BrowserUseDomTreeNode {
    BrowserUseDomTreeNode {
        target_id: "target-1".to_string(),
        frame_id: None,
        backend_node_id,
        node_type,
        node_name: node_name.to_string(),
        node_value: None,
        attribute_pairs: Vec::new(),
        attributes: HashMap::new(),
        snapshot: Some(BrowserUseSnapshotNode {
            is_clickable: clickable,
            ..Default::default()
        }),
        rect: None,
        visibility_ratio: None,
        is_visible: true,
        has_js_click_listener: false,
        ax_data: BrowserUseAxData::default(),
        som_id: None,
        shadow_root_type: None,
        children: Vec::new(),
        shadow_roots: Vec::new(),
        content_document: None,
        hidden_elements_info: Vec::new(),
        has_hidden_content: false,
        should_display: true,
        assigned_interactive: clickable,
        is_new: false,
        ignored_by_paint_order: false,
        excluded_by_parent: false,
        is_shadow_host: false,
        compound_children: Vec::new(),
    }
}

fn text(value: &str) -> BrowserUseDomTreeNode {
    BrowserUseDomTreeNode {
        target_id: "target-1".to_string(),
        frame_id: None,
        backend_node_id: None,
        node_type: 3,
        node_name: "#text".to_string(),
        node_value: Some(value.to_string()),
        attribute_pairs: Vec::new(),
        attributes: HashMap::new(),
        snapshot: None,
        rect: None,
        visibility_ratio: None,
        is_visible: true,
        has_js_click_listener: false,
        ax_data: BrowserUseAxData::default(),
        som_id: None,
        shadow_root_type: None,
        children: Vec::new(),
        shadow_roots: Vec::new(),
        content_document: None,
        hidden_elements_info: Vec::new(),
        has_hidden_content: false,
        should_display: true,
        assigned_interactive: false,
        is_new: false,
        ignored_by_paint_order: false,
        excluded_by_parent: false,
        is_shadow_host: false,
        compound_children: Vec::new(),
    }
}

#[test]
fn pagination_detection_matches_numeric_and_next_buttons() {
    let mut root = node(9, "#document", None, false);
    let mut next = node(1, "A", Some(10), true);
    next.children.push(text("Next"));
    next.som_id = Some(4);

    let mut page_two = node(1, "BUTTON", Some(11), true);
    page_two.children.push(text("2"));

    root.children.push(next);
    root.children.push(page_two);

    let identities = build_browser_use_element_identity_map(&root);
    let buttons = detect_pagination_buttons_from_tree(&root, &identities);
    let rendered = render_pagination_buttons_text(&buttons).expect("pagination text");

    assert_eq!(buttons.len(), 2);
    assert!(rendered.contains("type=next"), "{rendered}");
    assert!(rendered.contains("type=page_number"), "{rendered}");
    assert!(rendered.contains("[4]"), "{rendered}");
}
