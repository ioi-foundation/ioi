use super::{
    build_attributes_string, collect_interactive_backend_keys, prepare_tree_for_browser_use_render,
};
use crate::browser::dom_ops::browser_use::BrowserUseSnapshotNode;
use crate::browser::dom_ops::browser_use_dom::{BrowserUseAxData, BrowserUseDomTreeNode};
use crate::gui::accessibility::Rect as AccessibilityRect;
use std::collections::{HashMap, HashSet};

fn element(
    tag: &str,
    backend: i64,
    rect: Option<(f64, f64, f64, f64)>,
    attrs: &[(&str, &str)],
    children: Vec<BrowserUseDomTreeNode>,
) -> BrowserUseDomTreeNode {
    let snapshot = rect.map(|(x, y, width, height)| BrowserUseSnapshotNode {
        is_clickable: false,
        cursor_style: None,
        bounds: Some(crate::browser::dom_ops::browser_use::BrowserUseDomRect {
            x,
            y,
            width,
            height,
        }),
        client_rects: None,
        scroll_rects: None,
        computed_styles: HashMap::from([
            ("display".to_string(), "block".to_string()),
            ("visibility".to_string(), "visible".to_string()),
            ("opacity".to_string(), "1".to_string()),
            (
                "background-color".to_string(),
                "rgb(255, 255, 255)".to_string(),
            ),
        ]),
        paint_order: Some(backend),
    });

    BrowserUseDomTreeNode {
        target_id: "target-1".to_string(),
        frame_id: None,
        backend_node_id: Some(backend),
        node_type: 1,
        node_name: tag.to_ascii_uppercase(),
        node_value: None,
        attribute_pairs: attrs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect(),
        attributes: attrs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect(),
        snapshot,
        rect: rect.map(|(x, y, width, height)| AccessibilityRect {
            x: x as i32,
            y: y as i32,
            width: width as i32,
            height: height as i32,
        }),
        visibility_ratio: Some(1.0),
        is_visible: true,
        has_js_click_listener: false,
        ax_data: BrowserUseAxData::default(),
        som_id: Some(backend as u32),
        shadow_root_type: None,
        children,
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
        visibility_ratio: Some(1.0),
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
fn prepare_tree_adds_compound_components_to_file_inputs() {
    let mut root = element(
        "input",
        7,
        Some((0.0, 0.0, 200.0, 32.0)),
        &[("type", "file")],
        Vec::new(),
    );
    root.ax_data
        .properties
        .insert("valuetext".to_string(), "resume.pdf".to_string());

    prepare_tree_for_browser_use_render(&mut root, None);
    let attrs = build_attributes_string(&root);

    assert!(attrs.contains("compound_components="), "{attrs}");
    assert!(attrs.contains("Browse Files"), "{attrs}");
    assert!(attrs.contains("resume.pdf"), "{attrs}");
}

#[test]
fn prepare_tree_excludes_child_fully_contained_by_button_bounds() {
    let child = element(
        "span",
        8,
        Some((0.0, 0.0, 100.0, 40.0)),
        &[("class", "icon-wrapper")],
        vec![text("Decorative")],
    );
    let mut root = element("button", 7, Some((0.0, 0.0, 100.0, 40.0)), &[], vec![child]);

    prepare_tree_for_browser_use_render(&mut root, None);

    assert!(root.children[0].excluded_by_parent);
}

#[test]
fn prepare_tree_marks_lower_paint_order_overlap_as_ignored() {
    let lower = element(
        "button",
        5,
        Some((0.0, 0.0, 100.0, 40.0)),
        &[],
        vec![text("Lower")],
    );
    let higher = element(
        "button",
        9,
        Some((0.0, 0.0, 100.0, 40.0)),
        &[],
        vec![text("Higher")],
    );
    let mut root = element(
        "div",
        1,
        Some((0.0, 0.0, 120.0, 80.0)),
        &[],
        vec![lower, higher],
    );

    prepare_tree_for_browser_use_render(&mut root, None);

    assert!(root.children[0].ignored_by_paint_order);
    assert!(!root.children[1].ignored_by_paint_order);
}

#[test]
fn prepare_tree_marks_interactive_nodes_as_new_when_not_seen_before() {
    let mut root = element(
        "button",
        11,
        Some((0.0, 0.0, 120.0, 32.0)),
        &[("id", "submit")],
        vec![],
    );
    let previous = HashSet::from([("target-1".to_string(), 10)]);

    prepare_tree_for_browser_use_render(&mut root, Some(&previous));
    let keys = collect_interactive_backend_keys(&root);

    assert!(root.assigned_interactive);
    assert!(root.is_new);
    assert!(keys.contains(&("target-1".to_string(), 11)));
}
