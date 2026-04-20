use super::{
    annotate_tree_with_browser_use_identities, annotate_tree_with_browser_use_metadata,
    build_snapshot_lookup, extract_dom_node_metadata, required_snapshot_computed_styles,
};
use crate::browser::dom_ops::browser_use_dom::BrowserUseElementIdentity;
use crate::gui::accessibility::{AccessibilityNode, Rect as AccessibilityRect};
use chromiumoxide::cdp::browser_protocol::dom::BackendNodeId;
use chromiumoxide::cdp::browser_protocol::dom_snapshot::{
    ArrayOfStrings, CaptureSnapshotReturns, DocumentSnapshot, LayoutTreeSnapshot, NodeTreeSnapshot,
    RareBooleanData, Rectangle, StringIndex, TextBoxSnapshot,
};
use std::collections::{HashMap, HashSet};

fn test_snapshot() -> CaptureSnapshotReturns {
    let strings = vec![
        "https://example.test".to_string(),
        "title".to_string(),
        "base".to_string(),
        "lang".to_string(),
        "utf-8".to_string(),
        "".to_string(),
        "root-frame".to_string(),
        "html".to_string(),
        "iframe".to_string(),
        "input".to_string(),
        "id".to_string(),
        "cross-origin-frame".to_string(),
        "name".to_string(),
        "search".to_string(),
        "type".to_string(),
        "text".to_string(),
        "placeholder".to_string(),
        "Search".to_string(),
        "display".to_string(),
        "block".to_string(),
        "visibility".to_string(),
        "visible".to_string(),
        "opacity".to_string(),
        "1".to_string(),
        "overflow".to_string(),
        "auto".to_string(),
        "overflow-x".to_string(),
        "hidden".to_string(),
        "overflow-y".to_string(),
        "scroll".to_string(),
        "cursor".to_string(),
        "pointer".to_string(),
        "pointer-events".to_string(),
        "auto".to_string(),
        "position".to_string(),
        "relative".to_string(),
        "background-color".to_string(),
        "rgb(255,255,255)".to_string(),
    ];

    let styles = ArrayOfStrings::new(
        (19..=37)
            .step_by(2)
            .map(StringIndex::new)
            .collect::<Vec<_>>(),
    );

    let document = DocumentSnapshot::builder()
        .document_url(StringIndex::new(0))
        .title(StringIndex::new(1))
        .base_url(StringIndex::new(2))
        .content_language(StringIndex::new(3))
        .encoding_name(StringIndex::new(4))
        .public_id(StringIndex::new(5))
        .system_id(StringIndex::new(5))
        .frame_id(StringIndex::new(6))
        .nodes(
            NodeTreeSnapshot::builder()
                .parent_indexs(vec![-1, 0, 0])
                .node_types(vec![9, 1, 1])
                .node_names(vec![
                    StringIndex::new(7),
                    StringIndex::new(8),
                    StringIndex::new(9),
                ])
                .node_values(vec![
                    StringIndex::new(5),
                    StringIndex::new(5),
                    StringIndex::new(5),
                ])
                .backend_node_ids(vec![
                    BackendNodeId::new(1),
                    BackendNodeId::new(2),
                    BackendNodeId::new(3),
                ])
                .attributes(vec![
                    ArrayOfStrings::new(Vec::<StringIndex>::new()),
                    ArrayOfStrings::new(vec![StringIndex::new(10), StringIndex::new(11)]),
                    ArrayOfStrings::new(vec![
                        StringIndex::new(12),
                        StringIndex::new(13),
                        StringIndex::new(14),
                        StringIndex::new(15),
                        StringIndex::new(16),
                        StringIndex::new(17),
                    ]),
                ])
                .is_clickable(
                    RareBooleanData::builder()
                        .index(1)
                        .index(2)
                        .build()
                        .expect("clickable"),
                )
                .build(),
        )
        .layout(
            LayoutTreeSnapshot::builder()
                .node_indexs(vec![1, 2])
                .styles(vec![styles.clone(), styles])
                .bounds(vec![
                    Rectangle::new(vec![10.0, 20.0, 320.0, 240.0]),
                    Rectangle::new(vec![40.0, 280.0, 200.0, 48.0]),
                ])
                .texts(vec![StringIndex::new(5), StringIndex::new(5)])
                .stacking_contexts(RareBooleanData::new(Vec::new()))
                .paint_orders(vec![7, 8])
                .offset_rects(vec![
                    Rectangle::new(vec![10.0, 20.0, 320.0, 240.0]),
                    Rectangle::new(vec![40.0, 280.0, 200.0, 48.0]),
                ])
                .scroll_rects(vec![
                    Rectangle::new(vec![0.0, 20.0, 320.0, 800.0]),
                    Rectangle::new(vec![0.0, 0.0, 200.0, 48.0]),
                ])
                .client_rects(vec![
                    Rectangle::new(vec![0.0, 0.0, 320.0, 240.0]),
                    Rectangle::new(vec![0.0, 0.0, 200.0, 48.0]),
                ])
                .build()
                .expect("layout"),
        )
        .text_boxes(TextBoxSnapshot::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ))
        .scroll_offset_x(0.0)
        .scroll_offset_y(0.0)
        .content_width(1280.0)
        .content_height(960.0)
        .build()
        .expect("document");

    CaptureSnapshotReturns::new(vec![document], strings)
}

#[test]
fn annotate_tree_with_browser_use_identities_projects_hashes_and_xpath() {
    let mut tree = AccessibilityNode {
        id: "button".to_string(),
        role: "button".to_string(),
        name: Some("Next".to_string()),
        value: None,
        rect: AccessibilityRect {
            x: 0,
            y: 0,
            width: 10,
            height: 10,
        },
        children: Vec::new(),
        is_visible: true,
        attributes: HashMap::from([
            ("backend_dom_node_id".to_string(), "41".to_string()),
            ("target_id".to_string(), "target-1".to_string()),
        ]),
        som_id: Some(7),
    };

    annotate_tree_with_browser_use_identities(
        &mut tree,
        "target-1",
        &HashMap::from([(
            ("target-1".to_string(), 41),
            BrowserUseElementIdentity {
                x_path: Some("nav/a[2]".to_string()),
                element_hash: Some(11),
                stable_hash: Some(22),
                parent_branch_hash: Some(33),
                ax_name: Some("Next".to_string()),
            },
        )]),
    );

    assert_eq!(
        tree.attributes.get("x_path").map(String::as_str),
        Some("nav/a[2]")
    );
    assert_eq!(
        tree.attributes.get("stable_hash").map(String::as_str),
        Some("22")
    );
    assert_eq!(
        tree.attributes.get("ax_name").map(String::as_str),
        Some("Next")
    );
}

#[test]
fn required_styles_include_browser_use_fields() {
    let styles = required_snapshot_computed_styles();
    assert!(styles.iter().any(|value| value == "cursor"));
    assert!(styles.iter().any(|value| value == "overflow-y"));
}

#[test]
fn snapshot_lookup_extracts_clickability_scroll_and_cursor() {
    let snapshot = test_snapshot();
    let lookup = build_snapshot_lookup(&snapshot);
    let iframe = lookup.get(&2).expect("iframe metadata");
    let input = lookup.get(&3).expect("input metadata");

    assert!(iframe.is_clickable);
    assert_eq!(iframe.cursor_style.as_deref(), Some("pointer"));
    assert_eq!(iframe.paint_order, Some(7));
    assert_eq!(input.bounds.as_ref().map(|rect| rect.width), Some(200.0));
}

#[test]
fn dom_metadata_extracts_tag_and_attributes() {
    let snapshot = test_snapshot();
    let metadata = extract_dom_node_metadata(&snapshot);
    let iframe = metadata.get(&2).expect("iframe node");
    let input = metadata.get(&3).expect("input node");

    assert_eq!(iframe.tag_name.as_deref(), Some("iframe"));
    assert_eq!(
        iframe.attributes.get("id").map(String::as_str),
        Some("cross-origin-frame")
    );
    assert_eq!(
        input.attributes.get("placeholder").map(String::as_str),
        Some("Search")
    );
}

#[test]
fn annotation_merges_dom_metadata_and_iframe_hints() {
    let snapshot = test_snapshot();
    let dom_metadata =
        HashMap::from([("target-1".to_string(), extract_dom_node_metadata(&snapshot))]);
    let snapshot_lookup =
        HashMap::from([("target-1".to_string(), build_snapshot_lookup(&snapshot))]);

    let mut tree = AccessibilityNode {
        id: "root".to_string(),
        role: "root".to_string(),
        name: None,
        value: None,
        rect: AccessibilityRect {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
        },
        children: vec![AccessibilityNode {
            id: "iframe".to_string(),
            role: "iframe".to_string(),
            name: Some("Embedded frame".to_string()),
            value: None,
            rect: AccessibilityRect {
                x: 10,
                y: 20,
                width: 320,
                height: 240,
            },
            children: vec![AccessibilityNode {
                id: "search".to_string(),
                role: "textbox".to_string(),
                name: Some("Search".to_string()),
                value: None,
                rect: AccessibilityRect {
                    x: 40,
                    y: 280,
                    width: 200,
                    height: 48,
                },
                children: vec![],
                is_visible: true,
                attributes: HashMap::from([
                    ("target_id".to_string(), "target-1".to_string()),
                    ("backend_dom_node_id".to_string(), "3".to_string()),
                ]),
                som_id: None,
            }],
            is_visible: true,
            attributes: HashMap::from([
                ("target_id".to_string(), "target-1".to_string()),
                ("backend_dom_node_id".to_string(), "2".to_string()),
            ]),
            som_id: None,
        }],
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
    };

    annotate_tree_with_browser_use_metadata(
        &mut tree,
        &dom_metadata,
        &snapshot_lookup,
        &HashMap::new(),
    );
    let iframe = &tree.children[0];
    let input = &iframe.children[0];
    assert_eq!(
        iframe.attributes.get("dom_id").map(String::as_str),
        Some("cross-origin-frame")
    );
    assert_eq!(
        iframe.attributes.get("scrollable").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        iframe
            .attributes
            .get("hidden_below_count")
            .map(String::as_str),
        Some("1")
    );
    assert_eq!(
        input.attributes.get("placeholder").map(String::as_str),
        Some("Search")
    );
    assert_eq!(
        input.attributes.get("dom_clickable").map(String::as_str),
        Some("true")
    );
}

#[test]
fn annotation_marks_js_click_listener_nodes_clickable() {
    let mut tree = AccessibilityNode {
        id: "button-like".to_string(),
        role: "generic".to_string(),
        name: Some("Open menu".to_string()),
        value: None,
        rect: AccessibilityRect {
            x: 10,
            y: 10,
            width: 120,
            height: 32,
        },
        children: vec![],
        is_visible: true,
        attributes: HashMap::from([
            ("target_id".to_string(), "target-1".to_string()),
            ("backend_dom_node_id".to_string(), "42".to_string()),
        ]),
        som_id: None,
    };

    annotate_tree_with_browser_use_metadata(
        &mut tree,
        &HashMap::new(),
        &HashMap::new(),
        &HashMap::from([("target-1".to_string(), HashSet::from([42_i64]))]),
    );

    assert_eq!(
        tree.attributes
            .get("has_js_click_listener")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        tree.attributes.get("dom_clickable").map(String::as_str),
        Some("true")
    );
}
