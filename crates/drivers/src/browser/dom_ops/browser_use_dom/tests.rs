use super::{
    build_ax_lookup_by_target_backend, collect_som_ids_by_target_backend,
    render_browser_use_observation_from_dom, BrowserUseSnapshotNode,
};
use crate::browser::dom_ops::browsergym::BrowserGymSnapshotMetadata;
use crate::browser::dom_ops::targets::BrowserFrameTarget;
use crate::gui::accessibility::{AccessibilityNode, Rect};
use chromiumoxide::cdp::browser_protocol::{
    accessibility::{AxNode, AxValue, AxValueType},
    dom::{BackendNodeId, Node, NodeId, ShadowRootType},
};
use std::collections::{HashMap, HashSet};

fn ax_string(value: &str) -> AxValue {
    AxValue::builder()
        .r#type(AxValueType::String)
        .value(serde_json::Value::String(value.to_string()))
        .build()
        .expect("ax value")
}

fn dom_node(
    node_id: i64,
    backend_node_id: i64,
    node_type: i64,
    node_name: &str,
    attributes: &[(&str, &str)],
) -> Node {
    Node::builder()
        .node_id(NodeId::new(node_id))
        .backend_node_id(BackendNodeId::new(backend_node_id))
        .node_type(node_type)
        .node_name(node_name.to_string())
        .local_name(node_name.to_ascii_lowercase())
        .node_value(String::new())
        .attributes(
            attributes
                .iter()
                .flat_map(|(key, value)| [key.to_string(), value.to_string()])
                .collect::<Vec<_>>(),
        )
        .build()
        .expect("dom node")
}

#[test]
fn collect_som_ids_uses_default_target_id() {
    let tree = AccessibilityNode {
        id: "button".to_string(),
        role: "button".to_string(),
        name: Some("Submit".to_string()),
        value: None,
        rect: Rect {
            x: 0,
            y: 0,
            width: 20,
            height: 20,
        },
        children: Vec::new(),
        is_visible: true,
        attributes: HashMap::from([("backend_dom_node_id".to_string(), "41".to_string())]),
        som_id: Some(3),
    };

    let mut map = HashMap::new();
    collect_som_ids_by_target_backend(&tree, "target-1", &mut map);

    assert_eq!(map.get(&("target-1".to_string(), 41)), Some(&3));
}

#[test]
fn render_browser_use_state_from_dom_includes_shadow_iframe_and_ids() {
    let mut root = dom_node(1, 1, 9, "#document", &[]);
    let mut host = dom_node(2, 2, 1, "DIV", &[("bid", "a"), ("id", "host")]);
    let mut shadow_root = dom_node(3, 3, 11, "#document-fragment", &[]);
    shadow_root.shadow_root_type = Some(ShadowRootType::Open);
    shadow_root.children = Some(vec![dom_node(
        4,
        4,
        1,
        "BUTTON",
        &[("bid", "a0"), ("id", "shadow-btn"), ("value", "Click me")],
    )]);
    host.shadow_roots = Some(vec![shadow_root]);

    let mut iframe = dom_node(5, 5, 1, "IFRAME", &[("bid", "b"), ("name", "Embedded")]);
    iframe.frame_id = Some(chromiumoxide::cdp::browser_protocol::page::FrameId::new(
        "child-frame".to_string(),
    ));

    let mut child_root = dom_node(6, 6, 9, "#document", &[]);
    child_root.children = Some(vec![dom_node(
        7,
        7,
        1,
        "INPUT",
        &[("bid", "b0"), ("placeholder", "Search")],
    )]);

    root.children = Some(vec![host, iframe]);

    let dom_roots_by_target = HashMap::from([
        ("target-1".to_string(), root),
        ("target-2".to_string(), child_root),
    ]);

    let frames_by_id = HashMap::from([(
        "child-frame".to_string(),
        BrowserFrameTarget {
            frame_id: "child-frame".to_string(),
            target_id: "target-2".to_string(),
            parent_frame_id: Some("root-frame".to_string()),
            parent_target_id: Some("target-1".to_string()),
            child_frame_ids: Vec::new(),
            target_type: "iframe".to_string(),
        },
    )]);

    let snapshot_lookup_by_target = HashMap::from([
        (
            "target-1".to_string(),
            HashMap::from([
                (
                    2,
                    BrowserUseSnapshotNode {
                        is_clickable: false,
                        cursor_style: None,
                        bounds: None,
                        client_rects: None,
                        scroll_rects: None,
                        computed_styles: HashMap::new(),
                        paint_order: None,
                    },
                ),
                (
                    4,
                    BrowserUseSnapshotNode {
                        is_clickable: true,
                        cursor_style: Some("pointer".to_string()),
                        bounds: None,
                        client_rects: None,
                        scroll_rects: None,
                        computed_styles: HashMap::new(),
                        paint_order: None,
                    },
                ),
                (
                    5,
                    BrowserUseSnapshotNode {
                        is_clickable: true,
                        cursor_style: None,
                        bounds: Some(super::super::browser_use::BrowserUseDomRect {
                            x: 0.0,
                            y: 0.0,
                            width: 320.0,
                            height: 240.0,
                        }),
                        client_rects: None,
                        scroll_rects: None,
                        computed_styles: HashMap::new(),
                        paint_order: None,
                    },
                ),
            ]),
        ),
        (
            "target-2".to_string(),
            HashMap::from([(
                7,
                BrowserUseSnapshotNode {
                    is_clickable: true,
                    cursor_style: None,
                    bounds: None,
                    client_rects: None,
                    scroll_rects: None,
                    computed_styles: HashMap::new(),
                    paint_order: None,
                },
            )]),
        ),
    ]);

    let snapshot_metadata_by_target = HashMap::from([
        (
            "target-1".to_string(),
            BrowserGymSnapshotMetadata {
                extra_properties: HashMap::from([
                    (
                        "a".to_string(),
                        crate::browser::dom_ops::browsergym::BrowserGymElementProperties {
                            visibility_ratio: Some(1.0),
                            bbox: Some(Rect {
                                x: 0,
                                y: 0,
                                width: 200,
                                height: 60,
                            }),
                            clickable: false,
                            set_of_marks: false,
                        },
                    ),
                    (
                        "a0".to_string(),
                        crate::browser::dom_ops::browsergym::BrowserGymElementProperties {
                            visibility_ratio: Some(1.0),
                            bbox: Some(Rect {
                                x: 10,
                                y: 10,
                                width: 120,
                                height: 32,
                            }),
                            clickable: true,
                            set_of_marks: false,
                        },
                    ),
                    (
                        "b".to_string(),
                        crate::browser::dom_ops::browsergym::BrowserGymElementProperties {
                            visibility_ratio: Some(1.0),
                            bbox: Some(Rect {
                                x: 0,
                                y: 80,
                                width: 320,
                                height: 240,
                            }),
                            clickable: true,
                            set_of_marks: false,
                        },
                    ),
                ]),
                backend_node_bids: HashMap::new(),
            },
        ),
        (
            "target-2".to_string(),
            BrowserGymSnapshotMetadata {
                extra_properties: HashMap::from([(
                    "b0".to_string(),
                    crate::browser::dom_ops::browsergym::BrowserGymElementProperties {
                        visibility_ratio: Some(1.0),
                        bbox: Some(Rect {
                            x: 10,
                            y: 110,
                            width: 160,
                            height: 28,
                        }),
                        clickable: true,
                        set_of_marks: false,
                    },
                )]),
                backend_node_bids: HashMap::new(),
            },
        ),
    ]);

    let ax_nodes = vec![
        AxNode::builder()
            .node_id("n4".to_string())
            .backend_dom_node_id(BackendNodeId::new(4))
            .ignored(false)
            .role(ax_string("button"))
            .name(ax_string("Shadow Button"))
            .build()
            .expect("ax button"),
        AxNode::builder()
            .node_id("n7".to_string())
            .backend_dom_node_id(BackendNodeId::new(7))
            .ignored(false)
            .role(ax_string("textbox"))
            .name(ax_string("Search"))
            .build()
            .expect("ax textbox"),
    ];
    let ax_lookup = build_ax_lookup_by_target_backend(
        &ax_nodes,
        &HashMap::from([
            ("n4".to_string(), "target-1".to_string()),
            ("n7".to_string(), "target-2".to_string()),
        ]),
        "target-1",
    );

    let som_by_target_backend = HashMap::from([
        (("target-1".to_string(), 4), 3),
        (("target-2".to_string(), 7), 7),
    ]);

    let observation = render_browser_use_observation_from_dom(
        "target-1",
        &dom_roots_by_target,
        Some(&frames_by_id),
        &snapshot_metadata_by_target,
        &snapshot_lookup_by_target,
        &HashMap::<String, HashSet<i64>>::new(),
        &ax_lookup,
        &som_by_target_backend,
        None,
    );
    let text = observation.state_text.expect("state text");
    let selector_map = observation.selector_map_text.expect("selector map");

    assert!(text.contains("Open Shadow"));
    assert!(text.contains("Shadow End"));
    assert!(text.contains("*[4]<button name=Shadow Button"));
    assert!(text.contains("|IFRAME|<iframe name=Embedded"));
    assert!(text.contains("*[7]<input name=Search placeholder=Search"));
    assert!(selector_map.contains("[4] <button name=Shadow Button"));
    assert!(selector_map.contains("target_id=target-2"));
}
