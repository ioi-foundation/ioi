use super::{
    flatten_ax_tree_to_string, flatten_dom_snapshot_to_string, prune_html,
    BrowserGymAxFlattenOptions, BrowserGymDomFlattenOptions,
};
use crate::browser::dom_ops::browsergym::{
    cleanup_ax_tree_browsergym_ids, extract_browsergym_extra_properties,
};
use chromiumoxide::cdp::browser_protocol::accessibility::{
    AxNode, AxProperty, AxPropertyName, AxValue, AxValueType,
};
use chromiumoxide::cdp::browser_protocol::dom::BackendNodeId;
use chromiumoxide::cdp::browser_protocol::dom_snapshot::{
    ArrayOfStrings, CaptureSnapshotReturns, DocumentSnapshot, LayoutTreeSnapshot, NodeTreeSnapshot,
    RareBooleanData, Rectangle, StringIndex, TextBoxSnapshot,
};
use std::collections::HashMap;
fn ax_string(value: &str) -> AxValue {
    AxValue::builder()
        .r#type(AxValueType::String)
        .value(serde_json::Value::String(value.to_string()))
        .build()
        .expect("ax string")
}

fn dom_snapshot() -> CaptureSnapshotReturns {
    let strings = vec![
        "".to_string(),
        "html".to_string(),
        "body".to_string(),
        "input".to_string(),
        "#text".to_string(),
        "bid".to_string(),
        "n1".to_string(),
        "type".to_string(),
        "checkbox".to_string(),
        "browsergym_visibility_ratio".to_string(),
        "1".to_string(),
        "browsergym_set_of_marks".to_string(),
        "Text within a non-html tag".to_string(),
    ];

    let document = DocumentSnapshot::builder()
        .document_url(StringIndex::new(0))
        .title(StringIndex::new(0))
        .base_url(StringIndex::new(0))
        .content_language(StringIndex::new(0))
        .encoding_name(StringIndex::new(0))
        .public_id(StringIndex::new(0))
        .system_id(StringIndex::new(0))
        .frame_id(StringIndex::new(0))
        .nodes(
            NodeTreeSnapshot::builder()
                .parent_indexs(vec![-1, 0, 1, 2, 2])
                .node_types(vec![9, 1, 1, 1, 3])
                .node_names(vec![
                    StringIndex::new(1),
                    StringIndex::new(1),
                    StringIndex::new(2),
                    StringIndex::new(3),
                    StringIndex::new(4),
                ])
                .node_values(vec![
                    StringIndex::new(0),
                    StringIndex::new(0),
                    StringIndex::new(0),
                    StringIndex::new(0),
                    StringIndex::new(12),
                ])
                .backend_node_ids(vec![
                    BackendNodeId::new(1),
                    BackendNodeId::new(2),
                    BackendNodeId::new(3),
                    BackendNodeId::new(4),
                    BackendNodeId::new(5),
                ])
                .attributes(vec![
                    ArrayOfStrings::new(Vec::<StringIndex>::new()),
                    ArrayOfStrings::new(Vec::<StringIndex>::new()),
                    ArrayOfStrings::new(Vec::<StringIndex>::new()),
                    ArrayOfStrings::new(vec![
                        StringIndex::new(5),
                        StringIndex::new(6),
                        StringIndex::new(7),
                        StringIndex::new(8),
                        StringIndex::new(9),
                        StringIndex::new(10),
                        StringIndex::new(11),
                        StringIndex::new(10),
                    ]),
                    ArrayOfStrings::new(Vec::<StringIndex>::new()),
                ])
                .is_clickable(
                    RareBooleanData::builder()
                        .index(3)
                        .build()
                        .expect("clickable"),
                )
                .build(),
        )
        .layout(
            LayoutTreeSnapshot::builder()
                .node_indexs(vec![3])
                .styles(vec![ArrayOfStrings::new(Vec::<StringIndex>::new())])
                .bounds(vec![Rectangle::new(vec![10.0, 20.0, 100.0, 30.0])])
                .texts(vec![StringIndex::new(0)])
                .stacking_contexts(RareBooleanData::new(Vec::new()))
                .paint_orders(vec![1])
                .offset_rects(vec![Rectangle::new(vec![10.0, 20.0, 100.0, 30.0])])
                .scroll_rects(vec![Rectangle::new(vec![0.0, 0.0, 100.0, 30.0])])
                .client_rects(vec![Rectangle::new(vec![0.0, 0.0, 100.0, 30.0])])
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
        .content_width(800.0)
        .content_height(600.0)
        .build()
        .expect("document");

    CaptureSnapshotReturns::new(vec![document], strings)
}

#[test]
fn flatten_dom_snapshot_renders_browsergym_metadata() {
    let snapshot = dom_snapshot();
    let extra = extract_browsergym_extra_properties(&snapshot);
    let html = flatten_dom_snapshot_to_string(
        &snapshot,
        Some(&extra),
        &BrowserGymDomFlattenOptions {
            with_visible: true,
            with_clickable: true,
            with_center_coords: true,
            with_bounding_box_coords: true,
            with_som: true,
            ..Default::default()
        },
    );

    assert!(html.contains("center=\"(60,35)\""));
    assert!(html.contains("box=\"(10,20,110,50)\""));
    assert!(html.contains("clickable"));
    assert!(html.contains("som"));
    assert!(html.contains("Text within a non-html tag"));
    assert!(html.contains("\n <html>") || html.starts_with("<html>"));
    let box_idx = html.find("box=\"(10,20,110,50)\"").expect("box attr");
    let center_idx = html.find("center=\"(60,35)\"").expect("center attr");
    let clickable_idx = html.find("clickable").expect("clickable attr");
    let visible_idx = html.find("visible").expect("visible attr");
    let som_idx = html.find("som").expect("som attr");
    let input_idx = html.find("<input").expect("input");
    let self_close_idx = html[input_idx..].find("/>").expect("self close") + input_idx;
    let text_idx = html
        .find("Text within a non-html tag")
        .expect("inline text");
    assert!(box_idx < center_idx);
    assert!(center_idx < clickable_idx);
    assert!(clickable_idx < visible_idx);
    assert!(visible_idx < som_idx);
    assert!(self_close_idx < text_idx);
}

#[test]
fn prune_html_matches_browsergym_unwrap_and_decompose_rules() {
    let pruned = prune_html(
        r#"<html><body><div bid="1"><span bid="2">Hello</span></div><style>ignored</style><script>ignored</script><link rel="stylesheet" href="/x.css"><br><p bid="3"></p><p bid="4">World</p><section><b>Keep</b></section><!-- removed --></body></html>"#,
    );

    assert_eq!(
        pruned,
        "<head>\n</head>\nHelloWorld\n<section>\n <b>\n  Keep\n </b>\n</section>"
    );
}

#[test]
fn flatten_ax_tree_renders_browsergym_ids() {
    let mut nodes = vec![
        AxNode::builder()
            .node_id("root".to_string())
            .ignored(false)
            .role(ax_string("RootWebArea"))
            .name(ax_string("Page"))
            .child_id("child".to_string())
            .build()
            .expect("root"),
        AxNode::builder()
            .node_id("child".to_string())
            .ignored(false)
            .role(ax_string("button"))
            .name(ax_string("Submit"))
            .propertie(
                AxProperty::builder()
                    .name(AxPropertyName::Focused)
                    .value(ax_string("true"))
                    .build()
                    .expect("prop"),
            )
            .description(ax_string("browsergym_id_n1"))
            .build()
            .expect("child"),
    ];

    let ids = cleanup_ax_tree_browsergym_ids(&mut nodes);
    let snapshot = dom_snapshot();
    let extra = extract_browsergym_extra_properties(&snapshot);
    let text = flatten_ax_tree_to_string(
        &nodes,
        &ids,
        Some(&extra),
        &BrowserGymAxFlattenOptions {
            with_visible: true,
            with_clickable: true,
            with_center_coords: true,
            with_bounding_box_coords: true,
            with_som: true,
            ..Default::default()
        },
    );

    assert!(text.contains("[n1] button \"Submit\""));
    assert!(text.contains("focused"));
    assert!(text.contains("center=\"(60,35)\""));
    assert!(text.contains("box=\"(10,20,110,50)\""));
}

#[test]
fn flatten_ax_tree_skips_nodes_without_names_like_browsergym() {
    let nodes = vec![
        AxNode::builder()
            .node_id("root".to_string())
            .ignored(false)
            .role(ax_string("RootWebArea"))
            .name(ax_string("Page"))
            .child_id("child".to_string())
            .build()
            .expect("root"),
        AxNode::builder()
            .node_id("child".to_string())
            .ignored(false)
            .role(ax_string("button"))
            .build()
            .expect("child"),
    ];

    let text = flatten_ax_tree_to_string(
        &nodes,
        &HashMap::new(),
        None,
        &BrowserGymAxFlattenOptions::default(),
    );

    assert!(!text.contains("button"));
}
