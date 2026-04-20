use super::*;
use chromiumoxide::cdp::browser_protocol::accessibility::{
    AxNode, AxProperty, AxPropertyName, AxValue, AxValueType,
};
use chromiumoxide::cdp::browser_protocol::dom::BackendNodeId;
use chromiumoxide::cdp::browser_protocol::dom_snapshot::{
    ArrayOfStrings, DocumentSnapshot, LayoutTreeSnapshot, NodeTreeSnapshot, RareBooleanData,
    RareIntegerData, Rectangle, TextBoxSnapshot,
};

fn ax_string(value: &str) -> AxValue {
    AxValue::builder()
        .r#type(AxValueType::String)
        .value(serde_json::Value::String(value.to_string()))
        .build()
        .expect("ax string")
}

fn test_snapshot() -> CaptureSnapshotReturns {
    let strings = vec![
        "doc".to_string(),
        "title".to_string(),
        "base".to_string(),
        "lang".to_string(),
        "utf-8".to_string(),
        "".to_string(),
        "root-frame".to_string(),
        "html".to_string(),
        "iframe".to_string(),
        "bid".to_string(),
        "a".to_string(),
        "browsergym_visibility_ratio".to_string(),
        "1".to_string(),
        "browsergym_set_of_marks".to_string(),
        "a0".to_string(),
        "0.25".to_string(),
        "child-frame".to_string(),
    ];

    let root_doc = DocumentSnapshot::builder()
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
                .parent_indexs(vec![-1, 0])
                .node_types(vec![9, 1])
                .node_names(vec![StringIndex::new(7), StringIndex::new(8)])
                .node_values(vec![StringIndex::new(5), StringIndex::new(5)])
                .backend_node_ids(vec![BackendNodeId::new(1), BackendNodeId::new(2)])
                .attributes(vec![
                    ArrayOfStrings::new(Vec::<StringIndex>::new()),
                    ArrayOfStrings::new(vec![StringIndex::new(9), StringIndex::new(10)]),
                ])
                .content_document_index(
                    RareIntegerData::builder()
                        .index(1)
                        .value(1)
                        .build()
                        .expect("content doc index"),
                )
                .is_clickable(
                    RareBooleanData::builder()
                        .index(1)
                        .build()
                        .expect("clickable"),
                )
                .build(),
        )
        .layout(
            LayoutTreeSnapshot::builder()
                .node_indexs(vec![1])
                .styles(vec![ArrayOfStrings::new(Vec::<StringIndex>::new())])
                .bounds(vec![Rectangle::new(vec![100.0, 200.0, 300.0, 400.0])])
                .texts(vec![StringIndex::new(5)])
                .stacking_contexts(RareBooleanData::new(Vec::new()))
                .paint_orders(vec![1])
                .offset_rects(vec![Rectangle::new(vec![100.0, 200.0, 300.0, 400.0])])
                .scroll_rects(vec![Rectangle::new(vec![0.0, 0.0, 300.0, 400.0])])
                .client_rects(vec![Rectangle::new(vec![0.0, 0.0, 300.0, 400.0])])
                .build()
                .expect("root layout"),
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
        .expect("root doc");

    let child_doc = DocumentSnapshot::builder()
        .document_url(StringIndex::new(0))
        .title(StringIndex::new(1))
        .base_url(StringIndex::new(2))
        .content_language(StringIndex::new(3))
        .encoding_name(StringIndex::new(4))
        .public_id(StringIndex::new(5))
        .system_id(StringIndex::new(5))
        .frame_id(StringIndex::new(16))
        .nodes(
            NodeTreeSnapshot::builder()
                .parent_indexs(vec![-1, 0])
                .node_types(vec![9, 1])
                .node_names(vec![StringIndex::new(7), StringIndex::new(8)])
                .node_values(vec![StringIndex::new(5), StringIndex::new(5)])
                .backend_node_ids(vec![BackendNodeId::new(3), BackendNodeId::new(4)])
                .attributes(vec![
                    ArrayOfStrings::new(Vec::<StringIndex>::new()),
                    ArrayOfStrings::new(vec![
                        StringIndex::new(9),
                        StringIndex::new(14),
                        StringIndex::new(11),
                        StringIndex::new(15),
                        StringIndex::new(13),
                        StringIndex::new(12),
                    ]),
                ])
                .is_clickable(
                    RareBooleanData::builder()
                        .index(1)
                        .build()
                        .expect("child clickable"),
                )
                .build(),
        )
        .layout(
            LayoutTreeSnapshot::builder()
                .node_indexs(vec![1])
                .styles(vec![ArrayOfStrings::new(Vec::<StringIndex>::new())])
                .bounds(vec![Rectangle::new(vec![5.0, 6.0, 7.0, 8.0])])
                .texts(vec![StringIndex::new(5)])
                .stacking_contexts(RareBooleanData::new(Vec::new()))
                .paint_orders(vec![1])
                .offset_rects(vec![Rectangle::new(vec![5.0, 6.0, 7.0, 8.0])])
                .scroll_rects(vec![Rectangle::new(vec![10.0, 20.0, 30.0, 40.0])])
                .client_rects(vec![Rectangle::new(vec![0.0, 0.0, 7.0, 8.0])])
                .build()
                .expect("child layout"),
        )
        .text_boxes(TextBoxSnapshot::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ))
        .scroll_offset_x(10.0)
        .scroll_offset_y(20.0)
        .content_width(300.0)
        .content_height(200.0)
        .build()
        .expect("child doc");

    CaptureSnapshotReturns::new(vec![root_doc, child_doc], strings)
}

#[test]
fn aria_cleanup_extracts_browsergym_prefix() {
    let (bid, cleaned) = extract_browsergym_data_from_aria_text("browsergym_id_a1 Original label");
    assert_eq!(bid.as_deref(), Some("a1"));
    assert_eq!(cleaned, "Original label");

    let (bid, cleaned) = extract_browsergym_data_from_aria_text("browsergym_id_z9");
    assert_eq!(bid.as_deref(), Some("z9"));
    assert!(cleaned.is_empty());

    let (bid, cleaned) = extract_browsergym_data_from_aria_text("plain text");
    assert!(bid.is_none());
    assert_eq!(cleaned, "plain text");
}

#[test]
fn cleanup_ax_tree_extracts_browsergym_ids() {
    let mut nodes = vec![
        AxNode::builder()
            .node_id("node-1".to_string())
            .ignored(false)
            .propertie(
                AxProperty::builder()
                    .name(AxPropertyName::Roledescription)
                    .value(ax_string("browsergym_id_a1 Original role"))
                    .build()
                    .expect("role prop"),
            )
            .build()
            .expect("node 1"),
        AxNode::builder()
            .node_id("node-2".to_string())
            .ignored(false)
            .description(ax_string("browsergym_id_b2"))
            .build()
            .expect("node 2"),
    ];

    let ids = cleanup_ax_tree_browsergym_ids(&mut nodes);
    assert_eq!(ids.get("node-1").map(String::as_str), Some("a1"));
    assert_eq!(ids.get("node-2").map(String::as_str), Some("b2"));

    let props = nodes[0].properties.as_ref().expect("cleaned props");
    assert_eq!(
        ax_value_string(&props[0].value).as_deref(),
        Some("Original role")
    );
    assert!(nodes[1].description.is_none());
}

#[test]
fn extract_dom_extra_properties_offsets_child_iframe_bounds() {
    let snapshot = test_snapshot();
    let extra = extract_browsergym_extra_properties(&snapshot);
    let node = extra.get("a0").expect("child bid");

    assert_eq!(node.visibility_ratio, Some(0.25));
    assert!(node.clickable);
    assert!(node.set_of_marks);
    assert_eq!(
        node.bbox,
        Some(AccessibilityRect {
            x: 95,
            y: 186,
            width: 7,
            height: 8,
        })
    );
}

#[test]
fn annotate_tree_applies_browsergym_metadata() {
    let mut root = AccessibilityNode {
        id: "node-1".to_string(),
        role: "button".to_string(),
        name: Some("Submit".to_string()),
        value: None,
        rect: AccessibilityRect {
            x: 0,
            y: 0,
            width: 1,
            height: 1,
        },
        children: Vec::new(),
        is_visible: true,
        attributes: HashMap::from([("bid".to_string(), "a0".to_string())]),
        som_id: None,
    };

    let extra = HashMap::from([(
        "a0".to_string(),
        BrowserGymElementProperties {
            visibility_ratio: Some(0.25),
            bbox: Some(AccessibilityRect {
                x: 10,
                y: 20,
                width: 30,
                height: 40,
            }),
            clickable: true,
            set_of_marks: true,
        },
    )]);

    annotate_tree_with_browsergym_metadata(&mut root, &extra, Some("a0"));

    assert!(!root.is_visible);
    assert_eq!(root.rect.x, 10);
    assert_eq!(
        root.attributes.get("browsergym_id").map(String::as_str),
        Some("a0")
    );
    assert_eq!(
        root.attributes.get("dom_clickable").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        root.attributes.get("focused").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        root.attributes
            .get("browsergym_set_of_marks")
            .map(String::as_str),
        Some("1")
    );
}

#[test]
fn render_extra_properties_text_preserves_browsergym_shape() {
    let extra = HashMap::from([(
        "a0".to_string(),
        BrowserGymElementProperties {
            visibility_ratio: Some(0.25),
            bbox: Some(AccessibilityRect {
                x: 10,
                y: 20,
                width: 30,
                height: 40,
            }),
            clickable: true,
            set_of_marks: true,
        },
    )]);

    let rendered =
        render_browsergym_extra_properties_text(&extra).expect("browsergym extra-properties");

    assert!(rendered.contains("\"a0\""));
    assert!(rendered.contains("\"visibility\": 0.25"));
    assert!(rendered.contains("\"bbox\": ["));
    assert!(rendered.contains("\"clickable\": true"));
    assert!(rendered.contains("\"set_of_marks\": true"));
}
