use super::AutoLens;
use crate::gui::accessibility::{AccessibilityNode, Rect};
use crate::gui::lenses::AppLens;
use std::collections::HashMap;

#[test]
fn transform_keeps_hidden_assistive_hint_nodes() {
    let root = AccessibilityNode {
        id: "root".to_string(),
        role: "root".to_string(),
        name: Some("DOM fallback tree".to_string()),
        value: None,
        rect: Rect {
            x: 0,
            y: 0,
            width: 160,
            height: 210,
        },
        children: vec![
            AccessibilityNode {
                id: "input".to_string(),
                role: "textbox".to_string(),
                name: Some("Poland".to_string()),
                value: Some("Poland".to_string()),
                rect: Rect {
                    x: 10,
                    y: 71,
                    width: 128,
                    height: 21,
                },
                children: vec![],
                is_visible: true,
                attributes: HashMap::from([("focused".to_string(), "true".to_string())]),
                som_id: None,
            },
            AccessibilityNode {
                id: "assistive-ui-id-2".to_string(),
                role: "status".to_string(),
                name: Some(
                    "1 result is available, use up and down arrow keys to navigate. Poland"
                        .to_string(),
                ),
                value: None,
                rect: Rect {
                    x: -1,
                    y: 209,
                    width: 1,
                    height: 16,
                },
                children: vec![],
                is_visible: false,
                attributes: HashMap::from([("assistive_hint".to_string(), "true".to_string())]),
                som_id: None,
            },
        ],
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
    };

    let transformed = AutoLens.transform(&root).expect("tree should transform");
    assert!(
        transformed
            .children
            .iter()
            .any(|child| child.attributes.contains_key("assistive_hint")),
        "{transformed:#?}"
    );
}

#[test]
fn transform_adds_dom_id_based_aliases_for_mutable_controls() {
    let root = AccessibilityNode {
        id: "root".to_string(),
        role: "root".to_string(),
        name: Some("DOM fallback tree".to_string()),
        value: None,
        rect: Rect {
            x: 0,
            y: 0,
            width: 240,
            height: 180,
        },
        children: vec![AccessibilityNode {
            id: "dom-id-status".to_string(),
            role: "combobox".to_string(),
            name: Some("Awaiting Dispatch".to_string()),
            value: Some("Awaiting Dispatch".to_string()),
            rect: Rect {
                x: 12,
                y: 30,
                width: 160,
                height: 40,
            },
            children: vec![],
            is_visible: true,
            attributes: HashMap::from([
                ("dom_id".to_string(), "status".to_string()),
                ("tag_name".to_string(), "select".to_string()),
            ]),
            som_id: None,
        }],
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
    };

    let transformed = AutoLens.transform(&root).expect("tree should transform");
    let child = transformed
        .children
        .first()
        .expect("mutable control should survive");
    let aliases = child
        .attributes
        .get("semantic_aliases")
        .expect("semantic aliases should be present");

    assert!(aliases.split_whitespace().any(|alias| alias == "status"));
    assert!(aliases
        .split_whitespace()
        .any(|alias| alias == "inp_status"));
}

#[test]
fn transform_prefers_dom_id_for_svg_geometry_nodes_with_moving_names() {
    let make_circle = |name: &str, x: i32, y: i32| AccessibilityNode {
        id: "dom-id-circ".to_string(),
        role: "generic".to_string(),
        name: Some(name.to_string()),
        value: None,
        rect: Rect {
            x,
            y,
            width: 44,
            height: 44,
        },
        children: vec![],
        is_visible: true,
        attributes: HashMap::from([
            ("dom_id".to_string(), "circ".to_string()),
            ("tag_name".to_string(), "circle".to_string()),
            ("shape_kind".to_string(), "circle".to_string()),
        ]),
        som_id: None,
    };

    let root_a = AccessibilityNode {
        id: "root".to_string(),
        role: "root".to_string(),
        name: Some("DOM fallback tree".to_string()),
        value: None,
        rect: Rect {
            x: 0,
            y: 0,
            width: 240,
            height: 180,
        },
        children: vec![make_circle(
            "large circle centered at 59,156 radius 22",
            37,
            134,
        )],
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
    };
    let root_b = AccessibilityNode {
        children: vec![make_circle(
            "large circle centered at 112,94 radius 22",
            90,
            72,
        )],
        ..root_a.clone()
    };

    let transformed_a = AutoLens.transform(&root_a).expect("tree should transform");
    let transformed_b = AutoLens.transform(&root_b).expect("tree should transform");
    let circle_a = transformed_a
        .children
        .first()
        .expect("circle should survive");
    let circle_b = transformed_b
        .children
        .first()
        .expect("circle should survive");

    assert_eq!(circle_a.id, "grp_circ");
    assert_eq!(circle_b.id, "grp_circ");
}

#[test]
fn transform_keeps_human_readable_button_ids_when_dom_id_is_opaque() {
    let root = AccessibilityNode {
        id: "root".to_string(),
        role: "root".to_string(),
        name: Some("DOM fallback tree".to_string()),
        value: None,
        rect: Rect {
            x: 0,
            y: 0,
            width: 240,
            height: 180,
        },
        children: vec![AccessibilityNode {
            id: "dom-id-subbtn".to_string(),
            role: "button".to_string(),
            name: Some("Submit".to_string()),
            value: None,
            rect: Rect {
                x: 12,
                y: 30,
                width: 96,
                height: 32,
            },
            children: vec![],
            is_visible: true,
            attributes: HashMap::from([
                ("dom_id".to_string(), "subbtn".to_string()),
                ("tag_name".to_string(), "button".to_string()),
            ]),
            som_id: None,
        }],
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
    };

    let transformed = AutoLens.transform(&root).expect("tree should transform");
    let button = transformed.children.first().expect("button should survive");
    assert_eq!(button.id, "btn_submit");
}
