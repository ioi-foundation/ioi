use super::{
    assign_browser_som_ids, selected_child_indices, serialize_tree_to_xml, AccessibilityNode, Rect,
};
use std::collections::HashMap;

#[test]
fn serialize_tree_to_xml_includes_browser_locator_attrs_for_native_selects() {
    let node = AccessibilityNode {
        id: "inp_turkey".to_string(),
        role: "combobox".to_string(),
        name: Some("Turkey".to_string()),
        value: Some("Turkey".to_string()),
        rect: Rect {
            x: 2,
            y: 57,
            width: 150,
            height: 19,
        },
        children: vec![],
        is_visible: true,
        attributes: HashMap::from([
            ("dom_id".to_string(), "options".to_string()),
            ("tag_name".to_string(), "select".to_string()),
            ("focused".to_string(), "true".to_string()),
            ("readonly".to_string(), "true".to_string()),
        ]),
        som_id: None,
    };

    let xml = serialize_tree_to_xml(&node, 0);
    assert!(xml.contains(r#"dom_id="options""#), "{xml}");
    assert!(xml.contains(r#"tag_name="select""#), "{xml}");
    assert!(
        xml.contains(r#"selector="[id=&quot;options&quot;]""#),
        "{xml}"
    );
    assert!(xml.contains(r#"focused="true""#), "{xml}");
    assert!(xml.contains(r#"readonly="true""#), "{xml}");
}

#[test]
fn serialize_tree_to_xml_includes_dom_clickable_locator_attr_for_generic_targets() {
    let node = AccessibilityNode {
        id: "grp_trash".to_string(),
        role: "generic".to_string(),
        name: Some("trash".to_string()),
        value: None,
        rect: Rect {
            x: 117,
            y: 119,
            width: 12,
            height: 12,
        },
        children: vec![],
        is_visible: true,
        attributes: HashMap::from([
            ("tag_name".to_string(), "span".to_string()),
            ("class_name".to_string(), "trash".to_string()),
            ("dom_clickable".to_string(), "true".to_string()),
        ]),
        som_id: None,
    };

    let xml = serialize_tree_to_xml(&node, 0);
    assert!(xml.contains(r#"class_name="trash""#), "{xml}");
    assert!(xml.contains(r#"dom_clickable="true""#), "{xml}");
}

#[test]
fn assign_browser_som_ids_keeps_broader_actionable_indexing_when_explicit_marks_exist() {
    let mut tree = AccessibilityNode {
        id: "root".to_string(),
        role: "root".to_string(),
        name: None,
        value: None,
        rect: Rect {
            x: 0,
            y: 0,
            width: 400,
            height: 300,
        },
        children: vec![
            AccessibilityNode {
                id: "marked".to_string(),
                role: "button".to_string(),
                name: Some("Marked".to_string()),
                value: None,
                rect: Rect {
                    x: 10,
                    y: 10,
                    width: 120,
                    height: 32,
                },
                children: vec![],
                is_visible: true,
                attributes: HashMap::from([(
                    "browsergym_set_of_marks".to_string(),
                    "1".to_string(),
                )]),
                som_id: None,
            },
            AccessibilityNode {
                id: "plain-input".to_string(),
                role: "textbox".to_string(),
                name: Some("Search".to_string()),
                value: None,
                rect: Rect {
                    x: 10,
                    y: 60,
                    width: 180,
                    height: 32,
                },
                children: vec![],
                is_visible: true,
                attributes: HashMap::from([("tag_name".to_string(), "input".to_string())]),
                som_id: None,
            },
        ],
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
    };

    assign_browser_som_ids(&mut tree);

    assert_eq!(tree.children[0].som_id, Some(1));
    assert_eq!(tree.children[1].som_id, Some(2));
}

#[test]
fn serialize_tree_to_xml_includes_ported_browser_use_attrs() {
    let node = AccessibilityNode {
        id: "frame_main".to_string(),
        role: "iframe".to_string(),
        name: Some("Embedded Search".to_string()),
        value: None,
        rect: Rect {
            x: 10,
            y: 20,
            width: 320,
            height: 240,
        },
        children: vec![],
        is_visible: true,
        attributes: HashMap::from([
            ("dom_id".to_string(), "cross-origin-frame".to_string()),
            ("tag_name".to_string(), "iframe".to_string()),
            ("scrollable".to_string(), "true".to_string()),
            ("hidden_below_count".to_string(), "2".to_string()),
            (
                "hidden_below".to_string(),
                "textbox:Search@1.1p|button:Submit@1.5p".to_string(),
            ),
            ("cursor_style".to_string(), "pointer".to_string()),
        ]),
        som_id: Some(7),
    };

    let xml = serialize_tree_to_xml(&node, 0);
    assert!(xml.contains(r#"som_id="7""#), "{xml}");
    assert!(xml.contains(r#"scrollable="true""#), "{xml}");
    assert!(xml.contains(r#"hidden_below_count="2""#), "{xml}");
    assert!(xml.contains(r#"cursor_style="pointer""#), "{xml}");
    assert!(
        xml.contains(r#"hidden_below="textbox:Search@1.1p|button:Submit@1.5p""#),
        "{xml}"
    );
}

#[test]
fn serialize_tree_to_xml_keeps_hidden_assistive_autocomplete_hints() {
    let tree = AccessibilityNode {
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
                id: "inp_poland".to_string(),
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
                attributes: HashMap::from([
                    ("dom_id".to_string(), "tags".to_string()),
                    ("tag_name".to_string(), "input".to_string()),
                    ("focused".to_string(), "true".to_string()),
                    ("autocomplete".to_string(), "list".to_string()),
                    ("controls_dom_id".to_string(), "ui-id-1".to_string()),
                    (
                        "active_descendant_dom_id".to_string(),
                        "ui-id-2".to_string(),
                    ),
                ]),
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
                attributes: HashMap::from([
                    ("dom_id".to_string(), "ui-id-2".to_string()),
                    ("tag_name".to_string(), "div".to_string()),
                    ("assistive_hint".to_string(), "true".to_string()),
                    (
                        "assistive_reason".to_string(),
                        "assistive_live_region".to_string(),
                    ),
                ]),
                som_id: None,
            },
        ],
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
    };

    let xml = serialize_tree_to_xml(&tree, 0);
    assert!(xml.contains(r#"autocomplete="list""#), "{xml}");
    assert!(xml.contains(r#"controls_dom_id="ui-id-1""#), "{xml}");
    assert!(
        xml.contains(r#"active_descendant_dom_id="ui-id-2""#),
        "{xml}"
    );
    assert!(xml.contains(r#"assistive_hint="true""#), "{xml}");
    assert!(xml.contains(r#"visible="false""#), "{xml}");
    assert!(xml.contains("use up and down arrow keys"), "{xml}");
}

#[test]
fn serialize_tree_to_xml_includes_scrollable_control_attrs() {
    let node = AccessibilityNode {
        id: "inp_scrollbox".to_string(),
        role: "textbox".to_string(),
        name: Some("Scrollable note".to_string()),
        value: Some("Line 1 Line 2 Line 3".to_string()),
        rect: Rect {
            x: 2,
            y: 57,
            width: 156,
            height: 106,
        },
        children: vec![],
        is_visible: true,
        attributes: HashMap::from([
            ("dom_id".to_string(), "text-area".to_string()),
            ("tag_name".to_string(), "textarea".to_string()),
            ("scroll_top".to_string(), "120".to_string()),
            ("scroll_height".to_string(), "510".to_string()),
            ("client_height".to_string(), "104".to_string()),
            ("can_scroll_up".to_string(), "true".to_string()),
            ("can_scroll_down".to_string(), "true".to_string()),
        ]),
        som_id: None,
    };

    let xml = serialize_tree_to_xml(&node, 0);
    assert!(xml.contains(r#"scroll_top="120""#), "{xml}");
    assert!(xml.contains(r#"scroll_height="510""#), "{xml}");
    assert!(xml.contains(r#"client_height="104""#), "{xml}");
    assert!(xml.contains(r#"can_scroll_up="true""#), "{xml}");
    assert!(xml.contains(r#"can_scroll_down="true""#), "{xml}");
}

#[test]
fn serialize_tree_to_xml_includes_svg_shape_attrs() {
    let node = AccessibilityNode {
        id: "grp_2".to_string(),
        role: "generic".to_string(),
        name: Some("2".to_string()),
        value: None,
        rect: Rect {
            x: 30,
            y: 100,
            width: 20,
            height: 20,
        },
        children: vec![],
        is_visible: true,
        attributes: HashMap::from([
            ("tag_name".to_string(), "rect".to_string()),
            ("shape_kind".to_string(), "rectangle".to_string()),
            ("shape_size".to_string(), "large".to_string()),
            ("geometry_role".to_string(), "vertex".to_string()),
            ("connected_lines".to_string(), "2".to_string()),
            ("connected_points".to_string(), "71,125|91,81".to_string()),
            (
                "connected_points_precise".to_string(),
                "71.125,125.5|91.375,81.25".to_string(),
            ),
            (
                "connected_line_angles_deg".to_string(),
                "-24|23".to_string(),
            ),
            (
                "connected_line_angles_deg_precise".to_string(),
                "-24.228|23.025".to_string(),
            ),
            ("angle_mid_deg".to_string(), "0".to_string()),
            ("angle_span_deg".to_string(), "47".to_string()),
            ("data_index".to_string(), "2".to_string()),
            ("center_x_precise".to_string(), "40.25".to_string()),
            ("center_y_precise".to_string(), "110.75".to_string()),
        ]),
        som_id: None,
    };

    let xml = serialize_tree_to_xml(&node, 0);
    assert!(xml.contains(r#"tag_name="rect""#), "{xml}");
    assert!(xml.contains(r#"shape_kind="rectangle""#), "{xml}");
    assert!(xml.contains(r#"shape_size="large""#), "{xml}");
    assert!(xml.contains(r#"geometry_role="vertex""#), "{xml}");
    assert!(xml.contains(r#"connected_lines="2""#), "{xml}");
    assert!(xml.contains(r#"connected_points="71,125|91,81""#), "{xml}");
    assert!(
        xml.contains(r#"connected_points_precise="71.125,125.5|91.375,81.25""#),
        "{xml}"
    );
    assert!(
        xml.contains(r#"connected_line_angles_deg="-24|23""#),
        "{xml}"
    );
    assert!(
        xml.contains(r#"connected_line_angles_deg_precise="-24.228|23.025""#),
        "{xml}"
    );
    assert!(xml.contains(r#"angle_mid_deg="0""#), "{xml}");
    assert!(xml.contains(r#"angle_span_deg="47""#), "{xml}");
    assert!(xml.contains(r#"data_index="2""#), "{xml}");
    assert!(xml.contains(r#"center_x_precise="40.25""#), "{xml}");
    assert!(xml.contains(r#"center_y_precise="110.75""#), "{xml}");
    assert!(xml.contains(r#"center_x="40""#), "{xml}");
    assert!(xml.contains(r#"center_y="110""#), "{xml}");
}

#[test]
fn serialize_tree_to_xml_includes_svg_line_geometry_attrs() {
    let node = AccessibilityNode {
        id: "grp_line".to_string(),
        role: "generic".to_string(),
        name: Some("line from 31,108 to 71,125".to_string()),
        value: None,
        rect: Rect {
            x: 31,
            y: 108,
            width: 40,
            height: 17,
        },
        children: vec![],
        is_visible: true,
        attributes: HashMap::from([
            ("tag_name".to_string(), "line".to_string()),
            ("shape_kind".to_string(), "line".to_string()),
            ("line_x1".to_string(), "31".to_string()),
            ("line_y1".to_string(), "108".to_string()),
            ("line_x2".to_string(), "71".to_string()),
            ("line_y2".to_string(), "125".to_string()),
            ("line_length".to_string(), "43".to_string()),
            ("line_angle_deg".to_string(), "23".to_string()),
        ]),
        som_id: None,
    };

    let xml = serialize_tree_to_xml(&node, 0);
    assert!(xml.contains(r#"shape_kind="line""#), "{xml}");
    assert!(xml.contains(r#"line_x1="31""#), "{xml}");
    assert!(xml.contains(r#"line_y1="108""#), "{xml}");
    assert!(xml.contains(r#"line_x2="71""#), "{xml}");
    assert!(xml.contains(r#"line_y2="125""#), "{xml}");
    assert!(xml.contains(r#"line_length="43""#), "{xml}");
    assert!(xml.contains(r#"line_angle_deg="23""#), "{xml}");
    assert!(xml.contains(r#"center_x="51""#), "{xml}");
    assert!(xml.contains(r#"center_y="116""#), "{xml}");
}

#[test]
fn selected_child_indices_preserve_late_interactive_children_under_truncation() {
    let mut children = (0..30)
        .map(|idx| AccessibilityNode {
            id: format!("grp_{idx}"),
            role: "generic".to_string(),
            name: Some(format!("Group {idx}")),
            value: None,
            rect: Rect {
                x: 0,
                y: idx,
                width: 10,
                height: 10,
            },
            children: vec![],
            is_visible: true,
            attributes: HashMap::new(),
            som_id: None,
        })
        .collect::<Vec<_>>();
    children[29].id = "lnk_target".to_string();
    children[29].role = "link".to_string();
    children[29].name = Some("T-215".to_string());
    children[29].attributes =
        HashMap::from([("dom_id".to_string(), "ticket-link-t-215".to_string())]);

    let selected = selected_child_indices(&children, 25);
    assert_eq!(selected.len(), 25);
    assert!(selected.contains(&29), "{selected:?}");
    assert!(!selected.contains(&28), "{selected:?}");
}

#[test]
fn selected_child_indices_preserve_late_svg_targets_under_truncation() {
    let mut children = (0..30)
        .map(|idx| AccessibilityNode {
            id: format!("grp_{idx}"),
            role: "generic".to_string(),
            name: Some(format!("Group {idx}")),
            value: None,
            rect: Rect {
                x: 0,
                y: idx,
                width: 10,
                height: 10,
            },
            children: vec![],
            is_visible: true,
            attributes: HashMap::new(),
            som_id: None,
        })
        .collect::<Vec<_>>();
    children[29].id = "grp_2".to_string();
    children[29].name = Some("2".to_string());
    children[29].attributes = HashMap::from([
        ("tag_name".to_string(), "rect".to_string()),
        ("shape_kind".to_string(), "rectangle".to_string()),
        ("data_index".to_string(), "2".to_string()),
    ]);

    let selected = selected_child_indices(&children, 25);
    assert_eq!(selected.len(), 25);
    assert!(selected.contains(&29), "{selected:?}");
    assert!(!selected.contains(&28), "{selected:?}");
}

#[test]
fn selected_child_indices_preserve_late_children_with_interactive_descendants() {
    let mut children = (0..30)
        .map(|idx| AccessibilityNode {
            id: format!("grp_{idx}"),
            role: "generic".to_string(),
            name: Some(format!("Group {idx}")),
            value: None,
            rect: Rect {
                x: 0,
                y: idx,
                width: 10,
                height: 10,
            },
            children: vec![],
            is_visible: true,
            attributes: HashMap::new(),
            som_id: None,
        })
        .collect::<Vec<_>>();
    children[29].children.push(AccessibilityNode {
        id: "lnk_target".to_string(),
        role: "link".to_string(),
        name: Some("T-215".to_string()),
        value: None,
        rect: Rect {
            x: 1,
            y: 29,
            width: 8,
            height: 8,
        },
        children: vec![],
        is_visible: true,
        attributes: HashMap::from([("dom_id".to_string(), "ticket-link-t-215".to_string())]),
        som_id: None,
    });

    let selected = selected_child_indices(&children, 25);
    assert_eq!(selected.len(), 25);
    assert!(selected.contains(&29), "{selected:?}");
    assert!(!selected.contains(&28), "{selected:?}");
}

#[test]
fn serialize_tree_to_xml_surfaces_omitted_high_priority_targets() {
    let children = (0..26)
        .map(|idx| AccessibilityNode {
            id: format!("grp_{idx}"),
            role: "generic".to_string(),
            name: Some(format!("Row {idx}")),
            value: None,
            rect: Rect {
                x: 0,
                y: idx,
                width: 10,
                height: 10,
            },
            children: vec![AccessibilityNode {
                id: format!("lnk_{idx}"),
                role: "link".to_string(),
                name: Some(format!("T-{idx}")),
                value: None,
                rect: Rect {
                    x: 1,
                    y: idx,
                    width: 8,
                    height: 8,
                },
                children: vec![],
                is_visible: true,
                attributes: HashMap::from([("dom_id".to_string(), format!("ticket-link-t-{idx}"))]),
                som_id: None,
            }],
            is_visible: true,
            attributes: HashMap::new(),
            som_id: None,
        })
        .collect::<Vec<_>>();
    let root = AccessibilityNode {
        id: "root_dom_fallback_tree".to_string(),
        role: "root".to_string(),
        name: Some("DOM fallback tree".to_string()),
        value: None,
        rect: Rect {
            x: 0,
            y: 0,
            width: 800,
            height: 600,
        },
        children,
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
    };

    let xml = serialize_tree_to_xml(&root, 0);
    assert!(xml.contains(r#"id="lnk_25""#), "{xml}");
    assert!(xml.contains(r#"omitted="true""#), "{xml}");
    assert!(xml.contains(r#"dom_id="ticket-link-t-25""#), "{xml}");
}

#[test]
fn serialize_tree_to_xml_prefers_locator_bearing_omitted_targets_over_structural_noise() {
    let mut children = (0..25)
        .map(|idx| AccessibilityNode {
            id: format!("grp_{idx}"),
            role: "generic".to_string(),
            name: Some(format!("Group {idx}")),
            value: None,
            rect: Rect {
                x: 0,
                y: idx,
                width: 10,
                height: 10,
            },
            children: vec![],
            is_visible: true,
            attributes: HashMap::new(),
            som_id: None,
        })
        .collect::<Vec<_>>();
    let tickets = ["T-202", "T-204", "T-215"];
    for idx in 0..6 {
        children.push(AccessibilityNode {
            id: format!("row_noise_{idx}"),
            role: "listitem".to_string(),
            name: Some(format!("Noise row {idx}")),
            value: None,
            rect: Rect {
                x: 0,
                y: 25 + idx,
                width: 10,
                height: 10,
            },
            children: vec![],
            is_visible: true,
            attributes: HashMap::from([("tag_name".to_string(), "td".to_string())]),
            som_id: None,
        });
        if idx < 3 {
            let ticket = tickets[idx as usize].to_string();
            let suffix = ticket.to_ascii_lowercase();
            children.push(AccessibilityNode {
                id: format!("lnk_{suffix}"),
                role: "link".to_string(),
                name: Some(ticket.clone()),
                value: None,
                rect: Rect {
                    x: 1,
                    y: 40 + idx,
                    width: 8,
                    height: 8,
                },
                children: vec![],
                is_visible: true,
                attributes: HashMap::from([(
                    "dom_id".to_string(),
                    format!("ticket-link-{}", suffix),
                )]),
                som_id: None,
            });
        }
    }
    let root = AccessibilityNode {
        id: "root_dom_fallback_tree".to_string(),
        role: "root".to_string(),
        name: Some("DOM fallback tree".to_string()),
        value: None,
        rect: Rect {
            x: 0,
            y: 0,
            width: 800,
            height: 600,
        },
        children,
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
    };

    let xml = serialize_tree_to_xml(&root, 0);
    assert!(xml.contains(r#"ticket-link-t-202"#), "{xml}");
    assert!(xml.contains(r#"ticket-link-t-204"#), "{xml}");
    assert!(xml.contains(r#"ticket-link-t-215"#), "{xml}");
}

#[test]
fn serialize_tree_to_xml_adds_same_row_context_to_omitted_actionable_targets() {
    let mut children = (0..25)
        .map(|idx| AccessibilityNode {
            id: format!("btn_{idx}"),
            role: "button".to_string(),
            name: Some(format!("Action {idx}")),
            value: None,
            rect: Rect {
                x: 0,
                y: idx * 12,
                width: 10,
                height: 10,
            },
            children: vec![],
            is_visible: true,
            attributes: HashMap::from([("dom_id".to_string(), format!("action-{idx}"))]),
            som_id: None,
        })
        .collect::<Vec<_>>();
    children.push(AccessibilityNode {
        id: "lnk_t_204".to_string(),
        role: "link".to_string(),
        name: Some("T-204".to_string()),
        value: None,
        rect: Rect {
            x: 20,
            y: 420,
            width: 40,
            height: 18,
        },
        children: vec![],
        is_visible: true,
        attributes: HashMap::from([("dom_id".to_string(), "ticket-link-t-204".to_string())]),
        som_id: None,
    });
    children.push(AccessibilityNode {
        id: "cell_assignee".to_string(),
        role: "generic".to_string(),
        name: Some("Unassigned".to_string()),
        value: None,
        rect: Rect {
            x: 180,
            y: 418,
            width: 90,
            height: 22,
        },
        children: vec![],
        is_visible: true,
        attributes: HashMap::from([("tag_name".to_string(), "td".to_string())]),
        som_id: None,
    });
    children.push(AccessibilityNode {
        id: "cell_status".to_string(),
        role: "generic".to_string(),
        name: Some("Awaiting Dispatch".to_string()),
        value: None,
        rect: Rect {
            x: 300,
            y: 418,
            width: 120,
            height: 22,
        },
        children: vec![],
        is_visible: true,
        attributes: HashMap::from([("tag_name".to_string(), "td".to_string())]),
        som_id: None,
    });
    let root = AccessibilityNode {
        id: "root_dom_fallback_tree".to_string(),
        role: "root".to_string(),
        name: Some("DOM fallback tree".to_string()),
        value: None,
        rect: Rect {
            x: 0,
            y: 0,
            width: 800,
            height: 600,
        },
        children,
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
    };

    let xml = serialize_tree_to_xml(&root, 0);
    assert!(xml.contains(r#"id="lnk_t_204""#), "{xml}");
    assert!(xml.contains(r#"omitted="true""#), "{xml}");
    assert!(
        xml.contains(r#"context="Unassigned / Awaiting Dispatch""#),
        "{xml}"
    );
}

#[test]
fn serialize_tree_to_xml_prefers_compact_metric_context_for_omitted_actionable_targets() {
    let mut children = (0..25)
        .map(|idx| AccessibilityNode {
            id: format!("btn_{idx}"),
            role: "button".to_string(),
            name: Some(format!("Action {idx}")),
            value: None,
            rect: Rect {
                x: 0,
                y: idx * 14,
                width: 80,
                height: 12,
            },
            children: vec![],
            is_visible: true,
            attributes: HashMap::from([("dom_id".to_string(), format!("action-{idx}"))]),
            som_id: None,
        })
        .collect::<Vec<_>>();
    children.push(AccessibilityNode {
        id: "grp_flight_row".to_string(),
        role: "generic".to_string(),
        name: Some(
            "Depart: 1:13 AM Fri Oct 07 2016 Kiana, AK (IAN) Arrives: 5:09 AM Fri Oct 07 2016 Augusta, GA Duration: 3h 56m Book flight for $944"
                .to_string(),
        ),
        value: None,
        rect: Rect {
            x: 3,
            y: 473,
            width: 144,
            height: 125,
        },
        children: vec![],
        is_visible: true,
        attributes: HashMap::from([("tag_name".to_string(), "div".to_string())]),
        som_id: None,
    });
    children.push(AccessibilityNode {
        id: "grp_duration_row".to_string(),
        role: "generic".to_string(),
        name: Some("Duration: 3h 56m".to_string()),
        value: None,
        rect: Rect {
            x: 5,
            y: 545,
            width: 140,
            height: 13,
        },
        children: vec![],
        is_visible: true,
        attributes: HashMap::from([("tag_name".to_string(), "div".to_string())]),
        som_id: None,
    });
    children.push(AccessibilityNode {
        id: "grp_duration_value".to_string(),
        role: "generic".to_string(),
        name: Some("3h 56m".to_string()),
        value: None,
        rect: Rect {
            x: 48,
            y: 546,
            width: 97,
            height: 11,
        },
        children: vec![],
        is_visible: true,
        attributes: HashMap::from([("tag_name".to_string(), "div".to_string())]),
        som_id: None,
    });
    children.push(AccessibilityNode {
        id: "btn_book_flight_for_944".to_string(),
        role: "button".to_string(),
        name: Some("Book flight for $944".to_string()),
        value: None,
        rect: Rect {
            x: 12,
            y: 560,
            width: 126,
            height: 34,
        },
        children: vec![],
        is_visible: true,
        attributes: HashMap::from([
            ("dom_id".to_string(), "book-flight-944".to_string()),
            ("class_name".to_string(), "flight-price".to_string()),
        ]),
        som_id: None,
    });
    let root = AccessibilityNode {
        id: "root_dom_fallback_tree".to_string(),
        role: "root".to_string(),
        name: Some("DOM fallback tree".to_string()),
        value: None,
        rect: Rect {
            x: 0,
            y: 0,
            width: 800,
            height: 600,
        },
        children,
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
    };

    let xml = serialize_tree_to_xml(&root, 0);
    assert!(xml.contains(r#"id="btn_book_flight_for_944""#), "{xml}");
    assert!(
        xml.contains(r#"context="3h 56m / Duration: 3h 56m""#),
        "{xml}"
    );
    assert!(!xml.contains(r#"context="Depart: 1:13 AM"#), "{xml}");
}

#[test]
fn serialize_tree_to_xml_keeps_omitted_calendar_days_available() {
    let mut calendar_children = (0..25)
        .map(|idx| AccessibilityNode {
            id: format!("grp_header_{idx}"),
            role: "generic".to_string(),
            name: Some(format!("Header {idx}")),
            value: None,
            rect: Rect {
                x: 0,
                y: idx,
                width: 10,
                height: 10,
            },
            children: vec![],
            is_visible: true,
            attributes: HashMap::new(),
            som_id: None,
        })
        .collect::<Vec<_>>();
    calendar_children.extend((1..=31).map(|day| AccessibilityNode {
        id: format!("lnk_{day}"),
        role: "link".to_string(),
        name: Some(day.to_string()),
        value: None,
        rect: Rect {
            x: day as i32,
            y: 60 + day as i32,
            width: 10,
            height: 10,
        },
        children: vec![],
        is_visible: true,
        attributes: HashMap::from([("class_name".to_string(), "ui-state-default".to_string())]),
        som_id: None,
    }));
    let root = AccessibilityNode {
        id: "root_dom_fallback_tree".to_string(),
        role: "root".to_string(),
        name: Some("DOM fallback tree".to_string()),
        value: None,
        rect: Rect {
            x: 0,
            y: 0,
            width: 800,
            height: 600,
        },
        children: vec![AccessibilityNode {
            id: "grp_calendar".to_string(),
            role: "generic".to_string(),
            name: Some("Calendar".to_string()),
            value: None,
            rect: Rect {
                x: 0,
                y: 0,
                width: 200,
                height: 200,
            },
            children: calendar_children,
            is_visible: true,
            attributes: HashMap::from([(
                "class_name".to_string(),
                "ui-datepicker-calendar".to_string(),
            )]),
            som_id: None,
        }],
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
    };

    let xml = serialize_tree_to_xml(&root, 0);
    assert!(xml.contains(r#"id="lnk_20""#), "{xml}");
    assert!(xml.contains(r#"id="lnk_31""#), "{xml}");
    assert!(xml.contains(r#"omitted="true""#), "{xml}");
}
