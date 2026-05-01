use super::{
    merge_missing_dom_fallback_nodes, node_contains_visible_start_gate,
    prune_redundant_dom_fallback_aggregates, should_cache_prompt_observation_warmup, BrowserDriver,
    DomFallbackNode, DomFallbackRect,
};
use crate::gui::accessibility::{AccessibilityNode, Rect as AccessibilityRect};
use std::collections::HashMap;

#[test]
fn rect_from_dom_quad_builds_bounds() {
    let quad = [10.2, 20.8, 50.0, 20.1, 49.6, 60.4, 10.1, 60.9];
    let (rect, area) = BrowserDriver::rect_from_dom_quad(&quad).expect("quad should resolve");
    assert_eq!(rect.x, 10);
    assert_eq!(rect.y, 20);
    assert_eq!(rect.width, 40);
    assert_eq!(rect.height, 41);
    assert!(area > 1500.0);
}

#[test]
fn rect_from_dom_quad_rejects_degenerate_geometry() {
    let tiny = [10.0, 10.0, 10.5, 10.0, 10.5, 10.4, 10.0, 10.4];
    assert!(BrowserDriver::rect_from_dom_quad(&tiny).is_none());
}

#[test]
fn rect_from_dom_quad_rejects_non_finite_values() {
    let bad = [10.0, 10.0, f64::NAN, 10.0, 50.0, 50.0, 10.0, 50.0];
    assert!(BrowserDriver::rect_from_dom_quad(&bad).is_none());
}

#[test]
fn dom_fallback_is_allowed_for_not_rendered_ax_errors() {
    assert!(super::allow_dom_fallback_for_ax_error(
        "CDP GetAxTree failed: notRendered"
    ));
    assert!(super::allow_dom_fallback_for_ax_error(
        "AX snapshot failed because the page is not rendered"
    ));
}

#[test]
fn dom_fallback_is_allowed_for_label_for_ax_errors() {
    assert!(super::allow_dom_fallback_for_ax_error(
        "CDP GetAxTree failed: labelFor"
    ));
}

fn dom_node(
    id: &str,
    role: &str,
    name: Option<&str>,
    rect: (f64, f64, f64, f64),
    attrs: &[(&str, &str)],
) -> DomFallbackNode {
    DomFallbackNode {
        id: id.to_string(),
        role: role.to_string(),
        name: name.map(str::to_string),
        value: None,
        rect: DomFallbackRect {
            x: rect.0,
            y: rect.1,
            width: rect.2,
            height: rect.3,
        },
        is_visible: Some(true),
        attributes: attrs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect::<HashMap<_, _>>(),
        children: Vec::new(),
    }
}

fn ax_node(
    id: &str,
    role: &str,
    name: Option<&str>,
    rect: (i32, i32, i32, i32),
    attrs: &[(&str, &str)],
) -> AccessibilityNode {
    AccessibilityNode {
        id: id.to_string(),
        role: role.to_string(),
        name: name.map(str::to_string),
        value: None,
        rect: AccessibilityRect {
            x: rect.0,
            y: rect.1,
            width: rect.2,
            height: rect.3,
        },
        children: Vec::new(),
        is_visible: true,
        attributes: attrs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect::<HashMap<_, _>>(),
        som_id: None,
    }
}

#[test]
fn dom_fallback_icon_control_synthesizes_name_from_class_hint() {
    let node = dom_node(
        "dom-node-1",
        "generic",
        None,
        (120.0, 57.0, 12.0, 12.0),
        &[
            ("dom_fallback", "true"),
            ("tag_name", "span"),
            ("class_name", "trash"),
            ("dom_clickable", "true"),
        ],
    )
    .into_accessibility();

    assert_eq!(node.name.as_deref(), Some("trash"));
    assert!(node.is_interactive());
}

#[test]
fn dom_fallback_icon_control_synthesizes_name_from_dom_id_hint() {
    let node = dom_node(
        "dom-node-2",
        "generic",
        None,
        (2.0, 56.0, 12.0, 12.0),
        &[
            ("dom_fallback", "true"),
            ("tag_name", "span"),
            ("dom_id", "close-email"),
            ("dom_clickable", "true"),
        ],
    )
    .into_accessibility();

    assert_eq!(node.name.as_deref(), Some("close email"));
    assert!(node.is_interactive());
}

#[test]
fn dom_fallback_semantic_hint_ignores_structural_class_tokens() {
    let node = dom_node(
        "dom-node-3",
        "generic",
        None,
        (2.0, 56.0, 12.0, 12.0),
        &[
            ("dom_fallback", "true"),
            ("tag_name", "span"),
            ("class_name", "controls spacer details"),
        ],
    )
    .into_accessibility();

    assert_eq!(node.name.as_deref(), None);
    assert!(!node.is_interactive());
}

#[test]
fn visible_start_gate_is_detected_from_sync_cover_node() {
    let mut root = ax_node(
        "root",
        "root",
        Some("DOM fallback tree"),
        (0, 0, 800, 600),
        &[("snapshot_fallback_cause", "navigate_warmup")],
    );
    root.children.push(ax_node(
        "grp_start",
        "generic",
        Some("START"),
        (0, 0, 160, 210),
        &[("dom_id", "sync-task-cover")],
    ));

    assert!(node_contains_visible_start_gate(&root));
    assert!(!should_cache_prompt_observation_warmup(&root));
}

#[test]
fn warmup_cache_is_skipped_when_start_gate_coexists_with_grounded_target() {
    let mut root = ax_node(
        "root",
        "root",
        Some("DOM fallback tree"),
        (0, 0, 800, 600),
        &[("snapshot_fallback_cause", "navigate_warmup")],
    );
    root.children.push(ax_node(
        "grp_start",
        "generic",
        Some("START"),
        (0, 0, 160, 210),
        &[("dom_id", "sync-task-cover")],
    ));
    root.children.push(ax_node(
        "grp_circ",
        "generic",
        Some("large circle"),
        (62, 119, 44, 44),
        &[
            ("dom_id", "circ"),
            ("selector", "[id=\"circ\"]"),
            ("shape_kind", "circle"),
        ],
    ));

    assert!(node_contains_visible_start_gate(&root));
    assert!(!should_cache_prompt_observation_warmup(&root));
}

#[test]
fn warmup_cache_is_kept_for_started_task_surface() {
    let mut root = ax_node(
        "root",
        "root",
        Some("DOM fallback tree"),
        (0, 0, 800, 600),
        &[("snapshot_fallback_cause", "navigate_warmup")],
    );
    root.children.push(ax_node(
        "grp_circ",
        "generic",
        Some("large circle"),
        (62, 119, 44, 44),
        &[
            ("dom_id", "circ"),
            ("selector", "[id=\"circ\"]"),
            ("shape_kind", "circle"),
        ],
    ));

    assert!(!node_contains_visible_start_gate(&root));
    assert!(should_cache_prompt_observation_warmup(&root));
}

#[test]
fn dom_fallback_script_declares_selector_helper_before_use() {
    let source = include_str!("capture.rs");
    let helper_idx = source
        .find("const selectorFor = (el) =>")
        .expect("DOM fallback script should declare selectorFor");
    let use_idx = source
        .find("const selector = selectorFor(el);")
        .expect("DOM fallback script should use selectorFor for selector attrs");

    assert!(helper_idx < use_idx);
}

#[test]
fn dom_fallback_script_surfaces_svg_geometry_roles_and_line_metrics() {
    let source = include_str!("capture.rs")
        .split("\n#[cfg(test)]")
        .next()
        .expect("pre-test source");

    assert!(
        source.contains("attrs.geometry_role = metadata.geometryRole;"),
        "{source}"
    );
    assert!(
        source.contains("attrs.connected_lines = String(metadata.connectedLines);"),
        "{source}"
    );
    assert!(
        source.contains("attrs.connected_points = connectedPoints;"),
        "{source}"
    );
    assert!(
        source.contains("attrs.connected_points_precise = connectedPointsPrecise;"),
        "{source}"
    );
    assert!(
        source.contains("attrs.connected_line_angles_deg = connectedLineAngles;"),
        "{source}"
    );
    assert!(
        source.contains("attrs.connected_line_angles_deg_precise = connectedLineAnglesPrecise;"),
        "{source}"
    );
    assert!(
        source.contains("attrs.angle_mid_deg = roundedSvgCoord(metadata.angleMidDeg);"),
        "{source}"
    );
    assert!(
        source.contains("attrs.angle_span_deg = roundedSvgCoord(metadata.angleSpanDeg);"),
        "{source}"
    );
    assert!(
        !source.contains("attrs.target_angle_mid_deg = roundedSvgCoord("),
        "{source}"
    );
    assert!(
        !source.contains("attrs.angle_mid_offset_deg = roundedSvgCoord("),
        "{source}"
    );
    assert!(
        !source.contains("attrs.angle_mid_delta_deg = roundedSvgCoord("),
        "{source}"
    );
    assert!(
        !source.contains("attrs.midpoint_probe_x = roundedSvgCoord("),
        "{source}"
    );
    assert!(
        !source.contains("attrs.midpoint_probe_y = roundedSvgCoord("),
        "{source}"
    );
    assert!(
        !source.contains("attrs.midpoint_probe_distance = roundedSvgCoord("),
        "{source}"
    );
    assert!(
        !source.contains("const maybePushDerivedSvgProbeTarget = ("),
        "{source}"
    );
    assert!(
        !source.contains("derived_target_kind: \"midpoint_probe\""),
        "{source}"
    );
    assert!(
        !source.contains("geometry_role: \"midpoint_probe\""),
        "{source}"
    );
    assert!(!source.contains("svgTouchesPoint("), "{source}");
    assert!(!source.contains("const svgPointFromAngle = ("), "{source}");
    assert!(
        source.contains("attrs.line_length = roundedSvgCoord(metadata.geometry.length);"),
        "{source}"
    );
    assert!(
        source.contains("attrs.line_angle_deg = roundedSvgCoord(metadata.geometry.angleDeg);"),
        "{source}"
    );
    assert!(
        source
            .contains("attrs.center_x_precise = highPrecisionSvgCoord(metadata.geometry.centerX);"),
        "{source}"
    );
    assert!(
        source
            .contains("attrs.center_y_precise = highPrecisionSvgCoord(metadata.geometry.centerY);"),
        "{source}"
    );
}

#[test]
fn prune_redundant_dom_fallback_aggregates_drops_flat_container_noise() {
    let root = DomFallbackNode {
        id: "dom-root".to_string(),
        role: "root".to_string(),
        name: Some("DOM fallback tree".to_string()),
        value: None,
        rect: DomFallbackRect {
            x: 0.0,
            y: 0.0,
            width: 800.0,
            height: 600.0,
        },
        is_visible: Some(true),
        attributes: HashMap::from([("snapshot_fallback".to_string(), "dom".to_string())]),
        children: vec![
            dom_node(
                "grp_wrap",
                "generic",
                Some("Select TeCSlMn and click Submit. TeCSlMn Submit"),
                (0.0, 0.0, 160.0, 210.0),
                &[("dom_fallback", "true"), ("tag_name", "div")],
            ),
            dom_node(
                "grp_query",
                "generic",
                Some("Select TeCSlMn and click Submit."),
                (0.0, 0.0, 160.0, 50.0),
                &[("dom_fallback", "true"), ("tag_name", "div")],
            ),
            dom_node(
                "grp_area",
                "generic",
                Some("TeCSlMn Submit"),
                (0.0, 50.0, 160.0, 136.0),
                &[("dom_fallback", "true"), ("tag_name", "div")],
            ),
            dom_node(
                "radio_tecslmn",
                "radio",
                Some("TeCSlMn"),
                (7.0, 55.0, 20.0, 13.0),
                &[("dom_fallback", "true"), ("tag_name", "input")],
            ),
            dom_node(
                "btn_submit",
                "button",
                Some("Submit"),
                (2.0, 153.0, 95.0, 31.0),
                &[("dom_fallback", "true"), ("tag_name", "button")],
            ),
        ],
    }
    .into_accessibility();

    let pruned = prune_redundant_dom_fallback_aggregates(root);
    let child_ids = pruned
        .children
        .iter()
        .map(|child| child.id.as_str())
        .collect::<Vec<_>>();

    assert!(!child_ids.contains(&"grp_wrap"));
    assert!(!child_ids.contains(&"grp_area"));
    assert!(child_ids.contains(&"grp_query"));
    assert!(child_ids.contains(&"radio_tecslmn"));
    assert!(child_ids.contains(&"btn_submit"));
    assert_eq!(
        pruned
            .attributes
            .get("dom_fallback_pruned_aggregate_count")
            .map(String::as_str),
        Some("2")
    );
}

#[test]
fn prune_redundant_dom_fallback_aggregates_keeps_scrollable_container_state() {
    let root = DomFallbackNode {
        id: "dom-root".to_string(),
        role: "root".to_string(),
        name: Some("DOM fallback tree".to_string()),
        value: None,
        rect: DomFallbackRect {
            x: 0.0,
            y: 0.0,
            width: 800.0,
            height: 600.0,
        },
        is_visible: Some(true),
        attributes: HashMap::from([("snapshot_fallback".to_string(), "dom".to_string())]),
        children: vec![
            dom_node(
                "grp_scroll_region",
                "generic",
                Some("Messages Submit"),
                (0.0, 0.0, 160.0, 210.0),
                &[
                    ("dom_fallback", "true"),
                    ("tag_name", "div"),
                    ("scroll_top", "12"),
                ],
            ),
            dom_node(
                "btn_submit",
                "button",
                Some("Submit"),
                (2.0, 153.0, 95.0, 31.0),
                &[("dom_fallback", "true"), ("tag_name", "button")],
            ),
        ],
    }
    .into_accessibility();

    let pruned = prune_redundant_dom_fallback_aggregates(root);
    let child_ids = pruned
        .children
        .iter()
        .map(|child| child.id.as_str())
        .collect::<Vec<_>>();

    assert!(child_ids.contains(&"grp_scroll_region"));
    assert!(pruned
        .attributes
        .get("dom_fallback_pruned_aggregate_count")
        .is_none());
}

#[test]
fn prune_redundant_dom_fallback_aggregates_drops_table_cell_wrapper_for_link_child() {
    let root = DomFallbackNode {
        id: "dom-root".to_string(),
        role: "root".to_string(),
        name: Some("DOM fallback tree".to_string()),
        value: None,
        rect: DomFallbackRect {
            x: 0.0,
            y: 0.0,
            width: 800.0,
            height: 600.0,
        },
        is_visible: Some(true),
        attributes: HashMap::from([("snapshot_fallback".to_string(), "dom".to_string())]),
        children: vec![
            dom_node(
                "grp_t_215",
                "generic",
                Some("T-215"),
                (66.0, 850.0, 73.0, 91.0),
                &[("dom_fallback", "true"), ("tag_name", "td")],
            ),
            dom_node(
                "lnk_t_215",
                "link",
                Some("T-215"),
                (78.0, 884.0, 41.0, 22.0),
                &[
                    ("dom_fallback", "true"),
                    ("tag_name", "a"),
                    ("dom_id", "ticket-link-t-215"),
                ],
            ),
        ],
    }
    .into_accessibility();

    let pruned = prune_redundant_dom_fallback_aggregates(root);
    let child_ids = pruned
        .children
        .iter()
        .map(|child| child.id.as_str())
        .collect::<Vec<_>>();

    assert!(!child_ids.contains(&"grp_t_215"));
    assert!(child_ids.contains(&"lnk_t_215"));
    assert_eq!(
        pruned
            .attributes
            .get("dom_fallback_pruned_aggregate_count")
            .map(String::as_str),
        Some("1")
    );
}

#[test]
fn merge_missing_dom_fallback_nodes_adds_clickable_overlay_without_duplicate_submit() {
    let ax_tree = AccessibilityNode {
        id: "root".to_string(),
        role: "root".to_string(),
        name: Some("AX tree".to_string()),
        value: None,
        rect: AccessibilityRect {
            x: 0,
            y: 0,
            width: 160,
            height: 210,
        },
        children: vec![
            ax_node(
                "btn_submit",
                "button",
                Some("Submit"),
                (30, 178, 95, 31),
                &[("dom_id", "subbtn"), ("selector", "#subbtn")],
            ),
            ax_node(
                "grp_svg_grid",
                "generic",
                Some("svg grid object"),
                (2, 52, 150, 130),
                &[("dom_id", "svg-grid"), ("selector", "#svg-grid")],
            ),
        ],
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
    };

    let dom_tree = DomFallbackNode {
        id: "dom-root".to_string(),
        role: "root".to_string(),
        name: Some("DOM fallback tree".to_string()),
        value: None,
        rect: DomFallbackRect {
            x: 0.0,
            y: 0.0,
            width: 160.0,
            height: 210.0,
        },
        is_visible: Some(true),
        attributes: HashMap::from([("snapshot_fallback".to_string(), "dom".to_string())]),
        children: vec![
            dom_node(
                "dom-id-subbtn",
                "button",
                Some("Submit"),
                (30.0, 178.0, 95.0, 31.0),
                &[
                    ("dom_fallback", "true"),
                    ("tag_name", "button"),
                    ("dom_id", "subbtn"),
                    ("selector", "#subbtn"),
                    ("dom_clickable", "true"),
                ],
            ),
            dom_node(
                "dom-id-sync-task-cover",
                "generic",
                Some("START"),
                (0.0, 0.0, 160.0, 210.0),
                &[
                    ("dom_fallback", "true"),
                    ("tag_name", "div"),
                    ("dom_id", "sync-task-cover"),
                    ("selector", "#sync-task-cover"),
                    ("dom_clickable", "true"),
                ],
            ),
        ],
    }
    .into_accessibility();

    let merged = merge_missing_dom_fallback_nodes(ax_tree, dom_tree);
    let child_ids = merged
        .children
        .iter()
        .map(|child| child.id.as_str())
        .collect::<Vec<_>>();

    assert!(child_ids.contains(&"dom-id-sync-task-cover"));
    assert_eq!(
        child_ids
            .iter()
            .filter(|child_id| **child_id == "btn_submit")
            .count(),
        1
    );
    assert_eq!(
        merged
            .attributes
            .get("dom_fallback_overlay_count")
            .map(String::as_str),
        Some("1")
    );
}
