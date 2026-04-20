use super::*;
use std::collections::HashMap;

fn node(
    id: &str,
    role: &str,
    rect: Rect,
    children: Vec<AccessibilityNode>,
    name: Option<&str>,
) -> AccessibilityNode {
    AccessibilityNode {
        id: id.to_string(),
        role: role.to_string(),
        name: name.map(|v| v.to_string()),
        value: None,
        rect,
        children,
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
    }
}

#[test]
fn find_best_element_for_point_skips_non_interactive_containers() {
    let child_outside = node(
        "child_outside",
        "label",
        Rect {
            x: 420,
            y: 420,
            width: 40,
            height: 30,
        },
        vec![],
        Some("outside"),
    );
    let pane = node(
        "pane_1",
        "pane",
        Rect {
            x: 0,
            y: 0,
            width: 500,
            height: 500,
        },
        vec![child_outside],
        Some("container"),
    );
    let root = node(
        "window_1",
        "window",
        Rect {
            x: 0,
            y: 0,
            width: 500,
            height: 500,
        },
        vec![pane],
        Some("Calculator"),
    );

    let result = find_best_element_for_point(&root, 100, 100);
    assert_eq!(result, None);
}

#[test]
fn find_best_element_for_point_returns_interactive_target() {
    let button = node(
        "btn_7",
        "button",
        Rect {
            x: 90,
            y: 80,
            width: 50,
            height: 50,
        },
        vec![],
        Some("7"),
    );
    let pane = node(
        "pane_1",
        "pane",
        Rect {
            x: 0,
            y: 0,
            width: 500,
            height: 500,
        },
        vec![button],
        Some("container"),
    );
    let root = node(
        "window_1",
        "window",
        Rect {
            x: 0,
            y: 0,
            width: 500,
            height: 500,
        },
        vec![pane],
        Some("Calculator"),
    );

    let result = find_best_element_for_point(&root, 100, 100);
    assert_eq!(result.as_deref(), Some("btn_7"));
}

#[test]
fn find_semantic_ui_match_uses_aria_label_when_name_missing() {
    let mut button = node(
        "button_17",
        "button",
        Rect {
            x: 120,
            y: 80,
            width: 100,
            height: 36,
        },
        vec![],
        None,
    );
    button
        .attributes
        .insert("aria-label".to_string(), "Save Draft".to_string());
    button
        .attributes
        .insert("data-testid".to_string(), "editor-save-button".to_string());

    let root = node(
        "window_editor",
        "window",
        Rect {
            x: 0,
            y: 0,
            width: 800,
            height: 600,
        },
        vec![button],
        Some("Editor"),
    );

    let found = find_semantic_ui_match(&root, "save draft")
        .expect("aria-label backed element should be matched");

    assert_eq!(found.id.as_deref(), Some("button_17"));
    assert_eq!(found.label.as_deref(), Some("Save Draft"));
    assert_eq!(found.source, "semantic_tree");
    assert!(
        found.confidence >= 0.8,
        "expected strong semantic confidence, got {}",
        found.confidence
    );
}

#[test]
fn find_semantic_ui_match_recovers_visual_clause_query_from_semantic_hints() {
    let mut button = node(
        "button_17",
        "button",
        Rect {
            x: 120,
            y: 80,
            width: 100,
            height: 36,
        },
        vec![],
        None,
    );
    button
        .attributes
        .insert("aria-label".to_string(), "Save Draft".to_string());
    button
        .attributes
        .insert("data-testid".to_string(), "editor-save-button".to_string());

    let root = node(
        "window_editor",
        "window",
        Rect {
            x: 0,
            y: 0,
            width: 800,
            height: 600,
        },
        vec![button],
        Some("Editor"),
    );

    let found = find_semantic_ui_match(&root, "save draft icon")
        .expect("semantic match should ignore extra visual clause when hints match");

    assert_eq!(found.id.as_deref(), Some("button_17"));
    assert_eq!(found.label.as_deref(), Some("Save Draft"));
    assert_eq!(found.source, "semantic_tree");
    assert!(
        found.confidence >= 0.40,
        "expected semantic confidence above fallback threshold, got {}",
        found.confidence
    );
}
