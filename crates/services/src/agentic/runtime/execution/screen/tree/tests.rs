use super::*;
use std::collections::HashMap;

fn node(
    id: &str,
    role: &str,
    name: Option<&str>,
    rect: Rect,
    children: Vec<AccessibilityNode>,
) -> AccessibilityNode {
    AccessibilityNode {
        id: id.to_string(),
        role: role.to_string(),
        name: name.map(|s| s.to_string()),
        value: None,
        rect,
        children,
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
    }
}

#[test]
fn choose_active_window_subtree_prefers_title_and_overlap() {
    let active = WindowInfo {
        title: "Target Window".to_string(),
        x: 100,
        y: 200,
        width: 800,
        height: 600,
        app_name: "TargetApp".to_string(),
    };

    let good = node(
        "win-good",
        "window",
        Some("Target Window - TargetApp"),
        Rect {
            x: 100,
            y: 200,
            width: 800,
            height: 600,
        },
        vec![],
    );
    let bad = node(
        "win-bad",
        "window",
        Some("Other Window - OtherApp"),
        Rect {
            x: 0,
            y: 0,
            width: 640,
            height: 480,
        },
        vec![],
    );

    let root = node(
        "root",
        "root",
        None,
        Rect {
            x: 0,
            y: 0,
            width: 1920,
            height: 1080,
        },
        vec![bad, good.clone()],
    );

    let scoped = choose_active_window_subtree(&root, &active).expect("expected a match");
    assert_eq!(scoped.id, good.id);
}

#[test]
fn choose_active_window_subtree_returns_none_when_no_match() {
    let active = WindowInfo {
        title: "Target Window".to_string(),
        x: 100,
        y: 200,
        width: 800,
        height: 600,
        app_name: "TargetApp".to_string(),
    };

    let child = node(
        "panel-1",
        "pane",
        Some("Unrelated"),
        Rect {
            x: 0,
            y: 0,
            width: 10,
            height: 10,
        },
        vec![],
    );
    let root = node(
        "root",
        "root",
        None,
        Rect {
            x: 0,
            y: 0,
            width: 1920,
            height: 1080,
        },
        vec![child],
    );

    assert!(choose_active_window_subtree(&root, &active).is_none());
}
