use super::*;
use crate::gui::geometry::{CoordinateSpace, Point};

fn test_transform(w: u32, h: u32) -> DisplayTransform {
    DisplayTransform::new(
        1.0,
        Point::new(0.0, 0.0, CoordinateSpace::ScreenLogical),
        Point::new(0.0, 0.0, CoordinateSpace::ImagePhysical),
        w,
        h,
    )
}

fn make_leaf(rect: Rect, role: &str) -> AccessibilityNode {
    AccessibilityNode {
        id: "blind_leaf".to_string(),
        role: role.to_string(),
        name: None,
        value: None,
        rect,
        children: vec![],
        is_visible: true,
        attributes: HashMap::new(),
        som_id: None,
    }
}

#[test]
fn dynamic_grid_injected_for_large_empty_leaf() {
    let mut root = make_leaf(
        Rect {
            x: 0,
            y: 0,
            width: 1000,
            height: 800,
        },
        "web_area",
    );
    let transform = test_transform(1000, 800);
    let mut counter = 1;
    let mut map = HashMap::new();

    assign_som_ids(&mut root, &transform, &mut counter, &mut map);

    assert_eq!(
        root.attributes.get("som.synthetic"),
        Some(&"grid_parent".to_string())
    );
    assert_eq!(root.children.len(), 16);
    assert_eq!(map.len(), 16);
    assert!(root.children.iter().all(|child| child.som_id.is_some()));
}

#[test]
fn dynamic_grid_not_injected_when_node_has_content() {
    let mut root = make_leaf(
        Rect {
            x: 0,
            y: 0,
            width: 900,
            height: 700,
        },
        "web_area",
    );
    root.name = Some("Page Content".to_string());

    let transform = test_transform(900, 700);
    let mut counter = 1;
    let mut map = HashMap::new();
    assign_som_ids(&mut root, &transform, &mut counter, &mut map);

    assert!(root.children.is_empty());
    assert!(map.is_empty());
}

#[test]
fn dynamic_grid_not_injected_for_small_leaf() {
    let mut root = make_leaf(
        Rect {
            x: 0,
            y: 0,
            width: 220,
            height: 140,
        },
        "canvas",
    );
    let transform = test_transform(1000, 800);
    let mut counter = 1;
    let mut map = HashMap::new();
    assign_som_ids(&mut root, &transform, &mut counter, &mut map);

    assert!(root.children.is_empty());
    assert!(map.is_empty());
}
