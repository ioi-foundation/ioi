use super::semantics::{find_center_of_element, resolve_semantic_som_id};
use super::tree::fetch_lensed_tree;
use super::ToolExecutor;
use ioi_api::vm::drivers::gui::{AtomicInput, MouseButton};
use std::collections::BTreeMap;

fn center_from_rect(x: i32, y: i32, w: i32, h: i32) -> [u32; 2] {
    let cx = x + (w / 2);
    let cy = y + (h / 2);
    [cx.max(0) as u32, cy.max(0) as u32]
}

pub(super) fn build_drag_drop_sequence(from: [u32; 2], to: [u32; 2]) -> Vec<AtomicInput> {
    vec![
        AtomicInput::MouseMove {
            x: from[0],
            y: from[1],
        },
        AtomicInput::MouseDown {
            button: MouseButton::Left,
        },
        AtomicInput::Wait { millis: 200 },
        AtomicInput::MouseMove { x: to[0], y: to[1] },
        AtomicInput::Wait { millis: 200 },
        AtomicInput::MouseUp {
            button: MouseButton::Left,
        },
    ]
}

pub(super) fn build_cursor_double_click_sequence() -> Vec<AtomicInput> {
    vec![
        AtomicInput::MouseDown {
            button: MouseButton::Left,
        },
        AtomicInput::Wait { millis: 50 },
        AtomicInput::MouseUp {
            button: MouseButton::Left,
        },
        AtomicInput::Wait { millis: 80 },
        AtomicInput::MouseDown {
            button: MouseButton::Left,
        },
        AtomicInput::Wait { millis: 50 },
        AtomicInput::MouseUp {
            button: MouseButton::Left,
        },
    ]
}

async fn resolve_som_target_point(
    exec: &ToolExecutor,
    som_id: u32,
    som_map: Option<&BTreeMap<u32, (i32, i32, i32, i32)>>,
) -> Option<[u32; 2]> {
    if let Some(map) = som_map {
        if let Some((x, y, w, h)) = map.get(&som_id) {
            return Some(center_from_rect(*x, *y, *w, *h));
        }
    }

    match exec.gui.get_element_center(som_id).await {
        Ok(Some((x, y))) => Some([x, y]),
        Ok(None) | Err(_) => None,
    }
}

pub(super) async fn resolve_target_point(
    exec: &ToolExecutor,
    id: &str,
    som_map: Option<&BTreeMap<u32, (i32, i32, i32, i32)>>,
    semantic_map: Option<&BTreeMap<u32, String>>,
    active_lens: Option<&str>,
) -> Option<[u32; 2]> {
    if let Ok(som_id) = id.trim().parse::<u32>() {
        if let Some(point) = resolve_som_target_point(exec, som_id, som_map).await {
            return Some(point);
        }
    }

    if let Some(smap) = semantic_map {
        if let Some(som_id) = resolve_semantic_som_id(smap, id) {
            if let Some(point) = resolve_som_target_point(exec, som_id, som_map).await {
                return Some(point);
            }
        }
    }

    if let Ok(tree) = fetch_lensed_tree(exec, active_lens).await {
        if let Some((x, y)) = find_center_of_element(&tree, id) {
            return Some([x.max(0) as u32, y.max(0) as u32]);
        }
    }

    None
}
