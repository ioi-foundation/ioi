use super::super::browser::is_probable_browser_window;
use super::targeting::resolve_target_point;
use super::{ToolExecutionResult, ToolExecutor};
use std::collections::BTreeMap;

const PHASE0_BROWSER_GUI_CLICK_ERROR_CODE: &str = "BrowserGuiClickDisallowedPhase0";

fn active_browser_window_rect(exec: &ToolExecutor) -> Option<(i32, i32, i32, i32)> {
    let window = exec.active_window.as_ref()?;
    if !is_probable_browser_window(&window.title, &window.app_name) {
        return None;
    }
    if window.width <= 0 || window.height <= 0 {
        return None;
    }
    Some((window.x, window.y, window.width, window.height))
}

fn rect_contains_point(rect: (i32, i32, i32, i32), x: i32, y: i32) -> bool {
    let (rx, ry, width, height) = rect;
    if width <= 0 || height <= 0 {
        return false;
    }

    let x2 = rx + width;
    let y2 = ry + height;
    x >= rx && x <= x2 && y >= ry && y <= y2
}

fn phase0_browser_gui_click_denied(action: &str, detail: &str) -> ToolExecutionResult {
    ToolExecutionResult::failure(format!(
        "ERROR_CLASS=TierViolation ERROR_CODE={} {}. {} Use `browser__snapshot` then `browser__click_element`.",
        PHASE0_BROWSER_GUI_CLICK_ERROR_CODE, action, detail
    ))
}

pub(super) fn guard_phase0_browser_click_with_coordinate(
    exec: &ToolExecutor,
    action: &str,
    x: i32,
    y: i32,
) -> Option<ToolExecutionResult> {
    let rect = active_browser_window_rect(exec)?;
    if rect_contains_point(rect, x, y) {
        return Some(phase0_browser_gui_click_denied(
            action,
            &format!(
                "GUI/computer click at ({}, {}) is inside active browser window",
                x, y
            ),
        ));
    }
    None
}

pub(super) fn guard_phase0_browser_click_without_coordinate(
    exec: &ToolExecutor,
    action: &str,
) -> Option<ToolExecutionResult> {
    active_browser_window_rect(exec).map(|_| {
        phase0_browser_gui_click_denied(
            action,
            "Coordinate-free GUI/computer click is blocked while browser window is active",
        )
    })
}

pub(super) async fn guard_phase0_browser_click_by_id(
    exec: &ToolExecutor,
    action: &str,
    id: &str,
    som_map: Option<&BTreeMap<u32, (i32, i32, i32, i32)>>,
    semantic_map: Option<&BTreeMap<u32, String>>,
    active_lens: Option<&str>,
) -> Option<ToolExecutionResult> {
    let rect = active_browser_window_rect(exec)?;
    let point = resolve_target_point(exec, id, som_map, semantic_map, active_lens).await;
    match point {
        Some([x, y]) => {
            if rect_contains_point(rect, x as i32, y as i32) {
                Some(phase0_browser_gui_click_denied(
                    action,
                    &format!(
                        "Resolved target '{}' to ({}, {}) inside active browser window",
                        id, x, y
                    ),
                ))
            } else {
                None
            }
        }
        None => Some(phase0_browser_gui_click_denied(
            action,
            &format!(
                "Could not resolve target '{}' while browser window is active (fail-closed)",
                id
            ),
        )),
    }
}

pub(super) fn guard_phase0_browser_drag_with_coordinates(
    exec: &ToolExecutor,
    action: &str,
    from: [u32; 2],
    to: [u32; 2],
) -> Option<ToolExecutionResult> {
    let rect = active_browser_window_rect(exec)?;
    let from_in_browser = rect_contains_point(rect, from[0] as i32, from[1] as i32);
    let to_in_browser = rect_contains_point(rect, to[0] as i32, to[1] as i32);
    if from_in_browser || to_in_browser {
        return Some(phase0_browser_gui_click_denied(
            action,
            &format!(
                "GUI/computer drag from ({}, {}) to ({}, {}) intersects active browser window",
                from[0], from[1], to[0], to[1]
            ),
        ));
    }
    None
}

pub(super) async fn guard_phase0_browser_drag_by_ids(
    exec: &ToolExecutor,
    action: &str,
    from_id: &str,
    to_id: &str,
    som_map: Option<&BTreeMap<u32, (i32, i32, i32, i32)>>,
    semantic_map: Option<&BTreeMap<u32, String>>,
    active_lens: Option<&str>,
) -> Option<ToolExecutionResult> {
    let rect = active_browser_window_rect(exec)?;
    let [from_x, from_y] =
        match resolve_target_point(exec, from_id, som_map, semantic_map, active_lens).await {
            Some(point) => point,
            None => {
                return Some(phase0_browser_gui_click_denied(
                    action,
                    &format!(
                "Could not resolve drag source '{}' while browser window is active (fail-closed)",
                from_id
            ),
                ))
            }
        };
    let [to_x, to_y] =
        match resolve_target_point(exec, to_id, som_map, semantic_map, active_lens).await {
            Some(point) => point,
            None => {
                return Some(phase0_browser_gui_click_denied(
                    action,
                    &format!(
                        "Could not resolve drag destination '{}' while browser window is active (fail-closed)",
                        to_id
                    ),
                ))
            }
        };

    let from_in_browser = rect_contains_point(rect, from_x as i32, from_y as i32);
    let to_in_browser = rect_contains_point(rect, to_x as i32, to_y as i32);
    if from_in_browser || to_in_browser {
        return Some(phase0_browser_gui_click_denied(
            action,
            &format!(
                "Resolved drag endpoints '{}' -> ({}, {}), '{}' -> ({}, {}) intersect active browser window",
                from_id, from_x, from_y, to_id, to_x, to_y
            ),
        ));
    }
    None
}
