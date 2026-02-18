// Path: crates/services/src/agentic/desktop/execution/computer.rs

use super::browser::{browser_surface_regions, is_probable_browser_window};
use super::resilience;
use super::{ToolExecutionResult, ToolExecutor};
use crate::agentic::desktop::types::ExecutionTier;
use ioi_api::vm::drivers::gui::{AtomicInput, InputEvent, MouseButton};
use ioi_drivers::gui::geometry::{CoordinateSpace, Point};
use ioi_drivers::gui::operator::{ClickTarget, NativeOperator};
use ioi_types::app::agentic::{AgentTool, ComputerAction};
use serde_json::json;
use std::collections::BTreeMap;

mod click;
mod input;
mod semantics;
mod tree;
mod ui_find;

use click::{click_by_coordinate_from_som, click_by_som_id};
use input::{exec_input, parse_mouse_button};
use semantics::{find_best_element_for_point, find_center_of_element, resolve_semantic_som_id};
use ui_find::find_element_coordinates;

pub(super) use click::{click_element_by_id, click_element_by_id_with_button, exec_click};
pub use input::{build_cursor_click_sequence, build_cursor_drag_sequence};
pub use semantics::{find_semantic_ui_match, UiFindSemanticMatch};
pub(super) use tree::fetch_lensed_tree;

const PHASE0_BROWSER_GUI_CLICK_ERROR_CODE: &str = "BrowserGuiClickDisallowedPhase0";

fn is_missing_focus_dependency_error(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("missing focus dependency")
        || lower.contains("wmctrl")
        || lower.contains("not found")
}

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

fn guard_phase0_browser_click_with_coordinate(
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

fn guard_phase0_browser_click_without_coordinate(
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

async fn guard_phase0_browser_click_by_id(
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

fn guard_phase0_browser_drag_with_coordinates(
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

async fn guard_phase0_browser_drag_by_ids(
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
    let [to_x, to_y] = match resolve_target_point(exec, to_id, som_map, semantic_map, active_lens).await
    {
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

fn center_from_rect(x: i32, y: i32, w: i32, h: i32) -> [u32; 2] {
    let cx = x + (w / 2);
    let cy = y + (h / 2);
    [cx.max(0) as u32, cy.max(0) as u32]
}

fn build_drag_drop_sequence(from: [u32; 2], to: [u32; 2]) -> Vec<AtomicInput> {
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

fn build_cursor_double_click_sequence() -> Vec<AtomicInput> {
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

async fn resolve_target_point(
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

fn append_verify_metadata(
    mut result: ToolExecutionResult,
    verify: serde_json::Value,
) -> ToolExecutionResult {
    if !result.success {
        return result;
    }

    let base = result
        .history_entry
        .take()
        .unwrap_or_else(|| "GUI click executed".to_string());
    result.history_entry = Some(format!("{base}. verify={verify}"));
    result
}

fn verification_attempt_payload(
    attempt: u32,
    verification: &resilience::verifier::VerificationResult,
) -> serde_json::Value {
    json!({
        "attempt": attempt,
        "tree_changed": verification.tree_changed,
        "visual_distance": verification.visual_distance,
        "significant": verification.is_significant(),
    })
}

async fn execute_verified_gui_click_element_som(
    exec: &ToolExecutor,
    som_id: u32,
    som_map: Option<&BTreeMap<u32, (i32, i32, i32, i32)>>,
    active_lens: Option<&str>,
) -> Option<ToolExecutionResult> {
    let before_snapshot =
        resilience::verifier::ActionVerifier::capture_snapshot(exec, active_lens).await;
    let mut attempts: Vec<serde_json::Value> = Vec::new();

    let first = click_by_som_id(exec, som_id, som_map, MouseButton::Left).await?;
    if !first.success {
        return Some(first);
    }

    let before_snapshot = match before_snapshot {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let verify = json!({
                "method": "som_id",
                "som_id": som_id,
                "snapshot": "unavailable",
                "snapshot_error": error,
                "postcondition": { "met": true },
            });
            return Some(append_verify_metadata(first, verify));
        }
    };

    tokio::time::sleep(std::time::Duration::from_millis(220)).await;
    match resilience::verifier::ActionVerifier::capture_snapshot(exec, active_lens).await {
        Ok(after_first) => {
            let verification =
                resilience::verifier::ActionVerifier::verify_impact(&before_snapshot, &after_first);
            attempts.push(verification_attempt_payload(1, &verification));
            if verification.is_significant() {
                let verify = json!({
                    "method": "som_id",
                    "som_id": som_id,
                    "snapshot": "available",
                    "postcondition": { "met": true },
                    "attempts": attempts,
                });
                return Some(append_verify_metadata(first, verify));
            }
        }
        Err(error) => {
            let verify = json!({
                "method": "som_id",
                "som_id": som_id,
                "snapshot": "unavailable",
                "snapshot_error": error,
                "postcondition": { "met": true },
            });
            return Some(append_verify_metadata(first, verify));
        }
    }

    let retry = match click_by_som_id(exec, som_id, som_map, MouseButton::Left).await {
        Some(result) => result,
        None => {
            return Some(ToolExecutionResult::failure(format!(
                "ERROR_CLASS=TargetNotFound SoM ID {} could not be resolved for retry.",
                som_id
            )))
        }
    };
    if !retry.success {
        return Some(retry);
    }

    tokio::time::sleep(std::time::Duration::from_millis(220)).await;
    match resilience::verifier::ActionVerifier::capture_snapshot(exec, active_lens).await {
        Ok(after_retry) => {
            let verification =
                resilience::verifier::ActionVerifier::verify_impact(&before_snapshot, &after_retry);
            attempts.push(verification_attempt_payload(2, &verification));
            if verification.is_significant() {
                let verify = json!({
                    "method": "som_id",
                    "som_id": som_id,
                    "snapshot": "available",
                    "postcondition": { "met": true },
                    "attempts": attempts,
                });
                return Some(append_verify_metadata(retry, verify));
            }

            let verify = json!({
                "method": "som_id",
                "som_id": som_id,
                "snapshot": "available",
                "postcondition": { "met": false },
                "attempts": attempts,
            });
            Some(ToolExecutionResult::failure(format!(
                "ERROR_CLASS=NoEffectAfterAction UI state static after SoM click (som_id={}). verify={}",
                som_id, verify
            )))
        }
        Err(error) => {
            let verify = json!({
                "method": "som_id",
                "som_id": som_id,
                "snapshot": "unavailable",
                "snapshot_error": error,
                "postcondition": { "met": true },
                "attempts": attempts,
            });
            Some(append_verify_metadata(retry, verify))
        }
    }
}

pub async fn handle(
    exec: &ToolExecutor,
    tool: AgentTool,
    som_map: Option<&BTreeMap<u32, (i32, i32, i32, i32)>>,
    semantic_map: Option<&BTreeMap<u32, String>>,
    active_lens: Option<&str>,
) -> ToolExecutionResult {
    match tool {
        AgentTool::Computer(action) => {
            handle_computer_action(exec, action, som_map, semantic_map, active_lens).await
        }

        AgentTool::GuiClick { x, y, button } => {
            if let Some(blocked) =
                guard_phase0_browser_click_with_coordinate(exec, "gui__click", x as i32, y as i32)
            {
                return blocked;
            }

            let allow_raw_coords =
                matches!(exec.current_tier, Some(ExecutionTier::VisualForeground));
            let allow_vision_fallback =
                resilience::allow_vision_fallback_for_tier(exec.current_tier);
            let btn = parse_mouse_button(button.as_deref());

            if let Some(result) =
                click_by_coordinate_from_som(exec, x as i32, y as i32, som_map, btn).await
            {
                if result.success || !allow_raw_coords {
                    return result;
                }
            }

            let mut semantic_override = None;
            if let Ok(tree) = fetch_lensed_tree(exec, active_lens).await {
                semantic_override = find_best_element_for_point(&tree, x as i32, y as i32);
            }

            if let Some(element_id) = semantic_override {
                let semantic_result = if matches!(btn, MouseButton::Left) {
                    resilience::execute_reflexive_click(
                        exec,
                        Some(&element_id),
                        &element_id,
                        active_lens,
                        allow_vision_fallback,
                    )
                    .await
                } else {
                    click_element_by_id_with_button(exec, &element_id, active_lens, btn).await
                };

                if semantic_result.success {
                    return semantic_result;
                }
                if !allow_raw_coords {
                    return semantic_result;
                }
            }

            if !allow_raw_coords {
                return ToolExecutionResult::failure(
                    "ERROR_CLASS=TierViolation Raw coordinate click is disabled outside VisualForeground (VisualLast). Use `gui__click_element` or `computer.left_click_element`.",
                );
            }

            let transform = NativeOperator::current_display_transform();
            let target = ClickTarget::Exact(Point::new(
                x as f64,
                y as f64,
                CoordinateSpace::ScreenLogical,
            ));
            let resolved = match NativeOperator::resolve_click_target(target, &transform) {
                Ok(pt) => pt,
                Err(e) => {
                    return ToolExecutionResult::failure(format!("Invalid click target: {}", e))
                }
            };
            exec_click(exec, btn, target, resolved, transform, None).await
        }

        AgentTool::GuiType { text } => exec_input(exec, InputEvent::Type { text }).await,

        AgentTool::GuiScroll { delta_x, delta_y } => {
            // Scroll is a tier-independent primitive (used for UI parity), but cursor repositioning
            // remains VisualForeground-only to avoid background cursor churn.
            if matches!(exec.current_tier, Some(ExecutionTier::VisualForeground)) {
                if let Some(regions) = browser_surface_regions(exec).await {
                    let (x, y) = regions.viewport_center();
                    let hover = exec_input(exec, InputEvent::MouseMove { x, y }).await;
                    if !hover.success {
                        return hover;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(40)).await;
                }
            }

            exec_input(
                exec,
                InputEvent::Scroll {
                    dx: delta_x,
                    dy: delta_y,
                },
            )
            .await
        }

        AgentTool::GuiSnapshot {} => match fetch_lensed_tree(exec, active_lens).await {
            Ok(tree) => ToolExecutionResult::success(
                ioi_drivers::gui::accessibility::serialize_tree_to_xml(&tree, 0),
            ),
            Err(e) => ToolExecutionResult::failure(format!("Extraction failed: {}", e)),
        },

        AgentTool::GuiClickElement { id } => {
            if let Some(blocked) = guard_phase0_browser_click_by_id(
                exec,
                "gui__click_element",
                &id,
                som_map,
                semantic_map,
                active_lens,
            )
            .await
            {
                return blocked;
            }

            let allow_vision_fallback =
                resilience::allow_vision_fallback_for_tier(exec.current_tier);
            if let Ok(som_id) = id.trim().parse::<u32>() {
                if let Some(result) =
                    execute_verified_gui_click_element_som(exec, som_id, som_map, active_lens).await
                {
                    return result;
                }
            }
            if let Some(smap) = semantic_map {
                if let Some(som_id) = resolve_semantic_som_id(smap, &id) {
                    if let Some(result) =
                        execute_verified_gui_click_element_som(exec, som_id, som_map, active_lens)
                            .await
                    {
                        return result;
                    }
                }
            }
            resilience::execute_reflexive_click(
                exec,
                Some(&id),
                &id,
                active_lens,
                allow_vision_fallback,
            )
            .await
        }

        AgentTool::UiFind { query } => find_element_coordinates(exec, &query, active_lens).await,

        AgentTool::OsFocusWindow { title } => match exec.os.focus_window(&title).await {
            Ok(true) => {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                let focused = exec.os.get_active_window_info().await.unwrap_or(None);
                let msg = if let Some(win) = focused {
                    format!("Focused '{}' ({})", win.title, win.app_name)
                } else {
                    format!("Focus requested for '{}'", title)
                };
                ToolExecutionResult::success(msg)
            }
            Ok(false) => ToolExecutionResult::failure(format!("No window matched '{}'", title)),
            Err(e) => {
                let err = e.to_string();
                if is_missing_focus_dependency_error(&err) {
                    ToolExecutionResult::failure(format!(
                        "ERROR_CLASS=MissingDependency Focus dependency unavailable for '{}': {}",
                        title, err
                    ))
                } else {
                    ToolExecutionResult::failure(format!(
                        "Window focus failed for '{}': {}",
                        title, err
                    ))
                }
            }
        },

        AgentTool::OsCopy { content } => match exec.os.set_clipboard(&content).await {
            Ok(()) => ToolExecutionResult::success("Copied to clipboard"),
            Err(e) => ToolExecutionResult::failure(format!("Clipboard write failed: {}", e)),
        },

        AgentTool::OsPaste { .. } => match exec.os.get_clipboard().await {
            Ok(content) => ToolExecutionResult::success(content),
            Err(e) => ToolExecutionResult::failure(format!("Clipboard read failed: {}", e)),
        },

        _ => ToolExecutionResult::failure("Unsupported GUI action"),
    }
}

async fn handle_computer_action(
    exec: &ToolExecutor,
    action: ComputerAction,
    som_map: Option<&BTreeMap<u32, (i32, i32, i32, i32)>>,
    semantic_map: Option<&BTreeMap<u32, String>>,
    active_lens: Option<&str>,
) -> ToolExecutionResult {
    match action {
        ComputerAction::MouseMove { coordinate } => {
            exec_input(
                exec,
                InputEvent::MouseMove {
                    x: coordinate[0],
                    y: coordinate[1],
                },
            )
            .await
        }
        ComputerAction::LeftClick { coordinate } => {
            if let Some(coord) = coordinate {
                if let Some(blocked) = guard_phase0_browser_click_with_coordinate(
                    exec,
                    "computer.left_click",
                    coord[0] as i32,
                    coord[1] as i32,
                ) {
                    return blocked;
                }

                let allow_raw_coords =
                    matches!(exec.current_tier, Some(ExecutionTier::VisualForeground));
                let allow_vision_fallback =
                    resilience::allow_vision_fallback_for_tier(exec.current_tier);

                if let Some(result) = click_by_coordinate_from_som(
                    exec,
                    coord[0] as i32,
                    coord[1] as i32,
                    som_map,
                    MouseButton::Left,
                )
                .await
                {
                    if result.success || !allow_raw_coords {
                        return result;
                    }
                }

                let mut semantic_override = None;
                if let Ok(tree) = fetch_lensed_tree(exec, active_lens).await {
                    semantic_override =
                        find_best_element_for_point(&tree, coord[0] as i32, coord[1] as i32);
                }

                if let Some(element_id) = semantic_override {
                    let semantic_result = resilience::execute_reflexive_click(
                        exec,
                        Some(&element_id),
                        &element_id,
                        active_lens,
                        allow_vision_fallback,
                    )
                    .await;

                    if semantic_result.success {
                        return semantic_result;
                    }
                    if !allow_raw_coords {
                        return semantic_result;
                    }
                }

                if !allow_raw_coords {
                    return ToolExecutionResult::failure(
                        "ERROR_CLASS=TierViolation Raw coordinate click is disabled outside VisualForeground (VisualLast). Use `left_click_element`.",
                    );
                }

                let transform = NativeOperator::current_display_transform();
                let target = ClickTarget::Exact(Point::new(
                    coord[0] as f64,
                    coord[1] as f64,
                    CoordinateSpace::ScreenLogical,
                ));
                let resolved = match NativeOperator::resolve_click_target(target, &transform) {
                    Ok(pt) => pt,
                    Err(e) => {
                        return ToolExecutionResult::failure(format!("Invalid click target: {}", e))
                    }
                };
                exec_click(exec, MouseButton::Left, target, resolved, transform, None).await
            } else {
                if let Some(blocked) =
                    guard_phase0_browser_click_without_coordinate(exec, "computer.left_click")
                {
                    return blocked;
                }

                // Coordinate-free click: click at the current cursor location.
                exec_input(
                    exec,
                    InputEvent::AtomicSequence(build_cursor_click_sequence(MouseButton::Left)),
                )
                .await
            }
        }
        ComputerAction::RightClick { coordinate } => {
            if let Some(coord) = coordinate {
                if let Some(blocked) = guard_phase0_browser_click_with_coordinate(
                    exec,
                    "computer.right_click",
                    coord[0] as i32,
                    coord[1] as i32,
                ) {
                    return blocked;
                }

                let allow_raw_coords =
                    matches!(exec.current_tier, Some(ExecutionTier::VisualForeground));

                if let Some(result) = click_by_coordinate_from_som(
                    exec,
                    coord[0] as i32,
                    coord[1] as i32,
                    som_map,
                    MouseButton::Right,
                )
                .await
                {
                    if result.success || !allow_raw_coords {
                        return result;
                    }
                }

                if let Ok(tree) = fetch_lensed_tree(exec, active_lens).await {
                    if let Some(element_id) =
                        find_best_element_for_point(&tree, coord[0] as i32, coord[1] as i32)
                    {
                        let semantic_result = click_element_by_id_with_button(
                            exec,
                            &element_id,
                            active_lens,
                            MouseButton::Right,
                        )
                        .await;
                        if semantic_result.success || !allow_raw_coords {
                            return semantic_result;
                        }
                    }
                }

                if !allow_raw_coords {
                    return ToolExecutionResult::failure(
                        "ERROR_CLASS=TierViolation Raw coordinate right-click is disabled outside VisualForeground (VisualLast).",
                    );
                }

                let transform = NativeOperator::current_display_transform();
                let target = ClickTarget::Exact(Point::new(
                    coord[0] as f64,
                    coord[1] as f64,
                    CoordinateSpace::ScreenLogical,
                ));
                let resolved = match NativeOperator::resolve_click_target(target, &transform) {
                    Ok(pt) => pt,
                    Err(e) => {
                        return ToolExecutionResult::failure(format!("Invalid click target: {}", e))
                    }
                };
                exec_click(exec, MouseButton::Right, target, resolved, transform, None).await
            } else {
                if let Some(blocked) =
                    guard_phase0_browser_click_without_coordinate(exec, "computer.right_click")
                {
                    return blocked;
                }

                exec_input(
                    exec,
                    InputEvent::AtomicSequence(build_cursor_click_sequence(MouseButton::Right)),
                )
                .await
            }
        }
        ComputerAction::DoubleClick { coordinate } => {
            if let Some(coord) = coordinate {
                if let Some(blocked) = guard_phase0_browser_click_with_coordinate(
                    exec,
                    "computer.double_click",
                    coord[0] as i32,
                    coord[1] as i32,
                ) {
                    return blocked;
                }

                let allow_raw_coords =
                    matches!(exec.current_tier, Some(ExecutionTier::VisualForeground));
                let allow_vision_fallback =
                    resilience::allow_vision_fallback_for_tier(exec.current_tier);

                if let Some(first_click) = click_by_coordinate_from_som(
                    exec,
                    coord[0] as i32,
                    coord[1] as i32,
                    som_map,
                    MouseButton::Left,
                )
                .await
                {
                    if first_click.success {
                        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
                        if let Some(second_click) = click_by_coordinate_from_som(
                            exec,
                            coord[0] as i32,
                            coord[1] as i32,
                            som_map,
                            MouseButton::Left,
                        )
                        .await
                        {
                            if second_click.success {
                                return ToolExecutionResult::success(format!(
                                    "Double-click executed via SoM fallback at ({}, {})",
                                    coord[0], coord[1]
                                ));
                            }
                            if !allow_raw_coords {
                                return second_click;
                            }
                        }
                    } else if !allow_raw_coords {
                        return first_click;
                    }
                }

                let mut semantic_override = None;
                if let Ok(tree) = fetch_lensed_tree(exec, active_lens).await {
                    semantic_override =
                        find_best_element_for_point(&tree, coord[0] as i32, coord[1] as i32);
                }

                if let Some(element_id) = semantic_override {
                    let first_click = resilience::execute_reflexive_click(
                        exec,
                        Some(&element_id),
                        &element_id,
                        active_lens,
                        allow_vision_fallback,
                    )
                    .await;

                    if first_click.success {
                        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
                        let second_click = resilience::execute_reflexive_click(
                            exec,
                            Some(&element_id),
                            &element_id,
                            active_lens,
                            allow_vision_fallback,
                        )
                        .await;
                        if second_click.success {
                            return ToolExecutionResult::success(format!(
                                "Double-click executed on semantic element '{}'",
                                element_id
                            ));
                        }
                        if !allow_raw_coords {
                            return second_click;
                        }
                    } else if !allow_raw_coords {
                        return first_click;
                    }
                }

                if !allow_raw_coords {
                    return ToolExecutionResult::failure(
                        "ERROR_CLASS=TierViolation Raw coordinate double-click is disabled outside VisualForeground (VisualLast).",
                    );
                }

                let transform = NativeOperator::current_display_transform();
                let target = ClickTarget::Exact(Point::new(
                    coord[0] as f64,
                    coord[1] as f64,
                    CoordinateSpace::ScreenLogical,
                ));
                let resolved = match NativeOperator::resolve_click_target(target, &transform) {
                    Ok(pt) => pt,
                    Err(e) => {
                        return ToolExecutionResult::failure(format!("Invalid click target: {}", e))
                    }
                };

                let first_click = exec_click(
                    exec,
                    MouseButton::Left,
                    target,
                    resolved,
                    transform.clone(),
                    None,
                )
                .await;
                if !first_click.success {
                    return first_click;
                }

                tokio::time::sleep(std::time::Duration::from_millis(80)).await;
                let second_click =
                    exec_click(exec, MouseButton::Left, target, resolved, transform, None).await;
                if !second_click.success {
                    return second_click;
                }

                ToolExecutionResult::success(format!(
                    "Double-click executed at ScreenLogical({}, {})",
                    coord[0], coord[1]
                ))
            } else {
                if let Some(blocked) =
                    guard_phase0_browser_click_without_coordinate(exec, "computer.double_click")
                {
                    return blocked;
                }

                exec_input(
                    exec,
                    InputEvent::AtomicSequence(build_cursor_double_click_sequence()),
                )
                .await
            }
        }
        ComputerAction::LeftClickId { id } => {
            if let Some(blocked) = guard_phase0_browser_click_by_id(
                exec,
                "computer.left_click_id",
                &id.to_string(),
                som_map,
                semantic_map,
                active_lens,
            )
            .await
            {
                return blocked;
            }

            if let Some(result) = click_by_som_id(exec, id, som_map, MouseButton::Left).await {
                return result;
            }

            if let Some(smap) = semantic_map {
                if let Some(semantic_id) = smap.get(&id) {
                    let fallback = resilience::execute_reflexive_click(
                        exec,
                        Some(semantic_id),
                        semantic_id,
                        active_lens,
                        resilience::allow_vision_fallback_for_tier(exec.current_tier),
                    )
                    .await;
                    if fallback.success {
                        return fallback;
                    }
                }
            }

            ToolExecutionResult::failure(format!("SoM ID {} not found in visual context", id))
        }
        ComputerAction::LeftClickElement { id } => {
            if let Some(blocked) = guard_phase0_browser_click_by_id(
                exec,
                "computer.left_click_element",
                &id,
                som_map,
                semantic_map,
                active_lens,
            )
            .await
            {
                return blocked;
            }

            let allow_vision_fallback =
                resilience::allow_vision_fallback_for_tier(exec.current_tier);
            // Reverse lookup: check semantic map if we have the ID from visual processing
            // Otherwise, scan current tree
            if let Ok(som_id) = id.trim().parse::<u32>() {
                if let Some(result) =
                    click_by_som_id(exec, som_id, som_map, MouseButton::Left).await
                {
                    return result;
                }
            }
            if let Some(smap) = semantic_map {
                if let Some(som_id) = resolve_semantic_som_id(smap, &id) {
                    if let Some(result) =
                        click_by_som_id(exec, som_id, som_map, MouseButton::Left).await
                    {
                        return result;
                    }
                }
            }

            // Fallback: Scan tree directly
            resilience::execute_reflexive_click(
                exec,
                Some(&id),
                &id,
                active_lens,
                allow_vision_fallback,
            )
            .await
        }
        ComputerAction::RightClickId { id } => {
            if let Some(blocked) = guard_phase0_browser_click_by_id(
                exec,
                "computer.right_click_id",
                &id.to_string(),
                som_map,
                semantic_map,
                active_lens,
            )
            .await
            {
                return blocked;
            }

            if let Some(result) = click_by_som_id(exec, id, som_map, MouseButton::Right).await {
                return result;
            }

            if let Some(smap) = semantic_map {
                if let Some(semantic_id) = smap.get(&id) {
                    let fallback = click_element_by_id_with_button(
                        exec,
                        semantic_id,
                        active_lens,
                        MouseButton::Right,
                    )
                    .await;
                    if fallback.success {
                        return fallback;
                    }
                }
            }

            ToolExecutionResult::failure(format!("SoM ID {} not found in visual context", id))
        }
        ComputerAction::RightClickElement { id } => {
            if let Some(blocked) = guard_phase0_browser_click_by_id(
                exec,
                "computer.right_click_element",
                &id,
                som_map,
                semantic_map,
                active_lens,
            )
            .await
            {
                return blocked;
            }

            if let Ok(som_id) = id.trim().parse::<u32>() {
                if let Some(result) =
                    click_by_som_id(exec, som_id, som_map, MouseButton::Right).await
                {
                    return result;
                }
            }
            if let Some(smap) = semantic_map {
                if let Some(som_id) = resolve_semantic_som_id(smap, &id) {
                    if let Some(result) =
                        click_by_som_id(exec, som_id, som_map, MouseButton::Right).await
                    {
                        return result;
                    }
                }
            }

            click_element_by_id_with_button(exec, &id, active_lens, MouseButton::Right).await
        }
        ComputerAction::Type { text } => exec_input(exec, InputEvent::Type { text }).await,
        ComputerAction::Key { text } => exec_input(exec, InputEvent::KeyPress { key: text }).await,
        ComputerAction::Hotkey { keys } => {
            // Atomic sequence for chords
            let mut steps = Vec::new();
            // Hold modifiers
            for k in &keys[..keys.len() - 1] {
                steps.push(AtomicInput::KeyDown { key: k.clone() });
            }
            // Click final key
            if let Some(last) = keys.last() {
                steps.push(AtomicInput::KeyPress { key: last.clone() });
            }
            // Release modifiers
            for k in keys[..keys.len() - 1].iter().rev() {
                steps.push(AtomicInput::KeyUp { key: k.clone() });
            }
            exec_input(exec, InputEvent::AtomicSequence(steps)).await
        }
        ComputerAction::LeftClickDrag { coordinate } => {
            if let Some(blocked) = guard_phase0_browser_drag_with_coordinates(
                exec,
                "computer.left_click_drag",
                coordinate,
                coordinate,
            ) {
                return blocked;
            }

            exec_input(
                exec,
                InputEvent::AtomicSequence(build_cursor_drag_sequence(coordinate)),
            )
            .await
        }
        ComputerAction::DragDrop { from, to } => {
            if let Some(blocked) =
                guard_phase0_browser_drag_with_coordinates(exec, "computer.drag_drop", from, to)
            {
                return blocked;
            }

            let steps = build_drag_drop_sequence(from, to);
            exec_input(exec, InputEvent::AtomicSequence(steps)).await
        }
        ComputerAction::DragDropId { from_id, to_id } => {
            if let Some(blocked) = guard_phase0_browser_drag_by_ids(
                exec,
                "computer.drag_drop_id",
                &from_id.to_string(),
                &to_id.to_string(),
                som_map,
                semantic_map,
                active_lens,
            )
            .await
            {
                return blocked;
            }

            let from = resolve_target_point(
                exec,
                &from_id.to_string(),
                som_map,
                semantic_map,
                active_lens,
            )
            .await;
            let to =
                resolve_target_point(exec, &to_id.to_string(), som_map, semantic_map, active_lens)
                    .await;

            match (from, to) {
                (Some(start), Some(end)) => {
                    let steps = build_drag_drop_sequence(start, end);
                    exec_input(exec, InputEvent::AtomicSequence(steps)).await
                }
                (None, _) => {
                    ToolExecutionResult::failure(format!("Drag source ID {} not found", from_id))
                }
                (_, None) => {
                    ToolExecutionResult::failure(format!("Drag destination ID {} not found", to_id))
                }
            }
        }
        ComputerAction::DragDropElement { from_id, to_id } => {
            if let Some(blocked) = guard_phase0_browser_drag_by_ids(
                exec,
                "computer.drag_drop_element",
                &from_id,
                &to_id,
                som_map,
                semantic_map,
                active_lens,
            )
            .await
            {
                return blocked;
            }

            let from =
                resolve_target_point(exec, &from_id, som_map, semantic_map, active_lens).await;
            let to = resolve_target_point(exec, &to_id, som_map, semantic_map, active_lens).await;

            match (from, to) {
                (Some(start), Some(end)) => {
                    let steps = build_drag_drop_sequence(start, end);
                    exec_input(exec, InputEvent::AtomicSequence(steps)).await
                }
                (None, _) => ToolExecutionResult::failure(format!(
                    "Drag source element '{}' not found",
                    from_id
                )),
                (_, None) => ToolExecutionResult::failure(format!(
                    "Drag destination element '{}' not found",
                    to_id
                )),
            }
        }
        ComputerAction::Screenshot => match exec.gui.capture_screen(None).await {
            Ok(_) => ToolExecutionResult::success("Screenshot captured"),
            Err(e) => ToolExecutionResult::failure(e.to_string()),
        },
        ComputerAction::CursorPosition => match exec.gui.get_cursor_position().await {
            Ok((x, y)) => {
                let payload = json!({
                    "x": x,
                    "y": y,
                    "coordinate_space": "ScreenLogical",
                });
                ToolExecutionResult::success(format!("Cursor position: {}", payload))
            }
            Err(e) => ToolExecutionResult::failure(format!(
                "ERROR_CLASS=MissingDependency Failed to read cursor position: {}",
                e
            )),
        },
        ComputerAction::Scroll { coordinate, delta } => {
            if let Some(coord) = coordinate {
                let moved = exec_input(
                    exec,
                    InputEvent::MouseMove {
                        x: coord[0],
                        y: coord[1],
                    },
                )
                .await;
                if !moved.success {
                    return moved;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            } else if let Some(regions) = browser_surface_regions(exec).await {
                let (x, y) = regions.viewport_center();
                let moved = exec_input(exec, InputEvent::MouseMove { x, y }).await;
                if !moved.success {
                    return moved;
                }
                tokio::time::sleep(std::time::Duration::from_millis(40)).await;
            }
            exec_input(
                exec,
                InputEvent::Scroll {
                    dx: delta[0],
                    dy: delta[1],
                },
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use ioi_api::vm::drivers::gui::GuiDriver;
    use ioi_api::vm::drivers::os::{OsDriver, WindowInfo};
    use ioi_api::vm::inference::{mock::MockInferenceRuntime, InferenceRuntime};
    use ioi_drivers::browser::BrowserDriver;
    use ioi_drivers::mcp::McpManager;
    use ioi_drivers::terminal::TerminalDriver;
    use ioi_types::app::{ActionRequest, ContextSlice};
    use ioi_types::error::VmError;
    use std::collections::{BTreeMap, HashMap};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct RecordingGuiDriver {
        injected: Mutex<Vec<InputEvent>>,
    }

    impl RecordingGuiDriver {
        fn take_events(&self) -> Vec<InputEvent> {
            let mut guard = self.injected.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut *guard)
        }
    }

    #[async_trait]
    impl GuiDriver for RecordingGuiDriver {
        async fn capture_screen(
            &self,
            _crop_rect: Option<(i32, i32, u32, u32)>,
        ) -> Result<Vec<u8>, VmError> {
            Err(VmError::HostError("capture_screen not implemented".into()))
        }

        async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
            Err(VmError::HostError(
                "capture_raw_screen not implemented".into(),
            ))
        }

        async fn capture_tree(&self) -> Result<String, VmError> {
            Err(VmError::HostError("capture_tree not implemented".into()))
        }

        async fn capture_context(&self, _intent: &ActionRequest) -> Result<ContextSlice, VmError> {
            Err(VmError::HostError("capture_context not implemented".into()))
        }

        async fn inject_input(&self, event: InputEvent) -> Result<(), VmError> {
            let mut guard = self.injected.lock().unwrap_or_else(|e| e.into_inner());
            guard.push(event);
            Ok(())
        }

        async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
            Ok(None)
        }

        async fn register_som_overlay(
            &self,
            _map: HashMap<u32, (i32, i32, i32, i32)>,
        ) -> Result<(), VmError> {
            Ok(())
        }
    }

    struct TestOsDriver {
        active_window: Option<WindowInfo>,
    }

    #[async_trait]
    impl OsDriver for TestOsDriver {
        async fn get_active_window_title(&self) -> Result<Option<String>, VmError> {
            Ok(self.active_window.as_ref().map(|w| w.title.clone()))
        }

        async fn get_active_window_info(&self) -> Result<Option<WindowInfo>, VmError> {
            Ok(self.active_window.clone())
        }

        async fn focus_window(&self, _title_query: &str) -> Result<bool, VmError> {
            Ok(false)
        }

        async fn set_clipboard(&self, _content: &str) -> Result<(), VmError> {
            Ok(())
        }

        async fn get_clipboard(&self) -> Result<String, VmError> {
            Ok(String::new())
        }
    }

    fn browser_window() -> WindowInfo {
        WindowInfo {
            title: "Google Chrome".to_string(),
            app_name: "chrome".to_string(),
            x: 10,
            y: 20,
            width: 300,
            height: 200,
        }
    }

    fn build_executor(
        gui: Arc<RecordingGuiDriver>,
        active_window: Option<WindowInfo>,
        tier: ExecutionTier,
    ) -> ToolExecutor {
        let os: Arc<dyn OsDriver> = Arc::new(TestOsDriver {
            active_window: active_window.clone(),
        });
        let terminal = Arc::new(TerminalDriver::new());
        let browser = Arc::new(BrowserDriver::new());
        let mcp = Arc::new(McpManager::new());
        let inference: Arc<dyn InferenceRuntime> = Arc::new(MockInferenceRuntime::default());

        ToolExecutor::new(gui, os, terminal, browser, mcp, None, None, inference, None)
            .with_window_context(active_window, None, Some(tier))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn gui_scroll_is_allowed_outside_visual_foreground() {
        let gui = Arc::new(RecordingGuiDriver::default());
        let exec = build_executor(gui.clone(), None, ExecutionTier::VisualBackground);

        let result = handle(
            &exec,
            AgentTool::GuiScroll {
                delta_x: 12,
                delta_y: 340,
            },
            None,
            None,
            None,
        )
        .await;

        assert!(result.success);
        assert_eq!(
            gui.take_events(),
            vec![InputEvent::Scroll { dx: 12, dy: 340 }]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn gui_click_inside_browser_window_is_blocked_phase0() {
        let gui = Arc::new(RecordingGuiDriver::default());
        let exec = build_executor(
            gui.clone(),
            Some(browser_window()),
            ExecutionTier::VisualForeground,
        );

        let result = handle(
            &exec,
            AgentTool::GuiClick {
                x: 50,
                y: 50,
                button: Some("left".to_string()),
            },
            None,
            None,
            None,
        )
        .await;

        assert!(!result.success);
        let err = result.error.unwrap_or_default();
        assert!(err.contains("ERROR_CLASS=TierViolation"));
        assert!(err.contains("ERROR_CODE=BrowserGuiClickDisallowedPhase0"));
        assert!(gui.take_events().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn gui_click_outside_browser_window_is_allowed() {
        let gui = Arc::new(RecordingGuiDriver::default());
        let exec = build_executor(
            gui.clone(),
            Some(browser_window()),
            ExecutionTier::VisualForeground,
        );

        let result = handle(
            &exec,
            AgentTool::GuiClick {
                x: 600,
                y: 600,
                button: Some("left".to_string()),
            },
            None,
            None,
            None,
        )
        .await;

        assert!(result.success);
        assert_eq!(gui.take_events().len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn computer_left_click_without_coordinate_is_blocked_when_browser_active() {
        let gui = Arc::new(RecordingGuiDriver::default());
        let exec = build_executor(
            gui.clone(),
            Some(browser_window()),
            ExecutionTier::VisualForeground,
        );

        let result = handle(
            &exec,
            AgentTool::Computer(ComputerAction::LeftClick { coordinate: None }),
            None,
            None,
            None,
        )
        .await;

        assert!(!result.success);
        let err = result.error.unwrap_or_default();
        assert!(err.contains("ERROR_CLASS=TierViolation"));
        assert!(err.contains("ERROR_CODE=BrowserGuiClickDisallowedPhase0"));
        assert!(gui.take_events().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn gui_click_element_is_blocked_when_browser_active_and_target_unresolved() {
        let gui = Arc::new(RecordingGuiDriver::default());
        let exec = build_executor(
            gui.clone(),
            Some(browser_window()),
            ExecutionTier::VisualForeground,
        );

        let result = handle(
            &exec,
            AgentTool::GuiClickElement {
                id: "btn_submit".to_string(),
            },
            None,
            None,
            None,
        )
        .await;

        assert!(!result.success);
        let err = result.error.unwrap_or_default();
        assert!(err.contains("ERROR_CLASS=TierViolation"));
        assert!(err.contains("ERROR_CODE=BrowserGuiClickDisallowedPhase0"));
        assert!(gui.take_events().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn computer_right_click_element_is_blocked_when_browser_active_and_target_unresolved() {
        let gui = Arc::new(RecordingGuiDriver::default());
        let exec = build_executor(
            gui.clone(),
            Some(browser_window()),
            ExecutionTier::VisualForeground,
        );

        let result = handle(
            &exec,
            AgentTool::Computer(ComputerAction::RightClickElement {
                id: "btn_context_menu".to_string(),
            }),
            None,
            None,
            None,
        )
        .await;

        assert!(!result.success);
        let err = result.error.unwrap_or_default();
        assert!(err.contains("ERROR_CLASS=TierViolation"));
        assert!(err.contains("ERROR_CODE=BrowserGuiClickDisallowedPhase0"));
        assert!(gui.take_events().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn computer_drag_drop_with_coordinate_inside_browser_is_blocked() {
        let gui = Arc::new(RecordingGuiDriver::default());
        let exec = build_executor(
            gui.clone(),
            Some(browser_window()),
            ExecutionTier::VisualForeground,
        );

        let result = handle(
            &exec,
            AgentTool::Computer(ComputerAction::DragDrop {
                from: [50, 60],
                to: [600, 600],
            }),
            None,
            None,
            None,
        )
        .await;

        assert!(!result.success);
        let err = result.error.unwrap_or_default();
        assert!(err.contains("ERROR_CLASS=TierViolation"));
        assert!(err.contains("ERROR_CODE=BrowserGuiClickDisallowedPhase0"));
        assert!(gui.take_events().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn computer_drag_drop_id_is_blocked_when_browser_active_and_target_unresolved() {
        let gui = Arc::new(RecordingGuiDriver::default());
        let exec = build_executor(
            gui.clone(),
            Some(browser_window()),
            ExecutionTier::VisualForeground,
        );

        let result = handle(
            &exec,
            AgentTool::Computer(ComputerAction::DragDropId {
                from_id: 111,
                to_id: 222,
            }),
            None,
            None,
            None,
        )
        .await;

        assert!(!result.success);
        let err = result.error.unwrap_or_default();
        assert!(err.contains("ERROR_CLASS=TierViolation"));
        assert!(err.contains("ERROR_CODE=BrowserGuiClickDisallowedPhase0"));
        assert!(gui.take_events().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn computer_right_click_element_outside_browser_is_allowed() {
        let gui = Arc::new(RecordingGuiDriver::default());
        let exec = build_executor(
            gui.clone(),
            Some(browser_window()),
            ExecutionTier::VisualForeground,
        );
        let som_map = BTreeMap::from([(42u32, (600, 600, 40, 40))]);

        let result = handle(
            &exec,
            AgentTool::Computer(ComputerAction::RightClickElement {
                id: "42".to_string(),
            }),
            Some(&som_map),
            None,
            None,
        )
        .await;

        assert!(result.success);
        assert!(!gui.take_events().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn gui_click_element_som_path_emits_verify_when_snapshot_unavailable() {
        let gui = Arc::new(RecordingGuiDriver::default());
        let exec = build_executor(gui.clone(), None, ExecutionTier::VisualBackground);
        let som_map = BTreeMap::from([(42u32, (600, 600, 40, 40))]);

        let result = handle(
            &exec,
            AgentTool::GuiClickElement {
                id: "42".to_string(),
            },
            Some(&som_map),
            None,
            None,
        )
        .await;

        assert!(result.success);
        let history = result.history_entry.unwrap_or_default();
        assert!(history.contains("verify="));
        assert!(history.contains("\"snapshot\":\"unavailable\""));
        assert!(!gui.take_events().is_empty());
    }
}
