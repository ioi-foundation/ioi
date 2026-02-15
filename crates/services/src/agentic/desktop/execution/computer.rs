// Path: crates/services/src/agentic/desktop/execution/computer.rs

use super::browser::browser_surface_regions;
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

fn is_missing_focus_dependency_error(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("missing focus dependency")
        || lower.contains("wmctrl")
        || lower.contains("not found")
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
            let allow_raw = matches!(exec.current_tier, Some(ExecutionTier::VisualForeground));
            if !allow_raw {
                return ToolExecutionResult::failure(
                    "ERROR_CLASS=TierViolation Scrolling requires VisualForeground (VisualLast) tier.",
                );
            }
            if let Some(regions) = browser_surface_regions(exec).await {
                let (x, y) = regions.viewport_center();
                let hover = exec_input(exec, InputEvent::MouseMove { x, y }).await;
                if !hover.success {
                    return hover;
                }
                tokio::time::sleep(std::time::Duration::from_millis(40)).await;
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

        AgentTool::GuiClickElement { id } => {
            let allow_vision_fallback =
                resilience::allow_vision_fallback_for_tier(exec.current_tier);
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
                exec_input(
                    exec,
                    InputEvent::AtomicSequence(build_cursor_click_sequence(MouseButton::Right)),
                )
                .await
            }
        }
        ComputerAction::DoubleClick { coordinate } => {
            if let Some(coord) = coordinate {
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
                exec_input(
                    exec,
                    InputEvent::AtomicSequence(build_cursor_double_click_sequence()),
                )
                .await
            }
        }
        ComputerAction::LeftClickId { id } => {
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
            exec_input(
                exec,
                InputEvent::AtomicSequence(build_cursor_drag_sequence(coordinate)),
            )
            .await
        }
        ComputerAction::DragDrop { from, to } => {
            let steps = build_drag_drop_sequence(from, to);
            exec_input(exec, InputEvent::AtomicSequence(steps)).await
        }
        ComputerAction::DragDropId { from_id, to_id } => {
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
