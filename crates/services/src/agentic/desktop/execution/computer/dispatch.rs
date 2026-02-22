use super::super::browser::browser_surface_regions;
use super::super::resilience;
use super::click::{click_by_coordinate_from_som, click_by_som_id};
use super::input::{build_cursor_click_sequence, exec_input, parse_mouse_button};
use super::semantics::{find_best_element_for_point, resolve_semantic_som_id};
use super::signals::{
    guard_phase0_browser_click_by_id, guard_phase0_browser_click_with_coordinate,
    guard_phase0_browser_click_without_coordinate, guard_phase0_browser_drag_by_ids,
    guard_phase0_browser_drag_with_coordinates,
};
use super::targeting::{
    build_cursor_double_click_sequence, build_drag_drop_sequence, resolve_target_point,
};
use super::ui_find::find_element_coordinates;
use super::verification::execute_verified_gui_click_element_som;
use super::{click_element_by_id_with_button, exec_click, fetch_lensed_tree};
use super::{ToolExecutionResult, ToolExecutor};
use crate::agentic::desktop::types::ExecutionTier;
use ioi_api::vm::drivers::gui::{AtomicInput, InputEvent, MouseButton};
use ioi_drivers::gui::geometry::{CoordinateSpace, Point};
use ioi_drivers::gui::operator::{ClickTarget, NativeOperator};
use ioi_types::app::agentic::{AgentTool, ComputerAction};
use serde_json::json;
use std::collections::BTreeMap;

fn is_missing_focus_dependency_error(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("missing focus dependency")
        || lower.contains("wmctrl")
        || lower.contains("not found")
}

pub(super) async fn handle(
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
                InputEvent::AtomicSequence(super::build_cursor_drag_sequence(coordinate)),
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
