use super::super::{GroundingDebug, ToolExecutionResult, ToolExecutor};
use super::semantics::{
    find_center_by_query, find_center_for_numeric_query, find_center_of_element,
    find_closest_matches,
};
use super::tree::fetch_lensed_tree;
use ioi_api::vm::drivers::gui::{InputEvent, MouseButton};
use ioi_drivers::gui::geometry::{CoordinateSpace, DisplayTransform, Point};
use ioi_drivers::gui::operator::{ClickTarget, NativeOperator};
use std::collections::BTreeMap;

fn point_to_u32(point: Point) -> (u32, u32) {
    let x = point.x.max(0.0).round() as u32;
    let y = point.y.max(0.0).round() as u32;
    (x, y)
}

fn rect_tuple_contains_point(rect: (i32, i32, i32, i32), x: i32, y: i32) -> bool {
    let (rx, ry, width, height) = rect;
    if width <= 0 || height <= 0 {
        return false;
    }
    let x2 = rx + width;
    let y2 = ry + height;
    x >= rx && x <= x2 && y >= ry && y <= y2
}

fn best_som_id_for_coordinate(
    som_map: Option<&BTreeMap<u32, (i32, i32, i32, i32)>>,
    x: i32,
    y: i32,
) -> Option<u32> {
    let map = som_map?;
    map.iter()
        .filter_map(|(som_id, rect)| {
            if !rect_tuple_contains_point(*rect, x, y) {
                return None;
            }
            let area = rect.2.saturating_mul(rect.3);
            Some((*som_id, area))
        })
        .min_by_key(|(_, area)| *area)
        .map(|(som_id, _)| som_id)
}

pub(super) async fn click_by_coordinate_from_som(
    exec: &ToolExecutor,
    x: i32,
    y: i32,
    som_map: Option<&BTreeMap<u32, (i32, i32, i32, i32)>>,
    button: MouseButton,
) -> Option<ToolExecutionResult> {
    let som_id = best_som_id_for_coordinate(som_map, x, y)?;
    click_by_som_id(exec, som_id, som_map, button).await
}

pub(super) async fn click_by_som_id(
    exec: &ToolExecutor,
    som_id: u32,
    som_map: Option<&BTreeMap<u32, (i32, i32, i32, i32)>>,
    button: MouseButton,
) -> Option<ToolExecutionResult> {
    if let Some(map) = som_map {
        if let Some((x, y, w, h)) = map.get(&som_id) {
            let cx = x + (w / 2);
            let cy = y + (h / 2);
            let transform = NativeOperator::current_display_transform();
            let resolved = Point::new(cx as f64, cy as f64, CoordinateSpace::ScreenLogical);
            return Some(
                exec_click(
                    exec,
                    button,
                    ClickTarget::SemanticId(som_id),
                    resolved,
                    transform,
                    None,
                )
                .await,
            );
        }
    }

    match exec.gui.get_element_center(som_id).await {
        Ok(Some((x, y))) => {
            let transform = NativeOperator::current_display_transform();
            let resolved = Point::new(x as f64, y as f64, CoordinateSpace::ScreenLogical);
            Some(
                exec_click(
                    exec,
                    button,
                    ClickTarget::SemanticId(som_id),
                    resolved,
                    transform,
                    None,
                )
                .await,
            )
        }
        Ok(None) => None,
        Err(e) => Some(ToolExecutionResult::failure(format!(
            "SoM ID {} lookup failed in driver cache: {}",
            som_id, e
        ))),
    }
}

pub(in super::super) async fn exec_click(
    exec: &ToolExecutor,
    button: MouseButton,
    target: ClickTarget,
    resolved_point: Point,
    transform: DisplayTransform,
    expected_visual_hash: Option<[u8; 32]>,
) -> ToolExecutionResult {
    let (x, y) = point_to_u32(resolved_point);
    let event = InputEvent::Click {
        button,
        x,
        y,
        expected_visual_hash: expected_visual_hash.or(exec.expected_visual_hash),
    };

    match exec.gui.inject_input(event.clone()).await {
        Ok(_) => ToolExecutionResult::success(format!(
            "Input executed: {:?} -> ScreenLogical({}, {})",
            target, x, y
        )),
        Err(e) => {
            let debug_packet = GroundingDebug {
                transform,
                target,
                resolved_point,
                debug_image_path: String::new(),
            };
            let debug_path = exec.emit_grounding_debug_packet(debug_packet).await;
            let mut msg = format!("Input injection failed: {}", e);
            if let Some(path) = debug_path {
                msg.push_str(&format!(" [grounding_debug={}]", path));
            }
            ToolExecutionResult::failure(msg)
        }
    }
}

pub(in super::super) async fn click_element_by_id(
    exec: &ToolExecutor,
    id: &str,
    active_lens: Option<&str>,
) -> ToolExecutionResult {
    click_element_by_id_with_button(exec, id, active_lens, MouseButton::Left).await
}

pub(in super::super) async fn click_element_by_id_with_button(
    exec: &ToolExecutor,
    id: &str,
    active_lens: Option<&str>,
    button: MouseButton,
) -> ToolExecutionResult {
    let tree = match fetch_lensed_tree(exec, active_lens).await {
        Ok(tree) => tree,
        Err(err) => return ToolExecutionResult::failure(err),
    };

    // Find center
    if let Some((x, y)) = find_center_of_element(&tree, id) {
        let transform = NativeOperator::current_display_transform();
        let target = ClickTarget::Exact(Point::new(
            x as f64,
            y as f64,
            CoordinateSpace::ScreenLogical,
        ));
        let resolved = match NativeOperator::resolve_click_target(target, &transform) {
            Ok(pt) => pt,
            Err(e) => return ToolExecutionResult::failure(format!("Invalid click target: {}", e)),
        };
        exec_click(exec, button, target, resolved, transform, None).await
    } else {
        // Fallback to fuzzy semantic match (aliases/name/value/id substring).
        if let Some((x, y)) = find_center_by_query(&tree, id) {
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
            exec_click(exec, button, target, resolved, transform, None).await
        } else if let Some((x, y)) = find_center_for_numeric_query(&tree, id) {
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
            exec_click(exec, button, target, resolved, transform, None).await
        } else {
            let suggestions = find_closest_matches(&tree, id);
            let suggestion_text = if suggestions.is_empty() {
                String::new()
            } else {
                format!(" Similar elements found: [{}].", suggestions.join(", "))
            };

            ToolExecutionResult::failure(format!(
                "ERROR_CLASS=TargetNotFound Target '{}' not found in current UI tree.{} HINT: Verify the element ID in the XML or use `ui__find` to locate it visually.",
                id, suggestion_text
            ))
        }
    }
}
