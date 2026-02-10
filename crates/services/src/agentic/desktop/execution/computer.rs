// Path: crates/services/src/agentic/desktop/execution/computer.rs

use super::{resilience, GroundingDebug, ToolExecutionResult, ToolExecutor};
use crate::agentic::desktop::types::ExecutionTier;
use ioi_api::vm::drivers::gui::{AtomicInput, InputEvent, MouseButton};
use ioi_drivers::gui::accessibility::{AccessibilityNode, Rect};
use ioi_drivers::gui::geometry::{CoordinateSpace, DisplayTransform, Point};
use ioi_drivers::gui::operator::{ClickTarget, NativeOperator};
use ioi_drivers::gui::platform::fetch_tree_direct;
use ioi_types::app::agentic::{AgentTool, ComputerAction};
use serde_json::json;
use std::collections::BTreeMap;

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

            if let Ok(tree) = fetch_lensed_tree(exec, active_lens).await {
                if let Some(element_id) = find_best_element_for_point(&tree, x as i32, y as i32) {
                    let semantic_result = resilience::execute_reflexive_click(
                        exec,
                        Some(&element_id),
                        &element_id,
                        active_lens,
                        allow_vision_fallback,
                    )
                    .await;
                    if semantic_result.success || !allow_raw_coords {
                        return semantic_result;
                    }
                }
            }

            if !allow_raw_coords {
                return ToolExecutionResult::failure(
                    "ERROR_CLASS=TierViolation Raw coordinate click is disabled outside VisualForeground (VisualLast). Use `gui__click_element` or `computer.left_click_element`.",
                );
            }

            let btn = match button.as_deref() {
                Some("right") => MouseButton::Right,
                Some("middle") => MouseButton::Middle,
                _ => MouseButton::Left,
            };
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

        AgentTool::GuiClickElement { id } => {
            let allow_vision_fallback =
                resilience::allow_vision_fallback_for_tier(exec.current_tier);
            if let Ok(som_id) = id.trim().parse::<u32>() {
                if let Some(result) = click_by_som_id(exec, som_id, som_map).await {
                    return result;
                }
            }
            if let Some(smap) = semantic_map {
                if let Some(som_id) = resolve_semantic_som_id(smap, &id) {
                    if let Some(result) = click_by_som_id(exec, som_id, som_map).await {
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

        AgentTool::UiFind { query } => {
            // Use visual search via reasoning inference logic (not implemented here)
            // or fallback to accessibility tree search
            find_element_coordinates(exec, &query).await
        }

        AgentTool::OsFocusWindow { title } => {
            // This requires OsDriver, which is injected into the service but not directly
            // exposed on ToolExecutor struct in this refactor.
            // We assume the caller handles this or we inject OsDriver into executor.
            // For now, return failure or TODO if missing.
            ToolExecutionResult::failure("OS Driver access required for focus")
        }

        AgentTool::OsCopy { content } => {
            // Requires OS Driver
            ToolExecutionResult::failure("OS Driver access required for copy")
        }

        AgentTool::OsPaste { .. } => {
            // Requires OS Driver
            ToolExecutionResult::failure("OS Driver access required for paste")
        }

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

                if let Ok(tree) = fetch_lensed_tree(exec, active_lens).await {
                    if let Some(element_id) =
                        find_best_element_for_point(&tree, coord[0] as i32, coord[1] as i32)
                    {
                        let semantic_result = resilience::execute_reflexive_click(
                            exec,
                            Some(&element_id),
                            &element_id,
                            active_lens,
                            allow_vision_fallback,
                        )
                        .await;
                        if semantic_result.success || !allow_raw_coords {
                            return semantic_result;
                        }
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
        ComputerAction::LeftClickId { id } => {
            if let Some(result) = click_by_som_id(exec, id, som_map).await {
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
                if let Some(result) = click_by_som_id(exec, som_id, som_map).await {
                    return result;
                }
            }
            if let Some(smap) = semantic_map {
                if let Some(som_id) = resolve_semantic_som_id(smap, &id) {
                    if let Some(result) = click_by_som_id(exec, som_id, som_map).await {
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
            let steps = vec![
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
            ];
            exec_input(exec, InputEvent::AtomicSequence(steps)).await
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
    }
}

/// Build an atomic click sequence using the current cursor position.
pub fn build_cursor_click_sequence(button: MouseButton) -> Vec<AtomicInput> {
    vec![
        AtomicInput::MouseDown { button },
        AtomicInput::Wait { millis: 50 },
        AtomicInput::MouseUp { button },
    ]
}

/// Build a drag sequence from current cursor position to an absolute coordinate.
pub fn build_cursor_drag_sequence(to: [u32; 2]) -> Vec<AtomicInput> {
    vec![
        AtomicInput::MouseDown {
            button: MouseButton::Left,
        },
        AtomicInput::Wait { millis: 120 },
        AtomicInput::MouseMove { x: to[0], y: to[1] },
        AtomicInput::Wait { millis: 120 },
        AtomicInput::MouseUp {
            button: MouseButton::Left,
        },
    ]
}

async fn exec_input(exec: &ToolExecutor, event: InputEvent) -> ToolExecutionResult {
    match exec.gui.inject_input(event.clone()).await {
        Ok(_) => ToolExecutionResult::success(format!("Input executed: {:?}", event)),
        Err(e) => ToolExecutionResult::failure(format!("Input injection failed: {}", e)),
    }
}

fn point_to_u32(point: Point) -> (u32, u32) {
    let x = point.x.max(0.0).round() as u32;
    let y = point.y.max(0.0).round() as u32;
    (x, y)
}

fn normalize_semantic_key(value: &str) -> String {
    value
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect()
}

pub(super) async fn fetch_lensed_tree(
    exec: &ToolExecutor,
    active_lens: Option<&str>,
) -> Result<AccessibilityNode, String> {
    let raw_tree = fetch_tree_direct()
        .await
        .map_err(|e| format!("Failed to fetch UI tree: {}", e))?;

    let tree = if let Some(lens_name) = active_lens {
        if let Some(registry) = &exec.lens_registry {
            if let Some(lens) = registry.get(lens_name) {
                lens.transform(&raw_tree).unwrap_or(raw_tree)
            } else {
                raw_tree
            }
        } else {
            raw_tree
        }
    } else {
        raw_tree
    };

    Ok(tree)
}

fn has_node_content(node: &AccessibilityNode) -> bool {
    node.name.as_deref().is_some_and(|s| !s.trim().is_empty())
        || node.value.as_deref().is_some_and(|s| !s.trim().is_empty())
        || node
            .attributes
            .get("aria-label")
            .is_some_and(|s| !s.trim().is_empty())
        || node
            .attributes
            .get("title")
            .is_some_and(|s| !s.trim().is_empty())
        || node
            .attributes
            .get("description")
            .is_some_and(|s| !s.trim().is_empty())
}

fn is_interactive_role_like(role: &str) -> bool {
    matches!(
        role.trim().to_ascii_lowercase().as_str(),
        "button"
            | "push button"
            | "pushbutton"
            | "toggle button"
            | "menu item"
            | "menuitem"
            | "list item"
            | "listitem"
            | "link"
            | "check box"
            | "checkbox"
            | "radio button"
            | "tab"
            | "combo box"
            | "combobox"
            | "text box"
            | "textbox"
            | "entry"
            | "edit"
            | "text"
    )
}

fn is_structural_role_like(role: &str) -> bool {
    matches!(
        role.trim().to_ascii_lowercase().as_str(),
        "root" | "window" | "dialog" | "pane" | "panel" | "group" | "application"
    )
}

fn rect_contains_point(rect: Rect, x: i32, y: i32) -> bool {
    if rect.width <= 0 || rect.height <= 0 {
        return false;
    }
    let x2 = rect.x + rect.width;
    let y2 = rect.y + rect.height;
    x >= rect.x && x <= x2 && y >= rect.y && y <= y2
}

fn find_best_element_for_point(root: &AccessibilityNode, x: i32, y: i32) -> Option<String> {
    let mut best: Option<(i32, i32, String)> = None; // score, area, id
    let mut stack = vec![root];

    while let Some(node) = stack.pop() {
        if node.is_visible && !node.id.trim().is_empty() && rect_contains_point(node.rect, x, y) {
            let role = node.role.to_ascii_lowercase();
            let mut score = 0i32;
            let area = (node.rect.width * node.rect.height).max(1);

            if is_interactive_role_like(&role) {
                score += 55;
            }
            if has_node_content(node) {
                score += 25;
            }
            if node
                .attributes
                .get("semantic_aliases")
                .is_some_and(|s| !s.trim().is_empty())
            {
                score += 10;
            }
            if node.children.is_empty() {
                score += 8;
            }
            if node.id.to_ascii_lowercase().starts_with("btn_") {
                score += 12;
            }
            if is_structural_role_like(&role) && !is_interactive_role_like(&role) {
                score -= 40;
            }
            if (20..=200).contains(&node.rect.width) && (20..=200).contains(&node.rect.height) {
                score += 15;
            }

            score -= (area / 800).min(35);

            let cx = node.rect.x + (node.rect.width / 2);
            let cy = node.rect.y + (node.rect.height / 2);
            let center_distance = (cx - x).abs() + (cy - y).abs();
            score -= (center_distance / 100).min(10);

            match &best {
                Some((best_score, best_area, _))
                    if *best_score > score || (*best_score == score && *best_area <= area) => {}
                _ => best = Some((score, area, node.id.clone())),
            }
        }

        for child in &node.children {
            stack.push(child);
        }
    }

    best.and_then(|(score, _, id)| if score >= 15 { Some(id) } else { None })
}

fn resolve_semantic_som_id(smap: &BTreeMap<u32, String>, query: &str) -> Option<u32> {
    if let Ok(id) = query.trim().parse::<u32>() {
        if smap.contains_key(&id) {
            return Some(id);
        }
    }

    if let Some((som_id, _)) = smap.iter().find(|(_, val)| val.as_str() == query) {
        return Some(*som_id);
    }

    if let Some((som_id, _)) = smap.iter().find(|(_, val)| val.eq_ignore_ascii_case(query)) {
        return Some(*som_id);
    }

    let qn = normalize_semantic_key(query);
    if !qn.is_empty() {
        if let Some((som_id, _)) = smap
            .iter()
            .find(|(_, val)| normalize_semantic_key(val.as_str()) == qn)
        {
            return Some(*som_id);
        }
    }

    let ql = query.to_ascii_lowercase();
    if !ql.is_empty() {
        if let Some((som_id, _)) = smap.iter().find(|(_, val)| {
            let v = val.to_ascii_lowercase();
            v.ends_with(&format!("_{}", ql)) || v.contains(&format!("_{}_", ql))
        }) {
            return Some(*som_id);
        }
        if let Some((som_id, _)) = smap
            .iter()
            .find(|(_, val)| val.to_ascii_lowercase().contains(&ql))
        {
            return Some(*som_id);
        }
    }

    None
}

async fn click_by_som_id(
    exec: &ToolExecutor,
    som_id: u32,
    som_map: Option<&BTreeMap<u32, (i32, i32, i32, i32)>>,
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
                    MouseButton::Left,
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
                    MouseButton::Left,
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

pub(super) async fn exec_click(
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

pub(super) async fn click_element_by_id(
    exec: &ToolExecutor,
    id: &str,
    active_lens: Option<&str>,
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
        exec_click(exec, MouseButton::Left, target, resolved, transform, None).await
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
            exec_click(exec, MouseButton::Left, target, resolved, transform, None).await
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
            exec_click(exec, MouseButton::Left, target, resolved, transform, None).await
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

fn find_center_of_element(node: &AccessibilityNode, id: &str) -> Option<(i32, i32)> {
    if node.id == id && node.is_visible {
        let cx = node.rect.x + (node.rect.width / 2);
        let cy = node.rect.y + (node.rect.height / 2);
        return Some((cx, cy));
    }
    for child in &node.children {
        if let Some(coords) = find_center_of_element(child, id) {
            return Some(coords);
        }
    }
    None
}

fn find_center_by_query(node: &AccessibilityNode, query: &str) -> Option<(i32, i32)> {
    let matches = node.find_matches(query);
    if matches.is_empty() {
        return None;
    }

    let query_norm = normalize_semantic_key(query);
    let query_lc = query.to_ascii_lowercase();

    let mut best: Option<(i32, (i32, i32))> = None;
    for (id, role, label, rect) in matches {
        if rect.width <= 0 || rect.height <= 0 {
            continue;
        }

        let mut score = 0i32;
        let id_lc = id.to_ascii_lowercase();
        let label_lc = label.to_ascii_lowercase();

        if id_lc == query_lc {
            score += 100;
        }
        if label_lc == query_lc {
            score += 90;
        }
        if !query_norm.is_empty() && normalize_semantic_key(&id) == query_norm {
            score += 80;
        }
        if !query_norm.is_empty() && normalize_semantic_key(&label) == query_norm {
            score += 70;
        }
        if id_lc.ends_with(&format!("_{}", query_lc)) {
            score += 40;
        }
        if role.to_ascii_lowercase().contains("button") {
            score += 20;
        }

        let cx = rect.x + (rect.width / 2);
        let cy = rect.y + (rect.height / 2);
        let candidate = (score, (cx, cy));
        if best.as_ref().map(|(s, _)| candidate.0 > *s).unwrap_or(true) {
            best = Some(candidate);
        }
    }

    best.map(|(_, center)| center)
}

fn is_generic_number_query(query: &str) -> bool {
    let q = query.trim().to_ascii_lowercase();
    if q.is_empty() {
        return false;
    }

    q == "number"
        || q == "digit"
        || q == "num"
        || q == "any number"
        || q == "a number"
        || q.contains("number key")
        || q.contains("digit key")
}

fn extract_single_digit_token(node: &AccessibilityNode) -> Option<char> {
    let mut candidates: Vec<String> = Vec::new();

    candidates.push(node.id.clone());
    if let Some(name) = node.name.as_deref() {
        candidates.push(name.to_string());
    }
    if let Some(value) = node.value.as_deref() {
        candidates.push(value.to_string());
    }

    for key in [
        "semantic_id",
        "semantic_aliases",
        "aria-label",
        "title",
        "description",
    ] {
        if let Some(v) = node.attributes.get(key) {
            candidates.push(v.clone());
        }
    }

    for raw in candidates {
        for token in raw
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .flat_map(|part| part.split('_'))
        {
            let trimmed = token.trim();
            if trimmed.len() == 1 {
                if let Some(ch) = trimmed.chars().next() {
                    if ch.is_ascii_digit() {
                        return Some(ch);
                    }
                }
            }
        }
    }

    None
}

fn find_center_for_numeric_query(node: &AccessibilityNode, query: &str) -> Option<(i32, i32)> {
    if !is_generic_number_query(query) {
        return None;
    }

    let mut best: Option<(i32, (i32, i32))> = None;
    let mut stack = vec![node];

    while let Some(current) = stack.pop() {
        if current.is_visible
            && current.rect.width > 0
            && current.rect.height > 0
            && extract_single_digit_token(current).is_some()
        {
            let mut score = 0i32;
            let role_lc = current.role.to_ascii_lowercase();

            if role_lc.contains("button") || role_lc.contains("push button") {
                score += 50;
            } else if role_lc.contains("list item") || role_lc.contains("menu item") {
                score += 20;
            }

            if (20..=150).contains(&current.rect.width) && (20..=150).contains(&current.rect.height)
            {
                score += 35;
            } else if current.rect.width >= 12 && current.rect.height >= 12 {
                score += 10;
            }

            if current.name.as_deref().is_some_and(|n| {
                n.trim().len() == 1 && n.trim().chars().all(|c| c.is_ascii_digit())
            }) {
                score += 30;
            }
            if current.value.as_deref().is_some_and(|v| {
                v.trim().len() == 1 && v.trim().chars().all(|c| c.is_ascii_digit())
            }) {
                score += 25;
            }

            if current.id.to_ascii_lowercase().starts_with("btn_") {
                score += 15;
            }

            let cx = current.rect.x + (current.rect.width / 2);
            let cy = current.rect.y + (current.rect.height / 2);
            let candidate = (score, (cx, cy));

            if best.as_ref().map(|(s, _)| candidate.0 > *s).unwrap_or(true) {
                best = Some(candidate);
            }
        }

        for child in &current.children {
            stack.push(child);
        }
    }

    best.map(|(_, center)| center)
}

fn tokenize_query_terms(input: &str) -> Vec<String> {
    input
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|token| token.len() >= 2)
        .map(|token| token.to_ascii_lowercase())
        .collect()
}

fn find_closest_matches(node: &AccessibilityNode, query: &str) -> Vec<String> {
    let query_lc = query.trim().to_ascii_lowercase();
    if query_lc.is_empty() {
        return Vec::new();
    }

    let query_norm = normalize_semantic_key(&query_lc);
    let query_terms = tokenize_query_terms(&query_lc);
    let min_score = if query_lc.len() <= 2 { 70 } else { 35 };

    let mut best_by_id: BTreeMap<String, (i32, String)> = BTreeMap::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.is_visible {
            let id_lc = current.id.to_ascii_lowercase();
            let name = current.name.as_deref().unwrap_or("").trim();
            let value = current.value.as_deref().unwrap_or("").trim();
            let label = if !name.is_empty() { name } else { value };
            let label_lc = label.to_ascii_lowercase();
            let aliases = current
                .attributes
                .get("semantic_aliases")
                .map(String::as_str)
                .unwrap_or("");
            let aliases_lc = aliases.to_ascii_lowercase();

            let mut score = 0i32;
            if id_lc == query_lc {
                score += 120;
            }
            if !label_lc.is_empty() && label_lc == query_lc {
                score += 110;
            }
            if id_lc.contains(&query_lc) {
                score += 80;
            }
            if !label_lc.is_empty() && label_lc.contains(&query_lc) {
                score += 70;
            }
            if !aliases_lc.is_empty() && aliases_lc.contains(&query_lc) {
                score += 65;
            }

            if !query_norm.is_empty() {
                let id_norm = normalize_semantic_key(&current.id);
                if id_norm == query_norm {
                    score += 75;
                } else if id_norm.contains(&query_norm) {
                    score += 50;
                }

                if !label_lc.is_empty() {
                    let label_norm = normalize_semantic_key(label);
                    if label_norm == query_norm {
                        score += 70;
                    } else if label_norm.contains(&query_norm) {
                        score += 45;
                    }
                }
            }

            if !query_terms.is_empty() {
                let haystack = format!("{} {} {}", id_lc, label_lc, aliases_lc);
                for term in &query_terms {
                    if haystack.contains(term) {
                        score += 12;
                    }
                }
            }

            if current.role.to_ascii_lowercase().contains("button") {
                score += 5;
            }

            if score >= min_score {
                let display_label = if label.is_empty() { "-" } else { label };
                let display = format!(
                    "{} (role={}, label='{}')",
                    current.id, current.role, display_label
                );
                match best_by_id.get(&current.id) {
                    Some((existing_score, _)) if *existing_score >= score => {}
                    _ => {
                        best_by_id.insert(current.id.clone(), (score, display));
                    }
                }
            }
        }

        for child in &current.children {
            stack.push(child);
        }
    }

    let mut ranked: Vec<(i32, String)> = best_by_id.into_values().collect();
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.len().cmp(&b.1.len())));
    ranked
        .into_iter()
        .map(|(_, display)| display)
        .take(5)
        .collect()
}

async fn find_element_coordinates(exec: &ToolExecutor, query: &str) -> ToolExecutionResult {
    let tree = fetch_tree_direct()
        .await
        .unwrap_or_else(|_| AccessibilityNode {
            id: "root".into(),
            role: "root".into(),
            name: None,
            value: None,
            rect: Rect {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
            },
            children: vec![],
            is_visible: true,
            attributes: Default::default(),
            som_id: None,
        });

    let matches = tree.find_matches(query);
    if matches.is_empty() {
        return ToolExecutionResult::failure(format!("No element found matching '{}'", query));
    }

    // Return first match
    let (id, _, _, rect) = &matches[0];
    let cx = rect.x + (rect.width / 2);
    let cy = rect.y + (rect.height / 2);

    ToolExecutionResult::success(format!("Found '{}' at ({}, {}). ID: {}", query, cx, cy, id))
}
