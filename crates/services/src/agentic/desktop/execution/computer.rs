// Path: crates/services/src/agentic/desktop/execution/computer.rs

use super::{GroundingDebug, ToolExecutionResult, ToolExecutor};
use ioi_api::vm::drivers::gui::{AtomicInput, InputEvent, MouseButton};
use ioi_drivers::gui::accessibility::{AccessibilityNode, Rect};
use ioi_drivers::gui::geometry::{CoordinateSpace, DisplayTransform, Point};
use ioi_drivers::gui::operator::{ClickTarget, NativeOperator};
use ioi_drivers::gui::platform::fetch_tree_direct;
use ioi_types::app::agentic::{AgentTool, ComputerAction};
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
            click_element_by_id(exec, &id, active_lens).await
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
                ToolExecutionResult::failure("Missing coordinates for left_click")
            }
        }
        ComputerAction::LeftClickId { id } => {
            if let Some(result) = click_by_som_id(exec, id, som_map).await {
                return result;
            }

            if let Some(smap) = semantic_map {
                if let Some(semantic_id) = smap.get(&id) {
                    let fallback = click_element_by_id(exec, semantic_id, active_lens).await;
                    if fallback.success {
                        return fallback;
                    }
                }
            }

            ToolExecutionResult::failure(format!("SoM ID {} not found in visual context", id))
        }
        ComputerAction::LeftClickElement { id } => {
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
            click_element_by_id(exec, &id, active_lens).await
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
        _ => ToolExecutionResult::failure("Action not implemented in refactor"),
    }
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

async fn exec_click(
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
        expected_visual_hash,
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

async fn click_element_by_id(
    exec: &ToolExecutor,
    id: &str,
    active_lens: Option<&str>,
) -> ToolExecutionResult {
    // Fetch live tree
    let raw_tree = match fetch_tree_direct().await {
        Ok(t) => t,
        Err(e) => return ToolExecutionResult::failure(format!("Failed to fetch UI tree: {}", e)),
    };

    // Apply lens if known
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
        } else {
            ToolExecutionResult::failure(format!("Element '{}' not found or not visible", id))
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
