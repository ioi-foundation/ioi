// Path: crates/services/src/agentic/desktop/execution/computer.rs

use super::{ToolExecutionResult, ToolExecutor};
use ioi_api::vm::drivers::gui::{InputEvent, MouseButton, AtomicInput};
use ioi_types::app::agentic::{AgentTool, ComputerAction};
use ioi_drivers::gui::accessibility::{AccessibilityNode, Rect};
use ioi_drivers::gui::platform::fetch_tree_direct;
use anyhow::{anyhow, Result};
use std::collections::BTreeMap;

pub async fn handle(
    exec: &ToolExecutor,
    tool: AgentTool,
    som_map: Option<&BTreeMap<u32, (i32, i32, i32, i32)>>,
    semantic_map: Option<&BTreeMap<u32, String>>,
    active_lens: Option<&str>,
) -> ToolExecutionResult {
    match tool {
        AgentTool::Computer(action) => handle_computer_action(exec, action, som_map, semantic_map).await,
        
        AgentTool::GuiClick { x, y, button } => {
            let btn = match button.as_deref() {
                Some("right") => MouseButton::Right,
                Some("middle") => MouseButton::Middle,
                _ => MouseButton::Left,
            };
            exec_input(exec, InputEvent::Click { 
                button: btn, x, y, expected_visual_hash: None 
            }).await
        }

        AgentTool::GuiType { text } => {
            exec_input(exec, InputEvent::Type { text }).await
        }

        AgentTool::GuiClickElement { id } => {
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
) -> ToolExecutionResult {
    match action {
        ComputerAction::MouseMove { coordinate } => {
            exec_input(exec, InputEvent::MouseMove { x: coordinate[0], y: coordinate[1] }).await
        }
        ComputerAction::LeftClick { coordinate } => {
            if let Some(coord) = coordinate {
                exec_input(exec, InputEvent::Click { 
                    button: MouseButton::Left, x: coord[0], y: coord[1], expected_visual_hash: None 
                }).await
            } else {
                 ToolExecutionResult::failure("Missing coordinates for left_click")
            }
        }
        ComputerAction::LeftClickId { id } => {
             if let Some(map) = som_map {
                 if let Some((x, y, w, h)) = map.get(&id) {
                     let cx = x + (w / 2);
                     let cy = y + (h / 2);
                     let input = InputEvent::Click { 
                        button: MouseButton::Left, 
                        x: cx.max(0) as u32, 
                        y: cy.max(0) as u32, 
                        expected_visual_hash: None 
                    };
                    return exec_input(exec, input).await;
                 }
             }
             ToolExecutionResult::failure(format!("SoM ID {} not found in visual context", id))
        }
        ComputerAction::LeftClickElement { id } => {
            // Reverse lookup: check semantic map if we have the ID from visual processing
            // Otherwise, scan current tree
            if let Some(smap) = semantic_map {
                // Find SoM ID where value == id
                if let Some((som_id, _)) = smap.iter().find(|(_, val)| *val == &id) {
                     if let Some(map) = som_map {
                         if let Some((x, y, w, h)) = map.get(som_id) {
                             let cx = x + (w / 2);
                             let cy = y + (h / 2);
                             let input = InputEvent::Click { 
                                button: MouseButton::Left, 
                                x: cx.max(0) as u32, 
                                y: cy.max(0) as u32, 
                                expected_visual_hash: None 
                            };
                            return exec_input(exec, input).await;
                         }
                     }
                }
            }
            
            // Fallback: Scan tree directly
            click_element_by_id(exec, &id, None).await
        }
        ComputerAction::Type { text } => {
             exec_input(exec, InputEvent::Type { text }).await
        }
        ComputerAction::Key { text } => {
             exec_input(exec, InputEvent::KeyPress { key: text }).await
        }
        ComputerAction::Hotkey { keys } => {
             // Atomic sequence for chords
             let mut steps = Vec::new();
             // Hold modifiers
             for k in &keys[..keys.len()-1] {
                 steps.push(AtomicInput::KeyDown { key: k.clone() });
             }
             // Click final key
             if let Some(last) = keys.last() {
                 steps.push(AtomicInput::KeyPress { key: last.clone() });
             }
             // Release modifiers
             for k in keys[..keys.len()-1].iter().rev() {
                 steps.push(AtomicInput::KeyUp { key: k.clone() });
             }
             exec_input(exec, InputEvent::AtomicSequence(steps)).await
        }
        ComputerAction::DragDrop { from, to } => {
             let steps = vec![
                 AtomicInput::MouseMove { x: from[0], y: from[1] },
                 AtomicInput::MouseDown { button: MouseButton::Left },
                 AtomicInput::Wait { millis: 200 },
                 AtomicInput::MouseMove { x: to[0], y: to[1] },
                 AtomicInput::Wait { millis: 200 },
                 AtomicInput::MouseUp { button: MouseButton::Left },
             ];
             exec_input(exec, InputEvent::AtomicSequence(steps)).await
        }
        ComputerAction::Screenshot => {
             match exec.gui.capture_screen(None).await {
                 Ok(_) => ToolExecutionResult::success("Screenshot captured"),
                 Err(e) => ToolExecutionResult::failure(e.to_string()),
             }
        }
        _ => ToolExecutionResult::failure("Action not implemented in refactor"),
    }
}

async fn exec_input(exec: &ToolExecutor, event: InputEvent) -> ToolExecutionResult {
    match exec.gui.inject_input(event.clone()).await {
        Ok(_) => ToolExecutionResult::success(format!("Input executed: {:?}", event)),
        Err(e) => ToolExecutionResult::failure(format!("Input injection failed: {}", e)),
    }
}

async fn click_element_by_id(exec: &ToolExecutor, id: &str, active_lens: Option<&str>) -> ToolExecutionResult {
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
             } else { raw_tree }
         } else { raw_tree }
    } else { raw_tree };

    // Find center
    if let Some((x, y)) = find_center_of_element(&tree, id) {
        let input = InputEvent::Click { 
            button: MouseButton::Left, 
            x: x as u32, 
            y: y as u32, 
            expected_visual_hash: None 
        };
        exec_input(exec, input).await
    } else {
        ToolExecutionResult::failure(format!("Element '{}' not found or not visible", id))
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

async fn find_element_coordinates(exec: &ToolExecutor, query: &str) -> ToolExecutionResult {
    let tree = fetch_tree_direct().await.unwrap_or_else(|_| AccessibilityNode {
        id: "root".into(), role: "root".into(), name: None, value: None, 
        rect: Rect{x:0,y:0,width:0,height:0}, children: vec![], is_visible: true, 
        attributes: Default::default(), som_id: None 
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