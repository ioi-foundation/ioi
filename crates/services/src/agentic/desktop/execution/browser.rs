// Path: crates/services/src/agentic/desktop/execution/browser.rs

use super::{GroundingDebug, ToolExecutionResult, ToolExecutor};
use ioi_api::vm::drivers::gui::{InputEvent, MouseButton};
use ioi_drivers::gui::geometry::{CoordinateSpace, Point};
use ioi_drivers::gui::operator::{ClickTarget, NativeOperator};
use ioi_types::app::agentic::AgentTool;

pub async fn handle(exec: &ToolExecutor, tool: AgentTool) -> ToolExecutionResult {
    match tool {
        AgentTool::BrowserNavigate { url, context } => {
            match exec.browser.navigate(&url, &context).await {
                Ok(content) => ToolExecutionResult::success(format!(
                    "Navigated to {} [{}]. Content len: {}",
                    url,
                    context,
                    content.len()
                )),
                Err(e) => ToolExecutionResult::failure(format!("Navigation failed: {}", e)),
            }
        }
        AgentTool::BrowserExtract {} => match exec.browser.extract_dom().await {
            Ok(dom) => ToolExecutionResult::success(dom),
            Err(e) => ToolExecutionResult::failure(format!("Extraction failed: {}", e)),
        },
        AgentTool::BrowserClick { selector } => {
            match exec.browser.resolve_selector_screen_point(&selector).await {
                Ok(screen_pt) => {
                    let x = screen_pt.x.max(0.0).round() as u32;
                    let y = screen_pt.y.max(0.0).round() as u32;
                    let event = InputEvent::Click {
                        button: MouseButton::Left,
                        x,
                        y,
                        expected_visual_hash: None,
                    };
                    match exec.gui.inject_input(event).await {
                        Ok(_) => ToolExecutionResult::success(format!(
                            "Clicked '{}' at ScreenLogical({}, {})",
                            selector, x, y
                        )),
                        Err(e) => {
                            let debug = GroundingDebug {
                                transform: NativeOperator::current_display_transform(),
                                target: ClickTarget::Exact(Point::new(
                                    x as f64,
                                    y as f64,
                                    CoordinateSpace::ScreenLogical,
                                )),
                                resolved_point: Point::new(
                                    x as f64,
                                    y as f64,
                                    CoordinateSpace::ScreenLogical,
                                ),
                                debug_image_path: String::new(),
                            };
                            let debug_path = exec.emit_grounding_debug_packet(debug).await;
                            let mut msg =
                                format!("Browser click injection failed for '{}': {}", selector, e);
                            if let Some(path) = debug_path {
                                msg.push_str(&format!(" [grounding_debug={}]", path));
                            }
                            ToolExecutionResult::failure(msg)
                        }
                    }
                }
                Err(resolve_err) => match exec.browser.click_selector(&selector).await {
                    Ok(_) => ToolExecutionResult::success(format!(
                        "Clicked '{}' via CDP fallback (resolve error: {})",
                        selector, resolve_err
                    )),
                    Err(click_err) => ToolExecutionResult::failure(format!(
                        "Click failed (resolve: {}, cdp: {})",
                        resolve_err, click_err
                    )),
                },
            }
        }
        AgentTool::BrowserSyntheticClick { x, y } => {
            match exec.browser.synthetic_click(x as f64, y as f64).await {
                Ok(_) => ToolExecutionResult::success(format!("Clicked at ({}, {})", x, y)),
                Err(e) => ToolExecutionResult::failure(format!("Synthetic click failed: {}", e)),
            }
        }
        _ => ToolExecutionResult::failure("Unsupported Browser action"),
    }
}
