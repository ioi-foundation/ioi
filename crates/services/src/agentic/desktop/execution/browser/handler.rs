use super::super::{ToolExecutionResult, ToolExecutor};
use super::element_click::handle_browser_click_element;
use super::selector_click::handle_browser_click;
use super::tree::{apply_browser_auto_lens, detect_human_challenge, render_browser_tree_xml};
use ioi_types::app::agentic::AgentTool;

pub async fn handle(exec: &ToolExecutor, tool: AgentTool) -> ToolExecutionResult {
    match tool {
        AgentTool::BrowserNavigate { url } => match exec.browser.navigate(&url).await {
            Ok(content) => {
                if let Some(reason) = detect_human_challenge(&url, &content) {
                    return ToolExecutionResult::failure(format!(
                        "ERROR_CLASS=HumanChallengeRequired {}. Complete the challenge manually in your own browser/app, then resume: {}",
                        reason, url
                    ));
                }

                ToolExecutionResult::success(format!(
                    "Navigated to {}. Content len: {}",
                    url,
                    content.len()
                ))
            }
            Err(e) => ToolExecutionResult::failure(format!("Navigation failed: {}", e)),
        },
        AgentTool::BrowserSnapshot {} => match exec.browser.get_accessibility_tree().await {
            Ok(raw_tree) => {
                let transformed = apply_browser_auto_lens(raw_tree);
                ToolExecutionResult::success(render_browser_tree_xml(&transformed))
            }
            Err(e) => ToolExecutionResult::failure(format!("Extraction failed: {}", e)),
        },
        AgentTool::BrowserClick { selector } => handle_browser_click(exec, &selector).await,
        AgentTool::BrowserClickElement { id } => handle_browser_click_element(exec, &id).await,
        AgentTool::BrowserSyntheticClick { x, y } => {
            match exec.browser.synthetic_click(x as f64, y as f64).await {
                Ok(_) => ToolExecutionResult::success(format!("Clicked at ({}, {})", x, y)),
                Err(e) => ToolExecutionResult::failure(format!("Synthetic click failed: {}", e)),
            }
        }
        AgentTool::BrowserScroll { delta_x, delta_y } => {
            match exec.browser.scroll(delta_x, delta_y).await {
                Ok(_) => ToolExecutionResult::success(format!(
                    "Scrolled browser by ({}, {})",
                    delta_x, delta_y
                )),
                Err(e) => ToolExecutionResult::failure(format!("Browser scroll failed: {}", e)),
            }
        }
        AgentTool::BrowserType { text, selector } => {
            match exec.browser.type_text(&text, selector.as_deref()).await {
                Ok(_) => ToolExecutionResult::success(format!("Typed '{}' into browser", text)),
                Err(e) => ToolExecutionResult::failure(format!("Browser type failed: {}", e)),
            }
        }
        AgentTool::BrowserKey { key } => match exec.browser.press_key(&key).await {
            Ok(_) => ToolExecutionResult::success(format!("Pressed '{}' in browser", key)),
            Err(e) => ToolExecutionResult::failure(format!("Browser key press failed: {}", e)),
        },
        _ => ToolExecutionResult::failure("Unsupported Browser action"),
    }
}
