// Path: crates/services/src/agentic/desktop/execution/browser.rs

use super::{ToolExecutionResult, ToolExecutor};
use ioi_types::app::agentic::AgentTool;

pub async fn handle(exec: &ToolExecutor, tool: AgentTool) -> ToolExecutionResult {
    match tool {
        AgentTool::BrowserNavigate { url } => {
            match exec.browser.navigate(&url).await {
                Ok(content) => ToolExecutionResult::success(format!("Navigated to {}. Content len: {}", url, content.len())),
                Err(e) => ToolExecutionResult::failure(format!("Navigation failed: {}", e)),
            }
        }
        AgentTool::BrowserExtract {} => {
            match exec.browser.extract_dom().await {
                Ok(dom) => ToolExecutionResult::success(dom),
                Err(e) => ToolExecutionResult::failure(format!("Extraction failed: {}", e)),
            }
        }
        AgentTool::BrowserClick { selector } => {
            match exec.browser.click_selector(&selector).await {
                Ok(_) => ToolExecutionResult::success(format!("Clicked '{}'", selector)),
                Err(e) => ToolExecutionResult::failure(format!("Click failed: {}", e)),
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