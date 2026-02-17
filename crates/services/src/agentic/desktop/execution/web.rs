// Path: crates/services/src/agentic/desktop/execution/web.rs

use super::{ToolExecutionResult, ToolExecutor};
use ioi_types::app::agentic::AgentTool;

pub async fn handle(exec: &ToolExecutor, tool: AgentTool) -> ToolExecutionResult {
    match tool {
        AgentTool::WebSearch { query, limit, .. } => {
            let limit = limit.unwrap_or(5).clamp(1, 10);
            match crate::agentic::web::edge_web_search(&exec.browser, &query, limit).await {
                Ok(bundle) => match serde_json::to_string_pretty(&bundle) {
                    Ok(out) => ToolExecutionResult::success(out),
                    Err(e) => ToolExecutionResult::failure(format!(
                        "ERROR_CLASS=SerializationFailed Failed to serialize web evidence: {}",
                        e
                    )),
                },
                Err(e) => ToolExecutionResult::failure(e.to_string()),
            }
        }
        AgentTool::WebRead { url, max_chars } => {
            let max_chars = Some(max_chars.unwrap_or(12_000));
            match crate::agentic::web::edge_web_read(&exec.browser, &url, max_chars).await {
                Ok(bundle) => match serde_json::to_string_pretty(&bundle) {
                    Ok(out) => ToolExecutionResult::success(out),
                    Err(e) => ToolExecutionResult::failure(format!(
                        "ERROR_CLASS=SerializationFailed Failed to serialize web evidence: {}",
                        e
                    )),
                },
                Err(e) => ToolExecutionResult::failure(e.to_string()),
            }
        }
        other => {
            ToolExecutionResult::failure(format!("Tool {:?} not handled by web executor", other))
        }
    }
}
