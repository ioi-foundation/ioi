// Path: crates/services/src/agentic/runtime/execution/mcp.rs

use super::{ToolExecutionResult, ToolExecutor};
use serde_json::Value;

pub async fn handle(exec: &ToolExecutor, raw_json: Value) -> ToolExecutionResult {
    if let Some(name) = raw_json.get("name").and_then(|s| s.as_str()) {
        let args = raw_json
            .get("arguments")
            .cloned()
            .unwrap_or(serde_json::json!({}));

        match exec
            .mcp
            .execute_tool_with_result(name, args, exec.workload_spec.as_ref())
            .await
        {
            Ok(result) => ToolExecutionResult::success(result.result.to_string()),
            Err(e) => ToolExecutionResult::failure(format!("MCP Error: {}", e)),
        }
    } else {
        ToolExecutionResult::failure("Missing tool name in dynamic call")
    }
}
