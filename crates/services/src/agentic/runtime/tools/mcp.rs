use ioi_drivers::mcp::McpManager;
use ioi_types::app::agentic::LlmToolDefinition;
use std::collections::HashSet;

pub(super) async fn push_mcp_tools(
    mcp: &McpManager,
    tools: &mut Vec<LlmToolDefinition>,
    mcp_tool_names: &mut HashSet<String>,
) {
    // MCP Tool Discovery (External Tool Servers)
    // Prefer cached definitions from the MCP manager so the model sees accurate schemas.
    // Note: we DO NOT override built-in tool names (file__/browser__/shell__/etc) since
    // those are strictly typed in `AgentTool` and are executed by deterministic adapters.
    let mcp_tools = mcp.get_all_tools().await;
    for tool in mcp_tools {
        if tools.iter().any(|t| t.name == tool.name) {
            continue;
        }
        mcp_tool_names.insert(tool.name.clone());
        tools.push(tool);
    }
}
