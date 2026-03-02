use ioi_types::app::agentic::AgentTool;

pub(super) fn is_deterministic_tool_name(name: &str) -> bool {
    AgentTool::is_reserved_tool_name(name)
}
