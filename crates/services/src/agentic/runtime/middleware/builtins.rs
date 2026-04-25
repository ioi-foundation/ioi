use ioi_types::app::agentic::AgentTool;

pub(crate) fn is_deterministic_tool_name(name: &str) -> bool {
    AgentTool::is_reserved_tool_name(name)
}

pub(crate) fn canonical_deterministic_tool_name(name: &str) -> Option<String> {
    let normalized = name
        .trim_matches(|ch: char| ch == '"' || ch == '\'')
        .trim()
        .to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }

    if is_deterministic_tool_name(&normalized) {
        return Some(normalized);
    }

    None
}
