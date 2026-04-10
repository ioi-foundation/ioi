use ioi_types::app::agentic::AgentTool;

pub(super) fn is_deterministic_tool_name(name: &str) -> bool {
    AgentTool::is_reserved_tool_name(name)
}

pub(super) fn canonical_deterministic_tool_name(name: &str) -> Option<String> {
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

    // Accept common single-separator aliases produced by some models, for example:
    // sys_exec -> sys__exec, browser_click -> browser__click.
    if !normalized.contains("__") {
        if let Some((namespace, rest)) = normalized.split_once('_') {
            let candidate = format!("{}__{}", namespace, rest);
            if is_deterministic_tool_name(&candidate) {
                return Some(candidate);
            }
        }
        if let Some((namespace, rest)) = normalized.split_once("::") {
            let candidate = format!("{}__{}", namespace, rest);
            if is_deterministic_tool_name(&candidate) {
                return Some(candidate);
            }
        }
        if let Some((namespace, rest)) = normalized.split_once(':') {
            let candidate = format!("{}__{}", namespace, rest);
            if is_deterministic_tool_name(&candidate) {
                return Some(candidate);
            }
        }
        if let Some((namespace, rest)) = normalized.split_once('.') {
            let candidate = format!("{}__{}", namespace, rest);
            if is_deterministic_tool_name(&candidate) {
                return Some(candidate);
            }
        }
    }

    None
}
