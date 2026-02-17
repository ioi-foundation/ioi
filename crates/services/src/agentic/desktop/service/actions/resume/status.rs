use crate::agentic::desktop::types::AgentStatus;

/// String representation used in event emission (drops any payload inside enum variants).
pub(super) fn status_str(status: &AgentStatus) -> String {
    format!("{:?}", status)
        .split('(')
        .next()
        .unwrap_or("Unknown")
        .to_string()
}
