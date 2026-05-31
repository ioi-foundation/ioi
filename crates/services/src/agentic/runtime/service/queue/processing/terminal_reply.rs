pub(super) use crate::agentic::runtime::service::output::terminal_reply_shape::{
    observe_terminal_chat_reply_shape, terminal_chat_reply_layout_profile,
};

pub(super) fn is_absorbed_pending_web_read_gate(tool_name: &str, output: Option<&str>) -> bool {
    tool_name == "web__read"
        && output
            .map(|value| {
                value.starts_with("Recorded gated source in fixed payload (no approval retries): ")
            })
            .unwrap_or(false)
}

#[cfg(test)]
#[path = "terminal_reply/tests.rs"]
mod tests;
