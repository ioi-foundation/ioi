use super::super::{no_visual, ActionExecutionOutcome};

pub(crate) fn handle_chat_reply_tool(message: String) -> ActionExecutionOutcome {
    no_visual(true, Some(format!("Replied: {}", message)), None)
}
