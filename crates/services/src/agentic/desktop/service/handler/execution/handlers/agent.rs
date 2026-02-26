use super::super::{no_visual, ActionExecutionOutcome};

pub(crate) fn handle_agent_delegate_tool(goal: String, budget: u64) -> ActionExecutionOutcome {
    // Orchestration is stateful; spawning the child session is handled in the step layer
    // so receipts + session state mutations remain atomic and auditable.
    let _ = (goal, budget);
    no_visual(true, None, None)
}

pub(crate) fn handle_agent_await_tool() -> ActionExecutionOutcome {
    no_visual(true, None, None)
}

pub(crate) fn handle_agent_pause_tool() -> ActionExecutionOutcome {
    no_visual(true, None, None)
}

pub(crate) fn handle_agent_complete_tool() -> ActionExecutionOutcome {
    no_visual(true, None, None)
}

pub(crate) fn handle_commerce_checkout_tool() -> ActionExecutionOutcome {
    no_visual(
        true,
        Some("System: Initiated UCP Checkout (Pending Guardian Approval)".to_string()),
        None,
    )
}
