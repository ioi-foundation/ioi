use super::super::{no_visual, ActionExecutionOutcome};

pub(crate) fn handle_agent_delegate_tool(
    goal: String,
    budget: u64,
    playbook_id: Option<String>,
    template_id: Option<String>,
    workflow_id: Option<String>,
    role: Option<String>,
    success_criteria: Option<String>,
    merge_mode: Option<String>,
    expected_output: Option<String>,
) -> ActionExecutionOutcome {
    // Orchestration is stateful; spawning the child session is handled in the step layer
    // so receipts + session state mutations remain atomic and auditable.
    let _ = (
        goal,
        budget,
        playbook_id,
        template_id,
        workflow_id,
        role,
        success_criteria,
        merge_mode,
        expected_output,
    );
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
