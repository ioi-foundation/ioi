use crate::agentic::runtime::service::step::signals::infer_interaction_target;
use crate::agentic::runtime::types::AgentState;

mod approval_authority;
mod operator_control;
mod post_message;
mod resume;
mod session_delete;
mod start;

pub use approval_authority::{
    handle_register_approval_authority, handle_revoke_approval_authority,
};
pub use operator_control::{handle_cancel, handle_deny, handle_pause};
pub use post_message::handle_post_message;
pub use resume::handle_resume;
pub use session_delete::handle_delete_session;
pub use start::handle_start;

fn reset_for_new_user_goal(agent_state: &mut AgentState, goal: &str) {
    agent_state.goal = goal.to_string();
    agent_state.target = infer_interaction_target(goal);
    agent_state.resolved_intent = None;
    agent_state.awaiting_intent_clarification = false;
    agent_state.step_count = 0;
    agent_state.last_action_type = None;
    agent_state.pending_search_completion = None;
}

#[cfg(test)]
mod tests;
