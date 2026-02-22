use crate::agentic::desktop::service::step::anti_loop::{
    build_state_summary, choose_routing_tier, TierRoutingDecision,
};
use crate::agentic::desktop::service::step::helpers::{
    is_live_external_research_goal, is_mailbox_connector_goal,
};
use crate::agentic::desktop::types::AgentState;
use ioi_types::app::agentic::IntentScopeProfile;
use ioi_types::app::RoutingStateSummary;

/// Applies parity routing for queued actions and snapshots the pre-state after
/// tier selection so receipts and executor context stay coherent.
pub(super) fn resolve_queue_routing_context(
    agent_state: &mut AgentState,
) -> (TierRoutingDecision, RoutingStateSummary) {
    let routing_decision = choose_routing_tier(agent_state);
    agent_state.current_tier = routing_decision.tier;
    let pre_state_summary = build_state_summary(agent_state);
    (routing_decision, pre_state_summary)
}

pub(super) fn is_web_research_scope(agent_state: &AgentState) -> bool {
    if is_mailbox_connector_goal(&agent_state.goal) {
        return false;
    }
    agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| resolved.scope == IntentScopeProfile::WebResearch)
        .unwrap_or(false)
        || is_live_external_research_goal(&agent_state.goal)
}
