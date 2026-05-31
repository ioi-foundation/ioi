use crate::agentic::runtime::service::decision_loop::helpers::is_mailbox_connector_goal;
use crate::agentic::runtime::service::recovery::anti_loop::{
    build_state_summary, choose_routing_tier, TierRoutingDecision,
};
use crate::agentic::runtime::types::AgentState;
use ioi_types::app::agentic::{IntentScopeProfile, RuntimeRouteFrame};
use ioi_types::app::RoutingStateSummary;

/// Applies parity routing for queued actions and snapshots the pre-state after
/// tier selection so evidence and executor context stay coherent.
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
    if agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| resolved.scope == IntentScopeProfile::WebResearch)
        .unwrap_or(false)
    {
        return true;
    }

    agent_state
        .runtime_route_frame
        .as_ref()
        .map(runtime_route_frame_requires_web_research)
        .unwrap_or(false)
}

fn runtime_route_frame_requires_web_research(frame: &RuntimeRouteFrame) -> bool {
    frame.intent_id.eq_ignore_ascii_case("retrieval.answer")
        || route_token_requires_web_research(&frame.route_family)
        || route_token_requires_web_research(frame.target_kind.as_deref().unwrap_or_default())
        || frame.required_capabilities.iter().any(|capability| {
            let normalized = capability.to_ascii_lowercase();
            normalized.contains("web.")
                || normalized.contains("web_")
                || normalized.contains("web__")
                || normalized.contains("retrieval")
                || normalized.contains("source_grounding")
        })
}

fn route_token_requires_web_research(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized == "web_research"
        || normalized == "research"
        || normalized == "retrieval"
        || normalized.contains("web_research")
        || normalized.contains("source")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route_frame(intent_id: &str, route_family: &str) -> RuntimeRouteFrame {
        RuntimeRouteFrame {
            intent_id: intent_id.to_string(),
            route_family: route_family.to_string(),
            output_intent: "tool_execution".to_string(),
            direct_answer_allowed: false,
            target: "Find current sources".to_string(),
            target_kind: Some("agent".to_string()),
            host_mutation: false,
            required_capabilities: vec![],
            typed_evidence: vec![],
            typed_required_capabilities: vec![],
            host_mutation_scope: None,
            runtime_action: None,
            install_request: None,
            provenance: None,
        }
    }

    #[test]
    fn typed_web_research_route_frame_counts_as_web_research_scope() {
        assert!(runtime_route_frame_requires_web_research(&route_frame(
            "retrieval.answer",
            "web_research"
        )));
        assert!(runtime_route_frame_requires_web_research(&route_frame(
            "conversation.reply",
            "research"
        )));
    }

    #[test]
    fn ordinary_conversation_route_frame_is_not_web_research_scope() {
        assert!(!runtime_route_frame_requires_web_research(&route_frame(
            "conversation.reply",
            "conversation"
        )));
    }
}
