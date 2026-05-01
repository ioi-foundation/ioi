use super::reset_for_new_user_goal;
use crate::agentic::runtime::types::{
    AgentMode, AgentState, AgentStatus, ExecutionTier, PendingSearchCompletion,
};
use ioi_types::app::agentic::{
    IntentCandidateScore, IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState,
};
use std::collections::{BTreeMap, VecDeque};

fn test_state() -> AgentState {
    AgentState {
        session_id: [0u8; 32],
        goal: "old".to_string(),
        transcript_root: [0u8; 32],
        status: AgentStatus::Running,
        step_count: 7,
        max_steps: 16,
        last_action_type: Some("tool".to_string()),
        parent_session_id: None,
        child_session_ids: vec![],
        budget: 10,
        tokens_used: 0,
        consecutive_failures: 0,
        pending_approval: None,
        pending_tool_call: None,
        pending_tool_jcs: None,
        pending_tool_hash: None,
        pending_request_nonce: None,
        pending_visual_hash: None,
        recent_actions: vec![],
        mode: AgentMode::Agent,
        current_tier: ExecutionTier::DomHeadless,
        last_screen_phash: None,
        execution_queue: vec![],
        pending_search_completion: Some(PendingSearchCompletion::default()),
        planner_state: None,
        active_skill_hash: None,
        tool_execution_log: BTreeMap::new(),
        execution_ledger: Default::default(),
        visual_som_map: None,
        visual_semantic_map: None,
        work_graph_context: None,
        target: None,
        resolved_intent: Some(ResolvedIntentState {
            intent_id: "conversation.reply".to_string(),
            scope: IntentScopeProfile::Conversation,
            band: IntentConfidenceBand::High,
            score: 1.0,
            top_k: vec![IntentCandidateScore {
                intent_id: "conversation.reply".to_string(),
                score: 1.0,
            }],
            required_capabilities: vec![],
            required_evidence: vec![],
            success_conditions: vec![],
            risk_class: "low".to_string(),
            preferred_tier: "tool_first".to_string(),
            intent_catalog_version: "intent-catalog-v2".to_string(),
            embedding_model_id: "test".to_string(),
            embedding_model_version: "test".to_string(),
            similarity_function_id: "cosine".to_string(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: "v1".to_string(),
            intent_catalog_source_hash: [0u8; 32],
            evidence_requirements_hash: [0u8; 32],
            provider_selection: None,
            instruction_contract: None,
            constrained: false,
        }),
        awaiting_intent_clarification: true,
        working_directory: ".".to_string(),
        command_history: VecDeque::new(),
        active_lens: None,
    }
}

#[test]
fn reset_for_new_user_goal_refreshes_target_and_intent_state() {
    let mut state = test_state();
    reset_for_new_user_goal(&mut state, "open calculator");

    assert_eq!(state.goal, "open calculator");
    assert_eq!(
        state
            .target
            .as_ref()
            .and_then(|target| target.app_hint.as_deref()),
        Some("calculator")
    );
    assert!(state.resolved_intent.is_none());
    assert!(!state.awaiting_intent_clarification);
    assert_eq!(state.step_count, 0);
    assert!(state.last_action_type.is_none());
    assert!(state.pending_search_completion.is_none());
}
