use super::browser_snapshot_completion;
use crate::agentic::runtime::types::{AgentMode, AgentState, ExecutionTier};
use ioi_types::app::agentic::{
    CapabilityId, InstructionContract, InstructionSideEffectMode, IntentConfidenceBand,
    IntentScopeProfile, ResolvedIntentState,
};
use std::collections::{BTreeMap, VecDeque};

fn resolved_ui_interaction(
    side_effect_mode: InstructionSideEffectMode,
    success_criteria: Vec<&str>,
) -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "ui.interaction".to_string(),
        scope: IntentScopeProfile::UiInteraction,
        band: IntentConfidenceBand::High,
        score: 1.0,
        top_k: vec![],
        required_capabilities: vec![CapabilityId::from("ui.interact")],
        required_evidence: vec![],
        success_conditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "visual_last".to_string(),
        intent_catalog_version: "test".to_string(),
        embedding_model_id: String::new(),
        embedding_model_version: String::new(),
        similarity_function_id: String::new(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: String::new(),
        intent_catalog_source_hash: [0u8; 32],
        evidence_requirements_hash: [0u8; 32],
        provider_selection: None,
        instruction_contract: Some(InstructionContract {
            operation: "click".to_string(),
            side_effect_mode,
            slot_bindings: vec![],
            negative_constraints: vec![],
            success_criteria: success_criteria.into_iter().map(str::to_string).collect(),
        }),
        constrained: false,
    }
}

fn agent_state_with_resolved_intent(resolved_intent: ResolvedIntentState) -> AgentState {
    AgentState {
        session_id: [9u8; 32],
        goal: "Click Mark complete so the status becomes done.".to_string(),
        transcript_root: [0u8; 32],
        status: crate::agentic::runtime::types::AgentStatus::Running,
        step_count: 0,
        max_steps: 8,
        last_action_type: None,
        parent_session_id: None,
        child_session_ids: vec![],
        budget: 0,
        tokens_used: 0,
        consecutive_failures: 0,
        pending_approval: None,
        pending_tool_call: None,
        pending_tool_jcs: None,
        pending_tool_hash: None,
        pending_request_nonce: None,
        pending_visual_hash: None,
        recent_actions: vec![],
        mode: AgentMode::default(),
        current_tier: ExecutionTier::default(),
        last_screen_phash: None,
        execution_queue: vec![],
        pending_search_completion: None,
        planner_state: None,
        active_skill_hash: None,
        tool_execution_log: BTreeMap::new(),
        execution_ledger: Default::default(),
        visual_som_map: None,
        visual_semantic_map: None,
        work_graph_context: None,
        target: None,
        resolved_intent: Some(resolved_intent),
        awaiting_intent_clarification: false,
        working_directory: ".".to_string(),
        command_history: VecDeque::new(),
        active_lens: None,
    }
}

#[test]
fn browser_snapshot_completion_matches_update_success_criteria() {
    let state = agent_state_with_resolved_intent(resolved_ui_interaction(
        InstructionSideEffectMode::Update,
        vec!["status_text.updated_to_done"],
    ));
    let snapshot = r#"
        <root id="root_dom_fallback_tree">
          <generic id="grp_done" name="done" />
          <button id="btn_mark_complete" name="Mark complete" />
        </root>
    "#;

    let completion =
        browser_snapshot_completion(&state, "browser__inspect", Some(snapshot)).unwrap();
    assert!(completion.summary.contains("operation=click"));
    assert!(completion
        .summary
        .contains("success_criteria=status_text.updated_to_done"));
    assert_eq!(
        completion.matched_success_criteria,
        vec!["status_text.updated_to_done".to_string()]
    );
}

#[test]
fn browser_snapshot_completion_rejects_read_only_contracts() {
    let state = agent_state_with_resolved_intent(resolved_ui_interaction(
        InstructionSideEffectMode::ReadOnly,
        vec!["status_text.updated_to_done"],
    ));
    let snapshot = r#"<root><generic id="grp_done" name="done" /></root>"#;

    assert!(browser_snapshot_completion(&state, "browser__inspect", Some(snapshot)).is_none());
}

#[test]
fn browser_snapshot_completion_rejects_unrecognized_success_criteria() {
    let state = agent_state_with_resolved_intent(resolved_ui_interaction(
        InstructionSideEffectMode::Update,
        vec!["mail.reply.completed"],
    ));
    let snapshot = r#"<root><generic id="grp_done" name="done" /></root>"#;

    assert!(browser_snapshot_completion(&state, "browser__inspect", Some(snapshot)).is_none());
}

#[test]
fn browser_snapshot_completion_requires_ui_interaction_scope() {
    let mut resolved = resolved_ui_interaction(
        InstructionSideEffectMode::Update,
        vec!["status_text.updated_to_done"],
    );
    resolved.scope = IntentScopeProfile::Conversation;
    let state = agent_state_with_resolved_intent(resolved);
    let snapshot = r#"<root><generic id="grp_done" name="done" /></root>"#;

    assert!(browser_snapshot_completion(&state, "browser__inspect", Some(snapshot)).is_none());
}
