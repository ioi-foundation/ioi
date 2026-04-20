use super::{
    dispatch_next_planner_action, match_dispatched_step_for_execution, record_planner_step_outcome,
    validate_and_hash_planner_state, validate_planner_state, PlannerDispatchMatch,
};
use crate::agentic::runtime::types::{
    AgentMode, AgentState, AgentStatus, ExecutionTier, PlanStep, PlanStepConstraint, PlannerState,
    PlannerStatus, PlannerStepKind, PlannerStepStatus, PLANNER_SCHEMA_VERSION_V1,
};
use ioi_types::app::agentic::{
    CapabilityId, IntentCandidateScore, IntentConfidenceBand, IntentScopeProfile,
    ResolvedIntentState,
};
use std::collections::BTreeMap;

fn resolved_command_intent() -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "command.exec".to_string(),
        scope: IntentScopeProfile::CommandExecution,
        band: IntentConfidenceBand::High,
        score: 0.99,
        top_k: vec![IntentCandidateScore {
            intent_id: "command.exec".to_string(),
            score: 0.99,
        }],
        required_capabilities: vec![CapabilityId::from("command.exec")],
        required_receipts: vec![],
        required_postconditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        matrix_version: "intent-matrix-test".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "v1".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [1u8; 32],
        tool_registry_hash: [2u8; 32],
        capability_ontology_hash: [3u8; 32],
        query_normalization_version: "intent_query_norm_v1".to_string(),
        matrix_source_hash: [4u8; 32],
        receipt_hash: [5u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    }
}

fn resolved_web_intent() -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "web.research".to_string(),
        scope: IntentScopeProfile::WebResearch,
        band: IntentConfidenceBand::High,
        score: 0.99,
        top_k: vec![IntentCandidateScore {
            intent_id: "web.research".to_string(),
            score: 0.99,
        }],
        required_capabilities: vec![CapabilityId::from("browser.interact")],
        required_receipts: vec![],
        required_postconditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        matrix_version: "intent-matrix-test".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "v1".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [1u8; 32],
        tool_registry_hash: [2u8; 32],
        capability_ontology_hash: [3u8; 32],
        query_normalization_version: "intent_query_norm_v1".to_string(),
        matrix_source_hash: [4u8; 32],
        receipt_hash: [5u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    }
}

fn base_planner_state() -> PlannerState {
    PlannerState {
        plan_id: "plan-001".to_string(),
        plan_schema_version: PLANNER_SCHEMA_VERSION_V1.to_string(),
        goal_hash: [7u8; 32],
        intent_receipt_hash: [8u8; 32],
        plan_hash: [0u8; 32],
        discovery_requirements: vec![],
        steps: vec![PlanStep {
            step_id: "step-1".to_string(),
            kind: PlannerStepKind::ToolCallIntent,
            tool_name: Some("shell__run".to_string()),
            arguments_json: Some("{\"b\":2,\"a\":1}".to_string()),
            constraints: PlanStepConstraint {
                max_retries: 1,
                retry_eligible: true,
                requires_approval: false,
                timeout_ms: Some(1000),
            },
            depends_on: vec![],
            status: PlannerStepStatus::Pending,
            receipts: vec![],
        }],
        cursor: 0,
        replan_count: 0,
        status: PlannerStatus::Ready,
        last_replan_reason: None,
        last_batch: vec!["step-1".to_string()],
    }
}

fn test_agent_state() -> AgentState {
    AgentState {
        session_id: [0u8; 32],
        goal: "test".to_string(),
        transcript_root: [0u8; 32],
        status: AgentStatus::Running,
        step_count: 0,
        max_steps: 8,
        last_action_type: None,
        parent_session_id: None,
        child_session_ids: vec![],
        budget: 1,
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
        pending_search_completion: None,
        planner_state: None,
        active_skill_hash: None,
        tool_execution_log: BTreeMap::new(),
        visual_som_map: None,
        visual_semantic_map: None,
        swarm_context: None,
        target: None,
        resolved_intent: None,
        awaiting_intent_clarification: false,
        working_directory: ".".to_string(),
        command_history: Default::default(),
        active_lens: None,
    }
}

#[test]
fn planner_hash_is_stable_across_serde_roundtrip() {
    let resolved = resolved_command_intent();
    let mut state = base_planner_state();
    validate_and_hash_planner_state(&mut state, Some(&resolved))
        .expect("planner state should validate");
    let first_hash = state.plan_hash;

    let raw = serde_json::to_vec(&state).expect("serialize planner");
    let mut roundtrip: PlannerState = serde_json::from_slice(&raw).expect("deserialize planner");
    validate_and_hash_planner_state(&mut roundtrip, Some(&resolved))
        .expect("roundtrip planner should validate");
    assert_eq!(first_hash, roundtrip.plan_hash);
}

#[test]
fn planner_validation_rejects_disallowed_tools_for_resolved_intent() {
    let resolved = resolved_command_intent();
    let mut state = base_planner_state();
    state.steps[0].tool_name = Some("chat__reply".to_string());
    let err = validate_planner_state(&state, Some(&resolved))
        .expect_err("chat__reply should be blocked for command.exec required capabilities");
    assert!(err.to_string().contains("ERROR_CLASS=PolicyBlocked"));
}

#[test]
fn planner_validation_rejects_unknown_schema_version() {
    let resolved = resolved_command_intent();
    let mut state = base_planner_state();
    state.plan_schema_version = "planner.v0".to_string();
    let err = validate_planner_state(&state, Some(&resolved))
        .expect_err("unknown planner schema should fail");
    assert!(err.to_string().contains("Unsupported plan schema version"));
}

#[test]
fn planner_validation_rejects_missing_required_fields() {
    let resolved = resolved_command_intent();
    let mut state = base_planner_state();
    state.plan_id = "   ".to_string();
    let err =
        validate_planner_state(&state, Some(&resolved)).expect_err("empty plan_id should fail");
    assert!(err.to_string().contains("plan_id is required"));

    let mut no_steps = base_planner_state();
    no_steps.steps.clear();
    let err =
        validate_planner_state(&no_steps, Some(&resolved)).expect_err("empty plan should fail");
    assert!(err.to_string().contains("at least one step"));
}

#[test]
fn planner_dispatched_step_match_detects_mismatch() {
    let mut state = base_planner_state();
    state.steps[0].status = PlannerStepStatus::Dispatched;
    let tool_args = serde_json::json!({"a": 1, "b": 2});
    let matched = match_dispatched_step_for_execution(&state, "chat__reply", &tool_args)
        .expect("match should evaluate")
        .expect("a dispatched step must be considered");
    match matched {
        PlannerDispatchMatch::Mismatch {
            step_index,
            expected_tool_name,
            ..
        } => {
            assert_eq!(step_index, 0);
            assert_eq!(expected_tool_name, "shell__run");
        }
        other => panic!("expected mismatch, got {:?}", other),
    }
}

#[test]
fn planner_dispatched_step_match_succeeds_for_same_tool_and_args() {
    let mut state = base_planner_state();
    state.steps[0].status = PlannerStepStatus::Dispatched;
    let tool_args = serde_json::json!({"b": 2, "a": 1});
    let matched = match_dispatched_step_for_execution(&state, "shell__run", &tool_args)
        .expect("match should evaluate")
        .expect("a dispatched step must be considered");
    match matched {
        PlannerDispatchMatch::Matched {
            step_index,
            step_id,
        } => {
            assert_eq!(step_index, 0);
            assert_eq!(step_id, "step-1");
        }
        other => panic!("expected match, got {:?}", other),
    }
}

#[test]
fn planner_outcome_marks_success_and_hashes() {
    let resolved = resolved_command_intent();
    let mut state = base_planner_state();
    state.steps[0].status = PlannerStepStatus::Dispatched;
    let original_hash = state.plan_hash;
    record_planner_step_outcome(
        &mut state,
        0,
        true,
        false,
        false,
        None,
        Some("abc"),
        Some(&resolved),
    )
    .expect("outcome update should succeed");
    assert_eq!(state.steps[0].status, PlannerStepStatus::Succeeded);
    assert_eq!(state.status, PlannerStatus::Completed);
    assert_ne!(state.plan_hash, original_hash);
    assert!(state.steps[0]
        .receipts
        .iter()
        .any(|receipt| receipt.contains("execution_request_hash=abc")));
}

#[test]
fn planner_outcome_marks_blocked_without_retry() {
    let resolved = resolved_command_intent();
    let mut state = base_planner_state();
    state.steps[0].status = PlannerStepStatus::Dispatched;
    record_planner_step_outcome(
        &mut state,
        0,
        false,
        true,
        true,
        Some("ERROR_CLASS=PolicyBlocked denied"),
        Some("blocked"),
        Some(&resolved),
    )
    .expect("blocked update should succeed");
    assert_eq!(state.steps[0].status, PlannerStepStatus::Blocked);
    assert_eq!(state.status, PlannerStatus::Blocked);
    assert!(state.steps[0]
        .receipts
        .iter()
        .any(|receipt| receipt.contains("execution_error=ERROR_CLASS=PolicyBlocked")));
}

#[test]
fn planner_dispatch_embeds_browser_tool_name_metadata_for_browser_interact() {
    let resolved = resolved_web_intent();
    let mut planner = base_planner_state();
    planner.steps[0].tool_name = Some("browser__list_options".to_string());
    planner.steps[0].arguments_json = Some(r#"{"selector":"select[name='country']"}"#.to_string());

    let mut agent_state = test_agent_state();
    agent_state.planner_state = Some(planner);

    let dispatched = dispatch_next_planner_action(&mut agent_state, [2u8; 32], 11, Some(&resolved))
        .expect("planner dispatch should succeed");
    assert_eq!(dispatched.as_deref(), Some("step-1"));
    assert_eq!(agent_state.execution_queue.len(), 1);

    let params: serde_json::Value = serde_json::from_slice(&agent_state.execution_queue[0].params)
        .expect("queued params should decode");
    assert_eq!(
        params.get("__ioi_tool_name").and_then(|v| v.as_str()),
        Some("browser__list_options")
    );
}
