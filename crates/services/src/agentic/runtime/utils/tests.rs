use super::{
    await_child_session_status_for_inspection, delete_agent_state_checkpoint, get_state_key,
    load_agent_state_checkpoint, persist_agent_state,
    should_terminalize_running_agent_after_max_steps, AGENT_STATE_CHECKPOINT_NAME,
};
use crate::agentic::runtime::keys::get_parent_playbook_run_key;
use crate::agentic::runtime::types::{
    AgentMode, AgentState, AgentStatus, ExecutionTier, ParentPlaybookRun, ParentPlaybookStatus,
};
use ioi_api::state::{StateAccess, StateScanIter};
use ioi_memory::MemoryRuntime;
use ioi_types::app::agentic::{
    ArgumentOrigin, InstructionBindingKind, InstructionContract, InstructionSlotBinding,
    IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState,
};
use ioi_types::codec;
use ioi_types::error::StateError;
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

#[derive(Default)]
struct MockState {
    data: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl StateAccess for MockState {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.data.get(key).cloned())
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.data.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        self.data.remove(key);
        Ok(())
    }

    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        for (key, value) in updates {
            self.insert(key, value)?;
        }
        Ok(())
    }

    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        keys.iter().map(|key| self.get(key)).collect()
    }

    fn batch_apply(
        &mut self,
        inserts: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), StateError> {
        for key in deletes {
            self.delete(key)?;
        }
        for (key, value) in inserts {
            self.insert(key, value)?;
        }
        Ok(())
    }

    fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
        let rows: Vec<_> = self
            .data
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| Ok((Arc::from(key.as_slice()), Arc::from(value.as_slice()))))
            .collect();
        Ok(Box::new(rows.into_iter()))
    }
}

fn test_agent_state(session_id: [u8; 32]) -> AgentState {
    AgentState {
        session_id,
        goal: "checkpoint me".to_string(),
        transcript_root: [7u8; 32],
        status: AgentStatus::Running,
        step_count: 3,
        max_steps: 16,
        last_action_type: Some("click".to_string()),
        parent_session_id: None,
        child_session_ids: vec![],
        budget: 2,
        tokens_used: 0,
        consecutive_failures: 1,
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
        execution_ledger: Default::default(),
        visual_som_map: None,
        visual_semantic_map: None,
        swarm_context: None,
        target: None,
        resolved_intent: None,
        awaiting_intent_clarification: false,
        working_directory: ".".to_string(),
        command_history: VecDeque::new(),
        active_lens: None,
    }
}

fn resolved_web_intent_with_playbook(playbook_id: &str) -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "web.research.latest".to_string(),
        scope: IntentScopeProfile::WebResearch,
        band: IntentConfidenceBand::High,
        score: 0.99,
        top_k: vec![],
        required_capabilities: vec![],
        required_evidence: vec![],
        success_conditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        intent_catalog_version: "intent-catalog-test".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "v1".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [1u8; 32],
        tool_registry_hash: [2u8; 32],
        capability_ontology_hash: [3u8; 32],
        query_normalization_version: "intent-query-norm-v1".to_string(),
        intent_catalog_source_hash: [4u8; 32],
        evidence_requirements_hash: [5u8; 32],
        provider_selection: None,
        instruction_contract: Some(InstructionContract {
            operation: "web.research".to_string(),
            side_effect_mode: Default::default(),
            slot_bindings: vec![InstructionSlotBinding {
                slot: "playbook_id".to_string(),
                binding_kind: InstructionBindingKind::UserLiteral,
                value: Some(playbook_id.to_string()),
                origin: ArgumentOrigin::default(),
                protected_slot_kind: Default::default(),
            }],
            negative_constraints: vec![],
            success_criteria: vec![],
        }),
        constrained: false,
    }
}

#[test]
fn persist_agent_state_mirrors_runtime_checkpoint_blob() {
    let session_id = [9u8; 32];
    let checkpoint_key = b"agent::state::test".to_vec();
    let agent_state = test_agent_state(session_id);
    let expected_bytes = codec::to_bytes_canonical(&agent_state).expect("encode agent state");
    let mut state = MockState::default();
    let runtime = Arc::new(MemoryRuntime::open_sqlite_in_memory().expect("memory runtime"));

    persist_agent_state(&mut state, &checkpoint_key, &agent_state, Some(&runtime))
        .expect("persist agent state");

    assert_eq!(
        state.get(&checkpoint_key).expect("state get"),
        Some(expected_bytes.clone())
    );
    assert_eq!(
        runtime
            .load_checkpoint_blob(session_id, AGENT_STATE_CHECKPOINT_NAME)
            .expect("load checkpoint"),
        Some(expected_bytes),
    );
}

#[test]
fn delete_agent_state_checkpoint_removes_runtime_blob() {
    let session_id = [4u8; 32];
    let checkpoint_key = b"agent::state::test".to_vec();
    let agent_state = test_agent_state(session_id);
    let mut state = MockState::default();
    let runtime = Arc::new(MemoryRuntime::open_sqlite_in_memory().expect("memory runtime"));

    persist_agent_state(&mut state, &checkpoint_key, &agent_state, Some(&runtime))
        .expect("persist agent state");
    delete_agent_state_checkpoint(Some(&runtime), session_id)
        .expect("delete agent state checkpoint");

    assert_eq!(
        runtime
            .load_checkpoint_blob(session_id, AGENT_STATE_CHECKPOINT_NAME)
            .expect("load checkpoint"),
        None,
    );
}

#[test]
fn load_agent_state_checkpoint_decodes_runtime_blob() {
    let session_id = [6u8; 32];
    let checkpoint_key = b"agent::state::test".to_vec();
    let agent_state = test_agent_state(session_id);
    let mut state = MockState::default();
    let runtime = Arc::new(MemoryRuntime::open_sqlite_in_memory().expect("memory runtime"));

    persist_agent_state(&mut state, &checkpoint_key, &agent_state, Some(&runtime))
        .expect("persist agent state");

    let loaded: Option<AgentState> = load_agent_state_checkpoint(runtime.as_ref(), session_id)
        .expect("load agent state checkpoint");

    let loaded = loaded.expect("agent state present");
    assert_eq!(loaded.session_id, agent_state.session_id);
    assert_eq!(loaded.goal, agent_state.goal);
    assert_eq!(loaded.step_count, agent_state.step_count);
    assert_eq!(loaded.max_steps, agent_state.max_steps);
}

#[test]
fn max_steps_terminalization_stays_deferred_for_active_parent_playbook_child() {
    let session_id = [0x11; 32];
    let child_session_id = [0x22; 32];
    let mut state = MockState::default();
    let mut agent_state = test_agent_state(session_id);
    agent_state.step_count = agent_state.max_steps;
    agent_state.resolved_intent =
        Some(resolved_web_intent_with_playbook("citation_grounded_brief"));

    let run = ParentPlaybookRun {
        parent_session_id: session_id,
        playbook_id: "citation_grounded_brief".to_string(),
        playbook_label: "Citation-Grounded Brief".to_string(),
        topic: agent_state.goal.clone(),
        status: ParentPlaybookStatus::Running,
        current_step_index: 0,
        active_child_session_id: Some(child_session_id),
        started_at_ms: 1,
        updated_at_ms: 1,
        completed_at_ms: None,
        steps: Vec::new(),
    };
    state
        .insert(
            &get_parent_playbook_run_key(&session_id, "citation_grounded_brief"),
            &codec::to_bytes_canonical(&run).expect("parent playbook run should encode"),
        )
        .expect("persist parent playbook run");

    assert!(
        !should_terminalize_running_agent_after_max_steps(&state, &agent_state),
        "active delegated playbook child should defer generic max-steps completion"
    );
}

#[test]
fn max_steps_terminalization_still_completes_without_active_child_work() {
    let session_id = [0x33; 32];
    let state = MockState::default();
    let mut agent_state = test_agent_state(session_id);
    agent_state.step_count = agent_state.max_steps;

    assert!(
        should_terminalize_running_agent_after_max_steps(&state, &agent_state),
        "ordinary max-steps completion should remain available without active child work"
    );
}

#[test]
fn await_child_session_status_prefers_runtime_checkpoint() {
    let session_id = [8u8; 32];
    let checkpoint_key = get_state_key(&session_id);
    let mut runtime_state = test_agent_state(session_id);
    runtime_state.status = AgentStatus::Completed(Some("All done".to_string()));
    let mut stale_state = test_agent_state(session_id);
    stale_state.status = AgentStatus::Running;
    let stale_bytes = codec::to_bytes_canonical(&stale_state).expect("encode stale state");
    let mut state = MockState::default();
    let runtime = Arc::new(MemoryRuntime::open_sqlite_in_memory().expect("memory runtime"));

    state
        .insert(&checkpoint_key, &stale_bytes)
        .expect("insert stale raw state");
    persist_agent_state(&mut state, &checkpoint_key, &runtime_state, Some(&runtime))
        .expect("persist runtime-backed state");

    let status =
        await_child_session_status_for_inspection(&state, Some(&runtime), &hex::encode(session_id))
            .expect("await child session status");

    assert_eq!(status, "All done");
}

#[test]
fn await_child_session_status_falls_back_to_raw_state_when_checkpoint_missing() {
    let session_id = [5u8; 32];
    let checkpoint_key = get_state_key(&session_id);
    let mut child_state = test_agent_state(session_id);
    child_state.status = AgentStatus::Paused("Waiting".to_string());
    let child_bytes = codec::to_bytes_canonical(&child_state).expect("encode child state");
    let mut state = MockState::default();
    let runtime = Arc::new(MemoryRuntime::open_sqlite_in_memory().expect("memory runtime"));

    state
        .insert(&checkpoint_key, &child_bytes)
        .expect("insert raw child state");

    let status =
        await_child_session_status_for_inspection(&state, Some(&runtime), &hex::encode(session_id))
            .expect("await child session status");

    assert_eq!(status, "Running (paused: Waiting)");
}

#[test]
fn await_child_session_status_prefers_raw_terminal_state_over_running_checkpoint() {
    let session_id = [9u8; 32];
    let checkpoint_key = get_state_key(&session_id);
    let mut raw_state = test_agent_state(session_id);
    raw_state.status = AgentStatus::Failed(
        "Agent Failure: ERROR_CLASS=TimeoutOrHang verifier timed out".to_string(),
    );
    raw_state.step_count = 7;
    let raw_bytes = codec::to_bytes_canonical(&raw_state).expect("encode raw state");
    let mut checkpoint_state = test_agent_state(session_id);
    checkpoint_state.status = AgentStatus::Running;
    checkpoint_state.step_count = 6;
    let mut state = MockState::default();
    let runtime = Arc::new(MemoryRuntime::open_sqlite_in_memory().expect("memory runtime"));

    state
        .insert(&checkpoint_key, &raw_bytes)
        .expect("insert raw child state");
    persist_agent_state(
        &mut state,
        &checkpoint_key,
        &checkpoint_state,
        Some(&runtime),
    )
    .expect("persist runtime checkpoint");
    state
        .insert(&checkpoint_key, &raw_bytes)
        .expect("restore newer raw child state");

    let status =
        await_child_session_status_for_inspection(&state, Some(&runtime), &hex::encode(session_id))
            .expect_err("failed child should surface terminal raw state");

    assert!(status.contains("verifier timed out"));
}
