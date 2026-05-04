use super::{duplicate_execution_state, is_duplicate_safe_repeat_tool};
use crate::agentic::runtime::service::tool_execution::mark_action_fingerprint_executed_at_step;
use crate::agentic::runtime::types::{
    AgentMode, AgentState, AgentStatus, ExecutionTier, ToolCallStatus,
};
use ioi_types::app::agentic::AgentTool;
use std::collections::BTreeMap;

fn test_agent_state() -> AgentState {
    AgentState {
        session_id: [0u8; 32],
        goal: "test".to_string(),
        runtime_route_frame: None,
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
        execution_ledger: Default::default(),
        visual_som_map: None,
        visual_semantic_map: None,
        work_graph_context: None,
        target: None,
        resolved_intent: None,
        awaiting_intent_clarification: false,
        working_directory: ".".to_string(),
        command_history: Default::default(),
        active_lens: None,
    }
}

#[test]
fn duplicate_non_command_replay_detected_only_on_adjacent_step() {
    let mut state = test_agent_state();
    mark_action_fingerprint_executed_at_step(&mut state.tool_execution_log, "fp", 3, "success");
    let tool = AgentTool::FsList {
        path: ".".to_string(),
    };
    let mut checks = Vec::new();
    let (is_duplicate, history) =
        duplicate_execution_state(&mut state, &tool, false, 4, "fp", &mut checks);
    assert!(is_duplicate);
    assert!(history.is_none());
    assert!(!checks
        .iter()
        .any(|c| { c == "duplicate_action_fingerprint_non_command_stale_or_non_adjacent=true" }));
}

#[test]
fn duplicate_non_command_non_adjacent_step_is_not_forced_duplicate() {
    let mut state = test_agent_state();
    mark_action_fingerprint_executed_at_step(&mut state.tool_execution_log, "fp", 3, "success");
    let tool = AgentTool::FsList {
        path: ".".to_string(),
    };
    let mut checks = Vec::new();
    let (is_duplicate, history) =
        duplicate_execution_state(&mut state, &tool, false, 7, "fp", &mut checks);
    assert!(!is_duplicate);
    assert!(history.is_none());
    assert!(checks
        .iter()
        .any(|c| { c == "duplicate_action_fingerprint_non_command_stale_or_non_adjacent=true" }));
}

#[test]
fn duplicate_non_command_cooldown_step_blocks_alternating_replay_loop() {
    let mut state = test_agent_state();
    let tool = AgentTool::FsList {
        path: ".".to_string(),
    };
    let mut checks = Vec::new();

    mark_action_fingerprint_executed_at_step(&mut state.tool_execution_log, "fp", 3, "success");

    let (duplicate_at_step_4, _) =
        duplicate_execution_state(&mut state, &tool, false, 4, "fp", &mut checks);
    assert!(duplicate_at_step_4);

    // Duplicate-skip branch advances the fingerprint step to the current step.
    mark_action_fingerprint_executed_at_step(
        &mut state.tool_execution_log,
        "fp",
        4,
        "duplicate_skip",
    );

    let (duplicate_at_step_5, _) =
        duplicate_execution_state(&mut state, &tool, false, 5, "fp", &mut checks);
    assert!(duplicate_at_step_5);
}

#[test]
fn legacy_action_fingerprint_receipt_is_removed_and_not_used_for_dedupe() {
    let mut state = test_agent_state();
    state.tool_execution_log.insert(
        "action_fingerprint::legacy".to_string(),
        ToolCallStatus::Executed("success".to_string()),
    );
    let tool = AgentTool::FsList {
        path: ".".to_string(),
    };
    let mut checks = Vec::new();
    let (is_duplicate, history) =
        duplicate_execution_state(&mut state, &tool, false, 8, "legacy", &mut checks);
    assert!(!is_duplicate);
    assert!(history.is_none());
    assert!(checks
        .iter()
        .any(|c| c == "duplicate_action_fingerprint_legacy_removed=true"));
    assert!(!state
        .tool_execution_log
        .contains_key("action_fingerprint::legacy"));
}

#[test]
fn browser_wait_is_allowed_to_repeat_on_adjacent_steps() {
    let mut state = test_agent_state();
    mark_action_fingerprint_executed_at_step(&mut state.tool_execution_log, "fp", 3, "success");
    let tool = AgentTool::BrowserWait {
        ms: Some(100),
        condition: None,
        selector: None,
        query: None,
        scope: None,
        timeout_ms: None,
        continue_with: None,
    };
    let mut checks = Vec::new();
    let (is_duplicate, history) =
        duplicate_execution_state(&mut state, &tool, false, 4, "fp", &mut checks);
    assert!(!is_duplicate);
    assert!(history.is_none());
    assert!(!checks
        .iter()
        .any(|c| { c == "duplicate_action_fingerprint_non_command_stale_or_non_adjacent=true" }));
}

#[test]
fn browser_scroll_is_allowed_to_repeat_on_adjacent_steps() {
    let mut state = test_agent_state();
    mark_action_fingerprint_executed_at_step(&mut state.tool_execution_log, "fp", 3, "success");
    let tool = AgentTool::BrowserScroll {
        delta_x: 0,
        delta_y: -120,
    };
    let mut checks = Vec::new();
    let (is_duplicate, history) =
        duplicate_execution_state(&mut state, &tool, false, 4, "fp", &mut checks);
    assert!(!is_duplicate);
    assert!(history.is_none());
}

#[test]
fn browser_hover_is_allowed_to_repeat_on_adjacent_steps() {
    let mut state = test_agent_state();
    mark_action_fingerprint_executed_at_step(&mut state.tool_execution_log, "fp", 3, "success");
    let tool = AgentTool::BrowserHover {
        selector: None,
        id: Some("grp_circ".to_string()),
        duration_ms: None,
        resample_interval_ms: None,
    };
    let mut checks = Vec::new();
    let (is_duplicate, history) =
        duplicate_execution_state(&mut state, &tool, false, 4, "fp", &mut checks);
    assert!(!is_duplicate);
    assert!(history.is_none());
    assert!(is_duplicate_safe_repeat_tool(&tool));
}

#[test]
fn browser_page_up_is_allowed_to_repeat_on_adjacent_steps() {
    let mut state = test_agent_state();
    mark_action_fingerprint_executed_at_step(&mut state.tool_execution_log, "fp", 3, "success");
    let tool = AgentTool::BrowserKey {
        key: "PageUp".to_string(),
        selector: None,
        modifiers: None,
        continue_with: None,
    };
    let mut checks = Vec::new();
    let (is_duplicate, history) =
        duplicate_execution_state(&mut state, &tool, false, 4, "fp", &mut checks);
    assert!(!is_duplicate);
    assert!(history.is_none());
    assert!(is_duplicate_safe_repeat_tool(&tool));
}

#[test]
fn agent_await_result_is_allowed_to_repeat_on_adjacent_steps() {
    let mut state = test_agent_state();
    mark_action_fingerprint_executed_at_step(&mut state.tool_execution_log, "fp", 3, "success");
    let tool = AgentTool::AgentAwait {
        child_session_id_hex: "44".repeat(32),
    };
    let mut checks = Vec::new();
    let (is_duplicate, history) =
        duplicate_execution_state(&mut state, &tool, false, 4, "fp", &mut checks);
    assert!(!is_duplicate);
    assert!(history.is_none());
    assert!(is_duplicate_safe_repeat_tool(&tool));
}

#[test]
fn browser_enter_replay_remains_deduped() {
    let mut state = test_agent_state();
    mark_action_fingerprint_executed_at_step(&mut state.tool_execution_log, "fp", 3, "success");
    let tool = AgentTool::BrowserKey {
        key: "Enter".to_string(),
        selector: None,
        modifiers: None,
        continue_with: None,
    };
    let mut checks = Vec::new();
    let (is_duplicate, history) =
        duplicate_execution_state(&mut state, &tool, false, 4, "fp", &mut checks);
    assert!(is_duplicate);
    assert!(history.is_none());
    assert!(!is_duplicate_safe_repeat_tool(&tool));
}
