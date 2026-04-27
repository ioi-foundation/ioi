use super::*;
use crate::agentic::runtime::types::ExecutionTier;
use crate::agentic::runtime::{AgentMode, AgentStatus};
use std::collections::{BTreeMap, VecDeque};

fn test_agent_state() -> AgentState {
    AgentState {
        session_id: [0u8; 32],
        goal: String::new(),
        transcript_root: [0u8; 32],
        status: AgentStatus::Idle,
        step_count: 0,
        max_steps: 0,
        last_action_type: None,
        parent_session_id: None,
        child_session_ids: Vec::new(),
        budget: 0,
        tokens_used: 0,
        consecutive_failures: 0,
        pending_approval: None,
        pending_tool_call: None,
        pending_tool_jcs: None,
        pending_tool_hash: None,
        pending_request_nonce: None,
        pending_visual_hash: None,
        recent_actions: Vec::new(),
        mode: AgentMode::Agent,
        current_tier: ExecutionTier::DomHeadless,
        last_screen_phash: None,
        execution_queue: Vec::new(),
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

#[test]
fn queue_web_read_skips_seen_urls_and_duplicate_requests() {
    let mut agent_state = test_agent_state();
    agent_state.pending_search_completion = Some(PendingSearchCompletion {
        attempted_urls: vec!["https://example.com/known".to_string()],
        ..PendingSearchCompletion::default()
    });

    assert!(!queue_web_read_from_pipeline(
        &mut agent_state,
        [1u8; 32],
        "https://example.com/known",
        false
    )
    .expect("queue result"));

    agent_state
        .pending_search_completion
        .as_mut()
        .expect("pending")
        .attempted_urls
        .clear();

    assert!(queue_web_read_from_pipeline(
        &mut agent_state,
        [1u8; 32],
        "https://example.com/new",
        true
    )
    .expect("queue result"));
    assert_eq!(agent_state.execution_queue.len(), 1);
    assert!(!queue_web_read_from_pipeline(
        &mut agent_state,
        [1u8; 32],
        "https://example.com/new",
        true
    )
    .expect("duplicate queue result"));
}

#[test]
fn queue_web_search_deduplicates_identical_search_requests() {
    let mut agent_state = test_agent_state();

    assert!(queue_web_search_from_pipeline(
        &mut agent_state,
        [2u8; 32],
        "latest pqc standards",
        Some("latest pqc standards"),
        None,
        3,
    )
    .expect("queue result"));
    assert_eq!(agent_state.execution_queue.len(), 1);
    assert!(!queue_web_search_from_pipeline(
        &mut agent_state,
        [2u8; 32],
        "latest pqc standards",
        Some("latest pqc standards"),
        None,
        3,
    )
    .expect("duplicate queue result"));
}

#[test]
fn human_challenge_detection_matches_common_provider_surfaces() {
    assert!(is_human_challenge_error(
        "recaptcha required before continuing"
    ));
    assert!(is_human_challenge_error(
        "error_class=HumanChallengeRequired"
    ));
    assert!(!is_human_challenge_error("connection reset by peer"));
}
