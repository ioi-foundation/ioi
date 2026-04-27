use super::{
    blocked_web_read_note, maybe_normalize_unchanged_browser_snapshot,
    normalize_blocked_web_read_for_continuation, BROWSER_SNAPSHOT_CONTENT_HASH_RECEIPT,
    BROWSER_SNAPSHOT_CONTENT_STEP_RECEIPT,
};
use crate::agentic::runtime::service::step::action::support::{
    execution_evidence_key, execution_evidence_value,
};
use crate::agentic::runtime::service::step::anti_loop::FailureClass;
use crate::agentic::runtime::types::{AgentMode, AgentState, AgentStatus, ExecutionTier};
use ioi_types::app::ActionRequest;
use std::collections::{BTreeMap, VecDeque};

fn test_agent_state() -> AgentState {
    AgentState {
        session_id: [7u8; 32],
        goal: "test".to_string(),
        transcript_root: [0u8; 32],
        status: AgentStatus::Running,
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
        mode: AgentMode::Agent,
        current_tier: ExecutionTier::DomHeadless,
        last_screen_phash: None,
        execution_queue: Vec::<ActionRequest>::new(),
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
fn blocked_web_read_note_distinguishes_challenge_from_generic_failure() {
    assert_eq!(
        blocked_web_read_note("https://example.com", true),
        "Recorded challenged source in fixed payload (no fallback retries): https://example.com"
    );
    assert_eq!(
        blocked_web_read_note("https://example.com", false),
        "Source read failed in fixed payload (no fallback retries): https://example.com"
    );
}

#[test]
fn normalize_blocked_web_read_for_continuation_preserves_failure_state() {
    let mut success = false;
    let mut error_msg = Some("ERROR_CLASS=HumanChallengeRequired captcha".to_string());
    let mut history_entry = None;
    let mut action_output = None;
    let mut stop_condition_hit = true;
    let mut escalation_path = Some("pause".to_string());
    let mut verification_checks = Vec::new();

    normalize_blocked_web_read_for_continuation(
        &mut success,
        &mut error_msg,
        &mut history_entry,
        &mut action_output,
        &mut stop_condition_hit,
        &mut escalation_path,
        &mut verification_checks,
        "https://example.com",
        true,
    );

    assert!(!success);
    assert!(error_msg.is_some());
    assert_eq!(
        history_entry.as_deref(),
        Some(
            "Recorded challenged source in fixed payload (no fallback retries): https://example.com"
        )
    );
    assert_eq!(history_entry, action_output);
    assert!(stop_condition_hit);
    assert_eq!(escalation_path.as_deref(), Some("pause"));
    assert!(verification_checks
        .iter()
        .any(|check| check == "web_blocked_read_requires_remediation=true"));
}

#[test]
fn unchanged_immediate_browser_snapshot_becomes_no_effect_failure() {
    let mut state = test_agent_state();
    let snapshot =
        r#"<root><combobox id="inp_queue_status_filter" value="Awaiting Dispatch" /></root>"#;

    let mut success = true;
    let mut error_msg = None;
    let mut history_entry = Some(snapshot.to_string());
    let mut action_output = Some(snapshot.to_string());
    let mut failure_class = None;
    let mut verification_checks = Vec::new();
    maybe_normalize_unchanged_browser_snapshot(
        &mut state,
        "browser__inspect",
        &mut success,
        &mut error_msg,
        &mut history_entry,
        &mut action_output,
        &mut failure_class,
        &mut verification_checks,
    );

    assert!(success);
    assert!(error_msg.is_none());
    assert!(state
        .tool_execution_log
        .contains_key(&execution_evidence_key(
            BROWSER_SNAPSHOT_CONTENT_HASH_RECEIPT
        )));
    assert_eq!(
        execution_evidence_value(
            &state.tool_execution_log,
            BROWSER_SNAPSHOT_CONTENT_STEP_RECEIPT
        ),
        Some("0")
    );

    state.step_count = 1;
    let mut success = true;
    let mut error_msg = None;
    let mut history_entry = Some(snapshot.to_string());
    let mut action_output = Some(snapshot.to_string());
    let mut failure_class = None;
    let mut verification_checks = Vec::new();
    maybe_normalize_unchanged_browser_snapshot(
        &mut state,
        "browser__inspect",
        &mut success,
        &mut error_msg,
        &mut history_entry,
        &mut action_output,
        &mut failure_class,
        &mut verification_checks,
    );

    assert!(!success);
    assert!(error_msg
        .as_deref()
        .unwrap_or_default()
        .contains("ERROR_CLASS=NoEffectAfterAction"));
    assert_eq!(failure_class, Some(FailureClass::NoEffectAfterAction));
    assert!(verification_checks
        .iter()
        .any(|check| check == "browser_snapshot_immediate_replay_unchanged=true"));
}

#[test]
fn changed_or_non_adjacent_browser_snapshot_stays_success() {
    let mut state = test_agent_state();
    let first_snapshot =
        r#"<root><combobox id="inp_queue_status_filter" value="Awaiting Dispatch" /></root>"#;
    let second_snapshot =
        r#"<root><combobox id="inp_queue_status_filter" value="Escalated" /></root>"#;

    let mut success = true;
    let mut error_msg = None;
    let mut history_entry = Some(first_snapshot.to_string());
    let mut action_output = Some(first_snapshot.to_string());
    let mut failure_class = None;
    let mut verification_checks = Vec::new();
    maybe_normalize_unchanged_browser_snapshot(
        &mut state,
        "browser__inspect",
        &mut success,
        &mut error_msg,
        &mut history_entry,
        &mut action_output,
        &mut failure_class,
        &mut verification_checks,
    );

    state.step_count = 2;
    let mut success = true;
    let mut error_msg = None;
    let mut history_entry = Some(second_snapshot.to_string());
    let mut action_output = Some(second_snapshot.to_string());
    let mut failure_class = None;
    let mut verification_checks = Vec::new();
    maybe_normalize_unchanged_browser_snapshot(
        &mut state,
        "browser__inspect",
        &mut success,
        &mut error_msg,
        &mut history_entry,
        &mut action_output,
        &mut failure_class,
        &mut verification_checks,
    );

    assert!(success);
    assert!(error_msg.is_none());
    assert!(failure_class.is_none());
    assert!(!verification_checks
        .iter()
        .any(|check| check == "browser_snapshot_immediate_replay_unchanged=true"));
}
