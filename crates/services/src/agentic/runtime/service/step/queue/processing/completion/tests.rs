use super::*;
use crate::agentic::runtime::service::step::action::mark_execution_postcondition;
use crate::agentic::runtime::types::{AgentMode, ExecutionTier};
use ioi_types::app::agentic::{
    CapabilityId, IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState,
};
use std::collections::{BTreeMap, VecDeque};

fn mail_reply_resolved_intent() -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "mail.reply".to_string(),
        scope: IntentScopeProfile::Conversation,
        band: IntentConfidenceBand::High,
        score: 1.0,
        top_k: vec![],
        required_capabilities: vec![CapabilityId::from("mail.reply")],
        required_receipts: vec![],
        required_postconditions: vec![],
        risk_class: "medium".to_string(),
        preferred_tier: "tool_first".to_string(),
        matrix_version: "test".to_string(),
        embedding_model_id: String::new(),
        embedding_model_version: String::new(),
        similarity_function_id: String::new(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: String::new(),
        matrix_source_hash: [0u8; 32],
        receipt_hash: [0u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    }
}

fn agent_state_with_mail_reply() -> AgentState {
    AgentState {
        session_id: [7u8; 32],
        goal: "send email".to_string(),
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
        mode: AgentMode::default(),
        current_tier: ExecutionTier::default(),
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
        resolved_intent: Some(mail_reply_resolved_intent()),
        awaiting_intent_clarification: false,
        working_directory: ".".to_string(),
        command_history: VecDeque::new(),
        active_lens: None,
    }
}

#[test]
fn normalizes_output_only_success_for_queue_tools() {
    let mut success = false;
    let out = Some("provider completed request".to_string());
    let err = None;
    let mut verification_checks = Vec::new();

    normalize_output_only_success(
        "connector__google__gmail_send_email",
        &mut success,
        &out,
        &err,
        &mut verification_checks,
    );

    assert!(success);
    assert!(verification_checks
        .iter()
        .any(|check| check == "queue_output_only_success_normalized=true"));
}

#[test]
fn completes_mail_reply_after_first_successful_provider_action() {
    let mut agent_state = agent_state_with_mail_reply();
    let session_id = agent_state.session_id;
    mark_execution_postcondition(&mut agent_state.tool_execution_log, "mail.reply.completed");
    agent_state
        .execution_queue
        .push(ioi_types::app::ActionRequest {
            target: ioi_types::app::ActionTarget::Custom("mail.reply".to_string()),
            params: vec![],
            context: ioi_types::app::ActionContext {
                agent_id: "desktop_agent".to_string(),
                session_id: Some(session_id),
                window_id: None,
            },
            nonce: 0,
        });
    let mut success = true;
    let mut out = Some("Drafted the email successfully.".to_string());
    let mut err = None;
    let mut completion_summary = None;

    maybe_complete_mail_reply(
        &mut agent_state,
        "connector__google__gmail_draft_email",
        false,
        &mut success,
        &mut out,
        &mut err,
        &mut completion_summary,
        session_id,
    );

    assert!(matches!(agent_state.status, AgentStatus::Completed(_)));
    assert!(agent_state.execution_queue.is_empty());
    assert_eq!(
        completion_summary.as_deref(),
        Some("Drafted the email successfully.")
    );
}

#[test]
fn completes_mail_reply_when_only_fallback_provider_actions_remain() {
    let mut agent_state = agent_state_with_mail_reply();
    let session_id = agent_state.session_id;
    agent_state.resolved_intent = None;
    mark_execution_postcondition(&mut agent_state.tool_execution_log, "mail.reply.completed");
    agent_state
        .execution_queue
        .push(ioi_types::app::ActionRequest {
            target: ioi_types::app::ActionTarget::Custom(
                "connector__google__gmail_draft_email".to_string(),
            ),
            params: vec![],
            context: ioi_types::app::ActionContext {
                agent_id: "desktop_agent".to_string(),
                session_id: Some(session_id),
                window_id: None,
            },
            nonce: 0,
        });

    let mut success = true;
    let mut out = Some("Sent the email successfully.".to_string());
    let mut err = None;
    let mut completion_summary = None;

    maybe_complete_mail_reply(
        &mut agent_state,
        "connector__google__gmail_send_email",
        false,
        &mut success,
        &mut out,
        &mut err,
        &mut completion_summary,
        session_id,
    );

    assert!(matches!(agent_state.status, AgentStatus::Completed(_)));
    assert!(agent_state.execution_queue.is_empty());
    assert_eq!(
        completion_summary.as_deref(),
        Some("Sent the email successfully.")
    );
}

#[test]
fn completes_explicit_chat_reply_from_queue() {
    let mut agent_state = agent_state_with_mail_reply();
    agent_state.resolved_intent = None;
    let session_id = agent_state.session_id;
    let mut success = true;
    let mut out = Some("Replied: npm run dev:desktop".to_string());
    let mut err = None;
    let mut completion_summary = None;
    let mut verification_checks = Vec::new();
    let rules = crate::agentic::runtime::service::step::helpers::default_safe_policy();

    maybe_complete_chat_reply(
        &mut agent_state,
        &AgentTool::ChatReply {
            message:
                "In `package.json`, the npm script that launches the desktop app is `dev:desktop`."
                    .to_string(),
        },
        false,
        &mut success,
        &mut out,
        &mut err,
        &mut completion_summary,
        &mut verification_checks,
        &rules,
        session_id,
    );

    assert!(matches!(
        agent_state.status,
        AgentStatus::Completed(Some(_))
    ));
    assert!(agent_state.execution_queue.is_empty());
    assert_eq!(out, completion_summary);
    assert!(completion_summary
        .as_deref()
        .is_some_and(|summary| summary.contains("`dev:desktop`")));
    assert!(verification_checks
        .iter()
        .any(|check| check == "terminal_chat_reply_ready=true"));
}

#[test]
fn completes_explicit_agent_complete_result_from_queue() {
    let mut agent_state = agent_state_with_mail_reply();
    let session_id = agent_state.session_id;
    let mut success = true;
    let mut out = None;
    let mut err = None;
    let mut completion_summary = None;

    maybe_complete_agent_complete(
        &mut agent_state,
        &AgentTool::AgentComplete {
            result: "Touched files: path_utils.py\nCommand results: tests queued after edit"
                .to_string(),
        },
        false,
        &mut success,
        &mut out,
        &mut err,
        &mut completion_summary,
        session_id,
    );

    assert!(matches!(
        agent_state.status,
        AgentStatus::Completed(Some(_))
    ));
    assert_eq!(
        completion_summary.as_deref(),
        Some("Touched files: path_utils.py\nCommand results: tests queued after edit")
    );
    assert_eq!(out, completion_summary);
    assert!(err.is_none());
}
