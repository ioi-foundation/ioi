use crate::agentic::desktop::service::step::action::{
    has_execution_postcondition, is_command_probe_intent, is_ui_capture_screenshot_intent,
    summarize_command_probe_output,
};
use crate::agentic::desktop::service::step::browser_completion::browser_snapshot_completion;
use crate::agentic::desktop::service::step::helpers::should_auto_complete_open_app_goal;
use crate::agentic::desktop::service::step::intent_resolver::tool_has_capability;
use crate::agentic::desktop::types::{AgentState, AgentStatus};
use ioi_types::app::agentic::{AgentTool, ComputerAction};

pub(super) fn complete_with_summary(
    agent_state: &mut AgentState,
    summary: String,
    success: &mut bool,
    out: &mut Option<String>,
    err: &mut Option<String>,
    completion_summary: &mut Option<String>,
    clear_pending_search: bool,
) {
    *success = true;
    *out = Some(summary.clone());
    *err = None;
    *completion_summary = Some(summary.clone());
    agent_state.status = AgentStatus::Completed(Some(summary));
    if clear_pending_search {
        agent_state.pending_search_completion = None;
    }
    agent_state.execution_queue.clear();
    agent_state.recent_actions.clear();
}

fn completion_summary_from_output(output: Option<&str>, fallback: &str) -> String {
    output
        .and_then(|value| {
            value
                .split("\n\n")
                .next()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
        .unwrap_or_else(|| fallback.to_string())
}

fn remaining_queue_is_only_mail_reply_provider_fallbacks(agent_state: &AgentState) -> bool {
    let mut saw_mail_reply_fallback = false;
    for request in &agent_state.execution_queue {
        let target = request.target.canonical_label();
        if tool_has_capability(&target, "mail.reply") || tool_has_capability(&target, "mail.send") {
            saw_mail_reply_fallback = true;
            continue;
        }
        return false;
    }
    saw_mail_reply_fallback
}

pub(super) fn normalize_output_only_success(
    tool_name: &str,
    success: &mut bool,
    out: &Option<String>,
    err: &Option<String>,
    verification_checks: &mut Vec<String>,
) {
    if *success || err.is_some() {
        return;
    }
    let has_output = out
        .as_deref()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    if !has_output {
        return;
    }
    *success = true;
    verification_checks.push("queue_output_only_success_normalized=true".to_string());
    verification_checks.push(format!("queue_output_only_success_tool={}", tool_name));
}

pub(super) fn maybe_complete_mail_reply(
    agent_state: &mut AgentState,
    tool_name: &str,
    is_gated: bool,
    success: &mut bool,
    out: &mut Option<String>,
    err: &mut Option<String>,
    completion_summary: &mut Option<String>,
    session_id: [u8; 32],
) {
    if is_gated || !*success || completion_summary.is_some() {
        return;
    }
    let is_mail_reply_intent = agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| {
            resolved.intent_id == "mail.reply"
                || resolved
                    .required_capabilities
                    .iter()
                    .any(|capability| capability.as_str() == "mail.reply")
        })
        .unwrap_or(false);
    let fallback_only_queue = remaining_queue_is_only_mail_reply_provider_fallbacks(agent_state);
    if !tool_has_capability(tool_name, "mail.reply")
        || (!is_mail_reply_intent && !fallback_only_queue)
    {
        return;
    }
    if !has_execution_postcondition(&agent_state.tool_execution_log, "mail.reply.completed") {
        return;
    }

    let summary = completion_summary_from_output(out.as_deref(), "Email request completed.");
    complete_with_summary(
        agent_state,
        summary,
        success,
        out,
        err,
        completion_summary,
        false,
    );
    log::info!(
        "Auto-completed mail reply after provider action for session {} tool={} fallback_only_queue={}.",
        hex::encode(&session_id[..4]),
        tool_name,
        fallback_only_queue
    );
}

pub(super) fn maybe_complete_command_probe(
    agent_state: &mut AgentState,
    tool_wrapper: &AgentTool,
    is_gated: bool,
    success: &mut bool,
    out: &mut Option<String>,
    err: &mut Option<String>,
    completion_summary: &mut Option<String>,
    session_id: [u8; 32],
) {
    if is_gated
        || completion_summary.is_some()
        || !matches!(
            tool_wrapper,
            AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
        )
        || !is_command_probe_intent(agent_state.resolved_intent.as_ref())
    {
        return;
    }
    let Some(raw) = out.as_deref() else {
        return;
    };
    if let Some(summary) = summarize_command_probe_output(tool_wrapper, raw) {
        // Probe markers are deterministic completion signals even when the
        // underlying command exits non-zero (e.g. NOT_FOUND_IN_PATH).
        complete_with_summary(
            agent_state,
            summary,
            success,
            out,
            err,
            completion_summary,
            false,
        );
        log::info!(
            "Auto-completed command probe after shell-command tool for session {}.",
            hex::encode(&session_id[..4])
        );
    }
}

pub(super) fn maybe_complete_open_app(
    agent_state: &mut AgentState,
    tool_wrapper: &AgentTool,
    is_gated: bool,
    success: &mut bool,
    out: &mut Option<String>,
    err: &mut Option<String>,
    completion_summary: &mut Option<String>,
    session_id: [u8; 32],
) {
    if is_gated || !*success || completion_summary.is_some() {
        return;
    }
    let AgentTool::OsLaunchApp { app_name } = tool_wrapper else {
        return;
    };
    if should_auto_complete_open_app_goal(
        &agent_state.goal,
        app_name,
        agent_state
            .target
            .as_ref()
            .and_then(|target| target.app_hint.as_deref()),
    ) {
        complete_with_summary(
            agent_state,
            format!("Opened {}.", app_name),
            success,
            out,
            err,
            completion_summary,
            false,
        );
        log::info!(
            "Auto-completed app-launch queue flow for session {}.",
            hex::encode(&session_id[..4])
        );
    }
}

pub(super) fn maybe_complete_screenshot_capture(
    agent_state: &mut AgentState,
    tool_wrapper: &AgentTool,
    is_gated: bool,
    success: &mut bool,
    out: &mut Option<String>,
    err: &mut Option<String>,
    completion_summary: &mut Option<String>,
    session_id: [u8; 32],
) {
    if is_gated || !*success || completion_summary.is_some() {
        return;
    }
    if !is_ui_capture_screenshot_intent(agent_state.resolved_intent.as_ref()) {
        return;
    }

    let screenshot_tool = matches!(
        tool_wrapper,
        AgentTool::Computer(ComputerAction::Screenshot)
    );
    if !screenshot_tool {
        return;
    }

    let output = out.as_deref().unwrap_or_default();
    if !output.trim_start().starts_with("Screenshot captured") {
        return;
    }

    let summary = "Screenshot captured.".to_string();
    complete_with_summary(
        agent_state,
        summary,
        success,
        out,
        err,
        completion_summary,
        false,
    );
    log::info!(
        "Auto-completed screenshot capture flow for session {}.",
        hex::encode(&session_id[..4])
    );
}

pub(super) fn maybe_complete_browser_snapshot_interaction(
    agent_state: &mut AgentState,
    tool_name: &str,
    is_gated: bool,
    success: &mut bool,
    out: &mut Option<String>,
    err: &mut Option<String>,
    completion_summary: &mut Option<String>,
    verification_checks: &mut Vec<String>,
    session_id: [u8; 32],
) {
    if is_gated || !*success || completion_summary.is_some() {
        return;
    }

    let Some(completion) =
        browser_snapshot_completion(agent_state, tool_name, out.as_deref())
    else {
        return;
    };

    complete_with_summary(
        agent_state,
        completion.summary,
        success,
        out,
        err,
        completion_summary,
        false,
    );
    verification_checks.push("browser_snapshot_success_criteria_auto_completed=true".to_string());
    verification_checks.push(format!(
        "browser_snapshot_success_criteria_count={}",
        completion.matched_success_criteria.len()
    ));
    verification_checks.push(format!(
        "browser_snapshot_success_criteria={}",
        completion.matched_success_criteria.join(",")
    ));
    verification_checks.push("terminal_chat_reply_ready=true".to_string());
    log::info!(
        "Auto-completed browser snapshot interaction for session {}.",
        hex::encode(&session_id[..4])
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::desktop::service::step::action::mark_execution_postcondition;
    use crate::agentic::desktop::types::{AgentMode, ExecutionTier};
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
}
