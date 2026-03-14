use super::events::{emit_completion_gate_status_event, emit_completion_gate_violation_events};
use super::*;
use crate::agentic::desktop::service::step::action::support::action_fingerprint_execution_label;
use crate::agentic::desktop::service::step::intent_resolver::is_mail_reply_provider_tool;
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget};
use serde_json::json;

pub(super) struct DuplicateExecutionContext<'a> {
    pub service: &'a DesktopAgentService,
    pub agent_state: &'a mut AgentState,
    pub rules: &'a ActionRules,
    pub tool: &'a AgentTool,
    pub matching_command_history_entry: Option<crate::agentic::desktop::types::CommandExecution>,
    pub command_scope: bool,
    pub action_fingerprint: &'a str,
    pub session_id: [u8; 32],
    pub step_index: u32,
    pub resolved_intent_id: &'a str,
    pub verification_checks: &'a mut Vec<String>,
}

pub(super) struct DuplicateExecutionOutcome {
    pub success: bool,
    pub error_msg: Option<String>,
    pub history_entry: Option<String>,
    pub action_output: Option<String>,
    pub terminal_chat_reply_output: Option<String>,
    pub is_lifecycle_action: bool,
}

pub(super) fn handle_duplicate_command_execution(
    ctx: DuplicateExecutionContext<'_>,
) -> DuplicateExecutionOutcome {
    let DuplicateExecutionContext {
        service,
        agent_state,
        rules,
        tool,
        matching_command_history_entry,
        command_scope,
        action_fingerprint,
        session_id,
        step_index,
        resolved_intent_id,
        verification_checks,
    } = ctx;

    let mut success = false;
    let mut error_msg = None;
    let mut history_entry: Option<String> = None;
    let action_output: Option<String>;
    let mut terminal_chat_reply_output = None;
    let mut is_lifecycle_action = false;
    let matching_command_history_entry = matching_command_history_entry.as_ref();
    let is_command_tool = matches!(
        tool,
        AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. }
    );

    if let Some(summary) =
        duplicate_command_completion_summary(tool, matching_command_history_entry)
    {
        let missing_contract_markers =
            missing_execution_contract_markers_with_rules(agent_state, rules);
        if missing_contract_markers.is_empty() {
            success = true;
            history_entry = Some(summary.clone());
            action_output = Some(summary.clone());
            terminal_chat_reply_output = Some(summary.clone());
            is_lifecycle_action = true;
            agent_state.status = AgentStatus::Completed(Some(summary));
            agent_state.execution_queue.clear();
            agent_state.pending_search_completion = None;
            verification_checks.push("duplicate_action_fingerprint_terminalized=true".to_string());
            verification_checks.push("terminal_chat_reply_ready=true".to_string());
            emit_completion_gate_status_event(
                service,
                session_id,
                step_index,
                resolved_intent_id,
                true,
                "duplicate_command_completion",
            );
        } else {
            let missing = missing_contract_markers.join(",");
            let contract_error = execution_contract_violation_error(&missing);
            error_msg = Some(contract_error.clone());
            history_entry = Some(contract_error.clone());
            action_output = Some(contract_error);
            agent_state.status = AgentStatus::Running;
            verification_checks.push("execution_contract_gate_blocked=true".to_string());
            verification_checks.push(format!("execution_contract_missing_keys={}", missing));
            verification_checks.push("duplicate_action_fingerprint_blocked=true".to_string());
            emit_completion_gate_violation_events(
                service,
                session_id,
                step_index,
                resolved_intent_id,
                &missing,
            );
        }
    } else if let Some(summary) =
        duplicate_command_cached_success_summary(tool, matching_command_history_entry)
    {
        let missing_contract_markers =
            missing_execution_contract_markers_with_rules(agent_state, rules);
        if missing_contract_markers.is_empty() {
            success = true;
            history_entry = Some(summary.clone());
            if command_scope {
                let completion = duplicate_command_cached_completion_summary(
                    tool,
                    matching_command_history_entry,
                )
                .unwrap_or_else(|| summary.clone());
                let completion = enrich_command_scope_summary(&completion, agent_state);
                action_output = Some(completion.clone());
                terminal_chat_reply_output = Some(completion.clone());
                agent_state.status = AgentStatus::Completed(Some(completion));
                is_lifecycle_action = true;
                agent_state.execution_queue.clear();
                agent_state.pending_search_completion = None;
                verification_checks
                    .push("duplicate_action_fingerprint_terminalized=true".to_string());
                verification_checks.push("terminal_chat_reply_ready=true".to_string());
            } else {
                action_output = Some(summary);
                agent_state.status = AgentStatus::Running;
            }
            verification_checks.push("duplicate_action_fingerprint_cached=true".to_string());
            emit_completion_gate_status_event(
                service,
                session_id,
                step_index,
                resolved_intent_id,
                true,
                "duplicate_command_cached_completion",
            );
        } else {
            let missing = missing_contract_markers.join(",");
            let contract_error = execution_contract_violation_error(&missing);
            error_msg = Some(contract_error.clone());
            history_entry = Some(contract_error.clone());
            action_output = Some(contract_error);
            agent_state.status = AgentStatus::Running;
            verification_checks.push("execution_contract_gate_blocked=true".to_string());
            verification_checks.push(format!("execution_contract_missing_keys={}", missing));
            verification_checks.push("duplicate_action_fingerprint_blocked=true".to_string());
            emit_completion_gate_violation_events(
                service,
                session_id,
                step_index,
                resolved_intent_id,
                &missing,
            );
        }
    } else if is_command_tool {
        let summary = duplicate_command_execution_summary(tool);
        let duplicate_error = format!("ERROR_CLASS=NoEffectAfterAction {}", summary);
        error_msg = Some(duplicate_error.clone());
        history_entry = Some(summary);
        action_output = Some(duplicate_error);
        agent_state.status = AgentStatus::Running;
        verification_checks.push("duplicate_action_fingerprint_blocked=true".to_string());
    } else {
        let tool_name = canonical_tool_identity(tool).0;
        let active_web_pipeline_chat_reply =
            is_active_web_pipeline_chat_reply_duplicate(&tool_name, agent_state);
        let prior_successful_duplicate =
            has_prior_successful_duplicate_action(agent_state, action_fingerprint);
        let mut summary = if active_web_pipeline_chat_reply {
            "Deferred final reply while web research continues gathering evidence.".to_string()
        } else if prior_successful_duplicate {
            format!(
                "Skipped immediate replay of '{}' because the identical action already succeeded on the previous step. Do not repeat it. Verify the updated state once or finish with the gathered evidence.",
                tool_name
            )
        } else {
            format!(
                "Skipped immediate replay of '{}' because the same action fingerprint was already executed on the previous step. This fingerprint is now cooled down at the current step; choose a different action or finish with the gathered evidence.",
                tool_name
            )
        };
        let queued_browser_snapshot_verification = prior_successful_duplicate
            && tool.target() == ActionTarget::BrowserInteract
            && queue_browser_snapshot_verification(agent_state, session_id);
        if queued_browser_snapshot_verification {
            summary
                .push_str(" A browser__snapshot verification step has been queued automatically.");
        }
        mark_action_fingerprint_executed_at_step(
            &mut agent_state.tool_execution_log,
            action_fingerprint,
            step_index,
            if prior_successful_duplicate {
                "success_duplicate_skip"
            } else {
                "duplicate_skip"
            },
        );
        let noop_duplicate_allowed = prior_successful_duplicate
            || is_non_command_duplicate_noop_tool(&tool_name)
            || active_web_pipeline_chat_reply;
        if noop_duplicate_allowed {
            success = true;
            error_msg = None;
            if is_mail_reply_tool(&tool_name) {
                let completion = format!(
                    "Email send request already completed: {} Duplicate resend was skipped to avoid duplicate delivery.",
                    agent_state.goal.trim()
                );
                history_entry = Some(completion.clone());
                action_output = Some(completion.clone());
                terminal_chat_reply_output = Some(completion.clone());
                is_lifecycle_action = true;
                agent_state.status = AgentStatus::Completed(Some(completion));
                agent_state.execution_queue.clear();
                agent_state.pending_search_completion = None;
                verification_checks
                    .push("duplicate_action_fingerprint_terminalized=true".to_string());
                verification_checks.push("terminal_chat_reply_ready=true".to_string());
                verification_checks.push("duplicate_mail_reply_noop_terminalized=true".to_string());
                emit_completion_gate_status_event(
                    service,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    true,
                    "duplicate_mail_reply_noop_completion",
                );
            } else {
                action_output = Some(summary.clone());
            }
            verification_checks
                .push("duplicate_action_fingerprint_non_command_noop=true".to_string());
            if prior_successful_duplicate {
                verification_checks
                    .push("duplicate_action_fingerprint_prior_success_noop=true".to_string());
            }
            if queued_browser_snapshot_verification {
                verification_checks.push(
                    "duplicate_action_fingerprint_queued_browser_snapshot_verification=true"
                        .to_string(),
                );
            }
            if active_web_pipeline_chat_reply {
                verification_checks
                    .push("terminal_chat_reply_deferred_for_active_web_pipeline=true".to_string());
                verification_checks.push("web_pipeline_active=true".to_string());
            }
        } else {
            let duplicate_error = format!("ERROR_CLASS=NoEffectAfterAction {}", summary);
            success = false;
            error_msg = Some(duplicate_error.clone());
            action_output = Some(duplicate_error);
        }
        if history_entry.is_none() {
            history_entry = Some(summary.clone());
        }
        if !matches!(agent_state.status, AgentStatus::Completed(_)) {
            agent_state.status = AgentStatus::Running;
        }
        verification_checks
            .push("duplicate_action_fingerprint_non_command_skipped=true".to_string());
        verification_checks
            .push("duplicate_action_fingerprint_non_command_step_advanced=true".to_string());
    }
    verification_checks.push(format!(
        "duplicate_action_fingerprint={}",
        action_fingerprint
    ));
    verification_checks.push(format!(
        "duplicate_action_fingerprint_non_terminal={}",
        !success
    ));

    DuplicateExecutionOutcome {
        success,
        error_msg,
        history_entry,
        action_output,
        terminal_chat_reply_output,
        is_lifecycle_action,
    }
}

fn is_non_command_duplicate_noop_tool(tool_name: &str) -> bool {
    is_read_only_filesystem_tool(tool_name)
        || is_mail_read_latest_tool(tool_name)
        || is_mail_reply_tool(tool_name)
        || crate::agentic::desktop::connectors::google_workspace::is_google_duplicate_safe_tool_name(
            tool_name,
        )
}

fn is_active_web_pipeline_chat_reply_duplicate(tool_name: &str, agent_state: &AgentState) -> bool {
    tool_name == "chat__reply" && agent_state.pending_search_completion.is_some()
}

fn has_prior_successful_duplicate_action(
    agent_state: &AgentState,
    action_fingerprint: &str,
) -> bool {
    if action_fingerprint.trim().is_empty() {
        return false;
    }

    action_fingerprint_execution_label(&agent_state.tool_execution_log, action_fingerprint)
        .as_deref()
        .map(|label| label.starts_with("success"))
        .unwrap_or(false)
}

fn queue_browser_snapshot_verification(agent_state: &mut AgentState, session_id: [u8; 32]) -> bool {
    let request = ActionRequest {
        target: ActionTarget::BrowserInspect,
        params: match serde_jcs::to_vec(&json!({})) {
            Ok(params) => params,
            Err(_) => return false,
        },
        context: ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: Some(session_id),
            window_id: None,
        },
        nonce: agent_state.step_count as u64 + agent_state.execution_queue.len() as u64 + 1,
    };

    let duplicate = agent_state
        .execution_queue
        .iter()
        .any(|queued| queued.target == request.target && queued.params == request.params);
    if duplicate {
        return false;
    }

    agent_state.execution_queue.insert(0, request);
    true
}

fn is_read_only_filesystem_tool(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "filesystem__list_directory"
            | "filesystem__read_file"
            | "filesystem__stat"
            | "filesystem__search"
    )
}

fn is_mail_read_latest_tool(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "wallet_network__mail_read_latest" | "wallet_mail_read_latest" | "mail__read_latest"
    )
}

fn is_mail_reply_tool(tool_name: &str) -> bool {
    is_mail_reply_provider_tool(tool_name)
}

#[cfg(test)]
mod tests {
    use super::{
        has_prior_successful_duplicate_action, is_active_web_pipeline_chat_reply_duplicate,
        is_mail_read_latest_tool, is_mail_reply_tool, is_non_command_duplicate_noop_tool,
        is_read_only_filesystem_tool, queue_browser_snapshot_verification,
    };
    use crate::agentic::desktop::service::step::action::mark_action_fingerprint_executed_at_step;
    use crate::agentic::desktop::types::{
        AgentMode, AgentState, AgentStatus, ExecutionTier, PendingSearchCompletion,
    };
    use ioi_types::app::ActionTarget;
    use std::collections::BTreeMap;

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
    fn read_only_filesystem_tools_are_noop_safe() {
        assert!(is_read_only_filesystem_tool("filesystem__list_directory"));
        assert!(is_read_only_filesystem_tool("filesystem__read_file"));
        assert!(is_read_only_filesystem_tool("filesystem__stat"));
        assert!(is_read_only_filesystem_tool("filesystem__search"));
        assert!(!is_read_only_filesystem_tool("filesystem__move_path"));
    }

    #[test]
    fn noop_allowlist_includes_read_only_filesystem_tools() {
        assert!(is_non_command_duplicate_noop_tool(
            "filesystem__list_directory"
        ));
        assert!(is_non_command_duplicate_noop_tool("mail__read_latest"));
        assert!(is_non_command_duplicate_noop_tool("mail__reply"));
        assert!(!is_non_command_duplicate_noop_tool(
            "filesystem__create_directory"
        ));
    }

    #[test]
    fn active_web_pipeline_chat_reply_duplicates_are_noop_safe() {
        let mut agent_state = test_agent_state();
        agent_state.pending_search_completion = Some(PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: None,
            url: String::new(),
            started_step: 0,
            started_at_ms: 0,
            deadline_ms: 0,
            candidate_urls: Vec::new(),
            candidate_source_hints: Vec::new(),
            attempted_urls: Vec::new(),
            blocked_urls: Vec::new(),
            successful_reads: Vec::new(),
            min_sources: 2,
        });

        assert!(is_active_web_pipeline_chat_reply_duplicate(
            "chat__reply",
            &agent_state
        ));
        assert!(!is_active_web_pipeline_chat_reply_duplicate(
            "filesystem__read_file",
            &agent_state
        ));
    }

    #[test]
    fn mail_tool_duplicate_helpers_match_expected_tools() {
        assert!(is_mail_read_latest_tool("wallet_network__mail_read_latest"));
        assert!(is_mail_reply_tool("wallet_network__mail_reply"));
        assert!(is_mail_reply_tool("mail__reply"));
        assert!(is_mail_reply_tool("connector__google__gmail_send_email"));
        assert!(is_mail_reply_tool("connector__google__gmail_draft_email"));
        assert!(!is_mail_reply_tool("wallet_network__mail_read_latest"));
    }

    #[test]
    fn prior_successful_duplicate_action_is_detected() {
        let mut agent_state = test_agent_state();
        mark_action_fingerprint_executed_at_step(
            &mut agent_state.tool_execution_log,
            "fp",
            3,
            "success",
        );
        mark_action_fingerprint_executed_at_step(
            &mut agent_state.tool_execution_log,
            "fp-noop",
            4,
            "success_duplicate_skip",
        );

        assert!(has_prior_successful_duplicate_action(&agent_state, "fp"));
        assert!(has_prior_successful_duplicate_action(
            &agent_state,
            "fp-noop"
        ));
        assert!(!has_prior_successful_duplicate_action(
            &agent_state,
            "missing"
        ));
    }

    #[test]
    fn browser_snapshot_verification_is_queued_once() {
        let mut agent_state = test_agent_state();

        assert!(queue_browser_snapshot_verification(
            &mut agent_state,
            [7u8; 32]
        ));
        assert_eq!(agent_state.execution_queue.len(), 1);
        assert_eq!(
            agent_state.execution_queue[0].target,
            ActionTarget::BrowserInspect
        );
        assert!(!queue_browser_snapshot_verification(
            &mut agent_state,
            [7u8; 32]
        ));
        assert_eq!(agent_state.execution_queue.len(), 1);
    }
}
