use super::*;
use crate::agentic::desktop::service::step::browser_completion::browser_snapshot_completion;

const BROWSER_SNAPSHOT_CONTENT_HASH_RECEIPT: &str = "browser_snapshot_content_hash";
const BROWSER_SNAPSHOT_CONTENT_STEP_RECEIPT: &str = "browser_snapshot_content_step";

fn blocked_web_read_note(read_url: &str, challenged: bool) -> String {
    if challenged {
        return format!(
            "Recorded challenged source in fixed payload (no fallback retries): {}",
            read_url
        );
    }

    format!(
        "Source read failed in fixed payload (no fallback retries): {}",
        read_url
    )
}

fn normalize_blocked_web_read_for_continuation(
    success: &mut bool,
    error_msg: &mut Option<String>,
    history_entry: &mut Option<String>,
    action_output: &mut Option<String>,
    stop_condition_hit: &mut bool,
    escalation_path: &mut Option<String>,
    verification_checks: &mut Vec<String>,
    read_url: &str,
    challenged: bool,
) {
    if *success {
        return;
    }

    let note = blocked_web_read_note(read_url, challenged);
    *success = true;
    *error_msg = None;
    *history_entry = Some(note.clone());
    *action_output = Some(note);
    *stop_condition_hit = false;
    *escalation_path = None;
    verification_checks.push("web_blocked_read_continues=true".to_string());
}

fn maybe_normalize_unchanged_browser_snapshot(
    agent_state: &mut AgentState,
    current_tool_name: &str,
    success: &mut bool,
    error_msg: &mut Option<String>,
    history_entry: &mut Option<String>,
    action_output: &mut Option<String>,
    failure_class: &mut Option<FailureClass>,
    verification_checks: &mut Vec<String>,
) {
    if !*success
        || current_tool_name != "browser__snapshot"
        || agent_state.pending_search_completion.is_some()
    {
        return;
    }

    let snapshot_output = history_entry
        .as_deref()
        .or(action_output.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let Some(snapshot_output) = snapshot_output else {
        return;
    };

    let Ok(snapshot_digest) = sha256(snapshot_output.as_bytes()) else {
        return;
    };
    let snapshot_hash = hex::encode(snapshot_digest);
    let current_step = agent_state.step_count;
    let prior_hash = execution_receipt_value(
        &agent_state.tool_execution_log,
        BROWSER_SNAPSHOT_CONTENT_HASH_RECEIPT,
    )
    .map(str::to_string);
    let prior_step = execution_receipt_value(
        &agent_state.tool_execution_log,
        BROWSER_SNAPSHOT_CONTENT_STEP_RECEIPT,
    )
    .and_then(|value| value.parse::<u32>().ok());

    mark_execution_receipt_with_value(
        &mut agent_state.tool_execution_log,
        BROWSER_SNAPSHOT_CONTENT_HASH_RECEIPT,
        snapshot_hash.clone(),
    );
    mark_execution_receipt_with_value(
        &mut agent_state.tool_execution_log,
        BROWSER_SNAPSHOT_CONTENT_STEP_RECEIPT,
        current_step.to_string(),
    );
    verification_checks.push("browser_snapshot_content_hash_recorded=true".to_string());

    let unchanged_immediate_replay = prior_hash.as_deref() == Some(snapshot_hash.as_str())
        && prior_step
            .map(|step| current_step == step.saturating_add(1))
            .unwrap_or(false);
    if !unchanged_immediate_replay {
        return;
    }

    let summary = "Repeated `browser__snapshot` returned the same browser state as the previous step. Do not call `browser__snapshot` again yet. Use a different browser action or act on the visible control already named in `RECENT PENDING BROWSER STATE`.".to_string();
    *success = false;
    *failure_class = Some(FailureClass::NoEffectAfterAction);
    *error_msg = Some(format!("ERROR_CLASS=NoEffectAfterAction {}", summary));
    *history_entry = Some(summary);
    *action_output = error_msg.clone();
    verification_checks.push("browser_snapshot_immediate_replay_unchanged=true".to_string());
}

pub(crate) async fn apply_post_execution_guards(
    ctx: ApplyPostExecutionGuardsContext<'_, '_>,
    state_in: ActionProcessingState,
) -> Result<ActionProcessingState, TransactionError> {
    let ApplyPostExecutionGuardsContext {
        service,
        state,
        agent_state,
        session_id,
        block_height,
        block_timestamp_ns,
        tool_call_result,
        final_visual_phash,
    } = ctx;

    let ActionProcessingState {
        policy_decision,
        action_payload,
        intent_hash,
        retry_intent_hash,
        mut success,
        mut error_msg,
        is_gated,
        mut is_lifecycle_action,
        current_tool_name,
        mut history_entry,
        mut action_output,
        trace_visual_hash,
        executed_tool_jcs,
        mut failure_class,
        mut stop_condition_hit,
        mut escalation_path,
        remediation_queued,
        mut verification_checks,
        mut awaiting_sudo_password,
        mut awaiting_clarification,
        command_probe_completed,
        invalid_tool_call_fail_fast,
        invalid_tool_call_bootstrap_web,
        invalid_tool_call_fail_fast_mailbox,
        mut terminal_chat_reply_output,
    } = state_in;
    let is_install_package_tool = current_tool_name == "sys__install_package"
        || current_tool_name == "sys::install_package"
        || current_tool_name.ends_with("install_package");
    let clarification_required = !success
        && error_msg
            .as_deref()
            .map(|msg| requires_wait_for_clarification(&current_tool_name, msg))
            .unwrap_or(false);

    if !success
        && is_install_package_tool
        && error_msg
            .as_deref()
            .map(is_sudo_password_required_install_error)
            .unwrap_or(false)
    {
        awaiting_sudo_password = true;
        stop_condition_hit = true;
        escalation_path = Some("wait_for_sudo_password".to_string());
        is_lifecycle_action = true;
        failure_class = Some(FailureClass::PermissionOrApprovalRequired);
        agent_state.status = AgentStatus::Paused("Waiting for sudo password".to_string());
        mark_incident_wait_for_user(
            state,
            session_id,
            "wait_for_sudo_password",
            FailureClass::PermissionOrApprovalRequired,
            error_msg.as_deref(),
        )?;
        // Discard any queued remediation actions so resume prioritizes retrying
        // the canonical pending install with user-provided runtime secret.
        agent_state.execution_queue.clear();
        agent_state.pending_approval = None;
        agent_state.pending_tool_call = Some(tool_call_result.clone());
        agent_state.pending_request_nonce = Some(agent_state.step_count as u64);
        agent_state.pending_visual_hash = Some(final_visual_phash);
        agent_state.last_screen_phash = Some(final_visual_phash);
        if let Some(tool_jcs) = executed_tool_jcs.clone() {
            let tool_hash_bytes = ioi_crypto::algorithms::hash::sha256(&tool_jcs).map_err(|e| {
                TransactionError::Invalid(format!("Failed to hash pending install tool: {}", e))
            })?;
            let mut hash_arr = [0u8; 32];
            hash_arr.copy_from_slice(tool_hash_bytes.as_ref());
            agent_state.pending_tool_jcs = Some(tool_jcs);
            agent_state.pending_tool_hash = Some(hash_arr);
        }
        if let Some(err_text) = error_msg.clone() {
            let tool_msg = ioi_types::app::agentic::ChatMessage {
                role: "tool".to_string(),
                content: format!("Tool Output ({}): {}", current_tool_name, err_text),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
                trace_hash: None,
            };
            let _ = service
                .append_chat_to_scs(session_id, &tool_msg, block_height)
                .await?;
        }
        let sys_msg = ioi_types::app::agentic::ChatMessage {
            role: "system".to_string(),
            content: "System: WAIT_FOR_SUDO_PASSWORD. Install requires sudo password. Enter password to retry once."
                .to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            trace_hash: None,
        };
        let _ = service
            .append_chat_to_scs(session_id, &sys_msg, block_height)
            .await?;
        verification_checks.push("awaiting_sudo_password=true".to_string());
    }

    if clarification_required {
        awaiting_clarification = true;
        stop_condition_hit = true;
        escalation_path = Some("wait_for_clarification".to_string());
        is_lifecycle_action = true;
        failure_class = Some(FailureClass::UserInterventionNeeded);
        mark_incident_wait_for_user(
            state,
            session_id,
            "wait_for_clarification",
            FailureClass::UserInterventionNeeded,
            error_msg.as_deref(),
        )?;
        agent_state.status =
            AgentStatus::Paused("Waiting for clarification on target identity.".to_string());
        agent_state.pending_approval = None;
        agent_state.pending_tool_call = None;
        agent_state.pending_tool_jcs = None;
        agent_state.pending_tool_hash = None;
        agent_state.pending_request_nonce = None;
        agent_state.pending_visual_hash = None;
        agent_state.execution_queue.clear();

        if let Some(err_text) = error_msg.clone() {
            let tool_msg = ioi_types::app::agentic::ChatMessage {
                role: "tool".to_string(),
                content: format!("Tool Output ({}): {}", current_tool_name, err_text),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
                trace_hash: None,
            };
            let _ = service
                .append_chat_to_scs(session_id, &tool_msg, block_height)
                .await?;
        }
        let sys_msg = ioi_types::app::agentic::ChatMessage {
            role: "system".to_string(),
            content:
                "System: WAIT_FOR_CLARIFICATION. Target identity could not be resolved. Provide clarification input to continue."
                    .to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            trace_hash: None,
        };
        let _ = service
            .append_chat_to_scs(session_id, &sys_msg, block_height)
            .await?;
        verification_checks.push("awaiting_clarification=true".to_string());
    }

    if invalid_tool_call_fail_fast
        && !is_gated
        && !awaiting_sudo_password
        && !awaiting_clarification
    {
        let summary = if invalid_tool_call_fail_fast_mailbox {
            format!(
                "Mailbox connector action executed, but response synthesis failed due schema validation. Please retry the request. Run timestamp (UTC ms): {}.",
                block_timestamp_ns / 1_000_000
            )
        } else {
            "Invalid tool call generated during web research. Stopping early to avoid recovery churn."
                .to_string()
        };
        success = true;
        error_msg = None;
        stop_condition_hit = true;
        escalation_path = Some("invalid_tool_call_fail_fast".to_string());
        is_lifecycle_action = true;
        action_output = Some(summary.clone());
        if invalid_tool_call_fail_fast_mailbox {
            terminal_chat_reply_output = Some(summary.clone());
            verification_checks.push("mailbox_invalid_tool_call_fail_fast=true".to_string());
            verification_checks.push("terminal_chat_reply_ready=true".to_string());
        }
        agent_state.status = AgentStatus::Completed(Some(summary));
        agent_state.execution_queue.clear();
        agent_state.pending_search_completion = None;
        verification_checks.push("invalid_tool_call_fail_fast=true".to_string());
    }

    if invalid_tool_call_bootstrap_web
        && !is_gated
        && !awaiting_sudo_password
        && !awaiting_clarification
    {
        let goal = agent_state.goal.clone();
        let queued = queue_web_search_bootstrap(agent_state, session_id, &goal)?;
        success = true;
        error_msg = None;
        stop_condition_hit = false;
        escalation_path = None;
        is_lifecycle_action = true;
        let note = if queued {
            "Model returned empty tool output; bootstrapped deterministic web__search.".to_string()
        } else {
            "Model returned empty tool output; web__search bootstrap already queued.".to_string()
        };
        history_entry = Some(note.clone());
        action_output = Some(note);
        agent_state.status = AgentStatus::Running;
        verification_checks.push("invalid_tool_call_bootstrap_web=true".to_string());
    }

    if !is_gated && !awaiting_sudo_password && !awaiting_clarification {
        maybe_normalize_unchanged_browser_snapshot(
            agent_state,
            &current_tool_name,
            &mut success,
            &mut error_msg,
            &mut history_entry,
            &mut action_output,
            &mut failure_class,
            &mut verification_checks,
        );
    }

    if !is_gated
        && !awaiting_sudo_password
        && !awaiting_clarification
        && success
        && terminal_chat_reply_output.is_none()
    {
        if let Some(completion) = browser_snapshot_completion(
            agent_state,
            &current_tool_name,
            history_entry.as_deref().or(action_output.as_deref()),
        ) {
            let summary = completion.summary;
            history_entry = Some(summary.clone());
            action_output = Some(summary.clone());
            terminal_chat_reply_output = Some(summary.clone());
            is_lifecycle_action = true;
            stop_condition_hit = true;
            escalation_path = None;
            agent_state.status = AgentStatus::Completed(Some(summary));
            agent_state.execution_queue.clear();
            agent_state.recent_actions.clear();
            agent_state.pending_search_completion = None;
            verification_checks
                .push("browser_snapshot_success_criteria_auto_completed=true".to_string());
            verification_checks.push(format!(
                "browser_snapshot_success_criteria_count={}",
                completion.matched_success_criteria.len()
            ));
            verification_checks.push(format!(
                "browser_snapshot_success_criteria={}",
                completion.matched_success_criteria.join(",")
            ));
            verification_checks.push("terminal_chat_reply_ready=true".to_string());
        }
    }

    if !is_gated
        && !awaiting_sudo_password
        && !awaiting_clarification
        && current_tool_name == "web__read"
    {
        if let Some(mut pending) = agent_state.pending_search_completion.clone() {
            let read_url = extract_web_read_url_from_payload(&action_payload).unwrap_or_default();
            if !read_url.is_empty() {
                mark_pending_web_attempted(&mut pending, &read_url);
            }

            if success {
                if let Some(bundle) = history_entry.as_deref().and_then(parse_web_evidence_bundle) {
                    append_pending_web_success_from_bundle(&mut pending, &bundle, &read_url);
                } else {
                    append_pending_web_success_fallback(
                        &mut pending,
                        &read_url,
                        history_entry.as_deref(),
                    );
                }
            } else if !read_url.is_empty()
                && is_human_challenge_error(error_msg.as_deref().unwrap_or(""))
            {
                mark_pending_web_blocked(&mut pending, &read_url);
            }

            let now_ms = web_pipeline_now_ms();
            let elapsed_ms = now_ms.saturating_sub(pending.started_at_ms);
            let remaining_candidates = remaining_pending_web_candidates(&pending);
            let completion_reason = web_pipeline_completion_reason(&pending, now_ms);

            verification_checks.push(format!(
                "web_sources_success={}",
                pending.successful_reads.len()
            ));
            verification_checks.push(format!(
                "web_sources_blocked={}",
                pending.blocked_urls.len()
            ));
            verification_checks.push(format!("web_budget_ms={}", elapsed_ms));
            verification_checks.push(format!("web_remaining_candidates={}", remaining_candidates));
            verification_checks.push(format!("web_constraint_search_probe_queued={}", false));

            if let Some(reason) = completion_reason {
                let mut summary_candidates = Vec::new();
                if let Some(hybrid_summary) =
                    synthesize_web_pipeline_reply_hybrid(service, &pending, reason).await
                {
                    summary_candidates.push(
                        crate::agentic::desktop::service::step::queue::web_pipeline::FinalWebSummaryCandidate {
                            provider: "hybrid",
                            summary: hybrid_summary,
                        },
                    );
                }
                summary_candidates.push(
                    crate::agentic::desktop::service::step::queue::web_pipeline::FinalWebSummaryCandidate {
                        provider: "deterministic",
                        summary: synthesize_web_pipeline_reply(&pending, reason),
                    },
                );
                let selection =
                    crate::agentic::desktop::service::step::queue::web_pipeline::select_final_web_summary_from_candidates(
                        &pending,
                        reason,
                        summary_candidates,
                    )
                    .expect("web summary selection requires at least one candidate");
                verification_checks
                    .push(format!("web_final_summary_provider={}", selection.provider));
                verification_checks.push(format!(
                    "web_final_summary_contract_ready={}",
                    selection.contract_ready
                ));
                for evaluation in &selection.evaluations {
                    verification_checks.push(format!(
                        "web_final_summary_candidate={}::contract_ready={}::rendered_layout={}::document_layout_met={}",
                        evaluation.provider,
                        evaluation.contract_ready,
                        evaluation.facts.briefing_rendered_layout_profile,
                        evaluation.facts.briefing_document_layout_met
                    ));
                }
                let summary = selection.summary;
                let final_facts =
                    final_web_completion_facts_with_rendered_summary(&pending, reason, &summary);
                let intent_id = resolved_intent_id(agent_state);
                crate::agentic::desktop::service::step::queue::emit_final_web_completion_contract_receipts(
                    service,
                    session_id,
                    agent_state.step_count,
                    intent_id.as_str(),
                    &final_facts,
                );
                append_final_web_completion_receipts_with_rendered_summary(
                    &pending,
                    reason,
                    &summary,
                    &mut verification_checks,
                );
                if !crate::agentic::desktop::service::step::queue::web_pipeline::final_web_completion_contract_ready(&final_facts) {
                    agent_state.pending_search_completion = Some(pending);
                    verification_checks.push("execution_contract_gate_blocked=true".to_string());
                    verification_checks.push(
                        "execution_contract_missing_keys=receipt::final_output_contract_ready=true"
                            .to_string(),
                    );
                    verification_checks.push(
                        "web_pipeline_terminalization_blocked_on_rendered_output=true"
                            .to_string(),
                    );
                    verification_checks.push("web_pipeline_active=true".to_string());
                    verification_checks.push("terminal_chat_reply_ready=false".to_string());
                    let blocked_by_challenge =
                        is_human_challenge_error(error_msg.as_deref().unwrap_or(""));
                    normalize_blocked_web_read_for_continuation(
                        &mut success,
                        &mut error_msg,
                        &mut history_entry,
                        &mut action_output,
                        &mut stop_condition_hit,
                        &mut escalation_path,
                        &mut verification_checks,
                        &read_url,
                        blocked_by_challenge,
                    );
                    if success {
                        agent_state.status = AgentStatus::Running;
                    }
                } else {
                    success = true;
                    error_msg = None;
                    action_output = Some(summary.clone());
                    history_entry = Some(summary.clone());
                    terminal_chat_reply_output = Some(summary.clone());
                    is_lifecycle_action = true;
                    agent_state.status = AgentStatus::Completed(Some(summary));
                    agent_state.pending_search_completion = None;
                    agent_state.execution_queue.clear();
                    agent_state.recent_actions.clear();
                    verification_checks.push("web_pipeline_active=false".to_string());
                    verification_checks.push("terminal_chat_reply_ready=true".to_string());
                }
            } else {
                let challenge = is_human_challenge_error(error_msg.as_deref().unwrap_or(""));
                agent_state.pending_search_completion = Some(pending);
                verification_checks.push("web_pipeline_active=true".to_string());
                normalize_blocked_web_read_for_continuation(
                    &mut success,
                    &mut error_msg,
                    &mut history_entry,
                    &mut action_output,
                    &mut stop_condition_hit,
                    &mut escalation_path,
                    &mut verification_checks,
                    &read_url,
                    challenge,
                );
                if success {
                    agent_state.status = AgentStatus::Running;
                }
            }
        }
    }

    Ok(ActionProcessingState {
        policy_decision,
        action_payload,
        intent_hash,
        retry_intent_hash,
        success,
        error_msg,
        is_gated,
        is_lifecycle_action,
        current_tool_name,
        history_entry,
        action_output,
        trace_visual_hash,
        executed_tool_jcs,
        failure_class,
        stop_condition_hit,
        escalation_path,
        remediation_queued,
        verification_checks,
        awaiting_sudo_password,
        awaiting_clarification,
        command_probe_completed,
        invalid_tool_call_fail_fast,
        invalid_tool_call_bootstrap_web,
        invalid_tool_call_fail_fast_mailbox,
        terminal_chat_reply_output,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        blocked_web_read_note, maybe_normalize_unchanged_browser_snapshot,
        normalize_blocked_web_read_for_continuation, BROWSER_SNAPSHOT_CONTENT_HASH_RECEIPT,
        BROWSER_SNAPSHOT_CONTENT_STEP_RECEIPT,
    };
    use crate::agentic::desktop::service::step::action::support::{
        execution_receipt_value, receipt_marker,
    };
    use crate::agentic::desktop::service::step::anti_loop::FailureClass;
    use crate::agentic::desktop::types::{AgentMode, AgentState, AgentStatus, ExecutionTier};
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
    fn normalize_blocked_web_read_for_continuation_clears_failure_state() {
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

        assert!(success);
        assert!(error_msg.is_none());
        assert_eq!(
            history_entry.as_deref(),
            Some(
                "Recorded challenged source in fixed payload (no fallback retries): https://example.com"
            )
        );
        assert_eq!(history_entry, action_output);
        assert!(!stop_condition_hit);
        assert!(escalation_path.is_none());
        assert!(verification_checks
            .iter()
            .any(|check| check == "web_blocked_read_continues=true"));
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
            "browser__snapshot",
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
            .contains_key(&receipt_marker(BROWSER_SNAPSHOT_CONTENT_HASH_RECEIPT)));
        assert_eq!(
            execution_receipt_value(
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
            "browser__snapshot",
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
            "browser__snapshot",
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
            "browser__snapshot",
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
}
