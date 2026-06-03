async fn crystallize_successful_session(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    agent_state: &AgentState,
    session_id: [u8; 32],
    block_height: u64,
) {
    evaluate_and_crystallize(service, state, agent_state, session_id).await;
    let _ = service
        .update_skill_reputation(state, session_id, true, block_height)
        .await;
}

async fn record_terminal_chat_success_without_model_crystallization(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    session_id: [u8; 32],
    block_height: u64,
    verification_checks: &mut Vec<String>,
) {
    let _ = service
        .update_skill_reputation(state, session_id, true, block_height)
        .await;
    verification_checks.push("post_terminal_model_crystallization_deferred=true".to_string());
}

fn pending_web_evidence_ready_for_model_answer(
    pending: &crate::agentic::runtime::types::PendingSearchCompletion,
) -> bool {
    let required_sources = pending.min_sources.max(1) as usize;
    pending.successful_reads.len() >= required_sources
}

fn is_toolcat_single_tool_probe(goal: &str) -> bool {
    goal.contains("TOOLCAT_SINGLE_TOOL") || goal.contains("toolcat_tool=")
}

fn toolcat_single_tool_target(goal: &str) -> Option<&str> {
    goal.split_whitespace()
        .find_map(|part| part.strip_prefix("toolcat_tool="))
        .map(str::trim)
        .filter(|tool| !tool.is_empty())
}

fn history_has_successful_tool_output(history: &[ChatMessage], tool_name: &str) -> bool {
    let marker = format!("Tool Output ({}):", tool_name);
    history.iter().rev().any(|message| {
        message.role == "tool"
            && message.content.contains(&marker)
            && !message.content.contains("ERROR_CLASS=")
    })
}

fn toolcat_single_tool_target_completed(goal: &str, history: &[ChatMessage]) -> bool {
    let Some(tool_name) = toolcat_single_tool_target(goal) else {
        return false;
    };
    history_has_successful_tool_output(history, tool_name)
}

fn toolcat_single_tool_pause_reply(current_tool_name: &str) -> String {
    format!(
        "TOOLCAT_SINGLE_TOOL {} live IDE probe reached the pause control path.",
        current_tool_name
    )
}

fn toolcat_single_tool_success_reply(current_tool_name: &str, summary: &str) -> String {
    format!(
        "TOOLCAT_SINGLE_TOOL {} live IDE probe completed. {}",
        current_tool_name, summary
    )
}

fn browser_semantics_snapshot_present(text: &str) -> bool {
    text.contains("BROWSER_USE_STATE_TXT:")
        || text.contains("BROWSER_USE_PROMPT_CONTEXT_TXT:")
        || text.contains("BROWSERGYM_AXTREE_TXT:")
}

fn history_has_browser_semantics_snapshot(history: &[ChatMessage]) -> bool {
    history.iter().rev().any(|message| {
        message.role == "tool" && browser_semantics_snapshot_present(&message.content)
    })
}

#[cfg(test)]
fn blocked_terminalization_summary_from_history_and_snapshot(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
) -> Option<String> {
    blocked_terminalization_summary_from_history_and_snapshot_for_goal(
        history,
        current_snapshot,
        "",
    )
}

fn blocked_terminalization_summary_from_history_and_snapshot_for_goal(
    history: &[ChatMessage],
    current_snapshot: Option<&str>,
    goal: &str,
) -> Option<String> {
    if toolcat_single_tool_target_completed(goal, history) {
        return None;
    }

    if current_snapshot.is_some_and(browser_semantics_snapshot_present)
        || history_has_browser_semantics_snapshot(history)
    {
        return None;
    }

    let mut pending =
        build_recent_pending_browser_state_context_with_snapshot(history, current_snapshot);
    if pending.trim().is_empty() {
        if let Some(snapshot) = current_snapshot {
            pending = build_browser_snapshot_pending_state_context_with_history(snapshot, history);
        }
    }
    let pending = pending.trim();
    if pending.is_empty() {
        return None;
    }

    Some(format!(
        "Completion blocked because unresolved browser work remains. Do not finalize yet while RECENT PENDING BROWSER STATE is present. Use the named browser action first.\n{}",
        pending
    ))
}

fn blocked_terminalization_error(summary: &str) -> String {
    format!("ERROR_CLASS=NoEffectAfterAction {}", summary)
}

fn completion_gate_needs_pending_browser_check(resolved_intent_id: &str) -> bool {
    resolved_intent_id != "conversation.reply"
}

fn browser_observation_receipt_from_navigation_output(
    output: &str,
) -> Option<BrowserObservationReceipt> {
    serde_json::from_str::<serde_json::Value>(output)
        .ok()?
        .get("browser_observation_receipt")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
}

fn browser_page_title_completion_from_history(
    agent_state: &AgentState,
    tool: &AgentTool,
    history_entry: Option<&str>,
) -> Option<String> {
    if !matches!(tool, AgentTool::BrowserNavigate { .. }) {
        return None;
    }
    let route_frame = agent_state.runtime_route_frame.as_ref()?;
    if route_frame.intent_id != "browser.interact"
        || route_frame.target_kind.as_deref() != Some("browser_page_title")
    {
        return None;
    }
    let receipt = browser_observation_receipt_from_navigation_output(history_entry?)?;
    let title = receipt.title?.trim().to_string();
    if title.is_empty() {
        return None;
    }
    Some(format!("The page title is {}.", title))
}

#[cfg(test)]
fn blocked_terminalization_summary_from_history(history: &[ChatMessage]) -> Option<String> {
    blocked_terminalization_summary_from_history_and_snapshot(history, None)
}

async fn blocked_terminalization_summary(
    service: &RuntimeAgentService,
    session_id: [u8; 32],
    resolved_intent_id: &str,
    goal: &str,
) -> Option<String> {
    if !completion_gate_needs_pending_browser_check(resolved_intent_id) {
        return None;
    }

    let history = service.hydrate_session_history(session_id).ok()?;
    let current_snapshot = current_browser_observation_snapshot(service).await;
    blocked_terminalization_summary_from_history_and_snapshot_for_goal(
        &history,
        current_snapshot.as_deref(),
        goal,
    )
}

async fn handle_sys_exec_tool_outcome(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    agent_state: &mut AgentState,
    rules: &ActionRules,
    tool: &AgentTool,
    session_id: [u8; 32],
    block_height: u64,
    step_index: u32,
    resolved_intent_id: &str,
    synthesized_payload_hash: Option<String>,
    command_scope: bool,
    success: &mut bool,
    error_msg: &mut Option<String>,
    history_entry: &mut Option<String>,
    action_output: &mut Option<String>,
    terminal_chat_reply_output: &mut Option<String>,
    is_lifecycle_action: &mut bool,
    verification_checks: &mut Vec<String>,
    command_probe_completed: &mut bool,
) -> Result<(), TransactionError> {
    if is_command_probe_intent(agent_state.resolved_intent.as_ref()) {
        if let Some(raw) = history_entry.as_deref() {
            if let Some(summary) = summarize_command_probe_output(tool, raw) {
                // Probe markers are governed completion signals even when the
                // underlying command exits non-zero.
                *command_probe_completed = true;
                *success = true;
                *error_msg = None;
                agent_state.status = AgentStatus::Completed(Some(summary.clone()));
                agent_state
                    .execution_ledger
                    .record_terminal_success(Some(resolved_intent_id.to_string()));
                *is_lifecycle_action = true;
                *action_output = Some(summary);
                agent_state.execution_queue.clear();
                agent_state.pending_search_completion = None;
                crystallize_successful_session(
                    service,
                    state,
                    agent_state,
                    session_id,
                    block_height,
                )
                .await;
            }
        }
        return Ok(());
    }

    if is_system_clock_read_intent(agent_state.resolved_intent.as_ref()) {
        if let Some(summary) = history_entry
            .as_deref()
            .and_then(summarize_system_clock_or_plain_output)
        {
            let summary = enrich_command_scope_summary(&summary, agent_state);
            record_success_condition(
                &mut agent_state.tool_execution_log,
                CLOCK_TIMESTAMP_SUCCESS_CONDITION,
            );
            verification_checks.push(success_condition_key(CLOCK_TIMESTAMP_SUCCESS_CONDITION));
            emit_execution_contract_receipt_event_with_observation(
                service,
                session_id,
                step_index,
                resolved_intent_id,
                "verification",
                CLOCK_TIMESTAMP_SUCCESS_CONDITION,
                true,
                "clock_timestamp_observed=true",
                Some("command_history"),
                Some(summary.as_str()),
                Some("rfc3339_utc"),
                None,
                None,
                synthesized_payload_hash.clone(),
            );
            *success = true;
            *error_msg = None;
            agent_state.status = AgentStatus::Completed(Some(summary.clone()));
            *is_lifecycle_action = true;
            *action_output = Some(summary.clone());
            *terminal_chat_reply_output = Some(summary);
            agent_state.execution_queue.clear();
            agent_state.pending_search_completion = None;
            crystallize_successful_session(service, state, agent_state, session_id, block_height)
                .await;
        } else {
            let missing = success_condition_key(CLOCK_TIMESTAMP_SUCCESS_CONDITION);
            let contract_error = execution_contract_violation_error(&missing);
            *success = false;
            *error_msg = Some(contract_error.clone());
            *history_entry = Some(contract_error.clone());
            *action_output = Some(contract_error);
            agent_state.status = AgentStatus::Running;
            verification_checks.push("execution_contract_gate_blocked=true".to_string());
            verification_checks.push(format!("execution_contract_missing_keys={}", missing));
            emit_execution_contract_receipt_event_with_observation(
                service,
                session_id,
                step_index,
                resolved_intent_id,
                "verification",
                CLOCK_TIMESTAMP_SUCCESS_CONDITION,
                false,
                "clock_timestamp_observed=false",
                Some("command_history"),
                None,
                Some("rfc3339_utc"),
                None,
                None,
                synthesized_payload_hash,
            );
        }
        return Ok(());
    }

    if !command_scope {
        return Ok(());
    }

    if command_failure_should_stay_in_model_loop(verification_checks) {
        verification_checks.push("command_failure_terminalization_deferred=true".to_string());
        verification_checks.push("terminal_chat_reply_ready=false".to_string());
        return Ok(());
    }

    let summary = if let Some(summary) =
        duplicate_command_completion_summary(tool, agent_state.command_history.back())
    {
        Some((
            summary,
            "timer_schedule_terminalized=true",
            "command_scope_completion_gate_passed",
        ))
    } else {
        verified_command_probe_completion_summary(tool, &agent_state.command_history).map(
            |summary| {
                (
                    enrich_command_scope_summary(&summary, agent_state),
                    "verified_command_probe_terminalized=true",
                    "command_scope_verified_probe_completion_gate_passed",
                )
            },
        )
    };

    let Some((summary, terminalization_check, gate_label)) = summary else {
        return Ok(());
    };

    let missing_completion_evidence =
        evaluate_completion_requirements(agent_state, resolved_intent_id, verification_checks, rules);
    if missing_completion_evidence.is_empty() {
        *success = true;
        *error_msg = None;
        agent_state.status = AgentStatus::Completed(Some(summary.clone()));
        agent_state
            .execution_ledger
            .record_terminal_success(Some(resolved_intent_id.to_string()));
        *is_lifecycle_action = true;
        *action_output = Some(summary.clone());
        *terminal_chat_reply_output = Some(summary);
        agent_state.execution_queue.clear();
        agent_state.pending_search_completion = None;
        verification_checks.push(terminalization_check.to_string());
        verification_checks.push("terminal_chat_reply_ready=true".to_string());
        crystallize_successful_session(service, state, agent_state, session_id, block_height)
            .await;
        emit_completion_gate_status_event(
            service,
            session_id,
            step_index,
            resolved_intent_id,
            true,
            gate_label,
        );
    } else {
        let missing = missing_completion_evidence.join(",");
        let contract_error = execution_contract_violation_error(&missing);
        *success = false;
        *error_msg = Some(contract_error.clone());
        *history_entry = Some(contract_error.clone());
        *action_output = Some(contract_error);
        verification_checks.push("execution_contract_gate_blocked=true".to_string());
        verification_checks.push(format!("execution_contract_missing_keys={}", missing));
        emit_completion_gate_violation_events(
            service,
            session_id,
            step_index,
            resolved_intent_id,
            &missing,
        );
    }

    Ok(())
}

fn command_failure_should_stay_in_model_loop(verification_checks: &[String]) -> bool {
    verification_checks
        .iter()
        .any(|check| check == "command_failure_observed_as_tool_result=true")
}

#[cfg(test)]
mod command_failure_terminalization_tests {
    use super::command_failure_should_stay_in_model_loop;

    #[test]
    fn observed_command_failure_does_not_become_terminal_chat_reply() {
        assert!(command_failure_should_stay_in_model_loop(&[
            "command_failure_observed_as_tool_result=true".to_string(),
            "capability_execution_last_exit_code=1".to_string(),
        ]));
        assert!(!command_failure_should_stay_in_model_loop(&[
            "capability_execution_last_exit_code=0".to_string(),
        ]));
    }
}
