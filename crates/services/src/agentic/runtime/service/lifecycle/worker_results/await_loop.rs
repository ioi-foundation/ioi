use super::*;
use crate::agentic::runtime::service::step::action::command_contract::is_completion_contract_error;
use ioi_types::app::ActionTarget;

pub(crate) fn await_child_burst_step_limit(
    state: &dyn StateAccess,
    child_session_id: [u8; 32],
    child_state: &AgentState,
) -> Result<usize, String> {
    let Some(assignment) = load_worker_assignment(state, child_session_id)? else {
        return Ok(MAX_AWAIT_CHILD_BURST_STEPS);
    };
    if patch_build_verify_post_edit_followup_due(child_state, &assignment) {
        return Ok(MAX_AWAIT_CHILD_BURST_STEPS + PATCH_BUILD_VERIFY_POST_EDIT_BURST_GRACE_STEPS);
    }
    if assignment.workflow_id.as_deref().map(str::trim) == Some("live_research_brief") {
        return Ok(LIVE_RESEARCH_AWAIT_BURST_STEPS);
    }
    Ok(MAX_AWAIT_CHILD_BURST_STEPS)
}

pub(crate) async fn drive_child_session_once(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    call_context: ServiceCallContext<'_>,
    child_session_id: [u8; 32],
) -> Result<(), String> {
    let mut tx_context = TxContext {
        block_height: call_context.block_height,
        block_timestamp: call_context.block_timestamp,
        chain_id: call_context.chain_id,
        signer_account_id: call_context.signer_account_id,
        services: call_context.services,
        simulation: call_context.simulation,
        is_internal: call_context.is_internal,
    };
    Box::pin(handle_step(
        service,
        state,
        StepAgentParams {
            session_id: child_session_id,
        },
        &mut tx_context,
    ))
    .await
    .map_err(|error| error.to_string())
}

pub(crate) fn child_allows_await_burst(
    state: &dyn StateAccess,
    child_session_id: [u8; 32],
) -> Result<bool, String> {
    let Some(assignment) = load_worker_assignment(state, child_session_id)? else {
        return Ok(false);
    };
    let playbook_managed = assignment
        .playbook_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some();
    if !playbook_managed || assignment.allowed_tools.is_empty() {
        return Ok(false);
    }

    if assignment.workflow_id.as_deref().map(str::trim) == Some("live_research_brief") {
        return Ok(assignment
            .allowed_tools
            .iter()
            .all(|tool_name| tool_name_allows_research_await_burst(tool_name)));
    }

    Ok(assignment
        .allowed_tools
        .iter()
        .all(|tool_name| tool_name_allows_local_await_burst(tool_name)))
}

pub(crate) async fn merge_blocked_child_worker_result(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    parent_state: &mut AgentState,
    parent_step_index: u32,
    child_session_id_hex: &str,
    child_state: &AgentState,
) -> Result<String, String> {
    let child_session_id = child_state.session_id;
    let mut result =
        load_or_materialize_worker_result(service, state, child_state, child_session_id)?;

    if result.parent_session_id != parent_state.session_id {
        return Err(format!(
            "ERROR_CLASS=UnexpectedState Child session '{}' does not belong to the awaiting parent session.",
            child_session_id_hex
        ));
    }
    merge_child_pending_search_completion_into_parent(parent_state, child_state);

    if result.merged_at_ms.is_none() {
        result.merged_at_ms = Some(now_ms());
        result.merged_step_index = Some(parent_step_index);
        persist_worker_session_result(state, &result)?;
        emit_worker_merge_receipt(service, &result, parent_step_index);
    }
    if let Some(playbook_update) = block_parent_playbook_after_worker_failure(
        service,
        state,
        parent_state,
        parent_step_index,
        &result,
    )? {
        return Ok(playbook_update);
    }
    Err(format!(
        "ERROR_CLASS={} Child agent failed: {}",
        extract_error_class_token(result.error.as_deref()).unwrap_or("UserInterventionNeeded"),
        result
            .error
            .as_deref()
            .unwrap_or("worker step paused without an explicit reason")
    ))
}

pub(crate) async fn merge_terminal_child_worker_result(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    parent_state: &mut AgentState,
    parent_step_index: u32,
    block_height: u64,
    child_session_id_hex: &str,
    child_state: &AgentState,
) -> Result<String, String> {
    let child_session_id = child_state.session_id;
    let mut result =
        load_or_materialize_worker_result(service, state, child_state, child_session_id)?;

    if result.parent_session_id != parent_state.session_id {
        return Err(format!(
            "ERROR_CLASS=UnexpectedState Child session '{}' does not belong to the awaiting parent session.",
            child_session_id_hex
        ));
    }
    merge_child_pending_search_completion_into_parent(parent_state, child_state);

    if !result.success {
        if result.merged_at_ms.is_none() {
            result.merged_at_ms = Some(now_ms());
            result.merged_step_index = Some(parent_step_index);
            persist_worker_session_result(state, &result)?;
            emit_worker_merge_receipt(service, &result, parent_step_index);
        }
        if let Some(playbook_update) = block_parent_playbook_after_worker_failure(
            service,
            state,
            parent_state,
            parent_step_index,
            &result,
        )? {
            return Ok(playbook_update);
        }
        return Err(format!(
            "ERROR_CLASS={} Child agent failed: {}",
            extract_error_class_token(result.error.as_deref()).unwrap_or("UnexpectedState"),
            result.error.as_deref().unwrap_or("worker step failed")
        ));
    }

    let mut merged_output = result.merged_output.clone();
    if result.merged_at_ms.is_none() {
        result.merged_at_ms = Some(now_ms());
        result.merged_step_index = Some(parent_step_index);
        persist_worker_session_result(state, &result)?;
        emit_worker_merge_receipt(service, &result, parent_step_index);
        if let Some(playbook_update) = advance_parent_playbook_after_worker_merge(
            service,
            state,
            parent_state,
            parent_step_index,
            block_height,
            &result,
        )
        .await?
        {
            merged_output = format!("{}\n\n{}", merged_output, playbook_update);
        }
    }

    Ok(merged_output)
}

pub(crate) async fn maybe_merge_observed_patch_build_verify_completion(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    parent_state: &mut AgentState,
    parent_step_index: u32,
    block_height: u64,
    child_session_id_hex: &str,
    child_state: &mut AgentState,
) -> Result<Option<String>, String> {
    let Some(assignment) = load_worker_assignment(state, child_state.session_id)? else {
        return Ok(None);
    };
    let Some(summary) = synthesize_observed_patch_build_verify_completion(child_state, &assignment)
    else {
        return Ok(None);
    };

    child_state.status = AgentStatus::Completed(Some(summary));
    let child_key = get_state_key(&child_state.session_id);
    persist_agent_state(
        state,
        &child_key,
        child_state,
        service.memory_runtime.as_ref(),
    )
    .map_err(|error| {
        format!(
            "ERROR_CLASS=UnexpectedState Failed to persist observed worker completion: {}",
            error
        )
    })?;

    let merged_output = merge_terminal_child_worker_result(
        service,
        state,
        parent_state,
        parent_step_index,
        block_height,
        child_session_id_hex,
        child_state,
    )
    .await?;
    Ok(Some(merged_output))
}

fn queued_agent_complete_result(child_state: &AgentState) -> Option<String> {
    let request = child_state.execution_queue.first()?;
    match &request.target {
        ActionTarget::Custom(name) if name.trim() == "agent__complete" => {}
        _ => return None,
    }
    let value = serde_json::from_slice::<serde_json::Value>(&request.params).ok()?;
    value
        .get("result")
        .and_then(|result| result.as_str())
        .map(str::trim)
        .filter(|result| !result.is_empty())
        .map(str::to_string)
}

fn worker_contract_has_material_handoff(contract: &WorkerCompletionContract) -> bool {
    !contract.success_criteria.trim().is_empty() && !contract.expected_output.trim().is_empty()
}

fn assignment_authorizes_completion_tool(assignment: &WorkerAssignment) -> bool {
    assignment
        .allowed_tools
        .iter()
        .any(|tool_name| tool_name.trim() == "agent__complete")
}

fn assignment_requires_workspace_edit_evidence(assignment: &WorkerAssignment) -> bool {
    assignment.allowed_tools.iter().any(|tool_name| {
        matches!(
            tool_name.trim(),
            "file__edit" | "file__replace_line" | "file__write"
        )
    })
}

pub(crate) fn awaited_worker_handoff_completion_allowed(
    child_state: &AgentState,
    assignment: &WorkerAssignment,
) -> bool {
    if !worker_contract_has_material_handoff(&assignment.completion_contract)
        || !assignment_authorizes_completion_tool(assignment)
    {
        return false;
    }

    if assignment_requires_workspace_edit_evidence(assignment) {
        return latest_workspace_edit_step(child_state).is_some()
            && assignment
                .completion_contract
                .verification_hint
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_some();
    }

    true
}

pub(crate) async fn maybe_merge_queued_worker_handoff_completion(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    parent_state: &mut AgentState,
    parent_step_index: u32,
    block_height: u64,
    child_session_id_hex: &str,
    child_state: &mut AgentState,
) -> Result<Option<String>, String> {
    let Some(result) = queued_agent_complete_result(child_state) else {
        return Ok(None);
    };
    let Some(assignment) = load_worker_assignment(state, child_state.session_id)? else {
        return Ok(None);
    };
    if !awaited_worker_handoff_completion_allowed(child_state, &assignment) {
        return Ok(None);
    }

    child_state.execution_queue.remove(0);
    child_state.clear_pending_action_state();
    child_state.step_count = child_state.step_count.saturating_add(1);
    child_state.status = AgentStatus::Completed(Some(result));
    let child_key = get_state_key(&child_state.session_id);
    persist_agent_state(
        state,
        &child_key,
        child_state,
        service.memory_runtime.as_ref(),
    )
    .map_err(|error| {
        format!(
            "ERROR_CLASS=UnexpectedState Failed to persist awaited worker handoff completion: {}",
            error
        )
    })?;

    let merged_output = merge_terminal_child_worker_result(
        service,
        state,
        parent_state,
        parent_step_index,
        block_height,
        child_session_id_hex,
        child_state,
    )
    .await?;
    Ok(Some(merged_output))
}

pub(crate) async fn await_child_worker_result(
    service: &RuntimeAgentService,
    state: &mut dyn StateAccess,
    parent_state: &mut AgentState,
    parent_step_index: u32,
    block_height: u64,
    call_context: ServiceCallContext<'_>,
    child_session_id_hex: &str,
) -> Result<String, String> {
    let active_child_session_id = parse_child_session_id_hex(child_session_id_hex)?;
    let mut burst_steps = 0usize;
    let mut merged_updates: Vec<String> = Vec::new();

    loop {
        let active_child_session_id_hex = hex::encode(active_child_session_id);
        let allow_burst = child_allows_await_burst(state, active_child_session_id)?;
        let mut child_state = load_child_state(
            state,
            service.memory_runtime.as_ref(),
            active_child_session_id,
            &active_child_session_id_hex,
        )?;
        let mut burst_limit = if allow_burst {
            await_child_burst_step_limit(state, active_child_session_id, &child_state)?
        } else {
            MAX_AWAIT_CHILD_BURST_STEPS
        };
        let retry_blocked_reason = match &child_state.status {
            AgentStatus::Paused(reason) if retry_blocked_pause_reason(reason) => {
                Some(reason.to_string())
            }
            _ => None,
        };
        if let Some(merged_output) = maybe_merge_queued_worker_handoff_completion(
            service,
            state,
            parent_state,
            parent_step_index,
            block_height,
            &active_child_session_id_hex,
            &mut child_state,
        )
        .await?
        {
            merged_updates.push(merged_output);
            return Ok(merged_updates.join("\n\n"));
        }
        if retry_blocked_reason.is_some() {
            if let Some(merged_output) = maybe_merge_observed_patch_build_verify_completion(
                service,
                state,
                parent_state,
                parent_step_index,
                block_height,
                &active_child_session_id_hex,
                &mut child_state,
            )
            .await?
            {
                merged_updates.push(merged_output);
                return Ok(merged_updates.join("\n\n"));
            }
        }

        let should_drive = matches!(
            &child_state.status,
            AgentStatus::Running | AgentStatus::Idle
        ) || matches!(
            &child_state.status,
            AgentStatus::Paused(reason) if retry_blocked_pause_reason(reason)
        );
        if should_drive {
            if allow_burst && burst_steps >= burst_limit {
                return Ok(merged_updates
                    .pop()
                    .unwrap_or_else(|| "Running".to_string()));
            }
            if let Err(error) =
                drive_child_session_once(service, state, call_context, active_child_session_id)
                    .await
            {
                if is_completion_contract_error(Some(&error)) {
                    child_state = load_child_state(
                        state,
                        service.memory_runtime.as_ref(),
                        active_child_session_id,
                        &active_child_session_id_hex,
                    )?;
                    if let Some(merged_output) = maybe_merge_queued_worker_handoff_completion(
                        service,
                        state,
                        parent_state,
                        parent_step_index,
                        block_height,
                        &active_child_session_id_hex,
                        &mut child_state,
                    )
                    .await?
                    {
                        merged_updates.push(merged_output);
                        return Ok(merged_updates.join("\n\n"));
                    }
                    return Ok(merged_updates
                        .pop()
                        .unwrap_or_else(|| "Running".to_string()));
                }
                return Err(error);
            }
            burst_steps = burst_steps.saturating_add(1);
            child_state = load_child_state(
                state,
                service.memory_runtime.as_ref(),
                active_child_session_id,
                &active_child_session_id_hex,
            )?;
            burst_limit = if allow_burst {
                await_child_burst_step_limit(state, active_child_session_id, &child_state)?
            } else {
                MAX_AWAIT_CHILD_BURST_STEPS
            };
        }

        match &child_state.status {
            AgentStatus::Running | AgentStatus::Idle => {
                if allow_burst && burst_steps >= burst_limit {
                    if let Some(merged_output) = maybe_merge_observed_patch_build_verify_completion(
                        service,
                        state,
                        parent_state,
                        parent_step_index,
                        block_height,
                        &active_child_session_id_hex,
                        &mut child_state,
                    )
                    .await?
                    {
                        merged_updates.push(merged_output);
                        return Ok(merged_updates.join("\n\n"));
                    }
                }
                if !allow_burst || burst_steps >= burst_limit {
                    return Ok(merged_updates
                        .pop()
                        .unwrap_or_else(|| "Running".to_string()));
                }
            }
            AgentStatus::Paused(reason) if retry_blocked_pause_reason(reason) => {
                if !allow_burst || burst_steps >= burst_limit {
                    let paused_reason = reason.to_string();
                    if let Some(merged_output) = maybe_merge_observed_patch_build_verify_completion(
                        service,
                        state,
                        parent_state,
                        parent_step_index,
                        block_height,
                        &active_child_session_id_hex,
                        &mut child_state,
                    )
                    .await?
                    {
                        merged_updates.push(merged_output);
                        return Ok(merged_updates.join("\n\n"));
                    }
                    return Ok(merged_updates
                        .pop()
                        .unwrap_or_else(|| format!("Running (paused: {})", paused_reason)));
                }
            }
            AgentStatus::Paused(_) => {
                let paused_reason = match &child_state.status {
                    AgentStatus::Paused(reason) => reason.to_string(),
                    _ => String::new(),
                };
                if let Some(merged_output) = maybe_merge_observed_patch_build_verify_completion(
                    service,
                    state,
                    parent_state,
                    parent_step_index,
                    block_height,
                    &active_child_session_id_hex,
                    &mut child_state,
                )
                .await?
                {
                    merged_updates.push(merged_output);
                    return Ok(merged_updates.join("\n\n"));
                }
                if allow_burst {
                    let merged_output = merge_blocked_child_worker_result(
                        service,
                        state,
                        parent_state,
                        parent_step_index,
                        &active_child_session_id_hex,
                        &child_state,
                    )
                    .await?;
                    merged_updates.push(merged_output);
                    return Ok(merged_updates.join("\n\n"));
                }
                return Ok(merged_updates
                    .pop()
                    .unwrap_or_else(|| format!("Running (paused: {})", paused_reason)));
            }
            AgentStatus::Completed(_) | AgentStatus::Failed(_) | AgentStatus::Terminated => {
                let merged_output = merge_terminal_child_worker_result(
                    service,
                    state,
                    parent_state,
                    parent_step_index,
                    block_height,
                    &active_child_session_id_hex,
                    &child_state,
                )
                .await?;
                merged_updates.push(merged_output);
                return Ok(merged_updates.join("\n\n"));
            }
        }
    }
}
