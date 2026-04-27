use super::*;

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub(crate) const MAX_AWAIT_CHILD_BURST_STEPS: usize = 6;
pub(crate) const LIVE_RESEARCH_AWAIT_BURST_STEPS: usize = 4;
// Post-edit follow-through commonly needs a reread, a focused rerun, and a final handoff.
pub(crate) const PATCH_BUILD_VERIFY_POST_EDIT_BURST_GRACE_STEPS: usize = 3;

pub(crate) fn parse_child_session_id_hex(input: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(input.trim()).map_err(|error| {
        format!(
            "ERROR_CLASS=ToolUnavailable Invalid child_session_id_hex '{}': {}",
            input, error
        )
    })?;
    if bytes.len() != 32 {
        return Err(format!(
            "ERROR_CLASS=ToolUnavailable child_session_id_hex '{}' must be 32 bytes (got {}).",
            input,
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub(crate) fn load_child_state(
    state: &dyn StateAccess,
    memory_runtime: Option<&Arc<MemoryRuntime>>,
    child_session_id: [u8; 32],
    child_session_id_hex: &str,
) -> Result<AgentState, String> {
    load_agent_state_with_runtime_preference(
        state,
        memory_runtime,
        child_session_id,
        child_session_id_hex,
    )
}

pub(crate) fn retry_blocked_pause_reason(reason: &str) -> bool {
    reason.starts_with("Retry blocked: unchanged AttemptKey for")
        || reason.starts_with("Retry guard tripped after repeated")
}

pub(crate) fn pending_search_completion_has_inventory(state: &AgentState) -> bool {
    let Some(pending) = state.pending_search_completion.as_ref() else {
        return false;
    };

    !pending.query.trim().is_empty()
        || !pending.query_contract.trim().is_empty()
        || pending.retrieval_contract.is_some()
        || !pending.url.trim().is_empty()
        || !pending.candidate_urls.is_empty()
        || !pending.candidate_source_hints.is_empty()
        || !pending.attempted_urls.is_empty()
        || !pending.blocked_urls.is_empty()
        || !pending.successful_reads.is_empty()
}

pub(crate) fn merge_child_pending_search_completion_into_parent(
    parent_state: &mut AgentState,
    child_state: &AgentState,
) {
    if !pending_search_completion_has_inventory(child_state) {
        return;
    }

    let Some(incoming) = child_state.pending_search_completion.clone() else {
        return;
    };

    parent_state.pending_search_completion =
        Some(match parent_state.pending_search_completion.take() {
            Some(existing) => merge_pending_search_completion(existing, incoming),
            None => incoming,
        });
}

pub(crate) fn tool_name_allows_local_await_burst(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "agent__complete"
            | "agent__await"
            | "file__read"
            | "file__view"
            | "file__list"
            | "file__search"
            | "file__info"
            | "file__edit"
            | "file__multi_edit"
            | "file__replace_line"
            | "file__write"
            | "memory__search"
            | "memory__read"
            | "model__rerank"
            | "shell__cd"
            | "shell__start"
    )
}

pub(crate) fn tool_name_allows_research_await_burst(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "agent__complete"
            | "agent__await"
            | "memory__search"
            | "memory__read"
            | "web__search"
            | "web__read"
    )
}

pub(crate) fn first_goal_command_literal(goal: &str) -> Option<String> {
    let (_, inherited_context) = split_parent_playbook_context(goal);
    if let Some(command) = inherited_context
        .and_then(|text| {
            extract_worker_context_field(
                text,
                &[
                    "targeted_checks",
                    "targeted_check",
                    "verification_plan",
                    "verification",
                ],
            )
        })
        .and_then(|value| value.split(';').next().map(str::trim).map(str::to_string))
        .map(|value| normalize_whitespace(&value))
        .filter(|value| looks_like_command_literal(value))
    {
        return Some(command);
    }

    collect_goal_literals(goal)
        .into_iter()
        .map(|literal| normalize_whitespace(&literal))
        .find(|literal| looks_like_command_literal(literal))
}

pub(crate) fn parse_receipt_step(value: &str) -> Option<u32> {
    value
        .split(';')
        .find_map(|part| part.trim().strip_prefix("step="))
        .and_then(|step| step.parse::<u32>().ok())
}

pub(crate) fn parse_receipt_path<'a>(value: &'a str) -> Option<&'a str> {
    value
        .split(';')
        .find_map(|part| part.trim().strip_prefix("path="))
        .map(str::trim)
        .filter(|path| !path.is_empty())
}

pub(crate) fn latest_workspace_edit_step(agent_state: &AgentState) -> Option<u32> {
    execution_evidence_value(&agent_state.tool_execution_log, "workspace_edit_applied")
        .and_then(parse_receipt_step)
}

pub(crate) fn latest_workspace_edit_path(agent_state: &AgentState) -> Option<String> {
    execution_evidence_value(&agent_state.tool_execution_log, "workspace_edit_applied")
        .and_then(parse_receipt_path)
        .map(str::to_string)
}

pub(crate) fn looks_like_file_hint(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().any(|ch| ch.is_whitespace()) {
        return false;
    }
    let normalized = trimmed.replace('\\', "/");
    let path = Path::new(trimmed);
    path.extension().is_some() || normalized.starts_with("tests/") || normalized.contains("/tests/")
}

pub(crate) fn patch_build_verify_goal_likely_files(goal: &str) -> Vec<String> {
    let (_, inherited_context) = split_parent_playbook_context(goal);
    if let Some(value) =
        inherited_context.and_then(|text| extract_worker_context_field(text, &["likely_files"]))
    {
        return value
            .split(';')
            .map(str::trim)
            .filter(|candidate| !candidate.is_empty())
            .map(str::to_string)
            .collect();
    }

    let mut seen = BTreeSet::new();
    collect_goal_literals(goal)
        .into_iter()
        .filter(|literal| looks_like_file_hint(literal))
        .filter(|literal| seen.insert(literal.to_ascii_lowercase()))
        .collect()
}

pub(crate) fn latest_successful_goal_command(
    agent_state: &AgentState,
    assignment: &WorkerAssignment,
) -> Option<String> {
    let target = first_goal_command_literal(&assignment.goal)
        .map(|command_literal| normalize_whitespace(&command_literal));
    let edit_step = latest_workspace_edit_step(agent_state);
    let mut latest_success_after_edit: Option<String> = None;
    let mut latest_success_any: Option<String> = None;

    for entry in agent_state.command_history.iter().rev() {
        if entry.exit_code != 0 {
            continue;
        }
        let observed = normalize_whitespace(&entry.command);
        if !looks_like_command_literal(&observed) {
            continue;
        }
        if let Some(target) = target.as_ref() {
            if observed == *target || observed.contains(target) {
                return Some(entry.command.trim().to_string());
            }
        }
        if latest_success_after_edit.is_none()
            && edit_step
                .map(|step| entry.step_index >= step)
                .unwrap_or(false)
        {
            latest_success_after_edit = Some(entry.command.trim().to_string());
        }
        if latest_success_any.is_none() {
            latest_success_any = Some(entry.command.trim().to_string());
        }
    }

    latest_success_after_edit.or(latest_success_any)
}

pub(crate) fn latest_successful_goal_command_after_edit(
    agent_state: &AgentState,
    assignment: &WorkerAssignment,
) -> Option<String> {
    let target = first_goal_command_literal(&assignment.goal)
        .map(|command_literal| normalize_whitespace(&command_literal));
    let edit_step = latest_workspace_edit_step(agent_state)?;

    agent_state.command_history.iter().rev().find_map(|entry| {
        if entry.exit_code != 0 || entry.step_index <= edit_step {
            return None;
        }
        let observed = normalize_whitespace(&entry.command);
        if !looks_like_command_literal(&observed) {
            return None;
        }
        if let Some(target) = target.as_ref() {
            if observed == *target || observed.contains(target) {
                return Some(entry.command.trim().to_string());
            }
        }
        Some(entry.command.trim().to_string())
    })
}

pub(crate) fn latest_failed_goal_command_step(
    agent_state: &AgentState,
    assignment: &WorkerAssignment,
) -> Option<u32> {
    let target = first_goal_command_literal(&assignment.goal)
        .map(|command_literal| normalize_whitespace(&command_literal));
    let mut latest_failed_any: Option<u32> = None;

    for entry in agent_state.command_history.iter().rev() {
        if entry.exit_code == 0 {
            continue;
        }
        let observed = normalize_whitespace(&entry.command);
        if !looks_like_command_literal(&observed) {
            continue;
        }
        if let Some(target) = target.as_ref() {
            if observed == *target || observed.contains(target) {
                return Some(entry.step_index);
            }
        }
        if latest_failed_any.is_none() {
            latest_failed_any = Some(entry.step_index);
        }
    }

    latest_failed_any
}

pub(crate) fn patch_build_verify_post_edit_followup_due(
    agent_state: &AgentState,
    assignment: &WorkerAssignment,
) -> bool {
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_build_verify") {
        return false;
    }

    let Some(command_step) = latest_failed_goal_command_step(agent_state, assignment) else {
        return false;
    };
    let Some(edit_step) = latest_workspace_edit_step(agent_state) else {
        return false;
    };

    edit_step > command_step
}

pub(crate) fn resolve_worker_assignment(
    child_session_id: [u8; 32],
    step_index: u32,
    requested_budget: u64,
    goal: &str,
    playbook_id: Option<&str>,
    template_id: Option<&str>,
    workflow_id: Option<&str>,
    requested_role: Option<&str>,
    success_criteria: Option<&str>,
    merge_mode: Option<&str>,
    expected_output: Option<&str>,
) -> WorkerAssignment {
    let template = builtin_worker_template(template_id);
    let workflow = builtin_worker_workflow(template_id, workflow_id);
    let mut completion_contract = template
        .as_ref()
        .map(|definition| definition.completion_contract.clone())
        .unwrap_or_default();
    if let Some(workflow_completion_contract) = workflow
        .as_ref()
        .and_then(|definition| definition.completion_contract.clone())
    {
        completion_contract = workflow_completion_contract;
    }

    if let Some(value) = success_criteria
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        completion_contract.success_criteria = value.to_string();
    }
    if let Some(value) = expected_output
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        completion_contract.expected_output = value.to_string();
    }
    if let Some(mode) = WorkerMergeMode::parse_label(merge_mode) {
        completion_contract.merge_mode = mode;
    }

    if completion_contract.success_criteria.trim().is_empty() {
        completion_contract.success_criteria =
            "Complete the delegated goal and return a deterministic handoff.".to_string();
    }
    if completion_contract.expected_output.trim().is_empty() {
        completion_contract.expected_output =
            "Delegated worker handoff summarizing the completed slice.".to_string();
    }

    let role = requested_role
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| template.as_ref().map(|definition| definition.role.clone()))
        .unwrap_or_else(|| default_worker_role_label(template_id).to_string());
    let effective_budget = workflow
        .as_ref()
        .and_then(|definition| definition.default_budget)
        .map(|workflow_budget| {
            if requested_budget == 0 {
                workflow_budget
            } else {
                requested_budget.min(workflow_budget)
            }
        })
        .unwrap_or(requested_budget);
    let max_retries = workflow
        .as_ref()
        .and_then(|definition| definition.max_retries)
        .or_else(|| template.as_ref().map(|definition| definition.max_retries))
        .unwrap_or(1);
    let allowed_tools = workflow
        .as_ref()
        .filter(|definition| !definition.allowed_tools.is_empty())
        .map(|definition| definition.allowed_tools.clone())
        .or_else(|| {
            template
                .as_ref()
                .map(|definition| definition.allowed_tools.clone())
        })
        .unwrap_or_default();

    WorkerAssignment {
        step_key: format!(
            "delegate:{}:{}",
            step_index,
            hex::encode(&child_session_id[..4])
        ),
        budget: effective_budget,
        goal: resolve_worker_goal(goal, workflow.as_ref()),
        success_criteria: completion_contract.success_criteria.clone(),
        max_retries,
        retries_used: 0,
        assigned_session_id: Some(child_session_id),
        status: "running".to_string(),
        playbook_id: playbook_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        template_id: template_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        workflow_id: workflow.map(|definition| definition.workflow_id),
        role: Some(role),
        allowed_tools,
        completion_contract,
    }
}

pub(crate) fn derive_workflow_topic(raw_goal: &str) -> String {
    let trimmed = raw_goal.trim().trim_end_matches(['.', '!', '?']);
    if trimmed.is_empty() {
        return "the delegated topic".to_string();
    }

    let lowercase = trimmed.to_ascii_lowercase();
    for prefix in [
        "implement ",
        "research ",
        "find ",
        "investigate ",
        "look up ",
        "gather evidence about ",
        "gather evidence for ",
        "summarize ",
        "check ",
        "verify ",
    ] {
        if lowercase.starts_with(prefix) {
            let suffix = trimmed[prefix.len()..]
                .trim_start_matches([':', '-', ' '])
                .trim();
            if !suffix.is_empty() {
                return suffix.to_string();
            }
        }
    }

    trimmed.to_string()
}

pub(crate) fn resolve_worker_goal(
    raw_goal: &str,
    workflow: Option<&WorkerTemplateWorkflowDefinition>,
) -> String {
    let (goal_without_context, inherited_context) =
        if let Some((head, tail)) = raw_goal.split_once(PARENT_PLAYBOOK_CONTEXT_MARKER) {
            (head.trim(), Some(tail.trim()))
        } else {
            (raw_goal.trim(), None)
        };
    let Some(workflow) = workflow else {
        return raw_goal.to_string();
    };
    let goal_template = workflow.goal_template.trim();
    if goal_template.is_empty() {
        return raw_goal.to_string();
    }

    if let Some(context) = inherited_context.filter(|value| !value.is_empty()) {
        return format!(
            "{}\n\n{}\n{}",
            goal_without_context, PARENT_PLAYBOOK_CONTEXT_MARKER, context
        );
    }

    let topic = derive_workflow_topic(goal_without_context);
    let resolved = goal_template.replace("{topic}", &topic);
    resolved
}

pub(crate) fn persist_worker_assignment(
    state: &mut dyn StateAccess,
    child_session_id: [u8; 32],
    assignment: &WorkerAssignment,
) -> Result<(), TransactionError> {
    let key = get_worker_assignment_key(&child_session_id);
    let bytes = codec::to_bytes_canonical(assignment)?;
    state.insert(&key, &bytes)?;
    Ok(())
}

pub(crate) fn load_worker_assignment(
    state: &dyn StateAccess,
    child_session_id: [u8; 32],
) -> Result<Option<WorkerAssignment>, String> {
    let key = get_worker_assignment_key(&child_session_id);
    let Some(bytes) = state.get(&key).map_err(|error| {
        format!(
            "ERROR_CLASS=UnexpectedState Failed to read worker assignment: {}",
            error
        )
    })?
    else {
        return Ok(None);
    };
    codec::from_bytes_canonical::<WorkerAssignment>(&bytes)
        .map(Some)
        .map_err(|error| {
            format!(
                "ERROR_CLASS=UnexpectedState Failed to decode worker assignment: {}",
                error
            )
        })
}

pub(crate) fn load_worker_session_result(
    state: &dyn StateAccess,
    child_session_id: [u8; 32],
) -> Result<Option<WorkerSessionResult>, String> {
    let key = get_session_result_key(&child_session_id);
    let Some(bytes) = state.get(&key).map_err(|error| {
        format!(
            "ERROR_CLASS=UnexpectedState Failed to read worker session result: {}",
            error
        )
    })?
    else {
        return Ok(None);
    };
    codec::from_bytes_canonical::<WorkerSessionResult>(&bytes)
        .map(Some)
        .map_err(|error| {
            format!(
                "ERROR_CLASS=UnexpectedState Failed to decode worker session result: {}",
                error
            )
        })
}

pub(crate) fn persist_worker_session_result(
    state: &mut dyn StateAccess,
    result: &WorkerSessionResult,
) -> Result<(), String> {
    let key = get_session_result_key(&result.child_session_id);
    let bytes = codec::to_bytes_canonical(result).map_err(|error| {
        format!(
            "ERROR_CLASS=UnexpectedState Failed to encode worker session result: {}",
            error
        )
    })?;
    state.insert(&key, &bytes).map_err(|error| {
        format!(
            "ERROR_CLASS=UnexpectedState Failed to persist worker session result: {}",
            error
        )
    })?;
    Ok(())
}

pub(crate) fn load_parent_playbook_run(
    state: &dyn StateAccess,
    parent_session_id: [u8; 32],
    playbook_id: &str,
) -> Result<Option<ParentPlaybookRun>, String> {
    let key = get_parent_playbook_run_key(&parent_session_id, playbook_id);
    let Some(bytes) = state.get(&key).map_err(|error| {
        format!(
            "ERROR_CLASS=UnexpectedState Failed to read parent playbook run: {}",
            error
        )
    })?
    else {
        return Ok(None);
    };
    codec::from_bytes_canonical::<ParentPlaybookRun>(&bytes)
        .map(Some)
        .map_err(|error| {
            format!(
                "ERROR_CLASS=UnexpectedState Failed to decode parent playbook run: {}",
                error
            )
        })
}

pub(crate) fn persist_parent_playbook_run(
    state: &mut dyn StateAccess,
    run: &ParentPlaybookRun,
) -> Result<(), String> {
    let key = get_parent_playbook_run_key(&run.parent_session_id, &run.playbook_id);
    let bytes = codec::to_bytes_canonical(run).map_err(|error| {
        format!(
            "ERROR_CLASS=UnexpectedState Failed to encode parent playbook run: {}",
            error
        )
    })?;
    state.insert(&key, &bytes).map_err(|error| {
        format!(
            "ERROR_CLASS=UnexpectedState Failed to persist parent playbook run: {}",
            error
        )
    })?;
    Ok(())
}

pub(crate) fn build_parent_playbook_run(
    parent_state: &AgentState,
    playbook: &AgentPlaybookDefinition,
    timestamp_ms: u64,
) -> ParentPlaybookRun {
    ParentPlaybookRun {
        parent_session_id: parent_state.session_id,
        playbook_id: playbook.playbook_id.clone(),
        playbook_label: playbook.label.clone(),
        topic: parent_state.goal.trim().to_string(),
        status: ParentPlaybookStatus::Running,
        current_step_index: 0,
        active_child_session_id: None,
        started_at_ms: timestamp_ms,
        updated_at_ms: timestamp_ms,
        completed_at_ms: None,
        steps: playbook
            .steps
            .iter()
            .map(|step| ParentPlaybookStepRun {
                step_id: step.step_id.clone(),
                label: step.label.clone(),
                summary: step.summary.clone(),
                status: ParentPlaybookStepStatus::Pending,
                child_session_id: None,
                template_id: Some(step.worker_template_id.clone()),
                workflow_id: Some(step.worker_workflow_id.clone()),
                goal: None,
                selected_skills: Vec::new(),
                prep_summary: None,
                artifact_generation: None,
                computer_use_perception: None,
                research_scorecard: None,
                artifact_quality: None,
                computer_use_verification: None,
                coding_scorecard: None,
                patch_synthesis: None,
                artifact_repair: None,
                computer_use_recovery: None,
                output_preview: None,
                error: None,
                spawned_at_ms: None,
                completed_at_ms: None,
                merged_at_ms: None,
            })
            .collect(),
    }
}

pub(crate) fn find_playbook_step_index(
    playbook: &AgentPlaybookDefinition,
    template_id: Option<&str>,
    workflow_id: Option<&str>,
) -> Option<usize> {
    playbook.steps.iter().position(|step| {
        let template_matches = template_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value == step.worker_template_id)
            .unwrap_or(false);
        let workflow_matches = workflow_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value == step.worker_workflow_id)
            .unwrap_or(false);
        workflow_matches || template_matches
    })
}

pub(crate) fn find_run_step_index_by_child(
    run: &ParentPlaybookRun,
    child_session_id: [u8; 32],
) -> Option<usize> {
    run.steps
        .iter()
        .position(|step| step.child_session_id == Some(child_session_id))
}

pub(crate) fn summarize_parent_playbook_text(text: &str) -> String {
    worker_receipt_summary(text)
}
