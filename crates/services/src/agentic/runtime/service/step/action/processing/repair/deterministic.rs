use super::*;

pub(crate) fn synthesize_patch_build_verify_targeted_exec_repair(
    agent_state: &AgentState,
    worker_assignment: Option<&WorkerAssignment>,
    latest_failure: Option<FailureClass>,
    effective_failure: Option<FailureClass>,
    allowed_tool_names: &BTreeSet<String>,
    raw_tool_output: &str,
    verification_checks: &mut Vec<String>,
) -> Option<AgentTool> {
    let assignment = worker_assignment.and_then(|assignment| {
        (assignment.workflow_id.as_deref().map(str::trim) == Some("patch_build_verify"))
            .then_some(assignment)
    })?;
    let command_literal = first_goal_command_literal(&assignment.goal)?;
    let command_already_ran = command_history_contains_goal_command(agent_state, &command_literal);
    let command_retry_ready_after_edit =
        goal_command_retry_ready_after_workspace_edit(agent_state, &command_literal);
    let initial_targeted_command_due = !command_already_ran
        && matches!(latest_failure, Some(FailureClass::NoEffectAfterAction))
        && matches!(effective_failure, Some(FailureClass::NoEffectAfterAction));
    if !command_retry_ready_after_edit
        && !initial_targeted_command_due
        && !looks_like_planning_restatement(raw_tool_output)
    {
        return None;
    }

    synthesize_patch_build_verify_targeted_exec_followup(
        agent_state,
        worker_assignment,
        latest_failure,
        effective_failure,
        allowed_tool_names,
        "goal_targeted_command",
        verification_checks,
    )
}

pub(crate) fn synthesize_patch_build_verify_targeted_exec_refusal_repair(
    agent_state: &AgentState,
    worker_assignment: Option<&WorkerAssignment>,
    latest_failure: Option<FailureClass>,
    effective_failure: Option<FailureClass>,
    allowed_tool_names: &BTreeSet<String>,
    refusal_reason: &str,
    verification_checks: &mut Vec<String>,
) -> Option<AgentTool> {
    if !reason_is_empty_content_refusal(refusal_reason) {
        return None;
    }

    if latest_failure.is_none() && effective_failure.is_none() {
        if let Some(repaired_tool) = synthesize_patch_build_verify_targeted_exec_bootstrap(
            agent_state,
            worker_assignment,
            allowed_tool_names,
            verification_checks,
        ) {
            return Some(repaired_tool);
        }
    }

    synthesize_patch_build_verify_targeted_exec_followup(
        agent_state,
        worker_assignment,
        latest_failure,
        effective_failure,
        allowed_tool_names,
        "refusal_empty_content",
        verification_checks,
    )
}

pub(crate) fn synthesize_patch_build_verify_targeted_exec_bootstrap(
    agent_state: &AgentState,
    worker_assignment: Option<&WorkerAssignment>,
    allowed_tool_names: &BTreeSet<String>,
    verification_checks: &mut Vec<String>,
) -> Option<AgentTool> {
    let assignment = worker_assignment?;
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_build_verify") {
        return None;
    }
    if !allowed_tool_names.contains("sys__exec_session") {
        return None;
    }

    let command_literal = first_goal_command_literal(&assignment.goal)?;
    if command_history_contains_goal_command(agent_state, &command_literal) {
        return None;
    }

    verification_checks
        .push("invalid_tool_call_repair_deterministic_recovery=targeted_exec".to_string());
    verification_checks.push(
        "invalid_tool_call_repair_deterministic_source=refusal_empty_content_bootstrap".to_string(),
    );
    verification_checks.push(format!(
        "invalid_tool_call_repair_targeted_command={}",
        sanitize_check_value(&command_literal)
    ));
    verification_checks
        .push("invalid_tool_call_repair_targeted_command_bootstrap=initial".to_string());

    Some(AgentTool::SysExecSession {
        command: "bash".to_string(),
        args: vec!["-lc".to_string(), command_literal],
        stdin: None,
    })
}

pub(crate) fn synthesize_patch_build_verify_targeted_exec_followup(
    agent_state: &AgentState,
    worker_assignment: Option<&WorkerAssignment>,
    latest_failure: Option<FailureClass>,
    effective_failure: Option<FailureClass>,
    allowed_tool_names: &BTreeSet<String>,
    recovery_source: &str,
    verification_checks: &mut Vec<String>,
) -> Option<AgentTool> {
    let assignment = worker_assignment?;
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_build_verify") {
        return None;
    }
    if !matches!(
        latest_failure,
        Some(FailureClass::NoEffectAfterAction) | Some(FailureClass::UnexpectedState)
    ) {
        return None;
    }
    if !allowed_tool_names.contains("sys__exec_session") {
        return None;
    }
    let command_literal = first_goal_command_literal(&assignment.goal)?;
    let command_already_ran = command_history_contains_goal_command(agent_state, &command_literal);
    let command_retry_ready_after_edit = command_already_ran
        && goal_command_retry_ready_after_workspace_edit(agent_state, &command_literal);
    if command_already_ran && !command_retry_ready_after_edit {
        return None;
    }

    let recovery_boundary_ready = match effective_failure {
        Some(FailureClass::NoEffectAfterAction) => true,
        Some(FailureClass::UnexpectedState) => command_retry_ready_after_edit,
        _ => false,
    };
    if !recovery_boundary_ready {
        return None;
    }

    verification_checks
        .push("invalid_tool_call_repair_deterministic_recovery=targeted_exec".to_string());
    verification_checks.push(format!(
        "invalid_tool_call_repair_deterministic_source={recovery_source}"
    ));
    verification_checks.push(format!(
        "invalid_tool_call_repair_targeted_command={}",
        sanitize_check_value(&command_literal)
    ));
    if command_already_ran {
        verification_checks
            .push("invalid_tool_call_repair_targeted_command_rerun=post_edit".to_string());
        if effective_failure == Some(FailureClass::UnexpectedState) {
            verification_checks.push(
                "invalid_tool_call_repair_targeted_command_boundary=post_edit_unexpected_state"
                    .to_string(),
            );
        }
    }

    Some(AgentTool::SysExecSession {
        command: "bash".to_string(),
        args: vec!["-lc".to_string(), command_literal],
        stdin: None,
    })
}

pub(crate) fn synthesize_patch_build_verify_completion_after_success(
    agent_state: &AgentState,
    worker_assignment: Option<&WorkerAssignment>,
    verification_checks: &mut Vec<String>,
) -> Option<AgentTool> {
    let assignment = worker_assignment?;
    let command_literal = patch_build_verify_completion_ready(agent_state, assignment)?;
    verification_checks
        .push("patch_build_verify_post_success_completion_rewritten=true".to_string());
    verification_checks.push(format!(
        "patch_build_verify_post_success_completion_command={}",
        sanitize_check_value(&command_literal)
    ));
    Some(AgentTool::AgentComplete {
        result: synthesize_patch_build_verify_completion_result(
            agent_state,
            assignment,
            &command_literal,
        ),
    })
}

pub(crate) fn reason_is_empty_content_refusal(reason: &str) -> bool {
    let normalized = reason.trim().to_ascii_lowercase();
    normalized.contains("empty content") || normalized.contains("reason: stop")
}

pub(crate) fn patch_build_verify_should_prefer_non_patch_edit_repair(
    agent_state: &AgentState,
    worker_assignment: Option<&WorkerAssignment>,
) -> bool {
    let Some(assignment) = worker_assignment else {
        return false;
    };
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_build_verify") {
        return false;
    }
    if latest_command_failure_summary(agent_state).is_none() {
        return false;
    }

    assignment
        .allowed_tools
        .iter()
        .any(|tool_name| tool_name == "filesystem__write_file")
        && patch_build_verify_current_file_snapshot(agent_state, assignment, &assignment.goal)
            .is_some()
}

pub(crate) fn should_prefer_runtime_patch_build_verify_edit_repair(
    agent_state: &AgentState,
    worker_assignment: Option<&WorkerAssignment>,
) -> bool {
    let Some(assignment) = worker_assignment else {
        return false;
    };
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_build_verify") {
        return false;
    }

    latest_command_failure_summary(agent_state).is_some()
}

pub(crate) fn maybe_prefer_non_patch_edit_repair(
    agent_state: &AgentState,
    worker_assignment: Option<&WorkerAssignment>,
    repair_tools: &mut Vec<LlmToolDefinition>,
    verification_checks: &mut Vec<String>,
    prefix: &str,
) {
    if !patch_build_verify_should_prefer_non_patch_edit_repair(agent_state, worker_assignment) {
        return;
    }

    let original_len = repair_tools.len();
    repair_tools.retain(|tool| tool.name != "filesystem__patch");
    if repair_tools.len() == original_len {
        return;
    }

    verification_checks.push(format!(
        "{prefix}_patch_tool_suppressed_after_command_failure=true"
    ));
}

pub(crate) fn patch_build_verify_deterministic_allowed_tool_names(
    agent_state: &AgentState,
    worker_assignment: Option<&WorkerAssignment>,
    allowed_tool_names: &BTreeSet<String>,
    verification_checks: &mut Vec<String>,
    prefix: &str,
) -> BTreeSet<String> {
    let Some(assignment) = worker_assignment else {
        return allowed_tool_names.clone();
    };
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_build_verify") {
        return allowed_tool_names.clone();
    }
    if latest_command_failure_summary(agent_state).is_none() {
        return allowed_tool_names.clone();
    }

    let mut deterministic_allowed_tool_names = allowed_tool_names.clone();
    let mut inserted = Vec::new();
    for tool_name in ["filesystem__write_file", "filesystem__edit_line"] {
        if assignment
            .allowed_tools
            .iter()
            .any(|allowed| allowed == tool_name)
            && deterministic_allowed_tool_names.insert(tool_name.to_string())
        {
            inserted.push(tool_name);
        }
    }

    if !inserted.is_empty() {
        verification_checks.push(format!(
            "{prefix}_deterministic_assignment_tool_hints={}",
            inserted.join("|")
        ));
    }

    deterministic_allowed_tool_names
}

pub(crate) fn synthesize_patch_build_verify_refresh_read_repair(
    agent_state: &AgentState,
    worker_assignment: Option<&WorkerAssignment>,
    allowed_tool_names: &BTreeSet<String>,
    raw_tool_output: &str,
    verification_checks: &mut Vec<String>,
) -> Option<AgentTool> {
    let assignment = worker_assignment?;
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_build_verify") {
        return None;
    }
    if !allowed_tool_names.contains("filesystem__read_file") {
        return None;
    }

    let target_path = patch_build_verify_primary_patch_file(assignment, raw_tool_output)?;
    if !patch_build_verify_refresh_read_ready(agent_state, &target_path) {
        return None;
    }
    if !raw_tool_output_requests_refresh_read(raw_tool_output, &target_path) {
        return None;
    }

    verification_checks
        .push("invalid_tool_call_repair_deterministic_recovery=refresh_read".to_string());
    verification_checks
        .push("invalid_tool_call_repair_deterministic_source=patch_miss_refresh_read".to_string());
    verification_checks.push(format!(
        "invalid_tool_call_repair_patch_target={}",
        sanitize_check_value(&target_path)
    ));

    Some(AgentTool::FsRead { path: target_path })
}

pub(crate) fn synthesize_patch_build_verify_code_block_edit_repair(
    agent_state: &AgentState,
    worker_assignment: Option<&WorkerAssignment>,
    allowed_tool_names: &BTreeSet<String>,
    raw_tool_output: &str,
    verification_checks: &mut Vec<String>,
) -> Option<AgentTool> {
    let assignment = worker_assignment?;
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_build_verify") {
        return None;
    }

    let code_blocks = extract_fenced_python_function_blocks(raw_tool_output);
    if code_blocks.len() < 2 {
        return None;
    }

    let target_path = patch_build_verify_primary_patch_file(assignment, raw_tool_output)?;
    let resolved_path =
        resolve_tool_path(&target_path, Some(&agent_state.working_directory)).ok()?;
    let file_content = fs::read_to_string(&resolved_path).ok()?;
    let current_block = code_blocks.first()?.clone();
    let updated_block = code_blocks.last()?.clone();
    if current_block.is_empty() || updated_block.is_empty() {
        return None;
    }

    let (search, replace) = match patch_search_block(&file_content, &current_block) {
        Some(search) => {
            if normalize_block_for_match(&search) == normalize_block_for_match(&updated_block) {
                return None;
            }
            (
                search.clone(),
                normalize_replacement_block(&search, &updated_block),
            )
        }
        None => {
            let reference_block = extract_primary_python_function_block(&file_content)?;
            if !python_blocks_reference_same_function(&reference_block, &current_block) {
                return None;
            }
            let aligned_updated_block =
                align_python_block_to_reference(&updated_block, &reference_block)?;
            if normalize_block_for_match(&reference_block)
                == normalize_block_for_match(&aligned_updated_block)
            {
                return None;
            }
            verification_checks.push(
                "invalid_tool_call_repair_deterministic_alignment=python_function_indent"
                    .to_string(),
            );
            (
                reference_block.clone(),
                normalize_replacement_block(&reference_block, &aligned_updated_block),
            )
        }
    };

    verification_checks
        .push("invalid_tool_call_repair_deterministic_source=fenced_code_blocks".to_string());
    verification_checks.push(format!(
        "invalid_tool_call_repair_patch_target={}",
        sanitize_check_value(&target_path)
    ));

    if allowed_tool_names.contains("filesystem__patch") {
        verification_checks
            .push("invalid_tool_call_repair_deterministic_recovery=code_block_patch".to_string());
        return Some(AgentTool::FsPatch {
            path: target_path,
            search,
            replace,
        });
    }

    if allowed_tool_names.contains("filesystem__write_file") {
        let updated_content = file_content.replacen(&search, &replace, 1);
        if updated_content == file_content {
            return None;
        }
        verification_checks
            .push("invalid_tool_call_repair_deterministic_recovery=code_block_write".to_string());
        return Some(AgentTool::FsWrite {
            path: target_path,
            content: updated_content,
            line_number: None,
        });
    }

    None
}

pub(crate) fn synthesize_patch_build_verify_inline_code_edit_repair(
    agent_state: &AgentState,
    worker_assignment: Option<&WorkerAssignment>,
    allowed_tool_names: &BTreeSet<String>,
    raw_tool_output: &str,
    verification_checks: &mut Vec<String>,
) -> Option<AgentTool> {
    let assignment = worker_assignment?;
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_build_verify") {
        return None;
    }

    let (target_path, file_content) =
        patch_build_verify_current_file_snapshot(agent_state, assignment, raw_tool_output)?;
    let current_block = extract_primary_python_function_block(&file_content)?;
    let updated_block =
        updated_python_block_candidate_from_raw_output(&current_block, raw_tool_output)?;
    if normalize_block_for_match(&current_block) == normalize_block_for_match(&updated_block) {
        return None;
    }

    verification_checks
        .push("invalid_tool_call_repair_deterministic_source=inline_code_segments".to_string());
    verification_checks.push(format!(
        "invalid_tool_call_repair_patch_target={}",
        sanitize_check_value(&target_path)
    ));

    if allowed_tool_names.contains("filesystem__patch") {
        verification_checks
            .push("invalid_tool_call_repair_deterministic_recovery=inline_code_patch".to_string());
        return Some(AgentTool::FsPatch {
            path: target_path,
            search: current_block,
            replace: updated_block,
        });
    }

    if allowed_tool_names.contains("filesystem__write_file") {
        let updated_content = file_content.replacen(&current_block, &updated_block, 1);
        if updated_content == file_content {
            return None;
        }
        verification_checks
            .push("invalid_tool_call_repair_deterministic_recovery=inline_code_write".to_string());
        return Some(AgentTool::FsWrite {
            path: target_path,
            content: updated_content,
            line_number: None,
        });
    }

    None
}

pub(crate) fn synthesize_patch_build_verify_goal_constrained_snapshot_repair(
    agent_state: &AgentState,
    worker_assignment: Option<&WorkerAssignment>,
    allowed_tool_names: &BTreeSet<String>,
    raw_tool_output: &str,
    verification_checks: &mut Vec<String>,
) -> Option<AgentTool> {
    let assignment = worker_assignment?;
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_build_verify") {
        return None;
    }
    if latest_command_failure_summary(agent_state).is_none() {
        return None;
    }
    if !allowed_tool_names.contains("filesystem__write_file") {
        return None;
    }

    let goal_lower = assignment.goal.to_ascii_lowercase();
    if !patch_build_verify_goal_requires_path_parity(&goal_lower) {
        return None;
    }
    let preferred_path = patch_build_verify_explicit_target_path(raw_tool_output);
    let rewritten_tool = patch_build_verify_goal_constrained_snapshot_rewrite(
        agent_state,
        assignment,
        preferred_path.as_deref(),
    )?;
    let target_path = patch_build_verify_edit_tool_path(&rewritten_tool)?.to_string();

    verification_checks.push(
        "invalid_tool_call_repair_deterministic_source=goal_constrained_snapshot".to_string(),
    );
    verification_checks.push(format!(
        "invalid_tool_call_repair_patch_target={}",
        sanitize_check_value(&target_path)
    ));
    verification_checks.push(
        "invalid_tool_call_repair_deterministic_recovery=goal_constrained_snapshot_write"
            .to_string(),
    );

    Some(rewritten_tool)
}

pub(crate) fn upconvert_patch_build_verify_runtime_line_edit_repair(
    agent_state: &AgentState,
    worker_assignment: Option<&WorkerAssignment>,
    raw_tool_output: &str,
    repaired_tool: AgentTool,
    verification_checks: &mut Vec<String>,
) -> AgentTool {
    let Some(assignment) = worker_assignment else {
        return repaired_tool;
    };
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_build_verify") {
        return repaired_tool;
    }

    let AgentTool::FsWrite {
        content,
        line_number: Some(_),
        ..
    } = &repaired_tool
    else {
        return repaired_tool;
    };

    let Some((target_path, file_content)) =
        patch_build_verify_current_file_snapshot(agent_state, assignment, raw_tool_output)
    else {
        return repaired_tool;
    };
    let Some(current_block) = extract_primary_python_function_block(&file_content) else {
        return repaired_tool;
    };

    let updated_block = if let Some(block) =
        updated_python_block_candidate_from_raw_output(&current_block, raw_tool_output)
    {
        verification_checks
            .push("invalid_tool_call_repair_runtime_line_edit_source=raw_output".to_string());
        block
    } else if matches_python_function_signature(content.trim_start()) {
        match align_python_block_to_reference(content, &current_block) {
            Some(block) => {
                verification_checks.push(
                    "invalid_tool_call_repair_runtime_line_edit_source=runtime_function_block"
                        .to_string(),
                );
                block
            }
            None => return repaired_tool,
        }
    } else {
        match inline_python_block_repair_candidate_from_line(&current_block, content) {
            Some(block) => {
                verification_checks.push(
                    "invalid_tool_call_repair_runtime_line_edit_source=runtime_line".to_string(),
                );
                block
            }
            None => return repaired_tool,
        }
    };

    let updated_content = file_content.replacen(&current_block, &updated_block, 1);
    if updated_content == file_content {
        return repaired_tool;
    }

    verification_checks
        .push("invalid_tool_call_repair_runtime_line_edit_upconverted=true".to_string());
    verification_checks.push(format!(
        "invalid_tool_call_repair_patch_target={}",
        sanitize_check_value(&target_path)
    ));

    AgentTool::FsWrite {
        path: target_path,
        content: updated_content,
        line_number: None,
    }
}

pub(crate) fn patch_build_verify_repair_source_from_raw_tool_output(
    raw_tool_output: &str,
) -> Option<String> {
    let tool = middleware::normalize_tool_call(raw_tool_output).ok()?;
    match tool {
        AgentTool::FsPatch { replace, .. } => Some(replace),
        AgentTool::FsWrite { content, .. } => Some(content),
        _ => None,
    }
}

pub(crate) fn patch_build_verify_edit_tool_path(tool: &AgentTool) -> Option<&str> {
    match tool {
        AgentTool::FsPatch { path, .. } | AgentTool::FsWrite { path, .. } => Some(path.as_str()),
        _ => None,
    }
}

pub(crate) fn patch_build_verify_goal_constrained_snapshot_content(
    agent_state: &AgentState,
    assignment: &WorkerAssignment,
    raw_tool_output: &str,
) -> Option<(String, String)> {
    let goal_lower = assignment.goal.to_ascii_lowercase();
    if !patch_build_verify_goal_requires_path_parity(&goal_lower) {
        return None;
    }

    let (target_path, file_content) =
        patch_build_verify_current_file_snapshot(agent_state, assignment, raw_tool_output)?;
    let current_block = extract_primary_python_function_block(&file_content)?;
    if !patch_build_verify_current_block_needs_path_parity_repair(&current_block) {
        return None;
    }

    let updated_block = patch_build_verify_path_parity_reference_repair(&current_block)?;
    if normalize_block_for_match(&current_block) == normalize_block_for_match(&updated_block) {
        return None;
    }

    let updated_content = file_content.replacen(&current_block, &updated_block, 1);
    if updated_content == file_content {
        return None;
    }

    Some((target_path, updated_content))
}

pub(crate) fn patch_build_verify_goal_constrained_snapshot_rewrite(
    agent_state: &AgentState,
    assignment: &WorkerAssignment,
    preferred_path: Option<&str>,
) -> Option<AgentTool> {
    let (snapshot_path, updated_content) =
        patch_build_verify_goal_constrained_snapshot_content(agent_state, assignment, "")?;
    let rewritten_path = preferred_path
        .filter(|path| {
            patch_build_verify_runtime_edit_targets_expected_path(agent_state, path, &snapshot_path)
        })
        .map(str::to_string)
        .unwrap_or(snapshot_path);
    Some(AgentTool::FsWrite {
        path: rewritten_path,
        content: updated_content,
        line_number: None,
    })
}

pub(crate) fn patch_build_verify_updated_content_from_repair_source(
    agent_state: &AgentState,
    assignment: &WorkerAssignment,
    raw_tool_output: &str,
    repair_source: &str,
) -> Option<(String, String)> {
    let (target_path, file_content) =
        patch_build_verify_current_file_snapshot(agent_state, assignment, raw_tool_output)?;
    let current_block = extract_primary_python_function_block(&file_content)?;
    let updated_block =
        updated_python_block_candidate_from_raw_output(&current_block, repair_source)?;
    let updated_content = file_content.replacen(&current_block, &updated_block, 1);
    if updated_content == file_content {
        return None;
    }

    Some((target_path, updated_content))
}

pub(crate) fn maybe_salvage_disallowed_patch_build_verify_runtime_edit(
    agent_state: &AgentState,
    worker_assignment: Option<&WorkerAssignment>,
    raw_tool_output: &str,
    repaired_tool: &AgentTool,
    allowed_tool_names: &BTreeSet<String>,
    verification_checks: &mut Vec<String>,
    prefix: &str,
) -> Option<AgentTool> {
    let assignment = worker_assignment?;
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_build_verify") {
        return None;
    }
    if !allowed_tool_names.contains("filesystem__write_file")
        || allowed_tool_names.contains("filesystem__patch")
    {
        return None;
    }

    let repair_source = match repaired_tool {
        AgentTool::FsPatch { replace, .. } => replace.clone(),
        _ => return None,
    };
    let (target_path, updated_content) = patch_build_verify_updated_content_from_repair_source(
        agent_state,
        assignment,
        raw_tool_output,
        &repair_source,
    )?;

    verification_checks.push(format!("{prefix}_runtime_patch_upconverted=true"));
    verification_checks.push(format!(
        "{prefix}_patch_target={}",
        sanitize_check_value(&target_path)
    ));
    Some(AgentTool::FsWrite {
        path: target_path,
        content: updated_content,
        line_number: None,
    })
}

pub(crate) fn looks_like_planning_restatement(raw_tool_output: &str) -> bool {
    let lines = raw_tool_output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if lines.len() < 2 {
        return false;
    }

    lines.iter().skip(1).any(|line| {
        line.split_whitespace().count() >= 4
            && line.chars().any(|ch| ch.is_ascii_alphabetic())
            && !line.contains('{')
    })
}

pub(crate) fn normalize_replacement_block(search: &str, replace: &str) -> String {
    let mut normalized = replace.replace("\r\n", "\n").trim_matches('\n').to_string();
    if search.ends_with('\n') && !normalized.ends_with('\n') {
        normalized.push('\n');
    }
    normalized
}

pub(crate) fn truncate_for_prompt(value: &str, max_chars: usize) -> String {
    let trimmed = value.trim();
    if trimmed.chars().count() <= max_chars {
        return trimmed.to_string();
    }
    let mut truncated = trimmed.chars().take(max_chars).collect::<String>();
    truncated.push_str("...");
    truncated
}

pub(crate) fn sanitize_check_value(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_ascii_whitespace() { '_' } else { ch })
        .take(96)
        .collect()
}
