use super::*;

pub(crate) fn invalid_tool_repair_supported(
    agent_state: &AgentState,
    worker_assignment: Option<&WorkerAssignment>,
) -> bool {
    matches!(
        agent_state
            .resolved_intent
            .as_ref()
            .map(|resolved| resolved.scope),
        Some(IntentScopeProfile::WorkspaceOps | IntentScopeProfile::CommandExecution)
    ) || worker_assignment
        .and_then(|assignment| assignment.workflow_id.as_deref())
        .map(str::trim)
        == Some("patch_build_verify")
}

pub(crate) async fn validate_patch_build_verify_runtime_edit_repair(
    agent_state: &AgentState,
    worker_assignment: Option<&WorkerAssignment>,
    raw_tool_output: &str,
    repaired_tool: &AgentTool,
    verification_checks: &mut Vec<String>,
    prefix: &str,
    runtime_label: &str,
) -> Result<Option<String>, TransactionError> {
    let Some(assignment) = worker_assignment else {
        return Ok(None);
    };
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_build_verify") {
        return Ok(None);
    }

    if let Some(failure_summary) = validate_patch_build_verify_runtime_repair_boundary(
        agent_state,
        assignment,
        repaired_tool,
        verification_checks,
        prefix,
        runtime_label,
    ) {
        return Ok(Some(failure_summary));
    }

    let current_snapshot =
        patch_build_verify_current_file_snapshot(agent_state, assignment, raw_tool_output);
    if let AgentTool::FsWrite {
        content,
        line_number: Some(_),
        ..
    } = repaired_tool
    {
        if patch_build_verify_runtime_line_edit_requires_full_write(content) {
            verification_checks.push(format!(
                "{prefix}_runtime_{runtime_label}_line_edit_requires_full_write=true"
            ));
            return Ok(Some(format!(
                "{runtime_label}:line_edit_requires_full_write"
            )));
        }
        let Some((_, current_content)) = current_snapshot.as_ref() else {
            verification_checks.push(format!(
                "{prefix}_runtime_{runtime_label}_line_edit_requires_snapshot=true"
            ));
            return Ok(Some(format!("{runtime_label}:line_edit_requires_snapshot")));
        };
        if extract_primary_python_function_block(current_content).is_none() {
            verification_checks.push(format!(
                "{prefix}_runtime_{runtime_label}_line_edit_missing_python_context=true"
            ));
            return Ok(Some(format!(
                "{runtime_label}:line_edit_missing_python_context"
            )));
        }
    }

    let Some((path, content, line_number)) = patch_build_verify_runtime_edit_validation_projection(
        agent_state,
        assignment,
        raw_tool_output,
        repaired_tool,
        current_snapshot.as_ref(),
        verification_checks,
        prefix,
        runtime_label,
    ) else {
        return Ok(None);
    };

    let Some(expected_path) = patch_build_verify_primary_patch_file(assignment, raw_tool_output)
    else {
        return Ok(None);
    };
    if !patch_build_verify_runtime_edit_targets_expected_path(agent_state, &path, &expected_path) {
        verification_checks.push(format!(
            "{prefix}_runtime_{runtime_label}_path_mismatch=true"
        ));
        return Ok(Some(format!("{runtime_label}:path_mismatch")));
    }

    if !path.ends_with(".py") {
        return Ok(None);
    }

    if let Some((_, current_content)) = current_snapshot.as_ref() {
        if let Some(line_number) = line_number {
            if !patch_build_verify_runtime_line_edit_within_current_file(
                current_content,
                line_number,
            ) {
                verification_checks.push(format!(
                    "{prefix}_runtime_{runtime_label}_line_number_out_of_range=true"
                ));
                return Ok(Some(format!("{runtime_label}:line_number_out_of_range")));
            }
        }
        if !patch_build_verify_runtime_repair_preserves_python_signature(&current_content, &content)
        {
            verification_checks.push(format!(
                "{prefix}_runtime_{runtime_label}_python_signature_mismatch=true"
            ));
            return Ok(Some(format!("{runtime_label}:python_signature_mismatch")));
        }
    }

    if let Some(failure_summary) = validate_patch_build_verify_runtime_goal_constraints(
        assignment,
        &content,
        verification_checks,
        prefix,
        runtime_label,
    ) {
        return Ok(Some(failure_summary));
    }

    if let Some(syntax_error) = validate_python_module_syntax(&content).await? {
        verification_checks.push(format!(
            "{prefix}_runtime_{runtime_label}_python_syntax_error={}",
            sanitize_check_value(&syntax_error)
        ));
        return Ok(Some(format!("{runtime_label}:python_syntax_error")));
    }

    Ok(None)
}

pub(crate) fn patch_build_verify_runtime_edit_validation_projection(
    agent_state: &AgentState,
    assignment: &WorkerAssignment,
    raw_tool_output: &str,
    repaired_tool: &AgentTool,
    current_snapshot: Option<&(String, String)>,
    verification_checks: &mut Vec<String>,
    prefix: &str,
    runtime_label: &str,
) -> Option<(String, String, Option<u32>)> {
    match repaired_tool {
        AgentTool::FsWrite {
            path,
            content,
            line_number,
        } => {
            if let Some(line_number) = line_number {
                if let Some((_, current_content)) = current_snapshot {
                    if let Some(updated_content) =
                        patch_build_verify_preview_line_edit(current_content, *line_number, content)
                    {
                        verification_checks.push(format!(
                            "{prefix}_runtime_{runtime_label}_line_edit_materialized_for_validation=true"
                        ));
                        return Some((path.clone(), updated_content, Some(*line_number)));
                    }
                }
            }
            Some((path.clone(), content.clone(), *line_number))
        }
        AgentTool::FsPatch {
            path,
            search,
            replace,
        } => {
            let (_, file_content) =
                patch_build_verify_current_file_snapshot(agent_state, assignment, raw_tool_output)?;
            let updated_content = file_content.replacen(search, replace, 1);
            if updated_content == file_content {
                return None;
            }
            verification_checks.push(format!(
                "{prefix}_runtime_{runtime_label}_patch_materialized_for_validation=true"
            ));
            Some((path.clone(), updated_content, None))
        }
        _ => None,
    }
}

pub(crate) async fn validate_patch_build_verify_deterministic_edit_repair(
    agent_state: &AgentState,
    worker_assignment: Option<&WorkerAssignment>,
    raw_tool_output: &str,
    repaired_tool: AgentTool,
    verification_checks: &mut Vec<String>,
    deterministic_label: &str,
) -> Result<DeterministicEditRepairValidation, TransactionError> {
    let runtime_label = format!("deterministic_{deterministic_label}");
    if let Some(failure_summary) = validate_patch_build_verify_runtime_edit_repair(
        agent_state,
        worker_assignment,
        raw_tool_output,
        &repaired_tool,
        verification_checks,
        "invalid_tool_call_repair",
        &runtime_label,
    )
    .await?
    {
        verification_checks.push(format!(
            "invalid_tool_call_repair_{}_rejected={}",
            runtime_label,
            sanitize_check_value(&failure_summary)
        ));
        return Ok(DeterministicEditRepairValidation::Rejected(failure_summary));
    }

    Ok(DeterministicEditRepairValidation::Accepted(repaired_tool))
}

pub(crate) async fn attempt_patch_build_verify_deterministic_edit_repair(
    agent_state: &AgentState,
    worker_assignment: Option<&WorkerAssignment>,
    allowed_tool_names: &BTreeSet<String>,
    raw_tool_output: &str,
    verification_checks: &mut Vec<String>,
) -> Result<Option<DeterministicEditRepairValidation>, TransactionError> {
    let mut rejection_summary = None;

    if let Some(repaired_tool) = synthesize_patch_build_verify_code_block_edit_repair(
        agent_state,
        worker_assignment,
        allowed_tool_names,
        raw_tool_output,
        verification_checks,
    ) {
        match validate_patch_build_verify_deterministic_edit_repair(
            agent_state,
            worker_assignment,
            raw_tool_output,
            repaired_tool,
            verification_checks,
            "code_block",
        )
        .await?
        {
            DeterministicEditRepairValidation::Accepted(repaired_tool) => {
                return Ok(Some(DeterministicEditRepairValidation::Accepted(
                    repaired_tool,
                )));
            }
            DeterministicEditRepairValidation::Rejected(failure_summary) => {
                rejection_summary = Some(failure_summary);
            }
        }
    }

    if let Some(repaired_tool) = synthesize_patch_build_verify_goal_constrained_snapshot_repair(
        agent_state,
        worker_assignment,
        allowed_tool_names,
        raw_tool_output,
        verification_checks,
    ) {
        match validate_patch_build_verify_deterministic_edit_repair(
            agent_state,
            worker_assignment,
            raw_tool_output,
            repaired_tool,
            verification_checks,
            "goal_constrained_snapshot",
        )
        .await?
        {
            DeterministicEditRepairValidation::Accepted(repaired_tool) => {
                return Ok(Some(DeterministicEditRepairValidation::Accepted(
                    repaired_tool,
                )));
            }
            DeterministicEditRepairValidation::Rejected(failure_summary) => {
                rejection_summary = Some(failure_summary);
            }
        }
    }

    if let Some(repaired_tool) = synthesize_patch_build_verify_inline_code_edit_repair(
        agent_state,
        worker_assignment,
        allowed_tool_names,
        raw_tool_output,
        verification_checks,
    ) {
        match validate_patch_build_verify_deterministic_edit_repair(
            agent_state,
            worker_assignment,
            raw_tool_output,
            repaired_tool,
            verification_checks,
            "inline_code",
        )
        .await?
        {
            DeterministicEditRepairValidation::Accepted(repaired_tool) => {
                return Ok(Some(DeterministicEditRepairValidation::Accepted(
                    repaired_tool,
                )));
            }
            DeterministicEditRepairValidation::Rejected(failure_summary) => {
                rejection_summary = Some(failure_summary);
            }
        }
    }

    Ok(rejection_summary.map(DeterministicEditRepairValidation::Rejected))
}

pub(crate) fn validate_patch_build_verify_runtime_goal_constraints(
    assignment: &WorkerAssignment,
    content: &str,
    verification_checks: &mut Vec<String>,
    prefix: &str,
    runtime_label: &str,
) -> Option<String> {
    let goal_lower = assignment.goal.to_ascii_lowercase();
    if patch_build_verify_goal_requires_leading_path_preservation(&goal_lower)
        && patch_build_verify_runtime_edit_strips_required_prefix(content)
    {
        verification_checks.push(format!(
            "{prefix}_runtime_{runtime_label}_goal_path_prefix_violation=true"
        ));
        return Some(format!("{runtime_label}:goal_path_prefix_violation"));
    }

    if patch_build_verify_goal_requires_duplicate_separator_collapse(&goal_lower)
        && patch_build_verify_runtime_edit_uses_single_pass_separator_collapse(content)
    {
        verification_checks.push(format!(
            "{prefix}_runtime_{runtime_label}_goal_duplicate_separator_violation=true"
        ));
        return Some(format!(
            "{runtime_label}:goal_duplicate_separator_violation"
        ));
    }

    if patch_build_verify_goal_requires_forward_slash_normalization(&goal_lower)
        && patch_build_verify_runtime_edit_reverses_separator_direction(content)
    {
        verification_checks.push(format!(
            "{prefix}_runtime_{runtime_label}_goal_separator_direction_violation=true"
        ));
        return Some(format!(
            "{runtime_label}:goal_separator_direction_violation"
        ));
    }

    None
}

pub(crate) fn validate_patch_build_verify_runtime_repair_boundary(
    agent_state: &AgentState,
    assignment: &WorkerAssignment,
    repaired_tool: &AgentTool,
    verification_checks: &mut Vec<String>,
    prefix: &str,
    runtime_label: &str,
) -> Option<String> {
    if latest_command_failure_summary(agent_state).is_none() {
        return None;
    }

    match repaired_tool {
        AgentTool::FsRead { .. }
        | AgentTool::FsList { .. }
        | AgentTool::FsSearch { .. }
        | AgentTool::FsStat { .. } => {
            verification_checks.push(format!(
                "{prefix}_runtime_{runtime_label}_post_command_observation_blocked=true"
            ));
            Some(format!("{runtime_label}:post_command_observation_blocked"))
        }
        AgentTool::SysExecSession { .. } => {
            let retry_ready = first_goal_command_literal(&assignment.goal)
                .map(|command| goal_command_retry_ready_after_workspace_edit(agent_state, &command))
                .unwrap_or(false);
            if retry_ready {
                None
            } else {
                verification_checks.push(format!(
                    "{prefix}_runtime_{runtime_label}_post_command_exec_blocked=true"
                ));
                Some(format!("{runtime_label}:post_command_exec_blocked"))
            }
        }
        _ => None,
    }
}

pub(crate) fn patch_build_verify_should_retry_constrained_runtime_repair(
    agent_state: &AgentState,
    worker_assignment: Option<&WorkerAssignment>,
    rejection_summary: &str,
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

    !rejection_summary.trim().is_empty()
}

pub(crate) fn patch_build_verify_goal_requires_leading_path_preservation(goal_lower: &str) -> bool {
    goal_lower.contains("preserve a leading `./` or `/`")
        || goal_lower.contains("preserves a leading `./` or `/`")
        || goal_lower.contains("preserve a leading ./ or /")
        || goal_lower.contains("preserves a leading ./ or /")
}

pub(crate) fn patch_build_verify_goal_requires_duplicate_separator_collapse(
    goal_lower: &str,
) -> bool {
    goal_lower.contains("collapse duplicate separators")
        || goal_lower.contains("collapses duplicate separators")
        || goal_lower.contains("collapse duplicate separator")
}

pub(crate) fn patch_build_verify_goal_requires_forward_slash_normalization(
    goal_lower: &str,
) -> bool {
    goal_lower.contains("convert backslashes to forward slashes")
        || goal_lower.contains("converts backslashes to forward slashes")
        || goal_lower.contains("convert backslash to forward slash")
        || goal_lower.contains("converts backslash to forward slash")
}

pub(crate) fn patch_build_verify_goal_requires_path_parity(goal_lower: &str) -> bool {
    patch_build_verify_goal_requires_leading_path_preservation(goal_lower)
        && patch_build_verify_goal_requires_duplicate_separator_collapse(goal_lower)
        && patch_build_verify_goal_requires_forward_slash_normalization(goal_lower)
}

pub(crate) fn patch_build_verify_current_block_needs_path_parity_repair(
    current_block: &str,
) -> bool {
    let normalized = current_block
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>()
        .replace('"', "'");
    let has_forward_slash_normalization = normalized.contains(".replace('\\\\','/')");
    let has_duplicate_collapse =
        normalized.contains("while'//'in") || normalized.contains("re.sub(");
    let has_prefix_preservation =
        normalized.contains("startswith('./')") || normalized.contains("startswith('/')");

    !has_forward_slash_normalization || !has_duplicate_collapse || !has_prefix_preservation
}

pub(crate) fn patch_build_verify_runtime_edit_strips_required_prefix(content: &str) -> bool {
    let normalized = content
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>()
        .replace('"', "'");
    normalized.contains(".lstrip('./')")
        || normalized.contains(".lstrip('/')")
        || normalized.contains(".strip('./')")
        || normalized.contains(".strip('/')")
}

pub(crate) fn patch_build_verify_runtime_edit_uses_single_pass_separator_collapse(
    content: &str,
) -> bool {
    let normalized = content
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>()
        .replace('"', "'");
    let has_single_pass_replace = normalized.contains(".replace('//','/')");
    let has_repeated_collapse =
        normalized.contains("while'//'in") || normalized.contains("re.sub(");
    has_single_pass_replace && !has_repeated_collapse
}

pub(crate) fn patch_build_verify_runtime_edit_reverses_separator_direction(content: &str) -> bool {
    let normalized = content
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>()
        .replace('"', "'");
    normalized.contains(".replace('/','\\')") || normalized.contains(".replace('/','\\\\')")
}

pub(crate) fn patch_build_verify_runtime_candidate_failure_summary(
    assignment: &WorkerAssignment,
    current_content: &str,
    candidate_content: &str,
    verification_checks: &mut Vec<String>,
    prefix: &str,
    runtime_label: &str,
) -> Option<String> {
    if !patch_build_verify_runtime_repair_preserves_python_signature(
        current_content,
        candidate_content,
    ) {
        verification_checks.push(format!(
            "{prefix}_{runtime_label}_python_signature_mismatch=true"
        ));
        return Some(format!("{runtime_label}:python_signature_mismatch"));
    }

    validate_patch_build_verify_runtime_goal_constraints(
        assignment,
        candidate_content,
        verification_checks,
        prefix,
        runtime_label,
    )
}

pub(crate) fn patch_build_verify_runtime_line_edit_requires_full_write(content: &str) -> bool {
    let normalized = normalize_code_block_content(content);
    normalized
        .lines()
        .filter(|line| !line.trim().is_empty())
        .nth(1)
        .is_some()
        || matches_python_function_signature(normalized.trim_start())
}

pub(crate) fn patch_build_verify_preview_line_edit(
    current_content: &str,
    line_number: u32,
    replacement: &str,
) -> Option<String> {
    if line_number == 0 {
        return None;
    }

    let mut lines = current_content.lines().collect::<Vec<_>>();
    if lines.is_empty() {
        return None;
    }

    let index = (line_number - 1) as usize;
    if index >= lines.len() {
        return None;
    }

    lines[index] = replacement;
    let newline = if current_content.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut updated = lines.join(newline);
    if current_content.ends_with('\n') {
        updated.push_str(newline);
    }
    Some(updated)
}

pub(crate) fn patch_build_verify_runtime_line_edit_within_current_file(
    current_content: &str,
    line_number: u32,
) -> bool {
    let line_count = current_content.lines().count();
    line_number > 0 && (line_number as usize) <= line_count
}

pub(crate) fn patch_build_verify_edit_only_repair_tools(
    repair_tools: &[LlmToolDefinition],
) -> Vec<LlmToolDefinition> {
    repair_tools
        .iter()
        .filter(|tool| {
            [
                "filesystem__patch",
                "filesystem__write_file",
                "file__edit",
                "file__write",
            ]
            .iter()
            .any(|candidate| repair_tool_names_match(&tool.name, candidate))
        })
        .cloned()
        .collect()
}

pub(crate) fn patch_build_verify_runtime_edit_targets_expected_path(
    agent_state: &AgentState,
    actual_path: &str,
    expected_path: &str,
) -> bool {
    let cwd = Some(agent_state.working_directory.as_str());
    match (
        resolve_tool_path(actual_path, cwd),
        resolve_tool_path(expected_path, cwd),
    ) {
        (Ok(actual), Ok(expected)) => actual == expected,
        _ => actual_path.trim() == expected_path.trim(),
    }
}
