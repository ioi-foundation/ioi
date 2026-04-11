use super::*;

pub(crate) fn attempt_patch_build_verify_runtime_patch_miss_repair(
    state: &dyn StateAccess,
    agent_state: &AgentState,
    session_id: [u8; 32],
    current_tool_name: &str,
    error_msg: Option<&str>,
    raw_tool_output: &str,
    verification_checks: &mut Vec<String>,
) -> Option<AgentTool> {
    if current_tool_name != "file__edit" {
        return None;
    }
    let error = error_msg?.trim();
    let normalized_error = error.to_ascii_lowercase();
    if !normalized_error.contains("error_class=noeffectafteraction")
        || !normalized_error.contains("search block not found in file")
    {
        return None;
    }

    let assignment = load_worker_assignment(state, session_id).ok().flatten()?;
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_build_verify") {
        return None;
    }
    if !assignment
        .allowed_tools
        .iter()
        .any(|tool| tool == "file__write")
    {
        return None;
    }

    let (target_path, file_content) =
        patch_build_verify_current_file_snapshot(agent_state, &assignment, raw_tool_output)?;
    let current_block = extract_primary_python_function_block(&file_content)?;
    let repair_source = patch_build_verify_repair_source_from_raw_tool_output(raw_tool_output)
        .unwrap_or_else(|| raw_tool_output.to_string());
    let updated_block =
        updated_python_block_candidate_from_raw_output(&current_block, &repair_source)?;
    let updated_content = file_content.replacen(&current_block, &updated_block, 1);
    if updated_content == file_content {
        return None;
    }

    if let Some(failure_summary) = patch_build_verify_runtime_candidate_failure_summary(
        &assignment,
        &file_content,
        &updated_content,
        verification_checks,
        "runtime_patch_miss_repair",
        "full_write",
    ) {
        verification_checks.push(format!(
            "runtime_patch_miss_repair_projection_rejected={}",
            sanitize_check_value(&failure_summary)
        ));
        if let Some(rewritten_tool) = patch_build_verify_goal_constrained_snapshot_rewrite(
            agent_state,
            &assignment,
            Some(&target_path),
        ) {
            verification_checks.push(
                "runtime_patch_miss_repair_deterministic_recovery=goal_constrained_snapshot_write"
                    .to_string(),
            );
            verification_checks.push(format!(
                "runtime_patch_miss_repair_target={}",
                sanitize_check_value(&target_path)
            ));
            return Some(rewritten_tool);
        }
    }

    verification_checks
        .push("runtime_patch_miss_repair_deterministic_recovery=full_write".to_string());
    verification_checks.push(format!(
        "runtime_patch_miss_repair_target={}",
        sanitize_check_value(&target_path)
    ));

    Some(AgentTool::FsWrite {
        path: target_path,
        content: updated_content,
        line_number: None,
    })
}

pub(crate) async fn maybe_rewrite_patch_build_verify_post_command_edit(
    state: &dyn StateAccess,
    agent_state: &AgentState,
    session_id: [u8; 32],
    tool: &AgentTool,
    verification_checks: &mut Vec<String>,
) -> Result<Option<AgentTool>, TransactionError> {
    let Some(assignment) =
        load_worker_assignment(state, session_id).map_err(TransactionError::Invalid)?
    else {
        return Ok(None);
    };
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_build_verify") {
        return Ok(None);
    }
    if latest_command_failure_summary(agent_state).is_none() {
        return Ok(None);
    }
    if !matches!(tool, AgentTool::FsPatch { .. } | AgentTool::FsWrite { .. }) {
        return Ok(None);
    }

    let tool_json = serde_json::to_string(tool)
        .map_err(|error| TransactionError::Serialization(error.to_string()))?;
    let current_snapshot =
        patch_build_verify_current_file_snapshot(agent_state, &assignment, &tool_json);
    let projection = patch_build_verify_runtime_edit_validation_projection(
        agent_state,
        &assignment,
        &tool_json,
        tool,
        current_snapshot.as_ref(),
        verification_checks,
        "patch_build_verify_direct_edit",
        "direct",
    );
    let mut rejection_summary = None;
    if projection.is_none() {
        verification_checks
            .push("patch_build_verify_direct_edit_projection_missing=true".to_string());
        rejection_summary = Some("direct:projection_missing".to_string());
    } else if let Some(failure_summary) = validate_patch_build_verify_runtime_edit_repair(
        agent_state,
        Some(&assignment),
        &tool_json,
        tool,
        verification_checks,
        "patch_build_verify_direct_edit",
        "direct",
    )
    .await?
    {
        verification_checks.push(format!(
            "patch_build_verify_direct_edit_rejected={}",
            sanitize_check_value(&failure_summary)
        ));
        rejection_summary = Some(failure_summary);
    }

    if rejection_summary.is_none() {
        return Ok(None);
    }

    let preferred_path = patch_build_verify_edit_tool_path(tool);
    let Some(rewritten_tool) = patch_build_verify_goal_constrained_snapshot_rewrite(
        agent_state,
        &assignment,
        preferred_path,
    ) else {
        return Ok(None);
    };
    let rewritten_tool_json = serde_json::to_string(&rewritten_tool)
        .map_err(|error| TransactionError::Serialization(error.to_string()))?;
    if let Some(failure_summary) = validate_patch_build_verify_runtime_edit_repair(
        agent_state,
        Some(&assignment),
        &rewritten_tool_json,
        &rewritten_tool,
        verification_checks,
        "patch_build_verify_direct_edit",
        "goal_snapshot",
    )
    .await?
    {
        verification_checks.push(format!(
            "patch_build_verify_direct_edit_rewrite_rejected={}",
            sanitize_check_value(&failure_summary)
        ));
        return Ok(None);
    }

    verification_checks.push("patch_build_verify_direct_edit_rewritten=true".to_string());
    verification_checks.push(
        "patch_build_verify_direct_edit_rewrite_source=goal_constrained_snapshot".to_string(),
    );
    Ok(Some(rewritten_tool))
}

pub(crate) fn maybe_rewrite_patch_build_verify_redundant_refresh_read(
    state: &dyn StateAccess,
    agent_state: &AgentState,
    session_id: [u8; 32],
    tool: &AgentTool,
    verification_checks: &mut Vec<String>,
) -> Option<AgentTool> {
    let assignment = load_worker_assignment(state, session_id).ok().flatten()?;
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_build_verify") {
        return None;
    }

    let AgentTool::FsRead { path } = tool else {
        return None;
    };

    let command_literal = first_goal_command_literal(&assignment.goal)?;
    let (exit_code, command_step) = latest_goal_command(agent_state, &command_literal)?;
    if exit_code == 0 {
        return None;
    }
    if latest_workspace_edit_step(agent_state)
        .map(|edit_step| edit_step > command_step)
        .unwrap_or(false)
    {
        return None;
    }

    let expected_path = patch_build_verify_primary_patch_file(&assignment, path)?;
    if !patch_build_verify_runtime_edit_targets_expected_path(agent_state, path, &expected_path) {
        return None;
    }

    let latest_read_step = latest_workspace_read_step(agent_state, path)
        .or_else(|| latest_workspace_read_step(agent_state, &expected_path))?;
    if latest_read_step <= command_step {
        return None;
    }
    if patch_build_verify_refresh_read_ready(agent_state, path)
        || patch_build_verify_refresh_read_ready(agent_state, &expected_path)
    {
        return None;
    }

    let rewritten_tool =
        patch_build_verify_goal_constrained_snapshot_rewrite(agent_state, &assignment, Some(path))?;
    verification_checks
        .push("patch_build_verify_redundant_refresh_read_rewritten=true".to_string());
    verification_checks.push(
        "patch_build_verify_redundant_refresh_read_rewrite_source=goal_constrained_snapshot"
            .to_string(),
    );
    verification_checks.push(format!(
        "patch_build_verify_redundant_refresh_read_target={}",
        sanitize_check_value(path)
    ));
    Some(rewritten_tool)
}

pub(crate) fn maybe_rewrite_patch_build_verify_post_success_completion(
    state: &dyn StateAccess,
    agent_state: &AgentState,
    session_id: [u8; 32],
    tool: &AgentTool,
    verification_checks: &mut Vec<String>,
) -> Option<AgentTool> {
    if !matches!(
        tool,
        AgentTool::FsRead { .. }
            | AgentTool::FsList { .. }
            | AgentTool::FsStat { .. }
            | AgentTool::FsPatch { .. }
            | AgentTool::FsWrite { .. }
    ) {
        return None;
    }

    let assignment = load_worker_assignment(state, session_id).ok().flatten()?;
    synthesize_patch_build_verify_completion_after_success(
        agent_state,
        Some(&assignment),
        verification_checks,
    )
}
