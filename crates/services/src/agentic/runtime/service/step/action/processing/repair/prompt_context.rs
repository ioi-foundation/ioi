use super::*;

pub(crate) fn build_invalid_tool_repair_prompt(
    agent_state: &AgentState,
    worker_assignment: Option<&WorkerAssignment>,
    allowed_tool_names: &BTreeSet<String>,
    effective_failure: Option<&str>,
    parse_error: &str,
    raw_tool_output: &str,
) -> String {
    let goal_context = worker_assignment
        .map(|assignment| assignment.goal.trim())
        .filter(|goal| !goal.is_empty())
        .unwrap_or(agent_state.goal.trim());
    let mut prompt = String::from(
        "You repair malformed tool-call outputs for the IOI desktop agent.\n\
Return EXACTLY ONE valid JSON tool call object using one of the provided tools.\n\
Rules:\n\
1. No prose, no markdown, no code fences.\n\
2. Preserve the original intended action when possible.\n\
3. If the malformed response contains code, a function body, or an edit plan, convert it into the best matching editing tool call.\n\
4. Use only paths, commands, or arguments grounded in the goal context.\n\
5. Use `agent__complete` only when the task is actually complete or no safe executable action remains.\n",
    );
    if worker_assignment
        .and_then(|assignment| assignment.workflow_id.as_deref())
        .map(str::trim)
        == Some("patch_build_verify")
    {
        prompt.push_str(
            "Patch/build/verify worker rules:\n\
6. Do not reread files or search again after a no-effect recovery boundary unless the focused verification command already ran and the latest failure was a malformed edit/tool-call recovery.\n\
7. Prefer `file__edit`, `file__replace_line`, or `file__write` when the malformed response already contains the intended code change.\n\
8. Use `shell__start` only after the edit is ready for the focused verification command.\n\
9. If the focused verification command already ran and failed, produce an edit tool call next instead of rerunning tests.\n\
10. If you use `file__write` for a code edit, omit `line_number` and provide the full updated file contents grounded in the current file snapshot.\n",
        );
    }
    prompt.push_str(&format!(
        "Allowed tools now: {}\n",
        allowed_tool_names
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    ));
    if let Some(effective_failure) = effective_failure {
        prompt.push_str(&format!("Recovery boundary: {effective_failure}\n"));
    }
    prompt.push_str("Goal context:\n");
    prompt.push_str(&truncate_for_prompt(goal_context, 3000));
    prompt.push_str("\nParse error:\n");
    prompt.push_str(&truncate_for_prompt(parse_error, 600));
    prompt.push_str("\nMalformed response to repair:\n");
    prompt.push_str(&truncate_for_prompt(raw_tool_output, 3000));
    if let Some(assignment) = worker_assignment.filter(|assignment| {
        assignment.workflow_id.as_deref().map(str::trim) == Some("patch_build_verify")
    }) {
        if let Some(recent_command) = latest_command_failure_summary(agent_state) {
            prompt.push_str(
                "\nLatest command result (already executed; do not rerun until after an edit):\n",
            );
            prompt.push_str(&truncate_for_prompt(&recent_command, 1800));
        }
        if let Some((target_path, file_contents)) =
            patch_build_verify_current_file_snapshot(agent_state, assignment, raw_tool_output)
        {
            prompt.push_str("\nCurrent likely patch file:\n");
            prompt.push_str(&truncate_for_prompt(&target_path, 300));
            prompt.push_str("\nCurrent likely patch file contents:\n");
            prompt.push_str(&truncate_for_prompt(&file_contents, 2200));
        }
    }
    prompt
}

pub(crate) fn build_invalid_tool_repair_retry_prompt(
    agent_state: &AgentState,
    worker_assignment: Option<&WorkerAssignment>,
    allowed_tool_names: &BTreeSet<String>,
    effective_failure: Option<&str>,
    parse_error: &str,
    raw_tool_output: &str,
    rejection_summary: &str,
) -> String {
    let mut prompt = build_invalid_tool_repair_prompt(
        agent_state,
        worker_assignment,
        allowed_tool_names,
        effective_failure,
        parse_error,
        raw_tool_output,
    );
    prompt.push_str("\nPrevious repair rejection:\n");
    prompt.push_str(&truncate_for_prompt(rejection_summary, 300));
    prompt.push_str(
        "\nRetry rules:\n\
1. Emit an EDIT tool call only. Do not reread, search, stat, list directories, or rerun commands.\n\
2. Ground the edit in the current file snapshot instead of transcribing the malformed response verbatim.\n\
3. Preserve explicit goal constraints, including preserving a leading `./` or `/` when requested.\n\
4. If you use `file__write`, provide the full updated file contents.\n",
    );
    prompt
}

pub(crate) fn build_refusal_repair_prompt(
    agent_state: &AgentState,
    worker_assignment: Option<&WorkerAssignment>,
    allowed_tool_names: &BTreeSet<String>,
    effective_failure: Option<&str>,
    refusal_reason: &str,
) -> String {
    let goal_context = worker_assignment
        .map(|assignment| assignment.goal.trim())
        .filter(|goal| !goal.is_empty())
        .unwrap_or(agent_state.goal.trim());
    let mut prompt = String::from(
        "You recover from empty-content model refusals for the IOI desktop agent.\n\
Return EXACTLY ONE valid JSON tool call object using one of the provided tools.\n\
Rules:\n\
1. No prose, no markdown, no code fences.\n\
2. Use only paths, commands, or arguments grounded in the goal context and retained execution evidence.\n\
3. Preserve the intended next action from the latest evidence instead of restarting discovery.\n\
4. If focused verification already ran and failed, do not rerun it until after an edit lands.\n\
5. Use `agent__complete` only when the task is actually complete or no safe executable action remains.\n",
    );
    if worker_assignment
        .and_then(|assignment| assignment.workflow_id.as_deref())
        .map(str::trim)
        == Some("patch_build_verify")
    {
        prompt.push_str(
            "Patch/build/verify worker rules:\n\
6. After a failing focused verifier result, produce `file__edit`, `file__replace_line`, or `file__write` next.\n\
7. Do not emit `shell__start` again until a workspace edit has landed.\n\
8. Ground any edit tool call in the current likely patch file snapshot.\n\
9. If you use `file__write` for a code edit, omit `line_number` and provide the full updated file contents.\n",
        );
    }
    prompt.push_str(&format!(
        "Allowed tools now: {}\n",
        allowed_tool_names
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    ));
    if let Some(effective_failure) = effective_failure {
        prompt.push_str(&format!("Recovery boundary: {effective_failure}\n"));
    }
    prompt.push_str("Refusal reason:\n");
    prompt.push_str(&truncate_for_prompt(refusal_reason, 600));
    prompt.push_str("\nGoal context:\n");
    prompt.push_str(&truncate_for_prompt(goal_context, 3000));
    if let Some(recent_command) = latest_command_failure_summary(agent_state) {
        prompt.push_str("\nLatest command result (already executed):\n");
        prompt.push_str(&truncate_for_prompt(&recent_command, 1800));
    }
    if let Some(assignment) = worker_assignment.filter(|assignment| {
        assignment.workflow_id.as_deref().map(str::trim) == Some("patch_build_verify")
    }) {
        if let Some((target_path, file_contents)) =
            patch_build_verify_current_file_snapshot(agent_state, assignment, refusal_reason)
        {
            prompt.push_str("\nCurrent likely patch file:\n");
            prompt.push_str(&truncate_for_prompt(&target_path, 300));
            prompt.push_str("\nCurrent likely patch file contents:\n");
            prompt.push_str(&truncate_for_prompt(&file_contents, 2200));
        }
    }
    prompt
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
        .map(|value| value.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|value| matches_command_literal(value, CommandLiteralHeuristic::Strict))
    {
        return Some(command);
    }

    collect_goal_literals(goal)
        .into_iter()
        .find(|literal| matches_command_literal(literal, CommandLiteralHeuristic::Strict))
}

pub(crate) fn patch_build_verify_likely_files(assignment: &WorkerAssignment) -> Vec<String> {
    let (_, inherited_context) = split_parent_playbook_context(&assignment.goal);
    inherited_context
        .and_then(|text| extract_worker_context_field(text, &["likely_files", "likely_file"]))
        .map(|value| {
            value
                .split(';')
                .map(str::trim)
                .filter(|candidate| !candidate.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

pub(crate) fn patch_build_verify_primary_patch_file(
    assignment: &WorkerAssignment,
    raw_tool_output: &str,
) -> Option<String> {
    let candidates = patch_build_verify_likely_files(assignment);
    if let Some(explicit_path) = patch_build_verify_explicit_target_path(raw_tool_output) {
        if !looks_like_test_path(&explicit_path)
            || candidates
                .iter()
                .all(|candidate| looks_like_test_path(candidate))
        {
            return Some(explicit_path);
        }
    }
    if candidates.is_empty() {
        return None;
    }

    if let Some(explicit_match) = candidates.iter().find(|candidate| {
        raw_tool_output.contains(candidate.as_str())
            || raw_tool_output.contains(&format!("`{candidate}`"))
    }) {
        return Some(explicit_match.clone());
    }

    candidates
        .iter()
        .find(|candidate| !looks_like_test_path(candidate))
        .cloned()
        .or_else(|| candidates.first().cloned())
}

pub(crate) fn patch_build_verify_explicit_target_path(raw_tool_output: &str) -> Option<String> {
    let tool = middleware::normalize_tool_call(raw_tool_output).ok()?;
    let path = match tool {
        AgentTool::FsRead { path }
        | AgentTool::FsPatch { path, .. }
        | AgentTool::FsWrite { path, .. } => path,
        _ => return None,
    };
    let path = path.trim();
    if path.is_empty() {
        None
    } else {
        Some(path.to_string())
    }
}

pub(crate) fn patch_build_verify_current_file_snapshot(
    agent_state: &AgentState,
    assignment: &WorkerAssignment,
    raw_tool_output: &str,
) -> Option<(String, String)> {
    let target_path = patch_build_verify_primary_patch_file(assignment, raw_tool_output)?;
    let resolved_path =
        resolve_tool_path(&target_path, Some(&agent_state.working_directory)).ok()?;
    let file_contents = fs::read_to_string(resolved_path).ok()?;
    Some((target_path, file_contents))
}

pub(crate) fn looks_like_test_path(path: &str) -> bool {
    let normalized = path.trim().replace('\\', "/").to_ascii_lowercase();
    normalized.starts_with("tests/")
        || normalized.contains("/tests/")
        || normalized.ends_with("_test.py")
        || normalized.ends_with("_test.rs")
        || normalized.ends_with(".spec.ts")
        || normalized.ends_with(".spec.tsx")
        || normalized.ends_with(".test.ts")
        || normalized.ends_with(".test.tsx")
        || normalized.ends_with(".test.js")
        || normalized.ends_with(".test.jsx")
}

pub(crate) fn latest_command_failure_summary(agent_state: &AgentState) -> Option<String> {
    let entry = agent_state.command_history.back()?;
    if entry.exit_code == 0 {
        return None;
    }
    let mut summary = format!("command: {}\nexit_code: {}", entry.command, entry.exit_code);
    if !entry.stdout.trim().is_empty() {
        summary.push_str("\nstdout:\n");
        summary.push_str(entry.stdout.trim());
    }
    if !entry.stderr.trim().is_empty() {
        summary.push_str("\nstderr:\n");
        summary.push_str(entry.stderr.trim());
    }
    Some(summary)
}

pub(crate) fn latest_goal_command(
    agent_state: &AgentState,
    command_literal: &str,
) -> Option<(i32, u32)> {
    let target = normalize_whitespace(command_literal);
    agent_state.command_history.iter().rev().find_map(|entry| {
        let observed = normalize_whitespace(&entry.command);
        (observed == target || observed.contains(&target))
            .then_some((entry.exit_code, entry.step_index))
    })
}

pub(crate) fn command_history_contains_goal_command(
    agent_state: &AgentState,
    command_literal: &str,
) -> bool {
    latest_goal_command(agent_state, command_literal).is_some()
}

pub(crate) fn parse_receipt_step(value: &str) -> Option<u32> {
    value
        .split(';')
        .find_map(|segment| segment.trim().strip_prefix("step="))
        .and_then(|step| step.parse::<u32>().ok())
}

pub(crate) fn latest_workspace_edit_step(agent_state: &AgentState) -> Option<u32> {
    match agent_state
        .tool_execution_log
        .get("evidence::workspace_edit_applied=true")
    {
        Some(ToolCallStatus::Executed(value)) => parse_receipt_step(value),
        _ => None,
    }
}

pub(crate) fn latest_workspace_edit_path(agent_state: &AgentState) -> Option<String> {
    match agent_state
        .tool_execution_log
        .get("evidence::workspace_edit_applied=true")
    {
        Some(ToolCallStatus::Executed(value)) => parse_receipt_path(value).map(str::to_string),
        _ => None,
    }
}

pub(crate) fn latest_workspace_read_step(
    agent_state: &AgentState,
    target_path: &str,
) -> Option<u32> {
    execution_evidence_value(&agent_state.tool_execution_log, "workspace_read_observed").and_then(
        |value| {
            (parse_receipt_path(value)? == target_path)
                .then(|| parse_receipt_step(value))
                .flatten()
        },
    )
}

pub(crate) fn parse_receipt_path<'a>(value: &'a str) -> Option<&'a str> {
    value
        .split(';')
        .find_map(|segment| segment.trim().strip_prefix("path="))
        .map(str::trim)
        .filter(|path| !path.is_empty())
}

pub(crate) fn latest_workspace_patch_miss_step(
    agent_state: &AgentState,
    target_path: &str,
) -> Option<u32> {
    execution_evidence_value(
        &agent_state.tool_execution_log,
        "workspace_patch_miss_observed",
    )
    .and_then(|value| {
        (parse_receipt_path(value)? == target_path)
            .then(|| parse_receipt_step(value))
            .flatten()
    })
}

pub(crate) fn patch_build_verify_refresh_read_ready(
    agent_state: &AgentState,
    target_path: &str,
) -> bool {
    let Some(patch_miss_step) = latest_workspace_patch_miss_step(agent_state, target_path) else {
        return false;
    };

    latest_workspace_read_step(agent_state, target_path)
        .map(|read_step| patch_miss_step > read_step)
        .unwrap_or(true)
}

pub(crate) fn raw_tool_output_requests_refresh_read(
    raw_tool_output: &str,
    target_path: &str,
) -> bool {
    let normalized = raw_tool_output.to_ascii_lowercase();
    let Some(file_name) = Path::new(target_path)
        .file_name()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
    else {
        return false;
    };

    let mentions_read = normalized.contains("read the")
        || normalized.contains("read `")
        || normalized.contains("read the content")
        || normalized.contains("read the file")
        || normalized.contains("open the")
        || normalized.contains("inspect the");
    mentions_read
        && (normalized.contains(&file_name)
            || normalized.contains("file__read")
            || normalized.contains("current file"))
}

pub(crate) fn goal_command_retry_ready_after_workspace_edit(
    agent_state: &AgentState,
    command_literal: &str,
) -> bool {
    let Some((exit_code, command_step)) = latest_goal_command(agent_state, command_literal) else {
        return false;
    };
    if exit_code == 0 {
        return false;
    }

    latest_workspace_edit_step(agent_state)
        .map(|edit_step| edit_step > command_step)
        .unwrap_or(false)
}

pub(crate) fn patch_build_verify_completion_ready(
    agent_state: &AgentState,
    assignment: &WorkerAssignment,
) -> Option<String> {
    if assignment.workflow_id.as_deref().map(str::trim) != Some("patch_build_verify") {
        return None;
    }
    if !assignment
        .allowed_tools
        .iter()
        .any(|tool| tool == "agent__complete")
    {
        return None;
    }

    let command_literal = first_goal_command_literal(&assignment.goal)?;
    let (exit_code, command_step) = latest_goal_command(agent_state, &command_literal)?;
    if exit_code != 0 {
        return None;
    }
    if latest_workspace_edit_step(agent_state)
        .map(|edit_step| edit_step > command_step)
        .unwrap_or(false)
    {
        return None;
    }

    Some(command_literal)
}

pub(crate) fn synthesize_patch_build_verify_completion_result(
    agent_state: &AgentState,
    assignment: &WorkerAssignment,
    command_literal: &str,
) -> String {
    let touched_files = latest_workspace_edit_path(agent_state)
        .and_then(|path| {
            Path::new(&path)
                .file_name()
                .and_then(|value| value.to_str())
                .map(str::to_string)
        })
        .into_iter()
        .chain(
            patch_build_verify_likely_files(assignment)
                .into_iter()
                .take(1),
        )
        .fold(Vec::<String>::new(), |mut acc, item| {
            if !acc.iter().any(|existing| existing == &item) {
                acc.push(item);
            }
            acc
        });
    let touched_files_line = if touched_files.is_empty() {
        "Touched files: none recorded".to_string()
    } else {
        format!("Touched files: {}", touched_files.join("; "))
    };

    format!(
        "{}\nVerification: {} (passed)\nResidual risk: Focused verification passed; broader checks were not rerun.",
        touched_files_line, command_literal
    )
}
