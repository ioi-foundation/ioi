use super::*;

pub(super) fn duplicate_prior_success_noop(verification_checks: &[String]) -> bool {
    verification_checks
        .iter()
        .any(|check| check == "duplicate_action_fingerprint_prior_success_noop=true")
}

pub(super) fn active_web_pipeline_chat_reply_duplicate_noop(
    verification_checks: &[String],
) -> bool {
    verification_checks.iter().any(|check| {
        check == "terminal_chat_reply_deferred_for_active_web_pipeline=true"
            || check == "web_model_chat_reply_duplicate_suppressed=true"
    })
}

pub(super) fn retained_shell_input_duplicate_noop(
    verification_checks: &[String],
    current_tool_name: &str,
) -> bool {
    current_tool_name == "shell__input"
        && verification_checks
            .iter()
            .any(|check| check == "retained_shell_input_duplicate_noop=true")
}

pub(super) fn terminal_product_handoff_violation_error(reason: &str) -> String {
    format!(
        "ERROR_CLASS=UnexpectedState Final reply was not product-safe ({reason}). Return a fresh concise user-facing Markdown answer through the available terminal reply tool. Do not include raw temp paths, fixture/probe markers, raw logs, stdout/stderr dumps, receipt ids, trace ids, JSON payloads, or daemon scaffolding. Summarize the observed work and verification result instead."
    )
}

pub(super) fn recoverable_action_completion_contract_error(error: Option<&str>) -> bool {
    let Some(error) = error else {
        return false;
    };
    let normalized = error.to_ascii_lowercase();
    normalized.contains("error_class=executioncontractviolation")
        && normalized.contains("missing_keys=tool::")
        && normalized.contains("::executed")
}

pub(super) fn read_only_workspace_context_duplicate_noop(
    agent_state: &AgentState,
    current_tool_name: &str,
) -> bool {
    if !matches!(
        current_tool_name,
        "file__read" | "file__search" | "file__info" | "file__list"
    ) {
        return false;
    }
    let goal_workspace_edit_verification =
        goal_suggests_workspace_edit_and_verification(&agent_state.goal);
    let Some(resolved) = agent_state.resolved_intent.as_ref() else {
        return goal_workspace_edit_verification;
    };
    let workspace_or_command_workspace = matches!(resolved.scope, IntentScopeProfile::WorkspaceOps)
        || matches!(resolved.scope, IntentScopeProfile::CommandExecution)
            && resolved
                .required_capabilities
                .iter()
                .any(|capability| capability.as_str() == "command.exec")
            && resolved.required_capabilities.iter().any(|capability| {
                matches!(
                    capability.as_str(),
                    "filesystem.read" | "filesystem.write" | "filesystem.metadata"
                )
            });
    if !workspace_or_command_workspace {
        return goal_workspace_edit_verification;
    }

    if matches!(resolved.scope, IntentScopeProfile::CommandExecution) {
        return true;
    }

    has_execution_evidence(&agent_state.tool_execution_log, "workspace_read")
        && has_execution_evidence(&agent_state.tool_execution_log, "file_context")
}

fn goal_suggests_workspace_edit_and_verification(goal: &str) -> bool {
    let lower = goal.to_ascii_lowercase();
    let wants_change = [
        "fix", "edit", "change", "update", "modify", "repair", "patch",
    ]
    .iter()
    .any(|needle| lower.contains(needle));
    let has_workspace_target = [
        "src/",
        "test",
        "tests/",
        ".js",
        ".mjs",
        ".ts",
        ".tsx",
        ".rs",
        ".py",
        ".json",
        ".md",
        "file",
        "repo",
        "workspace",
    ]
    .iter()
    .any(|needle| lower.contains(needle));
    let has_verification = [
        "`",
        "run test",
        "run the test",
        "run tests",
        "verify",
        "verification",
        "node --test",
        "npm test",
        "cargo test",
        "pytest",
    ]
    .iter()
    .any(|needle| lower.contains(needle));

    wants_change && has_workspace_target && has_verification
}

pub(super) fn duplicate_after_prior_success(verification_checks: &[String]) -> bool {
    verification_checks.iter().any(|check| {
        check == "duplicate_action_fingerprint_prior_success=true"
            || check == "duplicate_action_fingerprint_prior_success_noop=true"
    })
}

pub(super) fn browser_route_owns_dedicated_surface(agent_state: &AgentState) -> bool {
    if resolved_intent_id(agent_state).eq_ignore_ascii_case("browser.interact") {
        return true;
    }

    agent_state
        .runtime_route_frame
        .as_ref()
        .is_some_and(|frame| frame.intent_id.eq_ignore_ascii_case("browser.interact"))
}

pub(super) fn web_pipeline_completion_reason_label(
    reason: WebPipelineCompletionReason,
) -> &'static str {
    match reason {
        WebPipelineCompletionReason::MinSourcesReached => "min_sources_reached",
        WebPipelineCompletionReason::ExhaustedCandidates => "exhausted_candidates",
        WebPipelineCompletionReason::DeadlineReached => "deadline_reached",
    }
}

pub(super) fn preserve_tool_history_or_fill_ready_note(
    history_entry: &mut Option<String>,
    action_output: &mut Option<String>,
) {
    const READY_NOTE: &str = "Web evidence is ready for a model-authored final answer.";
    if history_entry
        .as_deref()
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        *history_entry = Some(READY_NOTE.to_string());
    }
    if action_output
        .as_deref()
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        *action_output = history_entry.clone();
    }
}

pub(super) fn should_release_browser_after_terminal_reply(
    agent_state: &AgentState,
    current_tool_name: &str,
    terminal_chat_reply_output: Option<&str>,
) -> bool {
    matches!(agent_state.status, AgentStatus::Completed(_))
        && current_tool_name != "chat__reply"
        && terminal_chat_reply_output.is_some_and(|output| !output.trim().is_empty())
        && browser_route_owns_dedicated_surface(agent_state)
}

pub(super) fn patch_build_verify_patch_miss_receipt_evidence(
    current_tool_name: &str,
    error_msg: Option<&str>,
    executed_tool_jcs: Option<&[u8]>,
    tool_call_result: &str,
    step_index: u32,
) -> Option<String> {
    if current_tool_name != "file__edit" {
        return None;
    }
    let normalized_error = error_msg?.trim().to_ascii_lowercase();
    if !normalized_error.contains("error_class=noeffectafteraction")
        || !normalized_error.contains("search block not found in file")
    {
        return None;
    }

    let path_from_executed = executed_tool_jcs
        .and_then(|bytes| serde_json::from_slice::<AgentTool>(bytes).ok())
        .and_then(|tool| match tool {
            AgentTool::FsPatch { path, .. } => Some(path),
            _ => None,
        });
    let path = path_from_executed.or_else(|| {
        crate::agentic::runtime::middleware::normalize_tool_call(tool_call_result)
            .ok()
            .and_then(|tool| match tool {
                AgentTool::FsPatch { path, .. } => Some(path),
                _ => None,
            })
    })?;
    let path = path.trim();
    if path.is_empty() {
        return None;
    }

    Some(format!(
        "step={step_index};tool=file__edit;path={path};reason=search_block_not_found"
    ))
}
